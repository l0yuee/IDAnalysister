"""Forward symbolic propagation engine — drives intra-function argument
value resolution (3.3).

Given the register an argument enters a function in, `ForwardSymbolicEngine`
seeds an `AbstractState` with a `Symbolic` placeholder for it and runs a
bounded worklist fixpoint over the function's control-flow graph, applying
each instruction's effect (`locators.base.Locator.apply_forward` for
register-only transfer functions; memory loads/stores to stack-relative
locations are handled centrally here, mirroring how `core.engine_backward`
normalizes stack/frame-pointer-relative addresses). At CFG merge points,
per-location values are joined via `core.merge.join`; loop bodies are
revisited up to a bound and then widened to `Unknown` for any location that
hasn't converged, guaranteeing termination.

Scope limitation (documented, not silently guessed around): only
register-passed arguments can be seeded — an argument passed on the stack
has no single well-defined "callee-frame-relative" offset this engine can
derive generically across calling conventions, so forward-tracking a
stack-passed argument yields `Unknown(UNSUPPORTED_OPERAND_SHAPE)` rather
than risking an incorrect offset. Similarly, only stack-pointer- and
frame-pointer-relative memory (spills/reloads of a tracked value) are
modeled; writes through an arbitrary register (heap/struct pointers) are
not tracked as scalar state — see `core.values.MutatedRegion` and the
architecture notes for why that is a deliberate boundary, not an oversight.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idanalysister.core.cfg_model import build_cfg
from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.ida_types import BasicBlockInfo
from idanalysister.core.insn_model import Instruction, Operand, OperandKind
from idanalysister.core.merge import join_all
from idanalysister.core.state import AbstractState
from idanalysister.core.values import Concrete, Symbolic, ValueKind, ValueLattice, unknown
from idanalysister.logging_ import get_logger

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort
    from idanalysister.core.insn_cache import InstructionCache
    from idanalysister.locators.base import LocatorRegistry

_logger = get_logger("core.engine_forward")


class ForwardSymbolicEngine:
    def __init__(
        self,
        port: "IdaPort",
        cache: "InstructionCache",
        registry: "LocatorRegistry",
        max_instructions: int = 4000,
        max_block_visits: int = 64,
        loop_widen_after: int = 3,
    ):
        self.port = port
        self.cache = cache
        self.registry = registry
        self.max_instructions = max_instructions
        self.max_block_visits = max_block_visits
        self.loop_widen_after = loop_widen_after

    def resolve_at(self, func_ea: int, arg_index: int, target_ea: int, initial_reg: int | None) -> ValueLattice:
        if initial_reg is None:
            return unknown(
                UnknownReason.UNSUPPORTED_OPERAND_SHAPE,
                detail="forward tracking of stack-passed arguments is not supported",
            )
        cfg = build_cfg(self.port, func_ea)
        if cfg.is_empty():
            return unknown(UnknownReason.NO_DEFINITION_FOUND, detail="no CFG for function")
        by_start = {b.start_ea: b for b in cfg.blocks}
        entry_block = cfg.block_containing(func_ea)
        target_block = cfg.block_containing(target_ea)
        if entry_block is None or target_block is None:
            return unknown(UnknownReason.NO_DEFINITION_FOUND, detail="entry or target not within function")

        initial_state = AbstractState()
        initial_state.set_register(initial_reg, Symbolic(f"arg{arg_index}"))

        # Deliberately NOT pre-seeded with the entry block's state: `prev_in`
        # below uses "not in in_states yet" to mean "never simulated", and
        # pre-populating it here would make the first visit look identical
        # to a (nonexistent) prior visit, short-circuiting before the entry
        # block's instructions are ever actually simulated.
        in_states: dict[int, AbstractState] = {}
        out_states: dict[int, AbstractState] = {}
        visit_counts: dict[int, int] = {b.start_ea: 0 for b in cfg.blocks}
        budget = {"instr": 0}
        budget_exceeded = False

        worklist = [entry_block.start_ea]
        while worklist and not budget_exceeded:
            start = worklist.pop(0)
            block = by_start.get(start)
            if block is None:
                continue
            visit_counts[start] += 1
            if visit_counts[start] > self.max_block_visits:
                continue
            computed_in = self._join_predecessor_states(cfg, block, out_states, entry_block, initial_state)
            if computed_in is None:
                continue
            if visit_counts[start] > self.loop_widen_after and start in in_states:
                computed_in = self._widen(in_states[start], computed_in)
            prev_in = in_states.get(start)
            if prev_in is not None and prev_in.registers == computed_in.registers and prev_in.stack == computed_in.stack:
                continue
            in_states[start] = computed_in
            out_state, exceeded = self._simulate_block(block, computed_in, func_ea, budget)
            out_states[start] = out_state
            if exceeded:
                budget_exceeded = True
                break
            for succ in cfg.successors(block):
                worklist.append(succ.start_ea)

        target_in = in_states.get(target_block.start_ea)
        if target_in is None:
            return unknown(UnknownReason.NO_DEFINITION_FOUND, detail="target block never reached in forward walk")
        final_state, _ = self._simulate_block(
            target_block, target_in, func_ea, {"instr": 0}, stop_before_ea=target_ea
        )
        return final_state.get_register(initial_reg)

    # -- fixpoint machinery -------------------------------------------------------------
    def _join_predecessor_states(self, cfg, block, out_states, entry_block, initial_state) -> AbstractState | None:
        if block.start_ea == entry_block.start_ea:
            return initial_state
        preds = cfg.predecessors(block)
        available = [out_states[p.start_ea] for p in preds if p.start_ea in out_states]
        if not available:
            return None
        return self._join_states(available)

    @staticmethod
    def _join_states(states: list[AbstractState]) -> AbstractState:
        result = AbstractState()
        reg_keys: set[int] = set()
        stack_keys: set = set()
        for s in states:
            reg_keys.update(s.registers.keys())
            stack_keys.update(s.stack.keys())
        for reg in reg_keys:
            result.set_register(reg, join_all(s.get_register(reg) for s in states))
        for key in stack_keys:
            result.set_stack(key, join_all(s.get_stack(key) for s in states))
        return result

    @staticmethod
    def _widen(prev_state: AbstractState, new_state: AbstractState) -> AbstractState:
        result = AbstractState()
        for reg in set(prev_state.registers) | set(new_state.registers):
            pv, nv = prev_state.get_register(reg), new_state.get_register(reg)
            result.set_register(reg, pv if pv == nv else unknown(UnknownReason.LOOP_NON_CONVERGENT))
        for key in set(prev_state.stack) | set(new_state.stack):
            pv, nv = prev_state.get_stack(key), new_state.get_stack(key)
            result.set_stack(key, pv if pv == nv else unknown(UnknownReason.LOOP_NON_CONVERGENT))
        return result

    def _simulate_block(
        self,
        block: BasicBlockInfo,
        in_state: AbstractState,
        func_ea: int,
        budget: dict,
        stop_before_ea: int | None = None,
    ) -> tuple[AbstractState, bool]:
        state = in_state.copy()
        ea = block.start_ea
        while ea < block.end_ea:
            if stop_before_ea is not None and ea >= stop_before_ea:
                break
            instr = self.cache.get(ea)
            if instr is None:
                ea += 1
                continue
            budget["instr"] += 1
            if budget["instr"] > self.max_instructions:
                return state, True
            state = self._step(instr, state, func_ea)
            ea = instr.next_ea
        return state, False

    # -- per-instruction transfer function -----------------------------------------------
    def _step(self, instr: Instruction, state: AbstractState, func_ea: int) -> AbstractState:
        dst_mem_op = None
        src_mem_op = None
        for op in instr.operands:
            if not op.is_memory:
                continue
            if instr.is_written(op.number):
                dst_mem_op = op
            else:
                src_mem_op = op

        if dst_mem_op is not None:
            key = self._stack_key(dst_mem_op, instr.ea, func_ea)
            if key is not None:
                source = self._other_operand(instr, dst_mem_op)
                state.set_stack(key, self._value_of_source(source, state))
            return state

        if src_mem_op is not None:
            dst_reg = self._register_destination(instr)
            if dst_reg is not None:
                key = self._stack_key(src_mem_op, instr.ea, func_ea)
                if key is not None:
                    state.set_register(dst_reg.reg, state.get_stack(key))
                else:
                    state.invalidate_register(dst_reg.reg, UnknownReason.UNSUPPORTED_INSTRUCTION)
            return state

        locator = self.registry.match(instr)
        if locator is not None:
            try:
                return locator.apply_forward(instr, state)
            except Exception:
                _logger.exception("Locator %s raised in apply_forward on %s at %#x", locator.name, instr.mnem, instr.ea)

        for op in instr.operands:
            if op.kind is OperandKind.REG and instr.is_written(op.number):
                state.invalidate_register(op.reg, UnknownReason.UNSUPPORTED_INSTRUCTION)
        return state

    def _stack_key(self, op: Operand, ea: int, func_ea: int) -> tuple | None:
        if op.kind not in (OperandKind.MEM_DISPL, OperandKind.MEM_PHRASE) or op.reg is None:
            return None
        sp_reg = self.port.stack_pointer_reg()
        if sp_reg is not None and op.reg == sp_reg:
            delta = self.port.get_sp_delta(func_ea, ea)
            if delta is None:
                return None
            return ("sp", delta + op.disp)
        fp_reg = self.port.frame_pointer_reg()
        if fp_reg is not None and op.reg == fp_reg:
            return ("fp", op.disp)
        return None

    @staticmethod
    def _other_operand(instr: Instruction, exclude: Operand) -> Operand | None:
        for candidate in instr.operands:
            if candidate.number != exclude.number:
                return candidate
        return None

    @staticmethod
    def _value_of_source(op: Operand | None, state: AbstractState) -> ValueLattice:
        if op is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE)
        if op.kind is OperandKind.REG:
            return state.get_register(op.reg)
        if op.kind is OperandKind.IMMEDIATE:
            return Concrete(op.imm_value, ValueKind.INT)
        return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE)

    @staticmethod
    def _register_destination(instr: Instruction) -> Operand | None:
        for op in instr.operands:
            if op.kind is OperandKind.REG and instr.is_written(op.number):
                return op
        return None
