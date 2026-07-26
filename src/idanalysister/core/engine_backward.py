"""Backward def-use resolver — drives call-site argument extraction (3.1).

Given a register, or a memory location described as `(base_reg, disp)`, and
a point in the program to resolve it as-used-at, `BackwardResolver` walks
backward through the owning function's control-flow graph looking for the
nearest definition, delegating interpretation of each candidate defining
instruction to whichever `Locator` matches it (`locators.base`). Multiple
predecessor paths are joined via `core.merge.join`; the walk is bounded by a
per-query `ResolutionBudget` so a pathological CFG fails closed quickly
rather than hanging, and every "couldn't resolve" outcome carries a
`core.diagnostics.UnknownReason`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from idanalysister.core.cfg_model import CfgModel, build_cfg
from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.ida_types import BasicBlockInfo
from idanalysister.core.insn_cache import InstructionCache
from idanalysister.core.insn_model import Instruction, OperandKind
from idanalysister.core.merge import join_all
from idanalysister.core.values import Concrete, MemoryRef, ValueKind, ValueLattice, unknown
from idanalysister.locators.base import LocatorOutcome, LocatorRegistry, ResolutionContext
from idanalysister.logging_ import get_logger

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort

_logger = get_logger("core.engine_backward")

#: Safety cap on a contiguous push-sequence scan, independent of the
#: general step budget (push sequences are always short in practice; this
#: only guards against a pathological run of `push` mnemonics).
_MAX_PUSH_SEQUENCE = 64

#: Safety cap on how many non-push instructions `collect_push_sequence` will
#: skip over looking for more pushes, independent of the general step
#: budget — bounds the cost of scanning through unrelated code once the
#: push sequence has clearly ended.
_MAX_TRANSPARENT_SKIP = 16


def _is_transparent_to_push_sequence(instr: Instruction, sp_reg: int | None) -> bool:
    """Whether `instr` can be skipped over while scanning backward for a
    push sequence without treating it as ending that sequence: it must not
    alter control flow (call/jmp/ret/...) and must not write to the stack
    pointer register or to stack-pointer-relative memory (which would mean
    it's itself adjusting/using the stack in a way `collect_push_sequence`
    doesn't model, e.g. a `mov [esp+N], reg` argument write — the
    STACK_OFFSET convention path handles that shape, not this one)."""
    if instr.is_control_transfer:
        return False
    if sp_reg is None:
        return True
    for op in instr.operands:
        if not instr.is_written(op.number):
            continue
        if op.kind is OperandKind.REG and op.reg == sp_reg:
            return False
        if op.is_memory and op.reg == sp_reg:
            return False
    return True


class _NotFound:
    """Sentinel distinguishing "no local write found, caller should decide
    on a fallback" from a resolved `Unknown` value (which must be returned
    as-is, not overridden by a fallback)."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "<not found>"


_NOT_FOUND = _NotFound()


@dataclass
class ResolutionBudget:
    """Per-top-level-query bound shared across every recursive callback a
    walk triggers (including locators calling back into the resolver),
    ensuring one argument's resolution can never run unbounded."""

    max_steps: int = 200
    max_blocks: int = 64
    steps_used: int = field(default=0, init=False)
    blocks_used: int = field(default=0, init=False)

    def step(self) -> bool:
        self.steps_used += 1
        return self.steps_used <= self.max_steps

    def step_block(self) -> bool:
        self.blocks_used += 1
        return self.blocks_used <= self.max_blocks


class BackwardResolver:
    def __init__(
        self,
        port: "IdaPort",
        cache: InstructionCache,
        registry: LocatorRegistry,
        max_steps: int = 200,
        max_blocks: int = 64,
    ):
        self.port = port
        self.cache = cache
        self.registry = registry
        self._max_steps = max_steps
        self._max_blocks = max_blocks
        self._budget = ResolutionBudget(max_steps, max_blocks)
        self._func_cache: dict[int, int | None] = {}
        self._cfg_cache: dict[int, CfgModel] = {}

    # -- public API -----------------------------------------------------------------
    def resolve_register(self, reg: int, before_ea: int) -> ValueLattice:
        self._budget = ResolutionBudget(self._max_steps, self._max_blocks)
        return self._resolve_register_impl(reg, before_ea)

    def resolve_memory(self, base_reg: int | None, disp: int, before_ea: int, size: int) -> ValueLattice:
        self._budget = ResolutionBudget(self._max_steps, self._max_blocks)
        return self._resolve_memory_impl(base_reg, disp, before_ea, size)

    def resolve_at_instruction(self, ea: int, dest_operand: int = 0) -> ValueLattice:
        self._budget = ResolutionBudget(self._max_steps, self._max_blocks)
        return self._resolve_at_instruction_impl(ea, dest_operand)

    def dereference(self, addr: int, size: int) -> ValueLattice:
        if not self._budget.step():
            return unknown(UnknownReason.BUDGET_EXCEEDED)
        raw = self.port.read_int(addr, size)
        if raw is None:
            return MemoryRef(addr=addr, value=unknown(UnknownReason.MEMORY_READ_FAILED))
        return MemoryRef(addr=addr, value=Concrete(raw, ValueKind.INT))

    def collect_push_sequence(self, call_ea: int) -> list[int]:
        """Addresses of `push` instructions preceding `call_ea`, in program
        (chronological) order — the last element is the push closest to the
        call. Non-`push` instructions interleaved between them are skipped
        transparently as long as they don't touch the stack pointer or
        alter control flow (see `_is_transparent_to_push_sequence`) — real
        compiler output very commonly inserts unrelated bookkeeping (e.g.
        MSVC's `/EHsc` unwind-state tracking, `mov [ebp+var], N`) between
        the last argument push and the call itself."""
        func_ea = self._func_ea_for(call_ea)
        if func_ea is None:
            return []
        sp_reg = self.port.stack_pointer_reg()
        pushes: list[int] = []
        skipped = 0
        ea = self.port.prev_head(call_ea, func_ea)
        while ea is not None and len(pushes) < _MAX_PUSH_SEQUENCE and skipped < _MAX_TRANSPARENT_SKIP:
            instr = self.cache.get(ea)
            if instr is None:
                break
            if instr.mnem == "push":
                pushes.append(ea)
                ea = self.port.prev_head(ea, func_ea)
                continue
            if _is_transparent_to_push_sequence(instr, sp_reg):
                skipped += 1
                ea = self.port.prev_head(ea, func_ea)
                continue
            break
        pushes.reverse()
        return pushes

    # -- register resolution ----------------------------------------------------------
    def _resolve_register_impl(self, reg: int, before_ea: int) -> ValueLattice:
        if reg is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="no register to resolve")
        if not self._budget.step():
            return unknown(UnknownReason.BUDGET_EXCEEDED)
        func_ea = self._func_ea_for(before_ea)
        if func_ea is None:
            return unknown(UnknownReason.NO_DEFINITION_FOUND, detail="no owning function")
        cfg = self._cfg_for(func_ea)
        block = cfg.block_containing(before_ea) if not cfg.is_empty() else None
        if block is None:
            return self._walk_register_linear(reg, before_ea, func_ea)
        return self._walk_register_block(reg, before_ea, block, func_ea, cfg, frozenset())

    def _walk_register_linear(self, reg: int, boundary_ea: int, func_ea: int) -> ValueLattice:
        ea = self.port.prev_head(boundary_ea, func_ea)
        while ea is not None:
            if not self._budget.step():
                return unknown(UnknownReason.BUDGET_EXCEEDED)
            instr = self.cache.get(ea)
            if instr is not None:
                result = self._match_register_definition(instr, reg, func_ea)
                if result is not None:
                    return result
            ea = self.port.prev_head(ea, func_ea)
        return unknown(UnknownReason.NO_DEFINITION_FOUND)

    def _walk_register_block(
        self,
        reg: int,
        boundary_ea: int,
        block: BasicBlockInfo,
        func_ea: int,
        cfg: CfgModel,
        visited_blocks: frozenset,
    ) -> ValueLattice:
        ea = self.port.prev_head(boundary_ea, block.start_ea)
        while ea is not None:
            if not self._budget.step():
                return unknown(UnknownReason.BUDGET_EXCEEDED)
            instr = self.cache.get(ea)
            if instr is not None:
                result = self._match_register_definition(instr, reg, func_ea)
                if result is not None:
                    return result
            ea = self.port.prev_head(ea, block.start_ea)
        if block.start_ea in visited_blocks:
            return unknown(UnknownReason.BUDGET_EXCEEDED, detail="cyclic backward path")
        preds = cfg.predecessors(block)
        if not preds:
            return unknown(UnknownReason.NO_DEFINITION_FOUND)
        if not self._budget.step_block():
            return unknown(UnknownReason.BUDGET_EXCEEDED)
        next_visited = visited_blocks | {block.start_ea}
        results = [
            self._walk_register_block(reg, pred.end_ea, pred, func_ea, cfg, next_visited) for pred in preds
        ]
        return join_all(results)

    def _match_register_definition(self, instr: Instruction, reg: int, func_ea: int) -> ValueLattice | None:
        for op in instr.operands:
            if op.kind is OperandKind.REG and op.reg == reg and instr.is_written(op.number):
                return self._interpret_definition(instr, op.number, func_ea)
        if instr.mnem.startswith("call") and reg == self.port.return_value_reg():
            return self._interpret_definition(instr, 0, func_ea)
        return None

    # -- memory resolution --------------------------------------------------------------
    def _resolve_memory_impl(self, base_reg: int | None, disp: int, before_ea: int, size: int) -> ValueLattice:
        if not self._budget.step():
            return unknown(UnknownReason.BUDGET_EXCEEDED)
        func_ea = self._func_ea_for(before_ea)
        found: ValueLattice | _NotFound = _NOT_FOUND
        if func_ea is not None:
            query_key = self._normalize_memory_key(base_reg, disp, before_ea, func_ea)
            cfg = self._cfg_for(func_ea)
            block = cfg.block_containing(before_ea) if not cfg.is_empty() else None
            if block is None:
                found = self._walk_memory_linear(query_key, before_ea, func_ea)
            else:
                found = self._walk_memory_block(query_key, before_ea, block, func_ea, cfg, frozenset())
        if found is not _NOT_FOUND:
            return found
        return self._fallback_dereference(base_reg, disp, before_ea, size)

    def _walk_memory_linear(self, query_key: tuple, boundary_ea: int, func_ea: int):
        ea = self.port.prev_head(boundary_ea, func_ea)
        while ea is not None:
            if not self._budget.step():
                return unknown(UnknownReason.BUDGET_EXCEEDED)
            instr = self.cache.get(ea)
            if instr is not None:
                result = self._match_memory_definition(instr, query_key, func_ea)
                if result is not None:
                    return result
            ea = self.port.prev_head(ea, func_ea)
        return _NOT_FOUND

    def _walk_memory_block(
        self,
        query_key: tuple,
        boundary_ea: int,
        block: BasicBlockInfo,
        func_ea: int,
        cfg: CfgModel,
        visited_blocks: frozenset,
    ):
        ea = self.port.prev_head(boundary_ea, block.start_ea)
        while ea is not None:
            if not self._budget.step():
                return unknown(UnknownReason.BUDGET_EXCEEDED)
            instr = self.cache.get(ea)
            if instr is not None:
                result = self._match_memory_definition(instr, query_key, func_ea)
                if result is not None:
                    return result
            ea = self.port.prev_head(ea, block.start_ea)
        if block.start_ea in visited_blocks:
            return _NOT_FOUND
        preds = cfg.predecessors(block)
        if not preds:
            return _NOT_FOUND
        if not self._budget.step_block():
            return unknown(UnknownReason.BUDGET_EXCEEDED)
        next_visited = visited_blocks | {block.start_ea}
        results = [
            self._walk_memory_block(query_key, pred.end_ea, pred, func_ea, cfg, next_visited) for pred in preds
        ]
        found = [r for r in results if r is not _NOT_FOUND]
        if not found:
            return _NOT_FOUND
        if len(found) != len(results):
            return unknown(
                UnknownReason.DIVERGENT_PATHS,
                detail="memory location defined on some incoming paths but not others",
            )
        return join_all(found)

    def _match_memory_definition(self, instr: Instruction, query_key: tuple, func_ea: int) -> ValueLattice | None:
        for op in instr.operands:
            if not op.is_memory or not instr.is_written(op.number):
                continue
            if op.kind is OperandKind.MEM_DIRECT:
                key = self._normalize_memory_key(None, op.addr, instr.ea, func_ea)
            elif op.reg is not None:
                key = self._normalize_memory_key(op.reg, op.disp, instr.ea, func_ea)
            else:
                continue
            if key != query_key:
                continue
            return self._interpret_definition(instr, op.number, func_ea)
        return None

    def _normalize_memory_key(self, base_reg: int | None, disp: int, ea: int, func_ea: int) -> tuple:
        if base_reg is None:
            return ("abs", disp)
        sp_reg = self.port.stack_pointer_reg()
        if sp_reg is not None and base_reg == sp_reg:
            delta = self.port.get_sp_delta(func_ea, ea)
            if delta is None:
                return ("sp-unknown", base_reg, disp, ea)
            return ("sp", delta + disp)
        fp_reg = self.port.frame_pointer_reg()
        if fp_reg is not None and base_reg == fp_reg:
            return ("fp", disp)
        return ("reg", base_reg, disp)

    def _fallback_dereference(self, base_reg: int | None, disp: int, before_ea: int, size: int) -> ValueLattice:
        if base_reg is None:
            return self.dereference(disp, size)
        base_val = self._resolve_register_impl(base_reg, before_ea)
        base_int = base_val.value if isinstance(base_val, Concrete) and isinstance(base_val.value, int) else None
        if base_int is None:
            return unknown(UnknownReason.NO_DEFINITION_FOUND)
        return self.dereference(base_int + disp, size)

    # -- shared instruction interpretation -----------------------------------------------
    def _resolve_at_instruction_impl(self, ea: int, dest_operand: int) -> ValueLattice:
        if not self._budget.step():
            return unknown(UnknownReason.BUDGET_EXCEEDED)
        instr = self.cache.get(ea)
        if instr is None:
            return unknown(UnknownReason.NO_DEFINITION_FOUND, detail=f"failed to decode {ea:#x}")
        func_ea = self._func_ea_for(ea)
        return self._interpret_definition(instr, dest_operand, func_ea)

    def _interpret_definition(self, instr: Instruction, dest_operand: int, func_ea: int | None) -> ValueLattice:
        locator = self.registry.match(instr)
        if locator is None:
            return unknown(UnknownReason.UNSUPPORTED_INSTRUCTION, detail=f"{instr.mnem} at {instr.ea:#x}")
        ctx = self._make_context(func_ea)
        outcome = self._safe_extract(locator, instr, dest_operand, ctx)
        if not outcome.is_resolved:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail=f"{instr.mnem} at {instr.ea:#x}")
        return outcome.value

    def _safe_extract(self, locator, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        try:
            return locator.extract(instr, dest_operand, ctx)
        except Exception:
            _logger.exception("Locator %s raised on %s at %#x", locator.name, instr.mnem, instr.ea)
            return LocatorOutcome.not_applicable()

    def _make_context(self, func_ea: int | None) -> ResolutionContext:
        return ResolutionContext(
            port=self.port,
            cache=self.cache,
            func_ea=func_ea,
            resolve_register=self._resolve_register_impl,
            resolve_memory=self._resolve_memory_impl,
            dereference=self.dereference,
        )

    # -- caching ----------------------------------------------------------------------------
    def _func_ea_for(self, ea: int) -> int | None:
        if ea in self._func_cache:
            return self._func_cache[ea]
        func_ea = self.port.get_func_start(ea)
        self._func_cache[ea] = func_ea
        return func_ea

    def _cfg_for(self, func_ea: int) -> CfgModel:
        if func_ea in self._cfg_cache:
            return self._cfg_cache[func_ea]
        cfg = build_cfg(self.port, func_ea)
        self._cfg_cache[func_ea] = cfg
        return cfg
