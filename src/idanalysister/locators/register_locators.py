"""Register-destination instruction forms.

Covers requirement 3.1 form #1 (register direct passing: `mov ecx, value`)
and most of form #9's named examples (`xchg`, `cmov`, `movsx`/`movzx`,
`lea`). Memory-*source* loads into a register (`mov eax, dword_403000`,
`mov eax, [ebp-4]`) live in `locators.memory_locators` since their matching
key is the source operand's memory shape, not the destination.
"""

from __future__ import annotations

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.insn_model import Instruction, OperandKind
from idanalysister.core.merge import join
from idanalysister.core.state import AbstractState
from idanalysister.core.values import Concrete, ValueKind, unknown
from idanalysister.locators.base import Locator, LocatorOutcome, LocatorRegistry, ResolutionContext

_MOVE_MNEMONICS = ("mov", "movzx", "movsx", "movsxd")


class MovRegRegLocator(Locator):
    """`mov reg, reg2` (and the widening `movzx`/`movsx` reg,reg2 forms) —
    chase the source register's prior value. Bit-width truncation/extension
    is not modeled precisely; the underlying integer value is passed
    through, which is sufficient for the pointer/handle-passing cases this
    framework targets."""

    name = "mov_reg_reg"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem not in _MOVE_MNEMONICS:
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return (
            dst is not None
            and src is not None
            and dst.kind is OperandKind.REG
            and src.kind is OperandKind.REG
        )

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        src = instr.operand(1)
        value = ctx.resolve_register(src.reg, instr.ea)
        return LocatorOutcome.resolved(value)

    def apply_forward(self, instr: Instruction, state: AbstractState) -> AbstractState:
        dst, src = instr.operand(0), instr.operand(1)
        state.set_register(dst.reg, state.get_register(src.reg))
        return state


class MovRegImmLocator(Locator):
    """`mov reg, imm` — the immediate is the resolved value directly."""

    name = "mov_reg_imm"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem != "mov":
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return (
            dst is not None
            and src is not None
            and dst.kind is OperandKind.REG
            and src.kind is OperandKind.IMMEDIATE
        )

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        src = instr.operand(1)
        return LocatorOutcome.resolved(Concrete(src.imm_value, ValueKind.INT))

    def apply_forward(self, instr: Instruction, state: AbstractState) -> AbstractState:
        dst, src = instr.operand(0), instr.operand(1)
        state.set_register(dst.reg, Concrete(src.imm_value, ValueKind.INT))
        return state


class LeaRegAddrLocator(Locator):
    """`lea reg, [absolute_global]` — takes the *address*, never
    dereferences (unlike `mov`), so the resolved value is the address
    itself, retained as a pointer for post-processors to dereference
    further (e.g. a string pointer)."""

    name = "lea_reg_addr"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem != "lea":
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return (
            dst is not None
            and src is not None
            and dst.kind is OperandKind.REG
            and src.kind is OperandKind.MEM_DIRECT
        )

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        src = instr.operand(1)
        return LocatorOutcome.resolved(Concrete(src.addr, ValueKind.POINTER))

    def apply_forward(self, instr: Instruction, state: AbstractState) -> AbstractState:
        dst, src = instr.operand(0), instr.operand(1)
        state.set_register(dst.reg, Concrete(src.addr, ValueKind.POINTER))
        return state


class XchgRegRegLocator(Locator):
    """`xchg reg1, reg2` — both operands are simultaneously read and
    written, so whichever one the resolver is chasing, its pre-instruction
    value came from the *other* operand."""

    name = "xchg_reg_reg"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem != "xchg":
            return False
        a, b = instr.operand(0), instr.operand(1)
        return a is not None and b is not None and a.kind is OperandKind.REG and b.kind is OperandKind.REG

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        other = instr.operand(1 - dest_operand)
        if other is None or other.kind is not OperandKind.REG:
            return LocatorOutcome.not_applicable()
        value = ctx.resolve_register(other.reg, instr.ea)
        return LocatorOutcome.resolved(value)

    def apply_forward(self, instr: Instruction, state: AbstractState) -> AbstractState:
        a, b = instr.operand(0), instr.operand(1)
        va, vb = state.get_register(a.reg), state.get_register(b.reg)
        state.set_register(a.reg, vb)
        state.set_register(b.reg, va)
        return state


class CmovRegRegLocator(Locator):
    """`cmovCC reg, reg2` — the move only happens if the condition holds,
    and the condition's outcome is not statically decidable from a pure
    backward data-flow walk. Reporting a guessed value here would violate
    the framework's "never guess" contract, so this is treated as a
    genuine divergence between the "moved" and "not moved" outcomes."""

    name = "cmov_reg_reg"

    def matches(self, instr: Instruction) -> bool:
        if not instr.mnem.startswith("cmov"):
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return dst is not None and src is not None and dst.kind is OperandKind.REG

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        return LocatorOutcome.resolved(
            unknown(
                UnknownReason.DIVERGENT_PATHS,
                detail=f"{instr.mnem} at {instr.ea:#x}: condition not statically evaluable",
            )
        )

    def apply_forward(self, instr: Instruction, state: AbstractState) -> AbstractState:
        # Forward direction: the move may or may not have executed, so the
        # post-instruction value is the join of "moved" and "didn't move" —
        # exactly the same "never guess, join on divergence" rule applied
        # to a condition collapsed into one instruction rather than a
        # branch.
        dst, src = instr.operand(0), instr.operand(1)
        state.set_register(dst.reg, join(state.get_register(dst.reg), state.get_register(src.reg)))
        return state


def register_builtins(registry: LocatorRegistry) -> None:
    registry.register(MovRegRegLocator())
    registry.register(MovRegImmLocator())
    registry.register(LeaRegAddrLocator())
    registry.register(XchgRegRegLocator())
    registry.register(CmovRegRegLocator())
