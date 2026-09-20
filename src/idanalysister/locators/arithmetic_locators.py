"""Simple constant-foldable arithmetic on registers.

Not explicitly named in requirement 3.1's form list, but `lea reg,
[base+disp]` (address computation) and `add/sub reg, imm` (pointer/index
adjustment) are extremely common between a register's initial load and its
use as an argument — without folding them, the backward resolver would
report `Unknown` for a large fraction of real-world register-indirect and
pointer-arithmetic call sites. Folding is intentionally limited to
compile-time-constant operands; anything else defers to the operand's own
resolution or yields `Unknown`, matching the "constant-fold simple
arithmetic, don't guess" requirement from 3.3 (this module is shared by
both the backward resolver and, via `apply_forward`, the forward engine).
"""

from __future__ import annotations

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.insn_model import Instruction, OperandKind
from idanalysister.core.state import AbstractState
from idanalysister.core.values import Concrete, ValueKind, unknown
from idanalysister.locators._common import wrap_to_width
from idanalysister.locators.base import Locator, LocatorOutcome, LocatorRegistry, ResolutionContext


def _int_of(value) -> int | None:
    return value.value if isinstance(value, Concrete) and isinstance(value.value, int) else None


class LeaRegDisplLocator(Locator):
    """`lea reg, [base+disp]` — address computation, not a dereference."""

    name = "lea_reg_displ"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem != "lea":
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return (
            dst is not None
            and src is not None
            and dst.kind is OperandKind.REG
            and src.kind in (OperandKind.MEM_DISPL, OperandKind.MEM_PHRASE)
            and src.reg is not None
            # `lea eax, [ebx+ecx*4]` depends on a runtime index; folding it
            # as `ebx+0` would fabricate a pointer to the wrong element.
            and not src.has_index
        )

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        dst, src = instr.operand(0), instr.operand(1)
        base = ctx.resolve_register(src.reg, instr.ea)
        base_int = _int_of(base)
        if base_int is None:
            return LocatorOutcome.resolved(base if not base.is_known else unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE))
        return LocatorOutcome.resolved(
            Concrete(wrap_to_width(base_int + src.disp, dst.dtype_size), ValueKind.POINTER)
        )

    def apply_forward(self, instr: Instruction, state: AbstractState) -> AbstractState:
        dst, src = instr.operand(0), instr.operand(1)
        if src.kind not in (OperandKind.MEM_DISPL, OperandKind.MEM_PHRASE) or src.reg is None:
            state.invalidate_register(dst.reg, UnknownReason.UNSUPPORTED_INSTRUCTION)
            return state
        base = state.get_register(src.reg)
        base_int = _int_of(base)
        if base_int is None:
            state.set_register(dst.reg, base if not base.is_known else unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE))
            return state
        state.set_register(
            dst.reg, Concrete(wrap_to_width(base_int + src.disp, dst.dtype_size), ValueKind.POINTER)
        )
        return state


class AddSubRegImmLocator(Locator):
    """`add reg, imm` / `sub reg, imm` — in-place adjustment by a constant."""

    name = "add_sub_reg_imm"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem not in ("add", "sub"):
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return dst is not None and src is not None and dst.kind is OperandKind.REG and src.kind is OperandKind.IMMEDIATE

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        dst, src = instr.operand(0), instr.operand(1)
        prior = ctx.resolve_register(dst.reg, instr.ea)
        prior_int = _int_of(prior)
        if prior_int is None:
            return LocatorOutcome.resolved(prior)
        delta = src.imm_value if instr.mnem == "add" else -src.imm_value
        return LocatorOutcome.resolved(
            Concrete(wrap_to_width(prior_int + delta, dst.dtype_size), ValueKind.INT)
        )

    def apply_forward(self, instr: Instruction, state: AbstractState) -> AbstractState:
        dst, src = instr.operand(0), instr.operand(1)
        prior = state.get_register(dst.reg)
        prior_int = _int_of(prior)
        if prior_int is None:
            state.set_register(dst.reg, prior if not prior.is_known else unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE))
            return state
        delta = src.imm_value if instr.mnem == "add" else -src.imm_value
        state.set_register(dst.reg, Concrete(wrap_to_width(prior_int + delta, dst.dtype_size), ValueKind.INT))
        return state


def register_builtins(registry: LocatorRegistry) -> None:
    registry.register(LeaRegDisplLocator())
    registry.register(AddSubRegImmLocator())
