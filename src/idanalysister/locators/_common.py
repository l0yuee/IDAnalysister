"""Shared helper for locators that need to read a memory operand.

Not a `Locator` itself — used by any locator whose source operand is a
memory reference (register loads, pushes, register-indirect writes) to
route through `ResolutionContext.resolve_memory`, which is what performs
the mandatory "final dereferenced value, not the address" behavior and the
local-write-shadowing search.
"""

from __future__ import annotations

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.insn_model import Operand, OperandKind
from idanalysister.core.values import ValueLattice, unknown
from idanalysister.locators.base import ResolutionContext


def load_memory_operand(op: Operand, ctx: ResolutionContext, before_ea: int) -> ValueLattice:
    """Resolve the value referenced by a memory operand of any shape."""
    size = op.dtype_size or ctx.port.pointer_size()
    if op.kind is OperandKind.MEM_DIRECT:
        return ctx.resolve_memory(None, op.addr, before_ea, size)
    if op.kind in (OperandKind.MEM_PHRASE, OperandKind.MEM_DISPL):
        if op.reg is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE)
        return ctx.resolve_memory(op.reg, op.disp, before_ea, size)
    return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE)
