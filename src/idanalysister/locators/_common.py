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


#: Register width to assume when IDA could not size an operand. Folding
#: without *any* wraparound would let a subtraction underflow into a
#: nonsensical huge/negative address, so a default is safer than none.
_DEFAULT_REGISTER_WIDTH = 8


def wrap_to_width(value: int, size_bytes: int) -> int:
    """Wrap an arithmetic result to the unsigned bit pattern a register of
    `size_bytes` would actually hold.

    Immediates arrive as the unsigned value of their own width (`add ebx,
    -8` is `0xFFFFFFF8`, the encoding the CPU really adds), so folding has
    to wrap the same way the hardware does or the result is off by a power
    of two."""
    width = size_bytes if size_bytes and 0 < size_bytes <= 8 else _DEFAULT_REGISTER_WIDTH
    return value & ((1 << (width * 8)) - 1)


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
