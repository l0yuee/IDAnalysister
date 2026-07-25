"""Stack-passing instruction forms: `push` and register-sourced memory
writes.

Covers requirement 3.1 form #4 (stack passing via `push` sequences) and
form #5 (stack passing via `mov [esp+N], reg` writes after `sub esp,N`).
`PushLocator` also directly satisfies the `push ebx` example in form #1 and
the `push 0x1234` example in form #2, since push's source operand can be
any shape (register/immediate/memory) and is handled uniformly here.
`MovMemRegLocator` is the register-source counterpart of
`locators.immediate_locators.MovMemImmLocator` — together they cover every
"write a value to a memory cell" shape `core.engine_backward.resolve_memory`
searches for, whether that cell is a stack slot, a global, or a
register-indirect struct/array field (requirement form #6).
"""

from __future__ import annotations

from idanalysister.core.insn_model import Instruction, OperandKind
from idanalysister.core.values import Concrete, ValueKind
from idanalysister.locators._common import load_memory_operand
from idanalysister.locators.base import Locator, LocatorOutcome, LocatorRegistry, ResolutionContext


class PushLocator(Locator):
    """`push X` for any operand shape `X`: register, immediate, or memory."""

    name = "push"

    def matches(self, instr: Instruction) -> bool:
        return instr.mnem == "push" and instr.operand(0) is not None

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        op = instr.operand(0)
        if op.kind is OperandKind.REG:
            return LocatorOutcome.resolved(ctx.resolve_register(op.reg, instr.ea))
        if op.kind is OperandKind.IMMEDIATE:
            return LocatorOutcome.resolved(Concrete(op.imm_value, ValueKind.INT))
        if op.is_memory:
            return LocatorOutcome.resolved(load_memory_operand(op, ctx, instr.ea))
        return LocatorOutcome.not_applicable()


class MovMemRegLocator(Locator):
    """`mov [mem], reg` — a register value written to a memory cell
    (stack slot, global, or register-indirect field)."""

    name = "mov_mem_reg"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem != "mov":
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return dst is not None and src is not None and dst.is_memory and src.kind is OperandKind.REG

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        src = instr.operand(1)
        return LocatorOutcome.resolved(ctx.resolve_register(src.reg, instr.ea))


def register_builtins(registry: LocatorRegistry) -> None:
    registry.register(PushLocator())
    registry.register(MovMemRegLocator())
