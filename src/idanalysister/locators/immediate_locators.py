"""Immediate-source instruction forms.

Covers requirement 3.1 form #2 (immediate direct passing): `push 0x1234`
(handled by `locators.stack_locators.PushLocator`, since push is always a
stack operation) and `mov [esp], 0x5678` / `mov dword_403000, 0x5678`
(handled here) — a memory write whose source is a compile-time constant.
This is one of the write-side locators `core.engine_backward`'s
`resolve_memory` matches against when it finds the nearest prior write to a
queried memory location.
"""

from __future__ import annotations

from idanalysister.core.insn_model import Instruction, OperandKind
from idanalysister.core.values import Concrete, ValueKind
from idanalysister.locators.base import Locator, LocatorOutcome, LocatorRegistry, ResolutionContext


class MovMemImmLocator(Locator):
    name = "mov_mem_imm"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem != "mov":
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return dst is not None and src is not None and dst.is_memory and src.kind is OperandKind.IMMEDIATE

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        src = instr.operand(1)
        return LocatorOutcome.resolved(Concrete(src.imm_value, ValueKind.INT))


def register_builtins(registry: LocatorRegistry) -> None:
    registry.register(MovMemImmLocator())
