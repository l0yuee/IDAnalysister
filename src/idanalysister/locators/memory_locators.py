"""Memory-source instruction forms: loading a register from a memory
operand in any addressing-mode shape.

Covers requirement 3.1 form #3 (memory indirect passing — absolute global,
`[ebp-4]`, `[rsp+0x20]`), form #6 (register indirect addressing,
`[eax+0x10]`), and form #7 (global/TLS passing, `gs:[0x30]`). All of these
decode to the same three `OperandKind` memory shapes; the actual "resolve
the base, normalize the offset, and prefer the nearest local write over the
IDB's static bytes" logic lives in `core.engine_backward` behind
`ResolutionContext.resolve_memory` — this module only has to recognize the
instruction shape and hand the source operand off.
"""

from __future__ import annotations

from idanalysister.core.insn_model import Instruction, OperandKind
from idanalysister.locators._common import load_memory_operand
from idanalysister.locators.base import Locator, LocatorOutcome, LocatorRegistry, ResolutionContext

_MOVE_MNEMONICS = ("mov", "movzx", "movsx", "movsxd")


class MovRegMemLocator(Locator):
    name = "mov_reg_mem"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem not in _MOVE_MNEMONICS:
            return False
        dst, src = instr.operand(0), instr.operand(1)
        return dst is not None and src is not None and dst.kind is OperandKind.REG and src.is_memory

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        src = instr.operand(1)
        return LocatorOutcome.resolved(load_memory_operand(src, ctx, instr.ea))


def register_builtins(registry: LocatorRegistry) -> None:
    registry.register(MovRegMemLocator())
