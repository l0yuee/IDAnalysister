"""Abstract-interpreter state for `core.engine_forward.ForwardSymbolicEngine`.

Lives in `core/` (rather than next to the forward engine) purely to break an
import cycle: `locators.base.Locator.apply_forward` needs this type, and
`locators` must not depend on `core.engine_forward` (which depends on
`locators` for registry dispatch).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.values import Unknown, ValueLattice


@dataclass
class AbstractState:
    """A snapshot of tracked register and stack-slot values at one point in
    a forward walk. Untracked locations implicitly read as `Unknown` rather
    than requiring every register to be pre-populated."""

    registers: dict[int, ValueLattice] = field(default_factory=dict)
    stack: dict[int, ValueLattice] = field(default_factory=dict)  # frame-relative offset -> value

    def copy(self) -> AbstractState:
        return AbstractState(dict(self.registers), dict(self.stack))

    def get_register(self, reg: int) -> ValueLattice:
        return self.registers.get(reg, Unknown(UnknownReason.NO_DEFINITION_FOUND))

    def set_register(self, reg: int, value: ValueLattice) -> None:
        self.registers[reg] = value

    def invalidate_register(
        self, reg: int, reason: UnknownReason = UnknownReason.UNSUPPORTED_INSTRUCTION
    ) -> None:
        self.registers[reg] = Unknown(reason)

    def get_stack(self, offset: int) -> ValueLattice:
        return self.stack.get(offset, Unknown(UnknownReason.NO_DEFINITION_FOUND))

    def set_stack(self, offset: int, value: ValueLattice) -> None:
        self.stack[offset] = value
