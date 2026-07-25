"""`ArgSlot` + `CallingConvention` interface.

A `CallingConvention` is deliberately just a mapping from argument index to
*where the value lives* — resolving that location to an actual value is
`core.engine_backward.BackwardResolver`'s job. This keeps conventions pure
declarative data (or a small function of `num_args`/`port`), which is what
lets users "combine argument locating strategies" (per the requirement)
without writing resolver code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort


class SlotKind(Enum):
    #: Value lives in a fixed register at call time.
    REGISTER = auto()
    #: Value is the Nth-from-the-top element of a contiguous `push`
    #: sequence immediately preceding the call (0 = the last instruction
    #: pushed before the call, i.e. the topmost stack value / the
    #: leftmost not-yet-in-a-register argument in a right-to-left push
    #: order).
    STACK_PUSH = auto()
    #: Value lives at a fixed byte offset from the stack pointer at the
    #: moment of the call (written via `mov [esp+N], ...` rather than a
    #: `push`, or reported directly by IDA's type system).
    STACK_OFFSET = auto()


@dataclass(frozen=True)
class ArgSlot:
    index: int
    kind: SlotKind
    reg: int | None = None  # for SlotKind.REGISTER
    stack_push_position: int | None = None  # for SlotKind.STACK_PUSH — see SlotKind docstring
    stack_offset: int | None = None  # for SlotKind.STACK_OFFSET


class CallingConvention(ABC):
    """A named strategy for locating each argument of a call."""

    name: str = "convention"

    @abstractmethod
    def slots(self, num_args: int, port: "IdaPort") -> list[ArgSlot]:
        """The `ArgSlot` for each argument index `0..num_args-1`. `port` is
        available for translating register names to processor-specific
        register numbers; implementations that already carry concrete
        `ArgSlot`s (e.g. built from an inferred prototype) may ignore it."""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<CallingConvention {self.name}>"
