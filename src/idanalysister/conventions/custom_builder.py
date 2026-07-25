"""Fluent builder for user-declared calling conventions.

Satisfies "users may freely combine argument locating strategies to
describe any custom calling convention" — purely declarative, no new
resolver code required:

    convention = (
        ConventionBuilder("my_convention")
        .reg(0, "rcx")
        .reg(1, "rdx")
        .stack_offset(2, 0x28)
        .build()
    )
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idanalysister.conventions.base import ArgSlot, CallingConvention, SlotKind
from idanalysister.errors import ConventionError

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort


class _CustomConvention(CallingConvention):
    def __init__(self, name: str, slot_specs: dict[int, ArgSlot], register_names: dict[int, str]):
        self.name = name
        self._slot_specs = slot_specs
        self._register_names = register_names

    def slots(self, num_args: int, port: "IdaPort") -> list[ArgSlot]:
        result: list[ArgSlot] = []
        for index in range(num_args):
            if index in self._register_names:
                reg = port.register_by_name(self._register_names[index])
                result.append(ArgSlot(index=index, kind=SlotKind.REGISTER, reg=reg))
            elif index in self._slot_specs:
                result.append(self._slot_specs[index])
            else:
                raise ConventionError(
                    f"convention {self.name!r} has no slot declared for argument index {index}"
                )
        return result


class ConventionBuilder:
    def __init__(self, name: str = "custom"):
        self._name = name
        self._slot_specs: dict[int, ArgSlot] = {}
        self._register_names: dict[int, str] = {}

    def reg(self, index: int, register_name: str) -> "ConventionBuilder":
        self._register_names[index] = register_name
        return self

    def stack_offset(self, index: int, offset: int) -> "ConventionBuilder":
        self._slot_specs[index] = ArgSlot(index=index, kind=SlotKind.STACK_OFFSET, stack_offset=offset)
        return self

    def stack_push(self, index: int, position: int) -> "ConventionBuilder":
        """`position` counts from the top of the (non-register) push
        sequence at call time: 0 = the first stack argument (the last one
        pushed, i.e. closest to the call instruction)."""
        self._slot_specs[index] = ArgSlot(index=index, kind=SlotKind.STACK_PUSH, stack_push_position=position)
        return self

    def build(self) -> CallingConvention:
        return _CustomConvention(self._name, dict(self._slot_specs), dict(self._register_names))
