import pytest

from idanalysister.conventions.base import SlotKind
from idanalysister.conventions.custom_builder import ConventionBuilder
from idanalysister.errors import ConventionError

from ..conftest import ECX, EDX


def test_custom_convention_combines_reg_and_stack(port):
    convention = (
        ConventionBuilder("my_convention")
        .reg(0, "ecx")
        .reg(1, "edx")
        .stack_offset(2, 0x28)
        .stack_push(3, 0)
        .build()
    )
    slots = convention.slots(4, port)
    assert slots[0].kind is SlotKind.REGISTER and slots[0].reg == ECX
    assert slots[1].kind is SlotKind.REGISTER and slots[1].reg == EDX
    assert slots[2].kind is SlotKind.STACK_OFFSET and slots[2].stack_offset == 0x28
    assert slots[3].kind is SlotKind.STACK_PUSH and slots[3].stack_push_position == 0


def test_custom_convention_missing_slot_raises_configuration_error(port):
    convention = ConventionBuilder("incomplete").reg(0, "ecx").build()
    with pytest.raises(ConventionError):
        convention.slots(2, port)
