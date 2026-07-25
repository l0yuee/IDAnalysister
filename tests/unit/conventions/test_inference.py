from idanalysister.conventions.base import SlotKind
from idanalysister.conventions.inference import PrototypeConvention, infer
from idanalysister.core.ida_types import ArgLocation, FunctionPrototype

from ..conftest import ECX, EDX

FUNC = 0x401000


def make_prototype():
    return FunctionPrototype(
        calling_convention="fastcall",
        arg_locations=(
            ArgLocation(index=0, is_register=True, reg=ECX, reg_name="ecx"),
            ArgLocation(index=1, is_register=False, stack_offset=0x8),
        ),
    )


def test_prototype_convention_maps_register_and_stack_slots(port):
    convention = PrototypeConvention(make_prototype())
    assert convention.arg_count == 2
    slots = convention.slots(2, port)
    assert slots[0].kind is SlotKind.REGISTER and slots[0].reg == ECX
    assert slots[1].kind is SlotKind.STACK_OFFSET and slots[1].stack_offset == 0x8


def test_prototype_convention_missing_index_is_unresolved_not_guessed(port):
    convention = PrototypeConvention(make_prototype())
    slots = convention.slots(3, port)  # index 2 has no declared location
    assert slots[2].kind is SlotKind.REGISTER and slots[2].reg is None


def test_infer_returns_none_without_prototype(port):
    assert infer(FUNC, port) is None


def test_infer_builds_convention_from_port_prototype(port):
    port.set_prototype(FUNC, make_prototype())
    convention = infer(FUNC, port)
    assert convention is not None
    assert convention.arg_count == 2
