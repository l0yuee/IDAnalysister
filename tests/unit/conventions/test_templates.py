from idanalysister.conventions.base import SlotKind
from idanalysister.conventions.templates import CDECL, FASTCALL, MS_X64, SYSV_X64, by_name

from ..conftest import ECX, EDX


def test_cdecl_all_stack_push(port):
    slots = CDECL.slots(3, port)
    assert [s.kind for s in slots] == [SlotKind.STACK_PUSH] * 3
    assert [s.stack_push_position for s in slots] == [0, 1, 2]


def test_fastcall_first_two_registers_rest_push(port):
    slots = FASTCALL.slots(3, port)
    assert slots[0].kind is SlotKind.REGISTER and slots[0].reg == ECX
    assert slots[1].kind is SlotKind.REGISTER and slots[1].reg == EDX
    assert slots[2].kind is SlotKind.STACK_PUSH and slots[2].stack_push_position == 0


def test_ms_x64_four_registers_then_shadow_space_offset(port64):
    slots = MS_X64.slots(5, port64)
    assert all(s.kind is SlotKind.REGISTER for s in slots[:4])
    assert slots[4].kind is SlotKind.STACK_OFFSET
    assert slots[4].stack_offset == 0x20


def test_sysv_x64_six_registers_then_stack_from_zero(port64):
    slots = SYSV_X64.slots(7, port64)
    assert all(s.kind is SlotKind.REGISTER for s in slots[:6])
    assert slots[6].kind is SlotKind.STACK_OFFSET
    assert slots[6].stack_offset == 0


def test_by_name_lookup():
    assert by_name("cdecl") is CDECL
    try:
        by_name("nonexistent")
        assert False, "expected KeyError"
    except KeyError:
        pass
