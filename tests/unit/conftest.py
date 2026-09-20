"""Shared fixtures/builders for the unit test suite — all pure-Python,
exercised against `adapters.fake_port.FakeIdaPort`, no IDA installation
required.
"""

import sys
from pathlib import Path

import pytest

# Allow running `pytest` directly against a source checkout without an
# editable install.
_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from idanalysister.adapters.fake_port import FakeIdaPort
from idanalysister.core.insn_model import Instruction, Operand, OperandKind

# Register numbers matching FakeIdaPort.DEFAULT_REGISTERS.
EAX = RAX = 0
ECX = RCX = 1
EDX = RDX = 2
EBX = RBX = 3
ESP = RSP = 4
EBP = RBP = 5
ESI = RSI = 6
EDI = RDI = 7
R8 = 8
R9 = 9


@pytest.fixture
def port():
    return FakeIdaPort(pointer_size=4)


@pytest.fixture
def port64():
    return FakeIdaPort(pointer_size=8)


def reg(number, register, size=4):
    return Operand(kind=OperandKind.REG, number=number, reg=register, dtype_size=size)


def imm(number, value, size=4):
    return Operand(kind=OperandKind.IMMEDIATE, number=number, imm_value=value, dtype_size=size)


def mem_direct(number, addr, size=4, segment_name=None):
    return Operand(kind=OperandKind.MEM_DIRECT, number=number, addr=addr, dtype_size=size, segment_name=segment_name)


def mem_displ(number, base_reg, disp, size=4):
    return Operand(kind=OperandKind.MEM_DISPL, number=number, reg=base_reg, disp=disp, dtype_size=size)


def mem_phrase(number, base_reg, size=4):
    return Operand(kind=OperandKind.MEM_PHRASE, number=number, reg=base_reg, disp=0, dtype_size=size)


def mem_index(number, base_reg, index_reg, scale=4, disp=0, size=4):
    """`[base + index*scale + disp]` — the indexed addressing form whose
    index used to be silently dropped by the adapter."""
    return Operand(
        kind=OperandKind.MEM_DISPL if disp else OperandKind.MEM_PHRASE,
        number=number,
        reg=base_reg,
        index_reg=index_reg,
        scale=scale,
        disp=disp,
        dtype_size=size,
    )


def insn(ea, mnem, size, operands, written=None, read=None, itype=1, is_control_transfer=None):
    """`written` defaults to True for operand 0 only (the common case),
    False elsewhere — pass an explicit tuple to override.

    `read` mirrors IDA's `CF_USE1..CF_USE8` and defaults to the `mov`-like
    shape: every operand is read except a written operand 0. Instructions
    that update their destination in place (`add eax, 4`, `add [ebp-8],
    ecx`) must pass it explicitly as `read=(True, True)` — the engines use
    written-and-not-read to tell a plain assignment apart from a
    read-modify-write, and defaulting it wrong here would hide exactly the
    bug that distinction exists to prevent.

    `is_control_transfer` defaults to True for call/jmp/j<cc>/ret mnemonics
    (mirroring IDA's own CF_CALL|CF_JUMP|CF_STOP feature bits) and False
    otherwise — pass an explicit bool to override."""
    if written is None:
        written = tuple(i == 0 for i in range(len(operands)))
    if read is None:
        read = tuple(not (i == 0 and written[i]) for i in range(len(operands)))
    if is_control_transfer is None:
        is_control_transfer = mnem.startswith(("call", "jmp", "j", "ret"))
    return Instruction(
        ea=ea,
        mnem=mnem,
        itype=itype,
        size=size,
        operands=tuple(operands),
        operand_written=written,
        operand_read=read,
        is_control_transfer=is_control_transfer,
    )
