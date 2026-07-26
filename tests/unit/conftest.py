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


def insn(ea, mnem, size, operands, written=None, itype=1):
    """`written` defaults to True for operand 0 only (the common case),
    False elsewhere — pass an explicit tuple to override."""
    if written is None:
        written = tuple(i == 0 for i in range(len(operands)))
    return Instruction(ea=ea, mnem=mnem, itype=itype, size=size, operands=tuple(operands), operand_written=written)
