"""`adapters.ida_operand_decode`: the x86 SIB reconstruction and operand
width normalization that `adapters.ida_port_impl` depends on.

Every `(phrase, specflag2, insnpref)` triple below was captured from a real
IDA 9.3 analysis of an assembled binary, so these are golden tests against
IDA's actual encoding rather than against an assumption about it. They live
in `tests/unit` because the module under test is deliberately free of any
`ida_*` import — the IDA-importing side is covered by `tests/integration`.
"""

import pytest

from idanalysister.adapters.ida_operand_decode import (
    decode_sib,
    memory_operand_addressing,
    rex_bits,
    sign_extend,
    unsigned_of_width,
)

# IDA register numbers: 0..7 = ax/cx/dx/bx/sp/bp/si/di, 8..15 = r8..r15.
AX, CX, DX, BX, SP, BP, SI, DI = range(8)
R10, R11, R12 = 10, 11, 12


@pytest.mark.parametrize(
    "asm, phrase, sib, insnpref, expected",
    [
        # 32-bit: `mov eax, [ebx+ecx*4]`. The phrase field is the ModRM
        # SIB marker (4 == esp), NOT the base — reading it directly is what
        # made this operand look like a stack access.
        ("mov eax, [ebx+ecx*4]", SP, 0x8B, 0, (BX, CX, 4)),
        # 32-bit: `mov edi, [esp+ecx*4+8]` — base really is esp here, but
        # there is still an index that must not be dropped.
        ("mov edi, [esp+ecx*4+8]", SP, 0x8C, 0, (SP, CX, 4)),
        # 64-bit: `mov rax, [rbx+rcx*8]`.
        ("mov rax, [rbx+rcx*8]", SP, 0xCB, 0x48, (BX, CX, 8)),
        # 64-bit: `mov rdx, [rsp+0x20]` — a plain stack access still needs
        # a SIB byte to encode rsp as the base, and has no index.
        ("mov rdx, [rsp+0x20]", SP, 0x24, 0x48, (SP, None, 1)),
        # 64-bit: `mov rdi, [r10+r11*8]` — REX.B extends the base and
        # REX.X the index; the phrase field becomes 12, naming neither.
        ("mov rdi, [r10+r11*8]", R12, 0xDA, 0x4B, (R10, R11, 8)),
    ],
)
def test_sib_decoding_matches_real_ida_encodings(asm, phrase, sib, insnpref, expected):
    assert memory_operand_addressing(phrase, True, sib, rex_bits(insnpref)) == expected


def test_operand_without_sib_uses_the_modrm_register_as_base():
    # `mov r8, [r10+0x18]` needs no SIB byte, so IDA's register field is
    # already the base and there can be no index.
    assert memory_operand_addressing(R10, False, 0, rex_bits(0x4D)) == (R10, None, 1)


def test_index_four_is_no_index_only_without_rex_x():
    # index bits 100b mean "no index"... unless REX.X makes it r12, which
    # is a perfectly usable index register.
    assert decode_sib(0x24, rex=0x00)[1] is None
    assert decode_sib(0x24, rex=0x02)[1] == R12


def test_rex_bits_ignores_non_rex_prefixes():
    assert rex_bits(0) == 0
    assert rex_bits(None) == 0
    assert rex_bits(0x66) == 0  # operand-size prefix, not REX
    assert rex_bits(0x4B) == 0x4B


def test_negative_displacements_are_sign_extended():
    # IDA widens `[ebp-8]` to a 64-bit ea_t even in a 32-bit database.
    assert sign_extend(0xFFFFFFFFFFFFFFF8) == -8
    assert sign_extend(0xFFFFFFFFFFFFFFF0) == -16
    assert sign_extend(0x20) == 0x20
    assert sign_extend(0) == 0


def test_immediates_are_narrowed_to_the_operand_width():
    # `push -4`, `mov eax, -1` and `mov ecx, 0x80000000` all arrive
    # sign-extended to 64 bits from a 32-bit database.
    assert unsigned_of_width(0xFFFFFFFFFFFFFFFC, 4) == 0xFFFFFFFC
    assert unsigned_of_width(0xFFFFFFFFFFFFFFFF, 4) == 0xFFFFFFFF
    assert unsigned_of_width(0xFFFFFFFF80000000, 4) == 0x80000000
    assert unsigned_of_width(0xFFFFFFFFFFFFFFFF, 1) == 0xFF
    assert unsigned_of_width(0x1234, 8) == 0x1234


def test_unknown_operand_width_leaves_the_value_alone():
    # Better an unnarrowed value than one truncated to a guessed width.
    assert unsigned_of_width(0xFFFFFFFFFFFFFFFC, 0) == 0xFFFFFFFFFFFFFFFC
