"""Pure decoding helpers for IDA's raw operand encoding.

Deliberately free of any `ida_*` import: everything here is arithmetic on
values `adapters.ida_port_impl` has already pulled out of `ida_ua.op_t` /
`ida_ua.insn_t`, which is what lets `tests/unit` cover the trickiest part
of the adapter (x86 SIB reconstruction) without an IDA installation, while
`ida_port_impl` stays the only module that touches IDA itself.

Two encoding details of IDA's x86 operands are handled here, both of which
are silently lossy if taken at face value:

* **SIB addressing.** For `o_phrase`/`o_displ` operands that carry a SIB
  byte, `op_t.reg`/`op_t.phrase` does *not* hold the base register — it
  holds the ModRM "a SIB byte follows" marker (`R_sp`, i.e. 4, plus 8 when
  `REX.B` is set). The real base, index and scale live in the SIB byte
  (`op_t.specflag2`, valid when `op_t.specflag1` is set) combined with the
  `REX.X`/`REX.B` bits of the instruction's REX prefix (`insn_t.insnpref`).
  Reading `op_t.reg` directly therefore reports `[ebx+ecx*4]` as `[esp+0]`
  — a *stack-pointer-relative* access — and drops the index entirely.

* **Width.** IDA widens `op_t.addr` (displacement) and `op_t.value`
  (immediate) to a sign-extended 64-bit `ea_t`/`uval_t` regardless of the
  database's bitness, so `[ebp-8]` arrives as `0xFFFFFFFFFFFFFFF8` and
  `push -4` as `0xFFFFFFFFFFFFFFFC` even in a 32-bit database. A
  displacement is meaningful as a *signed* offset; an immediate is
  meaningful as the *unsigned* bit pattern of the operand's own width.
"""

from __future__ import annotations

#: ModRM r/m value meaning "a SIB byte follows" — the same number as the
#: stack pointer register, which is why an undecoded SIB operand looks like
#: a stack access.
_SIB_MARKER_REG = 4

#: SIB `index` field value meaning "no index register". Only meaningful
#: when `REX.X` is clear: with `REX.X` set the same encoding names `r12`,
#: which *is* a usable index register.
_SIB_NO_INDEX = 4

_REX_B = 0x01  # extends the SIB base (and ModRM r/m) register
_REX_X = 0x02  # extends the SIB index register
_REX_PREFIX_MASK = 0xF0
_REX_PREFIX_VALUE = 0x40


def rex_bits(insn_prefix: int | None) -> int:
    """The REX byte of an x86-64 instruction, or 0 when there is none.

    `insn_t.insnpref` carries the REX prefix on x86-64 and is 0 in 32-bit
    databases; anything that isn't a REX byte (0x40..0x4F) is ignored so
    this stays harmless on processors that use `insnpref` differently.
    """
    if not insn_prefix:
        return 0
    if (insn_prefix & _REX_PREFIX_MASK) != _REX_PREFIX_VALUE:
        return 0
    return insn_prefix


def decode_sib(sib_byte: int, rex: int) -> tuple[int, int | None, int]:
    """Split a SIB byte into `(base_reg, index_reg, scale)`.

    Register numbers come back in IDA's own numbering, which for x86-64
    matches the hardware encoding (0..7 = rax..rdi, 8..15 = r8..r15), so
    the `REX.B`/`REX.X` extension bits are simply folded in. `index_reg` is
    `None` when the operand has no index term.
    """
    scale = 1 << ((sib_byte >> 6) & 3)
    index_bits = (sib_byte >> 3) & 7
    base_bits = sib_byte & 7

    base_reg = base_bits | (8 if rex & _REX_B else 0)
    if index_bits == _SIB_NO_INDEX and not (rex & _REX_X):
        return base_reg, None, scale
    return base_reg, index_bits | (8 if rex & _REX_X else 0), scale


def memory_operand_addressing(
    op_reg: int, has_sib: bool, sib_byte: int, rex: int
) -> tuple[int, int | None, int]:
    """`(base_reg, index_reg, scale)` for an `o_phrase`/`o_displ` operand.

    Without a SIB byte the ModRM r/m register IDA reports *is* the base and
    there can be no index. With one, everything comes from the SIB byte.
    """
    if not has_sib:
        return op_reg, None, 1
    return decode_sib(sib_byte, rex)


def sign_extend(value: int, bits: int = 64) -> int:
    """Interpret `value` as a two's-complement integer of `bits` bits."""
    if value is None:
        return 0
    mask = (1 << bits) - 1
    value &= mask
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def unsigned_of_width(value: int, size_bytes: int) -> int:
    """Truncate `value` to the unsigned bit pattern of a `size_bytes`-wide
    operand. A `size_bytes` of 0 (IDA could not size the operand) leaves
    the value untouched rather than guessing a width."""
    if value is None:
        return 0
    if not size_bytes or size_bytes <= 0 or size_bytes > 8:
        return value
    return value & ((1 << (size_bytes * 8)) - 1)
