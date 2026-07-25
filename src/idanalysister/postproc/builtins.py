"""Built-in post-processors: dereference-to-C-string, dereference-to-UTF-16
string, hex formatting, integer cast, and fixed-offset struct field access.
Covers the built-in minimum from requirement 3.2.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.values import Concrete, MemoryRef, ValueKind, ValueLattice, unknown
from idanalysister.postproc.base import PostProcessor

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort


def _address_of(value: ValueLattice) -> int | None:
    """Best-effort: treat a `Concrete` int, or a `MemoryRef`'s dereferenced
    int content, as a candidate pointer to read further — this is what
    lets a post-processor dereference a value that was itself the content
    of a prior memory read (e.g. a global holding a string pointer)."""
    if isinstance(value, Concrete) and isinstance(value.value, int):
        return value.value
    if isinstance(value, MemoryRef) and isinstance(value.value, Concrete) and isinstance(value.value.value, int):
        return value.value.value
    return None


class CStringDeref(PostProcessor):
    name = "c_string"

    def __init__(self, max_len: int = 4096):
        self.max_len = max_len

    def process(self, value: ValueLattice, port: "IdaPort") -> ValueLattice:
        addr = _address_of(value)
        if addr is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="not a pointer-shaped value")
        text = port.read_cstring(addr, self.max_len)
        if text is None:
            return unknown(UnknownReason.MEMORY_READ_FAILED, detail=f"no C string at {addr:#x}")
        return Concrete(text, ValueKind.STRING)


class WideStringDeref(PostProcessor):
    name = "wide_string"

    def __init__(self, max_len: int = 4096):
        self.max_len = max_len

    def process(self, value: ValueLattice, port: "IdaPort") -> ValueLattice:
        addr = _address_of(value)
        if addr is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="not a pointer-shaped value")
        text = port.read_wstring(addr, self.max_len)
        if text is None:
            return unknown(UnknownReason.MEMORY_READ_FAILED, detail=f"no UTF-16 string at {addr:#x}")
        return Concrete(text, ValueKind.STRING)


class HexFormat(PostProcessor):
    name = "hex_format"

    def process(self, value: ValueLattice, port: "IdaPort") -> ValueLattice:
        if not isinstance(value, Concrete) or not isinstance(value.value, int):
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="not an integer value")
        sign = "-" if value.value < 0 else ""
        return Concrete(f"{sign}{abs(value.value):#x}", ValueKind.STRING)


class IntCast(PostProcessor):
    """Coerces a value to a plain integer, unwrapping one level of
    `MemoryRef` if needed."""

    name = "int_cast"

    def process(self, value: ValueLattice, port: "IdaPort") -> ValueLattice:
        addr = _address_of(value)
        if addr is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="not an integer-shaped value")
        return Concrete(addr, ValueKind.INT)


class StructFieldDeref(PostProcessor):
    """Reads an integer field at a fixed byte `offset` from a pointer
    value — for pulling one field out of a struct argument without a full
    type system."""

    name = "struct_field"

    def __init__(self, offset: int, size: int, signed: bool = False):
        self.offset = offset
        self.size = size
        self.signed = signed

    def process(self, value: ValueLattice, port: "IdaPort") -> ValueLattice:
        base = _address_of(value)
        if base is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="not a pointer-shaped value")
        addr = base + self.offset
        raw = port.read_int(addr, self.size, self.signed)
        if raw is None:
            return unknown(UnknownReason.MEMORY_READ_FAILED, detail=f"no data at {addr:#x}")
        return Concrete(raw, ValueKind.INT)
