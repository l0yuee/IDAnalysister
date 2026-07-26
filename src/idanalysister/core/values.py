"""The value lattice used throughout the framework.

Every resolution result — a call-site argument, an intra-function forward
query, a dereferenced memory read — is one of these four shapes. Downstream
code (post-processors, merge logic, the public API) pattern-matches on type
instead of guessing what a bare `None` meant, and every "could not resolve"
outcome carries an explicit reason (see `core.diagnostics.UnknownReason`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from idanalysister.core.diagnostics import UnknownReason


class ValueKind(Enum):
    """A coarse hint about what a `Concrete.value` represents, used by
    post-processors and formatting — not a full type system."""

    INT = auto()
    POINTER = auto()
    STRING = auto()
    BYTES = auto()
    UNKNOWN_KIND = auto()


class ValueLattice:
    """Base class for the value lattice: `Unknown`, `Concrete`, `MemoryRef`,
    `Symbolic`, `MutatedRegion`. Never instantiated directly."""

    __slots__ = ()

    @property
    def is_known(self) -> bool:
        return not isinstance(self, Unknown)


@dataclass(frozen=True)
class Unknown(ValueLattice):
    """The value could not be statically determined. `reason` is always
    present so failures are auditable rather than a silent black box."""

    reason: UnknownReason
    detail: str = ""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        suffix = f": {self.detail}" if self.detail else ""
        return f"Unknown({self.reason.name}{suffix})"


@dataclass(frozen=True)
class Concrete(ValueLattice):
    """A fully resolved compile-time value: an immediate, a folded
    arithmetic result, or the content read from memory."""

    value: Any
    kind: ValueKind = ValueKind.INT

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Concrete({self.value!r}, {self.kind.name})"


@dataclass(frozen=True)
class MemoryRef(ValueLattice):
    """A resolved memory dereference. `addr` is where the value was read
    from; `value` is what was found there (usually `Concrete`, but `Unknown`
    if the read failed). Both are retained — if `value` is itself a pointer
    (e.g. to a string), post-processors can dereference it further without
    the original address having been discarded."""

    addr: int
    value: ValueLattice

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"MemoryRef(addr={self.addr:#x}, value={self.value!r})"


@dataclass(frozen=True)
class Symbolic(ValueLattice):
    """A value that is provably tracked through data flow but not reducible
    to a compile-time constant, e.g. ``"arg0"`` (the incoming value of
    argument 0, unmodified so far) or ``"ret(0x4010a0)"`` (the return value
    of a specific call site)."""

    expr: str

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Symbolic({self.expr!r})"


@dataclass(frozen=True)
class MutatedRegion(ValueLattice):
    """Memory relative to a symbolic base pointer was written through a
    non-constant offset/index (typically inside a loop, e.g. a decryption
    loop indexed by a counter). Distinct from `Unknown`: the *pointer* that
    identifies this region may still be fully known even though its
    contents are not tracked precisely. Decrypting/interpreting the content
    is the documented job of a user-supplied post-processor, not the
    generic engine."""

    base_expr: str
    via: str = ""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"MutatedRegion(base={self.base_expr!r}, via={self.via!r})"


def unknown(reason: UnknownReason, detail: str = "") -> Unknown:
    """Convenience constructor mirroring the common call pattern."""
    return Unknown(reason=reason, detail=detail)
