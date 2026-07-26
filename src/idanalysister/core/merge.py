"""Lattice join rules shared by the backward resolver and forward engine.

`join` implements the "never guess" contract at control-flow merge points:
two paths agreeing on a concrete value is safe to report; disagreeing paths
— even both being individually fully known — must not be silently resolved
to one of them or averaged, since a wrong concrete answer is worse than an
honest `Unknown` for a reverse engineer.
"""

from __future__ import annotations

from typing import Iterable

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.values import (
    Concrete,
    MemoryRef,
    MutatedRegion,
    Symbolic,
    Unknown,
    ValueLattice,
    unknown,
)


def join(a: ValueLattice, b: ValueLattice) -> ValueLattice:
    if isinstance(a, Unknown):
        return a
    if isinstance(b, Unknown):
        return b
    if isinstance(a, Concrete) and isinstance(b, Concrete):
        if a.value == b.value and a.kind == b.kind:
            return a
        return unknown(UnknownReason.DIVERGENT_PATHS, detail=f"{a.value!r} vs {b.value!r}")
    if isinstance(a, Symbolic) and isinstance(b, Symbolic):
        if a.expr == b.expr:
            return a
        return unknown(UnknownReason.DIVERGENT_SYMBOLIC, detail=f"{a.expr!r} vs {b.expr!r}")
    if isinstance(a, MemoryRef) and isinstance(b, MemoryRef):
        if a.addr == b.addr:
            return MemoryRef(addr=a.addr, value=join(a.value, b.value))
        return unknown(UnknownReason.DIVERGENT_PATHS, detail=f"{a.addr:#x} vs {b.addr:#x}")
    if isinstance(a, MutatedRegion) and isinstance(b, MutatedRegion):
        if a.base_expr == b.base_expr:
            return a
        return unknown(UnknownReason.DIVERGENT_SYMBOLIC, detail=f"{a.base_expr!r} vs {b.base_expr!r}")
    # Different lattice shapes entirely (e.g. Concrete vs Symbolic) — no
    # sound way to reconcile without deeper reasoning.
    return unknown(UnknownReason.DIVERGENT_PATHS, detail=f"{a!r} vs {b!r}")


def join_all(values: Iterable[ValueLattice]) -> ValueLattice:
    values = list(values)
    if not values:
        return unknown(UnknownReason.NO_DEFINITION_FOUND)
    result = values[0]
    for value in values[1:]:
        result = join(result, value)
    return result
