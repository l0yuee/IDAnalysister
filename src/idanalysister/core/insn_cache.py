"""Memoizes instruction decoding and cross-reference lookups.

Backward/forward walks repeatedly re-decode the same handful of addresses
(e.g. re-visiting a loop header, or re-querying a call site's neighborhood);
this cache is what keeps single call-site extraction within the <100ms
target and satisfies the "cache instruction decode + xref results"
non-functional requirement. It is owned by one `IdaPort` for the lifetime of
an analysis session (see `api.facade.ParamExtractor`) and is a bounded LRU so
long interactive sessions don't grow memory unboundedly.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TypeVar

from idanalysister.adapters.ida_port import IdaPort
from idanalysister.core.insn_model import Instruction

_K = TypeVar("_K")
_V = TypeVar("_V")


class InstructionCache:
    def __init__(self, port: IdaPort, max_entries: int = 4096):
        self._port = port
        self._max_entries = max_entries
        self._insn_cache: OrderedDict[int, Instruction | None] = OrderedDict()
        self._xref_cache: OrderedDict[int, tuple[int, ...]] = OrderedDict()

    def get(self, ea: int) -> Instruction | None:
        cached = self._lookup(self._insn_cache, ea)
        if cached is not _SENTINEL:
            return cached
        insn = self._port.decode_at(ea)
        self._store(self._insn_cache, ea, insn)
        return insn

    def code_refs_to(self, ea: int) -> tuple[int, ...]:
        cached = self._lookup(self._xref_cache, ea)
        if cached is not _SENTINEL:
            return cached
        refs = self._port.code_refs_to(ea)
        self._store(self._xref_cache, ea, refs)
        return refs

    def invalidate(self, ea: int | None = None) -> None:
        """Drop cached entries. `None` flushes everything; call this if the
        underlying IDB changes during a long-lived session."""
        if ea is None:
            self._insn_cache.clear()
            self._xref_cache.clear()
            return
        self._insn_cache.pop(ea, None)
        self._xref_cache.pop(ea, None)

    def _lookup(self, cache: OrderedDict[_K, _V], key: _K) -> _V:
        if key not in cache:
            return _SENTINEL  # type: ignore[return-value]
        cache.move_to_end(key)
        return cache[key]

    def _store(self, cache: OrderedDict[_K, _V], key: _K, value: _V) -> None:
        cache[key] = value
        cache.move_to_end(key)
        if len(cache) > self._max_entries:
            cache.popitem(last=False)


class _Sentinel:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "<not cached>"


_SENTINEL = _Sentinel()
