"""Public result dataclasses returned by `api.facade.ParamExtractor`."""

from __future__ import annotations

from dataclasses import dataclass

from idanalysister.core.values import ValueLattice


@dataclass(frozen=True)
class ArgumentResult:
    index: int
    #: The value as directly resolved by the backward/forward engine,
    #: before any post-processing (still fully dereferenced per the "never
    #: return a bare address" requirement — this is not "raw bytes", it's
    #: "raw *before user-declared type interpretation*").
    raw_value: ValueLattice
    #: `raw_value` after running the `ArgTypeSpec`-bound post-processor
    #: chain, if one was declared for this index; identical to `raw_value`
    #: otherwise.
    processed_value: ValueLattice
    label: str | None = None
    #: Which engine ultimately produced `raw_value`: `"raw"` (the default
    #: instruction-level backward resolver) or `"hexrays_fallback"` (the
    #: optional Hex-Rays cross-check, only ever used when the raw walk
    #: itself returned `Unknown` and `ParamExtractor(use_hexrays_fallback=True)`
    #: — see `adapters.hexrays_backend`). Never silently blended: a caller
    #: can always tell which engine is responsible for a given value.
    source: str = "raw"

    @property
    def is_known(self) -> bool:
        return self.processed_value.is_known


@dataclass(frozen=True)
class CallSiteResult:
    call_ea: int
    func_ea: int
    arguments: tuple[ArgumentResult, ...]

    def argument(self, index: int) -> ArgumentResult | None:
        for arg in self.arguments:
            if arg.index == index:
                return arg
        return None


@dataclass(frozen=True)
class ExtractionReport:
    func_ea: int
    call_sites: tuple[CallSiteResult, ...]

    @property
    def call_count(self) -> int:
        return len(self.call_sites)
