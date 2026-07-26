"""idanalysister — declarative argument extraction and intra-function value
resolution framework for IDA Pro.

The only symbols most users need are re-exported here; internal modules
(`core`, `locators`, `adapters`, ...) are implementation detail and may change
without notice.
"""

from idanalysister.api.facade import ParamExtractor
from idanalysister.api.results import ArgumentResult, CallSiteResult
from idanalysister.conventions.templates import (
    CDECL,
    FASTCALL,
    MS_X64,
    STDCALL,
    SYSV_X64,
    THISCALL,
)
from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.values import Concrete, MemoryRef, Symbolic, Unknown, ValueLattice
from idanalysister.typespec.argtype import ArgTypeSpec

__all__ = [
    "ParamExtractor",
    "CallSiteResult",
    "ArgumentResult",
    "ArgTypeSpec",
    "ValueLattice",
    "Unknown",
    "Concrete",
    "MemoryRef",
    "Symbolic",
    "UnknownReason",
    "CDECL",
    "STDCALL",
    "FASTCALL",
    "THISCALL",
    "MS_X64",
    "SYSV_X64",
]
