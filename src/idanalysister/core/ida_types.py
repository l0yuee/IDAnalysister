"""Plain, `ida_*`-free data shapes returned by `adapters.ida_port.IdaPort`.

These live in `core/` (not `adapters/`) because both the adapter
implementations and the consumers (`core.cfg_model`, `conventions.inference`)
need them, and `adapters` must stay a dependency leaf.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BasicBlockInfo:
    """One basic block of a function's control-flow graph."""

    start_ea: int
    end_ea: int  # exclusive
    succ_starts: tuple[int, ...]
    pred_starts: tuple[int, ...]


@dataclass(frozen=True)
class ArgLocation:
    """Where a single argument lives, as reported by IDA's type system
    (`ida_typeinf.func_type_data_t` / `argloc_t`)."""

    index: int
    is_register: bool
    reg: int | None = None  # processor register number, if is_register
    reg_name: str | None = None
    stack_offset: int | None = None  # offset from the argument area base, if not a register


@dataclass(frozen=True)
class FunctionPrototype:
    """A recognized function prototype, normalized for calling-convention
    inference (`conventions.inference`)."""

    calling_convention: str  # "cdecl" | "stdcall" | "fastcall" | "thiscall" | "ms_x64" | "sysv_x64" | "unknown"
    arg_locations: tuple[ArgLocation, ...]
    is_variadic: bool = False
