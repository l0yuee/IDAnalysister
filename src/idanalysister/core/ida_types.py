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


@dataclass(frozen=True)
class RegisterView:
    """One addressable *view* of a processor register.

    x86 register numbering is not one-number-per-register: `al`/`ah` get
    their own numbers (16/20 on x86) while `ax`/`eax`/`rax` all share
    number 0 and are told apart only by the operand's decoded size. Both
    shapes break naive "does this instruction write register N" matching —
    the first makes a write to `al` invisible as a write to `eax`, the
    second makes a write to `ax` look like a full write to `eax`.

    `parent` is the widest register this view belongs to, so views can be
    compared for identity, and `bit_offset`/`bit_size` say which part of it
    this view actually covers.
    """

    parent: int
    bit_offset: int
    bit_size: int
    parent_bit_size: int
    #: Whether *writing* this view leaves the whole parent register with a
    #: statically known value: either the view is the entire parent, or the
    #: ISA defines the rest to be cleared (x86-64 zeroes the upper 32 bits
    #: on any 32-bit-operand write). Only the adapter knows this rule, so it
    #: is decided there rather than re-derived in the analysis core.
    write_defines_parent: bool = False

    @property
    def is_whole_parent(self) -> bool:
        return self.bit_offset == 0 and self.bit_size >= self.parent_bit_size
