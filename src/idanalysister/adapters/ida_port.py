"""The entire `ida_*` surface the framework touches, behind one interface.

No module outside `adapters/` may import an `ida_*` module directly; every
IDA interaction goes through an instance of `IdaPort`, injected by the
composition root (`api.facade.ParamExtractor`). See `adapters.ida_port_impl`
for the concrete implementation backed by real IDA modules, and
`adapters.fake_port` for the in-memory test double used by `tests/unit`.

Every method is documented as returning `None` (or an empty tuple) on
failure rather than raising — implementations are expected to catch and log
underlying `ida_*` exceptions themselves, so the analysis core never has to
guard against them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from idanalysister.core.ida_types import BasicBlockInfo, FunctionPrototype, RegisterView
from idanalysister.core.insn_model import Instruction


class IdaPort(ABC):
    # -- instruction decoding -------------------------------------------------
    @abstractmethod
    def decode_at(self, ea: int) -> Instruction | None:
        """Decode the instruction at `ea`. Returns `None` if decoding fails
        or `ea` is not the start of a valid instruction."""

    @abstractmethod
    def prev_head(self, ea: int, min_ea: int) -> int | None:
        """Address of the previous instruction head strictly before `ea`,
        not going below `min_ea` (typically the owning function's start).
        Returns `None` if there is none."""

    # -- cross references -------------------------------------------------------
    @abstractmethod
    def code_refs_to(self, ea: int) -> tuple[int, ...]:
        """Addresses of all `call` instructions that target `ea` (near or
        far calls only — not ordinary jumps or fall-through flow)."""

    # -- functions / control flow ------------------------------------------------
    @abstractmethod
    def get_func_start(self, ea: int) -> int | None:
        """Start address of the function containing `ea`, or `None`."""

    @abstractmethod
    def get_func_end(self, ea: int) -> int | None:
        """End address (exclusive) of the function containing `ea`, or `None`."""

    @abstractmethod
    def get_flowchart_blocks(self, func_ea: int) -> tuple[BasicBlockInfo, ...]:
        """Basic blocks of the function starting at `func_ea`, each carrying
        its predecessor/successor block start addresses, in a stable order.
        Empty tuple if the function cannot be analyzed."""

    # -- memory reads (always the value stored at the address, never just the address) --
    @abstractmethod
    def read_int(self, addr: int, size: int, signed: bool = False) -> int | None:
        """Read a little-endian integer of `size` bytes (1/2/4/8) at `addr`."""

    @abstractmethod
    def read_bytes(self, addr: int, size: int) -> bytes | None:
        """Read `size` raw bytes at `addr`, or `None` if unmapped/unavailable."""

    @abstractmethod
    def read_cstring(self, addr: int, max_len: int = 4096) -> str | None:
        """Read a NUL-terminated narrow string at `addr`, or `None` on
        failure (unmapped memory, or no terminator within `max_len`)."""

    @abstractmethod
    def read_wstring(self, addr: int, max_len: int = 4096) -> str | None:
        """Read a NUL-terminated UTF-16LE string at `addr`, or `None`."""

    # -- calling convention / type info -------------------------------------------
    @abstractmethod
    def get_prototype(self, func_ea: int) -> FunctionPrototype | None:
        """The recognized function prototype (calling convention + per
        argument locations) if IDA already has one for `func_ea`, else
        `None`."""

    # -- stack frame ----------------------------------------------------------------
    @abstractmethod
    def get_sp_delta(self, func_ea: int, ea: int) -> int | None:
        """Cumulative stack-pointer delta at `ea` relative to the entry of
        the function starting at `func_ea` — used to normalize
        `[esp+N]`/`[rsp+N]` references taken at different points in a
        backward walk to a single frame-relative offset."""

    # -- address bitness / pointer size ------------------------------------------------
    @abstractmethod
    def pointer_size(self) -> int:
        """Size in bytes of a pointer in the current database (4 or 8)."""

    @abstractmethod
    def is_mapped(self, addr: int) -> bool:
        """Whether `addr` has data backing it in the IDB."""

    # -- architectural register roles ------------------------------------------------
    @abstractmethod
    def stack_pointer_reg(self) -> int | None:
        """Processor register number of the stack pointer (esp/rsp), used to
        recognize `[esp+N]`/`[rsp+N]`-style stack writes generically."""

    @abstractmethod
    def frame_pointer_reg(self) -> int | None:
        """Processor register number of the conventional frame pointer
        (ebp/rbp), if the architecture has one."""

    @abstractmethod
    def register_by_name(self, name: str) -> int | None:
        """Processor register number for `name` (e.g. `"ecx"`, `"rdx"`),
        used by calling-convention templates to name registers portably."""

    @abstractmethod
    def call_clobbered_registers(self) -> frozenset[int]:
        """Registers whose value is *not* preserved across a `call` under
        every calling convention plausible for this database.

        Deliberately the intersection, not the union: a register listed
        here is unambiguously destroyed by any callee, so a backward walk
        must not carry a value across a call through it. A register left
        out is merely not *known* to be preserved — omitting it keeps the
        previous (optimistic) behavior rather than inventing `Unknown`s
        from an ABI guess. Empty tuple if the architecture is unknown."""

    @abstractmethod
    def register_view(self, reg: int, size_bytes: int = 0) -> RegisterView | None:
        """Resolve `(register number, operand size)` to the part of a
        canonical register it names — see `core.ida_types.RegisterView`.
        `size_bytes` of 0 means "whatever width this register number
        denotes on its own". Returns `None` if the register is unknown, in
        which case callers must fall back to raw number comparison."""

    @abstractmethod
    def return_value_reg(self) -> int | None:
        """Processor register number conventionally holding a function's
        integer/pointer return value (eax/rax), used to recognize "prior
        call's return value used as an argument" data flow (requirement
        3.1 form #8) even though a `call` instruction has no explicit
        register operand naming it."""
