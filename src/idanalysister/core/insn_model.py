"""Normalized, architecture-agnostic instruction/operand model.

This is the framework's own view of an instruction, built once by
`adapters.ida_port_impl` from `ida_ua.insn_t`/`ida_ua.op_t` and cached by
`core.insn_cache.InstructionCache`. Locators and engines only ever see these
dataclasses, never raw IDA SWIG objects, which is what keeps `core` and
`locators` free of `ida_*` imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class OperandKind(Enum):
    VOID = auto()
    REG = auto()
    IMMEDIATE = auto()
    MEM_DIRECT = auto()  # absolute address, e.g. `dword_403000`
    MEM_PHRASE = auto()  # `[reg]` / `[reg+reg*scale]`, no displacement
    MEM_DISPL = auto()  # `[reg+disp]` / `[reg+reg*scale+disp]`
    FAR = auto()
    NEAR = auto()
    SPECIAL = auto()  # processor-specific escape hatch (o_idpspecN)


#: Operand kinds that represent *some* form of memory reference.
MEMORY_KINDS = frozenset({OperandKind.MEM_DIRECT, OperandKind.MEM_PHRASE, OperandKind.MEM_DISPL})


@dataclass(frozen=True)
class Operand:
    kind: OperandKind
    number: int  # 0-based operand index within the instruction
    reg: int | None = None  # o_reg, or base register for phrase/displ forms
    #: Scaled-index register of an indexed addressing form
    #: (`[base+index*scale+disp]`), or `None` when the operand has no index
    #: term. Anything that reduces a memory operand to a `(base, disp)`
    #: pair must check this first: dropping a non-`None` index silently
    #: turns an array/table access into a fixed-slot access, which is how a
    #: `[ebx+ecx*4]` write used to be mistaken for a write to `[esp+0]`.
    index_reg: int | None = None
    scale: int = 1  # index scale factor (1/2/4/8); meaningless if index_reg is None
    #: Displacement for MEM_DISPL / MEM_PHRASE, as a *signed* offset.
    disp: int = 0
    addr: int | None = None  # absolute address for MEM_DIRECT / FAR / NEAR
    #: `o_imm` value, as the unsigned bit pattern of `dtype_size` bytes
    #: (so `push -4` on x86 is `0xFFFFFFFC`, the value actually pushed).
    imm_value: int | None = None
    dtype_size: int = 0  # operand size in bytes
    segment_reg: int | None = None  # non-None for segment-override forms (e.g. gs:[...])
    segment_name: str | None = None

    @property
    def is_memory(self) -> bool:
        return self.kind in MEMORY_KINDS

    @property
    def has_index(self) -> bool:
        """Whether this is an indexed addressing form. The value of the
        index is generally not statically known, so a memory operand with
        an index cannot be normalized to a single `(base, disp)` location
        (see `index_reg`)."""
        return self.index_reg is not None


@dataclass(frozen=True)
class Instruction:
    ea: int
    mnem: str  # lowercase canonical mnemonic, e.g. "mov", "push", "cmovz"
    itype: int
    size: int
    operands: tuple[Operand, ...] = field(default_factory=tuple)
    #: Parallel to `operands` (same length/order): whether IDA's processor
    #: module flags that operand as a destination written by this
    #: instruction (`ida_idp`'s `CF_CHG1..CF_CHG8` feature bits). This is
    #: what lets `core.engine_backward` recognize "this instruction defines
    #: register/memory operand N" generically, for *any* instruction —
    #: including ones with no dedicated `Locator` — rather than needing a
    #: hardcoded mnemonic list to know what counts as a definition site.
    operand_written: tuple[bool, ...] = field(default_factory=tuple)
    #: Parallel to `operands`: whether IDA's processor module flags that
    #: operand as a *source* read by this instruction (`ida_idp`'s
    #: `CF_USE1..CF_USE8`). Together with `operand_written` this
    #: distinguishes a pure definition (`mov eax, X` — written, not read)
    #: from a read-modify-write (`add eax, X` / `add [ebp-8], eax` — both),
    #: which a transfer function must not treat as a plain assignment.
    operand_read: tuple[bool, ...] = field(default_factory=tuple)
    #: Whether IDA's processor module flags this instruction as altering
    #: control flow (`ida_idp`'s `CF_CALL | CF_JUMP | CF_STOP` feature
    #: bits) — covers `call`, every jump variant (conditional or not),
    #: `ret`/`iret`, and processor-specific equivalents generically,
    #: without a hardcoded mnemonic list. Used to recognize where a
    #: backward walk must stop treating intervening instructions as
    #: transparent (e.g. `core.engine_backward.collect_push_sequence`
    #: skipping over non-stack-touching instructions interleaved between
    #: `push`es, such as MSVC's `/EHsc` unwind-state bookkeeping, while
    #: still never walking through a real control-flow boundary).
    is_control_transfer: bool = False
    func_ea: int | None = None  # owning function entry, if known

    @property
    def next_ea(self) -> int:
        return self.ea + self.size

    def operand(self, number: int) -> Operand | None:
        for op in self.operands:
            if op.number == number:
                return op
        return None

    def is_written(self, number: int) -> bool:
        for op, written in zip(self.operands, self.operand_written):
            if op.number == number:
                return written
        return False

    def is_read(self, number: int) -> bool:
        for op, read in zip(self.operands, self.operand_read):
            if op.number == number:
                return read
        return False

    def is_pure_definition_of(self, number: int) -> bool:
        """Whether operand `number` is written *without* also being read —
        i.e. this instruction assigns it outright rather than updating it
        in place. False for a read-modify-write operand, and False when
        `operand_read` was never populated, so a caller that relies on this
        to justify an assignment fails closed."""
        return self.is_written(number) and not self.is_read(number) and bool(self.operand_read)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        ops = ", ".join(_operand_repr(op) for op in self.operands)
        return f"Instruction({self.ea:#x}: {self.mnem} {ops})"


def _operand_repr(op: Operand) -> str:  # pragma: no cover - cosmetic
    if op.kind is OperandKind.REG:
        return f"reg{op.reg}"
    if op.kind is OperandKind.IMMEDIATE:
        return f"{op.imm_value:#x}"
    if op.kind is OperandKind.MEM_DIRECT:
        return f"[{op.addr:#x}]"
    if op.kind in (OperandKind.MEM_PHRASE, OperandKind.MEM_DISPL):
        seg = f"{op.segment_name}:" if op.segment_name else ""
        index = f"+reg{op.index_reg}*{op.scale}" if op.index_reg is not None else ""
        return f"{seg}[reg{op.reg}{index}{op.disp:+#x}]"
    return f"<{op.kind.name}>"
