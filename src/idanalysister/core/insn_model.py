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
    index_reg: int | None = None  # secondary (SIB index) register, if known
    scale: int = 1
    disp: int = 0  # displacement for MEM_DISPL / MEM_PHRASE
    addr: int | None = None  # absolute address for MEM_DIRECT / FAR / NEAR
    imm_value: int | None = None  # o_imm value
    dtype_size: int = 0  # operand size in bytes
    segment_reg: int | None = None  # non-None for segment-override forms (e.g. gs:[...])
    segment_name: str | None = None

    @property
    def is_memory(self) -> bool:
        return self.kind in MEMORY_KINDS


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
        return f"{seg}[reg{op.reg}+{op.disp:#x}]"
    return f"<{op.kind.name}>"
