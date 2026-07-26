"""In-memory `IdaPort` test double.

Unit tests build a `FakeIdaPort` by hand: register instructions in program
order, optionally with explicit basic-block boundaries/edges for branchy
control-flow tests, a byte-addressable memory image for dereference tests,
and function prototypes for calling-convention-inference tests. No `ida_*`
import anywhere in this module — that is the entire point.
"""

from __future__ import annotations

from idanalysister.adapters.ida_port import IdaPort
from idanalysister.core.ida_types import BasicBlockInfo, FunctionPrototype
from idanalysister.core.insn_model import Instruction


class FakeIdaPort(IdaPort):
    #: A small fixed register namespace so tests can build instructions
    #: without needing a real IDA session. Numbering is arbitrary but
    #: internally consistent (matches neither real x86 nor x64 IDP register
    #: numbers) — tests refer to registers by name via `register_by_name`.
    DEFAULT_REGISTERS: dict[str, int] = {
        "eax": 0, "ax": 0, "al": 0, "rax": 0,
        "ecx": 1, "cx": 1, "cl": 1, "rcx": 1,
        "edx": 2, "dx": 2, "dl": 2, "rdx": 2,
        "ebx": 3, "bx": 3, "bl": 3, "rbx": 3,
        "esp": 4, "sp": 4, "rsp": 4,
        "ebp": 5, "bp": 5, "rbp": 5,
        "esi": 6, "si": 6, "rsi": 6,
        "edi": 7, "di": 7, "rdi": 7,
        "r8": 8, "r8d": 8,
        "r9": 9, "r9d": 9,
        "gs": 100,
        "fs": 101,
    }

    def __init__(self, *, pointer_size: int = 8, registers: dict[str, int] | None = None):
        self._pointer_size = pointer_size
        self._registers = dict(registers) if registers is not None else dict(self.DEFAULT_REGISTERS)
        self._instructions: dict[int, Instruction] = {}
        self._memory: dict[int, int] = {}  # byte-addressable: addr -> 0..255
        self._func_bounds: dict[int, tuple[int, int]] = {}  # func_ea -> (start, end)
        self._blocks: dict[int, tuple[BasicBlockInfo, ...]] = {}  # func_ea -> blocks
        self._prototypes: dict[int, FunctionPrototype] = {}
        self._sp_deltas: dict[tuple[int, int], int] = {}  # (func_ea, ea) -> delta

    # -- fixture-building API -----------------------------------------------------
    def add_instruction(self, insn: Instruction) -> None:
        self._instructions[insn.ea] = insn

    def add_instructions(self, insns: list[Instruction]) -> None:
        for insn in insns:
            self.add_instruction(insn)

    def set_function(
        self,
        func_ea: int,
        end_ea: int,
        blocks: tuple[BasicBlockInfo, ...] = (),
    ) -> None:
        self._func_bounds[func_ea] = (func_ea, end_ea)
        if blocks:
            self._blocks[func_ea] = blocks

    def set_memory(self, addr: int, data: bytes) -> None:
        for offset, byte_value in enumerate(data):
            self._memory[addr + offset] = byte_value

    def set_prototype(self, func_ea: int, proto: FunctionPrototype) -> None:
        self._prototypes[func_ea] = proto

    def set_sp_delta(self, func_ea: int, ea: int, delta: int) -> None:
        self._sp_deltas[(func_ea, ea)] = delta

    # -- IdaPort implementation ----------------------------------------------------
    def decode_at(self, ea: int) -> Instruction | None:
        return self._instructions.get(ea)

    def prev_head(self, ea: int, min_ea: int) -> int | None:
        candidates = [e for e in self._instructions if min_ea <= e < ea]
        return max(candidates) if candidates else None

    def code_refs_to(self, ea: int) -> tuple[int, ...]:
        refs = []
        for src_ea, insn in self._instructions.items():
            if not insn.mnem.startswith("call"):
                continue
            if any(op.addr == ea for op in insn.operands if op.addr is not None):
                refs.append(src_ea)
        return tuple(sorted(refs))

    def get_func_start(self, ea: int) -> int | None:
        for start, end in self._func_bounds.values():
            if start <= ea < end:
                return start
        return None

    def get_func_end(self, ea: int) -> int | None:
        for start, end in self._func_bounds.values():
            if start <= ea < end:
                return end
        return None

    def get_flowchart_blocks(self, func_ea: int) -> tuple[BasicBlockInfo, ...]:
        return self._blocks.get(func_ea, ())

    def read_int(self, addr: int, size: int, signed: bool = False) -> int | None:
        raw = self.read_bytes(addr, size)
        if raw is None:
            return None
        return int.from_bytes(raw, byteorder="little", signed=signed)

    def read_bytes(self, addr: int, size: int) -> bytes | None:
        out = bytearray()
        for offset in range(size):
            byte_value = self._memory.get(addr + offset)
            if byte_value is None:
                return None
            out.append(byte_value)
        return bytes(out)

    def read_cstring(self, addr: int, max_len: int = 4096) -> str | None:
        raw = bytearray()
        for offset in range(max_len):
            byte_value = self._memory.get(addr + offset)
            if byte_value is None:
                return None
            if byte_value == 0:
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    return raw.decode("latin-1")
            raw.append(byte_value)
        return None

    def read_wstring(self, addr: int, max_len: int = 4096) -> str | None:
        raw = bytearray()
        offset = 0
        while offset < max_len * 2:
            lo = self._memory.get(addr + offset)
            hi = self._memory.get(addr + offset + 1)
            if lo is None or hi is None:
                return None
            if lo == 0 and hi == 0:
                return raw.decode("utf-16-le", errors="replace")
            raw.append(lo)
            raw.append(hi)
            offset += 2
        return None

    def get_prototype(self, func_ea: int) -> FunctionPrototype | None:
        return self._prototypes.get(func_ea)

    def get_sp_delta(self, func_ea: int, ea: int) -> int | None:
        return self._sp_deltas.get((func_ea, ea))

    def pointer_size(self) -> int:
        return self._pointer_size

    def is_mapped(self, addr: int) -> bool:
        return addr in self._memory

    def stack_pointer_reg(self) -> int | None:
        return self._registers.get("rsp" if self._pointer_size == 8 else "esp")

    def frame_pointer_reg(self) -> int | None:
        return self._registers.get("rbp" if self._pointer_size == 8 else "ebp")

    def register_by_name(self, name: str) -> int | None:
        return self._registers.get(name.lower())

    def return_value_reg(self) -> int | None:
        return self._registers.get("rax" if self._pointer_size == 8 else "eax")
