"""Built-in calling-convention templates.

Each is a small declarative `RegisterThenStackConvention`: a fixed list of
register names for the first N arguments, then either a `push` sequence
(cdecl/stdcall/fastcall/thiscall on x86) or a fixed stack-pointer offset per
remaining argument (the x86-64 ABIs, which pass overflow arguments at a
known `[rsp+K]` rather than via `push`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from idanalysister.conventions.base import ArgSlot, CallingConvention, SlotKind

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort


@dataclass(frozen=True)
class RegisterThenStackConvention(CallingConvention):
    name: str
    register_names: tuple[str, ...] = ()
    stack_mode: str = "push"  # "push" or "offset"
    #: For stack_mode == "offset": byte offset of the *first* stack
    #: argument relative to the stack pointer at call time (e.g. 0x20 for
    #: the Microsoft x64 ABI's shadow space).
    stack_base_offset: int = 0
    #: For stack_mode == "offset": byte increment per stack argument.
    stack_arg_size: int = 4

    def slots(self, num_args: int, port: "IdaPort") -> list[ArgSlot]:
        result: list[ArgSlot] = []
        for index in range(num_args):
            if index < len(self.register_names):
                reg = port.register_by_name(self.register_names[index])
                result.append(ArgSlot(index=index, kind=SlotKind.REGISTER, reg=reg))
                continue
            stack_index = index - len(self.register_names)
            if self.stack_mode == "push":
                result.append(
                    ArgSlot(index=index, kind=SlotKind.STACK_PUSH, stack_push_position=stack_index)
                )
            else:
                offset = self.stack_base_offset + stack_index * self.stack_arg_size
                result.append(ArgSlot(index=index, kind=SlotKind.STACK_OFFSET, stack_offset=offset))
        return result


#: All arguments pushed right-to-left; caller cleans the stack.
CDECL = RegisterThenStackConvention(name="cdecl", register_names=(), stack_mode="push")

#: All arguments pushed right-to-left; callee cleans the stack. Identical to
#: cdecl from the *caller's* side, which is all this framework observes.
STDCALL = RegisterThenStackConvention(name="stdcall", register_names=(), stack_mode="push")

#: MSVC `__fastcall`: first two integer/pointer args in ecx, edx; rest pushed.
FASTCALL = RegisterThenStackConvention(name="fastcall", register_names=("ecx", "edx"), stack_mode="push")

#: MSVC `__thiscall`: `this` in ecx; rest pushed.
THISCALL = RegisterThenStackConvention(name="thiscall", register_names=("ecx",), stack_mode="push")

#: Microsoft x64 ABI: first four integer/pointer args in rcx, rdx, r8, r9;
#: remaining args at [rsp+0x20], [rsp+0x28], ... (past the 0x20-byte shadow
#: space the caller reserves for the first four).
MS_X64 = RegisterThenStackConvention(
    name="ms_x64",
    register_names=("rcx", "rdx", "r8", "r9"),
    stack_mode="offset",
    stack_base_offset=0x20,
    stack_arg_size=8,
)

#: System V AMD64 ABI (Linux/macOS): first six integer/pointer args in rdi,
#: rsi, rdx, rcx, r8, r9; remaining args at [rsp+0], [rsp+8], ...
SYSV_X64 = RegisterThenStackConvention(
    name="sysv_x64",
    register_names=("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    stack_mode="offset",
    stack_base_offset=0x0,
    stack_arg_size=8,
)

BUILTIN_TEMPLATES: dict[str, CallingConvention] = {
    "cdecl": CDECL,
    "stdcall": STDCALL,
    "fastcall": FASTCALL,
    "thiscall": THISCALL,
    "ms_x64": MS_X64,
    "sysv_x64": SYSV_X64,
}


def by_name(name: str) -> CallingConvention:
    try:
        return BUILTIN_TEMPLATES[name]
    except KeyError as exc:
        raise KeyError(
            f"Unknown calling convention template {name!r}; available: {sorted(BUILTIN_TEMPLATES)}"
        ) from exc
