"""Calling-convention inference from a recognized IDA prototype.

If IDA already knows a function's prototype (`ida_typeinf.tinfo_t`), its
per-argument `argloc_t` locations are authoritative for that specific
function — this turns that into a `CallingConvention` directly, skipping
template guessing entirely and correctly handling mixed register+stack
conventions with no extra code, per the requirement's "if IDA has already
recognized a function prototype, automatically infer the calling
convention" clause.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idanalysister.conventions.base import ArgSlot, CallingConvention, SlotKind

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort
    from idanalysister.core.ida_types import FunctionPrototype


class PrototypeConvention(CallingConvention):
    """A `CallingConvention` built once from a `FunctionPrototype`'s
    already-resolved argument locations.

    Note: `ArgLocation.stack_offset` (from `argloc_t.stkoff()`) is IDA's
    callee-frame-relative stack offset, used here directly as the
    caller-side offset from the stack pointer at call time. These usually
    coincide but are not guaranteed identical in every ABI edge case; this
    is a documented best-effort approximation rather than a fully general
    frame translation.
    """

    def __init__(self, prototype: "FunctionPrototype"):
        self.name = f"inferred:{prototype.calling_convention}"
        self._prototype = prototype

    @property
    def arg_count(self) -> int:
        return len(self._prototype.arg_locations)

    def slots(self, num_args: int, port: "IdaPort") -> list[ArgSlot]:
        by_index = {loc.index: loc for loc in self._prototype.arg_locations}
        result: list[ArgSlot] = []
        for index in range(num_args):
            loc = by_index.get(index)
            if loc is None:
                # No prototype entry for this index (e.g. a variadic tail
                # argument beyond the declared parameters) — fall back to
                # an unresolved register slot rather than guessing a
                # location; resolution degrades to Unknown cleanly.
                result.append(ArgSlot(index=index, kind=SlotKind.REGISTER, reg=None))
            elif loc.is_register:
                result.append(ArgSlot(index=index, kind=SlotKind.REGISTER, reg=loc.reg))
            else:
                result.append(ArgSlot(index=index, kind=SlotKind.STACK_OFFSET, stack_offset=loc.stack_offset))
        return result


def infer(func_ea: int, port: "IdaPort") -> PrototypeConvention | None:
    """Build a `CallingConvention` from IDA's own recognized prototype for
    `func_ea`, or `None` if IDA has no prototype (caller should fall back
    to a built-in template)."""
    prototype = port.get_prototype(func_ea)
    if prototype is None or not prototype.arg_locations:
        return None
    return PrototypeConvention(prototype)
