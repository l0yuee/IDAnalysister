"""Optional Hex-Rays microcode backend — an opt-in fallback/cross-check for
call-site argument extraction, never the primary or default engine.

Rationale (see `document/architecture.md` for the full discussion): the
Hex-Rays decompiler requires a separate license per target architecture and
is not guaranteed present in every deployment, so it cannot be a hard
dependency without silently breaking the "cover every x86/x86-64 form"
requirement on installs without it. It is also an *optimizing* layer —
`mba_t` microcode has already undergone constant propagation and
simplification, which can obscure exactly which raw instruction form
produced a value, something the framework's raw `core.engine_backward`
path is built to preserve with precise provenance. Hex-Rays therefore only
ever supplements the raw engines: `api.facade.ParamExtractor(use_hexrays_fallback=True)`
retries an argument through here *only* when the raw walk returned
`Unknown`, and the result is tagged `source="hexrays_fallback"` on
`api.results.ArgumentResult` rather than silently blended in.

This module is the only place `ida_hexrays` is imported; availability is
probed defensively so its absence never affects the raw path.

Scope: `resolve_call_args` (cross-checking 3.1 call-site extraction) is
fully implemented. Forward (3.3) cross-checking via microcode is a
documented extension point, not implemented here — reproducing
`core.engine_forward`'s fixpoint semantics against `mba_t` block/instruction
structures is substantial additional surface for a secondary, optional
backend; `resolve_forward` reports this explicitly via `UnknownReason`
rather than attempting a best-effort implementation that could not be
exercised against a live decompiler session while writing it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.values import Concrete, MemoryRef, ValueKind, ValueLattice, unknown
from idanalysister.logging_ import get_logger

if TYPE_CHECKING:
    pass

_logger = get_logger("adapters.hexrays_backend")


def available() -> bool:
    """Whether `ida_hexrays` can be imported and initialized in the current
    IDA session (requires a licensed decompiler for the target
    architecture). Never raises."""
    try:
        import ida_hexrays

        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


class HexraysBackend:
    """Stateless wrapper around `ida_hexrays.decompile_func`. Every public
    method returns `None` (rather than raising) when decompilation or
    lookup fails, so callers can fall back to the raw engines unconditionally."""

    def resolve_call_args(self, call_ea: int, num_args: int) -> dict[int, ValueLattice] | None:
        try:
            return self._resolve_call_args_impl(call_ea, num_args)
        except Exception:
            _logger.exception("Hex-Rays call-arg resolution failed at %#x", call_ea)
            return None

    def resolve_forward(self, func_ea: int, arg_index: int, target_ea: int) -> ValueLattice:
        return unknown(
            UnknownReason.UNSUPPORTED_OPERAND_SHAPE,
            detail="Hex-Rays forward (3.3) cross-check is not implemented; use ForwardSymbolicEngine",
        )

    def _resolve_call_args_impl(self, call_ea: int, num_args: int) -> dict[int, ValueLattice] | None:
        import ida_funcs
        import ida_hexrays

        pfn = ida_funcs.get_func(call_ea)
        if pfn is None:
            return None
        mba = ida_hexrays.decompile_func(pfn, None, ida_hexrays.DECOMP_NO_WAIT)
        if mba is None:
            return None

        callinfo = self._find_call_info(mba, call_ea)
        if callinfo is None:
            return None

        result: dict[int, ValueLattice] = {}
        args = callinfo.args
        for index in range(min(num_args, len(args))):
            result[index] = self._mop_to_value(args[index])
        return result

    @staticmethod
    def _find_call_info(mba, call_ea: int):
        """Scan the microcode for the call micro-instruction whose source
        address is `call_ea`, returning its `mcallinfo_t` (the resolved,
        constant-propagated argument list) or `None`."""
        import ida_hexrays

        for block_index in range(mba.qty):
            block = mba.get_mblock(block_index)
            insn = block.head
            while insn is not None:
                if insn.ea == call_ea and insn.opcode in (ida_hexrays.m_call, ida_hexrays.m_icall):
                    callinfo = insn.d.f if insn.d is not None else None
                    if callinfo is not None:
                        return callinfo
                insn = insn.next
        return None

    @staticmethod
    def _mop_to_value(mop) -> ValueLattice:
        import ida_hexrays

        try:
            if mop.t == ida_hexrays.mop_n and mop.nnn is not None:
                return Concrete(mop.nnn.value, ValueKind.INT)
            if mop.t == ida_hexrays.mop_v:
                return Concrete(mop.g, ValueKind.POINTER)
            if mop.t == ida_hexrays.mop_r:
                return unknown(
                    UnknownReason.UNSUPPORTED_OPERAND_SHAPE,
                    detail="argument left in a register by Hex-Rays optimization; no constant available",
                )
            if mop.t == ida_hexrays.mop_a and mop.a is not None:
                inner = HexraysBackend._mop_to_value(mop.a)
                if isinstance(inner, Concrete) and isinstance(inner.value, int):
                    return MemoryRef(addr=inner.value, value=unknown(UnknownReason.MEMORY_READ_FAILED))
                return inner
        except Exception:
            _logger.exception("Failed to convert Hex-Rays mop to a value")
        return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="unsupported Hex-Rays operand kind")
