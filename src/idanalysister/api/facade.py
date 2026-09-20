"""Public entry point: `ParamExtractor`.

Most analysis tasks are one or two lines:

    extractor = ParamExtractor()
    report = extractor.extract_calls(func_ea, convention=CDECL, num_args=2)
    for site in report.call_sites:
        print(hex(site.call_ea), [a.raw_value for a in site.arguments])

`ParamExtractor` is the composition root: it owns one `IdaPort`, one
`InstructionCache`, one `LocatorRegistry`, and one `BackwardResolver` bound
to them. Different `ParamExtractor` instances never share mutable state, so
registering a custom locator on one session cannot affect another (see
`locators.extension_points`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idanalysister.api.results import ArgumentResult, CallSiteResult, ExtractionReport
from idanalysister.conventions import inference
from idanalysister.conventions.base import CallingConvention, SlotKind
from idanalysister.conventions.templates import CDECL
from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.engine_backward import BackwardResolver
from idanalysister.core.insn_cache import InstructionCache
from idanalysister.core.values import ValueLattice, unknown
from idanalysister.errors import ConventionError
from idanalysister.locators.base import LocatorRegistry, default_registry
from idanalysister.logging_ import get_logger

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort
    from idanalysister.typespec.argtype import ArgTypeSpec

_logger = get_logger("api.facade")


class ParamExtractor:
    def __init__(
        self,
        port: "IdaPort | None" = None,
        registry: LocatorRegistry | None = None,
        max_steps: int = 200,
        max_blocks: int = 64,
        cache_size: int = 4096,
        use_hexrays_fallback: bool = False,
    ):
        self.port = port if port is not None else _default_port()
        self.registry = registry if registry is not None else default_registry()
        self.cache = InstructionCache(self.port, max_entries=cache_size)
        self.resolver = BackwardResolver(self.port, self.cache, self.registry, max_steps, max_blocks)
        self.use_hexrays_fallback = use_hexrays_fallback
        self._hexrays = None
        if use_hexrays_fallback:
            from idanalysister.adapters.hexrays_backend import HexraysBackend, available

            self._hexrays = HexraysBackend() if available() else None
            if self._hexrays is None:
                _logger.info("use_hexrays_fallback requested but Hex-Rays is unavailable; raw engine only")

    # -- 3.1: call-site argument extraction ------------------------------------------
    def extract_calls(
        self,
        func_ea: int,
        convention: CallingConvention | None = None,
        num_args: int | None = None,
        arg_types: "dict[int, ArgTypeSpec] | None" = None,
    ) -> ExtractionReport:
        resolved_convention, resolved_num_args = self._resolve_convention(func_ea, convention, num_args)
        call_sites = []
        for call_ea in sorted(self.cache.code_refs_to(func_ea)):
            call_sites.append(
                self._extract_one_call_safe(call_ea, func_ea, resolved_convention, resolved_num_args, arg_types)
            )
        return ExtractionReport(func_ea=func_ea, call_sites=tuple(call_sites))

    # -- 3.3: intra-function forward resolution ---------------------------------------
    def resolve_argument_at(
        self,
        func_ea: int,
        arg_index: int,
        target_ea: int,
        convention: CallingConvention | None = None,
        num_args: int | None = None,
    ) -> ValueLattice:
        from idanalysister.core.engine_forward import ForwardSymbolicEngine

        resolved_convention, resolved_num_args = self._resolve_convention(func_ea, convention, num_args)
        if arg_index < 0 or arg_index >= resolved_num_args:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="argument index out of range")
        slots = resolved_convention.slots(resolved_num_args, self.port)
        slot = slots[arg_index]
        initial_reg = slot.reg if slot.kind is SlotKind.REGISTER else None
        engine = ForwardSymbolicEngine(self.port, self.cache, self.registry)
        try:
            return engine.resolve_at(func_ea, arg_index, target_ea, initial_reg)
        except Exception:
            _logger.exception("Forward resolution failed for arg %d of %#x at %#x", arg_index, func_ea, target_ea)
            return unknown(UnknownReason.INTERNAL_ERROR)

    # -- internals ------------------------------------------------------------------------
    def _resolve_convention(
        self, func_ea: int, convention: CallingConvention | None, num_args: int | None
    ) -> tuple[CallingConvention, int]:
        inferred = None
        if convention is None:
            inferred = inference.infer(func_ea, self.port)
            convention = inferred or CDECL
        if num_args is None:
            if inferred is not None:
                num_args = inferred.arg_count
            elif isinstance(convention, inference.PrototypeConvention):
                num_args = convention.arg_count
            else:
                raise ConventionError(
                    f"num_args must be specified for template-based convention {convention.name!r} "
                    f"(no recognized prototype for function {func_ea:#x})"
                )
        return convention, num_args

    def _extract_one_call_safe(
        self,
        call_ea: int,
        func_ea: int,
        convention: CallingConvention,
        num_args: int,
        arg_types: "dict[int, ArgTypeSpec] | None",
    ) -> CallSiteResult:
        try:
            return self._extract_one_call(call_ea, func_ea, convention, num_args, arg_types)
        except Exception:
            _logger.exception("Failed to extract arguments at call site %#x", call_ea)
            fallback_args = tuple(
                ArgumentResult(
                    index=i,
                    raw_value=unknown(UnknownReason.INTERNAL_ERROR),
                    processed_value=unknown(UnknownReason.INTERNAL_ERROR),
                )
                for i in range(num_args)
            )
            return CallSiteResult(call_ea=call_ea, func_ea=func_ea, arguments=fallback_args)

    def _extract_one_call(
        self,
        call_ea: int,
        func_ea: int,
        convention: CallingConvention,
        num_args: int,
        arg_types: "dict[int, ArgTypeSpec] | None",
    ) -> CallSiteResult:
        slots = convention.slots(num_args, self.port)
        needs_pushes = any(slot.kind is SlotKind.STACK_PUSH for slot in slots)
        pushes = self.resolver.collect_push_sequence(call_ea) if needs_pushes else []
        # Resolved lazily: decompiling a function is expensive, so it only
        # happens if the raw walk actually left an argument unresolved.
        hexrays_args: dict | None = None
        hexrays_tried = False
        arguments = []
        for slot in slots:
            raw = self._resolve_slot(call_ea, slot, pushes)
            source = "raw"
            if not raw.is_known and self._hexrays is not None:
                if not hexrays_tried:
                    hexrays_args = self._hexrays.resolve_call_args(call_ea, num_args)
                    hexrays_tried = True
                fallback_value = hexrays_args.get(slot.index) if hexrays_args else None
                if fallback_value is not None and fallback_value.is_known:
                    raw = fallback_value
                    source = "hexrays_fallback"
            spec = arg_types.get(slot.index) if arg_types else None
            processed = spec.postprocessors.run(raw, self.port) if spec is not None else raw
            arguments.append(
                ArgumentResult(
                    index=slot.index,
                    raw_value=raw,
                    processed_value=processed,
                    label=spec.label if spec else None,
                    source=source,
                )
            )
        return CallSiteResult(call_ea=call_ea, func_ea=func_ea, arguments=tuple(arguments))

    def _resolve_slot(self, call_ea: int, slot, pushes: list[int]) -> ValueLattice:
        if slot.kind is SlotKind.REGISTER:
            if slot.reg is None:
                return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="unresolved register name")
            return self.resolver.resolve_register(slot.reg, call_ea)
        if slot.kind is SlotKind.STACK_PUSH:
            idx = len(pushes) - 1 - slot.stack_push_position
            if idx < 0 or idx >= len(pushes):
                return unknown(UnknownReason.NO_DEFINITION_FOUND, detail="push sequence too short")
            return self.resolver.resolve_at_instruction(pushes[idx])
        if slot.kind is SlotKind.STACK_OFFSET:
            if slot.stack_offset is None:
                return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE, detail="unresolved stack offset")
            sp_reg = self.port.stack_pointer_reg()
            size = self.port.pointer_size()
            return self.resolver.resolve_memory(sp_reg, slot.stack_offset, call_ea, size)
        return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE)


def _default_port() -> "IdaPort":
    from idanalysister.adapters.ida_port_impl import IdaPortImpl

    return IdaPortImpl()
