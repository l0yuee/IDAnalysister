"""Integration tests: the real `adapters.ida_port_impl.IdaPortImpl` driven
by a genuine headless IDA analysis of `fixtures/probe.asm`, validating the
adapter itself — the one layer `tests/unit`'s `FakeIdaPort` cannot cover.
Run with: pytest tests/integration -m requires_ida (requires a local IDA
Pro + idalib installation; skipped automatically otherwise).
"""

import pytest

from idanalysister import ParamExtractor
from idanalysister.conventions.custom_builder import ConventionBuilder
from idanalysister.conventions.templates import CDECL
from idanalysister.core.values import Concrete, MemoryRef, Symbolic

pytestmark = pytest.mark.requires_ida


def test_push_sequence_with_memory_indirect(probe_functions):
    extractor = ParamExtractor()
    report = extractor.extract_calls(probe_functions["target_func"], convention=CDECL, num_args=2)
    matches = [
        s
        for s in report.call_sites
        if isinstance(s.argument(0).raw_value, Concrete) and s.argument(0).raw_value.value == 0x1234
    ]
    assert matches, "expected the caller_push_seq call site (arg0 == 0x1234) to be found"
    arg1 = matches[0].argument(1).raw_value
    assert isinstance(arg1, MemoryRef) and arg1.value.value == 0xABCDEF0


def test_register_indirect_addressing(probe_functions):
    extractor = ParamExtractor()
    report = extractor.extract_calls(probe_functions["target_func"], convention=CDECL, num_args=1)
    matches = [
        s
        for s in report.call_sites
        if isinstance(s.argument(0).raw_value, Concrete) and s.argument(0).raw_value.value == 0x123
    ]
    assert matches, "expected the caller_reg_indirect call site (arg0 == 0x123) to be found"


def test_prior_call_return_value_chained(probe_functions):
    extractor = ParamExtractor()
    report = extractor.extract_calls(probe_functions["target_func"], convention=CDECL, num_args=1)
    symbolic_sites = [s for s in report.call_sites if isinstance(s.argument(0).raw_value, Symbolic)]
    assert symbolic_sites, "expected at least one call site whose argument is a prior call's return value"
    assert symbolic_sites[0].argument(0).raw_value.expr.startswith("ret(")


def test_forward_resolution_survives_decrypt_loop(probe_functions):
    import ida_funcs
    import idautils

    func_ea = probe_functions["decrypt_then_call"]
    pfn = ida_funcs.get_func(func_ea)
    target_ea = probe_functions["target_func"]
    # Locate the call instruction inside decrypt_then_call via xrefs to
    # target_func, restricted to this function's address range.
    call_ea = next(ea for ea in idautils.CodeRefsTo(target_ea, 0) if pfn.start_ea <= ea < pfn.end_ea)

    convention = ConventionBuilder("fastcall_arg0_ecx").reg(0, "ecx").build()
    extractor = ParamExtractor()
    value = extractor.resolve_argument_at(func_ea, arg_index=0, target_ea=call_ea, convention=convention, num_args=1)
    assert isinstance(value, Symbolic) and value.expr == "arg0"
