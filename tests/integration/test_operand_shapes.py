"""Integration regressions for operand shapes that `adapters.ida_port_impl`
used to decode into something silently different from what the instruction
actually says.

These are the tests `tests/unit` structurally cannot provide: the unit
suite builds `Operand`s by hand, so it validates the engines against an
*idealized* view of IDA's encoding. Everything here goes through the real
decoder on a real analysis, which is where the mismatch lived.
"""

import pytest

from idanalysister import ParamExtractor
from idanalysister.adapters.ida_port_impl import IdaPortImpl
from idanalysister.conventions.custom_builder import ConventionBuilder
from idanalysister.conventions.templates import CDECL
from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.insn_model import OperandKind
from idanalysister.core.values import Concrete, Unknown

pytestmark = pytest.mark.requires_ida


def _instructions_of(port, func_ea):
    import ida_funcs

    pfn = ida_funcs.get_func(func_ea)
    out = []
    ea = pfn.start_ea
    while ea < pfn.end_ea:
        instr = port.decode_at(ea)
        if instr is None:
            break
        out.append(instr)
        ea = instr.next_ea
    return out


def _sites_in(report, port, func_ea):
    import ida_funcs

    pfn = ida_funcs.get_func(func_ea)
    return [s for s in report.call_sites if pfn.start_ea <= s.call_ea < pfn.end_ea]


def test_indexed_operand_reports_its_real_base_and_index(probe_functions):
    port = IdaPortImpl()
    indexed = [
        op
        for instr in _instructions_of(port, probe_functions["caller_sib_shadow"])
        for op in instr.operands
        if op.is_memory and op.has_index
    ]
    assert indexed, "expected `mov [ebx+ecx*4], 0x99` to decode as an indexed operand"
    op = indexed[0]
    assert op.reg == port.register_by_name("ebx"), "base must be ebx, not the SIB marker (esp)"
    assert op.index_reg == port.register_by_name("ecx")
    assert op.scale == 4


def test_plain_stack_operand_is_not_mistaken_for_an_indexed_one(probe_functions):
    # `mov [esp], 0x5678` still needs a SIB byte to encode esp as the base,
    # but it has no index term and must stay a plain stack reference.
    port = IdaPortImpl()
    esp = port.register_by_name("esp")
    stack_writes = [
        op
        for instr in _instructions_of(port, probe_functions["caller_sib_shadow"])
        for op in instr.operands
        if op.is_memory and op.reg == esp
    ]
    assert stack_writes, "expected a [esp]-relative operand"
    assert all(not op.has_index for op in stack_writes)


def test_negative_displacement_is_signed(probe_functions):
    port = IdaPortImpl()
    displacements = [
        op.disp
        for instr in _instructions_of(port, probe_functions["caller_neg_disp"])
        for op in instr.operands
        if op.kind is OperandKind.MEM_DISPL
    ]
    assert -4 in displacements, f"expected a -4 displacement, got {displacements}"


def test_indexed_write_does_not_shadow_a_stack_argument(probe_functions):
    # The unrelated `mov [ebx+ecx*4], 0x99` used to decode as `[esp+0]` and
    # be reported as this call's argument.
    extractor = ParamExtractor()
    convention = ConventionBuilder("stack_at_0").stack_offset(0, 0).build()
    report = extractor.extract_calls(probe_functions["target_func"], convention=convention, num_args=1)
    sites = _sites_in(report, extractor.port, probe_functions["caller_sib_shadow"])
    assert len(sites) == 1
    value = sites[0].argument(0).raw_value
    assert isinstance(value, Concrete) and value.value == 0x5678


def test_lea_with_negative_displacement_folds_to_the_right_address(probe_functions):
    import ida_name

    extractor = ParamExtractor()
    report = extractor.extract_calls(probe_functions["target_func"], convention=CDECL, num_args=1)
    sites = _sites_in(report, extractor.port, probe_functions["caller_neg_disp"])
    assert len(sites) == 1
    value = sites[0].argument(0).raw_value
    expected = ida_name.get_name_ea(0, "buffer") - 4
    assert isinstance(value, Concrete) and value.value == expected
