"""End-to-end `ParamExtractor` tests: the three canonical scenarios from
the architecture walkthroughs, plus a crash-resistance property test."""

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from idanalysister import ParamExtractor
from idanalysister.conventions.templates import CDECL, FASTCALL, MS_X64
from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.ida_types import BasicBlockInfo
from idanalysister.core.insn_model import OperandKind
from idanalysister.core.values import Concrete, MemoryRef, Symbolic, Unknown
from idanalysister.typespec.argtype import ArgTypeSpec

from ..conftest import EAX, EBX, ECX, EDX, RCX, imm, insn, mem_direct, mem_displ, reg

FUNC = 0x401000
CALLER = 0x402000
CALLER_END = 0x402100


def test_push_sequence_with_memory_indirect_argument(port):
    port.set_memory(0x403000, (0xABCDEF).to_bytes(4, "little"))
    port.add_instructions(
        [
            insn(0x402000, "mov", 5, [reg(0, EAX), mem_direct(1, 0x403000)]),
            insn(0x402005, "push", 1, [reg(0, EAX)], written=(False,)),
            insn(0x40200A, "push", 5, [imm(0, 0x1234)], written=(False,)),
            insn(0x40200F, "call", 5, [mem_direct(0, FUNC)], written=(False,)),
        ]
    )
    port.set_function(CALLER, CALLER_END, blocks=(BasicBlockInfo(CALLER, CALLER_END, (), ()),))
    report = ParamExtractor(port=port).extract_calls(FUNC, convention=CDECL, num_args=2)
    assert report.call_count == 1
    site = report.call_sites[0]
    assert isinstance(site.argument(0).raw_value, Concrete) and site.argument(0).raw_value.value == 0x1234
    arg1 = site.argument(1).raw_value
    assert isinstance(arg1, MemoryRef) and arg1.value.value == 0xABCDEF


def test_fastcall_register_indirect_and_immediate(port):
    port.add_instructions(
        [
            insn(0x402100, "mov", 5, [reg(0, EAX), imm(1, 0x404000)]),
            insn(0x402105, "mov", 6, [mem_displ(0, EAX, 0x10), imm(1, 0x123)]),
            insn(0x40210B, "mov", 3, [reg(0, ECX), mem_displ(1, EAX, 0x10)]),
            insn(0x40210E, "mov", 5, [reg(0, EDX), imm(1, 7)]),
            insn(0x402113, "call", 5, [mem_direct(0, 0x401100)], written=(False,)),
        ]
    )
    port.set_function(0x402100, 0x402200, blocks=(BasicBlockInfo(0x402100, 0x402200, (), ()),))
    report = ParamExtractor(port=port).extract_calls(0x401100, convention=FASTCALL, num_args=2)
    site = report.call_sites[0]
    assert site.argument(0).raw_value.value == 0x123
    assert site.argument(1).raw_value.value == 7


def test_tail_call_via_unconditional_jmp_is_discovered_as_a_call_site(port):
    # Regression test: a compiler-generated tail call (`jmp target` instead
    # of `call target; ret`, e.g. the last statement in a small wrapper
    # function, or an import/thunk stub) must still be found as a call
    # site — IDA's own xref graph records it, and code_refs_to must not
    # silently filter it out just because the instruction is a jmp.
    port.add_instructions(
        [
            insn(0x402000, "push", 5, [imm(0, 0x99)], written=(False,)),
            insn(0x402005, "jmp", 5, [mem_direct(0, FUNC)], written=(False,)),
        ]
    )
    port.set_function(CALLER, CALLER_END, blocks=(BasicBlockInfo(CALLER, CALLER_END, (), ()),))
    report = ParamExtractor(port=port).extract_calls(FUNC, convention=CDECL, num_args=1)
    assert report.call_count == 1
    assert report.call_sites[0].call_ea == 0x402005
    assert report.call_sites[0].argument(0).raw_value.value == 0x99


def test_call_return_chaining_with_c_string_postprocessor(port):
    port.set_memory(0x405000, b"hello\x00")
    port.add_instructions(
        [
            insn(0x402200, "call", 5, [mem_direct(0, 0x401200)], written=(False,)),
            insn(0x402205, "mov", 2, [reg(0, EBX), reg(1, EAX)]),
            insn(0x402207, "push", 1, [reg(0, EBX)], written=(False,)),
            insn(0x402208, "call", 5, [mem_direct(0, 0x401300)], written=(False,)),
        ]
    )
    port.set_function(0x402200, 0x402300, blocks=(BasicBlockInfo(0x402200, 0x402300, (), ()),))
    report = ParamExtractor(port=port).extract_calls(
        0x401300, convention=CDECL, num_args=1, arg_types={0: ArgTypeSpec.c_string(0)}
    )
    site = report.call_sites[0]
    assert isinstance(site.argument(0).raw_value, Symbolic)
    # Not dereferenceable from a symbolic return value — honestly Unknown,
    # not a crash and not a fabricated string.
    assert not site.argument(0).processed_value.is_known


def test_multiple_call_sites_all_extracted(port):
    port.add_instructions(
        [
            insn(0x402000, "push", 5, [imm(0, 1)], written=(False,)),
            insn(0x402005, "call", 5, [mem_direct(0, FUNC)], written=(False,)),
            insn(0x40200A, "push", 5, [imm(0, 2)], written=(False,)),
            insn(0x40200F, "call", 5, [mem_direct(0, FUNC)], written=(False,)),
        ]
    )
    port.set_function(CALLER, CALLER_END, blocks=(BasicBlockInfo(CALLER, CALLER_END, (), ()),))
    report = ParamExtractor(port=port).extract_calls(FUNC, convention=CDECL, num_args=1)
    assert report.call_count == 2
    values = sorted(site.argument(0).raw_value.value for site in report.call_sites)
    assert values == [1, 2]


def test_resolve_argument_at_through_facade_tracks_register_reassignment(port64):
    # Regression test for a bug where the facade passed the whole
    # CallingConvention into ForwardSymbolicEngine.resolve_at instead of
    # the argument's concrete entry register — which happened to look
    # correct whenever the value survived unchanged, but silently ignored
    # any real reassignment. arg0 enters in rcx (MS x64 slot 0); it is
    # unconditionally overwritten with a constant before the call, so the
    # value at the call site must reflect that, not the original seed.
    func_ea = 0x510000
    call_ea = 0x510008
    port64.add_instructions(
        [
            insn(0x510000, "mov", 5, [reg(0, RCX, 8), imm(1, 0x2A, 8)]),
            insn(call_ea, "call", 5, [mem_direct(0, 0x600000, 8)], written=(False,)),
        ]
    )
    port64.set_function(func_ea, 0x510100, blocks=(BasicBlockInfo(func_ea, 0x510100, (), ()),))
    extractor = ParamExtractor(port=port64)
    result = extractor.resolve_argument_at(func_ea, arg_index=0, target_ea=call_ea, convention=MS_X64, num_args=1)
    assert isinstance(result, Concrete) and result.value == 0x2A


def test_resolve_argument_at_stack_slot_is_unsupported_through_facade(port64):
    # arg index beyond MS x64's 4 register slots is stack-passed; the
    # facade must surface the engine's documented scope limit, not crash.
    func_ea = 0x520000
    call_ea = 0x520005
    port64.add_instructions([insn(call_ea, "call", 5, [mem_direct(0, 0x600000, 8)], written=(False,))])
    port64.set_function(func_ea, 0x520100, blocks=(BasicBlockInfo(func_ea, 0x520100, (), ()),))
    extractor = ParamExtractor(port=port64)
    result = extractor.resolve_argument_at(func_ea, arg_index=4, target_ea=call_ea, convention=MS_X64, num_args=5)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_OPERAND_SHAPE


# -- crash resistance: random instruction soup must never raise -------------------------
_MNEMONICS = ["mov", "push", "lea", "xchg", "cmovz", "add", "sub", "vzeroupper", "nop", "not", "xor"]
_OPERAND_KINDS = [OperandKind.REG, OperandKind.IMMEDIATE, OperandKind.MEM_DIRECT, OperandKind.MEM_DISPL]


def _random_operand(draw, number):
    kind = draw(st.sampled_from(_OPERAND_KINDS))
    if kind is OperandKind.REG:
        return reg(number, draw(st.integers(min_value=0, max_value=7)))
    if kind is OperandKind.IMMEDIATE:
        return imm(number, draw(st.integers(min_value=-0xFFFF, max_value=0xFFFF)))
    if kind is OperandKind.MEM_DIRECT:
        return mem_direct(number, draw(st.integers(min_value=0x400000, max_value=0x410000)))
    return mem_displ(number, draw(st.integers(min_value=0, max_value=7)), draw(st.integers(min_value=-64, max_value=64)))


@st.composite
def random_program(draw):
    count = draw(st.integers(min_value=1, max_value=12))
    ea = 0x402000
    instrs = []
    for _ in range(count):
        mnem = draw(st.sampled_from(_MNEMONICS))
        num_operands = draw(st.integers(min_value=0, max_value=2))
        operands = [_random_operand(draw, i) for i in range(num_operands)]
        written = tuple(draw(st.booleans()) for _ in operands)
        instrs.append(insn(ea, mnem, 4, operands, written=written))
        ea += 4
    instrs.append(insn(ea, "call", 5, [mem_direct(0, FUNC)], written=(False,)))
    return instrs, ea + 5


@given(random_program())
@settings(max_examples=60, deadline=None)
def test_extraction_never_crashes_on_arbitrary_instruction_sequences(program):
    from idanalysister.adapters.fake_port import FakeIdaPort

    instrs, end_ea = program
    port = FakeIdaPort(pointer_size=4)
    port.add_instructions(instrs)
    port.set_function(CALLER, end_ea, blocks=(BasicBlockInfo(CALLER, end_ea, (), ()),))
    report = ParamExtractor(port=port).extract_calls(FUNC, convention=CDECL, num_args=3)
    assert report.call_count == 1
    for arg in report.call_sites[0].arguments:
        assert arg.raw_value is not None
