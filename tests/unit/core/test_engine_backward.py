"""BackwardResolver behavior: every requirement 3.1 instruction form, plus
merge/divergence and budget-exceeded semantics."""

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.engine_backward import BackwardResolver
from idanalysister.core.ida_types import BasicBlockInfo
from idanalysister.core.insn_cache import InstructionCache
from idanalysister.core.values import Concrete, MemoryRef, Symbolic, Unknown
from idanalysister.locators.base import default_registry

from ..conftest import (
    EAX,
    EBP,
    EBX,
    ECX,
    EDX,
    ESI,
    ESP,
    imm,
    insn,
    mem_direct,
    mem_displ,
    mem_index,
    mem_phrase,
    reg,
)

FUNC = 0x401000
END = 0x401100


def make_resolver(port, **kwargs):
    cache = InstructionCache(port)
    return BackwardResolver(port, cache, default_registry(), **kwargs)


def linear_block(port, func_ea=FUNC, end_ea=END):
    port.set_function(func_ea, end_ea, blocks=(BasicBlockInfo(func_ea, end_ea, (), ()),))


# -- form #1: register direct passing -------------------------------------------------
def test_register_direct_mov_reg_reg(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x1234)]),
            insn(0x401005, "mov", 2, [reg(0, EBX), reg(1, EAX)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EBX, 0x401007)
    assert result == Concrete(0x1234, result.kind)


# -- form #2: immediate direct passing ------------------------------------------------
def test_immediate_direct(port):
    port.add_instructions([insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x5678)])])
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401005)
    assert isinstance(result, Concrete) and result.value == 0x5678


# -- form #3: memory indirect passing (must dereference) ------------------------------
def test_memory_indirect_dereferences_global(port):
    port.set_memory(0x403000, (0xABCDEF).to_bytes(4, "little"))
    port.add_instructions([insn(0x401000, "mov", 5, [reg(0, EAX), mem_direct(1, 0x403000)])])
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401005)
    assert isinstance(result, MemoryRef)
    assert result.addr == 0x403000
    assert isinstance(result.value, Concrete) and result.value.value == 0xABCDEF


def test_memory_read_failure_is_unknown_not_crash(port):
    port.add_instructions([insn(0x401000, "mov", 5, [reg(0, EAX), mem_direct(1, 0x999000)])])
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401005)
    assert isinstance(result, MemoryRef)
    assert isinstance(result.value, Unknown)
    assert result.value.reason is UnknownReason.MEMORY_READ_FAILED


# -- form #6: register indirect addressing --------------------------------------------
def test_register_indirect_write_then_read(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x404000)]),
            insn(0x401005, "mov", 6, [mem_displ(0, EAX, 0x10), imm(1, 0x123)]),
            insn(0x40100B, "mov", 3, [reg(0, ECX), mem_displ(1, EAX, 0x10)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(ECX, 0x40100E)
    assert isinstance(result, Concrete) and result.value == 0x123


# -- form #7: TLS / global passing ------------------------------------------------------
def test_tls_segment_operand_is_not_read_as_a_flat_address(port):
    # `mov eax, gs:[0x30]` names offset 0x30 *within the TLS segment*,
    # whose base is not statically known. Reading linear address 0x30
    # instead would silently report whatever unrelated data happens to
    # live there, so the honest answer is a reasoned Unknown.
    port.set_memory(0x30, (0xCAFEBABE).to_bytes(4, "little"))
    port.add_instructions([insn(0x401000, "mov", 6, [reg(0, EAX), mem_direct(1, 0x30, segment_name="gs")])])
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401006)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_OPERAND_SHAPE
    assert "gs" in result.detail


def test_plain_global_without_segment_override_still_reads_memory(port):
    port.set_memory(0x403000, (0xCAFEBABE).to_bytes(4, "little"))
    port.add_instructions([insn(0x401000, "mov", 6, [reg(0, EAX), mem_direct(1, 0x403000)])])
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401006)
    assert isinstance(result, MemoryRef) and result.value.value == 0xCAFEBABE


# -- form #8: prior call's return value used as argument -------------------------------
def test_call_return_value_chained_through_register_copy(port):
    port.add_instructions(
        [
            insn(0x401000, "call", 5, [mem_direct(0, 0x402000)], written=(False,)),
            insn(0x401005, "mov", 2, [reg(0, EBX), reg(1, EAX)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EBX, 0x401007)
    assert isinstance(result, Symbolic)
    assert result.expr == "ret(0x401000)"


# -- xchg / cmov / lea / add-sub (form #9 rare forms) -----------------------------------
def test_xchg_swaps_registers(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 1)]),
            insn(0x401005, "mov", 5, [reg(0, EBX), imm(1, 2)]),
            insn(0x40100A, "xchg", 2, [reg(0, EAX), reg(1, EBX)], written=(True, True)),
        ]
    )
    linear_block(port)
    resolver = make_resolver(port)
    assert resolver.resolve_register(EAX, 0x40100C).value == 2
    assert resolver.resolve_register(EBX, 0x40100C).value == 1


def test_cmov_is_divergent_not_guessed(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 1)]),
            insn(0x401005, "mov", 5, [reg(0, EBX), imm(1, 2)]),
            insn(0x40100A, "cmovz", 3, [reg(0, EAX), reg(1, EBX)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x40100D)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.DIVERGENT_PATHS


def test_lea_computes_address_without_dereferencing(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x404000)]),
            insn(0x401005, "lea", 3, [reg(0, ECX), mem_displ(1, EAX, 0x20)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(ECX, 0x401008)
    assert isinstance(result, Concrete) and result.value == 0x404020


def test_add_sub_constant_folding(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 100)]),
            insn(0x401005, "add", 3, [reg(0, EAX), imm(1, 5)]),
            insn(0x401008, "sub", 3, [reg(0, EAX), imm(1, 2)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x40100B)
    assert isinstance(result, Concrete) and result.value == 103


# -- unsupported instruction -> Unknown, never a crash ----------------------------------
def test_unrecognized_instruction_yields_unknown(port):
    port.add_instructions([insn(0x401000, "vpternlogd", 6, [reg(0, EAX), imm(1, 1)])])
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401006)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_INSTRUCTION


def test_no_definition_reaches_function_entry(port):
    port.add_instructions([insn(0x401000, "nop", 1, [])])
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401001)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.NO_DEFINITION_FOUND


# -- merge at branches: agree vs. diverge -----------------------------------------------
def test_merge_agreeing_paths_stays_concrete(port):
    # entry -> {left, right} -> join ; both branches set eax = 7
    port.add_instructions(
        [
            insn(0x401000, "jz", 5, [mem_direct(0, 0x401010)], written=(False,)),
            insn(0x401005, "mov", 5, [reg(0, EAX), imm(1, 7)]),  # left branch
            insn(0x401010, "mov", 5, [reg(0, EAX), imm(1, 7)]),  # right branch
            insn(0x401015, "mov", 2, [reg(0, EBX), reg(1, EAX)]),  # join point use
        ]
    )
    blocks = (
        BasicBlockInfo(0x401000, 0x401005, succ_starts=(0x401005, 0x401010), pred_starts=()),
        BasicBlockInfo(0x401005, 0x40100A, succ_starts=(0x401015,), pred_starts=(0x401000,)),
        BasicBlockInfo(0x401010, 0x401015, succ_starts=(0x401015,), pred_starts=(0x401000,)),
        BasicBlockInfo(0x401015, 0x40101A, succ_starts=(), pred_starts=(0x401005, 0x401010)),
    )
    port.set_function(FUNC, END, blocks=blocks)
    result = make_resolver(port).resolve_register(EBX, 0x401017)
    assert isinstance(result, Concrete) and result.value == 7


def test_merge_disagreeing_paths_is_divergent(port):
    port.add_instructions(
        [
            insn(0x401000, "jz", 5, [mem_direct(0, 0x401010)], written=(False,)),
            insn(0x401005, "mov", 5, [reg(0, EAX), imm(1, 7)]),
            insn(0x401010, "mov", 5, [reg(0, EAX), imm(1, 9)]),
            insn(0x401015, "mov", 2, [reg(0, EBX), reg(1, EAX)]),
        ]
    )
    blocks = (
        BasicBlockInfo(0x401000, 0x401005, succ_starts=(0x401005, 0x401010), pred_starts=()),
        BasicBlockInfo(0x401005, 0x40100A, succ_starts=(0x401015,), pred_starts=(0x401000,)),
        BasicBlockInfo(0x401010, 0x401015, succ_starts=(0x401015,), pred_starts=(0x401000,)),
        BasicBlockInfo(0x401015, 0x40101A, succ_starts=(), pred_starts=(0x401005, 0x401010)),
    )
    port.set_function(FUNC, END, blocks=blocks)
    result = make_resolver(port).resolve_register(EBX, 0x401017)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.DIVERGENT_PATHS


# -- budget exceeded: pathologically long chain still terminates -----------------------
def test_budget_exceeded_on_long_chain(port):
    ea = 0x401000
    prev_reg = EAX
    port.add_instructions([insn(ea, "mov", 5, [reg(0, EAX), imm(1, 1)])])
    ea += 5
    # Alternate EAX/EBX copies far beyond the default step budget.
    for i in range(500):
        src = EAX if prev_reg == EBX else EBX
        dst = EBX if prev_reg == EBX else EAX
        if i == 0:
            port.add_instruction(insn(ea, "mov", 2, [reg(0, EBX), reg(1, EAX)]))
            prev_reg = EBX
        else:
            port.add_instruction(insn(ea, "mov", 2, [reg(0, dst), reg(1, src)]))
            prev_reg = dst
        ea += 2
    linear_block(port, end_ea=ea + 0x1000)
    resolver = make_resolver(port, max_steps=50)
    result = resolver.resolve_register(prev_reg, ea)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.BUDGET_EXCEEDED


# -- push sequence with a non-stack instruction interleaved before the call ------------
def test_push_sequence_skips_transparent_instruction_before_call(port):
    # Reproduces a real-world MSVC pattern: `/EHsc` unwind-state bookkeeping
    # (`mov byte ptr [ebp+var_4], 1`) inserted between the last push and the
    # call. Regression test for collect_push_sequence stopping too early.
    port.add_instructions(
        [
            insn(0x401000, "push", 5, [imm(0, 0x0A)], written=(False,)),
            insn(0x401005, "push", 5, [mem_direct(0, 0x407930)], written=(False,)),
            insn(0x40100A, "mov", 4, [mem_displ(0, EBX, -4, size=1), imm(1, 1, size=1)]),
            insn(0x40100E, "call", 6, [mem_direct(0, 0x407188)], written=(False,)),
        ]
    )
    linear_block(port, end_ea=0x401100)
    resolver = make_resolver(port)
    pushes = resolver.collect_push_sequence(0x40100E)
    assert pushes == [0x401000, 0x401005]


def test_push_sequence_stops_at_a_real_control_flow_boundary(port):
    # A genuine call/jmp interleaved between pushes must NOT be treated as
    # transparent — only the trailing push(es) after it belong to this
    # call's argument setup.
    port.add_instructions(
        [
            insn(0x401000, "push", 5, [imm(0, 1)], written=(False,)),
            insn(0x401005, "call", 5, [mem_direct(0, 0x402000)], written=(False,)),
            insn(0x40100A, "push", 5, [imm(0, 2)], written=(False,)),
            insn(0x40100F, "call", 6, [mem_direct(0, 0x407188)], written=(False,)),
        ]
    )
    linear_block(port, end_ea=0x401100)
    resolver = make_resolver(port)
    pushes = resolver.collect_push_sequence(0x40100F)
    assert pushes == [0x40100A]


def test_push_sequence_stops_at_stack_pointer_write(port):
    # A `mov [esp+N], X` (stack-offset write) between pushes changes the
    # stack layout being described and must not be treated as transparent.
    port.add_instructions(
        [
            insn(0x401000, "push", 5, [imm(0, 1)], written=(False,)),
            insn(0x401005, "mov", 4, [mem_displ(0, ESP, 4), imm(1, 2)]),
            insn(0x401009, "call", 6, [mem_direct(0, 0x407188)], written=(False,)),
        ]
    )
    linear_block(port, end_ea=0x401100)
    resolver = make_resolver(port)
    pushes = resolver.collect_push_sequence(0x401009)
    assert pushes == []


# -- operand width normalization -------------------------------------------------------
def test_lea_with_a_negative_displacement_folds_correctly(port):
    # Displacements arrive from IDA sign-extended to 64 bits; without
    # normalizing them `lea eax, [ebx-4]` folded to base + 2**64 - 4.
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EBX), imm(1, 0x404004)]),
            insn(0x401005, "lea", 3, [reg(0, EAX), mem_displ(1, EBX, -4)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401008)
    assert isinstance(result, Concrete) and result.value == 0x404000


def test_add_of_a_negative_immediate_wraps_to_the_register_width(port):
    # `add ebx, -8` encodes the immediate as 0xFFFFFFF8; folding without
    # wrapping would land 2**32 away from the right answer.
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EBX), imm(1, 0x404000)]),
            insn(0x401005, "add", 3, [reg(0, EBX), imm(1, 0xFFFFFFF8)], read=(True, True)),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EBX, 0x401008)
    assert isinstance(result, Concrete) and result.value == 0x403FF8


# -- memory shapes that name no single static address ----------------------------------
def test_indexed_write_elsewhere_does_not_shadow_a_stack_argument(port):
    # `mov [ebx+ecx*4], 0x99` writes into a table through ebx. It used to
    # decode as `[esp+0]` (IDA reports the ModRM SIB marker, not the base),
    # so it shadowed the real argument written by `mov [esp], 0x1234` and
    # the call site reported 0x99.
    port.add_instructions(
        [
            insn(0x401000, "mov", 7, [mem_displ(0, ESP, 0), imm(1, 0x1234)]),
            insn(0x401007, "mov", 7, [mem_index(0, EBX, ECX, scale=4), imm(1, 0x99)]),
            insn(0x40100E, "call", 5, [mem_direct(0, 0x402000)], written=(False,)),
        ]
    )
    linear_block(port)
    for ea in (0x401000, 0x401007, 0x40100E):
        port.set_sp_delta(FUNC, ea, 0)
    result = make_resolver(port).resolve_memory(ESP, 0, 0x40100E, 4)
    assert isinstance(result, Concrete) and result.value == 0x1234


def test_indexed_write_in_the_same_region_is_reported_as_possible_aliasing(port):
    # `mov [esp+ecx*4], 0x99` really might land on [esp+0]; reporting the
    # older write would be a guess.
    port.add_instructions(
        [
            insn(0x401000, "mov", 7, [mem_displ(0, ESP, 0), imm(1, 0x1234)]),
            insn(0x401007, "mov", 7, [mem_index(0, ESP, ECX, scale=4), imm(1, 0x99)]),
        ]
    )
    linear_block(port)
    for ea in (0x401000, 0x401007, 0x40100E):
        port.set_sp_delta(FUNC, ea, 0)
    result = make_resolver(port).resolve_memory(ESP, 0, 0x40100E, 4)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_OPERAND_SHAPE
    assert "alias" in result.detail


def test_indexed_source_operand_is_not_flattened_to_its_base(port):
    port.set_memory(0x404000, (0xDEAD).to_bytes(4, "little"))
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EBX), imm(1, 0x404000)]),
            insn(0x401005, "mov", 3, [reg(0, EAX), mem_index(1, EBX, ECX, scale=4)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401008)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_OPERAND_SHAPE


# -- values used inside a loop ---------------------------------------------------------
def test_register_set_before_a_loop_resolves_at_a_use_inside_it(port):
    # The back edge into the loop header used to come back as
    # Unknown(BUDGET_EXCEEDED), and `join` is absorbing on Unknown, so it
    # poisoned the one predecessor that actually proved the value. Every
    # call site inside a loop was affected.
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, ESI), imm(1, 0x404000)]),
            insn(0x401005, "push", 1, [reg(0, ESI)], written=(False,)),
            insn(0x401006, "jmp", 2, [mem_direct(0, 0x401005)], written=(False,)),
        ]
    )
    port.set_function(
        FUNC,
        END,
        blocks=(
            BasicBlockInfo(0x401000, 0x401005, succ_starts=(0x401005,), pred_starts=()),
            BasicBlockInfo(0x401005, END, succ_starts=(0x401005,), pred_starts=(0x401000, 0x401005)),
        ),
    )
    result = make_resolver(port).resolve_register(ESI, 0x401005)
    assert isinstance(result, Concrete) and result.value == 0x404000


def test_stack_slot_written_before_a_loop_resolves_inside_it(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [mem_displ(0, EBP, -8), imm(1, 0x777)]),
            insn(0x401005, "mov", 3, [reg(0, EAX), mem_displ(1, EBP, -8)]),
            insn(0x401008, "jmp", 2, [mem_direct(0, 0x401005)], written=(False,)),
        ]
    )
    port.set_function(
        FUNC,
        END,
        blocks=(
            BasicBlockInfo(0x401000, 0x401005, succ_starts=(0x401005,), pred_starts=()),
            BasicBlockInfo(0x401005, END, succ_starts=(0x401005,), pred_starts=(0x401000, 0x401005)),
        ),
    )
    result = make_resolver(port).resolve_register(EAX, 0x401005 + 3)
    assert isinstance(result, Concrete) and result.value == 0x777


# -- partial writes and call clobbering ------------------------------------------------
def test_partial_register_write_is_not_reported_as_the_whole_register(port):
    # `mov al, 0x5A` gets its own register number on x86, so the walk used
    # to step straight past it and report the older full-width value.
    al = port.register_by_name("al")
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x11223344)]),
            insn(0x401005, "mov", 2, [reg(0, al, size=1), imm(1, 0x5A, size=1)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401007)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_OPERAND_SHAPE
    assert "bits [0, 8)" in result.detail


def test_sixteen_bit_write_sharing_the_parent_number_is_also_partial(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x11223344)]),
            insn(0x401005, "mov", 4, [reg(0, EAX, size=2), imm(1, 0x99, size=2)]),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401009)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_OPERAND_SHAPE


def test_thirty_two_bit_write_fully_defines_a_sixty_four_bit_register(port64):
    # x86-64 zeroes the upper half on any 32-bit destination, so
    # `mov ecx, 0x1234` really does define the whole of rcx. Without this
    # rule almost every x86-64 argument setup would report Unknown.
    port64.add_instructions([insn(0x401000, "mov", 5, [reg(0, ECX, size=4), imm(1, 0x1234)])])
    port64.set_function(FUNC, END, blocks=(BasicBlockInfo(FUNC, END, (), ()),))
    result = make_resolver(port64).resolve_register(ECX, 0x401005)
    assert isinstance(result, Concrete) and result.value == 0x1234


def test_caller_saved_register_is_not_carried_back_across_a_call(port):
    # ecx is volatile under every x86 convention: whatever `foo` did to it
    # is unknowable, so the value set before the call must not be reported.
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, ECX), imm(1, 5)]),
            insn(0x401005, "call", 5, [mem_direct(0, 0x402000)], written=(False,)),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(ECX, 0x40100A)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.NO_DEFINITION_FOUND
    assert "call" in result.detail


def test_callee_saved_register_still_resolves_across_a_call(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, ESI), imm(1, 0x404000)]),
            insn(0x401005, "call", 5, [mem_direct(0, 0x402000)], written=(False,)),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(ESI, 0x40100A)
    assert isinstance(result, Concrete) and result.value == 0x404000


def test_xor_register_with_itself_folds_to_zero(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x1234)]),
            insn(0x401005, "xor", 2, [reg(0, EAX), reg(1, EAX)], read=(True, True)),
        ]
    )
    linear_block(port)
    result = make_resolver(port).resolve_register(EAX, 0x401007)
    assert isinstance(result, Concrete) and result.value == 0
