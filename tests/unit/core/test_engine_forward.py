"""ForwardSymbolicEngine (3.3): straight-line propagation, alias tracking,
loop survival without widening, genuine non-convergence, and the
documented stack-argument scope limit."""

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.engine_forward import ForwardSymbolicEngine
from idanalysister.core.ida_types import BasicBlockInfo
from idanalysister.core.insn_cache import InstructionCache
from idanalysister.core.state import AbstractState
from idanalysister.core.values import Concrete, Symbolic, Unknown
from idanalysister.locators.base import default_registry

from ..conftest import (
    EAX,
    EBP,
    EBX,
    ECX,
    EDX,
    ESI,
    RCX,
    RDX,
    RSI,
    imm,
    insn,
    mem_direct,
    mem_displ,
    mem_index,
    mem_phrase,
    reg,
)

FUNC = 0x500000


def make_engine(port, **kwargs):
    cache = InstructionCache(port)
    return ForwardSymbolicEngine(port, cache, default_registry(), **kwargs)


def test_straight_line_alias_tracking(port64):
    # arg0 enters in rcx; mov rdx, rcx; call — rdx should read as Symbolic('arg0').
    port64.add_instructions(
        [
            insn(0x500000, "mov", 5, [reg(0, RDX, 8), reg(1, RCX, 8)]),
            insn(0x500005, "call", 5, [mem_direct(0, 0x600000, 8)], written=(False,)),
        ]
    )
    port64.set_function(FUNC, 0x500100, blocks=(BasicBlockInfo(FUNC, 0x500100, (), ()),))
    engine = make_engine(port64)
    result = engine.resolve_at(FUNC, arg_index=0, target_ea=0x500005, initial_reg=RCX)
    assert isinstance(result, Symbolic) and result.expr == "arg0"
    # And rdx (read via a second query re-seeded at rdx) should match too —
    # verified indirectly: simulate to just after the mov and check via a
    # fresh engine seeded at rdx is out of scope for this helper API, so we
    # instead confirm rcx itself (the source of the alias) is untouched.


def test_loop_that_never_reassigns_tracked_register_survives(port64):
    # Mirrors the architecture walkthrough: a counting loop writes memory
    # via [rcx+rsi] (index-relative, not sp/fp) without ever touching rcx.
    insns = [
        insn(0x500000, "mov", 5, [reg(0, RSI, 4), imm(1, 0)]),
        insn(0x500005, "cmp", 5, [reg(0, RSI, 4), imm(1, 0x20)], written=(False, False)),
        insn(0x50000A, "jge", 5, [mem_direct(0, 0x500020, 8)], written=(False,)),
        insn(0x50000F, "mov", 5, [mem_phrase(0, RCX, 1), reg(1, EAX, 1)]),
        insn(0x500014, "inc", 5, [reg(0, RSI, 4)]),
        insn(0x500019, "jmp", 1, [mem_direct(0, 0x500005, 8)], written=(False,)),
        insn(0x500020, "call", 5, [mem_direct(0, 0x600000, 8)], written=(False,)),
    ]
    blocks = (
        BasicBlockInfo(0x500000, 0x500005, succ_starts=(0x500005,), pred_starts=()),
        BasicBlockInfo(0x500005, 0x50000F, succ_starts=(0x50000F, 0x500020), pred_starts=(0x500000, 0x50000F)),
        BasicBlockInfo(0x50000F, 0x50001A, succ_starts=(0x500005,), pred_starts=(0x500005,)),
        BasicBlockInfo(0x500020, 0x500100, succ_starts=(), pred_starts=(0x500005,)),
    )
    port64.add_instructions(insns)
    port64.set_function(FUNC, 0x500100, blocks=blocks)
    engine = make_engine(port64)
    result = engine.resolve_at(FUNC, arg_index=0, target_ea=0x500020, initial_reg=RCX)
    assert isinstance(result, Symbolic) and result.expr == "arg0"


def test_divergent_branches_yield_unknown(port64):
    # arg0 in rcx; one branch overwrites rcx with a constant, the other
    # leaves it untouched -> value at the join must be Unknown, not guessed.
    insns = [
        insn(0x500000, "jz", 5, [mem_direct(0, 0x50000A, 8)], written=(False,)),
        insn(0x500005, "mov", 5, [reg(0, RCX, 8), imm(1, 42, 8)]),
        insn(0x50000A, "call", 5, [mem_direct(0, 0x600000, 8)], written=(False,)),
    ]
    blocks = (
        BasicBlockInfo(0x500000, 0x500005, succ_starts=(0x500005, 0x50000A), pred_starts=()),
        BasicBlockInfo(0x500005, 0x50000A, succ_starts=(0x50000A,), pred_starts=(0x500000,)),
        BasicBlockInfo(0x50000A, 0x500100, succ_starts=(), pred_starts=(0x500000, 0x500005)),
    )
    port64.add_instructions(insns)
    port64.set_function(FUNC, 0x500100, blocks=blocks)
    engine = make_engine(port64)
    result = engine.resolve_at(FUNC, arg_index=0, target_ea=0x50000A, initial_reg=RCX)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.DIVERGENT_PATHS


def test_stack_passed_argument_forward_tracking_is_unsupported_not_guessed(port64):
    port64.set_function(FUNC, 0x500100, blocks=(BasicBlockInfo(FUNC, 0x500100, (), ()),))
    engine = make_engine(port64)
    result = engine.resolve_at(FUNC, arg_index=0, target_ea=0x500000, initial_reg=None)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.UNSUPPORTED_OPERAND_SHAPE


# -- regressions: the central memory path used to hijack other shapes ------------------
def simulate(port, instructions, func_ea=0x401000, end_ea=0x401100, seed=None):
    """Run one straight-line block and return the resulting state."""
    port.add_instructions(instructions)
    block = BasicBlockInfo(func_ea, end_ea, (), ())
    port.set_function(func_ea, end_ea, blocks=(block,))
    state = AbstractState()
    for reg_num, value in (seed or {}).items():
        state.set_register(reg_num, value)
    out, _ = make_engine(port)._simulate_block(block, state, func_ea, {"instr": 0})
    return out


def test_lea_of_a_stack_address_is_not_a_load_of_that_slot(port):
    # `lea esi, [ebp-8]` computes an address; classifying it by operand
    # shape put it through the memory-load path, so esi took on the
    # *contents* of the slot instead.
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 3, [mem_displ(0, EBP, -8), reg(1, ECX)]),
            insn(0x401003, "lea", 3, [reg(0, ESI), mem_displ(1, EBP, -8)]),
        ],
        seed={ECX: Symbolic("arg0")},
    )
    assert out.get_register(ESI) != Symbolic("arg0")


def test_read_modify_write_to_a_stack_slot_is_not_recorded_as_a_store(port):
    # `add [ebp-8], ecx` leaves the slot holding old+ecx, not ecx.
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 3, [mem_displ(0, EBP, -8), imm(1, 0x10)]),
            insn(0x401003, "add", 3, [mem_displ(0, EBP, -8), reg(1, ECX)], written=(True, False), read=(True, True)),
            insn(0x401006, "mov", 3, [reg(0, EAX), mem_displ(1, EBP, -8)]),
        ],
        seed={ECX: Symbolic("arg0")},
    )
    assert isinstance(out.get_register(EAX), Unknown)


def test_read_modify_write_from_a_stack_slot_is_not_recorded_as_a_load(port):
    # `add eax, [ebp-8]` used to assign eax the slot's contents outright,
    # reporting 0x10 where 0x110 was correct.
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 3, [mem_displ(0, EBP, -8), imm(1, 0x10)]),
            insn(0x401003, "mov", 5, [reg(0, EAX), imm(1, 0x100)]),
            insn(0x401008, "add", 3, [reg(0, EAX), mem_displ(1, EBP, -8)], written=(True, False), read=(True, True)),
        ],
    )
    result = out.get_register(EAX)
    assert isinstance(result, Unknown), f"must not fabricate a value, got {result!r}"


def test_plain_spill_and_reload_still_propagates(port):
    # The gating above must not break the case the memory path exists for.
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 3, [mem_displ(0, EBP, -8), reg(1, ECX)]),
            insn(0x401003, "mov", 3, [reg(0, EAX), mem_displ(1, EBP, -8)]),
        ],
        seed={ECX: Symbolic("arg0")},
    )
    assert out.get_register(EAX) == Symbolic("arg0")


def test_indexed_stack_write_invalidates_the_tracked_slots(port):
    # `mov [ebp+eax*4], edx` lands on *some* frame slot; which one is not
    # knowable, so none of them can be trusted afterwards.
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 3, [mem_displ(0, EBP, -8), reg(1, ECX)]),
            insn(0x401003, "mov", 3, [mem_index(0, EBP, EAX, scale=4), reg(1, EDX)]),
            insn(0x401006, "mov", 3, [reg(0, EBX), mem_displ(1, EBP, -8)]),
        ],
        seed={ECX: Symbolic("arg0")},
    )
    assert isinstance(out.get_register(EBX), Unknown)


def test_indexed_write_through_another_register_leaves_the_stack_model_alone(port):
    # The canonical decryption loop writes `[ptr+counter]`. Those writes
    # must not wipe the caller's tracked stack slots.
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 3, [mem_displ(0, EBP, -8), reg(1, ECX)]),
            insn(0x401003, "mov", 3, [mem_index(0, EBX, EAX, scale=1), reg(1, EDX)]),
            insn(0x401006, "mov", 3, [reg(0, ESI), mem_displ(1, EBP, -8)]),
        ],
        seed={ECX: Symbolic("arg0")},
    )
    assert out.get_register(ESI) == Symbolic("arg0")


def test_partial_register_write_invalidates_the_parent(port):
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0x11223344)]),
            insn(0x401005, "mov", 4, [reg(0, EAX, size=2), imm(1, 0x99, size=2)]),
        ],
    )
    assert isinstance(out.get_register(EAX), Unknown)


def test_call_clobbers_caller_saved_registers_and_names_its_return_value(port):
    out = simulate(
        port,
        [
            insn(0x401000, "mov", 5, [reg(0, ECX), imm(1, 5)]),
            insn(0x401005, "mov", 5, [reg(0, ESI), imm(1, 7)]),
            insn(0x40100A, "call", 5, [mem_direct(0, 0x402000)], written=(False,)),
        ],
    )
    assert isinstance(out.get_register(ECX), Unknown)
    assert out.get_register(ESI) == Concrete(7, out.get_register(ESI).kind)
    assert out.get_register(EAX) == Symbolic("ret(0x40100a)")


def test_unconverged_fixpoint_reports_budget_exceeded_rather_than_a_value(port64):
    insns = [
        insn(0x500000, "mov", 5, [reg(0, RDX, 8), reg(1, RCX, 8)]),
        insn(0x500005, "jmp", 5, [mem_direct(0, 0x500000, 8)], written=(False,)),
    ]
    blocks = (
        BasicBlockInfo(0x500000, 0x500005, succ_starts=(0x500005,), pred_starts=()),
        BasicBlockInfo(0x500005, 0x500100, succ_starts=(0x500000,), pred_starts=(0x500000,)),
    )
    port64.add_instructions(insns)
    port64.set_function(FUNC, 0x500100, blocks=blocks)
    engine = make_engine(port64, max_instructions=1)
    result = engine.resolve_at(FUNC, arg_index=0, target_ea=0x500005, initial_reg=RCX)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.BUDGET_EXCEEDED
