from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.merge import join, join_all
from idanalysister.core.values import Concrete, MemoryRef, Symbolic, Unknown, ValueKind, unknown


def test_join_equal_concretes_stays_concrete():
    a = Concrete(5, ValueKind.INT)
    b = Concrete(5, ValueKind.INT)
    assert join(a, b) == a


def test_join_differing_concretes_is_divergent():
    result = join(Concrete(5, ValueKind.INT), Concrete(6, ValueKind.INT))
    assert isinstance(result, Unknown) and result.reason is UnknownReason.DIVERGENT_PATHS


def test_join_with_unknown_is_absorbing():
    u = unknown(UnknownReason.BUDGET_EXCEEDED)
    assert join(Concrete(1, ValueKind.INT), u) is u
    assert join(u, Concrete(1, ValueKind.INT)) is u


def test_join_equal_symbolic_expressions():
    a = Symbolic("arg0")
    assert join(a, Symbolic("arg0")) == a


def test_join_differing_symbolic_expressions():
    result = join(Symbolic("arg0"), Symbolic("ret(0x1000)"))
    assert isinstance(result, Unknown) and result.reason is UnknownReason.DIVERGENT_SYMBOLIC


def test_join_memory_ref_same_addr_joins_inner_value():
    a = MemoryRef(addr=0x1000, value=Concrete(1, ValueKind.INT))
    b = MemoryRef(addr=0x1000, value=Concrete(1, ValueKind.INT))
    result = join(a, b)
    assert result == a


def test_join_memory_ref_different_addr_diverges():
    a = MemoryRef(addr=0x1000, value=Concrete(1, ValueKind.INT))
    b = MemoryRef(addr=0x2000, value=Concrete(1, ValueKind.INT))
    result = join(a, b)
    assert isinstance(result, Unknown)


def test_join_all_empty_is_no_definition():
    result = join_all([])
    assert isinstance(result, Unknown) and result.reason is UnknownReason.NO_DEFINITION_FOUND


def test_join_all_single_value_passthrough():
    v = Concrete(9, ValueKind.INT)
    assert join_all([v]) == v
