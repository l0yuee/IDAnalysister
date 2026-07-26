from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.values import Concrete, MemoryRef, Unknown, ValueKind
from idanalysister.postproc.base import PostProcessorChain
from idanalysister.postproc.builtins import CStringDeref, HexFormat, IntCast, StructFieldDeref, WideStringDeref


def test_c_string_deref(port):
    port.set_memory(0x404000, b"hello\x00")
    result = CStringDeref().process(Concrete(0x404000, ValueKind.POINTER), port)
    assert isinstance(result, Concrete) and result.value == "hello"


def test_c_string_deref_through_memory_ref_pointer(port):
    port.set_memory(0x404000, b"world\x00")
    raw = MemoryRef(addr=0x403000, value=Concrete(0x404000, ValueKind.POINTER))
    result = CStringDeref().process(raw, port)
    assert isinstance(result, Concrete) and result.value == "world"


def test_c_string_deref_missing_data_is_unknown(port):
    result = CStringDeref().process(Concrete(0x999000, ValueKind.POINTER), port)
    assert isinstance(result, Unknown) and result.reason is UnknownReason.MEMORY_READ_FAILED


def test_wide_string_deref(port):
    port.set_memory(0x404000, "hi\x00".encode("utf-16-le"))
    result = WideStringDeref().process(Concrete(0x404000, ValueKind.POINTER), port)
    assert isinstance(result, Concrete) and result.value == "hi"


def test_hex_format(port):
    result = HexFormat().process(Concrete(255, ValueKind.INT), port)
    assert result.value == "0xff"


def test_hex_format_negative(port):
    result = HexFormat().process(Concrete(-1, ValueKind.INT), port)
    assert result.value == "-0x1"


def test_int_cast_unwraps_memory_ref(port):
    raw = MemoryRef(addr=0x1000, value=Concrete(42, ValueKind.INT))
    result = IntCast().process(raw, port)
    assert isinstance(result, Concrete) and result.value == 42 and result.kind is ValueKind.INT


def test_struct_field_deref(port):
    port.set_memory(0x404010, (999).to_bytes(4, "little"))
    result = StructFieldDeref(offset=0x10, size=4).process(Concrete(0x404000, ValueKind.POINTER), port)
    assert isinstance(result, Concrete) and result.value == 999


def test_chain_short_circuits_on_unknown(port):
    chain = PostProcessorChain([CStringDeref(), HexFormat()])
    from idanalysister.core.values import unknown

    u = unknown(UnknownReason.NO_DEFINITION_FOUND)
    assert chain.run(u, port) is u


def test_chain_runs_steps_in_order(port):
    port.set_memory(0x404000, b"abc\x00")
    chain = PostProcessorChain([CStringDeref()])
    result = chain.run(Concrete(0x404000, ValueKind.POINTER), port)
    assert result.value == "abc"
