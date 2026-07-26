"""Verifies the documented extension mechanism: a brand-new instruction
form (here, `not reg`) can be added by writing one Locator and registering
it on a session's own registry, with zero changes to core/ or any other
locator module."""

from idanalysister.core.engine_backward import BackwardResolver
from idanalysister.core.ida_types import BasicBlockInfo
from idanalysister.core.insn_cache import InstructionCache
from idanalysister.core.values import Concrete
from idanalysister.locators.base import default_registry
from idanalysister.locators.extension_points import register_example

from ..conftest import EAX, imm, insn, reg

FUNC = 0x401000
END = 0x401100


def test_not_locator_unregistered_by_default_yields_unsupported(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0)]),
            insn(0x401005, "not", 2, [reg(0, EAX)]),
        ]
    )
    port.set_function(FUNC, END, blocks=(BasicBlockInfo(FUNC, END, (), ()),))
    registry = default_registry()  # NotLocator is intentionally not built in
    resolver = BackwardResolver(port, InstructionCache(port), registry)
    result = resolver.resolve_register(EAX, 0x401007)
    assert not result.is_known


def test_registering_extension_locator_makes_it_resolvable(port):
    port.add_instructions(
        [
            insn(0x401000, "mov", 5, [reg(0, EAX), imm(1, 0)]),
            insn(0x401005, "not", 2, [reg(0, EAX)]),
        ]
    )
    port.set_function(FUNC, END, blocks=(BasicBlockInfo(FUNC, END, (), ()),))
    registry = default_registry()
    register_example(registry)  # the one line a user adds
    resolver = BackwardResolver(port, InstructionCache(port), registry)
    result = resolver.resolve_register(EAX, 0x401007)
    assert isinstance(result, Concrete) and result.value == 0xFFFFFFFF
