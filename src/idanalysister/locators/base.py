"""The extension mechanism: `Locator` interface + `LocatorRegistry`.

Every argument-passing / value-producing instruction form (register moves,
pushes, memory dereferences, `cmov`, `xchg`, ...) is a `Locator`. The
resolver core (`core.engine_backward.BackwardResolver`,
`core.engine_forward.ForwardSymbolicEngine`) never special-cases a mnemonic
— it asks a `LocatorRegistry` "which locator matches this instruction?" and
delegates. Adding support for a new form never requires touching resolver
code: write one `Locator` subclass and register it (see
`locators.extension_points` for a worked example).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Callable

from idanalysister.core.insn_model import Instruction
from idanalysister.core.values import ValueLattice

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort
    from idanalysister.core.insn_cache import InstructionCache
    from idanalysister.core.state import AbstractState


class ResolutionContext:
    """Everything a `Locator.extract` needs beyond the instruction itself.

    Rather than a data-only "defer to this register" signal, locators call
    back into the active resolver directly through `resolve_register` /
    `resolve_memory` / `dereference` — this lets a locator perform genuinely
    multi-step resolution (e.g. "chase the base register, add the
    displacement, then read whatever most recently wrote there" for
    register-indirect addressing) without the resolver core having to
    understand any particular instruction shape. All three callbacks share
    the resolver's step/recursion budget, so a chain of locators calling
    back in cannot run unbounded.

    `resolve_memory(base_reg, disp, before_ea, size)` is the workhorse for
    every memory-indirect form (global, TLS, stack, register-indirect
    struct/array access): it searches backward for the nearest prior write
    to the same effective location — normalizing stack-pointer-relative
    displacements across intervening `esp`/`rsp` changes, treating
    frame-pointer-relative displacements as stable, and otherwise matching
    by literal `(base_reg, disp)` identity — and only falls back to reading
    the IDB's static byte content when no such local write is found. Pass
    `base_reg=None` for an absolute address (a plain global). `dereference`
    is the lower-level primitive `resolve_memory` falls back to; locators
    that specifically want the raw static content, bypassing local-write
    shadowing, may call it directly.
    """

    def __init__(
        self,
        port: "IdaPort",
        cache: "InstructionCache",
        func_ea: int | None,
        resolve_register: Callable[[int, int], ValueLattice],
        resolve_memory: Callable[[int | None, int, int, int], ValueLattice],
        dereference: Callable[[int, int], ValueLattice],
    ):
        self.port = port
        self.cache = cache
        self.func_ea = func_ea
        self.resolve_register = resolve_register
        self.resolve_memory = resolve_memory
        self.dereference = dereference


class OutcomeKind(Enum):
    VALUE = auto()
    NOT_APPLICABLE = auto()


@dataclass(frozen=True)
class LocatorOutcome:
    kind: OutcomeKind
    value: ValueLattice | None = None

    @classmethod
    def resolved(cls, value: ValueLattice) -> "LocatorOutcome":
        return cls(kind=OutcomeKind.VALUE, value=value)

    @classmethod
    def not_applicable(cls) -> "LocatorOutcome":
        return cls(kind=OutcomeKind.NOT_APPLICABLE)

    @property
    def is_resolved(self) -> bool:
        return self.kind is OutcomeKind.VALUE


class Locator(ABC):
    """One argument-passing / value-producing instruction form."""

    name: str = "locator"

    @abstractmethod
    def matches(self, instr: Instruction) -> bool:
        """Whether this locator knows how to interpret `instr` as a
        definition of its (single) destination operand."""

    @abstractmethod
    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        """Interpret `instr` as the backward walk's candidate definition of
        operand `dest_operand` (the resolver has already confirmed this
        operand is register/memory-matched and written by `instr` — most
        locators can ignore `dest_operand` since their instruction shape
        only ever writes operand 0, but it disambiguates instructions with
        more than one written operand, e.g. `xchg`). May recurse via `ctx`.
        Must not raise — callers wrap this defensively, but a well-behaved
        locator returns `LocatorOutcome.not_applicable()` for shapes it
        cannot handle rather than guessing."""

    def apply_forward(self, instr: Instruction, state: "AbstractState") -> "AbstractState":
        """Forward abstract-interpretation transfer function, used by
        `core.engine_forward.ForwardSymbolicEngine` for register-only
        instructions (memory loads/stores are handled centrally by the
        engine itself, mirroring `core.engine_backward`'s address
        normalization). Default: conservatively invalidate every written
        register operand to `Unknown` — safe for any locator that only
        implements backward `extract`, since leaving a stale tracked value
        in place would be actively wrong. Locators with precise forward
        semantics (mov/lea/add/sub with an immediate, movzx/movsx, cmov)
        override this to propagate instead of losing the value."""
        from idanalysister.core.insn_model import OperandKind

        for op in instr.operands:
            if op.kind is OperandKind.REG and instr.is_written(op.number):
                state.invalidate_register(op.reg)
        return state

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<Locator {self.name}>"


class LocatorRegistry:
    """Ordered, priority-sorted dispatch table for `Locator`s.

    Owned per analysis session (`api.facade.ParamExtractor`) rather than as
    global mutable state, so different sessions can carry different
    extensions without interfering with each other.
    """

    def __init__(self):
        self._locators: list[tuple[int, Locator]] = []  # (priority, locator)

    def register(self, locator: Locator, priority: int = 0) -> None:
        self._locators.append((priority, locator))
        self._locators.sort(key=lambda entry: entry[0], reverse=True)

    def match(self, instr: Instruction) -> Locator | None:
        for _priority, locator in self._locators:
            try:
                if locator.matches(instr):
                    return locator
            except Exception:
                continue
        return None

    def all(self) -> tuple[Locator, ...]:
        return tuple(locator for _priority, locator in self._locators)


def default_registry() -> LocatorRegistry:
    """A `LocatorRegistry` pre-populated with every built-in locator."""
    from idanalysister.locators import (
        arithmetic_locators,
        call_return_locators,
        immediate_locators,
        memory_locators,
        register_locators,
        stack_locators,
    )

    registry = LocatorRegistry()
    for module in (
        register_locators,
        immediate_locators,
        memory_locators,
        stack_locators,
        call_return_locators,
        arithmetic_locators,
    ):
        module.register_builtins(registry)
    return registry
