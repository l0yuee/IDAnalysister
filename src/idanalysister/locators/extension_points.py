"""How to add support for an instruction form the built-in locators don't
cover, without touching any file under `core/`.

The pattern (satisfies requirement 3.1 form #9 — "any other rare forms ...
must be easily supportable through an extension mechanism without modifying
the framework core"):

    1. Subclass `locators.base.Locator`.
    2. `matches(instr)` recognizes the instruction shape by mnemonic and
       operand kinds only — cheap, no IDA calls.
    3. `extract(instr, dest_operand, ctx)` computes the value, recursing
       into `ctx.resolve_register` / `ctx.resolve_memory` for source
       operands that are themselves not yet resolved. Return
       `LocatorOutcome.not_applicable()` for any shape you don't handle —
       never guess.
    4. Register an instance with a `LocatorRegistry`, either by passing
       `registry=...` to `api.facade.ParamExtractor` at construction, or by
       calling `extractor.registry.register(YourLocator())` afterward.
       Each `ParamExtractor` owns its own registry (see
       `locators.base.default_registry`), so registering a custom locator in
       one session never leaks into another.

`NotLocator` below is a complete, runnable example — a one-operand
arithmetic form (`not reg`, bitwise complement, in place) not covered by the
built-ins. It is intentionally NOT included in `locators.base.default_registry`;
call `register_example` to add it, exactly as a user would add their own.
"""

from __future__ import annotations

from idanalysister.core.insn_model import Instruction, OperandKind
from idanalysister.core.values import Concrete, ValueKind
from idanalysister.locators.base import Locator, LocatorOutcome, LocatorRegistry, ResolutionContext

#: Mask width in bits used to fold `not` results — best-effort, keyed off
#: the operand's decoded size rather than assuming a fixed width.
_BITS_PER_BYTE = 8


class NotLocator(Locator):
    """`not reg` — bitwise complement, in place. Demonstrates a locator
    whose source and destination are the same operand (recurse into
    `ctx.resolve_register` for the register's value *before* this
    instruction, then fold)."""

    name = "not_reg"

    def matches(self, instr: Instruction) -> bool:
        if instr.mnem != "not":
            return False
        dst = instr.operand(0)
        return dst is not None and dst.kind is OperandKind.REG

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        dst = instr.operand(dest_operand)
        prior = ctx.resolve_register(dst.reg, instr.ea)
        if not isinstance(prior, Concrete) or not isinstance(prior.value, int):
            return LocatorOutcome.resolved(prior)  # propagate Unknown/Symbolic as-is
        width_bits = (dst.dtype_size or 4) * _BITS_PER_BYTE
        mask = (1 << width_bits) - 1
        return LocatorOutcome.resolved(Concrete((~prior.value) & mask, ValueKind.INT))


def register_example(registry: LocatorRegistry) -> None:
    """Adds `NotLocator` to `registry` — call this (or register your own
    locators the same way) after constructing a `ParamExtractor` to opt in
    to the example."""
    registry.register(NotLocator())
