"""Prior-call-return-value-as-argument chaining.

Covers requirement 3.1 form #8: `call funcA; mov ebx, eax; push ebx; call
funcB` — tracking a register's data flow back across an intervening call.
A `call` instruction has no explicit register operand naming the return
register, so `core.engine_backward.BackwardResolver` special-cases this:
when walking backward for `IdaPort.return_value_reg()` and it reaches a
`call`, that call is treated as the definition site and dispatched to this
locator, the same way any other definition is.
"""

from __future__ import annotations

from idanalysister.core.insn_model import Instruction
from idanalysister.core.values import Symbolic
from idanalysister.locators.base import Locator, LocatorOutcome, LocatorRegistry, ResolutionContext


class CallReturnLocator(Locator):
    """Resolves to a symbolic "return value of this call" rather than a
    concrete number — statically determining what a callee actually
    returns would require analyzing (and potentially executing) the callee,
    which is out of scope for a bounded, fast, per-call-site walk. Callers
    that need more precision can inspect `Symbolic.expr` (which encodes the
    call site address) and recurse into `api.facade.ParamExtractor` for
    that callee themselves."""

    name = "call_return"

    def matches(self, instr: Instruction) -> bool:
        return instr.mnem.startswith("call")

    def extract(self, instr: Instruction, dest_operand: int, ctx: ResolutionContext) -> LocatorOutcome:
        return LocatorOutcome.resolved(Symbolic(f"ret({instr.ea:#x})"))


def register_builtins(registry: LocatorRegistry) -> None:
    registry.register(CallReturnLocator())
