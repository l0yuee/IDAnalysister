"""Reasons a resolution attempt yielded `Unknown`.

Attaching a reason to every `Unknown` (rather than a bare `None`) makes
extraction failures auditable — a malware analyst needs to know *why* an
argument didn't resolve, not just that it didn't.
"""

from __future__ import annotations

from enum import Enum, auto


class UnknownReason(Enum):
    #: Backward walk reached the function entry (or analysis boundary)
    #: without finding a defining write to the tracked location.
    NO_DEFINITION_FOUND = auto()
    #: Two or more control-flow paths reach the use site with different
    #: concrete values; the framework never guesses which one applies.
    DIVERGENT_PATHS = auto()
    #: Two or more paths produce different symbolic expressions.
    DIVERGENT_SYMBOLIC = auto()
    #: The walk exceeded its configured step/block/time budget.
    BUDGET_EXCEEDED = auto()
    #: No registered `Locator` matched this instruction at all.
    UNSUPPORTED_INSTRUCTION = auto()
    #: A locator matched the mnemonic but not this exact operand shape.
    UNSUPPORTED_OPERAND_SHAPE = auto()
    #: Control flow reaches the point of interest through an indirect
    #: call/jump, breaking static certainty.
    INDIRECT_CONTROL_FLOW = auto()
    #: A memory dereference targeted an address with no data in the IDB.
    MEMORY_READ_FAILED = auto()
    #: A loop's tracked state did not converge within the iteration budget.
    LOOP_NON_CONVERGENT = auto()
    #: The underlying `IdaPort` call failed or raised.
    ADAPTER_ERROR = auto()
    #: An unexpected internal exception was caught at an engine boundary;
    #: this is the last-resort safety net for the "never crash" requirement.
    INTERNAL_ERROR = auto()
    #: Memory relative to a tracked pointer was mutated with a
    #: non-constant offset (e.g. inside a loop); the pointer identity may
    #: still be known even though its pointee content is not.
    MUTATED_MEMORY_CONTENT = auto()
