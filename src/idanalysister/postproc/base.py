"""Post-processor interface + chaining, bound to argument indices via
`typespec.argtype.ArgTypeSpec` (requirement 3.2).

Post-processors perform secondary processing on a raw resolved
`core.values.ValueLattice` — dereferencing a pointer into a C string,
formatting an integer as hex, or applying a user-supplied decryption
routine to a buffer. A chain never raises past `run()`: a failing step logs
and degrades to `Unknown` rather than crashing the whole extraction, and an
already-`Unknown` input short-circuits without running later steps.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from idanalysister.core.diagnostics import UnknownReason
from idanalysister.core.values import Unknown, ValueLattice, unknown
from idanalysister.logging_ import get_logger

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort

_logger = get_logger("postproc.base")


class PostProcessor(ABC):
    name: str = "postprocessor"

    @abstractmethod
    def process(self, value: ValueLattice, port: "IdaPort") -> ValueLattice:
        """Transform `value`. Should prefer returning `Unknown` over
        raising on failure — `PostProcessorChain.run` wraps this
        defensively regardless, as a second safety net."""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<PostProcessor {self.name}>"


class PostProcessorChain:
    def __init__(self, steps: list[PostProcessor] | None = None):
        self.steps: list[PostProcessor] = list(steps) if steps else []

    def run(self, value: ValueLattice, port: "IdaPort") -> ValueLattice:
        current = value
        for step in self.steps:
            if isinstance(current, Unknown):
                return current
            try:
                current = step.process(current, port)
            except Exception:
                _logger.exception("Post-processor %s failed", step.name)
                return unknown(UnknownReason.INTERNAL_ERROR, detail=f"post-processor {step.name} raised")
        return current

    def __bool__(self) -> bool:
        return bool(self.steps)
