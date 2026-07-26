"""Internal exception types.

None of these are meant to escape the public API (`api.facade.ParamExtractor`).
Every call into engine, locator, or post-processor code that can fail is
caught at a single boundary and converted into a typed `core.values.Unknown`
instead, per the framework's "never crash" stability requirement.
"""


class IdanalysisterError(Exception):
    """Base class for all internal framework errors."""


class DecodeError(IdanalysisterError):
    """Instruction decoding failed for a given address."""


class AdapterError(IdanalysisterError):
    """An `adapters.ida_port.IdaPort` call failed or returned inconsistent data."""


class ResolutionBudgetExceeded(IdanalysisterError):
    """A backward/forward walk exceeded its configured step/block/time budget."""


class ConventionError(IdanalysisterError):
    """A calling convention could not be constructed or applied."""
