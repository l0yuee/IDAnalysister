"""Pure-Python analysis core.

Nothing under `core/` imports an `ida_*` module directly — all IDA interaction
is injected as an `adapters.ida_port.IdaPort` instance, which is what makes
this package unit-testable without a running IDA instance.
"""
