"""Argument-passing instruction form strategies (`Locator`s).

Each module here implements one family of instruction forms. New forms are
added by writing a new `Locator` subclass and registering it — see
`locators.base.LocatorRegistry` and `locators.extension_points` for the
extension pattern. No module in this package imports an `ida_*` module
directly; all IDA interaction is reached through `ResolutionContext`
(`locators.base`), which wraps an `adapters.ida_port.IdaPort`.
"""
