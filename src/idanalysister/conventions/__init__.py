"""Calling-convention templates and inference.

A `CallingConvention` maps an argument index to an `ArgSlot` describing
*where* that argument's value lives at a call site — a fixed register, a
position in a contiguous `push` sequence immediately before the call, or a
byte offset from the stack pointer at the moment of the call. Users combine
built-in templates (`conventions.templates`), let the framework infer one
from a recognized IDA prototype (`conventions.inference`), or compose a
custom one (`conventions.custom_builder`) — never by writing new resolver
code.
"""
