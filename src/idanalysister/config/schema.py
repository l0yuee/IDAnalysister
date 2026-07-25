"""Build `CallingConvention` + `ArgTypeSpec` objects from a plain `dict`,
so most analysis tasks can be expressed as data instead of code:

    config = {
        "convention": "fastcall",
        "num_args": 3,
        "arg_types": {
            1: {"type": "c_string"},
            2: {"type": "integer", "hex": True},
        },
    }
    convention, num_args, arg_types = build_from_config(config)
    report = extractor.extract_calls(func_ea, convention, num_args, arg_types)

A custom convention is expressed as:

    {"convention": {"custom": [
        {"index": 0, "reg": "rcx"},
        {"index": 1, "stack_offset": 0x28},
        {"index": 2, "stack_push": 0},
    ]}}

No YAML dependency is taken here — load YAML/JSON yourself and pass the
resulting plain `dict`; this module only interprets that structure.
"""

from __future__ import annotations

from idanalysister.conventions.base import CallingConvention
from idanalysister.conventions.custom_builder import ConventionBuilder
from idanalysister.conventions.templates import by_name
from idanalysister.postproc.registry import create
from idanalysister.typespec.argtype import ArgTypeSpec


def _build_convention(spec) -> CallingConvention:
    if isinstance(spec, str):
        return by_name(spec)
    if isinstance(spec, dict) and "custom" in spec:
        builder = ConventionBuilder(spec.get("name", "custom"))
        for entry in spec["custom"]:
            index = entry["index"]
            if "reg" in entry:
                builder.reg(index, entry["reg"])
            elif "stack_offset" in entry:
                builder.stack_offset(index, entry["stack_offset"])
            elif "stack_push" in entry:
                builder.stack_push(index, entry["stack_push"])
            else:
                raise ValueError(f"unrecognized custom slot spec: {entry!r}")
        return builder.build()
    raise ValueError(f"unrecognized convention spec: {spec!r}")


def _build_arg_type(index: int, spec: dict) -> ArgTypeSpec:
    kind = spec.get("type")
    label = spec.get("label")
    if kind == "c_string":
        return ArgTypeSpec.c_string(index, label=label, max_len=spec.get("max_len", 4096))
    if kind == "wide_string":
        return ArgTypeSpec.wide_string(index, label=label, max_len=spec.get("max_len", 4096))
    if kind == "integer":
        return ArgTypeSpec.integer(index, hex_format=bool(spec.get("hex", False)), label=label)
    if kind == "custom":
        steps = [create(name, **params) for name, params in spec.get("postprocessors", [])]
        return ArgTypeSpec.custom(index, *steps, label=label)
    raise ValueError(f"unrecognized argument type {kind!r} for index {index}")


def build_from_config(config: dict):
    """Returns `(convention, num_args, arg_types)`, each ready to pass to
    `api.facade.ParamExtractor.extract_calls`. `convention` is `None` if
    `config` doesn't specify one (letting the extractor fall back to
    prototype inference / cdecl); `num_args` is `None` if unspecified."""
    convention = _build_convention(config["convention"]) if "convention" in config else None
    num_args = config.get("num_args")
    arg_types_cfg = config.get("arg_types", {})
    arg_types = {int(index): _build_arg_type(int(index), spec) for index, spec in arg_types_cfg.items()}
    return convention, num_args, arg_types
