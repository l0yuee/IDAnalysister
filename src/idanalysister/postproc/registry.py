"""Name -> `PostProcessor` factory registry, for declarative (config-driven)
post-processor selection — see `config.schema` and `typespec.argtype`.
Custom post-processors (e.g. a project-specific decryption routine) are
added the same way the built-ins are: call `register_postprocessor` with a
unique name and a zero/keyword-arg constructor.
"""

from __future__ import annotations

from typing import Callable

from idanalysister.postproc.base import PostProcessor
from idanalysister.postproc.builtins import CStringDeref, HexFormat, IntCast, StructFieldDeref, WideStringDeref

_REGISTRY: dict[str, Callable[..., PostProcessor]] = {}


def register_postprocessor(name: str, factory: Callable[..., PostProcessor]) -> None:
    _REGISTRY[name] = factory


def create(name: str, **kwargs) -> PostProcessor:
    try:
        factory = _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"Unknown post-processor {name!r}; available: {sorted(_REGISTRY)}") from exc
    return factory(**kwargs)


register_postprocessor("c_string", CStringDeref)
register_postprocessor("wide_string", WideStringDeref)
register_postprocessor("hex", HexFormat)
register_postprocessor("int", IntCast)
register_postprocessor("struct_field", StructFieldDeref)
