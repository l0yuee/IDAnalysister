"""`ArgTypeSpec` — declares the type/post-processing of one argument index.

    arg_types = {
        1: ArgTypeSpec.c_string(1, label="filename"),
        2: ArgTypeSpec.integer(2, hex_format=True),
    }
    report = extractor.extract_calls(func_ea, arg_types=arg_types)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from idanalysister.postproc.base import PostProcessor, PostProcessorChain
from idanalysister.postproc.registry import create


@dataclass
class ArgTypeSpec:
    index: int
    postprocessors: PostProcessorChain = field(default_factory=PostProcessorChain)
    label: str | None = None

    @classmethod
    def c_string(cls, index: int, label: str | None = None, max_len: int = 4096) -> "ArgTypeSpec":
        return cls(
            index=index,
            postprocessors=PostProcessorChain([create("c_string", max_len=max_len)]),
            label=label,
        )

    @classmethod
    def wide_string(cls, index: int, label: str | None = None, max_len: int = 4096) -> "ArgTypeSpec":
        return cls(
            index=index,
            postprocessors=PostProcessorChain([create("wide_string", max_len=max_len)]),
            label=label,
        )

    @classmethod
    def integer(cls, index: int, hex_format: bool = False, label: str | None = None) -> "ArgTypeSpec":
        steps: list[PostProcessor] = [create("int")]
        if hex_format:
            steps.append(create("hex"))
        return cls(index=index, postprocessors=PostProcessorChain(steps), label=label)

    @classmethod
    def custom(cls, index: int, *postprocessors: PostProcessor, label: str | None = None) -> "ArgTypeSpec":
        return cls(index=index, postprocessors=PostProcessorChain(list(postprocessors)), label=label)
