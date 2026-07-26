"""Queryable control-flow graph for one function.

Wraps `adapters.ida_port.IdaPort.get_flowchart_blocks` (itself a thin
wrapper over `ida_gdl.FlowChart`) into a structure the backward resolver and
forward engine can traverse without touching `ida_*` directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from idanalysister.core.ida_types import BasicBlockInfo

if TYPE_CHECKING:
    from idanalysister.adapters.ida_port import IdaPort


@dataclass(frozen=True)
class CfgModel:
    func_ea: int
    blocks: tuple[BasicBlockInfo, ...]

    def __post_init__(self):
        object.__setattr__(self, "_by_start", {b.start_ea: b for b in self.blocks})

    def is_empty(self) -> bool:
        return not self.blocks

    def block_containing(self, ea: int) -> BasicBlockInfo | None:
        for block in self.blocks:
            if block.start_ea <= ea < block.end_ea:
                return block
        return None

    def predecessors(self, block: BasicBlockInfo) -> tuple[BasicBlockInfo, ...]:
        by_start: dict[int, BasicBlockInfo] = self._by_start  # type: ignore[attr-defined]
        return tuple(by_start[s] for s in block.pred_starts if s in by_start)

    def successors(self, block: BasicBlockInfo) -> tuple[BasicBlockInfo, ...]:
        by_start: dict[int, BasicBlockInfo] = self._by_start  # type: ignore[attr-defined]
        return tuple(by_start[s] for s in block.succ_starts if s in by_start)


def build_cfg(port: "IdaPort", func_ea: int) -> CfgModel:
    blocks = port.get_flowchart_blocks(func_ea)
    return CfgModel(func_ea=func_ea, blocks=blocks)
