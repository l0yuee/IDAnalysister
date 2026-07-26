"""Concrete `IdaPort` backed by IDA's public `ida_*` Python modules.

This is the ONLY module in the framework allowed to import `ida_ua`,
`idautils`, `ida_gdl`, `ida_bytes`, `ida_funcs`, `ida_frame`, `ida_typeinf`,
`ida_nalt`, or `ida_idp`. Every method below is wrapped so that a failing or
raising underlying call is logged and degrades to the documented "not
resolvable" return value (`None` / empty tuple) instead of propagating —
this is the concrete mechanism behind the framework's "never crash" and
"public API only" requirements.
"""

from __future__ import annotations

import functools
from typing import Callable, TypeVar

from idanalysister.adapters.ida_port import IdaPort
from idanalysister.core.ida_types import ArgLocation, BasicBlockInfo, FunctionPrototype
from idanalysister.core.insn_model import Instruction, Operand, OperandKind
from idanalysister.logging_ import get_logger

_logger = get_logger("adapters.ida_port_impl")

_T = TypeVar("_T")

#: Segment-override register names relevant to argument passing (TLS access).
#: Anything else (cs/ds/ss/es) is the processor's default and not surfaced as
#: an explicit `segment_name` on the operand.
_TLS_SEGMENT_NAMES = {"fs", "gs"}

_CC_NAME_BY_CONST: dict[int, str] | None = None


def _safe(default: _T | Callable[[], _T] = None) -> Callable:
    """Decorator: any `ida_*` call wrapped with this never raises past the
    adapter boundary — it logs and returns `default` (or `default()` if
    callable) instead."""

    def decorator(fn: Callable[..., _T]) -> Callable[..., _T]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception:
                _logger.exception("IDA adapter call failed: %s", fn.__qualname__)
                return default() if callable(default) else default

        return wrapper

    return decorator


def _empty_tuple() -> tuple:
    return ()


class IdaPortImpl(IdaPort):
    """`IdaPort` implementation for use inside a running IDA / `idalib`
    session with a loaded database."""

    # -- instruction decoding -------------------------------------------------
    @_safe(default=None)
    def decode_at(self, ea: int) -> Instruction | None:
        import ida_ua

        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return None
        return _convert_instruction(insn)

    @_safe(default=None)
    def prev_head(self, ea: int, min_ea: int) -> int | None:
        import ida_bytes
        import ida_idaapi

        prev_ea = ida_bytes.prev_head(ea, min_ea)
        if prev_ea == ida_idaapi.BADADDR:
            return None
        return prev_ea

    # -- cross references -------------------------------------------------------
    @_safe(default=_empty_tuple)
    def code_refs_to(self, ea: int) -> tuple[int, ...]:
        import idautils
        import ida_xref

        # fl_CN/fl_CF: ordinary `call` instructions. fl_JN/fl_JF: a `jmp`
        # straight to the function's entry point from outside it — the
        # standard compiler pattern for a tail call (the last statement in
        # a function calling another is folded from `call X; ret` into
        # `jmp X`) or a thunk/import stub whose entire body is one jump.
        # Both are genuine call sites: the caller's own function set up
        # the arguments identically either way, so omitting jump-type
        # xrefs here would silently under-report call sites relative to
        # what IDA's own xref graph (and UI) already knows about.
        refs = []
        for xref in idautils.XrefsTo(ea, 0):
            if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF):
                refs.append(xref.frm)
        return tuple(sorted(set(refs)))

    # -- functions / control flow ------------------------------------------------
    @_safe(default=None)
    def get_func_start(self, ea: int) -> int | None:
        import ida_funcs

        pfn = ida_funcs.get_func(ea)
        return pfn.start_ea if pfn else None

    @_safe(default=None)
    def get_func_end(self, ea: int) -> int | None:
        import ida_funcs

        pfn = ida_funcs.get_func(ea)
        return pfn.end_ea if pfn else None

    @_safe(default=_empty_tuple)
    def get_flowchart_blocks(self, func_ea: int) -> tuple[BasicBlockInfo, ...]:
        import ida_funcs
        import ida_gdl

        pfn = ida_funcs.get_func(func_ea)
        if pfn is None:
            return ()
        flowchart = ida_gdl.FlowChart(f=pfn)
        blocks = []
        for block in flowchart:
            succ_starts = tuple(sorted({succ.start_ea for succ in block.succs()}))
            pred_starts = tuple(sorted({pred.start_ea for pred in block.preds()}))
            blocks.append(
                BasicBlockInfo(
                    start_ea=block.start_ea,
                    end_ea=block.end_ea,
                    succ_starts=succ_starts,
                    pred_starts=pred_starts,
                )
            )
        return tuple(blocks)

    # -- memory reads -------------------------------------------------------------
    @_safe(default=None)
    def read_int(self, addr: int, size: int, signed: bool = False) -> int | None:
        raw = self.read_bytes(addr, size)
        if raw is None:
            return None
        return int.from_bytes(raw, byteorder="little", signed=signed)

    @_safe(default=None)
    def read_bytes(self, addr: int, size: int) -> bytes | None:
        import ida_bytes

        out = bytearray()
        for offset in range(size):
            cur = addr + offset
            if not ida_bytes.is_loaded(cur):
                return None
            out.append(ida_bytes.get_byte(cur))
        return bytes(out)

    @_safe(default=None)
    def read_cstring(self, addr: int, max_len: int = 4096) -> str | None:
        import ida_bytes

        raw = bytearray()
        for offset in range(max_len):
            cur = addr + offset
            if not ida_bytes.is_loaded(cur):
                return None
            byte_value = ida_bytes.get_byte(cur)
            if byte_value == 0:
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    return raw.decode("latin-1")
            raw.append(byte_value)
        return None

    @_safe(default=None)
    def read_wstring(self, addr: int, max_len: int = 4096) -> str | None:
        import ida_bytes

        raw = bytearray()
        offset = 0
        while offset < max_len * 2:
            cur = addr + offset
            if not ida_bytes.is_loaded(cur) or not ida_bytes.is_loaded(cur + 1):
                return None
            lo = ida_bytes.get_byte(cur)
            hi = ida_bytes.get_byte(cur + 1)
            if lo == 0 and hi == 0:
                return raw.decode("utf-16-le", errors="replace")
            raw.append(lo)
            raw.append(hi)
            offset += 2
        return None

    # -- calling convention / type info -------------------------------------------
    @_safe(default=None)
    def get_prototype(self, func_ea: int) -> FunctionPrototype | None:
        import ida_nalt
        import ida_typeinf

        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, func_ea):
            if not ida_typeinf.guess_tinfo(tif, func_ea):
                return None
        if not tif.is_func():
            return None

        details = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(details):
            return None

        cc_name = _calling_convention_name(details.get_cc())
        is_variadic = bool(details.get_cc() & ida_typeinf.CM_CC_ELLIPSIS)

        locations = []
        for index in range(len(details)):
            arg = details[index]
            loc = arg.argloc
            if loc.is_reg1() or loc.is_reg2():
                reg = loc.reg1()
                locations.append(
                    ArgLocation(
                        index=index,
                        is_register=True,
                        reg=reg,
                        reg_name=_reg_name(reg),
                    )
                )
            elif loc.is_stkoff():
                locations.append(
                    ArgLocation(
                        index=index,
                        is_register=False,
                        stack_offset=loc.stkoff(),
                    )
                )
            else:
                # Scattered / register-relative / custom argloc kinds are not
                # representable as a single ArgSlot yet — omit rather than guess.
                _logger.debug(
                    "Unsupported argloc kind for %s arg %d; omitting from prototype",
                    hex(func_ea),
                    index,
                )

        return FunctionPrototype(
            calling_convention=cc_name,
            arg_locations=tuple(locations),
            is_variadic=is_variadic,
        )

    # -- stack frame ----------------------------------------------------------------
    @_safe(default=None)
    def get_sp_delta(self, func_ea: int, ea: int) -> int | None:
        import ida_frame
        import ida_funcs

        pfn = ida_funcs.get_func(func_ea)
        if pfn is None:
            return None
        return ida_frame.get_spd(pfn, ea)

    # -- address bitness / pointer size ------------------------------------------------
    @_safe(default=8)
    def pointer_size(self) -> int:
        import ida_ida

        if ida_ida.inf_is_64bit():
            return 8
        if ida_ida.inf_is_32bit_exactly():
            return 4
        return 8

    @_safe(default=False)
    def is_mapped(self, addr: int) -> bool:
        import ida_bytes

        return ida_bytes.is_loaded(addr)

    # -- architectural register roles ------------------------------------------------
    @_safe(default=None)
    def stack_pointer_reg(self) -> int | None:
        return self.register_by_name("rsp" if self.pointer_size() == 8 else "esp")

    @_safe(default=None)
    def frame_pointer_reg(self) -> int | None:
        return self.register_by_name("rbp" if self.pointer_size() == 8 else "ebp")

    @_safe(default=None)
    def register_by_name(self, name: str) -> int | None:
        import ida_idp

        reg = ida_idp.str2reg(name)
        return reg if reg >= 0 else None

    @_safe(default=None)
    def return_value_reg(self) -> int | None:
        return self.register_by_name("rax" if self.pointer_size() == 8 else "eax")


def _reg_name(reg: int) -> str | None:
    try:
        import ida_idp

        name = ida_idp.get_reg_name(reg, 8)
        return name or None
    except Exception:  # pragma: no cover - best-effort naming only
        return None


def _calling_convention_name(cc: int) -> str:
    """Best-effort label for the raw `callcnv_t`. The label is informational
    only — argument *locations* (`FunctionPrototype.arg_locations`) come
    straight from IDA's own ABI-aware `argloc_t` resolution and are
    authoritative regardless of this name, including for x86-64 where the
    Windows/SysV ABI distinction isn't encoded in `callcnv_t` itself."""

    import ida_typeinf

    global _CC_NAME_BY_CONST
    if _CC_NAME_BY_CONST is None:
        _CC_NAME_BY_CONST = {
            ida_typeinf.CM_CC_CDECL: "cdecl",
            ida_typeinf.CM_CC_STDCALL: "stdcall",
            ida_typeinf.CM_CC_PASCAL: "pascal",
            ida_typeinf.CM_CC_FASTCALL: "fastcall",
            ida_typeinf.CM_CC_THISCALL: "thiscall",
            ida_typeinf.CM_CC_SWIFT: "swift",
            ida_typeinf.CM_CC_GOLANG: "golang",
        }

    masked = cc & ida_typeinf.CM_CC_MASK
    return _CC_NAME_BY_CONST.get(masked, "unknown")


def _convert_instruction(insn) -> Instruction:
    import ida_idp
    import ida_ua

    chg_bits = (
        ida_idp.CF_CHG1,
        ida_idp.CF_CHG2,
        ida_idp.CF_CHG3,
        ida_idp.CF_CHG4,
        ida_idp.CF_CHG5,
        ida_idp.CF_CHG6,
        ida_idp.CF_CHG7,
        ida_idp.CF_CHG8,
    )
    feature = insn.get_canon_feature()

    operands = []
    written = []
    for number in range(8):
        op = insn.ops[number]
        if op.type == ida_ua.o_void:
            continue
        operands.append(_convert_operand(insn, op, number))
        written.append(bool(feature & chg_bits[number]))

    mnem = insn.get_canon_mnem() or ""
    return Instruction(
        ea=insn.ea,
        mnem=mnem.lower(),
        itype=insn.itype,
        size=insn.size,
        operands=tuple(operands),
        operand_written=tuple(written),
    )


def _convert_operand(insn, op, number: int) -> Operand:
    import ida_ua

    dtype_size = ida_ua.get_dtype_size(op.dtype)
    segment_reg, segment_name = _segment_override(insn)

    if op.type == ida_ua.o_reg:
        return Operand(kind=OperandKind.REG, number=number, reg=op.reg, dtype_size=dtype_size)

    if op.type == ida_ua.o_imm:
        return Operand(
            kind=OperandKind.IMMEDIATE,
            number=number,
            imm_value=op.value,
            dtype_size=dtype_size,
        )

    if op.type == ida_ua.o_mem:
        return Operand(
            kind=OperandKind.MEM_DIRECT,
            number=number,
            addr=op.addr,
            dtype_size=dtype_size,
            segment_reg=segment_reg,
            segment_name=segment_name,
        )

    if op.type == ida_ua.o_phrase:
        return Operand(
            kind=OperandKind.MEM_PHRASE,
            number=number,
            reg=op.reg,
            dtype_size=dtype_size,
            segment_reg=segment_reg,
            segment_name=segment_name,
        )

    if op.type == ida_ua.o_displ:
        return Operand(
            kind=OperandKind.MEM_DISPL,
            number=number,
            reg=op.reg,
            disp=op.addr,
            dtype_size=dtype_size,
            segment_reg=segment_reg,
            segment_name=segment_name,
        )

    if op.type == ida_ua.o_far:
        return Operand(kind=OperandKind.FAR, number=number, addr=op.addr, dtype_size=dtype_size)

    if op.type == ida_ua.o_near:
        return Operand(kind=OperandKind.NEAR, number=number, addr=op.addr, dtype_size=dtype_size)

    return Operand(kind=OperandKind.SPECIAL, number=number, dtype_size=dtype_size)


def _segment_override(insn) -> tuple[int | None, str | None]:
    """Best-effort detection of an explicit segment-override prefix (e.g.
    `gs:`/`fs:` for TLS access). `insn.segpref` is a processor-dependent
    field; only names that are actually meaningful overrides for argument
    passing (fs/gs) are surfaced, to avoid false positives from the default
    cs/ds/ss segment on every ordinary memory operand."""

    segpref = getattr(insn, "segpref", None)
    if segpref is None or segpref < 0 or segpref > 15:
        return None, None
    name = _reg_name(segpref)
    if name and name.lower() in _TLS_SEGMENT_NAMES:
        return segpref, name.lower()
    return None, None
