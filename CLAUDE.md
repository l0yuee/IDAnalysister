# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A declarative, interface-based Python framework that runs inside IDA Pro (IDAPython, IDA ≥ 9.3, Python ≥ 3.13) to extract call-site argument values for any function and to resolve an argument's value at an arbitrary point inside a function body. Built exclusively on IDA's public `ida_*` APIs. See `README.md` for the problem statement and a full module responsibility table, `document/architecture.md` for the design rationale, and `document/user_manual.md` for situation-by-situation usage. Both README and the user manual have `.zh-CN` Chinese counterparts, cross-linked from the English originals — keep both in sync when editing either.

## Commands

```sh
python3.13 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest tests/unit                          # no IDA installation required
pytest tests/integration -m requires_ida   # requires a local IDA Pro + idalib install
pytest tests/unit/core/test_engine_backward.py::test_register_indirect_write_then_read  # single test
```

Integration tests and any ad hoc script that imports `idapro`/`ida_*` outside of IDA itself need `IDADIR` pointed at the IDA install (e.g. `IDADIR=/home/kali/ida-pro-9.3`) and the `idapro` idalib wheel installed once (`pip install /path/to/ida/idalib/python/idapro-*.whl` then run that install's `py-activate-idalib.py`).

After running the test suite, `.pytest_cache/`, `.hypothesis/`, `src/idanalysister.egg-info/`, `__pycache__/` directories, and `tests/integration/fixtures/probe`/`probe.o`/`probe.i64` get regenerated — all gitignored, but worth deleting before inspecting `git status` so real changes aren't lost in the noise.

**Never open an IDA database that might be locked by a live GUI/idalib session directly.** Check `lsof <file>` first; if it's held open, copy the `.i64` (or the split `.id0`/`.id1`/`.id2`/`.nam`/`.til` set) to a scratch directory and operate on the copy. Opening the same database from two processes concurrently has produced a silently empty/degraded session in practice (no error, just zero results) — always use an independent copy per concurrently-running process.

## Architecture

**Two-plane design, one-way dependency direction.** `core/`, `locators/`, `conventions/`, `postproc/` contain zero `ida_*` imports — every IDA interaction goes through the `adapters.ida_port.IdaPort` interface, injected by the composition root (`api.facade.ParamExtractor`). This is what lets the entire analysis engine be unit-tested via `adapters.fake_port.FakeIdaPort` with no IDA installed; only `adapters/ida_port_impl.py` and `adapters/hexrays_backend.py` are allowed to import `ida_*` modules, and only `tests/integration` exercises them, against a real headless IDA session. Never add an `ida_*` import outside `adapters/`.

**Structural matching lives in the resolver, not in locators.** A `Locator` (`locators/*.py`) only answers "given that this instruction defines operand N, what value does it produce" (`matches()` + `extract()`); it never decides whether an instruction is relevant to a query. `core.engine_backward.BackwardResolver` decides that generically, using IDA's own per-operand `CF_CHG1..CF_CHG8` write flags (carried on `Instruction.operand_written`) and, for control-flow-altering instructions, `CF_CALL|CF_JUMP|CF_STOP` (carried on `Instruction.is_control_transfer`) — never a hardcoded mnemonic list. This is why adding a new instruction form is "write one `Locator` subclass and register it on a `LocatorRegistry`" with zero changes to `core/`, and it's also why `core/insn_model.Instruction` carries those two flags: any new locator needing to recognize "this instruction defines/clobbers X" or "this instruction alters control flow" should read them rather than pattern-matching mnemonics.

**Two independent resolution engines share the same `Locator`s through two different interface methods.** `core.engine_backward.BackwardResolver` (drives call-site extraction) walks backward on demand via `Locator.extract()`, recursing through a `ResolutionContext` (`resolve_register`/`resolve_memory`/`dereference`) that a locator calls back into for its own source operands. `core.engine_forward.ForwardSymbolicEngine` (drives intra-function resolution) runs a bounded worklist fixpoint over the CFG, applying `Locator.apply_forward(instr, state)` for register-only transfer functions; memory loads/stores to stack/frame-pointer-relative locations are handled centrally by the engine itself (mirroring `resolve_memory`'s normalization), not by locators. A locator that implements `extract()` but not `apply_forward()` gets a safe default (conservatively invalidate whatever it writes) during forward walks — correct but imprecise; add `apply_forward()` too when precision during forward resolution matters (see `locators/arithmetic_locators.py` for a locator implementing both).

**`resolve_memory`'s address normalization is the mechanism behind most of the "every instruction form" coverage.** Global (`mov eax, dword_403000`), TLS (`gs:[0x30]`), stack (`[esp+N]`/`[ebp-N]`), and register-indirect struct access (`[eax+0x10]`) are all just different `(base_reg, disp)` shapes fed through one normalization/search routine in `BackwardResolver`: stack-pointer-relative offsets get adjusted by `IdaPort.get_sp_delta` so they compare correctly across intervening `sub esp`/`push` changes, frame-pointer-relative offsets are used directly, and arbitrary-register-relative accesses are matched by literal `(reg, disp)` identity (a documented, deliberate approximation — no general aliasing analysis). It searches backward for the nearest matching write before falling back to the IDB's static byte content.

**The value lattice (`core.values`) is the "never guess" contract made concrete.** `Concrete`/`MemoryRef`/`Symbolic`/`MutatedRegion`/`Unknown` are pattern-matched everywhere; `core.merge.join` is the single place two control-flow paths' values get combined (agree → keep, disagree → `Unknown(DIVERGENT_PATHS)`, never averaged or arbitrarily picked). Every `Unknown` carries a `core.diagnostics.UnknownReason` — when debugging "why didn't this resolve," check the reason before assuming it's a bug.

**Calling conventions are pure data, not resolver logic.** `conventions.base.CallingConvention.slots(num_args, port) -> list[ArgSlot]` only says *where* an argument lives (`REGISTER`/`STACK_PUSH`/`STACK_OFFSET`); resolving that location to a value is the resolver's job. `conventions.inference.infer()` builds one directly from IDA's own `argloc_t` per-argument locations when a prototype is recognized, which is why it correctly handles mixed register+stack ABIs (including x86-64, where the ABI isn't encoded in `callcnv_t` at all) without template guessing.

**`api.facade.ParamExtractor` is the composition root and the only class most callers touch.** It owns one `IdaPort`, one `InstructionCache` (LRU over decode + xref lookups — the mechanism behind the <100ms/call-site target), and one `LocatorRegistry` per instance (no shared global mutable state, so registering a custom locator on one extractor never affects another).

## Known, deliberate scope limits (not bugs)

- `ForwardSymbolicEngine` can only seed register-passed arguments; a stack-passed argument has no single well-defined callee-frame-relative offset derivable generically across conventions, so it returns `Unknown(UNSUPPORTED_OPERAND_SHAPE)` rather than risking a wrong offset.
- The forward engine's memory model only tracks stack/frame-pointer-relative cells as scalar state. A write through an arbitrary register with a non-constant index (e.g. a decryption loop's `[ptr+i]`) is not fabricated into tracked content — the *pointer* resolves precisely, decoding the *content* is left to a user-supplied `PostProcessor` (see `postproc/`).
- `collect_push_sequence` skips over interleaved non-push instructions (common compiler bookkeeping, e.g. MSVC's `/EHsc` unwind-state writes) but only if they don't touch the stack pointer or alter control flow, and only up to `_MAX_TRANSPARENT_SKIP` (16) instructions — a bounded, generic allowance, not a pattern match for any specific compiler.
- The Hex-Rays backend (`adapters/hexrays_backend.py`) is opt-in (`ParamExtractor(use_hexrays_fallback=True)`) and only ever fills in values the raw engine left `Unknown` for call-site extraction (3.1); it does not cross-check forward resolution (3.3).
