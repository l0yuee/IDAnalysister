<p align="right"><a href="README.zh-CN.md">中文</a></p>

# idanalysister

A declarative, interface-based Python framework that runs inside IDA Pro
(IDAPython) to automate two of the most repetitive tasks in reverse
engineering: **finding every call site of a function and extracting the
actual values passed as arguments**, and **resolving what an argument's
value has become at an arbitrary point inside a function body** (e.g.
after a decryption loop). It is built strictly on IDA's public `ida_*`
APIs, is organized as small, independently-extensible components, and is
designed to never crash — anything it cannot statically determine comes
back as an explicit, reasoned "unknown" value instead of a guess or an
exception.

See [`document/architecture.md`](document/architecture.md) for the full
design write-up and [`document/user_manual.md`](document/user_manual.md)
for a task-by-task usage guide (中文版用户手册:
[`document/user_manual.zh-CN.md`](document/user_manual.zh-CN.md)).

## The problem it solves

Reverse-engineering a piece of software — especially malware — almost
always comes down to the same question, over and over: *"What value did
the caller pass into argument N of this function, at this specific call
site?"* or *"What has this argument turned into by the time execution
reaches this point?"* Answering it by hand means:

- Manually reading backward through the disassembly from every call site,
  chasing register assignments, stack pushes, and memory dereferences.
- Re-deriving the calling convention every time (is it cdecl? fastcall?
  does IDA's guess even match reality?).
- Writing a new one-off IDAPython script for practically every sample,
  because the argument might be an immediate, a global, a stack variable,
  a struct field reached through a pointer, or the return value of an
  earlier call — and compilers mix these forms freely even within one
  function.
- Manually dereferencing pointers into strings, formatting integers, or
  writing throwaway decryption code inline in the script.
- Doing it all again, slightly differently, inside the function body when
  the question is "what does this look like *after* it's been decrypted,
  right before this particular call" rather than "at the call site."

`idanalysister` turns this from **write a new script** into **describe
what you want**: point it at a function, tell it (or let it infer) the
calling convention, optionally say what type each argument is, and get
back fully-resolved values — with the same declarative call working
whether the argument is a register, an immediate, a dereferenced global, a
stack slot, a struct field behind a pointer, a value forwarded from a
previous call's return, or the surviving pointer identity after a loop has
mutated what it points to.

## Key capabilities

- **Call-site argument extraction** for every x86/x86-64 argument-passing
  form named in the project requirements: register-direct, immediate,
  memory-indirect (always dereferenced to the real value, never just the
  address), stack push sequences (correct right-to-left ordering),
  stack writes via `mov`, register-indirect/struct-field addressing,
  global access, and a prior call's return value used as an
  argument — plus `xchg`/`cmov`/`movsx`/`movzx`/`lea`/`add`/`sub` handled
  out of the box, and any other form addable without touching core code.
- **Calling-convention handling** three ways: built-in templates (cdecl,
  stdcall, fastcall, thiscall, Microsoft x64, System V x64), automatic
  inference from a prototype IDA already recognizes, or a fluent builder
  for any custom/nonstandard convention.
- **Typed, post-processed output**: declare "argument 1 is a C string",
  "argument 2 is a hex-formatted integer", or plug in your own
  post-processor (a decryption routine, a struct-field reader, anything)
  bound to a specific argument index.
- **Intra-function forward resolution**: given a function, an argument
  index, and a target instruction address inside that function, get the
  argument's value *at that point* — the canonical case being a pointer
  argument that survives a decryption loop unchanged even though what it
  points to has been mutated.
- **An honest "I don't know"**: every unresolved value is a typed `Unknown`
  with a specific, inspectable reason (budget exceeded, divergent control
  flow paths, unsupported instruction, memory read failed, ...) — the
  framework never fabricates a value, and no *analysis* failure ever
  raises out of its public API. (Calling it wrongly still raises: asking
  for a template convention without `num_args` when IDA has no prototype
  is a `ConventionError`, because that is a bug in the call, not an
  unresolvable program.) Shapes with no single statically-knowable answer
  — an indexed `[base+index*scale]` access, an `fs:`/`gs:` TLS offset
  whose segment base isn't in the database — are reported as `Unknown`
  with the specific reason, never flattened into a plausible-looking
  number.
- **Optional Hex-Rays cross-check**: if a licensed decompiler is available,
  it can be used as a secondary fallback for values the raw engine leaves
  unknown — opt-in, never the default, and every result is tagged with
  which engine produced it.

## Project layout and module responsibilities

```
src/idanalysister/
  api/            the public entry point most users interact with
  core/           the analysis engine — no IDA imports anywhere in this package
  locators/       one small file per instruction-form family — the extension point
  conventions/    calling-convention templates, inference, and a custom builder
  postproc/       post-processors (string/hex/int/struct extraction) + a name registry
  typespec/       binds a post-processor chain to an argument index
  config/         builds all of the above from a plain dict (for declarative/JSON config)
  adapters/       the only place any ida_* module is ever imported
```

| Module | Responsibility |
|---|---|
| `api.facade` | `ParamExtractor` — the composition root and main class you construct and call. Owns one adapter, one instruction cache, one locator registry, and orchestrates every extraction/resolution request. |
| `api.results` | The result shapes returned to you: `CallSiteResult`, `ArgumentResult` (raw value, post-processed value, label, and which engine produced it), `ExtractionReport`. |
| `core.values` | The value vocabulary every result is expressed in: `Concrete`, `MemoryRef`, `Symbolic`, `MutatedRegion`, `Unknown`. |
| `core.diagnostics` | `UnknownReason` — the enumerated, inspectable reasons a value could not be resolved. |
| `core.insn_model` | A normalized, architecture-agnostic instruction/operand representation built once from IDA's decoder. |
| `core.insn_cache` | Memoizes instruction decoding and cross-reference lookups for the lifetime of one session (the <100ms/call-site performance requirement). |
| `core.cfg_model` | A queryable control-flow graph wrapper used by both resolution engines. |
| `core.engine_backward` | The backward def-use resolver that powers call-site argument extraction (drives every "form" listed above). |
| `core.engine_forward` | The forward, loop-aware symbolic propagation engine that powers intra-function resolution. |
| `core.merge` | The "never guess" rule: how two control-flow paths' values are combined (agree → keep it, disagree → `Unknown`). |
| `core.state` | The per-register/per-stack-slot snapshot the forward engine tracks while walking the function. |
| `locators.base` | The `Locator` interface and per-session `LocatorRegistry` — the extension mechanism. |
| `locators.register_locators`, `.memory_locators`, `.immediate_locators`, `.stack_locators`, `.arithmetic_locators`, `.call_return_locators` | The built-in instruction-form handlers, one family per file. |
| `locators.extension_points` | A complete, runnable example showing how to add support for a new instruction form yourself. |
| `conventions.templates` | The built-in calling-convention constants: `CDECL`, `STDCALL`, `FASTCALL`, `THISCALL`, `MS_X64`, `SYSV_X64`. |
| `conventions.inference` | Builds a convention automatically from a function prototype IDA already recognizes. |
| `conventions.custom_builder` | `ConventionBuilder` — a fluent API for describing any nonstandard convention declaratively. |
| `postproc.base`, `.builtins`, `.registry` | The post-processor interface, the built-in ones (C string, wide string, hex, int cast, struct field), and a name-based registry for your own. |
| `typespec.argtype` | `ArgTypeSpec` — "argument N has this type/post-processing," the thing you actually pass in. |
| `config.schema` | Turns a plain `dict` (e.g. loaded from JSON/YAML) into a convention + argument-type configuration. |
| `adapters.ida_port` | The interface describing every IDA capability the framework needs — nothing outside `adapters/` ever imports `ida_*` directly. |
| `adapters.ida_port_impl` | The real implementation, backed by `ida_ua`, `idautils`, `ida_gdl`, `ida_bytes`, `ida_funcs`, `ida_frame`, `ida_typeinf`, `ida_nalt`, `ida_idp`. |
| `adapters.fake_port` | An in-memory stand-in used by the test suite so the analysis core can be tested without a running IDA instance. |
| `adapters.hexrays_backend` | The optional, opt-in Hex-Rays microcode cross-check. |

## Installation

```sh
cd IDAnalysister
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Then, inside IDA (or a script driven by `idalib`):

```python
import sys
sys.path.insert(0, "/path/to/IDAnalysister/src")

from idanalysister import ParamExtractor, CDECL

extractor = ParamExtractor()
report = extractor.extract_calls(func_ea=0x00401000, convention=CDECL, num_args=2)
for site in report.call_sites:
    print(hex(site.call_ea), [a.raw_value for a in site.arguments])
```

For a complete walkthrough of every module and situation (custom
conventions, typed/post-processed output, intra-function resolution,
extending with new instruction forms, declarative config, the optional
Hex-Rays fallback), see
[`document/user_manual.md`](document/user_manual.md).

## Running the tests

```sh
pytest tests/unit                          # no IDA installation required
pytest tests/integration -m requires_ida   # requires a local IDA Pro + idalib install
```

`tests/unit` exercises the entire analysis core against an in-memory fake
IDA adapter. `tests/integration` runs the real adapter against a small,
hand-written NASM binary via a genuine headless IDA analysis session.

## Requirements

- IDA Pro ≥ 9.3
- Python ≥ 3.13 (IDAPython)
- Only IDA's public `ida_*` modules — no private/undocumented interfaces
