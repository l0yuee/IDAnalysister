<p align="right"><a href="user_manual.zh-CN.md">中文</a></p>

# idanalysister — User Manual

This manual is organized around **what you're trying to do**, not the
package's internal structure — jump to the section that matches your
situation. A concise per-module reference follows for when you need to go
deeper (writing an extension, reading diagnostics, etc.). For *why* things
are built the way they are, see [`architecture.md`](architecture.md).

## Contents

1. [Installation and setup](#1-installation-and-setup)
2. [Core concepts in five minutes](#2-core-concepts-in-five-minutes)
3. Situations
   - [3.1 Extract arguments with a known calling convention](#31-extract-arguments-with-a-known-calling-convention)
   - [3.2 Let IDA infer the calling convention for you](#32-let-ida-infer-the-calling-convention-for-you)
   - [3.3 Describe a custom or nonstandard calling convention](#33-describe-a-custom-or-nonstandard-calling-convention)
   - [3.4 Get typed, human-readable output](#34-get-typed-human-readable-output)
   - [3.5 Write your own post-processor (e.g. a decryption routine)](#35-write-your-own-post-processor-eg-a-decryption-routine)
   - [3.6 Resolve a value at a point *inside* a function (3.3 in requirement.md)](#36-resolve-a-value-at-a-point-inside-a-function)
   - [3.7 Handle an instruction form the framework doesn't recognize](#37-handle-an-instruction-form-the-framework-doesnt-recognize)
   - [3.8 Configure everything declaratively (dict / JSON / YAML)](#38-configure-everything-declaratively-dict--json--yaml)
   - [3.9 Turn on the optional Hex-Rays fallback](#39-turn-on-the-optional-hex-rays-fallback)
   - [3.10 Tune performance and resolution budgets](#310-tune-performance-and-resolution-budgets)
   - [3.11 Read and diagnose an `Unknown` result](#311-read-and-diagnose-an-unknown-result)
4. [Module-by-module reference](#4-module-by-module-reference)
5. [Testing your own extensions](#5-testing-your-own-extensions)
6. [Troubleshooting / FAQ](#6-troubleshooting--faq)
7. [Running the test suite](#7-running-the-test-suite)

---

## 1. Installation and setup

```sh
cd IDAnalysister
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Inside IDA (or an `idalib`-driven headless script), put `src/` on the
path before importing:

```python
import sys
sys.path.insert(0, "/path/to/IDAnalysister/src")

from idanalysister import ParamExtractor, CDECL, STDCALL, FASTCALL, THISCALL, MS_X64, SYSV_X64
```

`import idanalysister` itself works fine outside IDA too (that's how the
unit test suite runs) — only constructing `ParamExtractor()` with no
explicit `port=` argument requires a live IDA/`idalib` session, since
that's the point at which it builds the real adapter
(`adapters.ida_port_impl.IdaPortImpl`).

## 2. Core concepts in five minutes

**`ParamExtractor`** (`idanalysister.ParamExtractor`) is the one class you
construct. It owns everything else internally (an IDA adapter, an
instruction cache, a locator registry) and exposes exactly two analysis
methods:

- `extract_calls(func_ea, convention=None, num_args=None, arg_types=None)` —
  requirement 3.1: find every call site of `func_ea` and resolve its
  arguments.
- `resolve_argument_at(func_ea, arg_index, target_ea, convention=None, num_args=None)` —
  requirement 3.3: resolve one argument's value at a specific point inside
  `func_ea`'s body.

**Every resolved value** is one of five shapes
(`idanalysister.core.values`), and you'll pattern-match on these constantly:

| Type | Meaning |
|---|---|
| `Concrete(value, kind)` | Fully known — an immediate, folded arithmetic, or memory content. |
| `MemoryRef(addr, value)` | A dereferenced read: `addr` is where it came from, `value` is what was there (chain further if `value` is itself a pointer). |
| `Symbolic(expr)` | Tracked precisely through data flow but not a compile-time constant — e.g. `"arg0"` (still the original argument, unmodified) or `"ret(0x4010a0)"` (a specific call's return value). |
| `MutatedRegion(base_expr, via)` | Memory relative to a tracked pointer was written with a non-constant index (e.g. inside a loop) — the pointer may still be exactly known even though its content isn't tracked as scalar state. |
| `Unknown(reason, detail)` | Could not be statically determined; `reason` is a `core.diagnostics.UnknownReason` — see [§3.11](#311-read-and-diagnose-an-unknown-result). |

Every `ValueLattice` has an `.is_known` property (`False` only for
`Unknown`). `ArgumentResult` (what you get back per argument) additionally
carries `.raw_value`, `.processed_value` (after post-processing, identical
to raw if you didn't declare a type), `.label`, and `.source` (`"raw"` or
`"hexrays_fallback"`).

---

## 3.1 Extract arguments with a known calling convention

The common case: you know (or are willing to assume) the convention.

```python
from idanalysister import ParamExtractor, CDECL

extractor = ParamExtractor()
report = extractor.extract_calls(func_ea=0x00401000, convention=CDECL, num_args=2)

print(f"{report.call_count} call sites")
for site in report.call_sites:
    print(hex(site.call_ea))
    for arg in site.arguments:
        print(f"  arg{arg.index} = {arg.raw_value!r}")
```

Built-in templates, from `idanalysister.conventions.templates` (also
re-exported at the top level: `from idanalysister import CDECL, STDCALL,
FASTCALL, THISCALL, MS_X64, SYSV_X64`):

| Constant | Convention |
|---|---|
| `CDECL` | All arguments pushed right-to-left; caller cleans the stack. |
| `STDCALL` | Same layout as cdecl from the caller's side (callee cleans the stack, which this framework doesn't need to observe). |
| `FASTCALL` | MSVC `__fastcall`: first two args in `ecx`, `edx`; rest pushed. |
| `THISCALL` | MSVC `__thiscall`: `this` in `ecx`; rest pushed. |
| `MS_X64` | Microsoft x64 ABI: first four args in `rcx`, `rdx`, `r8`, `r9`; rest at `[rsp+0x20]`, `[rsp+0x28]`, ... |
| `SYSV_X64` | System V AMD64 ABI (Linux/macOS): first six args in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`; rest at `[rsp+0]`, `[rsp+8]`, ... |

`num_args` is required here — a template alone has no way to know how many
arguments a specific call actually has.

## 3.2 Let IDA infer the calling convention for you

If IDA has already recognized the function's prototype (via signature
matching, a user-applied type, or its own analysis), you can omit both
arguments:

```python
report = extractor.extract_calls(func_ea)  # convention AND arity read from IDA's prototype
```

Internally this calls `idanalysister.conventions.inference.infer(func_ea,
port)`, which reads `ida_typeinf.func_type_data_t`/`argloc_t` directly —
so it correctly handles mixed register+stack conventions (including x86-64,
where the ABI isn't encoded in `callcnv_t` itself) with no guessing. If IDA
has no prototype, extraction falls back to `CDECL`, and you'll need to
supply `num_args` yourself (a `ConventionError` is raised otherwise, so you
find out immediately rather than getting silently wrong results).

You can also call inference explicitly and inspect it:

```python
from idanalysister.conventions.inference import infer

convention = infer(func_ea, extractor.port)
if convention is not None:
    print(convention.name, convention.arg_count)
```

## 3.3 Describe a custom or nonstandard calling convention

For hand-rolled, obfuscated, or otherwise nonstandard conventions, combine
locating strategies declaratively — no new resolver code:

```python
from idanalysister.conventions.custom_builder import ConventionBuilder

convention = (
    ConventionBuilder("my_convention")
    .reg(0, "rcx")            # argument 0 lives in rcx at call time
    .reg(1, "rdx")            # argument 1 lives in rdx
    .stack_offset(2, 0x28)    # argument 2 is the value at [rsp+0x28] at call time
    .stack_push(3, 0)         # argument 3 comes from a push sequence; position 0 = the last push before the call
    .build()
)
report = extractor.extract_calls(func_ea, convention=convention, num_args=4)
```

`.stack_push(index, position)`: `position` counts from the *top* of the
non-register push sequence at call time — `0` is the last instruction
pushed before the `call` (the argument closest to the call, i.e. the
"leftmost" not-yet-in-a-register argument in a right-to-left push order),
`1` is the one pushed before that, and so on. This matches how
`CDECL`/`FASTCALL`/etc. are themselves defined internally, so mixing a
custom prefix with a push-based tail behaves exactly like the built-in
templates do.

An index with no `.reg()`/`.stack_offset()`/`.stack_push()` declared
raises `idanalysister.errors.ConventionError` as soon as `slots()` is
evaluated — a configuration mistake is caught immediately rather than
producing a silently wrong result.

## 3.4 Get typed, human-readable output

Declare what each argument *is* and get post-processed output alongside
the raw value:

```python
from idanalysister.typespec.argtype import ArgTypeSpec

arg_types = {
    1: ArgTypeSpec.c_string(1, label="filename"),
    2: ArgTypeSpec.wide_string(2, label="message"),
    3: ArgTypeSpec.integer(3, hex_format=True, label="flags"),
}
report = extractor.extract_calls(func_ea, convention=CDECL, num_args=4, arg_types=arg_types)

for site in report.call_sites:
    filename = site.argument(1)
    print(filename.label, "=", filename.processed_value)
```

`arg.raw_value` is unaffected by `arg_types` — it's always the direct
resolution result. `arg.processed_value` is `raw_value` run through the
declared post-processor chain (or identical to `raw_value` if no type was
declared for that index, or if `raw_value` was already `Unknown`, in which
case post-processing is skipped entirely rather than operating on garbage).

Built-in `ArgTypeSpec` constructors:

| Constructor | Produces |
|---|---|
| `ArgTypeSpec.c_string(index, label=None, max_len=4096)` | Dereferences a pointer-shaped value into a narrow (UTF-8/Latin-1) C string. |
| `ArgTypeSpec.wide_string(index, label=None, max_len=4096)` | Same, but UTF-16LE. |
| `ArgTypeSpec.integer(index, hex_format=False, label=None)` | Coerces to a plain integer; optionally formats as a hex string. |
| `ArgTypeSpec.custom(index, *postprocessors, label=None)` | Runs an arbitrary chain of `PostProcessor` instances — see §3.5. |

## 3.5 Write your own post-processor (e.g. a decryption routine)

Subclass `idanalysister.postproc.base.PostProcessor`. `process(value, port)`
receives the previous step's `ValueLattice` and the active `IdaPort` (for
memory reads), and must return a `ValueLattice` — never raise (the chain
wraps it defensively anyway, but a well-behaved processor returns
`Unknown` on its own failure paths):

```python
from idanalysister.postproc.base import PostProcessor
from idanalysister.core.values import Concrete, MemoryRef, ValueKind, unknown
from idanalysister.core.diagnostics import UnknownReason

def _address_of(value):
    if isinstance(value, Concrete) and isinstance(value.value, int):
        return value.value
    if isinstance(value, MemoryRef) and isinstance(value.value, Concrete) and isinstance(value.value.value, int):
        return value.value.value
    return None

class XorDecrypt(PostProcessor):
    name = "xor_decrypt"

    def __init__(self, key: bytes, length: int):
        self.key = key
        self.length = length

    def process(self, value, port):
        addr = _address_of(value)
        if addr is None:
            return unknown(UnknownReason.UNSUPPORTED_OPERAND_SHAPE)
        raw = port.read_bytes(addr, self.length)
        if raw is None:
            return unknown(UnknownReason.MEMORY_READ_FAILED)
        decoded = bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(raw))
        return Concrete(decoded, ValueKind.BYTES)
```

Use it directly:

```python
arg_types = {0: ArgTypeSpec.custom(0, XorDecrypt(key=b"\x5a", length=16))}
```

Chain several steps — they run in order, short-circuiting on the first
`Unknown`:

```python
ArgTypeSpec.custom(0, XorDecrypt(key=b"\x5a", length=16), SomeOtherStep())
```

Or register it by name so it can be referenced from declarative config
(§3.8) instead of imported directly:

```python
from idanalysister.postproc.registry import register_postprocessor
register_postprocessor("xor_decrypt", XorDecrypt)
```

`port` here is the same `IdaPort` interface the whole framework uses —
useful methods for a post-processor: `read_bytes(addr, size)`,
`read_int(addr, size, signed=False)`, `read_cstring(addr, max_len)`,
`read_wstring(addr, max_len)`, `is_mapped(addr)`.

## 3.6 Resolve a value at a point inside a function

The scenario requirement.md calls out explicitly: an argument is a
pointer to encrypted data, the function decrypts it in place, and you want
the value *right before a particular call*, after decryption:

```python
value = extractor.resolve_argument_at(
    func_ea=0x00401000,
    arg_index=0,
    target_ea=0x00401050,   # the instruction address you care about
    convention=MS_X64,
    num_args=1,
)
```

What comes back:

- If the argument's register was never reassigned along every path
  reaching `target_ea` (the common case — a buffer pointer surviving a
  decryption loop that mutates the buffer through a variable index, not
  the pointer itself), you get `Symbolic("arg0")` — i.e. "still exactly
  the original argument."
- If it was reassigned to a compile-time-constant value on every reaching
  path, you get `Concrete(...)`.
- If different paths disagree, or a loop's tracked value never
  stabilizes, you get `Unknown(DIVERGENT_PATHS)` /
  `Unknown(LOOP_NON_CONVERGENT)`.

**Important scope limit**: only *register-passed* arguments can be
forward-tracked (`Unknown(UNSUPPORTED_OPERAND_SHAPE)` otherwise) — see
[`architecture.md` §7](architecture.md#7-forward-resolution--intra-function-value-tracking-33)
for why a stack-passed argument doesn't have a single well-defined
offset to seed from generically. Pick a convention/argument index that
puts the argument you care about in a register (which, for the "decrypt a
buffer before use" pattern, is virtually always the case — the pointer is
passed in, not the buffer contents).

**The engine resolves the pointer's identity, not decrypted bytes.** If
you need the actual decrypted content, first confirm the pointer resolved
to something concrete/symbolic-and-known, then use a custom post-processor
(§3.5) to read and decode memory at that address yourself — the engine
deliberately does not try to guess "this looks like an XOR loop" and
fabricate decrypted bytes.

## 3.7 Handle an instruction form the framework doesn't recognize

If `extract_calls`/`resolve_argument_at` reports
`Unknown(UNSUPPORTED_INSTRUCTION)` for an instruction your target binary
uses, add a `Locator` — no core files change. Follow
`src/idanalysister/locators/extension_points.py` (a complete, runnable
example: `not reg`, bitwise complement):

```python
from idanalysister.locators.base import Locator, LocatorOutcome
from idanalysister.core.insn_model import OperandKind
from idanalysister.core.values import Concrete, ValueKind

class MyLocator(Locator):
    name = "my_form"

    def matches(self, instr):
        # cheap shape check only: mnemonic + operand kinds
        return instr.mnem == "my_mnemonic" and instr.operand(0).kind is OperandKind.REG

    def extract(self, instr, dest_operand, ctx):
        # ctx.resolve_register(reg, before_ea) / ctx.resolve_memory(base_reg, disp, before_ea, size)
        # recurse for source operands that aren't already known.
        return LocatorOutcome.resolved(Concrete(0, ValueKind.INT))

extractor = ParamExtractor()
extractor.registry.register(MyLocator())
```

Notes:

- `matches()` only needs to recognize the *shape* — the resolver has
  already confirmed (via IDA's own `CF_CHG*` operand-write flags) that
  this instruction genuinely writes the register/memory location being
  queried before it ever calls `extract()`. You never need to check "is
  this the right definition," only "what value does this produce."
- Return `LocatorOutcome.not_applicable()` for any operand shape you don't
  handle — never guess a value for a shape you're unsure about.
- If you also want this instruction's effect modeled correctly during
  **forward** resolution (§3.6), override `apply_forward(self, instr,
  state)` too (see `arithmetic_locators.py`'s `AddSubRegImmLocator` for a
  worked example of both). If you skip it, the safe default conservatively
  invalidates whatever register the instruction writes during forward
  walks — correct but imprecise.
- `extractor.registry` is private to that `ParamExtractor` instance;
  registering something on one extractor never affects another, and
  there's no need to touch `locators/base.py`'s `default_registry()`
  unless you want your locator to ship as a built-in for everyone.

## 3.8 Configure everything declaratively (dict / JSON / YAML)

For the majority of tasks, skip importing convention/type-spec classes
entirely and express the whole request as a plain `dict` — handy for
config files, CLI tools, or a UI built on top of this package:

```python
from idanalysister.config.schema import build_from_config

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
```

A custom convention as config:

```python
{"convention": {"custom": [
    {"index": 0, "reg": "rcx"},
    {"index": 1, "stack_offset": 0x28},
    {"index": 2, "stack_push": 0},
]}}
```

A custom (previously-registered, see §3.5) post-processor as config:

```python
{"arg_types": {0: {"type": "custom", "postprocessors": [("xor_decrypt", {"key": b"\x5a", "length": 16})]}}}
```

No YAML dependency is bundled — load YAML yourself
(`yaml.safe_load(open(path))`) and pass the resulting `dict` in; `config.schema`
only interprets the plain Python structure, the same as if it came from
JSON.

## 3.9 Turn on the optional Hex-Rays fallback

If a licensed Hex-Rays decompiler is available for the target
architecture, you can let it fill in values the raw engine leaves
`Unknown`:

```python
extractor = ParamExtractor(use_hexrays_fallback=True)
report = extractor.extract_calls(func_ea, convention=CDECL, num_args=2)
for arg in report.call_sites[0].arguments:
    print(arg.index, arg.raw_value, arg.source)  # source: "raw" or "hexrays_fallback"
```

This is always opt-in and never changes a value the raw engine already
resolved — `arg.source` tells you exactly which engine is responsible for
each value, so a Hex-Rays-derived result is never silently indistinguishable
from a raw one. If Hex-Rays isn't licensed/available, this flag is a no-op
(logged, not an error) and everything still works via the raw engine alone.
See [`architecture.md` §10](architecture.md#10-hex-rays-optional-never-primary-adaptershexrays_backendpy)
for why this is opt-in rather than the default. Note that Hex-Rays
cross-checking currently only covers call-site extraction (3.1), not
forward resolution (3.6/3.3).

## 3.10 Tune performance and resolution budgets

```python
extractor = ParamExtractor(
    max_steps=200,     # per-query instruction-step budget for the backward resolver
    max_blocks=64,      # per-query basic-block budget for the backward resolver
    cache_size=4096,     # instruction/xref cache size (LRU), shared across all calls on this extractor
)
```

Raise `max_steps`/`max_blocks` if you're seeing
`Unknown(BUDGET_EXCEEDED)` on legitimately large-but-reasonable functions;
lower them for tighter worst-case latency on very large binaries. Reuse
one `ParamExtractor` across multiple `extract_calls`/`resolve_argument_at`
calls rather than constructing a new one each time, to benefit from
`cache_size`.

## 3.11 Read and diagnose an `Unknown` result

```python
if not arg.raw_value.is_known:
    print(arg.raw_value.reason, arg.raw_value.detail)
```

| `UnknownReason` | What it means | What to do |
|---|---|---|
| `NO_DEFINITION_FOUND` | Walked back to the function entry (or forward-analysis start) without a defining write, or the walk crossed a `call` through a caller-saved register, whose value the callee is free to destroy. | Often means the value genuinely comes from further up the call chain, or the function relies on a register the caller already set up — expected in many cases. If `detail` mentions a call, the value was set before that call in a volatile register, so it is not what the callee left behind. |
| `DIVERGENT_PATHS` / `DIVERGENT_SYMBOLIC` | Two control-flow paths disagree on the value. | Not a bug — the framework refuses to guess. Consider `resolve_argument_at` with a `target_ea` on the specific path you care about. |
| `BUDGET_EXCEEDED` | Hit the step/block cap. | Raise `max_steps`/`max_blocks` (§3.10). |
| `UNSUPPORTED_INSTRUCTION` | No `Locator` recognizes this instruction as a definition. | Add one — §3.7. |
| `UNSUPPORTED_OPERAND_SHAPE` | A locator matched the mnemonic but not this exact operand combination; an argument slot couldn't be resolved to a register/offset at all; the operand is indexed (`[base+index*scale]`) or `fs:`/`gs:`-relative, so it names no single static address; a write covered only part of the tracked register (`mov al, 5` into `eax`); or an indexed write may have aliased the queried location. | Read `detail` — it names the instruction and the exact reason. A convention mismatch is the most common cause, so check `convention`/`num_args` first; otherwise extend the matching locator. |
| `MEMORY_READ_FAILED` | The computed address has no data in the IDB. | Expected for stack/heap addresses with no local definition, or truly unmapped regions. |
| `INDIRECT_CONTROL_FLOW` | Reserved for indirect call/jump cases that break static certainty. | Informational. |
| `LOOP_NON_CONVERGENT` | A forward-tracked value kept changing across loop iterations without stabilizing. | The value genuinely isn't a single constant at that point. |
| `ADAPTER_ERROR` / `INTERNAL_ERROR` | An underlying IDA call or an unexpected internal exception was caught at a safety boundary. | Check IDA's own analysis of that address; file a bug if it looks like a framework defect. |
| `MUTATED_MEMORY_CONTENT` | Memory relative to a tracked pointer was written through a non-constant index (reserved for future finer-grained forward diagnostics; today surfaced via `MutatedRegion`, not `Unknown`). | See §3.6. |

---

## 4. Module-by-module reference

Most users only ever need `api`, `conventions`, `typespec`, `postproc`,
and `config`. The rest (`core`, `locators`, `adapters`) matter when you're
extending the framework or debugging its behavior.

### `api` — what you call

- **`api.facade.ParamExtractor`** — construct one per analysis session.
  `extract_calls(...)` (3.1) and `resolve_argument_at(...)` (3.3) are the
  two entry points; `registry` (a `LocatorRegistry`) and `port` (the
  active `IdaPort`) are public attributes for extension/introspection.
- **`api.results`** — `CallSiteResult` (one call site: `.call_ea`,
  `.func_ea`, `.arguments`, `.argument(index)`), `ArgumentResult` (one
  argument: `.index`, `.raw_value`, `.processed_value`, `.label`,
  `.source`, `.is_known`), `ExtractionReport` (`.func_ea`, `.call_sites`,
  `.call_count`).

### `core` — the analysis engine (no `ida_*` imports anywhere)

- **`core.values`** — the value vocabulary (§2).
- **`core.diagnostics`** — `UnknownReason` (§3.11).
- **`core.insn_model`** — `Instruction`/`Operand`, the normalized view of
  a decoded instruction every `Locator` works with.
- **`core.insn_cache`** — `InstructionCache`, an LRU cache over decoding
  and cross-reference lookups.
- **`core.cfg_model`** — `CfgModel`/`build_cfg`, a queryable
  control-flow-graph wrapper.
- **`core.engine_backward`** — `BackwardResolver`, the engine behind 3.1.
  You'd touch this directly only for advanced use (e.g. calling
  `resolve_register`/`resolve_memory`/`resolve_at_instruction`/
  `collect_push_sequence` yourself instead of going through
  `ParamExtractor`).
- **`core.engine_forward`** — `ForwardSymbolicEngine`, the engine behind
  3.3 (see §3.6).
- **`core.merge`** — `join`/`join_all`, the control-flow-merge rule.
- **`core.state`** — `AbstractState`, the forward engine's per-location
  value snapshot.

### `locators` — the extension mechanism

- **`locators.base`** — `Locator` (the interface), `LocatorRegistry`,
  `ResolutionContext` (what `extract()` receives), `default_registry()`
  (builds a registry with every built-in locator).
- **`locators.register_locators`** — `mov reg,reg`/`mov reg,imm`/
  `lea reg,[global]`/`xchg`/`cmov`.
- **`locators.arithmetic_locators`** — `lea reg,[base+disp]`/
  `add`,`sub reg,imm` (constant folding, both backward and forward).
- **`locators.memory_locators`** — `mov reg,[mem]` in every addressing
  shape that names one static cell (global, `[reg+off]`). Indexed
  (`[base+index*scale]`) and `fs:`/`gs:`-relative operands resolve to
  `Unknown(UNSUPPORTED_OPERAND_SHAPE)`: the first names a whole family of
  addresses, the second an offset into a segment whose base the database
  does not know.
- **`locators.immediate_locators`** — `mov [mem],imm`.
- **`locators.stack_locators`** — `push` (any operand shape),
  `mov [mem],reg`.
- **`locators.call_return_locators`** — a prior call's return register
  used as an argument.
- **`locators.extension_points`** — the worked example for §3.7.

### `conventions` — where an argument lives

- **`conventions.base`** — `ArgSlot`, `SlotKind`, `CallingConvention`
  (the interface).
- **`conventions.templates`** — `CDECL`, `STDCALL`, `FASTCALL`,
  `THISCALL`, `MS_X64`, `SYSV_X64`, `by_name(name)`.
- **`conventions.inference`** — `infer(func_ea, port)`,
  `PrototypeConvention`.
- **`conventions.custom_builder`** — `ConventionBuilder` (§3.3).

### `postproc` / `typespec` — turning a value into what you actually want

- **`postproc.base`** — `PostProcessor` (the interface),
  `PostProcessorChain`.
- **`postproc.builtins`** — `CStringDeref`, `WideStringDeref`,
  `HexFormat`, `IntCast`, `StructFieldDeref`.
- **`postproc.registry`** — `register_postprocessor(name, factory)`,
  `create(name, **kwargs)` (§3.5, §3.8).
- **`typespec.argtype`** — `ArgTypeSpec` (§3.4).

### `config` — declarative configuration

- **`config.schema`** — `build_from_config(config: dict)` (§3.8).

### `adapters` — the IDA boundary (touch this only when extending IDA support itself)

- **`adapters.ida_port.IdaPort`** — the interface every layer above is
  written against.
- **`adapters.ida_port_impl.IdaPortImpl`** — the real implementation; this
  is what `ParamExtractor()` builds by default inside IDA.
- **`adapters.fake_port.FakeIdaPort`** — an in-memory implementation for
  tests (§5) — build instructions/memory/functions by hand, no IDA needed.
- **`adapters.hexrays_backend`** — `HexraysBackend`, `available()` (§3.9).

---

## 5. Testing your own extensions

A custom `Locator`, `CallingConvention`, or `PostProcessor` is plain
Python and can be unit-tested without IDA using
`adapters.fake_port.FakeIdaPort`:

```python
from idanalysister.adapters.fake_port import FakeIdaPort
from idanalysister.core.insn_model import Instruction, Operand, OperandKind
from idanalysister.core.ida_types import BasicBlockInfo
from idanalysister import ParamExtractor

port = FakeIdaPort(pointer_size=4)
port.add_instruction(
    Instruction(
        ea=0x401000, mnem="my_mnemonic", itype=1, size=3,
        operands=(Operand(kind=OperandKind.REG, number=0, reg=0, dtype_size=4),),
        operand_written=(True,),
        operand_read=(False,),   # CF_USE bits: set for a read-modify-write operand
    )
)
port.set_function(0x401000, 0x401100, blocks=(BasicBlockInfo(0x401000, 0x401100, (), ()),))

extractor = ParamExtractor(port=port)
extractor.registry.register(MyLocator())
# ... call extractor.extract_calls / resolve_argument_at and assert on the result
```

See `tests/unit/conftest.py` for small helper builders (`reg`, `imm`,
`mem_direct`, `mem_displ`, `insn`) that make constructing test fixtures
less verbose, and `tests/unit/locators/test_extension_points.py` for a
complete before/after example (a locator unregistered vs. registered).

## 6. Troubleshooting / FAQ

**"`ConventionError: num_args must be specified...`"** — you passed a
template-based convention (or none, and IDA has no recognized prototype)
without `num_args`. Supply it explicitly.

**Every argument comes back `Unknown(NO_DEFINITION_FOUND)`** — double
check `func_ea` is actually the function whose *call sites* you want
analyzed (not the caller), and that `convention`/`num_args` match reality;
a wrong register/offset for a slot will walk back through unrelated code
forever and find nothing.

**I'm not inside IDA and want to experiment** — everything except
`ParamExtractor()`'s default port construction works fine outside IDA;
pass `port=FakeIdaPort(...)` explicitly (§5).

**Can I call this from a headless/idalib script?** — yes; see
`tests/integration/conftest.py` for a complete `idapro.open_database(...)`
+ `ParamExtractor()` example.

## 7. Running the test suite

```sh
pytest tests/unit                          # no IDA installation required
pytest tests/integration -m requires_ida   # requires a local IDA Pro + idalib install
```
