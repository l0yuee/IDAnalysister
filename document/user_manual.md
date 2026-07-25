# idanalysister — User Manual

## Installation

```sh
cd IDAnalysister
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Inside IDA (or `idalib`), make sure `src/` is on `sys.path`, then:

```python
import sys
sys.path.insert(0, "/path/to/IDAnalysister/src")

from idanalysister import ParamExtractor, CDECL, FASTCALL, MS_X64, SYSV_X64
```

Running `import idanalysister` outside IDA works fine (useful for the unit
tests) — only constructing `ParamExtractor()` with no explicit `port`
requires a running IDA/`idalib` session, since that's when it builds the
real `adapters.ida_port_impl.IdaPortImpl`.

## Quick start: extracting call-site arguments

```python
from idanalysister import ParamExtractor, CDECL

extractor = ParamExtractor()
func_ea = 0x00401000  # the function whose call sites you want

report = extractor.extract_calls(func_ea, convention=CDECL, num_args=2)
print(f"{report.call_count} call sites")
for site in report.call_sites:
    print(hex(site.call_ea))
    for arg in site.arguments:
        print(f"  arg{arg.index}: {arg.raw_value!r}")
```

`arg.raw_value` is always one of `Concrete`, `MemoryRef`, `Symbolic`,
`MutatedRegion`, or `Unknown` (see "Reading results" below) — never a bare
address for a memory-indirect argument; it's already dereferenced.

## Choosing a calling convention

Three ways, in order of preference:

**1. Let IDA tell you.** If IDA has already recognized the function's
prototype, omit `convention` and (often) `num_args` — both are inferred:

```python
report = extractor.extract_calls(func_ea)  # convention + arity from IDA's prototype
```

**2. Built-in templates** (`idanalysister.conventions.templates`):

```python
from idanalysister import CDECL, STDCALL, FASTCALL, THISCALL, MS_X64, SYSV_X64

report = extractor.extract_calls(func_ea, convention=FASTCALL, num_args=3)
```

**3. Combine your own** — for a nonstandard or hand-rolled convention:

```python
from idanalysister.conventions.custom_builder import ConventionBuilder

convention = (
    ConventionBuilder("my_convention")
    .reg(0, "rcx")
    .reg(1, "rdx")
    .stack_offset(2, 0x28)   # value at [rsp+0x28] at call time
    .stack_push(3, 0)        # value from a push sequence, position 0 = last pushed
    .build()
)
report = extractor.extract_calls(func_ea, convention=convention, num_args=4)
```

`num_args` is required whenever it can't be derived from a recognized
prototype — the framework won't guess an argument count.

## Declaring argument types (post-processing)

```python
from idanalysister.typespec.argtype import ArgTypeSpec

arg_types = {
    1: ArgTypeSpec.c_string(1, label="filename"),
    2: ArgTypeSpec.integer(2, hex_format=True, label="flags"),
}
report = extractor.extract_calls(func_ea, convention=CDECL, num_args=3, arg_types=arg_types)

for site in report.call_sites:
    filename_arg = site.argument(1)
    print(filename_arg.label, "=", filename_arg.processed_value)
```

`raw_value` stays the unprocessed resolved value; `processed_value` is the
result after running the declared post-processor chain. Built-in
constructors: `ArgTypeSpec.c_string`, `.wide_string`, `.integer`,
`.custom(*postprocessors)`.

### Custom post-processors

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

arg_types = {0: ArgTypeSpec.custom(0, XorDecrypt(key=b"\x5a", length=16))}
```

Register it by name for use from declarative config too:

```python
from idanalysister.postproc.registry import register_postprocessor
register_postprocessor("xor_decrypt", XorDecrypt)
```

## Declarative (dict-based) configuration

For most tasks you don't need to import convention/type-spec classes at
all — express the whole thing as a plain `dict`:

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
]}}
```

## Intra-function forward resolution (3.3)

Resolve what an argument's value has become at a specific point inside the
function — the "value after the decryption loop, right before this call"
case:

```python
value = extractor.resolve_argument_at(
    func_ea,
    arg_index=0,
    target_ea=0x00401050,   # e.g. the call instruction right after a decrypt loop
    convention=MS_X64,
    num_args=1,
)
```

Only register-passed arguments can be forward-tracked (see
`document/architecture.md` §7 for why) — a stack-passed argument returns
`Unknown(UNSUPPORTED_OPERAND_SHAPE)`. The returned value reflects the
**pointer identity**, not decrypted memory content, when the argument's
target buffer is mutated through a variable-indexed write inside a loop —
pair this with a custom `PostProcessor` (above) to actually decode the
buffer once you know its address is unchanged.

## Reading results

| Type | Meaning |
|---|---|
| `Concrete(value, kind)` | Fully resolved: an immediate, folded arithmetic, or memory content. |
| `MemoryRef(addr, value)` | A dereferenced memory read; `addr` is where it came from, `value` is what was found (chain another dereference off `value` if it's itself a pointer). |
| `Symbolic(expr)` | Tracked through data flow but not a constant, e.g. `"arg0"` or `"ret(0x4010a0)"` (a prior call's return value). |
| `Unknown(reason, detail)` | Could not be statically determined — check `reason` (a `core.diagnostics.UnknownReason`) to see why. |

Common `UnknownReason` values and what to do about them:

- `NO_DEFINITION_FOUND` — walked back to the function entry without a
  write; the value likely comes from a caller-supplied argument itself, or
  genuinely isn't initialized on this path.
- `DIVERGENT_PATHS` / `DIVERGENT_SYMBOLIC` — two control-flow paths
  disagree; the framework refuses to guess which one applies.
- `BUDGET_EXCEEDED` — the walk hit its step/block cap (`ParamExtractor(max_steps=...,
  max_blocks=...)` to raise it) — usually means a pathological or very
  large function.
- `UNSUPPORTED_INSTRUCTION` — no `Locator` recognizes this instruction as a
  definition; see "Adding a new instruction form" below.
- `MEMORY_READ_FAILED` — the computed address has no data in the IDB.
- `LOOP_NON_CONVERGENT` — a forward-tracked value kept changing across loop
  iterations without stabilizing.

## Adding a new instruction form

No form your target binary uses should require touching this package's
internals. Follow `idanalysister/locators/extension_points.py` (a complete,
runnable example — `not reg`, bitwise complement):

```python
from idanalysister.locators.base import Locator, LocatorOutcome
from idanalysister.core.insn_model import OperandKind
from idanalysister.core.values import Concrete, ValueKind

class MyLocator(Locator):
    name = "my_form"

    def matches(self, instr):
        return instr.mnem == "my_mnemonic" and instr.operand(0).kind is OperandKind.REG

    def extract(self, instr, dest_operand, ctx):
        # recurse via ctx.resolve_register(...) / ctx.resolve_memory(...) as needed
        return LocatorOutcome.resolved(Concrete(0, ValueKind.INT))

extractor = ParamExtractor()
extractor.registry.register(MyLocator())
```

Each `ParamExtractor` owns its own `LocatorRegistry` — registering a custom
locator on one instance never affects another.

## Optional Hex-Rays fallback

If a licensed Hex-Rays decompiler is available for the target architecture,
you can opt into using it as a secondary source for arguments the raw
engine leaves `Unknown`:

```python
extractor = ParamExtractor(use_hexrays_fallback=True)
report = extractor.extract_calls(func_ea, convention=CDECL, num_args=2)
for arg in report.call_sites[0].arguments:
    print(arg.index, arg.raw_value, arg.source)  # source: "raw" or "hexrays_fallback"
```

Never required, never silently blended — `ArgumentResult.source` always
tells you which engine produced a given value. See
`document/architecture.md` §10 for why this is opt-in rather than the
default.

## Performance notes

- `ParamExtractor` owns one `InstructionCache` per session — reuse the same
  extractor across multiple `extract_calls`/`resolve_argument_at` calls
  rather than constructing a new one each time, to get the caching benefit.
- `max_steps`/`max_blocks` (constructor args) bound every backward walk;
  lower them for tighter latency guarantees on very large functions, raise
  them if you're seeing `BUDGET_EXCEEDED` on legitimately large but
  reasonable call sites.

## Running the tests

```sh
pytest tests/unit                        # no IDA required
pytest tests/integration -m requires_ida  # requires a local IDA Pro + idalib install
```
