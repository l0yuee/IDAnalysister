# idanalysister — Architecture

## 1. Goal and constraints

`idanalysister` extracts call-site argument values and resolves argument
values at arbitrary points inside a function body, driven by declarative
configuration (calling-convention templates, per-argument type hints)
rather than per-script code. It runs inside IDAPython (IDA Pro ≥ 9.3,
Python ≥ 3.13) using only public `ida_*` modules, and is built to never
raise an exception past its public API — anything it cannot statically
determine is reported as an explicit, reasoned `Unknown`, never a bare
`None` and never a guess.

## 2. Two-plane design

The package is split into a **pure-Python analysis core** (no `ida_*`
imports anywhere) sitting behind a thin **adapter boundary**
(`adapters.ida_port.IdaPort`) that is the *only* place `ida_*` calls occur:

```
adapters/ida_port.py         IdaPort — abstract interface, the entire ida_* surface used
adapters/ida_port_impl.py    concrete implementation over ida_ua/idautils/ida_gdl/
                              ida_bytes/ida_funcs/ida_frame/ida_typeinf/ida_nalt/ida_idp
adapters/fake_port.py        in-memory IdaPort test double (no IDA needed)
adapters/hexrays_backend.py  optional ida_hexrays cross-check (see §7)

core/                        graphs, dataflow lattice, caching — zero ida_* imports
locators/                    instruction-form strategies (the extension mechanism)
conventions/                 calling-convention templates, inference, custom builder
postproc/                    post-processor interface + built-ins + registry
typespec/                    per-argument type declaration (binds postproc to an index)
config/                      declarative dict → convention/type-spec construction
api/                         ParamExtractor (composition root) + result dataclasses
```

Dependency direction is one-way: `adapters` is a leaf; `core` depends only
on the `IdaPort` interface; `locators`/`conventions`/`postproc` depend on
`core` and `adapters.ida_port` (never `ida_port_impl` directly — they
receive a port via constructor injection); `api.facade` is the composition
root that wires a concrete `IdaPort` into everything else. This is what
lets `core`, `locators`, and `conventions` be unit-tested against
`FakeIdaPort` with no IDA installation (`tests/unit`), while
`ida_port_impl.py` itself is validated separately against a real,
headlessly-analyzed binary (`tests/integration`).

## 3. The value lattice (`core/values.py`)

Every resolution result is one of:

- **`Unknown(reason, detail)`** — could not be statically determined.
  `reason` is a `core.diagnostics.UnknownReason` (`NO_DEFINITION_FOUND`,
  `DIVERGENT_PATHS`, `BUDGET_EXCEEDED`, `UNSUPPORTED_INSTRUCTION`,
  `MEMORY_READ_FAILED`, `LOOP_NON_CONVERGENT`, ...) so a failure is
  auditable rather than a silent black box.
- **`Concrete(value, kind)`** — a fully resolved immediate, folded
  arithmetic result, or memory content.
- **`MemoryRef(addr, value)`** — the result of a dereference: `addr` is
  where the value was read from, `value` is what was found there (usually
  `Concrete`, but `Unknown` if the read failed). Both are retained, so if
  `value` is itself a pointer (e.g. to a string), a post-processor can
  dereference further without the original address having been discarded
  — this is the mechanism behind requirement 3.1.3's "if the memory
  content is another pointer, retain it for further resolution."
- **`Symbolic(expr)`** — provably tracked through data flow but not a
  compile-time constant, e.g. `"arg0"` or `"ret(0x4010a0)"`.
- **`MutatedRegion(base_expr, via)`** — memory relative to a tracked
  pointer was written through a non-constant offset (typically inside a
  loop); the pointer itself may still be fully known even though its
  contents are not tracked scalar-wise (see §6).

`core/merge.py` defines `join()`: two paths agreeing on a concrete value
stays concrete; disagreeing concrete values, differing symbolic
expressions, or anything joined with `Unknown` all collapse to `Unknown`
with an appropriate reason. The framework never averages or picks one side
— a wrong concrete answer is worse than an honest `Unknown`.

## 4. Instruction model and caching

`core/insn_model.py` defines `Instruction`/`Operand` — a normalized,
architecture-agnostic view built once by `ida_port_impl._convert_instruction`
from `ida_ua.insn_t`/`op_t`. Beyond the obvious fields (mnemonic, operand
kind/register/displacement/immediate), each operand carries a parallel
`operand_written: tuple[bool, ...]` computed from IDA's own `CF_CHG1..CF_CHG8`
instruction-feature bits (`ida_idp`). This is what lets the resolver
recognize "this instruction defines register/memory operand N" **generically,
for any instruction — including ones with no dedicated `Locator`** — rather
than needing a hardcoded mnemonic table to know what counts as a
definition site. It is the single biggest lever for requirement 3.1 form
#9 ("any other rare form... easily supportable"): even an instruction
nobody has written a `Locator` for is still correctly recognized as
*clobbering* a tracked location (yielding an honest `UNSUPPORTED_INSTRUCTION`
`Unknown` for its resolved value, rather than the resolver silently
skipping past a real definition).

`core/insn_cache.py`'s `InstructionCache` memoizes `IdaPort.decode_at` and
`code_refs_to` results (bounded LRU) for the lifetime of one
`ParamExtractor` session — this is what keeps single-call-site extraction
within the <100ms performance target and satisfies the "cache instruction
decode + xref results" requirement.

## 5. Locators — the extension mechanism (`locators/`)

Every argument-passing/value-producing instruction form is a
`locators.base.Locator`:

```python
class Locator(ABC):
    def matches(self, instr: Instruction) -> bool: ...
    def extract(self, instr, dest_operand, ctx: ResolutionContext) -> LocatorOutcome: ...
    def apply_forward(self, instr, state: AbstractState) -> AbstractState: ...  # optional, has a safe default
```

`matches()` is cheap shape recognition (mnemonic + operand kinds) only.
`extract()` interprets an instruction the resolver has *already confirmed*
is a definition of `dest_operand` — it never has to figure out "is this the
right instruction," only "what value does it produce," recursing into
`ctx.resolve_register()` / `ctx.resolve_memory()` for source operands that
aren't yet resolved. `apply_forward()` is the equivalent transfer function
for the forward engine (§6); locators that don't override it get a safe
default (invalidate whatever the instruction writes).

Built-in locators, one small module per family:

| Module | Forms covered |
|---|---|
| `register_locators.py` | `mov reg,reg` / `mov reg,imm` / `lea reg,[global]` / `xchg` / `cmov` |
| `arithmetic_locators.py` | `lea reg,[base+disp]` / `add`,`sub reg,imm` (constant folding) |
| `memory_locators.py` | `mov reg,[mem]` — global, `[reg+off]`, TLS (`gs:`/`fs:`) |
| `immediate_locators.py` | `mov [mem],imm` |
| `stack_locators.py` | `push` (any operand shape) / `mov [mem],reg` |
| `call_return_locators.py` | prior call's return register used as an argument |
| `extension_points.py` | documented ABC + a complete worked example (`not reg`), **not** auto-registered |

A **`LocatorRegistry`** is owned per `ParamExtractor` session (no shared
global mutable state), so adding a locator — `registry.register(MyLocator())`
— never touches `core/` and never affects another session. This is the
entire mechanism behind "adding a new argument-passing form requires only
writing a new component and registering it."

### Structural matching lives in the resolver, not the locator

A locator only answers "given that this instruction defines operand N, what
value does it produce" — it never decides *whether* an instruction is
relevant to a query. That decision (does this instruction write register R?
does this instruction write memory location `(base, disp)`?) is made
generically by `core.engine_backward.BackwardResolver` using
`operand_written` + operand shape, with one deliberate special case: a
`call` instruction is treated as a definition of the platform's return
register (`IdaPort.return_value_reg()`) even though it has no explicit
register operand naming it — this is what makes requirement 3.1 form #8
work without a `Locator` needing to special-case call semantics itself.

## 6. Backward resolution — call-site extraction (3.1)

`core.engine_backward.BackwardResolver` provides three primitives:

- **`resolve_register(reg, before_ea)`** — walk backward through the CFG
  (`core.cfg_model.CfgModel`, built from `IdaPort.get_flowchart_blocks`)
  looking for the nearest instruction that writes `reg`. At a block with
  multiple predecessors, recurse into each and `join()` the results.
- **`resolve_memory(base_reg, disp, before_ea, size)`** — the workhorse for
  every memory-indirect form (global, TLS, stack, register-indirect struct
  access). It normalizes `(base_reg, disp)` into a canonical key: stack-
  pointer-relative displacements are adjusted by `IdaPort.get_sp_delta`
  (so `[esp+4]` at two different points with different intervening
  `sub esp` amounts still compare correctly), frame-pointer-relative
  displacements are used directly (stable across the function), and
  arbitrary-register-relative accesses are matched by literal `(reg, disp)`
  identity — a documented approximation (no general pointer-aliasing
  analysis). It searches backward for the nearest matching write; only if
  none is found does it fall back to reading the IDB's static byte content
  (correct for true globals; for stack/heap-relative queries with no local
  write, the honest answer is `Unknown(NO_DEFINITION_FOUND)`, since raw
  stack bytes in a static image mean nothing).
- **`resolve_at_instruction(ea)`** — interpret one already-identified
  instruction directly (used for push-sequence slots, where the exact
  defining `push` is already known from `collect_push_sequence`).

Both walks share a per-top-level-query `ResolutionBudget` (step count +
block count), even across recursive locator callbacks, so one argument's
resolution can never run unbounded — this is what keeps the <100ms target
achievable and makes pathological CFGs fail closed quickly rather than
hang.

## 7. Forward resolution — intra-function value tracking (3.3)

`core.engine_forward.ForwardSymbolicEngine.resolve_at(func_ea, arg_index,
target_ea, initial_reg)` seeds an `AbstractState` (register + stack-slot
map) with `Symbolic(f"arg{i}")` in the argument's entry register, then runs
a bounded worklist fixpoint over the CFG:

- Register-only instructions delegate to `Locator.apply_forward` (mov/lea/
  add/sub-immediate/movzx/movsx propagate precisely; `xchg` swaps; `cmov`
  joins the "moved" and "not moved" outcomes, since the condition isn't
  statically decidable — never guessed).
- Memory loads/stores through the stack or frame pointer are handled
  centrally by the engine (mirroring the backward resolver's normalization),
  so a spill-then-reload of the tracked pointer survives correctly.
- At merge points, per-location values are joined the same way as the
  backward resolver.
- Loop headers are revisited up to a bound; after `loop_widen_after`
  visits, any location whose value hasn't stabilized is widened straight
  to `Unknown(LOOP_NON_CONVERGENT)` — since `Unknown` is absorbing under
  `join`, this guarantees termination.

**The canonical scenario this is built for**: a decryption loop that
mutates a buffer through `[ptr_reg + loop_counter]` — a *non-constant*
index — never reassigns `ptr_reg` itself. The engine's memory model only
tracks stack/frame-pointer-relative cells as scalar state; a write through
an arbitrary register with a variable index is neither fabricated nor
mistakenly invalidates unrelated state — it's simply not modeled as scalar
content, so the *pointer* resolves precisely (`Symbolic("arg0")`, unchanged)
while the *decrypted content* is explicitly out of pure-dataflow scope.
Decrypting the buffer's bytes is exposed as a first-class, user-suppliable
`PostProcessor` (requirement 3.2's own example — "applying a specific
decryption routine to a buffer") rather than something the generic engine
guesses at via pattern-matching "XOR loop" shapes.

**Scope limitation, stated plainly**: only register-passed arguments can be
seeded. A stack-passed argument has no single well-defined
callee-frame-relative offset derivable generically across calling
conventions from the caller-side `ArgSlot` alone; forward-tracking one
yields `Unknown(UNSUPPORTED_OPERAND_SHAPE)` rather than risking a wrong
offset.

## 8. Calling conventions (`conventions/`)

`CallingConvention.slots(num_args, port) -> list[ArgSlot]` maps an argument
index to *where its value lives* (`SlotKind.REGISTER` / `STACK_PUSH` /
`STACK_OFFSET`) — resolving that location to a value is the resolver's job,
keeping conventions pure declarative data.

- **`templates.py`** — `CDECL`, `STDCALL`, `FASTCALL`, `THISCALL`, `MS_X64`,
  `SYSV_X64`, each a small declarative `RegisterThenStackConvention` table.
- **`inference.py`** — if IDA already has a recognized prototype
  (`ida_typeinf.func_type_data_t`/`argloc_t`), `infer()` builds a
  `PrototypeConvention` directly from IDA's own per-argument
  `ALOC_REG1`/`ALOC_STACK` locations — correctly handling mixed
  register+stack conventions (including x86-64, where the ABI isn't
  encoded in `callcnv_t` itself) with no template guessing at all.
- **`custom_builder.py`** — `ConventionBuilder().reg(0,"rcx").stack_offset(1,0x28).build()`
  for ad hoc conventions, purely declaratively.

## 9. Post-processing and type specs (3.2)

`postproc.base.PostProcessor`/`PostProcessorChain` transform a raw resolved
value — built-ins (`postproc/builtins.py`) cover C-string and UTF-16-string
dereference, hex formatting, integer cast, and fixed-offset struct field
access. `typespec.argtype.ArgTypeSpec` binds a chain to an argument index;
`postproc.registry` lets custom post-processors (e.g. a project-specific
decryption routine) register by name for use from declarative config
(`config/schema.py`). A chain short-circuits on an already-`Unknown` input
and never raises past `run()` — a failing step logs and degrades to
`Unknown`.

## 10. Hex-Rays: optional, never primary (`adapters/hexrays_backend.py`)

`ida_hexrays` requires a separately-licensed decompiler per architecture
and is not guaranteed present, so it is never a hard dependency and never
the default engine — making it primary would silently break the "cover
every x86/x86-64 instruction form" requirement on any install without a
license for the target architecture, and its own constant-propagation
passes can obscure the exact raw-instruction provenance (dereferenced value
vs. address, exact form used) the framework's contract promises.

`HexraysBackend.resolve_call_args` is wired in only as an **opt-in
fallback**: `ParamExtractor(use_hexrays_fallback=True)` retries an
argument through Hex-Rays microcode (`mba_t`/`mcallinfo_t.args`) *only*
when the raw walk returned `Unknown`, and the substituted value is tagged
`ArgumentResult.source = "hexrays_fallback"` — never silently blended with
`"raw"` results. Availability is probed defensively
(`ida_hexrays.init_hexrays_plugin()` inside a `try/except`), so its absence
never affects the raw path. Forward (3.3) cross-checking via microcode is a
documented extension point, not implemented — reproducing the forward
engine's fixpoint semantics against `mba_t` block structures is
substantial additional surface for a secondary backend that the primary,
fully-implemented raw `ForwardSymbolicEngine` already covers.

## 11. Stability

Every engine boundary (locator `extract`/`apply_forward`, post-processor
`process`, every `IdaPort` method) is wrapped so an underlying exception is
logged and converted to a typed `Unknown`/`None` rather than propagating.
`api.facade.ParamExtractor.extract_calls` additionally wraps each call
site's extraction individually, so one call site's failure never aborts
extraction for the rest. This is exercised directly by a Hypothesis-based
property test (`tests/unit/api/test_facade.py`) that feeds randomized,
often-nonsensical instruction sequences through the full pipeline and
asserts no exception ever escapes.

## 12. Testing strategy

- **`tests/unit/`** (no IDA required) — every locator, the backward/forward
  engines' merge/widening/budget semantics, convention templates/inference/
  builder, post-processor chaining, and end-to-end `ParamExtractor` scenarios,
  all against `adapters.fake_port.FakeIdaPort`.
- **`tests/integration/`** (`pytest -m requires_ida`, needs a local IDA Pro +
  idalib installation) — a small hand-written NASM fixture
  (`tests/integration/fixtures/probe.asm`) covering push-sequence +
  memory-indirect, register-indirect addressing, prior-call-return
  chaining, and the decrypt-loop-then-call forward-resolution scenario,
  analyzed headlessly via `idapro.open_database` and validated against the
  real `IdaPortImpl` — the one layer `FakeIdaPort` cannot exercise.
