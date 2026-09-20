<p align="right"><a href="user_manual.md">English</a></p>

# idanalysister —— 用户手册

本手册按照**你想做什么**来组织，而不是按照代码包的内部结构——请直接跳转到与你当前场景匹配的小节。文档末尾提供了一份简明的逐模块参考,供你在需要深入了解时查阅（例如编写扩展、解读诊断信息等）。关于框架**为什么**要这样设计，请参阅 [`architecture.md`](architecture.md)（英文）。

## 目录

1. [安装与配置](#1-安装与配置)
2. [五分钟了解核心概念](#2-五分钟了解核心概念)
3. 场景手册
   - [3.1 使用已知的调用约定提取参数](#31-使用已知的调用约定提取参数)
   - [3.2 让 IDA 自动推断调用约定](#32-让-ida-自动推断调用约定)
   - [3.3 描述一个自定义/非标准调用约定](#33-描述一个自定义非标准调用约定)
   - [3.4 获取带类型、可读的输出](#34-获取带类型可读的输出)
   - [3.5 编写你自己的后处理器（例如解密例程）](#35-编写你自己的后处理器例如解密例程)
   - [3.6 求出函数内部某一点的参数值（对应 requirement.md 的 3.3）](#36-求出函数内部某一点的参数值)
   - [3.7 处理框架尚不认识的指令形式](#37-处理框架尚不认识的指令形式)
   - [3.8 用声明式方式（dict / JSON / YAML）配置一切](#38-用声明式方式dict--json--yaml配置一切)
   - [3.9 开启可选的 Hex-Rays 兜底机制](#39-开启可选的-hex-rays-兜底机制)
   - [3.10 调整性能与解析预算](#310-调整性能与解析预算)
   - [3.11 读懂并诊断一个 `Unknown` 结果](#311-读懂并诊断一个-unknown-结果)
4. [逐模块参考](#4-逐模块参考)
5. [为你自己的扩展编写测试](#5-为你自己的扩展编写测试)
6. [常见问题 / 故障排查](#6-常见问题--故障排查)
7. [运行测试套件](#7-运行测试套件)

---

## 1. 安装与配置

```sh
cd IDAnalysister
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

在 IDA 内部（或者由 `idalib` 驱动的无界面脚本中），在导入之前先把 `src/` 加入路径：

```python
import sys
sys.path.insert(0, "/path/to/IDAnalysister/src")

from idanalysister import ParamExtractor, CDECL, STDCALL, FASTCALL, THISCALL, MS_X64, SYSV_X64
```

`import idanalysister` 本身在 IDA 之外也能正常工作（单元测试套件正是这样运行的）——只有在不传入显式 `port=` 参数就构造 `ParamExtractor()` 时才需要一个正在运行的 IDA/`idalib` 会话，因为这正是它构建真实适配器（`adapters.ida_port_impl.IdaPortImpl`）的时刻。

## 2. 五分钟了解核心概念

**`ParamExtractor`**（`idanalysister.ParamExtractor`）是你唯一需要构造的类。它在内部持有其余所有组件（一个 IDA 适配器、一个指令缓存、一个定位器注册表），并对外暴露恰好两个分析方法：

- `extract_calls(func_ea, convention=None, num_args=None, arg_types=None)` —— 对应需求文档 3.1：找到 `func_ea` 的所有调用点并解析其参数。
- `resolve_argument_at(func_ea, arg_index, target_ea, convention=None, num_args=None)` —— 对应需求文档 3.3：解析某个参数在 `func_ea` 函数体内某一具体位置处的值。

**每一个被解析出的值**都是以下五种形态之一（定义在 `idanalysister.core.values` 中），你会一直用类型判断来处理它们：

| 类型 | 含义 |
|---|---|
| `Concrete(value, kind)` | 完全已知——一个立即数、经过常量折叠的算术结果，或内存内容。 |
| `MemoryRef(addr, value)` | 一次解引用的结果：`addr` 是读取来源的地址，`value` 是那里存放的内容（如果 `value` 本身又是一个指针，可以继续链式解引用）。 |
| `Symbolic(expr)` | 通过数据流被精确跟踪，但不是编译期常量——例如 `"arg0"`（仍然是最初传入、未被修改过的参数）或 `"ret(0x4010a0)"`（某次具体调用的返回值）。 |
| `MutatedRegion(base_expr, via)` | 相对于某个被跟踪指针的内存被以非常量下标写入过（例如在循环内部）——指针本身可能依然被精确掌握，即便其指向的内容没有被当作标量状态跟踪。 |
| `Unknown(reason, detail)` | 无法被静态确定；`reason` 是一个 `core.diagnostics.UnknownReason` 枚举值——见 [§3.11](#311-读懂并诊断一个-unknown-结果)。 |

每一个 `ValueLattice` 都有一个 `.is_known` 属性（只有 `Unknown` 为 `False`）。`ArgumentResult`（你为每个参数拿到的结果对象）还额外携带 `.raw_value`、`.processed_value`（经过后处理之后的值，如果没有声明类型则与原始值相同）、`.label`，以及 `.source`（`"raw"` 或 `"hexrays_fallback"`）。

---

## 3.1 使用已知的调用约定提取参数

最常见的情形：你已经知道（或者愿意假设）调用约定。

```python
from idanalysister import ParamExtractor, CDECL

extractor = ParamExtractor()
report = extractor.extract_calls(func_ea=0x00401000, convention=CDECL, num_args=2)

print(f"{report.call_count} 个调用点")
for site in report.call_sites:
    print(hex(site.call_ea))
    for arg in site.arguments:
        print(f"  arg{arg.index} = {arg.raw_value!r}")
```

内置模板位于 `idanalysister.conventions.templates`（同时也在包顶层重新导出：`from idanalysister import CDECL, STDCALL, FASTCALL, THISCALL, MS_X64, SYSV_X64`）：

| 常量 | 调用约定 |
|---|---|
| `CDECL` | 所有参数从右到左依次 `push` 入栈；由调用者负责清栈。 |
| `STDCALL` | 从调用者视角看,栈布局与 cdecl 相同（清栈由被调用者负责，这一点对本框架而言无需关心）。 |
| `FASTCALL` | MSVC `__fastcall`：前两个参数分别在 `ecx`、`edx` 中；其余参数入栈。 |
| `THISCALL` | MSVC `__thiscall`：`this` 指针在 `ecx` 中；其余参数入栈。 |
| `MS_X64` | Microsoft x64 ABI：前四个参数分别在 `rcx`、`rdx`、`r8`、`r9` 中；其余参数依次位于 `[rsp+0x20]`、`[rsp+0x28]`…… |
| `SYSV_X64` | System V AMD64 ABI（Linux/macOS）：前六个参数分别在 `rdi`、`rsi`、`rdx`、`rcx`、`r8`、`r9` 中；其余参数依次位于 `[rsp+0]`、`[rsp+8]`…… |

这里必须提供 `num_args`——仅凭一个模板本身无法知道某次具体调用到底有多少个参数。

## 3.2 让 IDA 自动推断调用约定

如果 IDA 已经识别出了该函数的原型（通过签名匹配、用户手动设置的类型，或 IDA 自身的分析），你可以两个参数都不传：

```python
report = extractor.extract_calls(func_ea)  # 调用约定和参数个数都从 IDA 的原型中读取
```

这在内部会调用 `idanalysister.conventions.inference.infer(func_ea, port)`，它直接读取 `ida_typeinf.func_type_data_t`/`argloc_t`——因此能够正确处理寄存器与栈混合的调用约定（包括 x86-64，因为其 ABI 本身并没有编码在 `callcnv_t` 里），完全不需要猜测。如果 IDA 没有原型信息，提取过程会退回到 `CDECL`，此时你需要自行提供 `num_args`（否则会抛出 `ConventionError`，让你立刻发现问题，而不是悄悄得到错误结果）。

你也可以显式调用推断逻辑并检查结果：

```python
from idanalysister.conventions.inference import infer

convention = infer(func_ea, extractor.port)
if convention is not None:
    print(convention.name, convention.arg_count)
```

## 3.3 描述一个自定义/非标准调用约定

对于手写、经过混淆或其他非标准的调用约定，可以用声明式的方式组合各种参数定位策略——完全不需要新写解析器代码：

```python
from idanalysister.conventions.custom_builder import ConventionBuilder

convention = (
    ConventionBuilder("my_convention")
    .reg(0, "rcx")            # 参数 0 在调用时位于 rcx
    .reg(1, "rdx")            # 参数 1 位于 rdx
    .stack_offset(2, 0x28)    # 参数 2 是调用时 [rsp+0x28] 处的值
    .stack_push(3, 0)         # 参数 3 来自 push 序列；position 0 表示调用前最后一次 push
    .build()
)
report = extractor.extract_calls(func_ea, convention=convention, num_args=4)
```

`.stack_push(index, position)`：`position` 是从调用时非寄存器 `push` 序列的**栈顶**开始计数的——`0` 表示 `call` 之前最后压入的那条指令（也就是离调用指令最近的参数，即按从右到左压栈顺序中"最靠左"、尚未占用寄存器的那个参数），`1` 表示再往前压入的那一条，依此类推。这与 `CDECL`/`FASTCALL` 等内置模板内部的定义方式完全一致，因此将一个自定义的寄存器前缀与基于 push 的尾部参数混合使用时，行为会与内置模板完全一致。

如果某个参数序号既没有声明 `.reg()`，也没有声明 `.stack_offset()` 或 `.stack_push()`，那么一旦 `slots()` 被求值就会抛出 `idanalysister.errors.ConventionError`——配置错误会被立刻捕获，而不是悄悄产生一个错误的结果。

## 3.4 获取带类型、可读的输出

声明每个参数**是什么类型**，就能在原始值之外同时拿到经过后处理的结果：

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

`arg.raw_value` 不受 `arg_types` 影响——它始终是直接解析出来的结果。`arg.processed_value` 则是 `raw_value` 经过声明的后处理链之后的结果（如果该序号没有声明类型，则与 `raw_value` 相同；如果 `raw_value` 本身已经是 `Unknown`，后处理会被完全跳过,而不会对一个无意义的值继续操作）。

内置的 `ArgTypeSpec` 构造方法：

| 构造方法 | 产生的结果 |
|---|---|
| `ArgTypeSpec.c_string(index, label=None, max_len=4096)` | 将一个指针形态的值解引用为窄字符（UTF-8/Latin-1）C 字符串。 |
| `ArgTypeSpec.wide_string(index, label=None, max_len=4096)` | 同上，但解码为 UTF-16LE。 |
| `ArgTypeSpec.integer(index, hex_format=False, label=None)` | 转换为普通整数；可选地格式化为十六进制字符串。 |
| `ArgTypeSpec.custom(index, *postprocessors, label=None)` | 运行任意一串 `PostProcessor` 实例——见 §3.5。 |

## 3.5 编写你自己的后处理器（例如解密例程）

继承 `idanalysister.postproc.base.PostProcessor`。`process(value, port)` 接收上一步产生的 `ValueLattice` 以及当前活跃的 `IdaPort`（用于读取内存），并且必须返回一个 `ValueLattice`——不要抛出异常（后处理链本身也会做防御性包装，但一个规范的后处理器应当在自己的失败路径上主动返回 `Unknown`）：

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

直接使用：

```python
arg_types = {0: ArgTypeSpec.custom(0, XorDecrypt(key=b"\x5a", length=16))}
```

串联多个步骤——它们按顺序执行，一旦遇到 `Unknown` 就会短路：

```python
ArgTypeSpec.custom(0, XorDecrypt(key=b"\x5a", length=16), SomeOtherStep())
```

或者按名称注册它，这样就可以从声明式配置（§3.8）中引用它，而不必直接导入：

```python
from idanalysister.postproc.registry import register_postprocessor
register_postprocessor("xor_decrypt", XorDecrypt)
```

这里的 `port` 就是全框架统一使用的 `IdaPort` 接口——对后处理器有用的方法包括：`read_bytes(addr, size)`、`read_int(addr, size, signed=False)`、`read_cstring(addr, max_len)`、`read_wstring(addr, max_len)`、`is_mapped(addr)`。

## 3.6 求出函数内部某一点的参数值

这正是 requirement.md 明确点名的场景：某个参数是一个指向加密数据的指针，函数原地对其解密，而你想要的是**某个特定调用之前**、解密完成之后的那个值：

```python
value = extractor.resolve_argument_at(
    func_ea=0x00401000,
    arg_index=0,
    target_ea=0x00401050,   # 你关心的那条指令的地址
    convention=MS_X64,
    num_args=1,
)
```

返回结果的含义：

- 如果在所有到达 `target_ea` 的路径上，该参数所在的寄存器都从未被重新赋值（这是最常见的情形——一个缓冲区指针在解密循环中存活了下来，因为循环是通过一个可变下标去修改缓冲区内容，而不是修改指针本身），你会得到 `Symbolic("arg0")`，也就是"仍然完全是最初传入的那个参数"。
- 如果在所有到达该点的路径上，它都被重新赋值为同一个编译期常量，你会得到 `Concrete(...)`。
- 如果不同路径上的结果互相矛盾，或者某个循环内被跟踪的值始终无法收敛，你会得到 `Unknown(DIVERGENT_PATHS)` 或 `Unknown(LOOP_NON_CONVERGENT)`。

**重要的适用范围限制**：目前只有**通过寄存器传递**的参数才能被正向跟踪（否则会得到 `Unknown(UNSUPPORTED_OPERAND_SHAPE)`）——具体原因见
[`architecture.md` 第 7 节](architecture.md#7-forward-resolution--intra-function-value-tracking-33)：一个通过栈传递的参数，在不同调用约定下并不存在一个能够被通用地推导出来的、单一确定的"被调用者帧内偏移量"可以作为种子值。请选择一个能把你关心的参数放进寄存器的调用约定/参数序号（对于"使用前先解密一个缓冲区"这种模式，这几乎总是成立的——传入的是指针，而不是缓冲区内容本身）。

**该引擎解析的是指针本身的身份，而不是解密后的字节内容。** 如果你需要实际解密后的内容，先确认指针已经被解析为某个具体的、已知的值,然后使用一个自定义后处理器（§3.5）自行读取并解码该地址处的内存——引擎故意不会去猜测"这看起来像一个 XOR 循环"并凭空编造解密后的数据。

## 3.7 处理框架尚不认识的指令形式

如果 `extract_calls`/`resolve_argument_at` 针对目标二进制中使用的某条指令报告了 `Unknown(UNSUPPORTED_INSTRUCTION)`，添加一个 `Locator` 即可——不需要修改任何核心文件。参照
`src/idanalysister/locators/extension_points.py`（一个完整、可直接运行的示例：`not reg`，按位取反）：

```python
from idanalysister.locators.base import Locator, LocatorOutcome
from idanalysister.core.insn_model import OperandKind
from idanalysister.core.values import Concrete, ValueKind

class MyLocator(Locator):
    name = "my_form"

    def matches(self, instr):
        # 只需做低成本的形态判断：助记符 + 操作数类型
        return instr.mnem == "my_mnemonic" and instr.operand(0).kind is OperandKind.REG

    def extract(self, instr, dest_operand, ctx):
        # 对尚未解析的源操作数，可以调用
        # ctx.resolve_register(reg, before_ea) / ctx.resolve_memory(base_reg, disp, before_ea, size) 递归求解
        return LocatorOutcome.resolved(Concrete(0, ValueKind.INT))

extractor = ParamExtractor()
extractor.registry.register(MyLocator())
```

几点说明：

- `matches()` 只需要识别指令的**形态**——解析器在调用 `extract()` 之前，已经通过 IDA 自身的 `CF_CHG*` 操作数写标志确认了这条指令确实写入了被查询的寄存器/内存位置。你完全不需要判断"这是不是正确的定义点"，只需要判断"这条指令产生了什么值"。
- 对于你不处理的操作数形态,应返回 `LocatorOutcome.not_applicable()`——绝不要对不确定的形态猜一个值出来。
- 如果你还希望这条指令在**正向**解析（§3.6）过程中也被正确建模，请同时重写 `apply_forward(self, instr, state)`（可参考 `arithmetic_locators.py` 中 `AddSubRegImmLocator` 的完整示例）。如果不重写，安全的默认行为会在正向遍历时保守地把该指令写入的寄存器置为未知——正确但不够精确。
- `extractor.registry` 是该 `ParamExtractor` 实例私有的；在一个 extractor 上注册的东西不会影响另一个,也完全不需要修改 `locators/base.py` 中的 `default_registry()`，除非你希望把自己的定位器作为内置组件提供给所有用户使用。

## 3.8 用声明式方式（dict / JSON / YAML）配置一切

对于绝大多数任务，完全不需要导入调用约定/类型规格相关的类，把整个请求表达成一个纯 `dict` 即可——这对配置文件、命令行工具，或构建在本包之上的 UI 都很方便：

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

以配置形式描述一个自定义调用约定：

```python
{"convention": {"custom": [
    {"index": 0, "reg": "rcx"},
    {"index": 1, "stack_offset": 0x28},
    {"index": 2, "stack_push": 0},
]}}
```

以配置形式引用一个（已在 §3.5 中注册过的）自定义后处理器：

```python
{"arg_types": {0: {"type": "custom", "postprocessors": [("xor_decrypt", {"key": b"\x5a", "length": 16})]}}}
```

框架本身不捆绑 YAML 依赖——请自行加载 YAML（`yaml.safe_load(open(path))`）并把得到的 `dict` 传入；`config.schema` 只负责解释这个纯 Python 结构，无论它最初来自 JSON 还是 YAML 都一样。

## 3.9 开启可选的 Hex-Rays 兜底机制

如果本地针对目标架构有已授权的 Hex-Rays 反编译器，可以让它去填补原始引擎判定为 `Unknown` 的那些值：

```python
extractor = ParamExtractor(use_hexrays_fallback=True)
report = extractor.extract_calls(func_ea, convention=CDECL, num_args=2)
for arg in report.call_sites[0].arguments:
    print(arg.index, arg.raw_value, arg.source)  # source 取值为 "raw" 或 "hexrays_fallback"
```

这个选项永远是按需开启的，并且绝不会覆盖原始引擎已经成功解析出的值——`arg.source` 会明确告诉你每个值究竟是哪个引擎产出的，因此来自 Hex-Rays 的结果永远不会被悄悄混入、变得与原始结果无法区分。如果 Hex-Rays 未被授权或不可用，这个开关就是一个空操作（会记录日志，但不会报错），框架仍然可以仅凭原始引擎正常工作。关于为什么这是一个可选项而不是默认行为，见
[`architecture.md` 第 10 节](architecture.md#10-hex-rays-optional-never-primary-adaptershexrays_backendpy)。另外需要注意，目前 Hex-Rays 交叉验证只覆盖调用点提取（3.1），尚不覆盖函数内部正向解析（3.6 / 3.3）。

## 3.10 调整性能与解析预算

```python
extractor = ParamExtractor(
    max_steps=200,     # 反向解析器每次查询的指令步数预算
    max_blocks=64,      # 反向解析器每次查询的基本块数量预算
    cache_size=4096,     # 指令/交叉引用缓存大小（LRU），在同一个 extractor 的所有调用间共享
)
```

如果在一些规模合理但偏大的函数上遇到了 `Unknown(BUDGET_EXCEEDED)`，可以调高 `max_steps`/`max_blocks`；如果需要在超大二进制文件上获得更紧的最坏情况延迟，则可以调低它们。建议在多次 `extract_calls`/`resolve_argument_at` 调用之间复用同一个 `ParamExtractor`，而不是每次都重新构造一个,这样才能从 `cache_size` 中获益。

## 3.11 读懂并诊断一个 `Unknown` 结果

```python
if not arg.raw_value.is_known:
    print(arg.raw_value.reason, arg.raw_value.detail)
```

| `UnknownReason` | 含义 | 该怎么办 |
|---|---|---|
| `NO_DEFINITION_FOUND` | 一直回溯到函数入口（或正向分析的起点）都没有找到写入该位置的指令；或者回溯过程中跨越了一条 `call`，而被追踪的是调用者保存（volatile）寄存器，被调用方可以随意破坏它。 | 通常意味着这个值确实来自更上层的调用链，或者函数依赖调用者已经预先设置好的寄存器——在很多情况下这是符合预期的。若 `detail` 中提到了某条 call，说明该值是在这条调用之前写入某个 volatile 寄存器的，并不是被调用方返回后的实际内容。 |
| `DIVERGENT_PATHS` / `DIVERGENT_SYMBOLIC` | 两条控制流路径上的值互相矛盾。 | 这不是 bug——框架拒绝猜测。可以考虑改用 `resolve_argument_at`，把 `target_ea` 定在你关心的那一条具体路径上。 |
| `BUDGET_EXCEEDED` | 触发了步数/基本块数量上限。 | 调高 `max_steps`/`max_blocks`（见 §3.10）。 |
| `UNSUPPORTED_INSTRUCTION` | 没有任何 `Locator` 认得这条指令是一个"定义点"。 | 添加一个——见 §3.7。 |
| `UNSUPPORTED_OPERAND_SHAPE` | 某个定位器匹配上了助记符，但操作数的具体组合不匹配；某个参数槽位根本无法被解析为寄存器/偏移量；操作数带变址（`[base+index*scale]`）或是 `fs:`/`gs:` 段相对寻址，因而不对应唯一的静态地址；某次写入只覆盖了被追踪寄存器的一部分（对 `eax` 追踪时遇到 `mov al, 5`）；或者某个带变址的写入可能与被查询的位置重叠。 | 先看 `detail`，它会给出具体指令与具体原因。最常见的仍是调用约定不匹配，先检查 `convention`/`num_args`；否则需要扩展相应的定位器。 |
| `MEMORY_READ_FAILED` | 计算出的地址在 IDB 中没有数据。 | 对于没有本地写入定义的栈/堆地址,或者确实未映射的区域，这是预期行为。 |
| `INDIRECT_CONTROL_FLOW` | 预留给间接调用/跳转导致静态确定性被打破的情形。 | 仅供参考。 |
| `LOOP_NON_CONVERGENT` | 一个被正向跟踪的值在循环的多次迭代中持续变化，未能收敛。 | 说明该值在那个位置确实不是一个单一常量。 |
| `ADAPTER_ERROR` / `INTERNAL_ERROR` | 底层 IDA 调用失败，或者在某个安全边界处捕获到了一个意外的内部异常。 | 检查 IDA 自身对该地址的分析结果；如果看起来像是框架本身的缺陷，请提交 issue。 |
| `MUTATED_MEMORY_CONTENT` | 相对于某个被跟踪指针的内存被以非常量下标写入过（预留给未来更细粒度的正向诊断；目前这种情况通过 `MutatedRegion` 表达，而不是 `Unknown`）。 | 见 §3.6。 |

---

## 4. 逐模块参考

绝大多数用户只需要用到 `api`、`conventions`、`typespec`、`postproc` 和 `config`。其余部分（`core`、`locators`、`adapters`）在你需要扩展框架或调试其行为时才会用到。

### `api` —— 你实际调用的部分

- **`api.facade.ParamExtractor`** —— 每次分析会话构造一个实例。`extract_calls(...)`（对应 3.1）和 `resolve_argument_at(...)`（对应 3.3）是两个入口方法；`registry`（一个 `LocatorRegistry`）和 `port`（当前生效的 `IdaPort`）是供扩展/内省使用的公开属性。
- **`api.results`** —— `CallSiteResult`（一个调用点：`.call_ea`、`.func_ea`、`.arguments`、`.argument(index)`）、`ArgumentResult`（一个参数：`.index`、`.raw_value`、`.processed_value`、`.label`、`.source`、`.is_known`）、`ExtractionReport`（`.func_ea`、`.call_sites`、`.call_count`）。

### `core` —— 分析引擎本体（这个包里任何文件都不导入 `ida_*`）

- **`core.values`** —— 值类型体系（见第 2 节）。
- **`core.diagnostics`** —— `UnknownReason`（见 §3.11）。
- **`core.insn_model`** —— `Instruction`/`Operand`，每个 `Locator` 所使用的、已解码指令的规范化表示。
- **`core.insn_cache`** —— `InstructionCache`，对解码结果和交叉引用查询的 LRU 缓存。
- **`core.cfg_model`** —— `CfgModel`/`build_cfg`，可查询的控制流图封装。
- **`core.engine_backward`** —— `BackwardResolver`，支撑 3.1 的引擎。只有在高级用法中才需要直接接触它（例如自己调用 `resolve_register`/`resolve_memory`/`resolve_at_instruction`/`collect_push_sequence`，而不是通过 `ParamExtractor`）。
- **`core.engine_forward`** —— `ForwardSymbolicEngine`，支撑 3.3 的引擎（见 §3.6）。
- **`core.merge`** —— `join`/`join_all`，控制流合并规则。
- **`core.state`** —— `AbstractState`，正向引擎为每个跟踪位置维护的值快照。

### `locators` —— 扩展机制

- **`locators.base`** —— `Locator`（接口）、`LocatorRegistry`、`ResolutionContext`（`extract()` 接收到的上下文对象）、`default_registry()`（构建一个包含全部内置定位器的注册表）。
- **`locators.register_locators`** —— `mov reg,reg`/`mov reg,imm`/`lea reg,[global]`/`xchg`/`cmov`。
- **`locators.arithmetic_locators`** —— `lea reg,[base+disp]`/`add`、`sub reg,imm`（常量折叠，反向与正向均支持）。
- **`locators.memory_locators`** —— `mov reg,[mem]` 中能确定唯一静态地址的各种寻址形态（全局变量、`[reg+off]`）。带变址的 `[base+index*scale]` 与 `fs:`/`gs:` 段相对操作数会解析为 `Unknown(UNSUPPORTED_OPERAND_SHAPE)`：前者对应的是一族地址而非单个单元，后者的段基址在数据库中无从得知。
- **`locators.immediate_locators`** —— `mov [mem],imm`。
- **`locators.stack_locators`** —— `push`（任意操作数形态）、`mov [mem],reg`。
- **`locators.call_return_locators`** —— 前一次调用的返回寄存器被用作参数。
- **`locators.extension_points`** —— §3.7 中的完整示例。

### `conventions` —— 参数存放在哪里

- **`conventions.base`** —— `ArgSlot`、`SlotKind`、`CallingConvention`（接口）。
- **`conventions.templates`** —— `CDECL`、`STDCALL`、`FASTCALL`、`THISCALL`、`MS_X64`、`SYSV_X64`、`by_name(name)`。
- **`conventions.inference`** —— `infer(func_ea, port)`、`PrototypeConvention`。
- **`conventions.custom_builder`** —— `ConventionBuilder`（见 §3.3）。

### `postproc` / `typespec` —— 把一个值变成你真正想要的东西

- **`postproc.base`** —— `PostProcessor`（接口）、`PostProcessorChain`。
- **`postproc.builtins`** —— `CStringDeref`、`WideStringDeref`、`HexFormat`、`IntCast`、`StructFieldDeref`。
- **`postproc.registry`** —— `register_postprocessor(name, factory)`、`create(name, **kwargs)`（见 §3.5、§3.8）。
- **`typespec.argtype`** —— `ArgTypeSpec`（见 §3.4）。

### `config` —— 声明式配置

- **`config.schema`** —— `build_from_config(config: dict)`（见 §3.8）。

### `adapters` —— IDA 边界（只有在扩展 IDA 支持本身时才需要接触）

- **`adapters.ida_port.IdaPort`** —— 上层所有代码所依赖的接口。
- **`adapters.ida_port_impl.IdaPortImpl`** —— 真实实现；这是 `ParamExtractor()` 在 IDA 内部默认构建出的对象。
- **`adapters.fake_port.FakeIdaPort`** —— 供测试使用的内存态实现（见第 5 节）——手动构造指令/内存/函数,完全不需要 IDA。
- **`adapters.hexrays_backend`** —— `HexraysBackend`、`available()`（见 §3.9）。

---

## 5. 为你自己的扩展编写测试

自定义的 `Locator`、`CallingConvention` 或 `PostProcessor` 都是纯 Python 代码，可以借助
`adapters.fake_port.FakeIdaPort` 在没有 IDA 的情况下进行单元测试：

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
        operand_read=(False,),   # CF_USE 位：读改写操作数才置 True
    )
)
port.set_function(0x401000, 0x401100, blocks=(BasicBlockInfo(0x401000, 0x401100, (), ()),))

extractor = ParamExtractor(port=port)
extractor.registry.register(MyLocator())
# ... 调用 extractor.extract_calls / resolve_argument_at 并对结果做断言
```

可以参考 `tests/unit/conftest.py` 中提供的一些小型辅助构造函数（`reg`、`imm`、`mem_direct`、`mem_displ`、`insn`），它们能让构造测试用的指令序列不那么繁琐；也可以参考
`tests/unit/locators/test_extension_points.py`，那里有一个完整的"注册前/注册后"对比示例。

## 6. 常见问题 / 故障排查

**"`ConventionError: num_args must be specified...`"** —— 你使用了一个基于模板的调用约定（或者根本没传 `convention`，而 IDA 又没有识别出原型），却没有提供 `num_args`。请显式提供它。

**所有参数都返回 `Unknown(NO_DEFINITION_FOUND)`** —— 请确认 `func_ea` 确实是你想分析其**调用点**的那个函数（而不是调用方本身），并确认 `convention`/`num_args` 与实际情况相符；如果某个槽位的寄存器/偏移量指定错了，解析过程会在无关代码中一直回溯却始终一无所获。

**我不在 IDA 里，只是想先试验一下** —— 除了 `ParamExtractor()` 默认构建适配器这一步之外，其余一切在 IDA 之外都能正常工作；显式传入 `port=FakeIdaPort(...)` 即可（见第 5 节）。

**可以从无界面 / idalib 脚本中调用吗？** —— 可以；完整示例见 `tests/integration/conftest.py`，其中展示了 `idapro.open_database(...)` 与 `ParamExtractor()` 的配合使用方式。

## 7. 运行测试套件

```sh
pytest tests/unit                          # 不需要安装 IDA
pytest tests/integration -m requires_ida   # 需要本地已安装 IDA Pro 及 idalib
```
