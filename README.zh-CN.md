<p align="right"><a href="README.md">English</a></p>

# idanalysister

`idanalysister` 是一个运行在 IDA Pro（IDAPython）环境中的声明式、接口化 Python 框架，用来自动化逆向分析中两类最重复、最耗时的工作：**定位某个函数的所有调用点并提取调用者实际传入的参数值**，以及**求出某个参数在函数体内某一具体指令位置处已经变成了什么值**（例如经过一段解密循环之后）。框架严格只使用 IDA 公开的 `ida_*` API，代码被拆分为一组职责单一、可独立扩展的小组件，并且被设计为**永不崩溃**——任何无法静态确定的值都会以一个带有明确原因的"未知"结果返回，而不是猜测,也不会抛出未处理的异常。

完整设计说明见 [`document/architecture.md`](document/architecture.md)（英文），逐场景使用指南见
[`document/user_manual.md`](document/user_manual.md)（英文）/
[`document/user_manual.zh-CN.md`](document/user_manual.zh-CN.md)（中文）。

## 这个项目解决了什么问题

逆向一份软件——尤其是恶意样本——几乎总是会反复遇到同一类问题：*"调用者在这个调用点给函数的第 N 个参数传了什么值？"* 或者 *"这个参数的值执行到某一点时已经变成了什么？"* 手工回答这个问题通常意味着：

- 从每一个调用点开始，手动往回阅读反汇编代码，追踪寄存器赋值、`push` 入栈、内存解引用等一连串数据流。
- 每次都要重新判断调用约定（是 cdecl 吗？还是 fastcall？IDA 自动识别的结果是否可信？）。
- 几乎每个样本都要重新写一个一次性的 IDAPython 脚本，因为参数可能是立即数、全局变量、栈变量、通过指针访问的结构体字段，也可能是前一次调用的返回值——而编译器往往在同一个函数里混用这些形式。
- 手动把指针解引用成字符串、格式化整数，或者在脚本里现写一段一次性的解密代码。
- 当问题从"调用点的值是什么"变成"执行到函数内部某一点、也就是解密完成、即将调用某函数之前，这个值变成了什么"时，还要再重复一遍上述全部工作，而且做法还不太一样。

`idanalysister` 把这件事从**"重新写一个脚本"**变成**"描述你想要什么"**：指定一个函数，告诉它调用约定（或者让它自动推断），可选地声明每个参数的类型，然后直接拿到已经完全解析好的结果——无论参数是寄存器、立即数、需要解引用的全局变量、栈槽位、通过指针访问的结构体字段、前一次调用的返回值，还是循环修改了指向内容之后依然存活的指针本身，调用方式都是同一套声明式接口。

## 核心能力

- **调用点参数提取**，覆盖需求文档中列出的每一种 x86/x86-64 参数传递形式：寄存器直接传递、立即数直接传递、内存间接传递（永远解引用到真实值，而不是仅返回地址）、`push` 序列传参（正确处理从右到左的顺序）、通过 `mov` 写栈传参、寄存器间接寻址/结构体字段访问、全局变量访问，以及"前一次调用的返回值被用作参数"这种跨调用的数据流；`xchg`、`cmov`、`movsx`、`movzx`、`lea`、`add`、`sub` 等形式开箱即支持，其他任何形式都可以在不修改核心代码的前提下自行添加。
- **三种方式处理调用约定**：内置模板（cdecl、stdcall、fastcall、thiscall、Microsoft x64、System V x64）、从 IDA 已识别的函数原型自动推断,或者用一个链式构建器描述任意自定义/非标准调用约定。
- **带类型、带后处理的输出**：声明"第 1 个参数是一个 C 字符串"、"第 2 个参数是一个以十六进制显示的整数"，或者绑定你自己写的后处理器（解密例程、结构体字段读取器,或任何其他逻辑）到指定的参数序号。
- **函数内部的正向值解析（3.3）**：给定一个函数、一个参数序号和函数体内某条目标指令地址，得到该参数**在这一点**的值——典型场景是一个指针参数在经过解密循环后指针本身没有变化，即便它所指向的内容已经被修改。
- **诚实的"不知道"**：任何无法解析的值都是一个带有具体、可检查原因的 `Unknown` 类型（预算耗尽、控制流路径分叉不一致、指令不受支持、内存读取失败……)——框架不会编造数值,公开 API 也绝不会抛出未处理的异常。
- **可选的 Hex-Rays 交叉验证**：如果本地有已授权的反编译器，可以将其作为原始引擎判定为"未知"时的次要兜底来源——默认关闭、按需开启，且每一个结果都会标注是哪个引擎产出的。

## 项目结构与模块职责

```
src/idanalysister/
  api/            大多数用户直接接触的公开入口
  core/           分析引擎本体——这个包里的任何文件都不导入 ida_*
  locators/       每种指令形式一个小文件——框架的扩展点
  conventions/    调用约定模板、自动推断，以及自定义构建器
  postproc/       后处理器（字符串/十六进制/整数/结构体字段提取）及名称注册表
  typespec/       把一条后处理链绑定到某个参数序号
  config/         从一个纯 dict（用于声明式/JSON 配置）构建以上所有对象
  adapters/       全项目中唯一允许出现 ida_* 导入的地方
```

| 模块 | 职责 |
|---|---|
| `api.facade` | `ParamExtractor`——组合根,也是你实际构造并调用的主类。持有一个适配器、一个指令缓存、一个定位器注册表，并负责编排每一次提取/解析请求。 |
| `api.results` | 返回给你的结果类型：`CallSiteResult`、`ArgumentResult`（原始值、后处理后的值、标签、以及由哪个引擎产出）、`ExtractionReport`。 |
| `core.values` | 所有结果所使用的值类型体系：`Concrete`、`MemoryRef`、`Symbolic`、`MutatedRegion`、`Unknown`。 |
| `core.diagnostics` | `UnknownReason`——一个值为何无法解析的、可枚举、可检查的原因列表。 |
| `core.insn_model` | 由 IDA 解码结果一次性构建出的、与具体架构无关的规范化指令/操作数表示。 |
| `core.insn_cache` | 在一次会话生命周期内缓存指令解码和交叉引用查询结果（用于满足"单次提取 <100ms"的性能要求）。 |
| `core.cfg_model` | 供两个解析引擎共用的、可查询的控制流图封装。 |
| `core.engine_backward` | 支撑调用点参数提取的反向定义-使用（def-use）解析器，驱动上面列出的每一种参数形式。 |
| `core.engine_forward` | 支撑函数内部值解析的、能感知循环的正向符号传播引擎。 |
| `core.merge` | "绝不猜测"这条规则的具体实现：两条控制流路径的值该如何合并（一致则保留，不一致则归为 `Unknown`）。 |
| `core.state` | 正向引擎在遍历函数时,针对每个寄存器/每个栈槽位所维护的状态快照。 |
| `locators.base` | `Locator` 接口与按会话隔离的 `LocatorRegistry`——整个框架的扩展机制。 |
| `locators.register_locators` / `.memory_locators` / `.immediate_locators` / `.stack_locators` / `.arithmetic_locators` / `.call_return_locators` | 内置的各类指令形式处理器,每个文件对应一个家族。 |
| `locators.extension_points` | 一个完整、可直接运行的示例，演示如何自行添加一种新的指令形式。 |
| `conventions.templates` | 内置调用约定常量：`CDECL`、`STDCALL`、`FASTCALL`、`THISCALL`、`MS_X64`、`SYSV_X64`。 |
| `conventions.inference` | 从 IDA 已识别的函数原型自动构建调用约定。 |
| `conventions.custom_builder` | `ConventionBuilder`——以链式声明方式描述任意非标准调用约定的 API。 |
| `postproc.base` / `.builtins` / `.registry` | 后处理器接口、内置后处理器（C 字符串、宽字符串、十六进制、整数转换、结构体字段读取），以及供自定义后处理器使用的按名称注册表。 |
| `typespec.argtype` | `ArgTypeSpec`——"第 N 个参数是这种类型/需要这样后处理"，即你实际传入的对象。 |
| `config.schema` | 把一个纯 `dict`（例如从 JSON/YAML 加载而来）转换为调用约定 + 参数类型配置。 |
| `adapters.ida_port` | 描述框架所需全部 IDA 能力的接口——`adapters/` 之外的任何代码都不会直接导入 `ida_*`。 |
| `adapters.ida_port_impl` | 基于 `ida_ua`、`idautils`、`ida_gdl`、`ida_bytes`、`ida_funcs`、`ida_frame`、`ida_typeinf`、`ida_nalt`、`ida_idp` 的真实实现。 |
| `adapters.fake_port` | 测试套件使用的内存态替身实现，使分析核心可以在没有真实 IDA 实例的情况下被测试。 |
| `adapters.hexrays_backend` | 可选的、默认关闭的 Hex-Rays 微码交叉验证后端。 |

## 安装

```sh
cd IDAnalysister
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

然后在 IDA 内部（或由 `idalib` 驱动的脚本中）：

```python
import sys
sys.path.insert(0, "/path/to/IDAnalysister/src")

from idanalysister import ParamExtractor, CDECL

extractor = ParamExtractor()
report = extractor.extract_calls(func_ea=0x00401000, convention=CDECL, num_args=2)
for site in report.call_sites:
    print(hex(site.call_ea), [a.raw_value for a in site.arguments])
```

关于每个模块、每种使用场景的完整说明（自定义调用约定、带类型/后处理的输出、函数内部值解析、通过新增指令形式进行扩展、声明式配置、可选的 Hex-Rays 兜底机制等），请参阅
[`document/user_manual.zh-CN.md`](document/user_manual.zh-CN.md)。

## 运行测试

```sh
pytest tests/unit                          # 不需要安装 IDA
pytest tests/integration -m requires_ida   # 需要本地已安装 IDA Pro 及 idalib
```

`tests/unit` 针对一个内存态的伪 IDA 适配器测试整个分析核心。`tests/integration` 则通过一次真实的无界面 IDA 分析会话，针对一个手写的小型 NASM 二进制文件测试真正的适配器实现。

## 环境要求

- IDA Pro ≥ 9.3
- Python ≥ 3.13（IDAPython）
- 仅使用 IDA 公开的 `ida_*` 模块——不使用任何私有或未公开的接口
