# IDA Pro Malware Parameter Extraction and Intra-Function Value Resolution Framework — Requirements Specification

## 1. Project Objective
Build a reusable Python package that runs inside IDA Pro to eliminate the repetitive pain of writing parameter extraction scripts during reverse engineering. The package must:
- Automatically locate all call sites of any given function and extract the actual argument values passed at each call (i.e., the concrete data prepared by the caller).
- Cover **every** instruction form used to pass arguments on x86 / x86-64, without requiring separate coding for each form.
- Support forward tracking of argument values inside a function, yielding the result after the argument has been operated on or decrypted at a given point within the function body.
- Allow users to adapt to different calling conventions and argument-passing patterns through declarative configuration (selecting templates, combining components) rather than writing new code.
- Provide a user-friendly way to specify the type of a particular argument (e.g., “this is a string pointer”, “this is an integer”), upon which the framework automatically performs further resolution.

## 2. Environment and Fundamental Constraints
- **IDA Pro Version**: ≥ 9.3
- **Python Version**: ≥ 3.13 (running inside IDA’s embedded IDAPython)
- **Allowed APIs**: Only IDA’s official, public `ida_*` modules; any use of non-public, private, or undocumented interfaces is prohibited.
- **Project Structure**: Source code under `src`, documentation under `document`; managed with Git, excluding virtual environments, bytecode, IDE configurations, and other irrelevant files; a dedicated Python virtual environment must be created inside the project.
- **Code Quality**: Interface-based, modular design; each module has clear, decoupled responsibilities; coding style must be rigorous and standardized; high extensibility.
- **Stability**: Any value that cannot be statically determined must return `None` or be explicitly marked as unknown; the framework must not crash or throw unhandled exceptions due to failure in extracting an individual argument.

## 3. Detailed Functional Requirements

### 3.1 Call-Site Argument Extraction
- **Input**: The starting address of a function in the IDB (`func_ea`).
- **Output**: All instruction addresses that directly call this function (`call_ea`), together with **the actual value of each argument** at each call.
- **All argument-passing forms that must be covered** (each must resolve the final value):
  1. **Register direct passing**  
     e.g., `mov ecx, value`; `push ebx`, etc.  
     Must trace back the assignments of that register to obtain an immediate, a memory address, or the value of another register.
  2. **Immediate direct passing**  
     e.g., `push 0x1234`; `mov [esp], 0x5678`.  
     Directly extract the immediate.
  3. **Memory indirect passing (extremely important)**  
     e.g., `mov eax, dword_403000`; `push dword ptr [ebp-4]`; `mov rcx, qword ptr [rsp+0x20]`.  
     Requirement: **Must automatically dereference**, i.e., read the actual value stored at that memory address (for example, if `dword_403000` holds the value `0xABCDEF`, then extract `0xABCDEF`), rather than merely returning the address `0x403000`.  
     If the memory content is another pointer (e.g., the address of a string), retain that pointer value for further string resolution by post-processors.
  4. **Stack passing – push sequence**  
     Multiple `push` instructions that push arguments in order (e.g., cdecl).  
     Must correctly handle argument order (right-to-left) and resolve the real value for each argument (including dereferences).
  5. **Stack passing – mov writes**  
     e.g., `sub esp, 0x10` followed by `mov [esp+0x4], eax`.  
     Recognize stack writes and resolve the source operand.
  6. **Register indirect addressing**  
     e.g., `mov eax, pStruct`; `mov [eax+0x10], 0x123`; then `call`.  
     First resolve the base register, then compute the value at `[base + offset]`.
  7. **Global variable / TLS passing**  
     e.g., `mov dword_40ABCD, param` … `call`; or `mov gs:[0x30], param` … `call`.  
     During extraction, read the current memory value at that global address or TLS offset.
  8. **Return value of a previous call as argument**  
     e.g., `call funcA` → `mov ebx, eax` → `push ebx` → `call funcB`.  
     Track the data flow of a register (e.g., `eax`) across calls.
  9. **Any other rare forms** (such as `xchg`, `cmov`, `movsx`, etc.) must be easily supportable through an extension mechanism without modifying the framework core.

- **Calling Convention Management**:
  - Provide built-in templates for common calling conventions (cdecl, stdcall, fastcall, MS x64, System V x64, etc.).
  - If IDA has already recognized a function prototype (`tinfo_t`), the framework should be able to automatically infer the calling convention and generate the corresponding argument extraction strategy.
  - Users may freely combine “argument locating strategies” to describe any custom calling convention.

### 3.2 Argument Type Specification and Post-Processing
- Allow users to **specify a type per argument index**, e.g., clearly indicating “the second argument is a string pointer”.
- The framework must provide a **post-processor mechanism** to perform secondary processing on the extracted raw values:
  - Built-in post-processors must at least include: converting a memory address to a C string, converting to a UTF-16 string, formatting an integer as hexadecimal, etc.
  - Users may add custom post-processors (e.g., applying a specific decryption routine to a buffer).
- Post-processors can be chained and are bound to argument indices.

### 3.3 Intra-Function Argument Value Resolution
- Given a function `func_ea`, an argument index `i`, and a target instruction address `target_ea` inside that function’s body, the framework must resolve the concrete value of **the i-th argument at the point of target_ea**.
- Typical scenario: the argument is a pointer to encrypted data; the function contains a decryption loop; after decryption finishes, before a certain `call` instruction, that argument should resolve to a pointer to the plaintext.
- Resolution method: starting from the function entry, forward-simulate execution, propagate the argument symbolically, and perform constant folding and simple arithmetic operations.
- If control flow is too complex to determine a unique value, return “unknown”.

## 4. Non-Functional Requirements
- **Performance**: Extraction of arguments for a single call site should be as fast as possible (target < 100 ms); internally, instruction decoding results and cross-reference results must be cached.
- **Extensibility**: Adding a new argument-passing form (e.g., `cmov` passing) should require only writing a new component and registering it, without modifying existing core modules.
- **Maintainability**: Modular code with a clear package structure (e.g., core engine, locators, convention templates, post-processors separated), with reasonable dependency directions.
- **User Friendliness**: Provide a concise API; most analysis tasks should be achievable by specifying a template name, argument count, and argument type annotations, without needing to read internal implementations.

## 5. Deliverables
- A Python package located under the `src` directory, which can be directly imported and used inside IDAPython.
- Under the `document` directory, architecture design notes and a user manual.
- A Git repository with a configured `.gitignore` that excludes virtual environments, cache files, etc.
