; Minimal x86 (32-bit) fixture binary for idanalysister's integration
; suite. Deliberately hand-written in NASM (not compiled from C) so the
; exact instruction forms exercised match requirement.md's own examples —
; a compiler could legally lower these differently. This binary is never
; executed; IDA only statically analyzes it.
;
; Build: nasm -f elf32 probe.asm -o probe.o && ld -m elf_i386 -o probe probe.o
; (also driven by tests/integration/conftest.py, which builds it on demand)

section .data
    global_val: dd 0x0ABCDEF0
    buffer:     dd 0x11111111, 0x22222222

section .text
global _start

target_func:
    ret

; requirement 3.1 forms #2 (immediate push) + #3 (memory-indirect, must
; dereference) + #4 (push sequence, right-to-left order)
caller_push_seq:
    mov eax, [global_val]
    push eax
    push 0x1234
    call target_func
    add esp, 8
    ret

; requirement 3.1 form #6: register indirect addressing — resolve the base
; register, write a field, then read it back through [base+offset].
caller_reg_indirect:
    mov eax, global_val
    mov dword [eax+0], 0x123
    mov ecx, [eax+0]
    push ecx
    call target_func
    add esp, 4
    ret

; requirement 3.1 form #8: prior call's return value used as an argument.
caller_return_chain:
    call target_func
    mov ebx, eax
    push ebx
    call target_func
    add esp, 4
    ret

; requirement 3.3: intra-function forward resolution — arg0 (ecx) is a
; buffer pointer; a 4-byte XOR "decryption" loop mutates *buffer* without
; ever reassigning ecx itself, then an alias (ebx) is taken before the
; final call. The pointer identity must resolve cleanly at that call.
decrypt_then_call:
    mov edx, 0
.loop:
    cmp edx, 4
    jge .after
    mov al, [ecx+edx]
    xor al, 0x5A
    mov [ecx+edx], al
    inc edx
    jmp .loop
.after:
    mov ebx, ecx
    push ecx
    call target_func
    add esp, 4
    ret

; Tail call via unconditional jmp (compiler-generated tail-call
; optimization / thunk pattern) instead of `call target; ret` — a genuine
; call site whose arguments were prepared by this function, but recorded
; in IDA's xref graph as a jump reference (fl_JN), not a call reference
; (fl_CN). code_refs_to must not silently drop it.
caller_tail_call:
    push 0x77
    jmp target_func

_start:
    call caller_push_seq
    call caller_reg_indirect
    call caller_return_chain
    mov ecx, buffer
    call decrypt_then_call
    call caller_tail_call
    mov eax, 1
    xor ebx, ebx
    int 0x80
