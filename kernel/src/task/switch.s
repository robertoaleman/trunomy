/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Trunomy OS - capability-based microkernel for isolating AI agents
 * Copyright (C) 2026 Roberto C. Aleman F.
 * https://github.com/robertoaleman/trunomy
 */

/* kernel/src/task/switch.s */

.global switch_to
.type switch_to, @function

/*
 * Firma C:
 * extern "C" fn switch_to(prev_ctx: *mut CpuContext, next_ctx: *const CpuContext, next_cr3: u64)
 *
 * Registros de entrada (System V ABI):
 *   RDI = prev_ctx (*mut CpuContext)
 *   RSI = next_ctx (*const CpuContext)
 *   RDX = next_cr3 (u64)
 */
switch_to:
    /* 1. Guardar contexto del proceso saliente (prev_ctx) */
    mov [rdi + 0x00], r15
    mov [rdi + 0x08], r14
    mov [rdi + 0x10], r13
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], rbx
    mov [rdi + 0x28], rbp

    /* Guardar RSP (pila actual) */
    mov [rdi + 0x30], rsp

    /* Guardar RIP (la dirección del caller está en la cima del stack) */
    mov rax, [rsp]
    mov [rdi + 0x38], rax

    /* Guardar RFLAGS */
    pushfq
    pop rax
    mov [rdi + 0x40], rax

    /* 2. Cambiar de Espacio de Direcciones (PAGINACIÓN / CR3) */
    mov rax, cr3
    cmp rax, rdx
    je .skip_cr3_flush      /* Evitar invalidación innecesaria de TLB si es el mismo CR3 */
    mov cr3, rdx
.skip_cr3_flush:

    /* 3. Restaurar contexto del proceso entrante (next_ctx) */
    mov r15, [rsi + 0x00]
    mov r14, [rsi + 0x08]
    mov r13, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov rbx, [rsi + 0x20]
    mov rbp, [rsi + 0x28]

    /* Restaurar RSP */
    mov rsp, [rsi + 0x30]

    /* Restaurar RFLAGS */
    mov rax, [rsi + 0x40]
    push rax
    popfq

    /* Cargar la dirección RIP de retorno */
    mov rax, [rsi + 0x38]
    mov [rsp], rax

    /* 4. Saltar a la nueva tarea */
    ret