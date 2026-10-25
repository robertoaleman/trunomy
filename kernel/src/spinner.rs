// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Tarea de prueba de Ring 3 (parche 14): demuestra que dos tareas comparten la CPU.
//!
//! Es un trozo de codigo independiente de la posicion, incluido en la imagen del kernel (que
//! va firmada) y copiado a una pagina de usuario propia (`R-X`, nunca escribible). No tiene
//! ninguna capability: solo usa `ClockNow`, `ConsoleWrite` y `Yield`, que no la exigen.
//! Cada segundo (100 ticks) escribe un '.' por el serie.
//!
//! Registros: `r12` guarda el proximo plazo; `syscall` solo destruye rcx y r11.
//! Numeros de syscall (trunomy-abi): ConsoleWrite=0x01, Yield=0x40, ClockNow=0x42.

use crate::memory::ProcessPml4;

pub const CODE_VADDR: u64 = 0x4000_0000;
pub const STACK_PAGE: u64 = 0x7FFF_F000;
pub const STACK_TOP: u64 = STACK_PAGE + 0x1000;

core::arch::global_asm!(
    ".section .rodata.trunomy_spinner,\"a\"",
    ".global trunomy_spinner_start",
    ".global trunomy_spinner_end",
    "trunomy_spinner_start:",
    "xor r12d, r12d",
    "2:",
    "mov eax, 0x42",
    "syscall",
    "cmp rax, r12",
    "jb 3f",
    "lea r12, [rax + 100]",
    "mov eax, 0x01",
    "mov edi, 0x2E",
    "syscall",
    "3:",
    "mov eax, 0x40",
    "syscall",
    "jmp 2b",
    "trunomy_spinner_end:",
    ".text",
);

extern "C" {
    static trunomy_spinner_start: u8;
    static trunomy_spinner_end: u8;
}

/// Mapea el codigo (R-X) y una pagina de pila (RW-) del spinner en `pml4`. Devuelve el punto de
/// entrada y la cima de la pila.
pub unsafe fn load(pml4: &mut ProcessPml4) -> Result<(u64, u64), &'static str> {
    let start = (&raw const trunomy_spinner_start) as usize;
    let end = (&raw const trunomy_spinner_end) as usize;
    let len = end - start;
    if len == 0 || len > 4096 {
        return Err("spinner code out of range");
    }
    let code = crate::memory::BITMAP_ALLOCATOR.lock().allocate_frame().ok_or("out of memory for the spinner")?;
    core::ptr::write_bytes(code as *mut u8, 0, 4096);
    core::ptr::copy_nonoverlapping(start as *const u8, code as *mut u8, len);
    pml4.map_user_page(CODE_VADDR, code, false, true)?;

    let stack = crate::memory::BITMAP_ALLOCATOR.lock().allocate_frame().ok_or("out of memory for the spinner stack")?;
    core::ptr::write_bytes(stack as *mut u8, 0, 4096);
    pml4.map_user_page(STACK_PAGE, stack, true, false)?;
    Ok((CODE_VADDR, STACK_TOP))
}
