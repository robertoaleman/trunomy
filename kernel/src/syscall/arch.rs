// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/syscall/arch.rs

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;

pub unsafe fn init_syscall_msrs(entry_fn: extern "C" fn()) {
    // 1. Activar el bit SCE (System Call Enable) en EFER MSR
    let mut efer = read_msr(IA32_EFER);
    efer |= 1; 
    write_msr(IA32_EFER, efer);

    // 2. Definir segmentos CS/SS para Anillo 0 (Kernel: 0x08) y Anillo 3 (User: 0x18/0x20)
    let star = ((0x08u64) << 32) | ((0x10u64 | 3) << 48);
    write_msr(IA32_STAR, star);

    // 3. Registrar el handler de entrada en LSTAR (RIP al presionar SYSCALL)
    write_msr(IA32_LSTAR, entry_fn as u64);

    // 4. Máscara de RFLAGS (limpiar IF/Interrupt Flag durante la llamada)
    write_msr(IA32_FMASK, 0x0200);
}

#[inline(always)]
unsafe fn read_msr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high);
    ((high as u64) << 32) | (low as u64)
}

#[inline(always)]
unsafe fn write_msr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    core::arch::asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high);
}