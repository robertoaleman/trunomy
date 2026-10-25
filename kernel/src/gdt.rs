// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// module: kernel/src/gdt.rs

use core::mem::size_of;

#[repr(C, packed)]
pub struct GdtPointer {
    pub limit: u16,
    pub base: u64,
}

#[repr(C, packed)]
pub struct Tss {
    reserved_1: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    reserved_2: u64,
    pub ist1: u64,
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    reserved_3: u64,
    reserved_4: u16,
    pub iomap_base: u16,
}

static mut TSS: Tss = Tss {
    reserved_1: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    reserved_2: 0,
    ist1: 0,
    ist2: 0,
    ist3: 0,
    ist4: 0,
    ist5: 0,
    ist6: 0,
    ist7: 0,
    reserved_3: 0,
    reserved_4: 0,
    iomap_base: size_of::<Tss>() as u16,
};

// GDT Entries:
// [0] 0x00: Null
// [1] 0x08: Kernel Code (64-bit, Ring 0)
// [2] 0x10: Kernel Data (Ring 0)
// [3] 0x18: User Data (Ring 3) - Corregido a 0x00CFF2000000FFFF
// [4] 0x20: User Code (64-bit, Ring 3)
// [5-6] 0x28: TSS
static mut GDT: [u64; 7] = [
    0,                  // 0x00: Null
    0x00AF9A000000FFFF, // 0x08: Kernel Code (Ring 0)
    0x00CF92000000FFFF, // 0x10: Kernel Data (Ring 0)
    0x00CFF2000000FFFF, // 0x18: User Data (Ring 3)
    0x00AFFA000000FFFF, // 0x20: User Code (Ring 3, L=1 / D=0)
    0,                  // 0x28: TSS Low
    0,                  // 0x30: TSS High
];

pub fn init() {
    unsafe {
        let tss_addr = &raw const TSS as *const _ as u64;

        GDT[5] = (size_of::<Tss>() as u64 - 1)
            | ((tss_addr & 0x00FF_FFFF) << 16)
            | (0x89 << 40)
            | (((tss_addr >> 24) & 0x0000_00FF) << 56);
        GDT[6] = tss_addr >> 32;

        let gdt_ptr = GdtPointer {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base: &raw const GDT as *const _ as u64,
        };

        core::arch::asm!("lgdt [{}]", in(reg) &gdt_ptr, options(readonly, nostack, preserves_flags));

        core::arch::asm!(
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            out("rax") _
        );

        core::arch::asm!("ltr ax", in("ax") 0x28u16);
    }
}

/// Pila a la que salta la CPU al entrar al kernel desde Ring 3 por una interrupcion.
/// Sin ella (rsp0 = 0) cualquier interrupcion en Ring 3 acaba en fallo triple.
pub fn set_rsp0(top: u64) {
    unsafe { core::ptr::addr_of_mut!(TSS.rsp0).write_unaligned(top) };
}

/// Pila de emergencia IST1 (doble fallo): funciona aunque la pila normal este corrupta.
pub fn set_ist1(top: u64) {
    unsafe { core::ptr::addr_of_mut!(TSS.ist1).write_unaligned(top) };
}
