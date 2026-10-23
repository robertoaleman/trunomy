// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Puertos de E/S de 8, 16 y 32 bits detras de un trait: la logica de PCI y de virtio se comprueba
//! en el host con un bus simulado, y solo `HwIo` toca el hardware (Ring 0).

pub trait Io {
    fn inb(&mut self, port: u16) -> u8;
    fn inw(&mut self, port: u16) -> u16;
    fn inl(&mut self, port: u16) -> u32;
    fn outb(&mut self, port: u16, value: u8);
    fn outw(&mut self, port: u16, value: u16);
    fn outl(&mut self, port: u16, value: u32);
}

/// Puertos reales. Solo se construye desde el arranque del kernel, nunca en las pruebas de host.
pub struct HwIo;

impl Io for HwIo {
    fn inb(&mut self, port: u16) -> u8 {
        let v: u8;
        unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
        v
    }
    fn inw(&mut self, port: u16) -> u16 {
        let v: u16;
        unsafe { core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack, preserves_flags)) };
        v
    }
    fn inl(&mut self, port: u16) -> u32 {
        let v: u32;
        unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags)) };
        v
    }
    fn outb(&mut self, port: u16, value: u8) {
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)) };
    }
    fn outw(&mut self, port: u16, value: u16) {
        unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)) };
    }
    fn outl(&mut self, port: u16, value: u32) {
        unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)) };
    }
}
