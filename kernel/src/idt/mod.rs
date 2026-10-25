// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// module: kernel/src/idt/mod.rs

pub mod entries;
pub mod handlers;

use entries::{IdtEntry, IdtPointer};

static mut IDT: [IdtEntry; 256] = [IdtEntry::missing(); 256];

pub fn init() {
    unsafe {
        // Convertir primero a *const () y luego a u64
        IDT[8].set_handler_ist(handlers::double_fault_handler as *const () as u64, 1);
        // Excepciones de CPU: un fallo en Ring 3 mata solo al proceso (faults.rs, I-33).
        #[cfg(not(test))]
        for (vector, addr) in crate::faults::stub_table() {
            IDT[vector].set_handler(addr);
        }

        #[cfg(not(test))]
        {
            let (timer, spur7, spur15) = crate::interrupts::handler_addrs();
            IDT[crate::interrupts::VECTOR_TIMER].set_handler(timer);
            IDT[crate::interrupts::VECTOR_SERIAL].set_handler(crate::interrupts::serial_handler_addr());
            IDT[crate::interrupts::VECTOR_SPURIOUS_MASTER].set_handler(spur7);
            IDT[crate::interrupts::VECTOR_SPURIOUS_SLAVE].set_handler(spur15);
        }

        let idt_ptr = IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            // Usar &raw const en lugar de as_ptr()
            base: &raw const IDT as *const _ as u64,
        };
        core::arch::asm!("lidt [{}]", in(reg) &idt_ptr, options(readonly, nostack, preserves_flags));
    }
}
