// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// module: kernel/src/idt/entries.rs

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct IdtEntry {
    pub pointer_low: u16,
    pub gdt_selector: u16,
    pub ist: u8,
    pub type_attr: u8,
    pub pointer_middle: u16,
    pub pointer_high: u32,
    pub reserved: u32,
}

impl IdtEntry {
    pub const fn missing() -> Self {
        Self {
            pointer_low: 0,
            gdt_selector: 0,
            ist: 0,
            type_attr: 0,
            pointer_middle: 0,
            pointer_high: 0,
            reserved: 0,
        }
    }

    pub fn set_handler(&mut self, handler_addr: u64) {
        self.set_handler_ist(handler_addr, 0);
    }

    /// Puerta de interrupcion (IF se limpia al entrar) con pila IST opcional (1..=7; 0 = ninguna).
    pub fn set_handler_ist(&mut self, handler_addr: u64, ist: u8) {
        self.pointer_low = handler_addr as u16;
        self.gdt_selector = 0x08; // Kernel Code Segment en nuestra GDT
        self.ist = ist & 0x7;
        self.type_attr = 0x8E;
        self.pointer_middle = (handler_addr >> 16) as u16;
        self.pointer_high = (handler_addr >> 32) as u32;
        self.reserved = 0;
    }
}

#[repr(C, packed)]
pub struct IdtPointer {
    pub limit: u16,
    pub base: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_encodes_address_selector_type_and_ist() {
        let mut e = IdtEntry::missing();
        e.set_handler_ist(0xFFFF_8000_1234_5678, 1);
        assert_eq!({ e.pointer_low }, 0x5678);
        assert_eq!({ e.pointer_middle }, 0x1234);
        assert_eq!({ e.pointer_high }, 0xFFFF_8000);
        assert_eq!({ e.gdt_selector }, 0x08);
        assert_eq!(e.type_attr, 0x8E); // presente, DPL 0 (ni int 0x80 desde Ring 3), puerta de interrupcion
        assert_eq!(e.ist, 1);
        assert_eq!({ e.reserved }, 0);
    }

    #[test]
    fn ist_field_never_exceeds_three_bits() {
        let mut e = IdtEntry::missing();
        e.set_handler_ist(0x1000, 0xFF);
        assert_eq!(e.ist, 7);
        e.set_handler(0x1000);
        assert_eq!(e.ist, 0);
    }
}
