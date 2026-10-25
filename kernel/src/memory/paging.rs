// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/memory/paging.rs

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const HUGE: u64 = 1 << 7;
    /// Bit disponible para el software: marca las tablas creadas por el kernel.
    pub const OWNED: u64 = 1 << 9;
    pub const NO_EXECUTE: u64 = 1 << 63;

    pub fn new(phys_addr: u64, flags: u64) -> Self {
        Self((phys_addr & 0x000F_FFFF_FFFF_F000) | flags)
    }

    pub fn is_present(&self) -> bool {
        (self.0 & Self::PRESENT) != 0
    }

    pub fn is_huge(&self) -> bool {
        (self.0 & Self::HUGE) != 0
    }

    pub fn is_owned(&self) -> bool {
        (self.0 & Self::OWNED) != 0
    }

    pub fn flags(&self) -> u64 {
        self.0 & !0x000F_FFFF_FFFF_F000
    }

    pub fn address(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl PageTable {
    #[cfg(test)]
    pub const fn empty() -> Self {
        Self {
            entries: [PageTableEntry(0); 512],
        }
    }

    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.0 = 0;
        }
    }
}
