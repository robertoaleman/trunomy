// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// I-16: todo bloque liberado del heap del kernel se pone a cero (zero_alloc.rs).
#[cfg(not(test))]
use linked_list_allocator::LockedHeap;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: crate::zero_alloc::ZeroOnFree<LockedHeap> = crate::zero_alloc::ZeroOnFree(LockedHeap::empty());

#[cfg(not(test))]
const HEAP_SIZE: usize = 100 * 1024;

#[cfg(not(test))]
static mut HEAP_MEM: [u8; HEAP_SIZE] = [0xFF; HEAP_SIZE];

#[cfg(not(test))]
pub fn init() {
    unsafe {
        ALLOCATOR.0.lock().init((&raw mut HEAP_MEM).cast::<u8>(), HEAP_SIZE);
    }
}

#[cfg(test)]
pub fn init() {}

/// (total, usado) del heap del kernel en bytes. En las pruebas de host no hay heap propio.
#[cfg(not(test))]
pub fn heap_stats() -> (u64, u64) {
    let heap = ALLOCATOR.0.lock();
    (heap.size() as u64, heap.used() as u64)
}

#[cfg(test)]
pub fn heap_stats() -> (u64, u64) {
    (0, 0)
}
