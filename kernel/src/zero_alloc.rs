// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Allocator global que pone a cero cada bloque al liberarlo (I-16).
//!
//! Cubre de una vez los payloads de objetos (sustituidos o borrados), las copias
//! temporales que el kernel hace de datos de usuario y cualquier otro buffer del heap.
//! `realloc` usa la implementacion por defecto (alloc + copia + dealloc), asi que el
//! bloque antiguo tambien se borra. Las escrituras son volatiles: el compilador no puede
//! eliminarlas por tratarse de memoria "que ya no se lee".

use core::alloc::{GlobalAlloc, Layout};

pub struct ZeroOnFree<A>(pub A);

#[inline]
unsafe fn wipe(ptr: *mut u8, len: usize) {
    for i in 0..len {
        core::ptr::write_volatile(ptr.add(i), 0);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for ZeroOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        wipe(ptr, layout.size());
        self.0.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.0.alloc_zeroed(layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::alloc::System;

    /// Allocator de prueba: antes de liberar de verdad, cuenta los bytes no nulos.
    struct Checker {
        frees: AtomicUsize,
        dirty_bytes: AtomicUsize,
    }

    unsafe impl GlobalAlloc for Checker {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            System.alloc(l)
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            let dirty = (0..l.size()).filter(|i| *p.add(*i) != 0).count();
            self.dirty_bytes.fetch_add(dirty, Ordering::SeqCst);
            self.frees.fetch_add(1, Ordering::SeqCst);
            System.dealloc(p, l)
        }
    }

    fn checker() -> ZeroOnFree<Checker> {
        ZeroOnFree(Checker { frees: AtomicUsize::new(0), dirty_bytes: AtomicUsize::new(0) })
    }

    #[test]
    fn freed_block_is_zero_when_it_reaches_the_inner_allocator() {
        let a = checker();
        let l = Layout::from_size_align(256, 8).unwrap();
        unsafe {
            let p = a.alloc(l);
            core::ptr::write_bytes(p, 0xAB, 256);
            a.dealloc(p, l);
        }
        assert_eq!(a.0.frees.load(Ordering::SeqCst), 1);
        assert_eq!(a.0.dirty_bytes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn realloc_wipes_the_old_block() {
        let a = checker();
        let l = Layout::from_size_align(16, 8).unwrap();
        unsafe {
            let p = a.alloc(l);
            core::ptr::write_bytes(p, 0xCD, 16);
            let q = a.realloc(p, l, 64);
            // el contenido se conserva en el bloque nuevo...
            assert!((0..16).all(|i| *q.add(i) == 0xCD));
            a.dealloc(q, Layout::from_size_align(64, 8).unwrap());
        }
        // ...y los dos bloques (el viejo y el nuevo) llegaron a cero al allocator interno.
        assert_eq!(a.0.frees.load(Ordering::SeqCst), 2);
        assert_eq!(a.0.dirty_bytes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn zero_sized_and_alloc_zeroed_paths_work() {
        let a = checker();
        let l = Layout::from_size_align(32, 8).unwrap();
        unsafe {
            let p = a.alloc_zeroed(l);
            assert!((0..32).all(|i| *p.add(i) == 0));
            a.dealloc(p, l);
        }
        assert_eq!(a.0.dirty_bytes.load(Ordering::SeqCst), 0);
    }
}
