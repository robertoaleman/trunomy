// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Entrada de consola por interrupcion (parche 15, I-30).
//!
//! La IRQ4 del puerto serie COM1 vacia el FIFO de la UART hacia un buffer circular sin candados
//! (productor: la interrupcion; consumidor: la syscall `ConsoleRead`). Si no hay datos, la tarea
//! que lee se bloquea en el planificador y la IRQ4 la despierta; ya no se sondea el puerto.
//!
//! - El buffer es acotado (`RX_CAPACITY`); si se llena se descartan los bytes nuevos y se cuentan
//!   (`dropped`). Nunca se sobrescribe lo que aun no se ha leido.
//! - Un solo consumidor a la vez puede dormir esperando (`WAITER`); otra tarea que lea a la vez
//!   espera con `hlt` sin bloquearse, de modo que nadie se queda sin despertador.
//! - El despertar es doble: la IRQ4 usa `try_lock`, y el tick del timer lo repite si quedo
//!   algo pendiente, asi un candado ocupado retrasa el despertar pero no lo pierde.
//! - Interruptor: `CONSOLE_IRQ_ENABLED = false` deja el sondeo anterior.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// `false`: `ConsoleRead` sondea el puerto como antes (sin IRQ4 ni bloqueo).
pub const CONSOLE_IRQ_ENABLED: bool = true;
pub const RX_CAPACITY: usize = 256;

/// Cola circular de un productor y un consumidor, sin candados (segura para la interrupcion).
pub struct Spsc<const N: usize> {
    buf: UnsafeCell<[u8; N]>,
    head: AtomicUsize, // siguiente posicion a escribir (solo el productor)
    tail: AtomicUsize, // siguiente posicion a leer (solo el consumidor)
    dropped: AtomicUsize,
}

// Un productor y un consumidor: cada indice solo lo modifica uno de los dos.
unsafe impl<const N: usize> Sync for Spsc<N> {}

impl<const N: usize> Spsc<N> {
    pub const fn new() -> Self {
        Self {
            buf: UnsafeCell::new([0; N]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Productor. `false` (y cuenta) si esta llena: no se pisa lo no leido.
    pub fn push(&self, byte: u8) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let next = (head + 1) % N;
        if next == self.tail.load(Ordering::Acquire) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        unsafe { (*self.buf.get())[head] = byte };
        self.head.store(next, Ordering::Release);
        true
    }

    /// Consumidor.
    pub fn pop(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        let byte = unsafe { (*self.buf.get())[tail] };
        self.tail.store((tail + 1) % N, Ordering::Release);
        Some(byte)
    }

    pub fn is_empty(&self) -> bool {
        self.tail.load(Ordering::Acquire) == self.head.load(Ordering::Acquire)
    }

    pub fn len(&self) -> usize {
        (self.head.load(Ordering::Acquire) + N - self.tail.load(Ordering::Acquire)) % N
    }

    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Capacidad util: una posicion queda libre para distinguir lleno de vacio.
    pub const fn capacity(&self) -> usize {
        N - 1
    }
}

static RX: Spsc<RX_CAPACITY> = Spsc::new();
/// Pid de la tarea dormida esperando entrada (0 = ninguna).
static WAITER: AtomicU64 = AtomicU64::new(0);
static IRQ_DRIVEN: AtomicBool = AtomicBool::new(false);

/// Activa el modo por interrupcion (lo llama el arranque tras configurar PIC y UART).
pub fn set_irq_driven(on: bool) {
    IRQ_DRIVEN.store(on, Ordering::Release);
}

pub fn irq_driven() -> bool {
    IRQ_DRIVEN.load(Ordering::Acquire)
}

/// Desde la IRQ4: un byte recibido.
pub fn push_input(byte: u8) -> bool {
    RX.push(byte)
}

/// Desde la syscall: el siguiente byte, si hay.
pub fn pop_input() -> Option<u8> {
    RX.pop()
}

pub fn has_input() -> bool {
    !RX.is_empty()
}

pub fn dropped_input() -> usize {
    RX.dropped()
}

/// Registra a `pid` como el que duerme esperando entrada. `false` si ya hay otro (o pid 0).
pub fn register_waiter(pid: u64) -> bool {
    pid != 0 && WAITER.compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// Retira y devuelve el pid dormido, si lo hay. Solo uno de los llamantes lo obtiene.
pub fn take_waiter() -> Option<u64> {
    match WAITER.swap(0, Ordering::AcqRel) {
        0 => None,
        pid => Some(pid),
    }
}

pub fn has_waiter() -> bool {
    WAITER.load(Ordering::Acquire) != 0
}

/// Cancela el registro propio (la tarea decidio no dormir).
pub fn cancel_waiter(pid: u64) {
    let _ = WAITER.compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Acquire);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsc_is_fifo_and_reports_empty() {
        let q: Spsc<8> = Spsc::new();
        assert!(q.is_empty());
        assert_eq!(q.pop(), None);
        for b in b"hola" {
            assert!(q.push(*b));
        }
        assert_eq!(q.len(), 4);
        let got: alloc::vec::Vec<u8> = core::iter::from_fn(|| q.pop()).collect();
        assert_eq!(got, b"hola");
        assert!(q.is_empty());
    }

    #[test]
    fn spsc_never_overwrites_unread_data_when_full() {
        let q: Spsc<4> = Spsc::new();
        assert_eq!(q.capacity(), 3);
        assert!(q.push(1) && q.push(2) && q.push(3));
        assert!(!q.push(4), "llena: se descarta el nuevo");
        assert!(!q.push(5));
        assert_eq!(q.dropped(), 2);
        assert_eq!((q.pop(), q.pop(), q.pop(), q.pop()), (Some(1), Some(2), Some(3), None));
        // tras vaciar vuelve a aceptar
        assert!(q.push(9));
        assert_eq!(q.pop(), Some(9));
    }

    #[test]
    fn spsc_wraps_around_many_times() {
        let q: Spsc<5> = Spsc::new();
        for round in 0..1000u32 {
            let a = (round % 251) as u8;
            assert!(q.push(a));
            assert!(q.push(a.wrapping_add(1)));
            assert_eq!(q.pop(), Some(a));
            assert_eq!(q.pop(), Some(a.wrapping_add(1)));
        }
        assert!(q.is_empty());
        assert_eq!(q.dropped(), 0);
    }

    #[test]
    fn spsc_survives_a_concurrent_producer_and_consumer() {
        use std::sync::Arc;
        let q: Arc<Spsc<64>> = Arc::new(Spsc::new());
        let producer = {
            let q = q.clone();
            std::thread::spawn(move || {
                let mut sent = 0u32;
                while sent < 20_000 {
                    if q.push((sent % 256) as u8) {
                        sent += 1;
                    } else {
                        std::thread::yield_now();
                    }
                }
            })
        };
        let mut expected = 0u32;
        while expected < 20_000 {
            match q.pop() {
                Some(b) => {
                    assert_eq!(b, (expected % 256) as u8, "orden y contenido intactos");
                    expected += 1;
                }
                None => std::thread::yield_now(),
            }
        }
        producer.join().unwrap();
        assert!(q.is_empty());
    }

    #[test]
    fn only_one_waiter_and_only_one_waker_wins() {
        // Estado global: todo en un solo test para no pisarse con otros hilos de prueba.
        while take_waiter().is_some() {}
        assert!(!register_waiter(0), "pid 0 no es una tarea");
        assert!(register_waiter(7));
        assert!(has_waiter());
        assert!(!register_waiter(8), "ya hay un durmiente");
        assert_eq!(take_waiter(), Some(7));
        assert_eq!(take_waiter(), None, "el despertar se entrega una sola vez");
        assert!(!has_waiter());
        // cancelar solo afecta al propio registro
        assert!(register_waiter(5));
        cancel_waiter(6);
        assert!(has_waiter());
        cancel_waiter(5);
        assert!(!has_waiter());
    }
}
