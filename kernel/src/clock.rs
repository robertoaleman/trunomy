// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Reloj logico del kernel (ticks monotonos).
//!
//! Lo avanza el temporizador (PIT via PIC, ver `interrupts.rs`) llamando a `advance`. Las capabilities con vencimiento comparan contra `now()`; las pruebas
//! de vencimiento usan `lookup_at` con un `now` explicito para ser deterministas y no
//! depender de este reloj global.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// Ticks por segundo (definido en trunomy-abi para que el userland convierta igual).
pub const TICK_HZ: u64 = trunomy_abi::TICK_HZ;

pub const fn ticks_to_ms(ticks: u64) -> u64 {
    ticks.saturating_mul(1000) / TICK_HZ
}

/// Redondea hacia arriba: un plazo nunca se acorta.
pub const fn ms_to_ticks(ms: u64) -> u64 {
    ms.saturating_mul(TICK_HZ).saturating_add(999) / 1000
}

static TICKS: AtomicU64 = AtomicU64::new(0);

/// Ticks transcurridos desde el arranque.
pub fn now() -> u64 {
    TICKS.load(Ordering::Acquire)
}

/// Avanza el reloj. Solo debe llamarlo el manejador del temporizador.
pub fn advance(ticks: u64) -> u64 {
    TICKS
        .fetch_add(ticks, Ordering::AcqRel)
        .saturating_add(ticks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_never_goes_backwards() {
        let before = now();
        let after = advance(1);
        assert!(after > before);
        assert!(now() >= after);
    }

    #[test]
    fn tick_conversions_round_the_safe_way() {
        assert_eq!(ticks_to_ms(100), 1000);
        assert_eq!(ticks_to_ms(1), 10);
        assert_eq!(ms_to_ticks(1000), 100);
        assert_eq!(ms_to_ticks(1), 1); // nunca 0: un plazo no se acorta
        assert_eq!(ms_to_ticks(11), 2);
        assert_eq!(ticks_to_ms(u64::MAX), u64::MAX / TICK_HZ);
    }
}
