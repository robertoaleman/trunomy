// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! PIT 8254, canal 0: la fuente del tick del kernel.

#![allow(dead_code)]

use crate::pic::Ports;

/// Frecuencia del oscilador del PIT.
pub const PIT_HZ: u32 = 1_193_182;
const CH0_DATA: u16 = 0x40;
const COMMAND: u16 = 0x43;
/// Canal 0, acceso lo/hi, modo 2 (generador de frecuencia), binario.
const CMD_CH0_RATE_GEN: u8 = 0x34;

/// Divisor para `hz` (redondeado). La frecuencia se acota a lo que cabe en 16 bits (>= 19 Hz).
pub fn divisor_for(hz: u32) -> u16 {
    let hz = hz.clamp(19, PIT_HZ);
    ((PIT_HZ + hz / 2) / hz).clamp(1, 0xFFFF) as u16
}

/// Frecuencia real que produce un divisor (en milihertz, para no perder precision).
pub fn actual_millihz(divisor: u16) -> u64 {
    PIT_HZ as u64 * 1000 / divisor.max(1) as u64
}

pub fn program<P: Ports>(p: &mut P, hz: u32) -> u16 {
    let d = divisor_for(hz);
    p.outb(COMMAND, CMD_CH0_RATE_GEN);
    p.outb(CH0_DATA, d as u8);
    p.outb(CH0_DATA, (d >> 8) as u8);
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pic::tests::MockPorts;

    #[test]
    fn divisor_for_100_hz() {
        assert_eq!(divisor_for(100), 11932);
        let hz_x1000 = actual_millihz(11932);
        assert!((99_990..=100_010).contains(&hz_x1000), "{hz_x1000}");
    }

    #[test]
    fn divisor_is_clamped_to_what_the_hardware_accepts() {
        assert_eq!(divisor_for(0), divisor_for(19)); // suelo: 19 Hz
        assert_eq!(divisor_for(1), 62799);
        assert_eq!(divisor_for(u32::MAX), 1);
    }

    #[test]
    fn programming_sends_mode_then_low_then_high_byte() {
        let mut p = MockPorts::new();
        let d = program(&mut p, 100);
        assert_eq!(d, 11932);
        assert_eq!(p.writes, [(0x43, 0x34), (0x40, (11932u16 & 0xFF) as u8), (0x40, (11932u16 >> 8) as u8)]);
    }
}
