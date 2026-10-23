// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Nucleo del arranque verificado (I-18, I-19), sin UEFI ni hardware: se prueba en el host.
//!
//! - [`sig`]: verificacion Ed25519 estricta, siempre y sin modos de bypass.
//! - [`rollback`]: version de seguridad firmada y contador anti-rollback del kernel (I-49).
//! - [`elf`] (feature `elf`): valida un ELF del kernel antes de copiar un solo byte y
//!   lo carga en una region acotada.
#![no_std]

extern crate alloc;

pub mod rollback;
pub mod sig;

#[cfg(feature = "elf")]
pub mod elf;
