// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Sesion de consola: tenants, actores y lectura de auditoria (solo el lider de la sesion).
//! Contrato: kernel/src/syscall/identity.rs. Para actuar como un actor se lanza un proceso
//! (`process::spawn`); ya no existe el cambio de identidad en el mismo proceso.

use crate::{decode, syscall4, Errno, SyscallNumber};
use trunomy_abi::audit::{Record, RECORD_SIZE};

pub fn tenant_create() -> Result<u64, Errno> {
    decode(unsafe { syscall4(SyscallNumber::TenantCreate.number(), 0, 0, 0, 0) })
}

/// Crea un actor (identidad) en `tenant`; devuelve su pid.
/// Con `ipc`, el actor recibe ademas las capabilities de enviar y recibir mensajes (I-43); con `net`, las de red (I-47).
pub fn actor_create(tenant: u64, ipc: bool, net: bool) -> Result<u64, Errno> {
    let flags = if ipc { trunomy_abi::actor::FLAG_IPC } else { 0 } | if net { trunomy_abi::actor::FLAG_NET } else { 0 };
    decode(unsafe { syscall4(SyscallNumber::ActorCreate.number(), tenant, flags, 0, 0) })
}

/// Corte de emergencia de `tenant` (solo el lider; I-45). Devuelve el resultado empaquetado
/// (`trunomy_abi::panic::unpack`: procesos matados, capabilities revocadas, objetos borrados).
pub fn tenant_panic(tenant: u64, wipe: bool) -> Result<u64, Errno> {
    let flags = if wipe { trunomy_abi::panic::FLAG_WIPE } else { 0 };
    decode(unsafe { syscall4(SyscallNumber::TenantPanic.number(), tenant, flags, 0, 0) })
}

/// Reabre un tenant cortado para actores NUEVOS (los retirados siguen retirados).
pub fn tenant_thaw(tenant: u64) -> Result<u64, Errno> {
    decode(unsafe { syscall4(SyscallNumber::TenantThaw.number(), tenant, 0, 0, 0) })
}

/// Lee registros de auditoria con `seq > after_seq`; devuelve cuantos se decodificaron en `out`.
pub fn audit_read(out: &mut [Record], after_seq: u64) -> Result<usize, Errno> {
    let mut raw = [0u8; RECORD_SIZE * 16];
    let max = out.len().min(16);
    let len = (max * RECORD_SIZE) as u64;
    let n = decode(unsafe { syscall4(SyscallNumber::AuditRead.number(), raw.as_mut_ptr() as u64, len, after_seq, 0) })? as usize;
    let mut count = 0;
    for chunk in raw.chunks_exact(RECORD_SIZE).take(n.min(max)) {
        if let Some(r) = Record::decode(chunk) {
            out[count] = r;
            count += 1;
        }
    }
    Ok(count)
}

/// Ticks del reloj del kernel desde el arranque (`TICK_HZ` por segundo).
pub fn clock_ticks() -> Result<u64, Errno> {
    decode(unsafe { syscall4(SyscallNumber::ClockNow.number(), 0, 0, 0, 0) })
}

/// Pone en marcha, apaga o comprueba la red (`trunomy_abi::netctl`; solo el lider, I-44).
pub fn net_control(op: u64) -> Result<u64, Errno> {
    decode(unsafe { syscall4(SyscallNumber::NetControl.number(), op, 0, 0, 0) })
}
