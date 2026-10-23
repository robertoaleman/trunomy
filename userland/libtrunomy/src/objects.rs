// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Objetos y capabilities desde userland. Contrato: trunomy-abi + kernel/src/syscall/objects.rs.

use alloc::vec::Vec;

use crate::{decode, syscall4, Errno, Handle, SyscallNumber};

/// Crea un objeto en el tenant del proceso; devuelve un handle READ|WRITE|DELEGATE.
pub fn object_create(data: &[u8]) -> Result<Handle, Errno> {
    let ptr = if data.is_empty() { 0 } else { data.as_ptr() as u64 };
    let ret = unsafe { syscall4(SyscallNumber::ObjectCreate.number(), ptr, data.len() as u64, 0, 0) };
    decode(ret).map(Handle)
}

/// Lee el objeto en `buf`; devuelve los bytes escritos.
pub fn object_read(h: Handle, buf: &mut [u8]) -> Result<usize, Errno> {
    let ret = unsafe { syscall4(SyscallNumber::ObjectRead.number(), h.0, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };
    decode(ret).map(|n| n as usize)
}

/// Lee el objeto completo (buffer de `max` bytes).
pub fn object_read_vec(h: Handle, max: usize) -> Result<Vec<u8>, Errno> {
    let mut buf = alloc::vec![0u8; max];
    let n = object_read(h, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn object_write(h: Handle, data: &[u8]) -> Result<(), Errno> {
    let ptr = if data.is_empty() { 0 } else { data.as_ptr() as u64 };
    let ret = unsafe { syscall4(SyscallNumber::ObjectWrite.number(), h.0, ptr, data.len() as u64, 0) };
    decode(ret).map(|_| ())
}

pub fn object_delete(h: Handle) -> Result<(), Errno> {
    let ret = unsafe { syscall4(SyscallNumber::ObjectDelete.number(), h.0, 0, 0, 0) };
    decode(ret).map(|_| ())
}

/// Delega una capability mas estrecha a `target_pid` (mismo tenant). `max_uses == 0` = sin limite.
pub fn cap_derive(h: Handle, target_pid: u64, rights_mask: u64, max_uses: u32) -> Result<Handle, Errno> {
    let ret = unsafe { syscall4(SyscallNumber::CapDerive.number(), h.0, target_pid, rights_mask, max_uses as u64) };
    decode(ret).map(Handle)
}

pub fn cap_revoke(h: Handle) -> Result<(), Errno> {
    let ret = unsafe { syscall4(SyscallNumber::CapRevoke.number(), h.0, 0, 0, 0) };
    decode(ret).map(|_| ())
}
