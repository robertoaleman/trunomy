// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// Cliente IPC de userland. Contrato = kernel/src/syscalls.rs (crate trunomy-abi).
//   SendIpc(target_pid, message_id, payload_ptr, payload_words)
//   ReceiveIpc(receiver_pid, payload_ptr, payload_words >= MAX_INLINE_WORDS)

use crate::{decode, syscall4, Errno, SyscallNumber, MAX_INLINE_WORDS};

/// Envia hasta MAX_INLINE_WORDS palabras (u64) al proceso destino.
pub fn send_ipc_message(target_pid: u64, message_id: u64, words: &[u64]) -> Result<(), Errno> {
    if words.len() > MAX_INLINE_WORDS {
        return Err(Errno::InvalidArgument);
    }
    let ret = unsafe {
        syscall4(
            SyscallNumber::SendIpc.number(),
            target_pid,
            message_id,
            words.as_ptr() as u64,
            words.len() as u64,
        )
    };
    decode(ret).map(|_| ())
}

/// Recibe el siguiente mensaje de `receiver_pid` (el propio pid). El buffer
/// debe tener al menos MAX_INLINE_WORDS palabras. Devuelve el retorno del kernel.
pub fn receive_ipc_message(receiver_pid: u64, out: &mut [u64]) -> Result<u64, Errno> {
    if out.len() < MAX_INLINE_WORDS {
        return Err(Errno::BufferTooSmall);
    }
    let ret = unsafe {
        syscall4(
            SyscallNumber::ReceiveIpc.number(),
            receiver_pid,
            out.as_mut_ptr() as u64,
            out.len() as u64,
            0,
        )
    };
    decode(ret)
}
