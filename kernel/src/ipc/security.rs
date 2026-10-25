// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

#![allow(dead_code)]

use crate::loader::CapabilityEntry;
use crate::memory_validation::validate_user_range;

pub const CAP_IPC_SEND: u32 = 0x0010;
pub const CAP_IPC_RECV: u32 = 0x0011;
pub const MAX_INLINE_WORDS: usize = trunomy_abi::MAX_INLINE_WORDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcValidationError {
    SenderDenied,
    ReceiverDenied,
    InvalidTarget,
    InvalidPayload,
    InvalidUserPointer,
    CapabilityNotOwned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedIpc {
    pub sender_pid: u64,
    pub target_pid: u64,
    pub message_id: u32,
    pub payload_words: usize,
    pub delegated_capability: Option<u32>,
}

fn has_capability(caps: &[CapabilityEntry], cap_id: u32) -> bool {
    caps.iter().any(|cap| cap.cap_id == cap_id)
}

pub fn validate_user_payload(data_ptr: u64, payload_words: usize) -> Result<(), IpcValidationError> {
    if payload_words == 0 || payload_words > MAX_INLINE_WORDS {
        return Err(IpcValidationError::InvalidPayload);
    }
    let byte_len = payload_words
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(IpcValidationError::InvalidPayload)?;
    validate_user_range(data_ptr, byte_len).map_err(|_| IpcValidationError::InvalidUserPointer)
}

pub fn validate_send(
    sender_pid: u64,
    target_pid: u64,
    message_id: u32,
    payload: Option<&[u64]>,
    sender_caps: &[CapabilityEntry],
    receiver_caps: &[CapabilityEntry],
    delegated_capability: Option<u32>,
) -> Result<ValidatedIpc, IpcValidationError> {
    if sender_pid == 0 || target_pid == 0 || sender_pid == target_pid {
        return Err(IpcValidationError::InvalidTarget);
    }
    if message_id == 0 {
        return Err(IpcValidationError::InvalidPayload);
    }
    if !has_capability(sender_caps, CAP_IPC_SEND) {
        return Err(IpcValidationError::SenderDenied);
    }
    if !has_capability(receiver_caps, CAP_IPC_RECV) {
        return Err(IpcValidationError::ReceiverDenied);
    }
    let payload_words = payload.ok_or(IpcValidationError::InvalidPayload)?.len();
    if payload_words == 0 || payload_words > MAX_INLINE_WORDS {
        return Err(IpcValidationError::InvalidPayload);
    }
    if let Some(cap_id) = delegated_capability {
        if !has_capability(sender_caps, cap_id) {
            return Err(IpcValidationError::CapabilityNotOwned);
        }
    }
    Ok(ValidatedIpc { sender_pid, target_pid, message_id, payload_words, delegated_capability })
}

pub fn validate_receive(
    receiver_pid: u64,
    sender_pid: u64,
    message_id: u32,
    payload_words: usize,
    receiver_caps: &[CapabilityEntry],
    buffer_ptr: u64,
) -> Result<ValidatedIpc, IpcValidationError> {
    if receiver_pid == 0 || sender_pid == 0 || receiver_pid == sender_pid {
        return Err(IpcValidationError::InvalidTarget);
    }
    if message_id == 0 {
        return Err(IpcValidationError::InvalidPayload);
    }
    if !has_capability(receiver_caps, CAP_IPC_RECV) {
        return Err(IpcValidationError::ReceiverDenied);
    }
    validate_user_payload(buffer_ptr, payload_words)?;
    Ok(ValidatedIpc { sender_pid, target_pid: receiver_pid, message_id, payload_words, delegated_capability: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cap(cap_id: u32) -> CapabilityEntry { CapabilityEntry { cap_id, cap_scope: 0 } }

    #[test]
    fn valid_ipc_send_and_receive_are_accepted() {
        assert!(validate_send(1, 2, 7, Some(&[10, 20]), &[cap(CAP_IPC_SEND)], &[cap(CAP_IPC_RECV)], None).is_ok());
        assert!(validate_receive(2, 1, 7, 2, &[cap(CAP_IPC_RECV)], 0x4000_0000).is_ok());
    }

    #[test]
    fn sender_and_receiver_capabilities_are_required() {
        assert_eq!(validate_send(1, 2, 7, Some(&[1]), &[], &[cap(CAP_IPC_RECV)], None), Err(IpcValidationError::SenderDenied));
        assert_eq!(validate_send(1, 2, 7, Some(&[1]), &[cap(CAP_IPC_SEND)], &[], None), Err(IpcValidationError::ReceiverDenied));
    }

    #[test]
    fn invalid_delegation_and_payload_are_rejected() {
        assert_eq!(validate_send(1, 2, 7, Some(&[1]), &[cap(CAP_IPC_SEND)], &[cap(CAP_IPC_RECV)], Some(99)), Err(IpcValidationError::CapabilityNotOwned));
        assert_eq!(validate_user_payload(0, 1), Err(IpcValidationError::InvalidUserPointer));
        assert_eq!(validate_user_payload(0x4000_0000, MAX_INLINE_WORDS + 1), Err(IpcValidationError::InvalidPayload));
    }
}
