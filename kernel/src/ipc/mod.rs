// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

pub mod manager;
pub mod security;
// kernel/src/ipc/mod.rs

use crate::loader::CapabilityEntry;

/// Estructura de un mensaje IPC seguro transferido mediante el Kernel
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IpcMessage {
    pub sender_pid: u64,
    pub target_pid: u64,
    pub message_id: u32,
    pub data: [u64; 4], // 32 bytes de payload inline rápido
    pub delegated_capability: Option<CapabilityEntry>, // Capacidad transferida opcional
}
