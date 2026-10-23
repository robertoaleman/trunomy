// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

use alloc::collections::VecDeque;

use super::IpcMessage;

/// Mensajes pendientes por proceso destino. Un emisor no puede llenar el heap del kernel ni
/// monopolizar la cola de otro (I-43).
pub const MAX_QUEUED_PER_TARGET: usize = 8;
/// Mensajes pendientes en todo el kernel (cada uno ocupa unos 100 bytes del heap de 100 KiB).
pub const MAX_QUEUED_TOTAL: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Pid cero, auto-envio o id de mensaje cero.
    Invalid,
    /// El destino ya tiene `MAX_QUEUED_PER_TARGET` mensajes sin recoger.
    TargetFull,
    /// La cola global esta en `MAX_QUEUED_TOTAL`.
    QueueFull,
}

pub struct IpcManager {
    message_queue: spin::Mutex<VecDeque<IpcMessage>>,
}

impl IpcManager {
    pub const fn new() -> Self {
        Self {
            message_queue: spin::Mutex::new(VecDeque::new()),
        }
    }

    pub fn enqueue_message(
        &self,
        sender_pid: u64,
        target_pid: u64,
        message_id: u32,
        payload: [u64; 4],
    ) -> Result<(), IpcError> {
        if sender_pid == 0 || target_pid == 0 || sender_pid == target_pid || message_id == 0 {
            return Err(IpcError::Invalid);
        }

        let mut queue = self.message_queue.lock();
        if queue.len() >= MAX_QUEUED_TOTAL {
            return Err(IpcError::QueueFull);
        }
        if queue.iter().filter(|m| m.target_pid == target_pid).count() >= MAX_QUEUED_PER_TARGET {
            return Err(IpcError::TargetFull);
        }
        queue.push_back(IpcMessage {
            sender_pid,
            target_pid,
            message_id,
            data: payload,
            delegated_capability: None,
        });
        Ok(())
    }

    /// Descarta los mensajes pendientes enviados por o dirigidos a cualquiera de `pids`.
    /// Devuelve cuantos. Lo usa `TenantPanic` (I-45): un tenant cortado no deja nada en cola.
    pub fn purge_pids(&self, pids: &[u64]) -> usize {
        let mut queue = self.message_queue.lock();
        let before = queue.len();
        queue.retain(|m| !pids.contains(&m.sender_pid) && !pids.contains(&m.target_pid));
        before - queue.len()
    }

    pub fn receive_message(&self, receiver_pid: u64) -> Option<IpcMessage> {
        let mut queue = self.message_queue.lock();
        let pos = queue.iter().position(|msg| msg.target_pid == receiver_pid)?;
        queue.remove(pos)
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.message_queue.lock().clear();
    }

    #[cfg(test)]
    pub fn queue_len(&self) -> usize {
        self.message_queue.lock().len()
    }

    /// Mensajes pendientes para `target_pid`.
    #[cfg(test)]
    pub fn pending_for(&self, target_pid: u64) -> usize {
        self.message_queue.lock().iter().filter(|m| m.target_pid == target_pid).count()
    }
}

pub static IPC_MANAGER: IpcManager = IpcManager::new();

#[cfg(test)]
mod tests {
    use super::*;

    // Cada prueba usa su propia instancia: la global la comparten otras pruebas del kernel.

    #[test]
    fn enqueue_message_stores_for_target() {
        let m = IpcManager::new();
        assert!(m.enqueue_message(1, 2, 7, [10, 20, 30, 40]).is_ok());
        let msg = m.receive_message(2).unwrap();
        assert_eq!((msg.sender_pid, msg.target_pid, msg.message_id), (1, 2, 7));
        assert_eq!(msg.data, [10, 20, 30, 40]);
    }

    #[test]
    fn receive_message_returns_none_when_no_target_message_exists() {
        let m = IpcManager::new();
        assert!(m.receive_message(99).is_none());
    }

    #[test]
    fn invalid_messages_are_rejected() {
        let m = IpcManager::new();
        assert_eq!(m.enqueue_message(0, 2, 1, [0; 4]), Err(IpcError::Invalid));
        assert_eq!(m.enqueue_message(1, 0, 1, [0; 4]), Err(IpcError::Invalid));
        assert_eq!(m.enqueue_message(2, 2, 1, [0; 4]), Err(IpcError::Invalid));
        assert_eq!(m.enqueue_message(1, 2, 0, [0; 4]), Err(IpcError::Invalid));
        assert_eq!(m.queue_len(), 0);
    }

    #[test]
    fn one_target_cannot_hold_more_than_its_share() {
        let m = IpcManager::new();
        for i in 0..MAX_QUEUED_PER_TARGET {
            m.enqueue_message(1, 2, 1, [i as u64; 4]).unwrap();
        }
        assert_eq!(m.enqueue_message(1, 2, 1, [9; 4]), Err(IpcError::TargetFull));
        // otro destino sigue disponible: un destino lleno no bloquea a los demas
        assert!(m.enqueue_message(1, 3, 1, [0; 4]).is_ok());
        // recoger uno libera un hueco, y se entrega en orden de llegada
        assert_eq!(m.receive_message(2).unwrap().data, [0; 4]);
        assert!(m.enqueue_message(1, 2, 1, [9; 4]).is_ok());
        assert_eq!(m.pending_for(2), MAX_QUEUED_PER_TARGET);
    }

    #[test]
    fn the_whole_queue_is_bounded() {
        let m = IpcManager::new();
        let mut sent = 0;
        // reparte entre destinos distintos para no tocar el limite por destino
        'outer: for target in 2u64.. {
            for _ in 0..MAX_QUEUED_PER_TARGET {
                match m.enqueue_message(1, target, 1, [0; 4]) {
                    Ok(()) => sent += 1,
                    Err(IpcError::QueueFull) => break 'outer,
                    Err(e) => panic!("{e:?}"),
                }
            }
        }
        assert_eq!(sent, MAX_QUEUED_TOTAL);
        assert_eq!(m.queue_len(), MAX_QUEUED_TOTAL);
    }

    #[test]
    fn the_global_limits_fit_the_kernel_heap() {
        // 100 KiB de heap: la cola entera debe ser una fraccion pequena.
        let bytes = MAX_QUEUED_TOTAL * core::mem::size_of::<IpcMessage>();
        assert!(bytes <= 8 * 1024, "{bytes} bytes");
    }
}
