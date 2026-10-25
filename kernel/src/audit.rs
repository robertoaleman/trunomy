// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Registro de auditoria acotado (anillo en memoria).
//!
//! Guarda cada decision de autorizacion sobre capabilities y objetos: quien lo
//! intento, que operacion, con que handle y si se permitio o se denego (y por
//! que). Es la base de "quien accedio a que" y "que se denego".
//!
//! Propiedades:
//! - Memoria acotada: `AUDIT_CAPACITY` eventos; al llenarse se descarta el mas
//!   antiguo y se cuenta en `overwritten`, para que la perdida sea visible.
//! - Los contadores totales (`allowed_total`, `denied_total`) no se pierden
//!   aunque el anillo rote.
//! - Orden de candados: el registro se toma DESPUES de cualquier otro candado
//!   del kernel y nunca toma otro candado por dentro (sin posibilidad de ciclo).
//! - Solo registra identificadores y codigos: nunca el contenido de los objetos.

#![allow(dead_code)]

use crate::capabilities::{CapabilityError, CapabilityHandle};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};

pub const AUDIT_CAPACITY: usize = 256;
/// Denegaciones identicas (mismo sujeto, operacion y recurso) que se registran completas antes de
/// solo contarse (I-41): un proceso hostil no puede borrar el historial repitiendo una denegacion.
pub const DENIAL_BURST: u32 = 4;
/// Claves (sujeto, operacion, recurso) que se recuerdan a la vez; al llenarse se olvida la mas vieja.
pub const THROTTLE_KEYS: usize = 32;
/// Tope de denegaciones guardadas por (sujeto, operacion) SIN importar el recurso (I-48): sin el, un proceso que
/// varia el recurso en cada intento (handles o puertos distintos) abre una clave nueva cada vez, nunca agota su
/// rafaga y llena el anillo.
pub const DENIAL_OP_CAP: u32 = 16;
/// `Halt` denegado es raro y grave: cupo mayor que el resto, pero tambien acotado (antes no tenia limite).
pub const HALT_BURST: u32 = 16;
pub const HALT_OP_CAP: u32 = 32;
/// Pares (sujeto, operacion) que se recuerdan a la vez; al llenarse se olvida el mas viejo.
pub const OP_BUDGET_KEYS: usize = 64;

pub static GLOBAL_AUDIT_LOG: Lazy<Mutex<AuditLog>> =
    Lazy::new(|| Mutex::new(AuditLog::with_capacity(AUDIT_CAPACITY)));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOp {
    Read,
    Write,
    Delete,
    Grant,
    Delegate,
    Revoke,
    Create,
    Identity,
    /// Un proceso fue terminado por una excepcion de CPU (resource = codigo de salida).
    ProcessFault,
    /// `ProcessKill` o plazo vencido de `ProcessWait` (resource = pid objetivo).
    ProcessKill,
    /// Denegacion de `ConsoleWrite`/`ConsoleRead` (resource = numero de syscall). Las escrituras
    /// permitidas NO se auditan (una por caracter: ruido que borraria lo importante).
    Console,
    /// `Halt`: permitido (la maquina se detiene) o denegado.
    Halt,
    /// Denegacion de `SendIpc`/`ReceiveIpc` (resource = pid destino o numero de syscall). Los envios
    /// permitidos no se auditan.
    Ipc,
    /// `TenantPanic` (resource = tenant), permitido o denegado (I-45).
    Panic,
    /// `TenantThaw` (resource = tenant), permitido o denegado.
    Thaw,
    /// `NetControl` (resource = operacion), permitido o denegado.
    Net,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Allowed,
    Denied(CapabilityError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEvent {
    /// Numero de secuencia monotono (empieza en 1).
    pub seq: u64,
    pub subject_id: u64,
    pub op: AuditOp,
    pub handle: Option<CapabilityHandle>,
    /// Tenant y recurso de la capability, cuando el handle se pudo resolver.
    pub tenant_id: Option<u64>,
    pub resource_id: Option<u64>,
    pub outcome: AuditOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditStats {
    pub stored: usize,
    pub allowed_total: u64,
    pub denied_total: u64,
    pub overwritten: u64,
    /// Denegaciones contadas pero no guardadas por superar `DENIAL_BURST` (I-41).
    pub suppressed: u64,
}

#[derive(Debug, Clone, Copy)]
struct ThrottleKey {
    subject: u64,
    op: AuditOp,
    resource: Option<u64>,
    count: u32,
}

#[derive(Debug, Clone, Copy)]
struct OpBudget {
    subject: u64,
    op: AuditOp,
    stored: u32,
}

/// Rafaga por clave y tope por (sujeto, operacion) de las denegaciones de `op`.
fn denial_limits(op: AuditOp) -> (u32, u32) {
    if op == AuditOp::Halt { (HALT_BURST, HALT_OP_CAP) } else { (DENIAL_BURST, DENIAL_OP_CAP) }
}

#[derive(Debug)]
pub struct AuditLog {
    events: VecDeque<AuditEvent>,
    capacity: usize,
    next_seq: u64,
    allowed_total: u64,
    denied_total: u64,
    overwritten: u64,
    suppressed: u64,
    throttle: VecDeque<ThrottleKey>,
    budgets: VecDeque<OpBudget>,
}

impl AuditLog {
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            next_seq: 1,
            allowed_total: 0,
            denied_total: 0,
            overwritten: 0,
            suppressed: 0,
            throttle: VecDeque::new(),
            budgets: VecDeque::new(),
        }
    }

    /// Registra una denegacion (la misma ruta que `record` con `Denied`; se conserva el nombre para quien ya la
    /// llama). Devuelve la secuencia si se guardo.
    pub fn record_throttled_denial(
        &mut self,
        subject_id: u64,
        op: AuditOp,
        tenant_id: Option<u64>,
        resource_id: Option<u64>,
        error: CapabilityError,
    ) -> Option<u64> {
        self.record_denial(subject_id, op, None, tenant_id, resource_id, error)
    }

    /// Toda denegacion pasa por aqui (I-41, I-48): un proceso hostil puede repetirlas sin coste y no debe
    /// desplazar la historia de los demas. Se guarda solo si caben en la rafaga de su clave (sujeto, operacion,
    /// recurso) Y en el tope de su par (sujeto, operacion); si no, solo suben `denied_total` y `suppressed`.
    fn record_denial(
        &mut self,
        subject_id: u64,
        op: AuditOp,
        handle: Option<CapabilityHandle>,
        tenant_id: Option<u64>,
        resource_id: Option<u64>,
        error: CapabilityError,
    ) -> Option<u64> {
        let (burst, op_cap) = denial_limits(op);
        let key = match self
            .throttle
            .iter()
            .position(|k| k.subject == subject_id && k.op == op && k.resource == resource_id)
        {
            Some(i) => i,
            None => {
                if self.throttle.len() == THROTTLE_KEYS {
                    self.throttle.pop_front();
                }
                self.throttle.push_back(ThrottleKey { subject: subject_id, op, resource: resource_id, count: 0 });
                self.throttle.len() - 1
            }
        };
        let budget = match self.budgets.iter().position(|b| b.subject == subject_id && b.op == op) {
            Some(i) => i,
            None => {
                if self.budgets.len() == OP_BUDGET_KEYS {
                    self.budgets.pop_front();
                }
                self.budgets.push_back(OpBudget { subject: subject_id, op, stored: 0 });
                self.budgets.len() - 1
            }
        };
        if self.throttle[key].count >= burst || self.budgets[budget].stored >= op_cap {
            self.denied_total = self.denied_total.saturating_add(1);
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.throttle[key].count += 1;
        self.budgets[budget].stored += 1;
        Some(self.push(subject_id, op, handle, tenant_id, resource_id, AuditOutcome::Denied(error)))
    }

    /// Registra un evento. Las denegaciones estan limitadas (ver `record_denial`); devuelve su secuencia, o 0
    /// si se contaron pero no se guardaron (la secuencia real empieza en 1).
    pub fn record(
        &mut self,
        subject_id: u64,
        op: AuditOp,
        handle: Option<CapabilityHandle>,
        tenant_id: Option<u64>,
        resource_id: Option<u64>,
        outcome: AuditOutcome,
    ) -> u64 {
        match outcome {
            AuditOutcome::Allowed => self.push(subject_id, op, handle, tenant_id, resource_id, outcome),
            AuditOutcome::Denied(error) => self
                .record_denial(subject_id, op, handle, tenant_id, resource_id, error)
                .unwrap_or(0),
        }
    }

    /// Guarda un evento sin limite de rafaga. Si el anillo esta lleno, una denegacion desplaza a la denegacion
    /// mas antigua (no a un evento permitido: grants, revokes, paradas de tenant...); solo si no hay ninguna
    /// denegacion desplaza al mas antiguo de todos (I-48).
    fn push(
        &mut self,
        subject_id: u64,
        op: AuditOp,
        handle: Option<CapabilityHandle>,
        tenant_id: Option<u64>,
        resource_id: Option<u64>,
        outcome: AuditOutcome,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);

        match outcome {
            AuditOutcome::Allowed => self.allowed_total = self.allowed_total.saturating_add(1),
            AuditOutcome::Denied(_) => self.denied_total = self.denied_total.saturating_add(1),
        }

        if self.events.len() == self.capacity {
            let victim = match outcome {
                AuditOutcome::Denied(_) => self
                    .events
                    .iter()
                    .position(|e| matches!(e.outcome, AuditOutcome::Denied(_)))
                    .unwrap_or(0),
                AuditOutcome::Allowed => 0,
            };
            self.events.remove(victim);
            self.overwritten = self.overwritten.saturating_add(1);
        }
        self.events.push_back(AuditEvent {
            seq,
            subject_id,
            op,
            handle,
            tenant_id,
            resource_id,
            outcome,
        });
        seq
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn stats(&self) -> AuditStats {
        AuditStats {
            stored: self.events.len(),
            allowed_total: self.allowed_total,
            denied_total: self.denied_total,
            overwritten: self.overwritten,
            suppressed: self.suppressed,
        }
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.iter().copied().collect()
    }

    pub fn events_for_subject(&self, subject_id: u64) -> Vec<AuditEvent> {
        self.events
            .iter()
            .filter(|event| event.subject_id == subject_id)
            .copied()
            .collect()
    }
}

/// Registra un evento en el anillo global.
pub fn record(
    subject_id: u64,
    op: AuditOp,
    handle: Option<CapabilityHandle>,
    tenant_id: Option<u64>,
    resource_id: Option<u64>,
    outcome: AuditOutcome,
) {
    GLOBAL_AUDIT_LOG
        .lock()
        .record(subject_id, op, handle, tenant_id, resource_id, outcome);
}

/// Registra una denegacion repetible en el anillo global (ver `AuditLog::record_throttled_denial`).
pub fn record_throttled_denial(
    subject_id: u64,
    op: AuditOp,
    tenant_id: Option<u64>,
    resource_id: Option<u64>,
    error: CapabilityError,
) -> Option<u64> {
    GLOBAL_AUDIT_LOG.lock().record_throttled_denial(subject_id, op, tenant_id, resource_id, error)
}

pub fn stats() -> AuditStats {
    GLOBAL_AUDIT_LOG.lock().stats()
}

pub fn events_for_subject(subject_id: u64) -> Vec<AuditEvent> {
    GLOBAL_AUDIT_LOG.lock().events_for_subject(subject_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied() -> AuditOutcome {
        AuditOutcome::Denied(CapabilityError::PermissionDenied)
    }

    #[test]
    fn records_events_in_order_with_monotonic_sequence() {
        let mut log = AuditLog::with_capacity(8);
        let a = log.record(1, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        let b = log.record(2, AuditOp::Write, None, None, None, denied());
        assert_eq!((a, b), (1, 2));
        let events = log.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].subject_id, 1);
        assert_eq!(events[1].outcome, denied());
    }

    #[test]
    fn ring_is_bounded_and_overwrites_are_counted() {
        let mut log = AuditLog::with_capacity(4);
        for i in 0..6u64 {
            log.record(i, AuditOp::Read, None, None, None, denied());
        }
        let stats = log.stats();
        assert_eq!(stats.stored, 4);
        assert_eq!(stats.overwritten, 2);
        assert_eq!(stats.denied_total, 6, "los totales sobreviven a la rotacion");
        // Se conservan los 4 mas recientes (seq 3..=6).
        assert_eq!(log.events().first().map(|e| e.seq), Some(3));
        assert_eq!(log.events().last().map(|e| e.seq), Some(6));
    }

    #[test]
    fn totals_separate_allowed_from_denied() {
        let mut log = AuditLog::with_capacity(8);
        log.record(1, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        log.record(1, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        log.record(1, AuditOp::Write, None, None, None, denied());
        let stats = log.stats();
        assert_eq!((stats.allowed_total, stats.denied_total), (2, 1));
    }

    #[test]
    fn filter_by_subject_returns_only_that_subject() {
        let mut log = AuditLog::with_capacity(8);
        log.record(1, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        log.record(2, AuditOp::Read, None, None, None, denied());
        log.record(1, AuditOp::Delete, None, None, None, denied());
        assert_eq!(log.events_for_subject(1).len(), 2);
        assert_eq!(log.events_for_subject(3).len(), 0);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let mut log = AuditLog::with_capacity(0);
        log.record(1, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        log.record(1, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        assert_eq!(log.len(), 1);
        assert_eq!(log.stats().overwritten, 1);
    }

    #[test]
    fn a_repeated_denial_cannot_wipe_the_history() {
        let mut log = AuditLog::with_capacity(16);
        // historia previa que importa
        for i in 0..8u64 {
            log.record(100 + i, AuditOp::Grant, None, None, None, AuditOutcome::Allowed);
        }
        // un proceso hostil repite la misma denegacion un millon de veces
        let mut stored = 0;
        for _ in 0..1_000_000u32 {
            if log
                .record_throttled_denial(666, AuditOp::Console, Some(9), Some(1), CapabilityError::NotFound)
                .is_some()
            {
                stored += 1;
            }
        }
        assert_eq!(stored, DENIAL_BURST);
        let ev = log.events();
        assert_eq!(ev.iter().filter(|e| e.op == AuditOp::Grant).count(), 8, "la historia sigue entera");
        assert_eq!(ev.iter().filter(|e| e.subject_id == 666).count(), DENIAL_BURST as usize);
        let st = log.stats();
        assert_eq!(st.overwritten, 0);
        assert_eq!(st.denied_total, 1_000_000, "ninguna denegacion se pierde en los contadores");
        assert_eq!(st.suppressed, 1_000_000 - DENIAL_BURST as u64);
    }

    #[test]
    fn the_burst_is_per_subject_operation_and_resource() {
        let mut log = AuditLog::with_capacity(64);
        let d = |log: &mut AuditLog, s, op, r| log.record_throttled_denial(s, op, None, Some(r), CapabilityError::NotFound);
        for _ in 0..DENIAL_BURST {
            assert!(d(&mut log, 1, AuditOp::Console, 1).is_some());
        }
        assert!(d(&mut log, 1, AuditOp::Console, 1).is_none(), "agotado");
        assert!(d(&mut log, 1, AuditOp::Console, 2).is_some(), "otro recurso (ConsoleRead) tiene su cupo");
        assert!(d(&mut log, 1, AuditOp::Halt, 1).is_some(), "otra operacion tiene su cupo");
        assert!(d(&mut log, 2, AuditOp::Console, 1).is_some(), "otro sujeto tiene su cupo");
    }

    #[test]
    fn varying_the_resource_does_not_open_a_fresh_budget_each_time() {
        // el agujero de I-41: una clave nueva por intento nunca agota su rafaga
        let mut log = AuditLog::with_capacity(64);
        for i in 0..8u64 {
            log.record(100 + i, AuditOp::Grant, None, None, None, AuditOutcome::Allowed);
        }
        let mut stored = 0;
        for resource in 0..100_000u64 {
            if log.record(666, AuditOp::Read, None, None, Some(resource), denied()) != 0 {
                stored += 1;
            }
        }
        assert_eq!(stored, DENIAL_OP_CAP, "un sujeto no guarda mas de DENIAL_OP_CAP denegaciones por operacion");
        assert_eq!(log.events().iter().filter(|e| e.op == AuditOp::Grant).count(), 8, "la historia sigue entera");
        let st = log.stats();
        assert_eq!(st.denied_total, 100_000);
        assert_eq!(st.suppressed, 100_000 - DENIAL_OP_CAP as u64);
        assert_eq!(st.overwritten, 0);
    }

    #[test]
    fn the_cap_is_per_operation_and_per_subject() {
        let mut log = AuditLog::with_capacity(256);
        let d = |log: &mut AuditLog, s, op, r| log.record(s, op, None, None, Some(r), denied()) != 0;
        for r in 0..DENIAL_OP_CAP as u64 {
            assert!(d(&mut log, 1, AuditOp::Read, r));
        }
        assert!(!d(&mut log, 1, AuditOp::Read, 999), "agotado para (1, Read)");
        assert!(d(&mut log, 1, AuditOp::Write, 999), "otra operacion tiene su tope");
        assert!(d(&mut log, 2, AuditOp::Read, 999), "otro sujeto tiene su tope");
    }

    #[test]
    fn denials_never_displace_allowed_events_from_a_full_ring() {
        let mut log = AuditLog::with_capacity(16);
        for i in 0..8u64 {
            log.record(100 + i, AuditOp::Revoke, None, None, None, AuditOutcome::Allowed);
        }
        // muchos sujetos distintos: cada uno con su propio cupo, asi que el limite por clave no basta
        for s in 0..5_000u64 {
            log.record(1_000 + s, AuditOp::Read, None, None, Some(s), denied());
        }
        let ev = log.events();
        assert_eq!(ev.len(), 16);
        assert_eq!(ev.iter().filter(|e| e.op == AuditOp::Revoke).count(), 8, "ningun evento permitido se pierde");
        assert_eq!(log.stats().allowed_total, 8);
        assert!(ev.iter().filter(|e| e.outcome == denied()).count() == 8, "las denegaciones solo rotan entre si");
        // los mas recientes son los que quedan
        assert_eq!(ev.last().map(|e| e.subject_id), Some(1_000 + 4_999));
    }

    #[test]
    fn allowed_events_still_rotate_when_there_is_no_denial_to_evict() {
        let mut log = AuditLog::with_capacity(4);
        for i in 0..6u64 {
            log.record(i, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        }
        assert_eq!((log.len(), log.stats().overwritten), (4, 2));
        assert_eq!(log.events().first().map(|e| e.seq), Some(3));
    }

    #[test]
    fn a_denial_into_a_ring_without_denials_evicts_the_oldest_event() {
        let mut log = AuditLog::with_capacity(2);
        log.record(1, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        log.record(2, AuditOp::Read, None, None, None, AuditOutcome::Allowed);
        log.record(3, AuditOp::Read, None, None, None, denied());
        let ev = log.events();
        assert_eq!(ev.iter().map(|e| e.subject_id).collect::<Vec<_>>(), [2, 3]);
    }

    #[test]
    fn the_budget_table_is_bounded() {
        let mut log = AuditLog::with_capacity(4096);
        for s in 0..(OP_BUDGET_KEYS as u64 + 10) {
            log.record(s, AuditOp::Read, None, None, None, denied());
        }
        assert!(log.budgets.len() <= OP_BUDGET_KEYS);
    }

    #[test]
    fn the_throttle_table_is_bounded_and_forgets_the_oldest_key() {
        let mut log = AuditLog::with_capacity(4096);
        for s in 0..(THROTTLE_KEYS as u64 + 10) {
            log.record_throttled_denial(s, AuditOp::Console, None, None, CapabilityError::NotFound);
        }
        assert!(log.throttle.len() <= THROTTLE_KEYS);
    }
}
