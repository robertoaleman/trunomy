// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! `NetControl(op)` (I-44): poner en marcha, apagar y comprobar el dispositivo de red.
//!
//! Activar la red es darle al dispositivo acceso directo a memoria (DMA): por eso es una decision del
//! lider administrador, nunca automatica y nunca de un actor. Toda operacion, permitida o no, queda
//! auditada (`AuditOp::Net`, resource = operacion); las denegaciones de quien no es el lider se limitan
//! como el resto (I-43). Un `op` desconocido no tiene efectos ni auditoria.

use spin::Mutex;
use trunomy_abi::{netctl, Errno};

use super::identity::Session;
use crate::audit::{self, AuditOp, AuditOutcome};
use crate::capabilities::CapabilityError;
use crate::process::ProcessContext;

pub fn net_control_with(
    current: ProcessContext,
    session: &Mutex<Session>,
    op: u64,
    run: &mut dyn FnMut(u64) -> Result<u64, Errno>,
) -> Result<u64, Errno> {
    if !session.lock().is_admin(current) {
        audit::record_throttled_denial(current.subject_id, AuditOp::Net, Some(current.tenant_id), Some(op), CapabilityError::PermissionDenied);
        return Err(Errno::PermissionDenied);
    }
    if !netctl::is_known(op) {
        return Err(Errno::InvalidArgument);
    }
    let r = run(op);
    let outcome = match r {
        Ok(_) => AuditOutcome::Allowed,
        Err(_) => AuditOutcome::Denied(CapabilityError::NotFound),
    };
    audit::record(current.subject_id, AuditOp::Net, None, Some(current.tenant_id), Some(op), outcome);
    r
}

pub fn net_control(current: ProcessContext, op: u64) -> u64 {
    net_control_with(current, &super::identity::SESSION, op, &mut crate::net::control).unwrap_or_else(|e| e.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{ResourceType, Rights, GLOBAL_CAPABILITY_BOOK};
    use crate::process::register_process;
    use crate::syscall::identity::CAP_ADMIN;

    /// Lider administrador (pid `base`) y un proceso ajeno.
    fn world(base: u64) -> (Mutex<Session>, ProcessContext, ProcessContext) {
        let lead = ProcessContext::new(base, base, base);
        assert!(register_process(base, lead));
        GLOBAL_CAPABILITY_BOOK.lock().try_grant(base, base, ResourceType::Task, CAP_ADMIN as u64, Rights::READ).unwrap();
        let other = ProcessContext::new(base + 1, base + 1, base + 1);
        (Mutex::new(Session::new(base, base * 1000, base * 1000)), lead, other)
    }

    #[test]
    fn only_the_leader_runs_it_and_a_refusal_runs_nothing() {
        let (session, lead, other) = world(7701);
        let mut calls = alloc::vec::Vec::new();
        let r = net_control_with(other, &session, netctl::UP, &mut |op| { calls.push(op); Ok(0) });
        assert_eq!(r, Err(Errno::PermissionDenied));
        assert!(calls.is_empty());
        let r = net_control_with(lead, &session, netctl::UP, &mut |op| { calls.push(op); Ok(0) });
        assert_eq!(r, Ok(0));
        assert_eq!(calls, alloc::vec![netctl::UP]);
    }

    #[test]
    fn unknown_operations_have_no_effect() {
        let (session, lead, _) = world(7703);
        let mut called = false;
        for op in [0, 4, 99, u64::MAX] {
            assert_eq!(net_control_with(lead, &session, op, &mut |_| { called = true; Ok(0) }), Err(Errno::InvalidArgument));
        }
        assert!(!called);
    }

    #[test]
    fn the_operation_result_and_its_failure_are_passed_through_and_audited() {
        let (session, lead, other) = world(7705);
        assert_eq!(net_control_with(lead, &session, netctl::SELFTEST, &mut |_| Ok(1)), Ok(1));
        assert_eq!(net_control_with(lead, &session, netctl::UP, &mut |_| Err(Errno::ResourceUnavailable)), Err(Errno::ResourceUnavailable));
        let _ = net_control_with(other, &session, netctl::DOWN, &mut |_| Ok(0));
        let mine: alloc::vec::Vec<_> = audit::events_for_subject(lead.subject_id).into_iter().filter(|e| e.op == AuditOp::Net).collect();
        assert_eq!(mine.len(), 2);
        assert_eq!(mine[0].outcome, AuditOutcome::Allowed);
        assert!(matches!(mine[1].outcome, AuditOutcome::Denied(_)));
        let theirs: alloc::vec::Vec<_> = audit::events_for_subject(other.subject_id).into_iter().filter(|e| e.op == AuditOp::Net).collect();
        assert_eq!(theirs.len(), 1);
        assert!(matches!(theirs[0].outcome, AuditOutcome::Denied(CapabilityError::PermissionDenied)));
    }
}
