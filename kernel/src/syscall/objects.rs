// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Syscalls de objetos y capabilities (ObjectCreate/Read/Write/Delete, CapDerive/CapRevoke).
//!
//! Identidad: siempre la del proceso llamante (`ProcessContext`), nunca un
//! argumento. Autoridad: el handle presentado (salvo ObjectCreate, que exige la
//! capability global CAP_OBJECT_CREATE en el dispatcher). Memoria de usuario: solo
//! via `user_access`. Errores: `errno_of` (taxonomia del ABI). Cada decision queda
//! en el registro de auditoria (capabilities.rs).

use alloc::vec::Vec;
use trunomy_abi::{rights, Errno, Handle};

use super::errno_of;
use crate::capabilities::{
    capability_tenant, create_object_for_subject, delete_object_via_capability,
    read_object_via_capability, write_object_via_capability, CapabilityError, CapabilityHandle,
    Limits, Rights, GLOBAL_CAPABILITY_BOOK, MAX_DELEGATED_PER_SUBJECT, MAX_OBJECT_PAYLOAD_BYTES,
};
use crate::process::{process_context, ProcessContext};
use crate::user_access::{UserSlice, UserSpace};

fn handle_from(raw: u64) -> Result<CapabilityHandle, Errno> {
    let h = Handle(raw);
    if !h.is_valid() {
        return Err(Errno::InvalidCapability);
    }
    Ok(CapabilityHandle { slot: h.slot(), generation: h.generation() })
}

fn handle_to(h: CapabilityHandle) -> u64 {
    Handle::new(h.slot, h.generation).0
}

fn rights_from(mask: u64) -> Result<Rights, Errno> {
    if mask == 0 || mask & !rights::ALL != 0 {
        return Err(Errno::InvalidArgument);
    }
    let table = [
        (rights::READ, Rights::READ),
        (rights::WRITE, Rights::WRITE),
        (rights::SEND, Rights::SEND),
        (rights::RECEIVE, Rights::RECEIVE),
        (rights::DELEGATE, Rights::DELEGATE),
    ];
    let mut out: Option<Rights> = None;
    for (bit, r) in table {
        if mask & bit != 0 {
            out = Some(out.map_or(r, |acc| acc | r));
        }
    }
    out.ok_or(Errno::InvalidArgument)
}

fn finish(r: Result<u64, Errno>) -> u64 {
    match r {
        Ok(v) => v,
        Err(e) => e.code(),
    }
}

fn cap_err(e: CapabilityError) -> Errno {
    errno_of(e)
}

/// ObjectCreate(payload_ptr, payload_len) -> handle (READ|WRITE|DELEGATE).
pub fn object_create<S: UserSpace>(caller: ProcessContext, space: &S, ptr: u64, len: u64) -> u64 {
    finish((|| {
        let slice = UserSlice::new(ptr, len).map_err(|e| e.errno())?;
        let payload = slice.read_to_vec(space, MAX_OBJECT_PAYLOAD_BYTES).map_err(|e| e.errno())?;
        let handle = create_object_for_subject(caller.subject_id, caller.tenant_id, payload).map_err(cap_err)?;
        Ok(handle_to(handle))
    })())
}

/// ObjectRead(handle, buf_ptr, buf_len) -> bytes escritos. Si el buffer es menor que
/// el objeto: BufferTooSmall y no se escribe nada (el uso de la capability ya se
/// consumio, como toda autorizacion).
pub fn object_read<S: UserSpace>(caller: ProcessContext, space: &S, handle: u64, ptr: u64, len: u64) -> u64 {
    finish((|| {
        let h = handle_from(handle)?;
        let out = UserSlice::new(ptr, len).map_err(|e| e.errno())?;
        let data = read_object_via_capability(caller.subject_id, h, Rights::READ).map_err(cap_err)?;
        let n = out.write_from(space, &data).map_err(|e| e.errno())?;
        Ok(n as u64)
    })())
}

/// ObjectWrite(handle, ptr, len) -> 0. Sustituye el contenido del objeto.
pub fn object_write<S: UserSpace>(caller: ProcessContext, space: &S, handle: u64, ptr: u64, len: u64) -> u64 {
    finish((|| {
        let h = handle_from(handle)?;
        let slice = UserSlice::new(ptr, len).map_err(|e| e.errno())?;
        let payload: Vec<u8> = slice.read_to_vec(space, MAX_OBJECT_PAYLOAD_BYTES).map_err(|e| e.errno())?;
        write_object_via_capability(caller.subject_id, h, Rights::WRITE, payload).map_err(cap_err)?;
        Ok(0)
    })())
}

/// ObjectDelete(handle) -> 0.
pub fn object_delete(caller: ProcessContext, handle: u64) -> u64 {
    finish((|| {
        let h = handle_from(handle)?;
        delete_object_via_capability(caller.subject_id, h, Rights::WRITE).map_err(cap_err)?;
        Ok(0)
    })())
}

/// CapDerive(handle, target_pid, rights_mask, max_uses) -> handle del hijo.
/// max_uses == 0 significa sin limite. El destino debe ser del mismo tenant que la
/// capability: no se delega entre tenants.
pub fn cap_derive(caller: ProcessContext, handle: u64, target_pid: u64, mask: u64, max_uses: u64) -> u64 {
    finish((|| {
        let h = handle_from(handle)?;
        let wanted = rights_from(mask)?;
        let uses = u32::try_from(max_uses).map_err(|_| Errno::InvalidArgument)?;
        let target = process_context(target_pid).ok_or(Errno::InvalidArgument)?;
        if target.pid == caller.pid {
            return Err(Errno::InvalidArgument);
        }
        let tenant = capability_tenant(caller.subject_id, h).ok_or(Errno::InvalidCapability)?;
        if target.tenant_id != tenant {
            return Err(Errno::TenantMismatch);
        }
        let limits = Limits { expires_at: None, max_uses: if uses == 0 { None } else { Some(uses) } };
        // Un proceso no puede llenar los slots de otro: el destino acepta como maximo
        // MAX_DELEGATED_PER_SUBJECT delegaciones; el resto queda para lo suyo. Un solo candado.
        let mut book = GLOBAL_CAPABILITY_BOOK.lock();
        if book.delegated_count(target.subject_id) >= MAX_DELEGATED_PER_SUBJECT {
            return Err(cap_err(CapabilityError::CapabilityQuotaExceeded));
        }
        let child = book
            .delegate_limited(caller.subject_id, h, target.subject_id, wanted, limits)
            .map_err(cap_err)?;
        drop(book);
        Ok(handle_to(child))
    })())
}

/// CapRevoke(handle) -> 0. Revoca la capability y su grupo de delegacion.
pub fn cap_revoke(caller: ProcessContext, handle: u64) -> u64 {
    finish((|| {
        let h = handle_from(handle)?;
        GLOBAL_CAPABILITY_BOOK.lock().revoke(caller.subject_id, h).map_err(cap_err)?;
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditOp, AuditOutcome};
    use crate::memory_validation::USER_MIN;
    use crate::process::register_process;
    use crate::user_access::tests::MockUserSpace;
    use trunomy_abi::decode;

    // Ids unicos por test: los estaticos globales se comparten entre hilos.
    fn proc(pid: u64, tenant: u64) -> ProcessContext {
        let c = ProcessContext::new(pid, pid, tenant);
        assert!(register_process(pid, c));
        c
    }

    fn put(sp: &MockUserSpace, off: usize, data: &[u8]) -> u64 {
        sp.mem.borrow_mut()[off..off + data.len()].copy_from_slice(data);
        USER_MIN + off as u64
    }

    #[test]
    fn create_read_write_delete_round_trip() {
        let sp = MockUserSpace::new(8192);
        let a = proc(9101, 9101);
        let p = put(&sp, 0, b"hola");
        let h = decode(object_create(a, &sp, p, 4)).unwrap();
        assert!(Handle(h).is_valid());

        let out = USER_MIN + 1024;
        assert_eq!(decode(object_read(a, &sp, h, out, 64)), Ok(4));
        assert_eq!(&sp.mem.borrow()[1024..1028], b"hola");

        let p2 = put(&sp, 2048, b"mundo!");
        assert_eq!(decode(object_write(a, &sp, h, p2, 6)), Ok(0));
        assert_eq!(decode(object_read(a, &sp, h, out, 64)), Ok(6));
        assert_eq!(&sp.mem.borrow()[1024..1030], b"mundo!");

        assert_eq!(decode(object_delete(a, h)), Ok(0));
        assert_eq!(decode(object_read(a, &sp, h, out, 64)), Err(Errno::InvalidCapability));
    }

    #[test]
    fn read_into_a_small_buffer_is_rejected_without_writing() {
        let sp = MockUserSpace::new(8192);
        let a = proc(9102, 9102);
        let p = put(&sp, 0, b"0123456789");
        let h = decode(object_create(a, &sp, p, 10)).unwrap();
        sp.mem.borrow_mut()[1024..1034].fill(0xEE);
        let r = object_read(a, &sp, h, USER_MIN + 1024, 4);
        assert_eq!(decode(r), Err(Errno::BufferTooSmall));
        assert!(sp.mem.borrow()[1024..1034].iter().all(|b| *b == 0xEE));
    }

    #[test]
    fn oversized_payload_and_bad_pointers_are_rejected() {
        let sp = MockUserSpace::new(8192);
        let a = proc(9103, 9103);
        assert_eq!(decode(object_create(a, &sp, USER_MIN, 1 << 20)), Err(Errno::InvalidArgument));
        assert_eq!(decode(object_create(a, &sp, 0, 4)), Err(Errno::InvalidPointer));
        assert_eq!(decode(object_create(a, &sp, 0xFFFF_8000_0000_0000, 4)), Err(Errno::InvalidPointer));
        assert_eq!(decode(object_read(a, &sp, 0, USER_MIN, 4)), Err(Errno::InvalidCapability));
        
    }

    #[test]
    fn derived_capability_is_narrower_and_other_tenant_is_refused() {
        let sp = MockUserSpace::new(8192);
        let owner = proc(9104, 9104);
        let reader = proc(9105, 9104);
        let outsider = proc(9106, 9106);
        let p = put(&sp, 0, b"secreto");
        let h = decode(object_create(owner, &sp, p, 7)).unwrap();

        let child = decode(cap_derive(owner, h, reader.pid, rights::READ, 0)).unwrap();
        let out = USER_MIN + 1024;
        assert_eq!(decode(object_read(reader, &sp, child, out, 64)), Ok(7));
        // sin WRITE: el hijo no puede escribir
        let p2 = put(&sp, 2048, b"x");
        assert_eq!(decode(object_write(reader, &sp, child, p2, 1)), Err(Errno::PermissionDenied));
        // el hijo no puede ampliar derechos
        assert_eq!(decode(cap_derive(reader, child, owner.pid, rights::READ | rights::WRITE, 0)), Err(Errno::PermissionDenied));
        // otro tenant: ni delegacion ni uso del handle ajeno
        assert_eq!(decode(cap_derive(owner, h, outsider.pid, rights::READ, 0)), Err(Errno::TenantMismatch));
        assert!(decode(object_read(outsider, &sp, h, out, 64)).is_err());
    }

    #[test]
    fn derive_validates_arguments() {
        let sp = MockUserSpace::new(8192);
        let owner = proc(9107, 9107);
        let other = proc(9108, 9107);
        let p = put(&sp, 0, b"d");
        let h = decode(object_create(owner, &sp, p, 1)).unwrap();
        assert_eq!(decode(cap_derive(owner, h, other.pid, 0, 0)), Err(Errno::InvalidArgument));
        assert_eq!(decode(cap_derive(owner, h, other.pid, 1 << 9, 0)), Err(Errno::InvalidArgument));
        assert_eq!(decode(cap_derive(owner, h, owner.pid, rights::READ, 0)), Err(Errno::InvalidArgument));
        assert_eq!(decode(cap_derive(owner, h, 424242, rights::READ, 0)), Err(Errno::InvalidArgument));
    }

    #[test]
    fn use_limit_and_revocation_are_enforced_through_the_syscalls() {
        let sp = MockUserSpace::new(8192);
        let owner = proc(9109, 9109);
        let agent = proc(9110, 9109);
        let p = put(&sp, 0, b"dato");
        let h = decode(object_create(owner, &sp, p, 4)).unwrap();
        let child = decode(cap_derive(owner, h, agent.pid, rights::READ, 2)).unwrap();
        let out = USER_MIN + 1024;
        assert_eq!(decode(object_read(agent, &sp, child, out, 16)), Ok(4));
        assert_eq!(decode(object_read(agent, &sp, child, out, 16)), Ok(4));
        assert_eq!(decode(object_read(agent, &sp, child, out, 16)), Err(Errno::UsesExhausted));

        let child2 = decode(cap_derive(owner, h, agent.pid, rights::READ, 0)).unwrap();
        assert_eq!(decode(object_read(agent, &sp, child2, out, 16)), Ok(4));
        assert_eq!(decode(cap_revoke(owner, h)), Ok(0));
        assert_eq!(decode(object_read(agent, &sp, child2, out, 16)), Err(Errno::RevokedCapability));
        assert_eq!(decode(object_read(owner, &sp, h, out, 16)), Err(Errno::RevokedCapability));
    }

    #[test]
    fn a_stranger_cannot_revoke_someone_elses_handle() {
        let sp = MockUserSpace::new(8192);
        let owner = proc(9111, 9111);
        let thief = proc(9112, 9111);
        let p = put(&sp, 0, b"d");
        let h = decode(object_create(owner, &sp, p, 1)).unwrap();
        assert!(decode(cap_revoke(thief, h)).is_err());
        assert_eq!(decode(object_read(owner, &sp, h, USER_MIN + 1024, 8)), Ok(1));
    }

    /// Hallazgo 4: quien tiene DELEGATE no puede llenar los slots de otro proceso del mismo tenant.
    #[test]
    fn cap_derive_cannot_fill_the_targets_slots() {
        let sp = MockUserSpace::new(8192);
        let attacker = proc(9121, 9121);
        let victim = proc(9122, 9121);
        let p = put(&sp, 0, b"x");
        let mut accepted = 0;
        for _ in 0..12 {
            let h = decode(object_create(attacker, &sp, p, 1)).unwrap();
            if decode(cap_derive(attacker, h, 9122, rights::READ, 0)).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, MAX_DELEGATED_PER_SUBJECT);
        // la victima conserva sitio para lo suyo, hasta el limite total
        for i in 0..(crate::capabilities::MAX_CAPABILITIES_PER_SUBJECT - MAX_DELEGATED_PER_SUBJECT) {
            assert!(decode(object_create(victim, &sp, p, 1)).is_ok(), "propia {i}");
        }
        assert_eq!(decode(object_create(victim, &sp, p, 1)), Err(Errno::QuotaExceeded));
    }

    #[test]
    fn capability_quota_failure_leaves_no_orphan_object() {
        let sp = MockUserSpace::new(8192);
        let a = proc(9113, 9113);
        let p = put(&sp, 0, b"x");
        for _ in 0..crate::capabilities::MAX_CAPABILITIES_PER_SUBJECT {
            decode(object_create(a, &sp, p, 1)).unwrap();
        }
        let before = crate::capabilities::GLOBAL_OBJECT_STORE.lock().count_for_tenant(9113);
        assert_eq!(decode(object_create(a, &sp, p, 1)), Err(Errno::QuotaExceeded));
        let after = crate::capabilities::GLOBAL_OBJECT_STORE.lock().count_for_tenant(9113);
        assert_eq!(before, after);
    }

    #[test]
    fn operations_are_audited_with_the_callers_identity() {
        let sp = MockUserSpace::new(8192);
        let a = proc(9114, 9114);
        let p = put(&sp, 0, b"audit");
        let h = decode(object_create(a, &sp, p, 5)).unwrap();
        let _ = object_read(a, &sp, h, USER_MIN + 1024, 16);
        let _ = object_read(a, &sp, h ^ (7 << 32), USER_MIN + 1024, 16);
        let events: Vec<_> = crate::audit::events_for_subject(9114);
        assert!(events.iter().any(|e| e.op == AuditOp::Create && e.outcome == AuditOutcome::Allowed));
        assert!(events.iter().any(|e| e.op == AuditOp::Read && e.outcome == AuditOutcome::Allowed));
        assert!(events.iter().any(|e| e.op == AuditOp::Read && matches!(e.outcome, AuditOutcome::Denied(_))));
    }
}
