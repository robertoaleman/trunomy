// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! `SystemInfo`: estado real del kernel para la shell (I-42).
//!
//! La shell no inventa nada: `free`, `ps`, `whoami`, `caps` y `tenant list` muestran lo que el
//! kernel entrega aqui. La autorizacion es de cada `kind` y la decide el kernel:
//! - Identity y TenantUsage: cualquiera, solo sobre si mismo / su tenant.
//! - Caps: las propias; las de otro sujeto solo el lider administrador y solo de miembros de la sesion.
//! - Memory, Processes, Actors: solo el lider administrador (revelan el estado de toda la maquina).
//! Todo es de solo lectura: no consume usos de capabilities ni cambia estado.

use alloc::vec::Vec;
use trunomy_abi::{sysinfo as k, Errno};

use crate::capabilities::{
    CapabilityState, ResourceType, GLOBAL_CAPABILITY_BOOK, GLOBAL_OBJECT_STORE, MAX_OBJECTS_PER_TENANT,
    MAX_OBJECT_PAYLOAD_BYTES,
};
use crate::process::ProcessContext;
use crate::proctab::{PState, PROCS};
use crate::syscall::identity::SESSION;
use crate::user_access::{UserSlice, UserSpace};

fn put<S: UserSpace>(out: &UserSlice, space: &S, words: &[u64]) -> Result<(), Errno> {
    out.write_words(space, words).map(|_| ()).map_err(|e| e.errno())
}

/// Cuantos registros de `rec_words` palabras caben en `out`.
fn capacity(out: &UserSlice, rec_words: usize) -> usize {
    out.len() / 8 / rec_words
}

fn type_code(t: ResourceType) -> u64 {
    match t {
        ResourceType::Data => k::RES_DATA,
        ResourceType::Pipe => k::RES_PIPE,
        ResourceType::Endpoint => k::RES_ENDPOINT,
        ResourceType::Task => k::RES_TASK,
    }
}

pub fn system_info<S: UserSpace>(current: ProcessContext, space: &S, kind: u64, ptr: u64, len: u64, arg: u64) -> u64 {
    info(current, space, kind, ptr, len, arg).unwrap_or_else(|e| e.code())
}

fn info<S: UserSpace>(current: ProcessContext, space: &S, kind: u64, ptr: u64, len: u64, arg: u64) -> Result<u64, Errno> {
    let out = UserSlice::new(ptr, len).map_err(|e| e.errno())?;
    match kind {
        k::IDENTITY => {
            put(&out, space, &[current.pid, current.tenant_id, current.subject_id])?;
            Ok(k::IDENTITY_WORDS as u64)
        }
        k::MEMORY => {
            if !SESSION.lock().is_admin(current) {
                return Err(Errno::PermissionDenied);
            }
            let (total, free) = {
                let a = crate::memory::frame_allocator::BITMAP_ALLOCATOR.lock();
                (a.total_frame_count() as u64, a.free_frames() as u64)
            };
            let (heap_total, heap_used) = crate::allocator::heap_stats();
            put(&out, space, &[total, free, heap_total, heap_used])?;
            Ok(k::MEMORY_WORDS as u64)
        }
        k::TENANT_USAGE => {
            let (objects, bytes) = {
                let s = GLOBAL_OBJECT_STORE.lock();
                (s.count_for_tenant(current.tenant_id) as u64, s.bytes_for_tenant(current.tenant_id) as u64)
            };
            put(&out, space, &[objects, MAX_OBJECTS_PER_TENANT as u64, bytes, MAX_OBJECT_PAYLOAD_BYTES as u64])?;
            Ok(k::TENANT_USAGE_WORDS as u64)
        }
        k::PROCESSES => {
            let leader = {
                let s = SESSION.lock();
                if !s.is_admin(current) {
                    return Err(Errno::PermissionDenied);
                }
                s.leader_pid()
            };
            // El lider no esta en la tabla de hijos: va primero (sin padre, corriendo).
            let mut words: Vec<u64> = alloc::vec![leader, 0, 0];
            for e in PROCS.lock().entries() {
                words.extend_from_slice(&[e.pid, e.parent, if matches!(e.state, PState::Running) { 0 } else { 1 }]);
            }
            let n = (words.len() / k::PROCESS_RECORD_WORDS).min(capacity(&out, k::PROCESS_RECORD_WORDS));
            put(&out, space, &words[..n * k::PROCESS_RECORD_WORDS])?;
            Ok(n as u64)
        }
        k::CAPS => {
            let subject = if arg == 0 || arg == current.subject_id {
                current.subject_id
            } else {
                let s = SESSION.lock();
                if !s.is_admin(current) {
                    return Err(Errno::PermissionDenied);
                }
                // Solo miembros de la sesion: no se sondean sujetos ajenos.
                if arg != s.leader_pid() && !s.is_actor(arg) {
                    return Err(Errno::InvalidArgument);
                }
                arg
            };
            let entries = GLOBAL_CAPABILITY_BOOK.lock().entries_of(subject);
            let mut words: Vec<u64> = Vec::with_capacity(entries.len() * k::CAP_RECORD_WORDS);
            for e in entries.iter().filter(|e| e.state == CapabilityState::Active).take(capacity(&out, k::CAP_RECORD_WORDS)) {
                words.extend_from_slice(&[
                    type_code(e.resource_type),
                    e.resource_id,
                    e.rights.bits() as u64,
                    e.remaining_uses.map_or(k::UNLIMITED, |u| u as u64),
                ]);
            }
            put(&out, space, &words)?;
            Ok((words.len() / k::CAP_RECORD_WORDS) as u64)
        }
        k::ACTORS => {
            let pids = {
                let s = SESSION.lock();
                if !s.is_admin(current) {
                    return Err(Errno::PermissionDenied);
                }
                s.actor_pids()
            };
            let mut words: Vec<u64> = Vec::new();
            for pid in pids.into_iter().take(capacity(&out, k::ACTOR_RECORD_WORDS)) {
                if let Some(c) = crate::process::process_context(pid) {
                    let state = SESSION.lock().actor_state(pid, c.tenant_id);
                    words.extend_from_slice(&[pid, c.tenant_id, state]);
                }
            }
            put(&out, space, &words)?;
            Ok((words.len() / k::ACTOR_RECORD_WORDS) as u64)
        }
        k::NET => {
            // Inventario de hardware: solo el lider (I-44), igual que memoria y procesos.
            if !SESSION.lock().is_admin(current) {
                return Err(Errno::PermissionDenied);
            }
            put(&out, space, &crate::net::info_words(&crate::net::state()))?;
            Ok(k::NET_WORDS as u64)
        }
        k::NET_STATS => {
            if !SESSION.lock().is_admin(current) {
                return Err(Errno::PermissionDenied);
            }
            put(&out, space, &crate::net::stats_words())?;
            Ok(k::NET_STATS_WORDS as u64)
        }
        _ => Err(Errno::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Rights;
    use crate::memory_validation::USER_MIN;
    use crate::process::register_process;
    use crate::syscall::identity::{Session, CAP_ADMIN};
    use crate::user_access::tests::MockUserSpace;

    fn words(sp: &MockUserSpace, n: usize) -> Vec<u64> {
        sp.mem.borrow()[..n * 8].chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
    }

    /// Sesion de prueba con su lider administrador y un tenant con dos actores. El lider real
    /// (`SESSION`) no se toca: las pruebas fijan su propia sesion en la global solo mientras corren
    /// bajo `serial()`.
    fn setup(pid: u64) -> (ProcessContext, u64, u64, u64, u64) {
        let lead = ProcessContext::new(pid, pid, pid);
        assert!(register_process(pid, lead));
        GLOBAL_CAPABILITY_BOOK.lock().try_grant(pid, pid, ResourceType::Task, CAP_ADMIN as u64, Rights::READ).unwrap();
        let mut s = Session::new(pid, pid * 1000, pid * 1000);
        let t = s.tenant_create(lead).unwrap();
        let a = s.actor_create(lead, t).unwrap();
        let b = s.actor_create(lead, t).unwrap();
        *SESSION.lock() = s;
        (lead, t, a, b, pid)
    }

    static SERIAL: spin::Mutex<()> = spin::Mutex::new(());

    #[test]
    fn identity_reports_the_callers_real_identity() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let who = ProcessContext::new(7001, 7001, 55);
        assert_eq!(info(who, &sp, k::IDENTITY, USER_MIN, 24, 0), Ok(3));
        assert_eq!(words(&sp, 3), [7001, 55, 7001]);
        // buffer corto: no escribe nada
        assert!(info(who, &sp, k::IDENTITY, USER_MIN, 16, 0).is_err());
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let sp = MockUserSpace::new(4096);
        let who = ProcessContext::new(7002, 7002, 1);
        assert_eq!(info(who, &sp, 99, USER_MIN, 64, 0), Err(Errno::InvalidArgument));
        assert_eq!(info(who, &sp, 0, USER_MIN, 64, 0), Err(Errno::InvalidArgument));
    }

    #[test]
    fn machine_wide_kinds_are_admin_only() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let (lead, _t, a, _b, _) = setup(7003);
        let actor = crate::process::process_context(a).unwrap();
        for kind in [k::MEMORY, k::PROCESSES, k::ACTORS, k::NET, k::NET_STATS] {
            assert_eq!(info(actor, &sp, kind, USER_MIN, 256, 0), Err(Errno::PermissionDenied), "kind {kind}");
            assert!(info(lead, &sp, kind, USER_MIN, 256, 0).is_ok(), "kind {kind}");
        }
        // un extrano (ni lider ni actor) tampoco
        let stranger = ProcessContext::new(7999, 7999, 7999);
        assert_eq!(info(stranger, &sp, k::MEMORY, USER_MIN, 256, 0), Err(Errno::PermissionDenied));
    }

    #[test]
    fn actors_listing_matches_the_session() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let (lead, t, a, b, _) = setup(7004);
        assert_eq!(info(lead, &sp, k::ACTORS, USER_MIN, 256, 0), Ok(2));
        assert_eq!(words(&sp, 6), [a, t, 0, b, t, 0]);
        // la capacidad del buffer acota los registros (un registro son 3 palabras)
        assert_eq!(info(lead, &sp, k::ACTORS, USER_MIN, 24, 0), Ok(1));
        assert!(info(lead, &sp, k::ACTORS, USER_MIN, 16, 0).is_ok(), "un buffer que no cabe ni un registro entrega 0");
    }

    #[test]
    fn actors_listing_reports_a_panicked_tenant_and_its_retired_actors() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let (lead, t, a, b, _) = setup(7014);
        SESSION.lock().quarantine(lead, t).unwrap();
        assert_eq!(info(lead, &sp, k::ACTORS, USER_MIN, 256, 0), Ok(2));
        let both = k::ACTOR_RETIRED | k::ACTOR_TENANT_FROZEN;
        assert_eq!(words(&sp, 6), [a, t, both, b, t, both]);
        SESSION.lock().thaw(lead, t).unwrap();
        assert_eq!(info(lead, &sp, k::ACTORS, USER_MIN, 256, 0), Ok(2));
        assert_eq!(words(&sp, 6), [a, t, k::ACTOR_RETIRED, b, t, k::ACTOR_RETIRED]);
    }

    #[test]
    fn caps_are_own_by_default_and_others_need_admin_and_membership() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let (lead, _t, a, b, _) = setup(7005);
        let actor_a = crate::process::process_context(a).unwrap();
        // el actor ve su propia capability global (object.create), sin limite de usos
        assert_eq!(info(actor_a, &sp, k::CAPS, USER_MIN, 256, 0), Ok(1));
        assert_eq!(words(&sp, 4), [k::RES_TASK, 4, 1, k::UNLIMITED]);
        // pedir las propias por pid explicito tambien vale
        assert_eq!(info(actor_a, &sp, k::CAPS, USER_MIN, 256, a), Ok(1));
        // pero no las de otro actor
        assert_eq!(info(actor_a, &sp, k::CAPS, USER_MIN, 256, b), Err(Errno::PermissionDenied));
        // el lider si, y de miembros solamente
        assert_eq!(info(lead, &sp, k::CAPS, USER_MIN, 256, b), Ok(1));
        assert_eq!(info(lead, &sp, k::CAPS, USER_MIN, 256, 424242), Err(Errno::InvalidArgument));
    }

    #[test]
    fn revoked_capabilities_are_not_listed_and_uses_are_reported() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let (lead, t, a, _b, _) = setup(7006);
        let mut book = GLOBAL_CAPABILITY_BOOK.lock();
        let h = book.try_grant(a, t, ResourceType::Data, 777, Rights::READ | Rights::WRITE).unwrap();
        drop(book);
        assert_eq!(info(lead, &sp, k::CAPS, USER_MIN, 256, a), Ok(2));
        assert_eq!(words(&sp, 8)[4..], [k::RES_DATA, 777, 3, k::UNLIMITED]);
        GLOBAL_CAPABILITY_BOOK.lock().revoke(a, h).unwrap();
        assert_eq!(info(lead, &sp, k::CAPS, USER_MIN, 256, a), Ok(1));
    }

    #[test]
    fn tenant_usage_counts_only_the_callers_tenant() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let a = ProcessContext::new(7007, 7007, 9701);
        let other = ProcessContext::new(7008, 7008, 9702);
        GLOBAL_OBJECT_STORE.lock().try_create(9701, 7007, ResourceType::Data, 1, Rights::READ, alloc::vec![0u8; 10]).unwrap();
        GLOBAL_OBJECT_STORE.lock().try_create(9701, 7007, ResourceType::Data, 2, Rights::READ, alloc::vec![0u8; 5]).unwrap();
        assert_eq!(info(a, &sp, k::TENANT_USAGE, USER_MIN, 32, 0), Ok(4));
        assert_eq!(words(&sp, 4), [2, MAX_OBJECTS_PER_TENANT as u64, 15, MAX_OBJECT_PAYLOAD_BYTES as u64]);
        assert_eq!(info(other, &sp, k::TENANT_USAGE, USER_MIN, 32, 0), Ok(4));
        assert_eq!(words(&sp, 4)[0], 0, "otro tenant no ve el uso ajeno");
    }

    #[test]
    fn processes_listing_starts_with_the_leader() {
        let _g = SERIAL.lock();
        let sp = MockUserSpace::new(4096);
        let (lead, _t, a, _b, pid) = setup(7009);
        PROCS.lock().spawn(a, pid).unwrap();
        let n = info(lead, &sp, k::PROCESSES, USER_MIN, 256, 0).unwrap() as usize;
        assert!(n >= 2);
        let w = words(&sp, n * 3);
        assert_eq!(w[..3], [pid, 0, 0]);
        assert!(w.chunks(3).any(|r| r == [a, pid, 0]));
        PROCS.lock().forget(a);
    }
}
