// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! `TenantPanic` / `TenantThaw` (I-45): corte de emergencia de un tenant.
//!
//! Hasta ahora solo la raiz podia detener algo (`Halt` apaga TODA la maquina). Con un tenant
//! comprometido hace falta cortar solo a ese. `TenantPanic(tenant, flags)`, solo el lider
//! administrador, hace en este orden:
//! 1. congela el tenant y retira a todos sus actores (no admite actores nuevos ni lanzamientos;
//!    una identidad retirada no vuelve a correr, ni siquiera tras `TenantThaw`);
//! 2. mata a los procesos vivos de esos actores y recoge sus restos (cada muerte queda auditada);
//! 3. revoca TODAS sus capabilities (y las derivadas): los handles que conocian dejan de valer;
//! 4. descarta los mensajes IPC pendientes enviados por o para ellos y cierra sus endpoints de red;
//! 5. con `FLAG_WIPE`, borra los objetos del tenant (zero-on-free);
//! 6. audita el corte (`AuditOp::Panic`, resource = tenant).
//! Cada fase toma sus candados por separado (nunca anidados). Repetirlo es inocuo.
//! `TenantThaw(tenant)` solo reabre el tenant para actores NUEVOS; no devuelve nada a los retirados.
//!

use spin::Mutex;
use trunomy_abi::{panic as abi_panic, Errno};

use super::identity::Session;
use super::spawn::{kill_child, Platform};
use crate::audit::{self, AuditOp, AuditOutcome};
use crate::capabilities::{CapabilityBook, CapabilityError, ObjectStore};
use crate::ipc::manager::IpcManager;
use crate::net::endpoint::Table;
use crate::process::ProcessContext;
use crate::proctab::{PState, ProcTable, WaitOutcome};

/// Audita una denegacion de quien no es el lider: repetible, por eso con limite (I-43).
fn deny_non_admin(current: ProcessContext, op: AuditOp, tenant: u64) {
    audit::record_throttled_denial(current.subject_id, op, Some(current.tenant_id), Some(tenant), CapabilityError::PermissionDenied);
}

pub fn tenant_panic_with<P: Platform>(
    current: ProcessContext,
    plat: &P,
    procs: &Mutex<ProcTable>,
    session: &Mutex<Session>,
    book: &Mutex<CapabilityBook>,
    store: &Mutex<ObjectStore>,
    ipc: &IpcManager,
    endpoints: &Mutex<Table>,
    tenant: u64,
    flags: u64,
) -> Result<u64, Errno> {
    if !session.lock().is_admin(current) {
        deny_non_admin(current, AuditOp::Panic, tenant);
        return Err(Errno::PermissionDenied);
    }
    // Argumentos invalidos: sin efectos (el lider puede equivocarse de nombre, no debe cortar nada).
    if flags & !abi_panic::KNOWN_FLAGS != 0 {
        return Err(Errno::InvalidArgument);
    }
    let members = match session.lock().quarantine(current, tenant) {
        Ok(m) => m,
        Err(e) => {
            audit::record(current.subject_id, AuditOp::Panic, None, Some(tenant), Some(tenant), AuditOutcome::Denied(CapabilityError::NotFound));
            return Err(e);
        }
    };

    // 2. Procesos vivos: matar y recoger (la shell raiz es su padre).
    let mut killed = 0u64;
    for pid in &members {
        let state = procs.lock().get(*pid).map(|e| e.state);
        if state == Some(PState::Running) && kill_child(current, plat, procs, *pid, trunomy_abi::exit::KILLED).is_ok() {
            killed += 1;
        }
        let r = procs.lock().wait_output(current.pid, *pid);
        if let Ok((WaitOutcome::Reaped(_), _)) = r {
            plat.reap(*pid);
        }
    }

    // 3. Capabilities.
    let mut revoked = 0u64;
    {
        let mut b = book.lock();
        for pid in &members {
            revoked += b.revoke_subject(*pid) as u64;
        }
    }

    // 4. IPC y red: mensajes pendientes descartados y endpoints del tenant cerrados (I-47).
    ipc.purge_pids(&members);
    endpoints.lock().close_tenant(tenant);

    // 5. Datos.
    let wiped = if flags & abi_panic::FLAG_WIPE != 0 { store.lock().purge_tenant(tenant) as u64 } else { 0 };

    audit::record(current.subject_id, AuditOp::Panic, None, Some(tenant), Some(tenant), AuditOutcome::Allowed);
    Ok(abi_panic::pack(killed, revoked, wiped))
}

pub fn tenant_thaw_with(current: ProcessContext, session: &Mutex<Session>, tenant: u64) -> Result<u64, Errno> {
    if !session.lock().is_admin(current) {
        deny_non_admin(current, AuditOp::Thaw, tenant);
        return Err(Errno::PermissionDenied);
    }
    let r = session.lock().thaw(current, tenant);
    let outcome = match r {
        Ok(()) => AuditOutcome::Allowed,
        Err(_) => AuditOutcome::Denied(CapabilityError::NotFound),
    };
    audit::record(current.subject_id, AuditOp::Thaw, None, Some(tenant), Some(tenant), outcome);
    r.map(|_| 0)
}

// --- Entradas del dispatcher (estado global) ---

#[cfg(not(test))]
pub fn tenant_panic(current: ProcessContext, tenant: u64, flags: u64) -> u64 {
    use crate::capabilities::{GLOBAL_CAPABILITY_BOOK, GLOBAL_OBJECT_STORE};
    tenant_panic_with(
        current,
        &crate::dispatch::HwPlatform,
        &crate::proctab::PROCS,
        &super::identity::SESSION,
        &GLOBAL_CAPABILITY_BOOK,
        &GLOBAL_OBJECT_STORE,
        &crate::ipc::manager::IPC_MANAGER,
        &crate::net::ENDPOINTS,
        tenant,
        flags,
    )
    .unwrap_or_else(|e| e.code())
}

#[cfg(test)]
pub fn tenant_panic(_current: ProcessContext, _tenant: u64, _flags: u64) -> u64 {
    Errno::ResourceUnavailable.code()
}

pub fn tenant_thaw(current: ProcessContext, tenant: u64) -> u64 {
    tenant_thaw_with(current, &super::identity::SESSION, tenant).unwrap_or_else(|e| e.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{ResourceType, Rights, GLOBAL_CAPABILITY_BOOK};
    use crate::process::{process_context, register_process};
    use crate::syscall::identity::CAP_ADMIN;
    use core::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        terminated: RefCell<alloc::vec::Vec<u64>>,
        reaped: RefCell<alloc::vec::Vec<u64>>,
    }

    impl Platform for Fake {
        fn create_process(&self, _c: ProcessContext, _a: &[u8]) -> Result<(), Errno> {
            Ok(())
        }
        fn exit_current(&self, _pid: u64, _w: Option<u64>) {}
        fn reap(&self, pid: u64) {
            self.reaped.borrow_mut().push(pid);
        }
        fn block_for_child(&self, _c: u64, _d: Option<u64>) {}
        fn now(&self) -> u64 {
            0
        }
        fn terminate(&self, pid: u64, _w: Option<u64>) {
            self.terminated.borrow_mut().push(pid);
        }
        fn admit_memory(&self) -> Result<(), Errno> {
            Ok(())
        }
        fn cpu_quota_exceeded(&self, _pid: u64) -> bool {
            false
        }
    }

    struct World {
        lead: ProcessContext,
        session: Mutex<Session>,
        procs: Mutex<ProcTable>,
        store: Mutex<ObjectStore>,
        ipc: IpcManager,
        endpoints: Mutex<Table>,
        plat: Fake,
        /// tenant A y B, con dos actores en A (a1, a2) y uno en B (b1).
        ta: u64,
        tb: u64,
        a1: u64,
        a2: u64,
        b1: u64,
    }

    /// Mundo de prueba con ids unicos por test (el libro de capabilities y la tabla de procesos son globales).
    fn world(base: u64) -> World {
        let lead = ProcessContext::new(base, base, base);
        assert!(register_process(base, lead));
        GLOBAL_CAPABILITY_BOOK.lock().try_grant(base, base, ResourceType::Task, CAP_ADMIN as u64, Rights::READ).unwrap();
        let mut s = Session::new(base, base * 1000, base * 1000);
        let ta = s.tenant_create(lead).unwrap();
        let tb = s.tenant_create(lead).unwrap();
        let a1 = s.actor_create_with(lead, ta, trunomy_abi::actor::FLAG_IPC).unwrap();
        let a2 = s.actor_create_with(lead, ta, trunomy_abi::actor::FLAG_IPC).unwrap();
        let b1 = s.actor_create_with(lead, tb, trunomy_abi::actor::FLAG_IPC).unwrap();
        World {
            lead,
            session: Mutex::new(s),
            procs: Mutex::new(ProcTable::new()),
            store: Mutex::new(ObjectStore::new()),
            ipc: IpcManager::new(),
            endpoints: Mutex::new(Table::new()),
            plat: Fake::default(),
            ta,
            tb,
            a1,
            a2,
            b1,
        }
    }

    fn panic(w: &World, tenant: u64, flags: u64) -> Result<u64, Errno> {
        tenant_panic_with(w.lead, &w.plat, &w.procs, &w.session, &GLOBAL_CAPABILITY_BOOK, &w.store, &w.ipc, &w.endpoints, tenant, flags)
    }

    fn denied(code: Result<u64, Errno>) -> bool {
        code == Err(Errno::PermissionDenied)
    }

    #[test]
    fn a_panicked_tenant_cannot_spawn_and_cannot_get_new_actors() {
        let w = world(7601);
        assert!(w.session.lock().authorize_spawn(w.lead, w.a1).is_ok());
        panic(&w, w.ta, 0).unwrap();
        assert!(w.session.lock().is_frozen(w.ta));
        for actor in [w.a1, w.a2] {
            assert_eq!(w.session.lock().authorize_spawn(w.lead, actor), Err(Errno::PermissionDenied), "retirado: no corre");
        }
        assert_eq!(w.session.lock().actor_create_with(w.lead, w.ta, 0), Err(Errno::PermissionDenied), "congelado: sin actores nuevos");
        // el otro tenant sigue funcionando
        assert!(!w.session.lock().is_frozen(w.tb));
        assert!(w.session.lock().authorize_spawn(w.lead, w.b1).is_ok());
        assert!(w.session.lock().actor_create_with(w.lead, w.tb, 0).is_ok());
    }

    #[test]
    fn a_refused_spawn_is_audited() {
        let w = world(7602);
        panic(&w, w.ta, 0).unwrap();
        let _ = w.session.lock().authorize_spawn(w.lead, w.a1);
        let ev = audit::events_for_subject(w.lead.subject_id);
        assert!(ev.iter().any(|e| e.op == AuditOp::Identity && e.resource_id == Some(w.a1) && matches!(e.outcome, AuditOutcome::Denied(_))));
        assert!(ev.iter().any(|e| e.op == AuditOp::Panic && e.resource_id == Some(w.ta) && e.outcome == AuditOutcome::Allowed));
    }

    #[test]
    fn live_workers_are_killed_and_reaped_and_zombies_do_not_leak_slots() {
        let w = world(7603);
        // a1 corre; a2 ya termino pero nadie lo recogio; b1 (otro tenant) tambien corre
        for pid in [w.a1, w.a2, w.b1] {
            w.procs.lock().spawn(pid, w.lead.pid).unwrap();
        }
        w.procs.lock().exit(w.a2, 3).unwrap();
        let packed = panic(&w, w.ta, 0).unwrap();
        let (killed, _, _) = abi_panic::unpack(packed);
        assert_eq!(killed, 1, "solo a1 estaba vivo");
        assert_eq!(*w.plat.terminated.borrow(), alloc::vec![w.a1]);
        let mut reaped = w.plat.reaped.borrow().clone();
        reaped.sort();
        assert_eq!(reaped, alloc::vec![w.a1, w.a2], "se recogen el matado y el zombie viejo");
        let gone = |pid: u64| w.procs.lock().get(pid).is_none();
        assert!(gone(w.a1), "la tabla queda libre");
        assert!(gone(w.a2), "la tabla queda libre");
        assert_eq!(w.procs.lock().get(w.b1).unwrap().state, PState::Running, "el otro tenant ni se entera");
        let ev = audit::events_for_subject(w.lead.subject_id);
        assert!(ev.iter().any(|e| e.op == AuditOp::ProcessKill && e.resource_id == Some(w.a1) && e.outcome == AuditOutcome::Allowed));
    }

    #[test]
    fn every_capability_is_revoked_and_known_handles_stop_working() {
        let w = world(7604);
        let h = GLOBAL_CAPABILITY_BOOK.lock().try_grant(w.a1, w.ta, ResourceType::Data, 5, Rights::READ).unwrap();
        let hb = GLOBAL_CAPABILITY_BOOK.lock().try_grant(w.b1, w.tb, ResourceType::Data, 6, Rights::READ).unwrap();
        assert!(GLOBAL_CAPABILITY_BOOK.lock().lookup(w.a1, h, Rights::READ, ResourceType::Data).is_ok());
        let count = |pid: u64| GLOBAL_CAPABILITY_BOOK.lock().entries_of(pid).len();
        let before = count(w.a1) + count(w.a2);
        let (_, revoked, _) = abi_panic::unpack(panic(&w, w.ta, 0).unwrap());
        assert_eq!(revoked as usize, before, "se cuenta cada capability que dejo de estar activa");
        assert!(before >= 5, "object.create + ipc.send + ipc.recv por actor, mas el dato: {before}");
        assert!(GLOBAL_CAPABILITY_BOOK.lock().lookup(w.a1, h, Rights::READ, ResourceType::Data).is_err(), "el handle conocido ya no vale");
        assert!(GLOBAL_CAPABILITY_BOOK.lock().entries_of(w.a1).is_empty());
        assert!(GLOBAL_CAPABILITY_BOOK.lock().entries_of(w.a2).is_empty());
        // el otro tenant conserva las suyas
        assert!(GLOBAL_CAPABILITY_BOOK.lock().lookup(w.b1, hb, Rights::READ, ResourceType::Data).is_ok());
        assert!(!GLOBAL_CAPABILITY_BOOK.lock().entries_of(w.b1).is_empty());
    }

    #[test]
    fn derived_capabilities_die_with_their_parent() {
        let w = world(7605);
        let parent = GLOBAL_CAPABILITY_BOOK
            .lock()
            .try_grant(w.a1, w.ta, ResourceType::Data, 9, Rights::READ | Rights::DELEGATE)
            .unwrap();
        let child = GLOBAL_CAPABILITY_BOOK.lock().delegate(w.a1, parent, w.a2, Rights::READ).unwrap();
        assert!(GLOBAL_CAPABILITY_BOOK.lock().lookup(w.a2, child, Rights::READ, ResourceType::Data).is_ok());
        panic(&w, w.ta, 0).unwrap();
        assert!(GLOBAL_CAPABILITY_BOOK.lock().lookup(w.a2, child, Rights::READ, ResourceType::Data).is_err());
    }

    #[test]
    fn ipc_messages_from_or_to_the_tenant_are_dropped_and_others_stay() {
        let w = world(7606);
        w.ipc.enqueue_message(w.a1, w.a2, 1, [1, 0, 0, 0]).unwrap();
        w.ipc.enqueue_message(w.a2, w.a1, 1, [2, 0, 0, 0]).unwrap();
        w.ipc.enqueue_message(w.b1, w.lead.pid + 1, 1, [3, 0, 0, 0]).unwrap();
        panic(&w, w.ta, 0).unwrap();
        assert_eq!(w.ipc.queue_len(), 1, "solo queda el mensaje del otro tenant");
        assert_eq!(w.ipc.pending_for(w.a1) + w.ipc.pending_for(w.a2), 0);
    }

    #[test]
    fn wipe_deletes_only_that_tenants_objects_and_only_when_asked() {
        let w = world(7607);
        for (t, owner, id) in [(w.ta, w.a1, 1u64), (w.ta, w.a2, 2), (w.tb, w.b1, 3)] {
            w.store.lock().try_create(t, owner, ResourceType::Data, id, Rights::READ, alloc::vec![7; 16]).unwrap();
        }
        let (_, _, none) = abi_panic::unpack(panic(&w, w.ta, 0).unwrap());
        assert_eq!(none, 0);
        assert_eq!(w.store.lock().count_for_tenant(w.ta), 2, "sin wipe los datos quedan (inalcanzables, no destruidos)");
        let (_, _, wiped) = abi_panic::unpack(panic(&w, w.ta, abi_panic::FLAG_WIPE).unwrap());
        assert_eq!(wiped, 2);
        assert_eq!(w.store.lock().count_for_tenant(w.ta), 0);
        assert_eq!(w.store.lock().count_for_tenant(w.tb), 1, "el otro tenant conserva sus datos");
    }

    #[test]
    fn only_the_session_leader_can_panic_and_a_refusal_changes_nothing() {
        let w = world(7608);
        let actor_ctx = process_context(w.a1).unwrap();
        let other_tenant_actor = process_context(w.b1).unwrap();
        for who in [actor_ctx, other_tenant_actor, ProcessContext::new(7999, 7999, 7999)] {
            let r = tenant_panic_with(who, &w.plat, &w.procs, &w.session, &GLOBAL_CAPABILITY_BOOK, &w.store, &w.ipc, &w.endpoints, w.ta, 0);
            assert!(denied(r), "{who:?}");
            assert!(denied(tenant_thaw_with(who, &w.session, w.ta)));
        }
        let frozen = |t: u64| w.session.lock().is_frozen(t);
        assert!(!frozen(w.ta), "nada cambio");
        assert!(!frozen(w.tb), "nada cambio");
        assert!(!GLOBAL_CAPABILITY_BOOK.lock().entries_of(w.a1).is_empty());
        let ev = audit::events_for_subject(w.a1);
        assert!(ev.iter().any(|e| e.op == AuditOp::Panic && matches!(e.outcome, AuditOutcome::Denied(_))), "el intento queda auditado");
    }

    #[test]
    fn a_hostile_actor_cannot_flood_the_audit_log_with_panic_attempts() {
        let w = world(7609);
        let actor_ctx = process_context(w.a1).unwrap();
        for _ in 0..200 {
            let _ = tenant_panic_with(actor_ctx, &w.plat, &w.procs, &w.session, &GLOBAL_CAPABILITY_BOOK, &w.store, &w.ipc, &w.endpoints, w.ta, 0);
        }
        let stored = audit::events_for_subject(w.a1).iter().filter(|e| e.op == AuditOp::Panic).count();
        assert!(stored <= 8, "el limite de denegaciones repetidas rige tambien aqui: {stored}");
    }

    #[test]
    fn unknown_tenant_or_flags_do_nothing() {
        let w = world(7610);
        assert_eq!(panic(&w, 424242, 0), Err(Errno::InvalidArgument));
        assert_eq!(panic(&w, w.ta, 1 << 7), Err(Errno::InvalidArgument), "bandera desconocida: no se corta nada");
        assert!(!w.session.lock().is_frozen(w.ta));
        assert!(!GLOBAL_CAPABILITY_BOOK.lock().entries_of(w.a1).is_empty());
        assert!(w.plat.terminated.borrow().is_empty());
    }

    #[test]
    fn network_endpoints_of_the_tenant_are_closed_and_other_tenants_keep_theirs() {
        use crate::net::endpoint::Owner;
        let w = world(7620);
        let own = |pid: u64, tenant: u64| Owner { pid, tenant, subject: pid };
        {
            let mut t = w.endpoints.lock();
            t.bind(100, own(w.a1, w.ta)).unwrap();
            t.bind(101, own(w.a2, w.ta)).unwrap();
            t.bind(200, own(w.b1, w.tb)).unwrap();
        }
        panic(&w, w.ta, 0).unwrap();
        let t = w.endpoints.lock();
        assert_eq!((t.count_for_tenant(w.ta), t.count_for_tenant(w.tb)), (0, 1));
        assert!(t.owns(200, w.b1));
    }

    #[test]
    fn a_refused_panic_does_not_touch_the_network() {
        use crate::net::endpoint::Owner;
        let w = world(7622);
        w.endpoints.lock().bind(100, Owner { pid: w.a1, tenant: w.ta, subject: w.a1 }).unwrap();
        let actor = crate::process::process_context(w.a1).unwrap();
        let r = tenant_panic_with(actor, &w.plat, &w.procs, &w.session, &GLOBAL_CAPABILITY_BOOK, &w.store, &w.ipc, &w.endpoints, w.ta, 0);
        assert_eq!(r, Err(Errno::PermissionDenied));
        assert_eq!(w.endpoints.lock().len(), 1);
    }

    #[test]
    fn panic_is_idempotent() {
        let w = world(7611);
        let first = panic(&w, w.ta, 0).unwrap();
        let (_, revoked_first, _) = abi_panic::unpack(first);
        assert!(revoked_first > 0);
        let (k, r, x) = abi_panic::unpack(panic(&w, w.ta, 0).unwrap());
        assert_eq!((k, r, x), (0, 0, 0), "la segunda vez ya no queda nada que cortar");
        assert!(w.session.lock().is_frozen(w.ta));
    }

    #[test]
    fn thaw_reopens_the_tenant_for_new_actors_but_never_for_retired_ones() {
        let w = world(7612);
        assert_eq!(tenant_thaw_with(w.lead, &w.session, w.ta), Err(Errno::InvalidArgument), "no estaba congelado");
        panic(&w, w.ta, 0).unwrap();
        assert_eq!(tenant_thaw_with(w.lead, &w.session, w.ta), Ok(0));
        assert!(!w.session.lock().is_frozen(w.ta));
        let fresh = w.session.lock().actor_create_with(w.lead, w.ta, 0).expect("actores nuevos si");
        assert!(w.session.lock().authorize_spawn(w.lead, fresh).is_ok());
        for old in [w.a1, w.a2] {
            assert_eq!(w.session.lock().authorize_spawn(w.lead, old), Err(Errno::PermissionDenied), "los retirados siguen retirados");
            assert!(GLOBAL_CAPABILITY_BOOK.lock().entries_of(old).is_empty(), "y sin capabilities");
        }
        let ev = audit::events_for_subject(w.lead.subject_id);
        assert!(ev.iter().any(|e| e.op == AuditOp::Thaw && e.outcome == AuditOutcome::Allowed));
    }

    #[test]
    fn the_actor_state_reports_retired_and_frozen() {
        use trunomy_abi::sysinfo::{ACTOR_RETIRED, ACTOR_TENANT_FROZEN};
        let w = world(7613);
        assert_eq!(w.session.lock().actor_state(w.a1, w.ta), 0);
        panic(&w, w.ta, 0).unwrap();
        assert_eq!(w.session.lock().actor_state(w.a1, w.ta), ACTOR_RETIRED | ACTOR_TENANT_FROZEN);
        assert_eq!(w.session.lock().actor_state(w.b1, w.tb), 0);
        tenant_thaw_with(w.lead, &w.session, w.ta).unwrap();
        assert_eq!(w.session.lock().actor_state(w.a1, w.ta), ACTOR_RETIRED, "descongelado pero retirado");
    }
}
