// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Sesion de consola: tenants, usuarios (actores) y autorizacion para lanzar procesos.
//!
//! El proceso LIDER de la sesion (pid 1, la shell raiz) crea tenants y actores y lanza
//! procesos con la identidad de un actor (`ProcessSpawn`). Reglas:
//! - Solo el lider, y solo si tiene la capability global `CAP_ADMIN`.
//! - Un actor solo puede ser un miembro de la sesion (creado por el lider).
//! - Cada lanzamiento queda auditado (`AuditOp::Identity`).
//! - Tenants y actores acotados (`MAX_TENANTS`, `MAX_ACTORS`).
//! Ya no existe `SwitchIdentity`: cada actor actua como un proceso real con su propio
//! espacio de direcciones.

use alloc::collections::BTreeSet;
use spin::Mutex;
use trunomy_abi::{audit as abi_audit, Errno};

use crate::audit::{self, AuditEvent, AuditOp, AuditOutcome};
use crate::capabilities::{ResourceType, Rights, GLOBAL_CAPABILITY_BOOK};
use crate::process::{process_context, register_process, validate_process_capability, ProcessContext};
use crate::syscall::errno_of;
use crate::user_access::{UserSlice, UserSpace};

pub const CAP_ADMIN: u32 = 0x0005;
pub const MAX_TENANTS: usize = 8;
pub const MAX_ACTORS: usize = 16;
const CAP_OBJECT_CREATE_ID: u64 = 4;

pub struct Session {
    leader_pid: u64,
    next_tenant: u64,
    next_pid: u64,
    tenants: BTreeSet<u64>,
    actors: BTreeSet<u64>,
    /// Tenants cortados por `TenantPanic` (I-45): no admiten actores nuevos ni lanzamientos.
    frozen: BTreeSet<u64>,
    /// Actores retirados por un panic: su identidad no vuelve a lanzarse, ni siquiera tras `thaw`.
    retired: BTreeSet<u64>,
}

/// Las bases (1000) quedan lejos de los ids del harness de depuracion (10, 20, 100, 200)
/// para que un actor nuevo nunca herede el libro de capabilities de otro sujeto.
pub static SESSION: Mutex<Session> = Mutex::new(Session::new(1, 1000, 1000));

impl Session {
    pub const fn new(leader_pid: u64, tenant_base: u64, pid_base: u64) -> Self {
        Self { leader_pid, next_tenant: tenant_base, next_pid: pid_base, tenants: BTreeSet::new(), actors: BTreeSet::new(), frozen: BTreeSet::new(), retired: BTreeSet::new() }
    }

    pub fn is_actor(&self, pid: u64) -> bool {
        self.actors.contains(&pid)
    }

    pub fn leader_pid(&self) -> u64 {
        self.leader_pid
    }

    /// Solo el lider de la sesion, y solo con `CAP_ADMIN`. Los actores (procesos lanzados) no
    /// administran la sesion aunque sean miembros.
    fn require_admin(&self, current: ProcessContext) -> Result<ProcessContext, Errno> {
        if current.pid != self.leader_pid {
            return Err(Errno::PermissionDenied);
        }
        let leader = process_context(self.leader_pid).ok_or(Errno::PermissionDenied)?;
        if validate_process_capability(leader, CAP_ADMIN) {
            Ok(leader)
        } else {
            Err(Errno::PermissionDenied)
        }
    }

    /// El llamante es el lider de la sesion y tiene `CAP_ADMIN` (sin tocar la auditoria).
    pub fn is_admin(&self, current: ProcessContext) -> bool {
        self.require_admin(current).is_ok()
    }

    #[cfg(test)]
    pub fn is_frozen(&self, tenant: u64) -> bool {
        self.frozen.contains(&tenant)
    }

    #[cfg(test)]
    pub fn is_retired(&self, pid: u64) -> bool {
        self.retired.contains(&pid)
    }

    /// Estado de un actor para `SystemInfo(ACTORS)`: bits `abi::sysinfo::ACTOR_*`.
    pub fn actor_state(&self, pid: u64, tenant: u64) -> u64 {
        use trunomy_abi::sysinfo::{ACTOR_RETIRED, ACTOR_TENANT_FROZEN};
        (if self.retired.contains(&pid) { ACTOR_RETIRED } else { 0 })
            | (if self.frozen.contains(&tenant) { ACTOR_TENANT_FROZEN } else { 0 })
    }

    /// Primera fase de `TenantPanic`: congela el tenant y retira a todos sus actores. Devuelve los
    /// pids de esos actores. Solo el lider administrador; un tenant desconocido es `InvalidArgument`.
    /// Repetirlo es inocuo (vuelve a devolver los actores para que el corte se complete).
    pub fn quarantine(&mut self, current: ProcessContext, tenant: u64) -> Result<alloc::vec::Vec<u64>, Errno> {
        self.require_admin(current)?;
        if !self.tenants.contains(&tenant) {
            return Err(Errno::InvalidArgument);
        }
        self.frozen.insert(tenant);
        let members: alloc::vec::Vec<u64> = self
            .actors
            .iter()
            .copied()
            .filter(|pid| process_context(*pid).map_or(false, |c| c.tenant_id == tenant))
            .collect();
        self.retired.extend(members.iter().copied());
        Ok(members)
    }

    /// `TenantThaw`: el tenant vuelve a admitir actores NUEVOS. Los retirados siguen retirados.
    pub fn thaw(&mut self, current: ProcessContext, tenant: u64) -> Result<(), Errno> {
        self.require_admin(current)?;
        if !self.frozen.remove(&tenant) {
            return Err(Errno::InvalidArgument);
        }
        Ok(())
    }

    /// Pids de los actores de la sesion, en orden.
    pub fn actor_pids(&self) -> alloc::vec::Vec<u64> {
        self.actors.iter().copied().collect()
    }

    /// TenantCreate -> id del tenant nuevo.
    pub fn tenant_create(&mut self, current: ProcessContext) -> Result<u64, Errno> {
        self.require_admin(current)?;
        if self.tenants.len() >= MAX_TENANTS {
            return Err(Errno::QuotaExceeded);
        }
        let id = self.next_tenant;
        self.next_tenant += 1;
        self.tenants.insert(id);
        Ok(id)
    }

    /// ActorCreate(tenant) -> pid del actor. Recibe CAP_OBJECT_CREATE en su tenant.
    #[cfg(test)]
    pub fn actor_create(&mut self, current: ProcessContext, tenant: u64) -> Result<u64, Errno> {
        self.actor_create_with(current, tenant, 0)
    }

    /// `flags` (`abi::actor`): `FLAG_IPC` da al actor las capabilities globales de enviar y recibir
    /// mensajes y `FLAG_NET` las de red. Una bandera desconocida se rechaza y no se crea nada. La concesion queda auditada.
    pub fn actor_create_with(&mut self, current: ProcessContext, tenant: u64, flags: u64) -> Result<u64, Errno> {
        self.require_admin(current)?;
        if flags & !trunomy_abi::actor::KNOWN_FLAGS != 0 {
            return Err(Errno::InvalidArgument);
        }
        if !self.tenants.contains(&tenant) {
            return Err(Errno::InvalidArgument);
        }
        if self.frozen.contains(&tenant) {
            return Err(Errno::PermissionDenied);
        }
        if self.actors.len() >= MAX_ACTORS {
            return Err(Errno::QuotaExceeded);
        }
        let pid = self.next_pid;
        self.next_pid += 1;
        let ctx = ProcessContext::new(pid, pid, tenant);
        GLOBAL_CAPABILITY_BOOK
            .lock()
            .try_grant(pid, tenant, ResourceType::Task, CAP_OBJECT_CREATE_ID, Rights::READ)
            .map_err(errno_of)?;
        let ipc = flags & trunomy_abi::actor::FLAG_IPC != 0;
        if ipc {
            let mut book = GLOBAL_CAPABILITY_BOOK.lock();
            for cap in [crate::ipc::security::CAP_IPC_SEND, crate::ipc::security::CAP_IPC_RECV] {
                book.try_grant(pid, tenant, ResourceType::Task, cap as u64, Rights::READ).map_err(errno_of)?;
            }
        }
        let net = flags & trunomy_abi::actor::FLAG_NET != 0;
        if net {
            let mut book = GLOBAL_CAPABILITY_BOOK.lock();
            for cap in [super::CAP_NET_SEND, super::CAP_NET_RECV] {
                book.try_grant(pid, tenant, ResourceType::Task, cap as u64, Rights::READ).map_err(errno_of)?;
            }
        }
        if !register_process(pid, ctx) {
            return Err(Errno::ResourceUnavailable);
        }
        self.actors.insert(pid);
        if ipc || net {
            audit::record(current.subject_id, AuditOp::Grant, None, Some(tenant), Some(pid), AuditOutcome::Allowed);
        }
        Ok(pid)
    }

    /// Autoriza `ProcessSpawn(actor)`: devuelve la identidad con la que correra el proceso hijo.
    /// Solo el lider administrador, solo para actores de la sesion. Audita el lanzamiento.
    pub fn authorize_spawn(&self, current: ProcessContext, actor_pid: u64) -> Result<ProcessContext, Errno> {
        self.require_admin(current)?;
        if !self.actors.contains(&actor_pid) {
            return Err(Errno::InvalidArgument);
        }
        let target = process_context(actor_pid).ok_or(Errno::InvalidArgument)?;
        if self.retired.contains(&actor_pid) || self.frozen.contains(&target.tenant_id) {
            // Un tenant cortado (o una identidad retirada) no vuelve a correr nada (I-45).
            audit::record(
                current.subject_id,
                AuditOp::Identity,
                None,
                Some(target.tenant_id),
                Some(target.pid),
                AuditOutcome::Denied(crate::capabilities::CapabilityError::PermissionDenied),
            );
            return Err(Errno::PermissionDenied);
        }
        audit::record(
            current.subject_id,
            AuditOp::Identity,
            None,
            Some(target.tenant_id),
            Some(target.pid),
            AuditOutcome::Allowed,
        );
        Ok(target)
    }

    /// AuditRead(buf, len, after_seq) -> registros escritos (solo admin de la sesion).
    pub fn audit_read<S: UserSpace>(
        &self,
        current: ProcessContext,
        space: &S,
        ptr: u64,
        len: u64,
        after_seq: u64,
    ) -> Result<u64, Errno> {
        self.require_admin(current)?;
        let out = UserSlice::new(ptr, len).map_err(|e| e.errno())?;
        let capacity = out.len() / abi_audit::RECORD_SIZE;
        let events: alloc::vec::Vec<AuditEvent> = audit::GLOBAL_AUDIT_LOG
            .lock()
            .events()
            .into_iter()
            .filter(|e| e.seq > after_seq)
            .take(capacity)
            .collect();
        let mut raw = alloc::vec::Vec::with_capacity(events.len() * abi_audit::RECORD_SIZE);
        for e in &events {
            raw.extend_from_slice(&record_of(e).encode());
        }
        out.write_from(space, &raw).map_err(|e| e.errno())?;
        Ok(events.len() as u64)
    }
}

fn record_of(e: &AuditEvent) -> abi_audit::Record {
    abi_audit::Record {
        seq: e.seq,
        subject: e.subject_id,
        tenant: e.tenant_id.unwrap_or(0),
        resource: e.resource_id.unwrap_or(0),
        handle: e.handle.map_or(0, |h| trunomy_abi::Handle::new(h.slot, h.generation).0),
        op: match e.op {
            AuditOp::Read => abi_audit::OP_READ,
            AuditOp::Write => abi_audit::OP_WRITE,
            AuditOp::Delete => abi_audit::OP_DELETE,
            AuditOp::Grant => abi_audit::OP_GRANT,
            AuditOp::Delegate => abi_audit::OP_DELEGATE,
            AuditOp::Revoke => abi_audit::OP_REVOKE,
            AuditOp::Create => abi_audit::OP_CREATE,
            AuditOp::Identity => abi_audit::OP_IDENTITY,
            AuditOp::ProcessFault => abi_audit::OP_FAULT,
            AuditOp::ProcessKill => abi_audit::OP_KILL,
            AuditOp::Console => abi_audit::OP_CONSOLE,
            AuditOp::Halt => abi_audit::OP_HALT,
            AuditOp::Ipc => abi_audit::OP_IPC,
            AuditOp::Panic => abi_audit::OP_PANIC,
            AuditOp::Thaw => abi_audit::OP_THAW,
            AuditOp::Net => abi_audit::OP_NET,
        },
        outcome: match e.outcome {
            AuditOutcome::Allowed => 0,
            AuditOutcome::Denied(err) => errno_of(err).code() as u8,
        },
    }
}

fn finish(r: Result<u64, Errno>) -> u64 {
    r.unwrap_or_else(|e| e.code())
}

// --- Entradas del dispatcher (estado global) ---

pub fn tenant_create(current: ProcessContext) -> u64 {
    finish(SESSION.lock().tenant_create(current))
}

pub fn actor_create(current: ProcessContext, tenant: u64, flags: u64) -> u64 {
    finish(SESSION.lock().actor_create_with(current, tenant, flags))
}

/// Autorizacion de `ProcessSpawn` contra la sesion global.
pub fn authorize_spawn(current: ProcessContext, actor_pid: u64) -> Result<ProcessContext, Errno> {
    SESSION.lock().authorize_spawn(current, actor_pid)
}

pub fn audit_read<S: UserSpace>(current: ProcessContext, space: &S, ptr: u64, len: u64, after_seq: u64) -> u64 {
    finish(SESSION.lock().audit_read(current, space, ptr, len, after_seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_validation::USER_MIN;
    use crate::user_access::tests::MockUserSpace;
    use trunomy_abi::decode;

    /// Lider de prueba con su propia identidad (ids unicos por test).
    fn leader(pid: u64, admin: bool) -> (ProcessContext, Session) {
        let ctx = ProcessContext::new(pid, pid, pid);
        assert!(register_process(pid, ctx));
        if admin {
            GLOBAL_CAPABILITY_BOOK
                .lock()
                .try_grant(pid, pid, ResourceType::Task, CAP_ADMIN as u64, Rights::READ)
                .unwrap();
        }
        (ctx, Session::new(pid, pid * 1000, pid * 1000))
    }

    #[test]
    fn leader_without_admin_cannot_do_anything() {
        let (ctx, mut s) = leader(8001, false);
        assert_eq!(s.tenant_create(ctx), Err(Errno::PermissionDenied));
        assert_eq!(s.actor_create(ctx, 1), Err(Errno::PermissionDenied));
        assert_eq!(s.authorize_spawn(ctx, 8001).err(), Some(Errno::PermissionDenied));
    }

    #[test]
    fn strangers_cannot_use_the_session_even_if_leader_is_admin() {
        let (_ctx, mut s) = leader(8002, true);
        let stranger = ProcessContext::new(8999, 8999, 8999);
        assert_eq!(s.tenant_create(stranger), Err(Errno::PermissionDenied));
    }

    #[test]
    fn tenants_actors_and_spawn_authorization() {
        let (ctx, mut s) = leader(8003, true);
        let t = s.tenant_create(ctx).unwrap();
        let a = s.actor_create(ctx, t).unwrap();
        let ac = process_context(a).unwrap();
        assert_eq!((ac.subject_id, ac.tenant_id), (a, t));
        // el lider puede lanzar procesos como un actor de su sesion y obtiene su identidad
        let child = s.authorize_spawn(ctx, a).unwrap();
        assert_eq!(child, ac);
        // el lider no se "lanza" a si mismo ni a pids ajenos a la sesion
        assert_eq!(s.authorize_spawn(ctx, 8003).err(), Some(Errno::InvalidArgument));
        assert_eq!(s.authorize_spawn(ctx, 1).err(), Some(Errno::InvalidArgument));
        // tenant inexistente
        assert_eq!(s.actor_create(ctx, 424242), Err(Errno::InvalidArgument));
    }

    #[test]
    fn spawn_is_audited_with_the_target_identity() {
        let (ctx, mut s) = leader(8008, true);
        let t = s.tenant_create(ctx).unwrap();
        let a = s.actor_create(ctx, t).unwrap();
        let before = audit::GLOBAL_AUDIT_LOG.lock().events().last().map_or(0, |e| e.seq);
        s.authorize_spawn(ctx, a).unwrap();
        let ev: alloc::vec::Vec<_> = audit::GLOBAL_AUDIT_LOG
            .lock()
            .events()
            .into_iter()
            .filter(|e| e.seq > before && e.op == AuditOp::Identity)
            .collect();
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].subject_id, ev[0].tenant_id, ev[0].resource_id), (8008, Some(t), Some(a)));
    }

    #[test]
    fn actors_do_not_administer_the_session() {
        // Cierra la limitacion de I-25: un actor (proceso lanzado) ya no crea tenants, ni actores,
        // ni lee la auditoria, ni lanza procesos, aunque sea miembro de la sesion.
        let sp = MockUserSpace::new(4096);
        let (lead, mut s) = leader(8009, true);
        let t = s.tenant_create(lead).unwrap();
        let a = s.actor_create(lead, t).unwrap();
        let b = s.actor_create(lead, t).unwrap();
        let actor = process_context(a).unwrap();
        assert_eq!(s.tenant_create(actor), Err(Errno::PermissionDenied));
        assert_eq!(s.actor_create(actor, t), Err(Errno::PermissionDenied));
        assert_eq!(s.audit_read(actor, &sp, USER_MIN, 96, 0), Err(Errno::PermissionDenied));
        assert_eq!(s.authorize_spawn(actor, b).err(), Some(Errno::PermissionDenied));
    }

    #[test]
    fn actors_get_ipc_only_when_asked_and_it_is_audited() {
        use crate::ipc::security::{CAP_IPC_RECV, CAP_IPC_SEND};
        use trunomy_abi::actor::FLAG_IPC;
        let (ctx, mut s) = leader(8010, true);
        let t = s.tenant_create(ctx).unwrap();
        let plain = s.actor_create(ctx, t).unwrap();
        let before = audit::GLOBAL_AUDIT_LOG.lock().events().last().map_or(0, |e| e.seq);
        let talker = s.actor_create_with(ctx, t, FLAG_IPC).unwrap();
        let has = |pid: u64, cap: u32| GLOBAL_CAPABILITY_BOOK.lock().has_capability_for(pid, t, cap);
        assert!(!has(plain, CAP_IPC_SEND) && !has(plain, CAP_IPC_RECV), "minimo privilegio por defecto");
        assert!(has(talker, CAP_IPC_SEND) && has(talker, CAP_IPC_RECV));
        let grants: alloc::vec::Vec<_> = audit::GLOBAL_AUDIT_LOG
            .lock()
            .events()
            .into_iter()
            .filter(|e| e.seq > before && e.op == AuditOp::Grant)
            .collect();
        assert_eq!(grants.len(), 1);
        assert_eq!((grants[0].subject_id, grants[0].resource_id), (8010, Some(talker)));
    }

    #[test]
    fn the_net_flag_grants_the_network_capabilities_and_nothing_else() {
        use trunomy_abi::actor::{FLAG_IPC, FLAG_NET};
        let (ctx, mut s) = leader(8020, true);
        let t = s.tenant_create(ctx).unwrap();
        let plain = s.actor_create(ctx, t).unwrap();
        let ipc_only = s.actor_create_with(ctx, t, FLAG_IPC).unwrap();
        let net_only = s.actor_create_with(ctx, t, FLAG_NET).unwrap();
        let both = s.actor_create_with(ctx, t, FLAG_IPC | FLAG_NET).unwrap();
        let has = |pid: u64, cap: u32| GLOBAL_CAPABILITY_BOOK.lock().has_capability_for(pid, t, cap);
        use crate::ipc::security::{CAP_IPC_RECV, CAP_IPC_SEND};
        use crate::syscall::{CAP_NET_RECV, CAP_NET_SEND};
        for p in [plain, ipc_only] {
            assert!(!has(p, CAP_NET_SEND) && !has(p, CAP_NET_RECV), "sin la bandera no hay red");
        }
        for p in [net_only, both] {
            assert!(has(p, CAP_NET_SEND) && has(p, CAP_NET_RECV));
        }
        assert!(!has(net_only, CAP_IPC_SEND) && !has(net_only, CAP_IPC_RECV), "la red no concede IPC");
        assert!(has(both, CAP_IPC_SEND));
    }

    #[test]
    fn unknown_actor_flags_create_nothing_and_only_the_leader_may_ask() {
        let (ctx, mut s) = leader(8011, true);
        let t = s.tenant_create(ctx).unwrap();
        assert_eq!(s.actor_create_with(ctx, t, 1 << 7), Err(Errno::InvalidArgument));
        assert_eq!(s.actor_create_with(ctx, t, u64::MAX), Err(Errno::InvalidArgument));
        assert!(s.actor_pids().is_empty(), "una bandera invalida no crea al actor");
        let a = s.actor_create(ctx, t).unwrap();
        let actor = process_context(a).unwrap();
        assert_eq!(s.actor_create_with(actor, t, trunomy_abi::actor::FLAG_IPC), Err(Errno::PermissionDenied));
    }

    #[test]
    fn sessions_are_bounded() {
        let (ctx, mut s) = leader(8004, true);
        let mut t = 0;
        for _ in 0..MAX_TENANTS {
            t = s.tenant_create(ctx).unwrap();
        }
        assert_eq!(s.tenant_create(ctx), Err(Errno::QuotaExceeded));
        for _ in 0..MAX_ACTORS {
            s.actor_create(ctx, t).unwrap();
        }
        assert_eq!(s.actor_create(ctx, t), Err(Errno::QuotaExceeded));
    }

    #[test]
    fn full_demo_flow_allowed_denied_revoked_and_audited() {
        use crate::syscall::objects::*;
        let sp = MockUserSpace::new(16384);
        let (lead, mut s) = leader(8005, true);
        let acme = s.tenant_create(lead).unwrap();
        let evil = s.tenant_create(lead).unwrap();
        let alice = s.actor_create(lead, acme).unwrap();
        let bob = s.actor_create(lead, acme).unwrap();
        let mallory = s.actor_create(lead, evil).unwrap();
        let ctx = |pid| process_context(pid).unwrap();
        let base = audit::GLOBAL_AUDIT_LOG.lock().events().last().map_or(0, |e| e.seq);

        sp.mem.borrow_mut()[..4].copy_from_slice(b"hola");
        let h = decode(object_create(ctx(alice), &sp, USER_MIN, 4)).unwrap();
        let hb = decode(cap_derive(ctx(alice), h, bob, trunomy_abi::rights::READ, 0)).unwrap();
        let out = USER_MIN + 1024;
        assert_eq!(decode(object_read(ctx(bob), &sp, hb, out, 64)), Ok(4));
        assert_eq!(decode(object_write(ctx(bob), &sp, hb, USER_MIN, 4)), Err(Errno::PermissionDenied));
        assert!(decode(object_read(ctx(mallory), &sp, h, out, 64)).is_err());
        assert_eq!(decode(cap_derive(ctx(alice), h, mallory, trunomy_abi::rights::READ, 0)), Err(Errno::TenantMismatch));
        assert_eq!(decode(cap_revoke(ctx(alice), h)), Ok(0));
        assert_eq!(decode(object_read(ctx(bob), &sp, hb, out, 64)), Err(Errno::RevokedCapability));

        // El administrador lee el registro por la syscall y ve permitidos y denegados.
        let n = s.audit_read(lead, &sp, USER_MIN + 4096, 48 * 192, base).unwrap() as usize;
        assert!(n > 0);
        let raw = sp.mem.borrow()[4096..4096 + n * 48].to_vec();
        let recs: alloc::vec::Vec<_> = raw.chunks(48).map(|c| abi_audit::Record::decode(c).unwrap()).collect();
        let mine: alloc::vec::Vec<_> = recs.iter().filter(|r| [alice, bob, mallory].contains(&r.subject)).collect();
        assert!(mine.iter().any(|r| r.subject == bob && r.op == abi_audit::OP_READ && r.outcome == 0));
        assert!(mine.iter().any(|r| r.subject == bob && r.op == abi_audit::OP_WRITE && r.outcome == Errno::PermissionDenied.code() as u8));
        assert!(mine.iter().any(|r| r.subject == mallory && r.outcome != 0));
        assert!(mine.iter().any(|r| r.op == abi_audit::OP_REVOKE && r.subject == alice));
        // seq crece estrictamente y after_seq filtra
        assert!(recs.windows(2).all(|w| w[0].seq < w[1].seq));
        let last = recs.last().unwrap().seq;
        let newer = s.audit_read(lead, &sp, USER_MIN + 4096, 48 * 192, last).unwrap() as usize;
        let raw2 = sp.mem.borrow()[4096..4096 + newer * 48].to_vec();
        assert!(raw2.chunks(48).all(|c| abi_audit::Record::decode(c).unwrap().seq > last));
        // un actor sin ser admin (lider sin cap) no lee: aqui el lider SI es admin, asi que otra sesion sin admin falla
        let (ctx2, s2) = leader(8006, false);
        assert_eq!(s2.audit_read(ctx2, &sp, USER_MIN, 48, 0), Err(Errno::PermissionDenied));
    }

    #[test]
    fn audit_read_respects_the_buffer_size() {
        let sp = MockUserSpace::new(4096);
        let (lead, s) = leader(8007, true);
        // 47 bytes: no cabe ningun registro
        assert_eq!(s.audit_read(lead, &sp, USER_MIN, 47, 0), Ok(0));
        assert_eq!(s.audit_read(lead, &sp, 0, 96, 0), Err(Errno::InvalidPointer));
    }
}
