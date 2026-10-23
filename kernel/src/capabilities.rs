// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

#![allow(dead_code)]

use crate::audit::{self, AuditOp, AuditOutcome};
use crate::clock;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::BitOr;
use spin::{Lazy, Mutex};

pub const MAX_CAPABILITY_SLOTS: usize = 64;
pub const MAX_CAPABILITIES_PER_SUBJECT: usize = 16;
/// De esas, las que un PROCESO puede empujarle a otro con la syscall `CapDerive` (sin su consentimiento).
/// El resto queda siempre disponible para lo propio (objetos que crea, capabilities de sistema): nadie
/// puede llenar los slots de otro. El libro NO lo impone (delegar dentro del kernel, como hace el escenario
/// del agente, puede usar todos los slots): lo aplica `syscall::objects::cap_derive`.
pub const MAX_DELEGATED_PER_SUBJECT: usize = 8;
pub const MAX_OBJECTS_PER_TENANT: usize = 64;
pub const MAX_OBJECT_PAYLOAD_BYTES: usize = 4096;
pub static GLOBAL_CAPABILITY_BOOK: Lazy<Mutex<CapabilityBook>> =
    Lazy::new(|| Mutex::new(CapabilityBook::new()));
pub static GLOBAL_OBJECT_STORE: Lazy<Mutex<ObjectStore>> =
    Lazy::new(|| Mutex::new(ObjectStore::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityHandle {
    pub slot: u32,
    pub generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const SEND: Self = Self(1 << 2);
    pub const RECEIVE: Self = Self(1 << 3);
    pub const DELEGATE: Self = Self(1 << 4);

    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn is_subset_of(self, parent: Self) -> bool {
        parent.contains(self)
    }

    /// Mascara cruda (los mismos bits que `trunomy_abi::rights`).
    pub fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    Data,
    Pipe,
    Endpoint,
    Task,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    NotFound,
    InvalidGeneration,
    Revoked,
    PermissionDenied,
    WrongResourceType,
    InvalidDelegation,
    TenantMismatch,
    PayloadTooLarge,
    ObjectQuotaExceeded,
    CapabilityQuotaExceeded,
    ResourceIdExhausted,
    OutOfMemory,
    /// La capability llego a su vencimiento (`now >= expires_at`).
    Expired,
    /// La capability agoto sus usos permitidos.
    UsesExhausted,
}

/// Restricciones opcionales de una capability delegada. Solo pueden estrecharse:
/// un hijo nunca vence despues que su padre ni tiene mas usos que el padre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Tick del reloj del kernel en el que deja de valer.
    pub expires_at: Option<u64>,
    /// Numero maximo de usos autorizados (lectura/escritura/borrado).
    pub max_uses: Option<u32>,
}

impl Limits {
    pub const NONE: Self = Self {
        expires_at: None,
        max_uses: None,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelCapabilityEntry {
    pub slot: u32,
    pub subject_id: u64,
    pub tenant_id: u64,
    pub resource_type: ResourceType,
    pub resource_id: u64,
    pub rights: Rights,
    pub generation: u32,
    pub state: CapabilityState,
    pub parent: Option<CapabilityHandle>,
    /// Sujeto dueno de `parent` (0 si no hay padre): con `parent` identifica el origen de la delegacion.
    pub parent_subject: u64,
    pub revocation_group: u64,
    pub expires_at: Option<u64>,
    pub remaining_uses: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct SubjectCapabilityBook {
    slots: Vec<Option<KernelCapabilityEntry>>,
}

impl SubjectCapabilityBook {
    pub fn new() -> Self {
        Self {
            slots: vec![None; MAX_CAPABILITY_SLOTS],
        }
    }

    /// Capabilities ACTIVAS del sujeto: las revocadas no cuentan y su slot se reutiliza.
    pub fn used_slots(&self) -> usize {
        self.slots.iter().flatten().filter(|e| e.state == CapabilityState::Active).count()
    }

    /// Capabilities activas que le llegaron por delegacion (tienen padre).
    fn delegated_slots(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|e| e.state == CapabilityState::Active && e.parent.is_some())
            .count()
    }

    fn try_insert(
        &mut self,
        mut entry: KernelCapabilityEntry,
    ) -> Result<CapabilityHandle, CapabilityError> {
        if self.used_slots() >= MAX_CAPABILITIES_PER_SUBJECT {
            return Err(CapabilityError::CapabilityQuotaExceeded);
        }

        // Un slot libre o uno revocado cuya generacion aun se puede incrementar. La capability nueva
        // hereda la generacion YA incrementada de la revocada (ningun handle emitido la tuvo), asi un
        // handle viejo sobre ese slot nunca vuelve a valer (sin ABA).
        let slot = self
            .slots
            .iter()
            .position(|cell| match cell {
                None => true,
                Some(old) => old.state == CapabilityState::Revoked && old.generation < u32::MAX,
            })
            .ok_or(CapabilityError::OutOfMemory)?;
        let generation = self.slots[slot].map_or(1, |old| old.generation);
        entry.slot = slot as u32;
        entry.generation = generation;
        let handle = CapabilityHandle {
            slot: slot as u32,
            generation: entry.generation,
        };
        self.slots[slot] = Some(entry);
        Ok(handle)
    }

    pub fn grant(
        &mut self,
        subject_id: u64,
        tenant_id: u64,
        resource_type: ResourceType,
        resource_id: u64,
        rights: Rights,
    ) -> Option<CapabilityHandle> {
        self.try_grant(subject_id, tenant_id, resource_type, resource_id, rights).ok()
    }

    pub fn try_grant(
        &mut self,
        subject_id: u64,
        tenant_id: u64,
        resource_type: ResourceType,
        resource_id: u64,
        rights: Rights,
    ) -> Result<CapabilityHandle, CapabilityError> {
        self.try_insert(KernelCapabilityEntry {
            slot: 0,
            subject_id,
            tenant_id,
            resource_type,
            resource_id,
            rights,
            generation: 1,
            state: CapabilityState::Active,
            parent: None,
            parent_subject: 0,
            revocation_group: 0,
            expires_at: None,
            remaining_uses: None,
        })
    }

    fn entry(&self, handle: CapabilityHandle) -> Result<&KernelCapabilityEntry, CapabilityError> {
        let entry = self
            .slots
            .get(handle.slot as usize)
            .and_then(Option::as_ref)
            .ok_or(CapabilityError::NotFound)?;

        if entry.generation != handle.generation {
            return Err(CapabilityError::InvalidGeneration);
        }
        Ok(entry)
    }

    pub fn lookup(
        &self,
        handle: CapabilityHandle,
        requested_rights: Rights,
        expected_type: ResourceType,
    ) -> Result<KernelCapabilityEntry, CapabilityError> {
        self.lookup_at(handle, requested_rights, expected_type, clock::now())
    }

    /// Como `lookup` pero con un instante explicito. No consume usos.
    pub fn lookup_at(
        &self,
        handle: CapabilityHandle,
        requested_rights: Rights,
        expected_type: ResourceType,
        now: u64,
    ) -> Result<KernelCapabilityEntry, CapabilityError> {
        let entry = self.entry(handle)?;

        if entry.state != CapabilityState::Active {
            return Err(CapabilityError::Revoked);
        }
        if entry.expires_at.map_or(false, |deadline| now >= deadline) {
            return Err(CapabilityError::Expired);
        }
        if entry.remaining_uses == Some(0) {
            return Err(CapabilityError::UsesExhausted);
        }
        if entry.resource_type != expected_type {
            return Err(CapabilityError::WrongResourceType);
        }
        if !entry.rights.contains(requested_rights) {
            return Err(CapabilityError::PermissionDenied);
        }

        Ok(*entry)
    }

    fn revoke_handle(&mut self, handle: CapabilityHandle) -> Result<u64, CapabilityError> {
        let entry = self
            .slots
            .get_mut(handle.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(CapabilityError::NotFound)?;

        if entry.generation != handle.generation {
            return Err(CapabilityError::InvalidGeneration);
        }
        entry.state = CapabilityState::Revoked;
        entry.generation = entry.generation.saturating_add(1);
        Ok(entry.revocation_group)
    }

    /// Revoca las capabilities activas de un grupo de revocacion; devuelve cuantas.
    fn revoke_group(&mut self, group: u64) -> usize {
        if group == 0 {
            return 0;
        }
        let mut n = 0;
        for cell in &mut self.slots {
            if let Some(entry) = cell {
                if entry.revocation_group == group && entry.state == CapabilityState::Active {
                    entry.state = CapabilityState::Revoked;
                    entry.generation = entry.generation.saturating_add(1);
                    n += 1;
                }
            }
        }
        n
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    pub object_id: ObjectId,
    pub tenant_id: u64,
    pub owner_subject_id: u64,
    pub resource_type: ResourceType,
    pub resource_id: u64,
    pub rights: Rights,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ObjectStore {
    objects: BTreeMap<ObjectId, StoredObject>,
    next_id: u64,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Borra todos los objetos del tenant (sus payloads se ponen a cero al liberarse, I-16).
    /// Devuelve cuantos. Lo usa `TenantPanic` con `FLAG_WIPE` (I-45).
    pub fn purge_tenant(&mut self, tenant_id: u64) -> usize {
        let before = self.objects.len();
        self.objects.retain(|_, o| o.tenant_id != tenant_id);
        before - self.objects.len()
    }

    pub fn count_for_tenant(&self, tenant_id: u64) -> usize {
        self.objects
            .values()
            .filter(|object| object.tenant_id == tenant_id)
            .count()
    }

    /// Bytes de payload almacenados por el tenant.
    pub fn bytes_for_tenant(&self, tenant_id: u64) -> usize {
        self.objects.values().filter(|o| o.tenant_id == tenant_id).map(|o| o.payload.len()).sum()
    }

    pub fn try_create(
        &mut self,
        tenant_id: u64,
        owner_subject_id: u64,
        resource_type: ResourceType,
        resource_id: u64,
        rights: Rights,
        payload: Vec<u8>,
    ) -> Result<ObjectId, CapabilityError> {
        if payload.len() > MAX_OBJECT_PAYLOAD_BYTES {
            return Err(CapabilityError::PayloadTooLarge);
        }

        if self.count_for_tenant(tenant_id) >= MAX_OBJECTS_PER_TENANT {
            return Err(CapabilityError::ObjectQuotaExceeded);
        }

        if self.next_id == u64::MAX {
            return Err(CapabilityError::ResourceIdExhausted);
        }

        let id = ObjectId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.objects.insert(
            id,
            StoredObject {
                object_id: id,
                tenant_id,
                owner_subject_id,
                resource_type,
                resource_id,
                rights,
                payload,
            },
        );
        Ok(id)
    }

    /// Solo para pruebas: aborta si falla. El camino real usa `try_create` y propaga el error; devolver
    /// un `ObjectId(0)` ante cualquier fallo escondia la cuota agotada o un id repetido (hallazgo 6).
    #[cfg(test)]
    pub fn create(
        &mut self,
        tenant_id: u64,
        owner_subject_id: u64,
        resource_type: ResourceType,
        resource_id: u64,
        rights: Rights,
        payload: Vec<u8>,
    ) -> ObjectId {
        self.try_create(
            tenant_id,
            owner_subject_id,
            resource_type,
            resource_id,
            rights,
            payload,
        )
        .expect("create: the test store must not fail")
    }

    pub fn read(
        &self,
        tenant_id: u64,
        subject_id: u64,
        object_id: ObjectId,
        required_rights: Rights,
    ) -> Result<&StoredObject, CapabilityError> {
        let object = self
            .objects
            .get(&object_id)
            .ok_or(CapabilityError::NotFound)?;

        if object.tenant_id != tenant_id {
            return Err(CapabilityError::TenantMismatch);
        }

        if object.owner_subject_id != subject_id && !object.rights.contains(required_rights) {
            return Err(CapabilityError::PermissionDenied);
        }

        Ok(object)
    }

    pub fn write(
        &mut self,
        tenant_id: u64,
        subject_id: u64,
        object_id: ObjectId,
        required_rights: Rights,
        payload: Vec<u8>,
    ) -> Result<(), CapabilityError> {
        if payload.len() > MAX_OBJECT_PAYLOAD_BYTES {
            return Err(CapabilityError::PayloadTooLarge);
        }

        let object = self
            .objects
            .get_mut(&object_id)
            .ok_or(CapabilityError::NotFound)?;

        if object.tenant_id != tenant_id {
            return Err(CapabilityError::TenantMismatch);
        }

        if object.owner_subject_id != subject_id && !object.rights.contains(required_rights) {
            return Err(CapabilityError::PermissionDenied);
        }

        object.payload = payload;
        Ok(())
    }

    pub fn delete(
        &mut self,
        tenant_id: u64,
        subject_id: u64,
        object_id: ObjectId,
        required_rights: Rights,
    ) -> Result<(), CapabilityError> {
        let object = self
            .objects
            .get(&object_id)
            .ok_or(CapabilityError::NotFound)?;

        if object.tenant_id != tenant_id {
            return Err(CapabilityError::TenantMismatch);
        }

        if object.owner_subject_id != subject_id && !object.rights.contains(required_rights) {
            return Err(CapabilityError::PermissionDenied);
        }

        self.objects.remove(&object_id);
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CapabilityBook {
    subjects: BTreeMap<u64, SubjectCapabilityBook>,
    next_revocation_group: u64,
}

impl CapabilityBook {
    pub fn new() -> Self {
        Self {
            subjects: BTreeMap::new(),
            next_revocation_group: 1,
        }
    }

    pub fn subject(&mut self, subject_id: u64) -> &mut SubjectCapabilityBook {
        self.subjects
            .entry(subject_id)
            .or_insert_with(SubjectCapabilityBook::new)
    }

    pub fn grant(
        &mut self,
        subject_id: u64,
        tenant_id: u64,
        resource_type: ResourceType,
        resource_id: u64,
        rights: Rights,
    ) -> Option<CapabilityHandle> {
        self.try_grant(subject_id, tenant_id, resource_type, resource_id, rights).ok()
    }

    pub fn try_grant(
        &mut self,
        subject_id: u64,
        tenant_id: u64,
        resource_type: ResourceType,
        resource_id: u64,
        rights: Rights,
    ) -> Result<CapabilityHandle, CapabilityError> {
        if self.subject(subject_id).used_slots() >= MAX_CAPABILITIES_PER_SUBJECT {
            return Err(CapabilityError::CapabilityQuotaExceeded);
        }

        self.subject(subject_id)
            .try_grant(subject_id, tenant_id, resource_type, resource_id, rights)
    }

    pub fn lookup(
        &self,
        subject_id: u64,
        handle: CapabilityHandle,
        requested_rights: Rights,
        expected_type: ResourceType,
    ) -> Result<KernelCapabilityEntry, CapabilityError> {
        self.subjects
            .get(&subject_id)
            .ok_or(CapabilityError::NotFound)?
            .lookup(handle, requested_rights, expected_type)
    }

    pub fn lookup_at(
        &self,
        subject_id: u64,
        handle: CapabilityHandle,
        requested_rights: Rights,
        expected_type: ResourceType,
        now: u64,
    ) -> Result<KernelCapabilityEntry, CapabilityError> {
        self.subjects
            .get(&subject_id)
            .ok_or(CapabilityError::NotFound)?
            .lookup_at(handle, requested_rights, expected_type, now)
    }

    /// Autoriza un uso: igual que `lookup_at` y, si la capability tiene limite de
    /// usos, consume uno. El uso se consume al AUTORIZAR, aunque la operacion
    /// posterior falle: sondear con una capability limitada no sale gratis.
    pub fn authorize_at(
        &mut self,
        subject_id: u64,
        handle: CapabilityHandle,
        requested_rights: Rights,
        expected_type: ResourceType,
        now: u64,
    ) -> Result<KernelCapabilityEntry, CapabilityError> {
        let entry = self.lookup_at(subject_id, handle, requested_rights, expected_type, now)?;
        if let Some(remaining) = entry.remaining_uses {
            let cell = self
                .subjects
                .get_mut(&subject_id)
                .and_then(|book| book.slots.get_mut(handle.slot as usize))
                .and_then(Option::as_mut)
                .ok_or(CapabilityError::NotFound)?;
            cell.remaining_uses = Some(remaining.saturating_sub(1));
        }
        Ok(entry)
    }

    /// Tenant y recurso de una capability, si el handle aun se resuelve.
    /// Solo para auditoria: no concede ni comprueba nada.
    fn audit_context(&self, subject_id: u64, handle: CapabilityHandle) -> (Option<u64>, Option<u64>) {
        self.subjects
            .get(&subject_id)
            .and_then(|book| book.entry(handle).ok())
            .map_or((None, None), |entry| (Some(entry.tenant_id), Some(entry.resource_id)))
    }

    pub fn delegate(
        &mut self,
        parent_subject: u64,
        parent_handle: CapabilityHandle,
        child_subject: u64,
        requested_rights: Rights,
    ) -> Result<CapabilityHandle, CapabilityError> {
        self.delegate_limited(
            parent_subject,
            parent_handle,
            child_subject,
            requested_rights,
            Limits::NONE,
        )
    }

    /// Delegacion con vencimiento y/o limite de usos. Los limites solo se estrechan:
    /// el hijo hereda como maximo lo que le queda al padre (los usos del hijo se
    /// descuentan del padre).
    pub fn delegate_limited(
        &mut self,
        parent_subject: u64,
        parent_handle: CapabilityHandle,
        child_subject: u64,
        requested_rights: Rights,
        limits: Limits,
    ) -> Result<CapabilityHandle, CapabilityError> {
        let (tenant, resource) = self.audit_context(parent_subject, parent_handle);
        let result = self.delegate_inner(
            parent_subject,
            parent_handle,
            child_subject,
            requested_rights,
            limits,
            clock::now(),
        );
        audit::record(
            parent_subject,
            AuditOp::Delegate,
            Some(parent_handle),
            tenant,
            resource,
            outcome_of(&result),
        );
        result
    }

    pub fn revoke(
        &mut self,
        subject_id: u64,
        handle: CapabilityHandle,
    ) -> Result<(), CapabilityError> {
        let (tenant, resource) = self.audit_context(subject_id, handle);
        let result = self.revoke_inner(subject_id, handle);
        audit::record(
            subject_id,
            AuditOp::Revoke,
            Some(handle),
            tenant,
            resource,
            outcome_of(&result),
        );
        result
    }

    /// Revoca TODA capability activa de `subject_id` (y las que derivan de ella por grupo de
    /// revocacion). Los handles que el sujeto ya conocia quedan con generacion vieja: dejan de valer
    /// aunque se los sepa de memoria. Devuelve cuantas capabilities dejaron de estar activas.
    /// Es la base de `TenantPanic` (I-45); no audita (lo hace quien la llama, una vez por corte).
    pub fn revoke_subject(&mut self, subject_id: u64) -> usize {
        let mut groups: Vec<u64> = Vec::new();
        let mut n = 0;
        if let Some(book) = self.subjects.get_mut(&subject_id) {
            for entry in book.slots.iter_mut().flatten() {
                if entry.state == CapabilityState::Active {
                    entry.state = CapabilityState::Revoked;
                    entry.generation = entry.generation.saturating_add(1);
                    n += 1;
                    if entry.revocation_group != 0 && !groups.contains(&entry.revocation_group) {
                        groups.push(entry.revocation_group);
                    }
                }
            }
        }
        for group in groups {
            for subject in self.subjects.values_mut() {
                n += subject.revoke_group(group);
            }
        }
        n
    }

    /// Capabilities ACTIVAS de `subject_id` (solo lectura; no consume usos ni audita).
    pub fn entries_of(&self, subject_id: u64) -> Vec<KernelCapabilityEntry> {
        self.subjects.get(&subject_id).map_or_else(Vec::new, |s| {
            s.slots.iter().flatten().filter(|e| e.state == CapabilityState::Active).copied().collect()
        })
    }

    /// ¿Tiene `subject_id` la capability de SISTEMA `resource_id` (crear objetos, administrar, consola,
    /// IPC, red...)? Solo cuenta una capability ACTIVA de tipo `Task` con el derecho `READ` (el que se
    /// concede al sembrarlas) y del mismo tenant. Una capability de DATOS cuyo `resource_id` (un
    /// `ObjectId`) coincida numericamente NO sirve: los dos espacios de ids son distintos y mezclarlos
    /// permitia que un tenant sin privilegios obtuviera la consola o `CAP_ADMIN` al recibir el objeto
    /// con ese numero (I-04, I-13, I-35).
    /// Capabilities activas de `subject_id` que le llegaron por delegacion (tienen padre).
    pub fn delegated_count(&self, subject_id: u64) -> usize {
        self.subjects.get(&subject_id).map_or(0, |s| s.delegated_slots())
    }

    pub fn has_capability_for(&self, subject_id: u64, tenant_id: u64, resource_id: u32) -> bool {
        self.subjects.get(&subject_id).map_or(false, |subject| {
            subject.slots.iter().flatten().any(|entry| {
                entry.tenant_id == tenant_id
                    && entry.resource_id == resource_id as u64
                    && entry.resource_type == ResourceType::Task
                    && entry.rights.contains(Rights::READ)
                    && entry.state == CapabilityState::Active
            })
        })
    }

    fn delegate_inner(
        &mut self,
        parent_subject: u64,
        parent_handle: CapabilityHandle,
        child_subject: u64,
        requested_rights: Rights,
        limits: Limits,
        now: u64,
    ) -> Result<CapabilityHandle, CapabilityError> {
        let (
            parent_state,
            parent_rights,
            parent_revocation_group,
            parent_tenant_id,
            parent_resource_type,
            parent_resource_id,
            parent_expires_at,
            parent_remaining_uses,
        ) = {
            let parent = self
                .subjects
                .get(&parent_subject)
                .ok_or(CapabilityError::NotFound)?
                .entry(parent_handle)?;

            (
                parent.state,
                parent.rights,
                parent.revocation_group,
                parent.tenant_id,
                parent.resource_type,
                parent.resource_id,
                parent.expires_at,
                parent.remaining_uses,
            )
        };

        if parent_state != CapabilityState::Active {
            return Err(CapabilityError::Revoked);
        }
        if parent_expires_at.map_or(false, |deadline| now >= deadline) {
            return Err(CapabilityError::Expired);
        }
        if parent_remaining_uses == Some(0) {
            return Err(CapabilityError::UsesExhausted);
        }

        if !parent_rights.contains(Rights::DELEGATE)
            || !requested_rights.is_subset_of(parent_rights)
        {
            return Err(CapabilityError::InvalidDelegation);
        }

        // Los limites solo se estrechan (monotonia tambien en tiempo y usos).
        let child_expires_at = match (parent_expires_at, limits.expires_at) {
            (Some(parent), Some(requested)) => Some(parent.min(requested)),
            (Some(parent), None) => Some(parent),
            (None, requested) => requested,
        };
        let child_uses = match (parent_remaining_uses, limits.max_uses) {
            (Some(_), None) => return Err(CapabilityError::InvalidDelegation),
            (Some(parent), Some(requested)) if requested > parent => {
                return Err(CapabilityError::InvalidDelegation)
            }
            (_, Some(0)) => return Err(CapabilityError::InvalidDelegation),
            (_, requested) => requested,
        };

        if self.subject(child_subject).used_slots() >= MAX_CAPABILITIES_PER_SUBJECT {
            return Err(CapabilityError::CapabilityQuotaExceeded);
        }

        let group = if parent_revocation_group == 0 {
            let group = self.next_revocation_group;
            self.next_revocation_group = self.next_revocation_group.saturating_add(1);

            let parent_entry = self
                .subjects
                .get_mut(&parent_subject)
                .and_then(|book| book.slots.get_mut(parent_handle.slot as usize))
                .and_then(Option::as_mut)
                .ok_or(CapabilityError::NotFound)?;

            if parent_entry.generation != parent_handle.generation {
                return Err(CapabilityError::InvalidGeneration);
            }

            parent_entry.revocation_group = group;
            group
        } else {
            parent_revocation_group
        };

        let child_entry = KernelCapabilityEntry {
            slot: 0,
            subject_id: child_subject,
            tenant_id: parent_tenant_id,
            resource_type: parent_resource_type,
            resource_id: parent_resource_id,
            rights: requested_rights,
            generation: 1,
            state: CapabilityState::Active,
            parent: Some(parent_handle),
            parent_subject,
            revocation_group: group,
            expires_at: child_expires_at,
            remaining_uses: child_uses,
        };

        let handle = self.subject(child_subject).try_insert(child_entry)?;

        // Los usos del hijo salen del presupuesto del padre.
        if let (Some(parent_remaining), Some(granted)) = (parent_remaining_uses, child_uses) {
            if let Some(cell) = self
                .subjects
                .get_mut(&parent_subject)
                .and_then(|book| book.slots.get_mut(parent_handle.slot as usize))
                .and_then(Option::as_mut)
            {
                cell.remaining_uses = Some(parent_remaining.saturating_sub(granted));
            }
        }
        Ok(handle)
    }

    /// Revoca `handle` y TODO lo que se derivo de el (hijos, nietos...), y nada mas: ni el padre, ni los
    /// hermanos, ni los antepasados. Quien recibio una delegacion puede soltar la suya (y lo que delego
    /// a su vez) pero no puede quitarle la capability a quien se la dio (hallazgo 2 de la revision).
    /// El corte de un tenant entero (`revoke_subject`, I-45) si es por grupo y sigue siendo mas amplio.
    fn revoke_inner(
        &mut self,
        subject_id: u64,
        handle: CapabilityHandle,
    ) -> Result<(), CapabilityError> {
        // Valida existencia y generacion antes de tocar nada.
        self.subjects
            .get(&subject_id)
            .ok_or(CapabilityError::NotFound)?
            .entry(handle)?;
        self.subject(subject_id).revoke_handle(handle)?;

        // Descendientes: cada hijo guarda (sujeto, handle) de su padre con la generacion del momento de
        // la delegacion, que es la que tenia el padre justo antes de revocarse.
        let mut pending: Vec<(u64, CapabilityHandle)> = Vec::new();
        pending.push((subject_id, handle));
        while let Some((owner, parent_handle)) = pending.pop() {
            for (child_subject, book) in self.subjects.iter_mut() {
                for cell in book.slots.iter_mut().flatten() {
                    if cell.state == CapabilityState::Active
                        && cell.parent_subject == owner
                        && cell.parent == Some(parent_handle)
                    {
                        let own = CapabilityHandle { slot: cell.slot, generation: cell.generation };
                        cell.state = CapabilityState::Revoked;
                        cell.generation = cell.generation.saturating_add(1);
                        pending.push((*child_subject, own));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub fn create_global_object(
    tenant_id: u64,
    owner_subject_id: u64,
    resource_type: ResourceType,
    resource_id: u64,
    rights: Rights,
    payload: Vec<u8>,
) -> ObjectId {
    GLOBAL_OBJECT_STORE
        .lock()
        .try_create(tenant_id, owner_subject_id, resource_type, resource_id, rights, payload)
        .expect("create_global_object: must not fail in tests")
}

pub fn grant_object_capability(
    subject_id: u64,
    tenant_id: u64,
    resource_type: ResourceType,
    resource_id: u64,
    rights: Rights,
) -> Option<CapabilityHandle> {
    // I-05: una capability de datos solo puede nacer sobre un objeto existente
    // del MISMO tenant. Los candados se toman por separado (nunca anidados).
    if resource_type == ResourceType::Data {
        let verdict = match GLOBAL_OBJECT_STORE.lock().objects.get(&ObjectId(resource_id)) {
            None => Err(CapabilityError::NotFound),
            Some(object) if object.tenant_id != tenant_id => Err(CapabilityError::TenantMismatch),
            Some(_) => Ok(()),
        };
        if let Err(error) = verdict {
            audit::record(
                subject_id,
                AuditOp::Grant,
                None,
                Some(tenant_id),
                Some(resource_id),
                AuditOutcome::Denied(error),
            );
            return None;
        }
    }

    let result = GLOBAL_CAPABILITY_BOOK
        .lock()
        .try_grant(subject_id, tenant_id, resource_type, resource_id, rights);
    audit::record(
        subject_id,
        AuditOp::Grant,
        result.ok(),
        Some(tenant_id),
        Some(resource_id),
        outcome_of(&result),
    );
    result.ok()
}

fn read_object_inner(
    subject_id: u64,
    handle: CapabilityHandle,
    required_rights: Rights,
) -> Result<Vec<u8>, CapabilityError> {
    let entry = {
        let mut book = GLOBAL_CAPABILITY_BOOK.lock();
        book.authorize_at(
            subject_id,
            handle,
            required_rights,
            ResourceType::Data,
            clock::now(),
        )?
    };
    let object_id = ObjectId(entry.resource_id);

    let object = {
        let store = GLOBAL_OBJECT_STORE.lock();
        store
            .objects
            .get(&object_id)
            .cloned()
            .ok_or(CapabilityError::NotFound)?
    };

    // I-05: la comprobacion de tenant es simetrica con escritura y borrado.
    if object.tenant_id != entry.tenant_id {
        return Err(CapabilityError::TenantMismatch);
    }

    if object.owner_subject_id != subject_id && !object.rights.contains(required_rights) {
        return Err(CapabilityError::PermissionDenied);
    }

    Ok(object.payload)
}

fn write_object_inner(
    subject_id: u64,
    handle: CapabilityHandle,
    required_rights: Rights,
    payload: Vec<u8>,
) -> Result<(), CapabilityError> {
    let entry = {
        let mut book = GLOBAL_CAPABILITY_BOOK.lock();
        book.authorize_at(
            subject_id,
            handle,
            required_rights,
            ResourceType::Data,
            clock::now(),
        )?
    };
    let object_id = ObjectId(entry.resource_id);

    let mut store = GLOBAL_OBJECT_STORE.lock();
    let object = store
        .objects
        .get_mut(&object_id)
        .ok_or(CapabilityError::NotFound)?;

    if payload.len() > MAX_OBJECT_PAYLOAD_BYTES {
        return Err(CapabilityError::PayloadTooLarge);
    }

    if object.owner_subject_id != subject_id && !object.rights.contains(required_rights) {
        return Err(CapabilityError::PermissionDenied);
    }
    if object.tenant_id != entry.tenant_id {
        return Err(CapabilityError::TenantMismatch);
    }

    object.payload = payload;
    Ok(())
}

fn delete_object_inner(
    subject_id: u64,
    handle: CapabilityHandle,
    required_rights: Rights,
) -> Result<(), CapabilityError> {
    let entry = {
        let mut book = GLOBAL_CAPABILITY_BOOK.lock();
        book.authorize_at(
            subject_id,
            handle,
            required_rights,
            ResourceType::Data,
            clock::now(),
        )?
    };
    let object_id = ObjectId(entry.resource_id);

    let mut store = GLOBAL_OBJECT_STORE.lock();
    let object = store
        .objects
        .get(&object_id)
        .ok_or(CapabilityError::NotFound)?;

    if object.owner_subject_id != subject_id && !object.rights.contains(required_rights) {
        return Err(CapabilityError::PermissionDenied);
    }
    if object.tenant_id != entry.tenant_id {
        return Err(CapabilityError::TenantMismatch);
    }

    store.objects.remove(&object_id);
    Ok(())
}

fn outcome_of<T>(result: &Result<T, CapabilityError>) -> AuditOutcome {
    match result {
        Ok(_) => AuditOutcome::Allowed,
        Err(error) => AuditOutcome::Denied(*error),
    }
}

/// Registra el resultado de una operacion sobre objetos. Se llama sin ningun
/// otro candado tomado.
fn audit_object_op<T>(
    subject_id: u64,
    op: AuditOp,
    handle: CapabilityHandle,
    result: &Result<T, CapabilityError>,
) {
    let (tenant, resource) = GLOBAL_CAPABILITY_BOOK.lock().audit_context(subject_id, handle);
    audit::record(subject_id, op, Some(handle), tenant, resource, outcome_of(result));
}

pub fn read_object_via_capability(
    subject_id: u64,
    handle: CapabilityHandle,
    required_rights: Rights,
) -> Result<Vec<u8>, CapabilityError> {
    let result = read_object_inner(subject_id, handle, required_rights);
    audit_object_op(subject_id, AuditOp::Read, handle, &result);
    result
}

pub fn write_object_via_capability(
    subject_id: u64,
    handle: CapabilityHandle,
    required_rights: Rights,
    payload: Vec<u8>,
) -> Result<(), CapabilityError> {
    let result = write_object_inner(subject_id, handle, required_rights, payload);
    audit_object_op(subject_id, AuditOp::Write, handle, &result);
    result
}

pub fn delete_object_via_capability(
    subject_id: u64,
    handle: CapabilityHandle,
    required_rights: Rights,
) -> Result<(), CapabilityError> {
    let result = delete_object_inner(subject_id, handle, required_rights);
    audit_object_op(subject_id, AuditOp::Delete, handle, &result);
    result
}

/// Crea un objeto en el tenant del sujeto y le concede una capability de datos
/// (READ|WRITE|DELEGATE). Atomico: si la capability no cabe (cuota por sujeto),
/// el objeto se elimina. Los candados se toman por separado (nunca anidados).
pub fn create_object_for_subject(
    subject_id: u64,
    tenant_id: u64,
    payload: Vec<u8>,
) -> Result<CapabilityHandle, CapabilityError> {
    let rights = Rights::READ | Rights::WRITE | Rights::DELEGATE;
    let created = GLOBAL_OBJECT_STORE.lock().try_create(
        tenant_id,
        subject_id,
        ResourceType::Data,
        0,
        rights,
        payload,
    );
    let id = match created {
        Ok(id) => id,
        Err(error) => {
            audit::record(subject_id, AuditOp::Create, None, Some(tenant_id), None, AuditOutcome::Denied(error));
            return Err(error);
        }
    };
    let granted = GLOBAL_CAPABILITY_BOOK
        .lock()
        .try_grant(subject_id, tenant_id, ResourceType::Data, id.0, rights);
    if granted.is_err() {
        GLOBAL_OBJECT_STORE.lock().objects.remove(&id);
    }
    audit::record(
        subject_id,
        AuditOp::Create,
        granted.ok(),
        Some(tenant_id),
        Some(id.0),
        outcome_of(&granted),
    );
    granted
}

/// Tenant al que pertenece la capability del sujeto, si el handle resuelve.
pub fn capability_tenant(subject_id: u64, handle: CapabilityHandle) -> Option<u64> {
    GLOBAL_CAPABILITY_BOOK.lock().audit_context(subject_id, handle).0
}

pub fn seed_root_capabilities() {
    seed_root_into(&mut GLOBAL_CAPABILITY_BOOK.lock());
}

/// Capabilities globales de la shell raiz (pid 1): las demas ordenes de la sesion, administracion
/// (CAP_ADMIN, tambien detener la maquina) y la consola del operador (CAP_CONSOLE, I-35). Los
/// actores y sus workers no reciben ninguna de las dos ultimas.
fn seed_root_into(book: &mut CapabilityBook) {
    for cap in [1u64, 2u64, 3u64, 4u64, 5u64, crate::syscall::CAP_CONSOLE as u64] {
        let _ = book.try_grant(
            1,
            1,
            ResourceType::Task,
            cap,
            Rights::READ | Rights::WRITE | Rights::DELEGATE,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_root_shell_gets_console_and_admin() {
        use crate::syscall::{CAP_CONSOLE, CAP_HALT, CAP_OBJECT_CREATE};
        let mut book = CapabilityBook::new();
        seed_root_into(&mut book);
        for cap in [CAP_CONSOLE, CAP_HALT, CAP_OBJECT_CREATE] {
            assert!(book.has_capability_for(1, 1, cap), "root cap {cap}");
        }
        // un actor (como lo crea identity::actor_create) solo puede crear objetos
        book.try_grant(1001, 1000, ResourceType::Task, CAP_OBJECT_CREATE as u64, Rights::READ).unwrap();
        assert!(book.has_capability_for(1001, 1000, CAP_OBJECT_CREATE));
        assert!(!book.has_capability_for(1001, 1000, CAP_CONSOLE), "un worker no escribe en la consola");
        assert!(!book.has_capability_for(1001, 1000, CAP_HALT), "un worker no detiene la maquina");
        // ni siquiera un pid ajeno en el tenant de la raiz
        assert!(!book.has_capability_for(2, 1, CAP_CONSOLE));
    }

    /// Regresion del informe de seguridad (hallazgo 1): una capability de datos con el mismo numero
    /// que una de sistema no la satisface.
    #[test]
    fn a_data_capability_never_satisfies_a_system_capability() {
        use crate::syscall::{CAP_CONSOLE, CAP_HALT, CAP_OBJECT_CREATE};
        let mut book = CapabilityBook::new();
        for cap in [CAP_OBJECT_CREATE, CAP_HALT, CAP_CONSOLE, 0x10, 0x11, 0x12, 0x13] {
            book.try_grant(5001, 500, ResourceType::Data, cap as u64, Rights::READ | Rights::WRITE).unwrap();
            assert!(!book.has_capability_for(5001, 500, cap), "datos {cap:#x} no es capability de sistema");
        }
        // el tipo correcto sin el derecho READ tampoco vale
        book.try_grant(5002, 500, ResourceType::Task, CAP_CONSOLE as u64, Rights::WRITE).unwrap();
        assert!(!book.has_capability_for(5002, 500, CAP_CONSOLE));
        // y el correcto si
        book.try_grant(5003, 500, ResourceType::Task, CAP_CONSOLE as u64, Rights::READ).unwrap();
        assert!(book.has_capability_for(5003, 500, CAP_CONSOLE));
    }

    /// Camino real: quien crea objetos recibe capabilities de DATOS sobre ids consecutivos; ninguno de
    /// esos ids puede convertirse en autoridad de sistema (los ids 4, 5, 6, 0x10..0x13 son alcanzables).
    #[test]
    fn creating_objects_never_yields_system_authority() {
        use crate::process::{validate_process_capability, ProcessContext};
        for k in 0..6u64 {
            let sid = 7_100_000 + k;
            let ctx = ProcessContext::new(sid, sid, 7_100_000);
            for _ in 0..8 {
                let _ = create_object_for_subject(sid, 7_100_000, vec![1]);
                for cap in [4u32, 5, 6, 0x10, 0x11, 0x12, 0x13] {
                    assert!(!validate_process_capability(ctx, cap), "objeto -> capability de sistema {cap:#x}");
                }
            }
        }
    }

    fn active(book: &CapabilityBook, subject: u64, resource: u64) -> usize {
        book.entries_of(subject).iter().filter(|e| e.resource_id == resource).count()
    }

    /// Hallazgo 2: quien recibe una delegacion (aunque sea de solo lectura) no puede revocar la
    /// capability de quien se la dio ni la de sus hermanos.
    #[test]
    fn a_delegatee_cannot_revoke_its_delegator_or_its_siblings() {
        let mut b = CapabilityBook::new();
        let owner = b.try_grant(1, 7, ResourceType::Data, 50, Rights::READ | Rights::WRITE | Rights::DELEGATE).unwrap();
        let child_a = b.delegate(1, owner, 2, Rights::READ).unwrap();
        let _child_b = b.delegate(1, owner, 3, Rights::READ).unwrap();
        assert!(b.revoke(2, child_a).is_ok());
        assert_eq!(active(&b, 1, 50), 1, "el dueno conserva su capability");
        assert_eq!(active(&b, 3, 50), 1, "el hermano conserva la suya");
        assert_eq!(active(&b, 2, 50), 0, "solo cayo la del que revoco");
        // la capability revocada ya no sirve (generacion nueva)
        assert!(b.revoke(2, child_a).is_err());
    }

    /// Revocar corta lo derivado de ese handle (transitivo) y nada mas.
    #[test]
    fn revoking_cuts_the_whole_subtree_and_nothing_else() {
        let mut b = CapabilityBook::new();
        let owner = b.try_grant(1, 7, ResourceType::Data, 60, Rights::READ | Rights::DELEGATE).unwrap();
        let mid = b.delegate(1, owner, 2, Rights::READ | Rights::DELEGATE).unwrap();
        let leaf = b.delegate(2, mid, 4, Rights::READ).unwrap();
        let other = b.delegate(1, owner, 3, Rights::READ).unwrap();
        assert_eq!(active(&b, 4, 60), 1);
        assert!(b.revoke(2, mid).is_ok());
        assert_eq!(active(&b, 2, 60), 0);
        assert_eq!(active(&b, 4, 60), 0, "el nieto cae con su padre");
        assert_eq!(active(&b, 1, 60), 1);
        assert_eq!(active(&b, 3, 60), 1, "la rama hermana no se toca");
        // el dueno revoca la suya: cae todo lo que queda derivado
        assert!(b.revoke(1, owner).is_ok());
        assert_eq!(active(&b, 3, 60), 0);
        let _ = (leaf, other);
    }

    /// Hallazgo 4: los slots revocados se reutilizan y un handle viejo nunca vuelve a valer (sin ABA).
    #[test]
    fn revoked_slots_are_reused_without_aba() {
        let mut b = CapabilityBook::new();
        let mut stale = Vec::new();
        // mas ciclos que slots: sin reutilizacion se agotaria MAX_CAPABILITY_SLOTS
        for i in 0..(MAX_CAPABILITY_SLOTS as u64 * 3) {
            let h = b.try_grant(1, 7, ResourceType::Data, 700 + i, Rights::READ).unwrap();
            assert!(!stale.contains(&h), "un handle nunca se repite");
            // sin auditar (revoke_handle, no revoke): 192 eventos desplazarian los del resto de tests
            // que cuentan eventos del anillo global
            assert!(b.subject(1).revoke_handle(h).is_ok());
            stale.push(h);
        }
        let fresh = b.try_grant(1, 7, ResourceType::Data, 9, Rights::READ).unwrap();
        for old in &stale {
            if old.slot == fresh.slot {
                assert_ne!(old.generation, fresh.generation);
                assert!(b.subject(1).revoke_handle(*old).is_err(), "el handle viejo del slot reutilizado no vale");
            }
        }
        assert_eq!(b.entries_of(1).len(), 1);
    }

    /// El libro no limita la delegacion por su cuenta (la usa el escenario del agente, que sostiene una
    /// capability por cliente): el tope contra el llenado ajeno vive en `cap_derive`. Aqui solo el limite
    /// total de 16 y que `delegated_count` cuenta lo delegado.
    #[test]
    fn the_book_delegates_up_to_the_total_quota_and_counts_what_was_delegated() {
        let mut b = CapabilityBook::new();
        let mut accepted = 0;
        for i in 0..20u64 {
            let att = 100 + (i % 4);
            let h = b.try_grant(att, 7, ResourceType::Data, 100 + i, Rights::READ | Rights::DELEGATE).unwrap();
            if b.delegate(att, h, 2, Rights::READ).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, MAX_CAPABILITIES_PER_SUBJECT);
        assert_eq!(b.delegated_count(2), MAX_CAPABILITIES_PER_SUBJECT);
        assert_eq!(b.delegated_count(100), 0);
    }

    const PARENT: Rights = Rights(Rights::READ.0 | Rights::DELEGATE.0);

    #[test]
    fn root_capability_is_subject_and_tenant_bound() {
        let mut book = CapabilityBook::new();
        let handle = book
            .subject(1)
            .grant(1, 10, ResourceType::Task, 1, Rights::READ)
            .unwrap();
        assert!(book.has_capability_for(1, 10, 1));
        assert!(!book.has_capability_for(2, 10, 1));
        assert!(book
            .lookup(1, handle, Rights::READ, ResourceType::Task)
            .is_ok());
    }

    #[test]
    fn tenant_a_can_read_its_object() {
        let mut store = ObjectStore::new();
        let id = store.create(
            10,
            100,
            ResourceType::Data,
            1,
            Rights::READ,
            b"secret".to_vec(),
        );
        assert_eq!(
            store.read(10, 100, id, Rights::READ).unwrap().payload,
            b"secret"
        );
    }

    #[test]
    fn tenant_b_cannot_read_tenant_a_object() {
        let mut store = ObjectStore::new();
        let id = store.create(
            10,
            100,
            ResourceType::Data,
            1,
            Rights::READ,
            b"secret".to_vec(),
        );
        assert_eq!(
            store.read(20, 200, id, Rights::READ),
            Err(CapabilityError::TenantMismatch)
        );
    }

    #[test]
    fn read_does_not_imply_write() {
        let mut store = ObjectStore::new();
        let id = store.create(
            10,
            100,
            ResourceType::Data,
            1,
            Rights::READ,
            b"old".to_vec(),
        );
        assert_eq!(
            store.write(10, 200, id, Rights::WRITE, b"new".to_vec()),
            Err(CapabilityError::PermissionDenied)
        );
    }

    #[test]
    fn parent_can_delegate_only_a_subset_of_its_rights() {
        let mut book = CapabilityBook::new();
        let parent = book
            .subject(1)
            .grant(1, 10, ResourceType::Data, 42, PARENT)
            .unwrap();

        let child = book.delegate(1, parent, 2, Rights::READ).unwrap();
        assert!(book
            .lookup(2, child, Rights::READ, ResourceType::Data)
            .is_ok());
    }

    #[test]
    fn delegation_cannot_add_rights() {
        let mut book = CapabilityBook::new();
        let parent = book
            .subject(1)
            .grant(1, 10, ResourceType::Data, 42, Rights::READ)
            .unwrap();

        let result = book.delegate(1, parent, 2, Rights::WRITE);
        assert_eq!(result, Err(CapabilityError::InvalidDelegation));
    }

    #[test]
    fn revoking_parent_revokes_child() {
        let mut book = CapabilityBook::new();
        let parent = book
            .subject(1)
            .grant(1, 10, ResourceType::Data, 42, PARENT)
            .unwrap();
        let child = book.delegate(1, parent, 2, Rights::READ).unwrap();

        book.revoke(1, parent).unwrap();

        assert_eq!(
            book.lookup(2, child, Rights::READ, ResourceType::Data),
            Err(CapabilityError::InvalidGeneration)
        );
    }

    #[test]
    fn revoked_capability_is_rejected_even_if_handle_is_known() {
        let mut book = CapabilityBook::new();
        let handle = book
            .subject(1)
            .grant(1, 10, ResourceType::Data, 99, Rights::READ)
            .unwrap();

        book.revoke(1, handle).unwrap();
        assert_eq!(
            book.lookup(1, handle, Rights::READ, ResourceType::Data),
            Err(CapabilityError::InvalidGeneration)
        );
    }

    #[test]
    fn stale_generation_is_rejected() {
        let mut book = CapabilityBook::new();
        let handle = book
            .subject(1)
            .grant(1, 10, ResourceType::Data, 77, Rights::READ)
            .unwrap();

        book.revoke(1, handle).unwrap();
        let stale = CapabilityHandle {
            slot: handle.slot,
            generation: handle.generation,
        };
        assert_eq!(
            book.lookup(1, stale, Rights::READ, ResourceType::Data),
            Err(CapabilityError::InvalidGeneration)
        );
    }

    #[test]
    fn child_cannot_delegate_more_than_it_received() {
        let mut book = CapabilityBook::new();
        let parent = book
            .subject(1)
            .grant(1, 10, ResourceType::Data, 42, PARENT)
            .unwrap();
        let child = book.delegate(1, parent, 2, Rights::READ).unwrap();

        let result = book.delegate(2, child, 3, Rights::WRITE);
        assert_eq!(result, Err(CapabilityError::InvalidDelegation));
    }

    #[test]
    fn object_payload_is_limited() {
        let mut store = ObjectStore::new();
        let payload = vec![b'x'; MAX_OBJECT_PAYLOAD_BYTES + 1];
        assert_eq!(
            store.try_create(1, 1, ResourceType::Data, 7, Rights::READ, payload),
            Err(CapabilityError::PayloadTooLarge)
        );
    }

    #[test]
    fn tenant_quota_is_enforced() {
        let mut store = ObjectStore::new();
        for index in 0..MAX_OBJECTS_PER_TENANT {
            let _ = store
                .try_create(
                    9,
                    10,
                    ResourceType::Data,
                    index as u64,
                    Rights::READ,
                    vec![b'x'; 8],
                )
                .unwrap();
        }

        assert_eq!(
            store.try_create(
                9,
                10,
                ResourceType::Data,
                999,
                Rights::READ,
                vec![b'z'; 8],
            ),
            Err(CapabilityError::ObjectQuotaExceeded)
        );
    }

    #[test]
    fn subject_capability_quota_is_enforced() {
        let mut book = CapabilityBook::new();
        for index in 0..MAX_CAPABILITIES_PER_SUBJECT {
            let _ = book
                .try_grant(
                    7,
                    1,
                    ResourceType::Data,
                    index as u64,
                    Rights::READ,
                )
                .unwrap();
        }

        assert_eq!(
            book.try_grant(7, 1, ResourceType::Data, 999, Rights::READ),
            Err(CapabilityError::CapabilityQuotaExceeded)
        );
    }

    // ---- Vencimiento y limite de usos (se usan relojes explicitos: deterministas) ----

    fn root_and_child(limits: Limits) -> (CapabilityBook, CapabilityHandle, CapabilityHandle) {
        let mut book = CapabilityBook::new();
        let root = book
            .try_grant(1, 10, ResourceType::Data, 5, Rights::READ | Rights::DELEGATE)
            .unwrap();
        let child = book
            .delegate_limited(1, root, 2, PARENT, limits)
            .unwrap();
        (book, root, child)
    }

    #[test]
    fn capability_expires_exactly_at_its_deadline() {
        let (book, _, child) = root_and_child(Limits { expires_at: Some(100), max_uses: None });
        let at = |now| book.lookup_at(2, child, Rights::READ, ResourceType::Data, now);
        assert!(at(0).is_ok());
        assert!(at(99).is_ok());
        assert_eq!(at(100), Err(CapabilityError::Expired));
        assert_eq!(at(10_000), Err(CapabilityError::Expired));
    }

    #[test]
    fn delegated_expiry_can_only_be_narrowed() {
        let (mut book, _, child) = root_and_child(Limits { expires_at: Some(100), max_uses: None });
        let expiry = |book: &CapabilityBook, subject, handle| {
            book.lookup_at(subject, handle, Rights::READ, ResourceType::Data, 0)
                .unwrap()
                .expires_at
        };
        // Sin pedir vencimiento hereda el del padre.
        let g1 = book.delegate_limited(2, child, 3, Rights::READ, Limits::NONE).unwrap();
        assert_eq!(expiry(&book, 3, g1), Some(100));
        // Pedir uno posterior no lo amplia.
        let g2 = book
            .delegate_limited(2, child, 4, Rights::READ, Limits { expires_at: Some(500), max_uses: None })
            .unwrap();
        assert_eq!(expiry(&book, 4, g2), Some(100));
        // Pedir uno anterior lo estrecha.
        let g3 = book
            .delegate_limited(2, child, 5, Rights::READ, Limits { expires_at: Some(50), max_uses: None })
            .unwrap();
        assert_eq!(expiry(&book, 5, g3), Some(50));
    }

    #[test]
    fn expired_parent_cannot_delegate() {
        let (mut book, _, child) = root_and_child(Limits { expires_at: Some(0), max_uses: None });
        assert_eq!(
            book.delegate_limited(2, child, 3, Rights::READ, Limits::NONE),
            Err(CapabilityError::Expired)
        );
    }

    #[test]
    fn uses_are_consumed_by_authorize_but_not_by_lookup() {
        let (mut book, _, child) = root_and_child(Limits { expires_at: None, max_uses: Some(2) });
        for _ in 0..5 {
            assert!(book.lookup_at(2, child, Rights::READ, ResourceType::Data, 0).is_ok());
        }
        assert!(book.authorize_at(2, child, Rights::READ, ResourceType::Data, 0).is_ok());
        assert!(book.authorize_at(2, child, Rights::READ, ResourceType::Data, 0).is_ok());
        assert_eq!(
            book.authorize_at(2, child, Rights::READ, ResourceType::Data, 0),
            Err(CapabilityError::UsesExhausted)
        );
        assert_eq!(
            book.lookup_at(2, child, Rights::READ, ResourceType::Data, 0),
            Err(CapabilityError::UsesExhausted)
        );
    }

    #[test]
    fn failed_authorization_does_not_consume_a_use() {
        let (mut book, _, child) = root_and_child(Limits { expires_at: None, max_uses: Some(1) });
        assert_eq!(
            book.authorize_at(2, child, Rights::WRITE, ResourceType::Data, 0),
            Err(CapabilityError::PermissionDenied)
        );
        assert!(book.authorize_at(2, child, Rights::READ, ResourceType::Data, 0).is_ok());
    }

    #[test]
    fn child_uses_come_out_of_the_parent_budget() {
        let (mut book, _, child) = root_and_child(Limits { expires_at: None, max_uses: Some(3) });
        // Mas de lo que le queda al padre, o sin limite: se rechaza.
        assert_eq!(
            book.delegate_limited(2, child, 3, Rights::READ, Limits { expires_at: None, max_uses: Some(4) }),
            Err(CapabilityError::InvalidDelegation)
        );
        assert_eq!(
            book.delegate_limited(2, child, 3, Rights::READ, Limits::NONE),
            Err(CapabilityError::InvalidDelegation)
        );
        // Cero usos no tiene sentido.
        assert_eq!(
            book.delegate_limited(2, child, 3, Rights::READ, Limits { expires_at: None, max_uses: Some(0) }),
            Err(CapabilityError::InvalidDelegation)
        );
        // Dos usos al nieto: al padre le queda uno.
        let grand = book
            .delegate_limited(2, child, 3, Rights::READ, Limits { expires_at: None, max_uses: Some(2) })
            .unwrap();
        assert!(book.authorize_at(2, child, Rights::READ, ResourceType::Data, 0).is_ok());
        assert_eq!(
            book.authorize_at(2, child, Rights::READ, ResourceType::Data, 0),
            Err(CapabilityError::UsesExhausted)
        );
        // El nieto conserva los suyos.
        assert!(book.authorize_at(3, grand, Rights::READ, ResourceType::Data, 0).is_ok());
        assert!(book.authorize_at(3, grand, Rights::READ, ResourceType::Data, 0).is_ok());
        assert_eq!(
            book.authorize_at(3, grand, Rights::READ, ResourceType::Data, 0),
            Err(CapabilityError::UsesExhausted)
        );
    }
}
