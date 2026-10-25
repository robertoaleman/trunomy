// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

#![allow(dead_code)]

use crate::capabilities::{
    CapabilityBook, CapabilityError, CapabilityHandle, ResourceType, Rights,
    GLOBAL_CAPABILITY_BOOK, create_global_object, grant_object_capability,
    read_object_via_capability,
};
use crate::process::{register_process, ProcessContext};
use spin::Mutex;

const COM1: u16 = 0x3F8;
const UART_LINE_STATUS: u16 = COM1 + 5;
const DEBUG_EVENT_CAPACITY: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugEventKind {
    ReadAllowed,
    ReadDenied,
    WriteDenied,
    Revoked,
    StaleHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugEvent {
    pub sequence: u64,
    pub kind: DebugEventKind,
    pub subject_id: u64,
    pub tenant_id: u64,
    pub object_id: u64,
    pub allowed: bool,
}

pub struct DebugEventLog {
    events: [Option<DebugEvent>; DEBUG_EVENT_CAPACITY],
    next: usize,
    sequence: u64,
}

impl DebugEventLog {
    pub const fn new() -> Self {
        Self {
            events: [None; DEBUG_EVENT_CAPACITY],
            next: 0,
            sequence: 0,
        }
    }

    pub fn record(
        &mut self,
        kind: DebugEventKind,
        subject_id: u64,
        tenant_id: u64,
        object_id: u64,
        allowed: bool,
    ) {
        self.events[self.next] = Some(DebugEvent {
            sequence: self.sequence,
            kind,
            subject_id,
            tenant_id,
            object_id,
            allowed,
        });
        self.next = (self.next + 1) % DEBUG_EVENT_CAPACITY;
        self.sequence = self.sequence.saturating_add(1);
    }

    pub fn count(&self) -> usize {
        self.events.iter().flatten().count()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DebugCounters {
    pub capability_lookups: u64,
    pub capability_denied: u64,
    pub object_reads: u64,
    pub object_writes: u64,
    pub object_denied: u64,
    pub tenant_mismatches: u64,
    pub ipc_allowed: u64,
    pub ipc_denied: u64,
    pub revoked_handles: u64,
}

pub static DEBUG_EVENTS: Mutex<DebugEventLog> = Mutex::new(DebugEventLog::new());
pub static DEBUG_COUNTERS: Mutex<DebugCounters> = Mutex::new(DebugCounters {
    capability_lookups: 0,
    capability_denied: 0,
    object_reads: 0,
    object_writes: 0,
    object_denied: 0,
    tenant_mismatches: 0,
    ipc_allowed: 0,
    ipc_denied: 0,
    revoked_handles: 0,
});

unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

fn uart_put_byte(value: u8) {
    unsafe {
        while inb(UART_LINE_STATUS) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, value);
    }
}

fn uart_print(value: &str) {
    for byte in value.bytes() {
        uart_put_byte(byte);
    }
}

fn uart_line(value: &str) {
    uart_print("[DBG] ");
    uart_print(value);
    uart_print("\r\n");
}

fn uart_u64(mut value: u64) {
    let mut buffer = [0u8; 20];
    let mut index = buffer.len();

    if value == 0 {
        uart_put_byte(b'0');
        return;
    }

    while value != 0 {
        index -= 1;
        buffer[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    for byte in &buffer[index..] {
        uart_put_byte(*byte);
    }
}

fn uart_capability_error(error: CapabilityError) {
    match error {
        CapabilityError::NotFound => uart_print("not_found"),
        CapabilityError::InvalidGeneration => uart_print("invalid_generation"),
        CapabilityError::Revoked => uart_print("revoked"),
        CapabilityError::PermissionDenied => uart_print("permission_denied"),
        CapabilityError::WrongResourceType => uart_print("wrong_resource_type"),
        CapabilityError::InvalidDelegation => uart_print("invalid_delegation"),
        CapabilityError::TenantMismatch => uart_print("tenant_mismatch"),
        CapabilityError::PayloadTooLarge => uart_print("payload_too_large"),
        CapabilityError::ObjectQuotaExceeded => uart_print("object_quota_exceeded"),
        CapabilityError::CapabilityQuotaExceeded => uart_print("capability_quota_exceeded"),
        CapabilityError::ResourceIdExhausted => uart_print("resource_id_exhausted"),
        CapabilityError::OutOfMemory => uart_print("out_of_memory"),
        CapabilityError::Expired => uart_print("expired"),
        CapabilityError::UsesExhausted => uart_print("uses_exhausted"),
    }
}

fn record(
    kind: DebugEventKind,
    subject_id: u64,
    tenant_id: u64,
    object_id: u64,
    allowed: bool,
) {
    DEBUG_EVENTS
        .lock()
        .record(kind, subject_id, tenant_id, object_id, allowed);
}

pub fn debug_help() {
    uart_line("commands: help, demo tenant, dump stats, reset");
}

pub fn debug_reset_counters() {
    *DEBUG_EVENTS.lock() = DebugEventLog::new();
    *DEBUG_COUNTERS.lock() = DebugCounters::default();
    uart_line("debug counters and event log reset");
}

pub fn debug_dump_stats() {
    let counters = *DEBUG_COUNTERS.lock();
    let events = DEBUG_EVENTS.lock().count();

    uart_print("stats lookups=");
    uart_u64(counters.capability_lookups);
    uart_print(" capability_denied=");
    uart_u64(counters.capability_denied);
    uart_print(" reads=");
    uart_u64(counters.object_reads);
    uart_print(" writes=");
    uart_u64(counters.object_writes);
    uart_print(" object_denied=");
    uart_u64(counters.object_denied);
    uart_print(" tenant_mismatch=");
    uart_u64(counters.tenant_mismatches);
    uart_print(" revoked=");
    uart_u64(counters.revoked_handles);
    uart_print(" events=");
    uart_u64(events as u64);
    uart_print("\r\n");

    let audit = crate::audit::stats();
    uart_print("audit stored=");
    uart_u64(audit.stored as u64);
    uart_print(" allowed=");
    uart_u64(audit.allowed_total);
    uart_print(" denied=");
    uart_u64(audit.denied_total);
    uart_print(" overwritten=");
    uart_u64(audit.overwritten);
    uart_print("\r\n");
}

fn capability_allowed(
    book: &CapabilityBook,
    subject_id: u64,
    handle: CapabilityHandle,
    rights: Rights,
) -> Result<(), CapabilityError> {
    book.lookup(subject_id, handle, rights, ResourceType::Data)
        .map(|_| ())
}

pub fn debug_demo_two_tenants() {
    uart_line("=== two-tenant demo start ===");
    debug_reset_counters();

    let tenant_a = ProcessContext::new(10, 100, 1);
    let tenant_b = ProcessContext::new(20, 200, 2);
    let _ = register_process(tenant_a.pid, tenant_a);
    let _ = register_process(tenant_b.pid, tenant_b);
    uart_line("registered tenant A pid=10 subject=100 tenant=1");
    uart_line("registered tenant B pid=20 subject=200 tenant=2");

    let object_id = create_global_object(
        tenant_a.tenant_id,
        tenant_a.subject_id,
        ResourceType::Data,
        42,
        Rights::READ,
        alloc::vec::Vec::from(&b"tenant-a-secret"[..]),
    );

    uart_print("object created id=");
    uart_u64(object_id.0);
    uart_print(" tenant=1 owner=100 bytes=16\r\n");

    let Some(handle_a) = grant_object_capability(
        tenant_a.subject_id,
        tenant_a.tenant_id,
        ResourceType::Data,
        object_id.0,
        Rights::READ,
    ) else {
        uart_line("capability grant failed");
        return;
    };

    uart_print("capability granted subject=100 slot=");
    uart_u64(handle_a.slot as u64);
    uart_print(" generation=");
    uart_u64(handle_a.generation as u64);
    uart_print(" rights=READ\r\n");

    let read_a = {
        let book = GLOBAL_CAPABILITY_BOOK.lock();
        capability_allowed(&book, tenant_a.subject_id, handle_a, Rights::READ).is_ok()
    };
    {
        let mut counters = DEBUG_COUNTERS.lock();
        counters.capability_lookups = counters.capability_lookups.saturating_add(1);
        if read_a {
            counters.object_reads = counters.object_reads.saturating_add(1);
        } else {
            counters.capability_denied = counters.capability_denied.saturating_add(1);
        }
    }
    if read_a {
        let object = read_object_via_capability(tenant_a.subject_id, handle_a, Rights::READ);
        uart_line(if object.is_ok() {
            "tenant A READ: ALLOWED"
        } else {
            "tenant A READ: FAILED"
        });
        record(
            DebugEventKind::ReadAllowed,
            tenant_a.subject_id,
            tenant_a.tenant_id,
            object_id.0,
            object.is_ok(),
        );
    }

    let read_b = {
        let book = GLOBAL_CAPABILITY_BOOK.lock();
        capability_allowed(&book, tenant_b.subject_id, handle_a, Rights::READ).is_ok()
    };
    {
        let mut counters = DEBUG_COUNTERS.lock();
        counters.capability_lookups = counters.capability_lookups.saturating_add(1);
        counters.object_denied = counters.object_denied.saturating_add(1);
        counters.tenant_mismatches = counters.tenant_mismatches.saturating_add(1);
        if !read_b {
            counters.capability_denied = counters.capability_denied.saturating_add(1);
        }
    }
    uart_line(if read_b {
        "tenant B READ with A handle: UNEXPECTED ALLOW"
    } else {
        "tenant B READ with A handle: DENIED"
    });
    record(
        DebugEventKind::ReadDenied,
        tenant_b.subject_id,
        tenant_b.tenant_id,
        object_id.0,
        read_b,
    );

    let write_a = {
        let book = GLOBAL_CAPABILITY_BOOK.lock();
        capability_allowed(&book, tenant_a.subject_id, handle_a, Rights::WRITE).is_ok()
    };
    {
        let mut counters = DEBUG_COUNTERS.lock();
        counters.capability_lookups = counters.capability_lookups.saturating_add(1);
        counters.object_denied = counters.object_denied.saturating_add(1);
        if !write_a {
            counters.capability_denied = counters.capability_denied.saturating_add(1);
        }
    }
    uart_line(if write_a {
        "tenant A WRITE using READ handle: UNEXPECTED ALLOW"
    } else {
        "tenant A WRITE using READ handle: DENIED"
    });
    record(
        DebugEventKind::WriteDenied,
        tenant_a.subject_id,
        tenant_a.tenant_id,
        object_id.0,
        write_a,
    );

    {
        let mut book = GLOBAL_CAPABILITY_BOOK.lock();
        match book.revoke(tenant_a.subject_id, handle_a) {
            Ok(()) => {
                {
                    let mut counters = DEBUG_COUNTERS.lock();
                    counters.revoked_handles = counters.revoked_handles.saturating_add(1);
                }
                uart_line("tenant A capability revoked");
                record(
                    DebugEventKind::Revoked,
                    tenant_a.subject_id,
                    tenant_a.tenant_id,
                    object_id.0,
                    false,
                );
            }
            Err(error) => {
                uart_print("revoke failed reason=");
                uart_capability_error(error);
                uart_print("\r\n");
            }
        }
    }

    let stale = {
        let book = GLOBAL_CAPABILITY_BOOK.lock();
        book.lookup(
            tenant_a.subject_id,
            handle_a,
            Rights::READ,
            ResourceType::Data,
        )
    };
    uart_print("stale handle result=");
    match stale {
        Ok(_) => uart_line("UNEXPECTED ALLOW"),
        Err(error) => {
            uart_capability_error(error);
            uart_print("\r\n");
            record(
                DebugEventKind::StaleHandle,
                tenant_a.subject_id,
                tenant_a.tenant_id,
                object_id.0,
                false,
            );
        }
    }

    debug_dump_stats();
    uart_line("=== two-tenant demo end ===");
}

pub fn debug_execute_command(command: &str) {
    match command {
        "help" => debug_help(),
        "demo tenant" => debug_demo_two_tenants(),
        "dump stats" => debug_dump_stats(),
        "reset" => debug_reset_counters(),
        _ => uart_line("unknown command"),
    }
}
