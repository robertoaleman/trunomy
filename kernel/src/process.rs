// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

use alloc::collections::BTreeMap;

use crate::capabilities::{CapabilityBook, GLOBAL_CAPABILITY_BOOK};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessContext {
    pub pid: u64,
    pub subject_id: u64,
    pub tenant_id: u64,
}

impl ProcessContext {
    pub const fn new(pid: u64, subject_id: u64, tenant_id: u64) -> Self {
        Self { pid, subject_id, tenant_id }
    }
}

pub static CURRENT_PROCESS: spin::Mutex<ProcessContext> =
    spin::Mutex::new(ProcessContext::new(1, 1, 1));

static PROCESS_TABLE: spin::Mutex<BTreeMap<u64, ProcessContext>> =
    spin::Mutex::new(BTreeMap::new());

pub fn current_process() -> ProcessContext {
    *CURRENT_PROCESS.lock()
}

pub fn register_process(pid: u64, context: ProcessContext) -> bool {
    if pid == 0
        || context.pid != pid
        || context.subject_id == 0
        || context.tenant_id == 0
    {
        return false;
    }
    PROCESS_TABLE.lock().insert(pid, context);
    true
}

pub fn process_context(pid: u64) -> Option<ProcessContext> {
    PROCESS_TABLE.lock().get(&pid).copied()
}

pub fn validate_current_capability(
    book: &CapabilityBook,
    process: ProcessContext,
    required_capability: u32,
) -> bool {
    book.has_capability_for(process.subject_id, process.tenant_id, required_capability)
}

pub fn validate_process_capability(process: ProcessContext, required_capability: u32) -> bool {
    let book = GLOBAL_CAPABILITY_BOOK.lock();
    validate_current_capability(&book, process, required_capability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{CapabilityBook, ResourceType, Rights};

    #[test]
    fn current_process_is_subject_and_tenant_bound() {
        let process = ProcessContext::new(7, 7, 42);
        let mut book = CapabilityBook::new();
        book.subject(7)
            .grant(7, 42, ResourceType::Task, 1, Rights::READ)
            .unwrap();

        assert!(validate_current_capability(&book, process, 1));
        assert!(!validate_current_capability(&book, ProcessContext::new(8, 8, 42), 1));
        assert!(!validate_current_capability(&book, ProcessContext::new(7, 7, 43), 1));
    }

    #[test]
    fn process_table_rejects_zero_pid_and_unknown_processes() {
        assert!(!register_process(0, ProcessContext::new(0, 1, 1)));
        assert!(register_process(77, ProcessContext::new(77, 7, 42)));
        assert_eq!(process_context(77), Some(ProcessContext::new(77, 7, 42)));
        assert_eq!(process_context(78), None);
    }
}
