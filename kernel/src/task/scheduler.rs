// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/task/scheduler.rs

use super::pcb::{ProcessControlBlock, ProcessId, ProcessState};
use alloc::collections::VecDeque;
use super::pcb::{ProcessControlBlock, switch_to};


pub struct Scheduler {
    processes: VecDeque<ProcessControlBlock>,
    current_pid: Option<ProcessId>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            processes: VecDeque::new(),
            current_pid: None,
        }
    }
impl Scheduler {
    /// Ejecuta la transición de contexto física hacia la siguiente tarea lista
    pub unsafe fn context_switch(&mut self, current_pcb: &mut ProcessControlBlock) {
        if let Some(next_pcb) = self.schedule_next() {
            if current_pcb.pid != next_pcb.pid {
                let prev_ctx = &mut current_pcb.context as *mut _;
                let next_ctx = &next_pcb.context as *const _;
                let next_cr3 = next_pcb.cr3;

                // Transición atómica a nivel de procesador
                switch_to(prev_ctx, next_ctx, next_cr3);
            }
        }
    }
}
    pub fn add_process(&mut self, pcb: ProcessControlBlock) {
        self.processes.push_back(pcb);
    }

    pub fn current_process(&mut self) -> Option<&mut ProcessControlBlock> {
        let current_pid = self.current_pid?;
        self.processes.iter_mut().find(|p| p.pid == current_pid)
    }

    /// Selecciona el siguiente proceso preparado (Round-Robin simple)
    pub fn schedule_next(&mut self) -> Option<&ProcessControlBlock> {
        if let Some(mut prev) = self.processes.pop_front() {
            if prev.state == ProcessState::Running {
                prev.state = ProcessState::Ready;
            }
            self.processes.push_back(prev);
        }

        if let Some(next) = self.processes.front_mut() {
            next.state = ProcessState::Running;
            self.current_pid = Some(next.pid);
            return Some(next);
        }

        None
    }
}
