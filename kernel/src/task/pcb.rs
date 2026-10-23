// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/task/pcb.rs

use crate::loader::CapabilityEntry;
use super::CpuContext;

extern "C" {
    /// Cambia el contexto de ejecución entre dos procesos.
    /// Actualiza CR3 si 'next_cr3' pertenece a un espacio de paginación distinto.
    pub fn switch_to(
        prev_ctx: *mut CpuContext,
        next_ctx: *const CpuContext,
        next_cr3: u64,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub type ProcessId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Terminated,
}

/// Contexto de registros guardados durante el cambio de contexto (Context Switch)
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CpuContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
}

pub struct ProcessControlBlock {
    pub pid: ProcessId,
    pub state: ProcessState,
    pub context: CpuContext,
    
    /// Dirección física de la tabla de páginas del proceso (CR3 / PML4)
    pub cr3: u64,
    
    /// Puntero a la pila de Anillo 0 (Kernel Stack) usada durante syscalls e interrupciones
    pub kernel_stack_top: u64,

    /// Lista INMUTABLE de capacidades asignadas al binario firmado
    capabilities: &'static [CapabilityEntry],
}

impl ProcessControlBlock {
    pub fn new(
        pid: ProcessId,
        cr3: u64,
        entry_point: u64,
        kernel_stack_top: u64,
        user_stack_top: u64,
        capabilities: &'static [CapabilityEntry],
    ) -> Self {
        let mut context = CpuContext::default();
        context.rip = entry_point;
        context.rsp = user_stack_top;
        context.rflags = 0x202; // Bit 9 activo (IF = Interrupt Enable)

        Self {
            pid,
            state: ProcessState::Ready,
            context,
            cr3,
            kernel_stack_top,
            capabilities,
        }
    }

    /// Verificación Cero Confianza: O(N) directo sobre la lista inmutable
    #[inline(always)]
    pub fn has_capability(&self, required_cap: u32) -> bool {
        self.capabilities.iter().any(|entry| entry.cap_id == required_cap)
    }

    /// Acceso de solo lectura a la lista de capacidades
    pub fn capabilities(&self) -> &[CapabilityEntry] {
        self.capabilities
    }
}
