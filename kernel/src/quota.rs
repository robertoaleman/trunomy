// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Cuotas de recursos de los procesos lanzados (parche 27, I-40).
//!
//! Codigo puro: las decisiones se toman aqui, con numeros, y se prueban en el host. Lo que mide
//! (marcos libres, ticks de CPU) lo aporta el kernel real.
//!
//! - CPU: cada worker puede correr `WORKER_CPU_TICKS` ticks en total. Al agotarlos el planificador
//!   lo detiene (`sched::Task::over_quota`) y su padre lo termina en `ProcessWait` con
//!   `abi::exit::CPU_QUOTA`. La cuota es de CPU realmente consumida, no de tiempo de pared:
//!   un worker dormido no la gasta (el plazo de `ProcessWait` acota el tiempo de pared).
//! - Memoria: un proceso nuevo no se crea si su coste estimado en marcos supera
//!   `MAX_PROCESS_FRAMES`, ni si tras crearlo quedarian menos de `KERNEL_RESERVE_FRAMES` marcos
//!   libres (reserva para el propio kernel: tablas, pilas, objetos). Como un proceso no reserva
//!   memoria despues de nacer (no hay `brk`/`mmap`), su coste queda fijado al crearlo, y con
//!   `MAX_PROCS` procesos vivos la memoria total de workers queda acotada.

/// CPU maxima por worker: 2 s a 100 Hz. Las ordenes de la shell son una syscall (milisegundos).
pub const WORKER_CPU_TICKS: u64 = 200;
/// Marcos maximos por proceso (8 MiB): imagen, pila, argumentos y tablas de paginas.
pub const MAX_PROCESS_FRAMES: usize = 2048;
/// Marcos que siempre deben quedar libres para el kernel (1 MiB).
pub const KERNEL_RESERVE_FRAMES: usize = 256;

const STACK_FRAMES: usize = 4;
const ARGS_FRAMES: usize = 1;
/// Tablas de paginas: PML4/PDPT/PD/PT del codigo y de la pila/argumentos, por exceso.
const PAGE_TABLE_BASE_FRAMES: usize = 8;

/// Cota superior de los marcos que consume un proceso con una imagen de `payload_len` bytes
/// (se redondea por exceso: una cuota nunca debe quedarse corta).
pub const fn frames_needed(payload_len: usize) -> usize {
    let code = payload_len.div_ceil(4096);
    code + STACK_FRAMES + ARGS_FRAMES + PAGE_TABLE_BASE_FRAMES + code.div_ceil(512)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    /// El proceso, por si solo, pasa de `MAX_PROCESS_FRAMES`.
    ProcessTooBig,
    /// No quedaria la reserva del kernel.
    LowMemory,
}

/// Decide si se puede crear un proceso que costaria `needed` marcos con `free` marcos libres.
pub const fn admit(needed: usize, free: usize) -> Result<(), QuotaError> {
    if needed > MAX_PROCESS_FRAMES {
        return Err(QuotaError::ProcessTooBig);
    }
    if free < needed || free - needed < KERNEL_RESERVE_FRAMES {
        return Err(QuotaError::LowMemory);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_estimate_grows_with_the_image_and_never_undercounts() {
        assert_eq!(frames_needed(0), 4 + 1 + 8);
        assert_eq!(frames_needed(1), 1 + 4 + 1 + 8 + 1);
        assert!(frames_needed(4096 * 100) >= 100 + 4 + 1);
        assert!(frames_needed(10_000) > frames_needed(5_000));
    }

    #[test]
    fn a_process_over_the_per_process_cap_is_refused_even_with_plenty_of_memory() {
        assert_eq!(admit(MAX_PROCESS_FRAMES + 1, usize::MAX / 2), Err(QuotaError::ProcessTooBig));
        assert_eq!(admit(MAX_PROCESS_FRAMES, 1_000_000), Ok(()));
    }

    #[test]
    fn the_kernel_reserve_is_never_spent_by_a_spawn() {
        let need = 100;
        assert_eq!(admit(need, need + KERNEL_RESERVE_FRAMES), Ok(()), "justo la reserva: se admite");
        assert_eq!(admit(need, need + KERNEL_RESERVE_FRAMES - 1), Err(QuotaError::LowMemory));
        assert_eq!(admit(need, 0), Err(QuotaError::LowMemory));
        assert_eq!(admit(need, need - 1), Err(QuotaError::LowMemory), "sin desbordar la resta");
    }

    #[test]
    fn worker_memory_is_bounded_by_the_process_table() {
        // MAX_PROCS procesos vivos, cada uno como mucho MAX_PROCESS_FRAMES.
        let worst = crate::proctab::MAX_PROCS * MAX_PROCESS_FRAMES;
        assert_eq!(worst * 4096, 8 * 8 * 1024 * 1024);
    }

    #[test]
    fn cpu_quota_is_a_few_seconds_not_unbounded() {
        assert!(WORKER_CPU_TICKS > 0 && WORKER_CPU_TICKS <= 1000);
        assert!(WORKER_CPU_TICKS < trunomy_abi::spawn::MAX_WAIT_TICKS);
    }
}
