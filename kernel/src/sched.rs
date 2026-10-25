// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Planificador round-robin: politica y estructuras (parche 13, sin cambio de contexto).
//!
//! Esta capa es codigo puro (sin asm, sin puertos): decide QUE tarea corre; el parche 14
//! hara el cambio de contexto real. Reglas que se comprueban en los tests:
//! - Una tarea esta en la cola de listos como maximo una vez, y solo si esta `Ready`.
//! - Hay como mucho una tarea `Running` (la actual); el resto nunca corre a la vez.
//! - Una tarea `Blocked` o `Exited` no se elige jamas.
//! - Sin inanicion: con N tareas listas, cada una corre en <= N*quantum ticks.
//! - Todo esta acotado (`MAX_TASKS`); un pid no se reutiliza mientras exista.
//! - Las tareas dormidas despiertan cuando el reloj del kernel alcanza su plazo.
//!
//! Integracion (parche 14, `dispatch.rs`): el manejador del timer llama a `on_tick` con
//! `try_lock` (si el planificador esta ocupado solo se cuenta el tick) y `Yield` lo toma con
//! las interrupciones cerradas.

#![allow(dead_code)]

use alloc::collections::{BTreeMap, VecDeque};
use spin::Mutex;

pub const MAX_TASKS: usize = 32;
/// Ticks que corre una tarea antes de ceder (a 100 Hz: 50 ms).
pub const DEFAULT_QUANTUM: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    /// Esperando un evento (`unblock`) o un plazo (`wake_at`).
    Blocked,
    Exited,
}

/// Lo minimo que hay que guardar para reanudar una tarea cuyo estado de CPU vive en su pila de
/// kernel (las registros callee-saved se apilan al conmutar; aqui solo se recuerda donde).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SavedContext {
    pub kernel_rsp: u64,
    /// CR3 (PML4 fisica) del espacio de direcciones de la tarea.
    pub cr3: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Task {
    pub pid: u64,
    pub state: TaskState,
    pub ctx: SavedContext,
    pub quantum_left: u32,
    pub wake_at: Option<u64>,
    /// Ticks que ha corrido (contabilidad).
    pub ticks_run: u64,
    /// Cuota de CPU en ticks (I-40). `None` = sin cuota (shell raiz, tareas del kernel).
    pub cpu_limit: Option<u64>,
    /// La tarea agoto su cuota: se detiene y no vuelve a ser planificada. Solo el kernel la
    /// termina (el padre, en `ProcessWait`, con `exit::CPU_QUOTA`).
    pub over_quota: bool,
    /// Tarea (el padre) dormida esperando a esta, a la que hay que despertar al agotar la cuota.
    pub watcher: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedError {
    ZeroPid,
    AlreadyExists,
    TableFull,
    NoSuchTask,
    /// La operacion no es valida en el estado actual de la tarea.
    BadState,
}

/// Que debe hacer la CPU tras un tick o una cesion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Sigue la tarea actual.
    Continue,
    /// Cambiar de `from` (None si no habia tarea corriendo) a `to`.
    Switch { from: Option<u64>, to: u64 },
    /// No hay nada listo: la CPU debe esperar (hlt) hasta la siguiente interrupcion.
    Idle,
}

pub struct Scheduler {
    tasks: BTreeMap<u64, Task>,
    ready: VecDeque<u64>,
    current: Option<u64>,
    quantum: u32,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self { tasks: BTreeMap::new(), ready: VecDeque::new(), current: None, quantum: DEFAULT_QUANTUM }
    }

    pub fn with_quantum(quantum: u32) -> Self {
        let mut s = Self::new();
        s.quantum = quantum.max(1);
        s
    }

    pub fn current(&self) -> Option<u64> {
        self.current
    }

    pub fn task(&self, pid: u64) -> Option<&Task> {
        self.tasks.get(&pid)
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn ready_count(&self) -> usize {
        self.ready.len()
    }

    /// Crea una tarea lista para correr.
    pub fn spawn(&mut self, pid: u64, ctx: SavedContext) -> Result<(), SchedError> {
        self.spawn_limited(pid, ctx, None)
    }

    /// Como `spawn`, con una cuota de CPU fijada desde el primer tick (I-40).
    pub fn spawn_limited(&mut self, pid: u64, ctx: SavedContext, cpu_limit: Option<u64>) -> Result<(), SchedError> {
        if pid == 0 {
            return Err(SchedError::ZeroPid);
        }
        if self.tasks.contains_key(&pid) {
            return Err(SchedError::AlreadyExists);
        }
        if self.tasks.len() >= MAX_TASKS {
            return Err(SchedError::TableFull);
        }
        self.tasks.insert(
            pid,
            Task { pid, state: TaskState::Ready, ctx, quantum_left: self.quantum, wake_at: None, ticks_run: 0, cpu_limit, over_quota: false, watcher: None },
        );
        self.ready.push_back(pid);
        Ok(())
    }

    /// Fija la cuota de CPU de `pid` (ticks totales que puede correr).
    pub fn set_cpu_limit(&mut self, pid: u64, limit: u64) -> Result<(), SchedError> {
        self.tasks.get_mut(&pid).map(|t| t.cpu_limit = Some(limit)).ok_or(SchedError::NoSuchTask)
    }

    pub fn over_quota(&self, pid: u64) -> bool {
        self.tasks.get(&pid).map_or(false, |t| t.over_quota)
    }

    /// `waiter` quiere que lo despierten si `pid` agota su cuota. Devuelve `false` si `pid` ya
    /// la agoto (el llamante no debe dormir: ya hay algo que hacer).
    pub fn watch(&mut self, pid: u64, waiter: u64) -> bool {
        match self.tasks.get_mut(&pid) {
            Some(t) if !t.over_quota => {
                t.watcher = Some(waiter);
                true
            }
            Some(_) => false,
            None => true,
        }
    }

    fn make_ready(&mut self, pid: u64) {
        if self.tasks.get(&pid).map_or(false, |t| t.over_quota) {
            return; // una tarea sin cuota no vuelve a correr (I-40)
        }
        if let Some(t) = self.tasks.get_mut(&pid) {
            t.state = TaskState::Ready;
            t.wake_at = None;
            t.quantum_left = self.quantum;
            debug_assert!(!self.ready.contains(&pid));
            self.ready.push_back(pid);
        }
    }

    /// Elige la siguiente tarea de la cola, la marca `Running` y la hace actual.
    fn dispatch_next(&mut self) -> Option<u64> {
        while let Some(pid) = self.ready.pop_front() {
            // Defensa: solo se ejecuta lo que sigue listo.
            if let Some(t) = self.tasks.get_mut(&pid) {
                if t.state == TaskState::Ready {
                    t.state = TaskState::Running;
                    t.quantum_left = self.quantum;
                    self.current = Some(pid);
                    return Some(pid);
                }
            }
        }
        self.current = None;
        None
    }

    fn decision_after_leaving(&mut self, from: Option<u64>) -> Decision {
        match self.dispatch_next() {
            Some(to) if Some(to) == from => Decision::Continue,
            Some(to) => Decision::Switch { from, to },
            None => Decision::Idle,
        }
    }

    /// Despierta a las tareas dormidas cuyo plazo ya llego.
    fn wake_sleepers(&mut self, now: u64) {
        let due: alloc::vec::Vec<u64> = self
            .tasks
            .values()
            .filter(|t| t.state == TaskState::Blocked && t.wake_at.map_or(false, |w| w <= now))
            .map(|t| t.pid)
            .collect();
        for pid in due {
            self.make_ready(pid);
        }
    }

    /// Un tick del temporizador (`now` = reloj del kernel). Cuenta el quantum de la tarea
    /// actual, despierta dormidos y decide si hay que conmutar.
    pub fn on_tick(&mut self, now: u64) -> Decision {
        self.wake_sleepers(now);

        let Some(cur) = self.current else {
            return self.decision_after_leaving(None);
        };

        let (expired, over, watcher) = {
            let t = self.tasks.get_mut(&cur).expect("the current task exists");
            t.ticks_run += 1;
            t.quantum_left = t.quantum_left.saturating_sub(1);
            if t.cpu_limit.map_or(false, |l| t.ticks_run >= l) {
                t.over_quota = true;
            }
            (t.quantum_left == 0, t.over_quota, if t.over_quota { t.watcher.take() } else { None })
        };
        if over {
            // Cuota agotada: se despierta al padre para que la termine y, si hay alguien mas
            // listo, esta tarea se detiene para siempre. Si no hay nadie mas, sigue (marcada)
            // hasta que alguien pueda correr: no hay a quien quitarle la CPU.
            if let Some(w) = watcher {
                if self.tasks.get(&w).map(|t| t.state) == Some(TaskState::Blocked) {
                    self.make_ready(w);
                }
            }
            if self.ready.is_empty() {
                return Decision::Continue;
            }
            let t = self.tasks.get_mut(&cur).unwrap();
            t.state = TaskState::Blocked;
            t.wake_at = None;
            return self.decision_after_leaving(Some(cur));
        }
        if !expired {
            return Decision::Continue;
        }
        if self.ready.is_empty() {
            // Nadie mas quiere correr: recarga y sigue.
            self.tasks.get_mut(&cur).unwrap().quantum_left = self.quantum;
            return Decision::Continue;
        }
        // Cede: va al final de la cola.
        self.tasks.get_mut(&cur).unwrap().state = TaskState::Ready;
        self.ready.push_back(cur);
        self.decision_after_leaving(Some(cur))
    }

    /// Arranque: elige la primera tarea cuando todavia no hay ninguna corriendo.
    /// Con una tarea ya en marcha no hace nada (`Continue`).
    pub fn start(&mut self) -> Decision {
        if self.current.is_some() {
            return Decision::Continue;
        }
        self.decision_after_leaving(None)
    }

    /// La tarea actual cede voluntariamente la CPU.
    pub fn yield_now(&mut self) -> Result<Decision, SchedError> {
        let cur = self.current.ok_or(SchedError::BadState)?;
        if self.ready.is_empty() {
            return Ok(Decision::Continue);
        }
        self.tasks.get_mut(&cur).unwrap().state = TaskState::Ready;
        self.ready.push_back(cur);
        Ok(self.decision_after_leaving(Some(cur)))
    }

    /// La tarea actual se bloquea esperando `unblock` (o un plazo, con `wake_at`).
    pub fn block_current(&mut self, wake_at: Option<u64>) -> Result<Decision, SchedError> {
        let cur = self.current.ok_or(SchedError::BadState)?;
        let t = self.tasks.get_mut(&cur).unwrap();
        t.state = TaskState::Blocked;
        t.wake_at = wake_at;
        Ok(self.decision_after_leaving(Some(cur)))
    }

    /// Duerme la tarea actual hasta que el reloj llegue a `deadline`.
    pub fn sleep_until(&mut self, deadline: u64) -> Result<Decision, SchedError> {
        self.block_current(Some(deadline))
    }

    /// Despierta una tarea bloqueada por evento. Solo valido para `Blocked`.
    pub fn unblock(&mut self, pid: u64) -> Result<(), SchedError> {
        match self.tasks.get(&pid).map(|t| t.state) {
            None => Err(SchedError::NoSuchTask),
            Some(TaskState::Blocked) => {
                self.make_ready(pid);
                Ok(())
            }
            Some(_) => Err(SchedError::BadState),
        }
    }

    /// Termina una tarea (la actual o cualquier otra) y la retira de la tabla.
    pub fn exit(&mut self, pid: u64) -> Result<Decision, SchedError> {
        if !self.tasks.contains_key(&pid) {
            return Err(SchedError::NoSuchTask);
        }
        self.ready.retain(|p| *p != pid);
        self.tasks.remove(&pid);
        if self.current == Some(pid) {
            self.current = None;
            return Ok(self.decision_after_leaving(None));
        }
        Ok(Decision::Continue)
    }

    /// Comprueba las invariantes internas (para tests y depuracion).
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        let mut seen = alloc::collections::BTreeSet::new();
        for pid in &self.ready {
            if !seen.insert(*pid) {
                return Err("duplicate task in the ready queue");
            }
            match self.tasks.get(pid) {
                Some(t) if t.state == TaskState::Ready => {}
                _ => return Err("the queue holds a task that is not Ready"),
            }
        }
        let running: alloc::vec::Vec<_> = self.tasks.values().filter(|t| t.state == TaskState::Running).collect();
        if running.len() > 1 {
            return Err("more than one Running task");
        }
        match (self.current, running.first()) {
            (Some(c), Some(t)) if c == t.pid => {}
            (None, None) => {}
            _ => return Err("current does not match the Running task"),
        }
        for t in self.tasks.values() {
            if t.state == TaskState::Ready && !self.ready.contains(&t.pid) {
                return Err("Ready task outside the queue");
            }
            if t.state == TaskState::Exited {
                return Err("Exited task not removed");
            }
        }
        if self.tasks.len() > MAX_TASKS {
            return Err("table exceeds MAX_TASKS");
        }
        Ok(())
    }
}

pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn sched(q: u32, pids: &[u64]) -> Scheduler {
        let mut s = Scheduler::with_quantum(q);
        for p in pids {
            s.spawn(*p, SavedContext::default()).unwrap();
        }
        s
    }

    /// Corre `ticks` ticks y devuelve que pid tuvo la CPU en cada uno.
    fn run(s: &mut Scheduler, ticks: u64) -> Vec<Option<u64>> {
        let mut timeline = Vec::new();
        for now in 1..=ticks {
            let d = s.on_tick(now);
            s.check_invariants().unwrap();
            let _ = d;
            timeline.push(s.current());
        }
        timeline
    }

    #[test]
    fn a_task_over_its_cpu_quota_is_stopped_and_never_scheduled_again() {
        let mut s = sched(100, &[1, 2]);
        s.set_cpu_limit(1, 5).unwrap();
        assert_eq!(s.on_tick(1), Decision::Switch { from: None, to: 1 });
        let mut stopped = None;
        for now in 2..=10 {
            if let Decision::Switch { from: Some(1), to: 2 } = s.on_tick(now) {
                stopped = Some(now);
                break;
            }
        }
        assert_eq!(stopped, Some(6), "tras 5 ticks de CPU de la tarea 1 (el tick 1 solo despacha) pierde la CPU");
        assert!(s.over_quota(1));
        assert_eq!(s.task(1).unwrap().state, TaskState::Blocked);
        s.check_invariants().unwrap();
        // ni el tiempo, ni un despertar por evento, ni el plazo la devuelven a la cola
        let _ = s.unblock(1);
        s.wake_sleepers(u64::MAX);
        for now in 11..=400 {
            s.on_tick(now);
            assert_ne!(s.current(), Some(1));
        }
        assert_eq!(s.task(1).unwrap().ticks_run, 5, "no consumio mas CPU");
        assert!(!s.ready.contains(&1));
    }

    #[test]
    fn quota_is_per_task_and_only_counts_cpu_it_actually_ran() {
        let mut s = sched(2, &[1, 2, 3]);
        s.set_cpu_limit(2, 4).unwrap();
        run(&mut s, 60);
        assert!(s.over_quota(2));
        assert_eq!(s.task(2).unwrap().ticks_run, 4);
        assert!(!s.over_quota(1) && !s.over_quota(3), "las demas siguen sin limite");
        assert!(s.task(1).unwrap().ticks_run > 4 && s.task(3).unwrap().ticks_run > 4);
    }

    #[test]
    fn a_task_without_a_limit_is_never_stopped() {
        let mut s = sched(3, &[1, 2]);
        run(&mut s, 500);
        assert!(!s.over_quota(1) && !s.over_quota(2));
    }

    #[test]
    fn the_parent_is_woken_when_its_child_exhausts_the_quota() {
        let mut s = sched(100, &[1, 2, 3]);
        s.set_cpu_limit(2, 3).unwrap();
        assert_eq!(s.on_tick(1), Decision::Switch { from: None, to: 1 });
        // el padre (1) se bloquea esperando al hijo (2) y deja constancia
        assert!(s.watch(2, 1));
        assert_eq!(s.block_current(Some(10_000)), Ok(Decision::Switch { from: Some(1), to: 2 }));
        let mut woken = false;
        for now in 2..=6 {
            s.on_tick(now);
            if s.task(1).unwrap().state != TaskState::Blocked {
                woken = true;
                break;
            }
        }
        assert!(woken, "el padre despierta sin esperar a su plazo");
        assert!(s.over_quota(2));
        assert_eq!(s.watch(2, 1), false, "quien llega tarde ve que ya se agoto y no duerme");
        s.check_invariants().unwrap();
    }

    #[test]
    fn with_nobody_else_ready_the_task_keeps_the_cpu_but_stays_flagged() {
        let mut s = sched(100, &[1]);
        s.set_cpu_limit(1, 3).unwrap();
        for now in 1..=10 {
            let d = s.on_tick(now);
            assert!(matches!(d, Decision::Switch { .. } | Decision::Continue));
        }
        assert!(s.over_quota(1));
        assert_eq!(s.current(), Some(1), "no hay a quien dar la CPU: el planificador no queda en un estado imposible");
        s.check_invariants().unwrap();
    }

    #[test]
    fn spawn_validates_and_is_bounded() {
        let mut s = Scheduler::new();
        assert_eq!(s.spawn(0, SavedContext::default()), Err(SchedError::ZeroPid));
        s.spawn(1, SavedContext::default()).unwrap();
        assert_eq!(s.spawn(1, SavedContext::default()), Err(SchedError::AlreadyExists));
        for p in 2..=MAX_TASKS as u64 {
            s.spawn(p, SavedContext::default()).unwrap();
        }
        assert_eq!(s.spawn(999, SavedContext::default()), Err(SchedError::TableFull));
        s.check_invariants().unwrap();
    }

    #[test]
    fn first_tick_dispatches_the_first_ready_task() {
        let mut s = sched(3, &[10, 20]);
        assert_eq!(s.on_tick(1), Decision::Switch { from: None, to: 10 });
        assert_eq!(s.current(), Some(10));
    }

    #[test]
    fn round_robin_gives_each_task_its_quantum_in_order() {
        let mut s = sched(2, &[1, 2, 3]);
        let t = run(&mut s, 12);
        // tick 1 despacha a 1; cada tarea corre `quantum` ticks y cede
        let pids: Vec<u64> = t.iter().map(|p| p.unwrap()).collect();
        assert_eq!(pids, [1, 1, 2, 2, 3, 3, 1, 1, 2, 2, 3, 3]);
    }

    #[test]
    fn no_starvation_everyone_runs_within_n_times_quantum() {
        let q = 4u64;
        let mut s = sched(q as u32, &[1, 2, 3, 4, 5]);
        let timeline = run(&mut s, 5 * q * 3);
        for pid in 1..=5u64 {
            let first = timeline.iter().position(|p| *p == Some(pid)).unwrap() as u64;
            assert!(first < 5 * q, "pid {pid} tardo {first} ticks");
            let count = timeline.iter().filter(|p| **p == Some(pid)).count() as u64;
            assert_eq!(count, 3 * q, "reparto injusto para {pid}");
        }
    }

    #[test]
    fn a_lone_task_keeps_running_without_switching() {
        let mut s = sched(2, &[7]);
        assert_eq!(s.on_tick(1), Decision::Switch { from: None, to: 7 });
        for now in 2..50 {
            assert_eq!(s.on_tick(now), Decision::Continue);
        }
        assert_eq!(s.task(7).unwrap().ticks_run, 48);
        s.check_invariants().unwrap();
    }

    #[test]
    fn blocked_task_is_never_chosen_until_unblocked() {
        let mut s = sched(2, &[1, 2]);
        s.on_tick(1); // corre 1
        assert_eq!(s.block_current(None).unwrap(), Decision::Switch { from: Some(1), to: 2 });
        let t = run(&mut s, 20);
        assert!(t.iter().all(|p| *p == Some(2)), "la bloqueada no debe correr");
        s.unblock(1).unwrap();
        let t = run(&mut s, 8);
        assert!(t.contains(&Some(1)));
        s.check_invariants().unwrap();
    }

    #[test]
    fn unblock_rejects_wrong_states_and_unknown_tasks() {
        let mut s = sched(2, &[1, 2]);
        assert_eq!(s.unblock(99), Err(SchedError::NoSuchTask));
        assert_eq!(s.unblock(1), Err(SchedError::BadState)); // Ready, no Blocked
        s.on_tick(1);
        assert_eq!(s.unblock(1), Err(SchedError::BadState)); // Running
        s.check_invariants().unwrap();
    }

    #[test]
    fn everything_blocked_means_idle_and_a_wakeup_resumes() {
        let mut s = sched(2, &[1]);
        s.on_tick(1);
        assert_eq!(s.block_current(None).unwrap(), Decision::Idle);
        assert_eq!(s.on_tick(2), Decision::Idle);
        s.unblock(1).unwrap();
        assert_eq!(s.on_tick(3), Decision::Switch { from: None, to: 1 });
    }

    #[test]
    fn sleepers_wake_exactly_when_the_clock_reaches_the_deadline() {
        let mut s = sched(3, &[1, 2]);
        s.on_tick(1); // corre 1
        assert_eq!(s.sleep_until(10).unwrap(), Decision::Switch { from: Some(1), to: 2 });
        for now in 2..10 {
            s.on_tick(now);
            assert_ne!(s.current(), Some(1), "desperto antes de tiempo (now={now})");
        }
        s.on_tick(10);
        assert_eq!(s.task(1).unwrap().wake_at, None);
        let t = run(&mut s, 12);
        assert!(t.contains(&Some(1)));
        s.check_invariants().unwrap();
    }

    #[test]
    fn yield_moves_to_the_back_and_is_a_noop_when_alone() {
        let mut s = sched(10, &[1, 2]);
        s.on_tick(1); // corre 1
        assert_eq!(s.yield_now().unwrap(), Decision::Switch { from: Some(1), to: 2 });
        assert_eq!(s.yield_now().unwrap(), Decision::Switch { from: Some(2), to: 1 });
        let mut alone = sched(10, &[5]);
        alone.on_tick(1);
        assert_eq!(alone.yield_now().unwrap(), Decision::Continue);
        let mut none = Scheduler::new();
        assert_eq!(none.yield_now(), Err(SchedError::BadState));
    }

    #[test]
    fn exit_removes_the_task_everywhere() {
        let mut s = sched(3, &[1, 2, 3]);
        s.on_tick(1); // corre 1
        // salir una lista que no corre
        assert_eq!(s.exit(3).unwrap(), Decision::Continue);
        assert!(s.task(3).is_none());
        s.check_invariants().unwrap();
        // salir la actual despacha la siguiente
        assert_eq!(s.exit(1).unwrap(), Decision::Switch { from: None, to: 2 });
        assert_eq!(s.exit(2).unwrap(), Decision::Idle);
        assert_eq!(s.exit(2), Err(SchedError::NoSuchTask));
        assert_eq!(s.task_count(), 0);
        s.check_invariants().unwrap();
    }

    #[test]
    fn pid_can_be_reused_only_after_exit() {
        let mut s = sched(2, &[4]);
        assert_eq!(s.spawn(4, SavedContext::default()), Err(SchedError::AlreadyExists));
        s.exit(4).unwrap();
        s.spawn(4, SavedContext { kernel_rsp: 0x1000, cr3: 0x2000 }).unwrap();
        assert_eq!(s.task(4).unwrap().ctx.cr3, 0x2000);
        assert_eq!(s.task(4).unwrap().ticks_run, 0);
    }

    #[test]
    fn random_operation_storm_never_breaks_the_invariants() {
        // Generador congruencial: determinista y sin dependencias.
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u32
        };
        let mut s = Scheduler::with_quantum(3);
        let mut now = 0u64;
        for _ in 0..5000 {
            now += 1;
            match next() % 8 {
                0 => { let _ = s.spawn((next() % 40) as u64, SavedContext::default()); }
                1 => { let _ = s.exit((next() % 40) as u64); }
                2 => { let _ = s.block_current(if next() % 2 == 0 { Some(now + (next() % 20) as u64) } else { None }); }
                3 => { let _ = s.unblock((next() % 40) as u64); }
                4 => { let _ = s.yield_now(); }
                5 => { let _ = s.sleep_until(now + (next() % 15) as u64); }
                _ => { let _ = s.on_tick(now); }
            }
            s.check_invariants().unwrap_or_else(|e| panic!("invariante rota: {e}"));
            assert!(s.task_count() <= MAX_TASKS);
        }
    }

    #[test]
    fn start_picks_the_first_ready_task_once() {
        let mut s = Scheduler::new();
        assert_eq!(s.start(), Decision::Idle, "sin tareas no hay nada que arrancar");
        s.spawn(1, SavedContext::default()).unwrap();
        s.spawn(2, SavedContext::default()).unwrap();
        assert_eq!(s.start(), Decision::Switch { from: None, to: 1 });
        assert_eq!(s.current(), Some(1));
        assert_eq!(s.task(1).unwrap().state, TaskState::Running);
        // una segunda llamada no cambia nada
        assert_eq!(s.start(), Decision::Continue);
        assert_eq!(s.current(), Some(1));
        s.check_invariants().unwrap();
    }
}
