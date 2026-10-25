// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Tabla de procesos hijos (parche 16, I-31): quien lanzo a quien y como terminaron.
//!
//! Codigo puro (sin asm, sin paginas): el ciclo de vida de un proceso es
//! `spawn -> Running -> exit -> Zombie(code) -> wait (reap) -> desaparece`.
//! - Un pid esta como mucho una vez en la tabla (un actor, un proceso vivo): no se puede lanzar
//!   otra vez hasta que el padre recoja (`wait`) al anterior.
//! - Solo el padre puede esperar a su hijo; el codigo de salida se entrega una sola vez.
//! - La tabla es fija (`MAX_PROCS`): un lanzador no puede agotar la memoria del kernel.
//! - `exit` avisa si el padre estaba dormido esperando, para que el kernel lo despierte.

#![allow(dead_code)]

pub const MAX_PROCS: usize = 8;
pub const MAX_OUTPUT: usize = trunomy_abi::output::MAX_OUTPUT;

/// Salida acumulada de un proceso (I-35): acotada, la deposita el propio proceso y la recibe su
/// padre al recogerlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Output {
    pub buf: [u8; MAX_OUTPUT],
    pub len: usize,
}

impl Output {
    pub const EMPTY: Output = Output { buf: [0; MAX_OUTPUT], len: 0 };
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PState {
    Running,
    Zombie(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: u64,
    pub parent: u64,
    pub state: PState,
    /// El padre esta dormido esperando a este hijo.
    pub parent_waiting: bool,
    pub output: Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcError {
    ZeroPid,
    /// El pid ya esta en la tabla (vivo o zombie sin recoger).
    Exists,
    Full,
    NoSuchProcess,
    /// Quien espera no es el padre.
    NotParent,
    /// `exit` sobre un proceso que ya termino.
    BadState,
    /// La salida no cabe en `MAX_OUTPUT`.
    OutputFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// El hijo ya termino: se entrega el codigo y desaparece de la tabla.
    Reaped(u64),
    /// Sigue vivo: el padre debe dormir y volver a preguntar al despertar.
    Pending,
}

pub struct ProcTable {
    slots: [Option<ProcEntry>; MAX_PROCS],
}

impl ProcTable {
    pub const fn new() -> Self {
        Self { slots: [None; MAX_PROCS] }
    }

    fn index(&self, pid: u64) -> Option<usize> {
        self.slots.iter().position(|s| s.map_or(false, |e| e.pid == pid))
    }

    pub fn get(&self, pid: u64) -> Option<&ProcEntry> {
        self.index(pid).and_then(|i| self.slots[i].as_ref())
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Copia de las entradas vivas (para `SystemInfo`).
    pub fn entries(&self) -> alloc::vec::Vec<ProcEntry> {
        self.slots.iter().flatten().copied().collect()
    }

    pub fn spawn(&mut self, pid: u64, parent: u64) -> Result<(), ProcError> {
        if pid == 0 {
            return Err(ProcError::ZeroPid);
        }
        if self.index(pid).is_some() {
            return Err(ProcError::Exists);
        }
        let slot = self.slots.iter().position(|s| s.is_none()).ok_or(ProcError::Full)?;
        self.slots[slot] = Some(ProcEntry { pid, parent, state: PState::Running, parent_waiting: false, output: Output::EMPTY });
        Ok(())
    }

    /// Deshace un `spawn` cuya creacion de proceso fallo (nunca llego a correr).
    pub fn forget(&mut self, pid: u64) {
        if let Some(i) = self.index(pid) {
            self.slots[i] = None;
        }
    }

    /// El proceso termina con `code`. Devuelve `Some(parent)` si el padre dormia esperandolo.
    pub fn exit(&mut self, pid: u64, code: u64) -> Result<Option<u64>, ProcError> {
        let i = self.index(pid).ok_or(ProcError::NoSuchProcess)?;
        let e = self.slots[i].as_mut().unwrap();
        if e.state != PState::Running {
            return Err(ProcError::BadState);
        }
        e.state = PState::Zombie(code);
        let wake = if e.parent_waiting { Some(e.parent) } else { None };
        e.parent_waiting = false;
        Ok(wake)
    }

    /// El kernel termina a `pid` por la fuerza (fallo de CPU o plazo vencido) con un codigo del
    /// rango `abi::exit`. Igual que `exit`, pero lo decide el kernel: no comprueba al llamante.
    pub fn terminate(&mut self, pid: u64, code: u64) -> Result<Option<u64>, ProcError> {
        debug_assert!(trunomy_abi::exit::is_kernel_terminated(code));
        self.exit(pid, code)
    }

    /// `caller` mata a `pid`: solo su padre, solo si sigue vivo. Devuelve `Some(parent)` si el
    /// padre dormia esperandolo.
    pub fn kill(&mut self, caller: u64, pid: u64, code: u64) -> Result<Option<u64>, ProcError> {
        let i = self.index(pid).ok_or(ProcError::NoSuchProcess)?;
        if self.slots[i].as_ref().unwrap().parent != caller {
            return Err(ProcError::NotParent);
        }
        self.terminate(pid, code)
    }

    /// `caller` espera a `child`. Si ya termino lo recoge; si no, deja constancia de que
    /// `caller` va a dormir.
    pub fn wait(&mut self, caller: u64, child: u64) -> Result<WaitOutcome, ProcError> {
        self.wait_output(caller, child).map(|(o, _)| o)
    }

    /// El proceso vivo `pid` anade `data` a su salida. Todo o nada: si no cabe, no se escribe nada.
    pub fn append_output(&mut self, pid: u64, data: &[u8]) -> Result<(), ProcError> {
        let i = self.index(pid).ok_or(ProcError::NoSuchProcess)?;
        let e = self.slots[i].as_mut().unwrap();
        if e.state != PState::Running {
            return Err(ProcError::BadState);
        }
        let end = e.output.len.checked_add(data.len()).filter(|n| *n <= MAX_OUTPUT).ok_or(ProcError::OutputFull)?;
        e.output.buf[e.output.len..end].copy_from_slice(data);
        e.output.len = end;
        Ok(())
    }

    /// Como `wait`, y al recoger entrega tambien la salida del hijo.
    pub fn wait_output(&mut self, caller: u64, child: u64) -> Result<(WaitOutcome, Output), ProcError> {
        let i = self.index(child).ok_or(ProcError::NoSuchProcess)?;
        let e = self.slots[i].as_mut().unwrap();
        if e.parent != caller {
            return Err(ProcError::NotParent);
        }
        match e.state {
            PState::Zombie(code) => {
                let out = e.output;
                self.slots[i] = None;
                Ok((WaitOutcome::Reaped(code), out))
            }
            PState::Running => {
                e.parent_waiting = true;
                Ok((WaitOutcome::Pending, Output::EMPTY))
            }
        }
    }

    /// El padre decidio no dormir (la espera fallo al bloquearse).
    pub fn cancel_wait(&mut self, child: u64) {
        if let Some(i) = self.index(child) {
            if let Some(e) = self.slots[i].as_mut() {
                e.parent_waiting = false;
            }
        }
    }
}

pub static PROCS: spin::Mutex<ProcTable> = spin::Mutex::new(ProcTable::new());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_spawn_exit_wait_reap() {
        let mut t = ProcTable::new();
        t.spawn(1001, 1).unwrap();
        assert_eq!(t.get(1001).unwrap().state, PState::Running);
        assert_eq!(t.wait(1, 1001), Ok(WaitOutcome::Pending));
        assert!(t.get(1001).unwrap().parent_waiting);
        assert_eq!(t.exit(1001, 42), Ok(Some(1)), "el padre dormia: hay que despertarlo");
        assert_eq!(t.wait(1, 1001), Ok(WaitOutcome::Reaped(42)));
        assert!(t.get(1001).is_none(), "tras recoger, desaparece");
        assert_eq!(t.wait(1, 1001), Err(ProcError::NoSuchProcess), "el codigo se entrega una sola vez");
    }

    #[test]
    fn exit_before_wait_leaves_a_zombie_with_its_code() {
        let mut t = ProcTable::new();
        t.spawn(5, 1).unwrap();
        assert_eq!(t.exit(5, 7), Ok(None));
        assert_eq!(t.get(5).unwrap().state, PState::Zombie(7));
        assert_eq!(t.spawn(5, 1), Err(ProcError::Exists), "no se relanza hasta recoger");
        assert_eq!(t.wait(1, 5), Ok(WaitOutcome::Reaped(7)));
        assert_eq!(t.spawn(5, 1), Ok(()), "recogido: el pid queda libre");
    }

    #[test]
    fn only_the_parent_can_wait_and_a_process_exits_once() {
        let mut t = ProcTable::new();
        t.spawn(9, 1).unwrap();
        assert_eq!(t.wait(2, 9), Err(ProcError::NotParent));
        assert!(!t.get(9).unwrap().parent_waiting, "un intruso no marca la espera");
        t.exit(9, 0).unwrap();
        assert_eq!(t.exit(9, 1), Err(ProcError::BadState));
        assert_eq!(t.exit(77, 0), Err(ProcError::NoSuchProcess));
        assert_eq!(t.wait(2, 9), Err(ProcError::NotParent), "ni recoger el codigo ajeno");
        assert_eq!(t.wait(1, 9), Ok(WaitOutcome::Reaped(0)));
    }

    #[test]
    fn table_is_bounded_and_rejects_pid_zero() {
        let mut t = ProcTable::new();
        assert_eq!(t.spawn(0, 1), Err(ProcError::ZeroPid));
        for pid in 1..=MAX_PROCS as u64 {
            t.spawn(pid, 1).unwrap();
        }
        assert_eq!(t.spawn(999, 1), Err(ProcError::Full));
        assert_eq!(t.len(), MAX_PROCS);
        t.forget(3);
        assert_eq!(t.spawn(999, 1), Ok(()));
    }

    #[test]
    fn only_the_parent_can_kill_and_only_a_live_process() {
        use trunomy_abi::exit::KILLED;
        let mut t = ProcTable::new();
        t.spawn(20, 1).unwrap();
        assert_eq!(t.kill(2, 20, KILLED), Err(ProcError::NotParent), "un extrano no mata");
        assert_eq!(t.get(20).unwrap().state, PState::Running);
        assert_eq!(t.kill(1, 99, KILLED), Err(ProcError::NoSuchProcess));
        assert_eq!(t.kill(1, 20, KILLED), Ok(None));
        assert_eq!(t.get(20).unwrap().state, PState::Zombie(KILLED));
        assert_eq!(t.kill(1, 20, KILLED), Err(ProcError::BadState), "ya esta muerto");
        assert_eq!(t.wait(1, 20), Ok(WaitOutcome::Reaped(KILLED)), "el padre recoge el codigo de kill");
    }

    #[test]
    fn kill_and_terminate_wake_a_sleeping_parent_once() {
        use trunomy_abi::exit::{fault, KILLED};
        let mut t = ProcTable::new();
        t.spawn(30, 1).unwrap();
        t.wait(1, 30).unwrap(); // el padre duerme
        assert_eq!(t.kill(1, 30, KILLED), Ok(Some(1)));
        assert_eq!(t.terminate(30, fault(14)), Err(ProcError::BadState), "no se termina dos veces");

        t.spawn(31, 1).unwrap();
        assert_eq!(t.terminate(31, fault(14)), Ok(None));
        assert_eq!(t.wait(1, 31), Ok(WaitOutcome::Reaped(fault(14))));
        // la shell raiz no esta en la tabla: un fallo suyo no se puede "terminar" aqui
        assert_eq!(t.terminate(1, fault(14)), Err(ProcError::NoSuchProcess));
    }

    #[test]
    fn output_is_bounded_all_or_nothing_and_reaches_only_the_parent() {
        let mut t = ProcTable::new();
        t.spawn(40, 1).unwrap();
        t.append_output(40, b"hola ").unwrap();
        t.append_output(40, b"mundo").unwrap();
        assert_eq!(t.append_output(40, &[b'x'; MAX_OUTPUT]), Err(ProcError::OutputFull));
        assert_eq!(t.get(40).unwrap().output.bytes(), b"hola mundo", "un intento fallido no deja restos");
        t.append_output(40, &[b'y'; MAX_OUTPUT - 10]).unwrap();
        assert_eq!(t.append_output(40, b"z"), Err(ProcError::OutputFull), "lleno");
        assert_eq!(t.append_output(99, b"a"), Err(ProcError::NoSuchProcess));
        assert_eq!(t.wait_output(2, 40).map(|(o, _)| o), Err(ProcError::NotParent), "un extrano no la lee");
        t.exit(40, 0).unwrap();
        assert_eq!(t.append_output(40, b"a"), Err(ProcError::BadState), "un zombie no escribe");
        let (o, out) = t.wait_output(1, 40).unwrap();
        assert_eq!(o, WaitOutcome::Reaped(0));
        assert_eq!(out.len, MAX_OUTPUT);
        assert!(out.bytes().starts_with(b"hola mundo"));
        // un pid reutilizado empieza con la salida vacia
        t.spawn(40, 1).unwrap();
        assert_eq!(t.get(40).unwrap().output.len, 0);
    }

    #[test]
    fn cancel_wait_clears_the_sleeping_flag() {
        let mut t = ProcTable::new();
        t.spawn(4, 1).unwrap();
        assert_eq!(t.wait(1, 4), Ok(WaitOutcome::Pending));
        t.cancel_wait(4);
        assert_eq!(t.exit(4, 3), Ok(None), "ya no hay nadie a quien despertar");
    }
}
