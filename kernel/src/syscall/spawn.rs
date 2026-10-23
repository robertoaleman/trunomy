// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! ProcessSpawn / ProcessExit / ProcessWait (parche 16, I-31).
//!
//! La logica de autorizacion y de ciclo de vida es independiente de la CPU: lo que toca paginas,
//! pilas y el planificador va detras del trait `Platform` (en el kernel real lo implementa
//! `dispatch::HwPlatform`; en las pruebas, un doble).
//!
//! - `ProcessSpawn(actor, args_ptr, args_len)`: solo el lider de la sesion con `CAP_ADMIN`,
//!   solo para actores de la sesion. Corre la imagen de la shell ya
//!   verificada al arrancar (nunca una imagen que el llamante aporte); `args` (1..=256 bytes)
//!   se copian a una pagina de solo lectura del hijo. Devuelve el pid del hijo (= el del actor).
//! - `ProcessExit(code)`: solo un proceso lanzado puede salir; el lider no.
//! - `ProcessWait(child, out_ptr, timeout_ticks)`: solo el padre; bloquea hasta que el hijo termine,
//!   escribe su codigo de salida en `*out_ptr` y recoge (libera) al hijo. El plazo es OBLIGATORIO
//!   (`1..=MAX_WAIT_TICKS`; `0` o mas es `InvalidArgument`, sin efectos): si el hijo sigue vivo al
//!   vencer el plazo el kernel lo mata y el codigo es `exit::TIMEOUT`. Si el hijo agota su cuota de
//!   CPU (`quota`), el kernel lo mata y el codigo es `exit::CPU_QUOTA` (I-40).
//! - Cuotas (I-40): un spawn que no cabe en la cuota de memoria (`quota::admit`) falla con
//!   `QuotaExceeded` antes de crear nada.
//! - `ProcessOutput(ptr, len)`: un proceso lanzado deja hasta `MAX_OUTPUT` bytes de salida; el padre
//!   los recibe en el buffer de `ProcessWait` (`[code][len][bytes]`). Un worker no tiene consola (I-35).
//! - `ProcessKill(child)`: solo el padre, solo un hijo vivo; el hijo termina con `exit::KILLED`
//!   y el padre lo recoge con `ProcessWait`. Cada intento (permitido o no) queda auditado.
//! - Un fallo de CPU en Ring 3 (`fault_with`) termina solo a ese proceso con `exit::fault(vector)`
//!   (I-33). La shell raiz no esta en la tabla: su fallo es fatal para la sesion.
//! - `ProcessExit` rechaza los codigos del rango del kernel (`abi::exit`): ese rango no se falsifica.

use spin::Mutex;
use trunomy_abi::Errno;

use crate::process::ProcessContext;
use crate::proctab::{ProcError, ProcTable, WaitOutcome};
use crate::user_access::{UserSlice, UserSpace};

pub const MAX_ARGS: usize = trunomy_abi::spawn::MAX_ARGS;

/// Lo que depende de la CPU y de la memoria fisica.
pub trait Platform {
    /// Crea el proceso (espacio de direcciones, pila, tarea lista para correr).
    fn create_process(&self, ctx: ProcessContext, args: &[u8]) -> Result<(), Errno>;
    /// Termina la tarea actual y cede la CPU para siempre; despierta al padre si dormia.
    /// En el kernel real no vuelve.
    fn exit_current(&self, pid: u64, wake_parent: Option<u64>);
    /// Libera los recursos de un hijo ya terminado (pila de kernel, espacio de direcciones).
    fn reap(&self, pid: u64);
    /// Duerme al padre hasta que `child` termine o llegue `deadline` (tick del reloj); si no puede
    /// dormir, cede un momento. En ambos casos el llamante vuelve a mirar el estado.
    fn block_for_child(&self, child: u64, deadline: Option<u64>);
    /// Reloj monotonico del kernel (ticks).
    fn now(&self) -> u64;
    /// Retira del planificador a OTRO proceso (nunca al actual) para que no vuelva a correr.
    /// Sus recursos se liberan despues con `reap`. Despierta al padre si dormia.
    fn terminate(&self, pid: u64, wake_parent: Option<u64>);
    /// Cuota de memoria: `Err(QuotaExceeded)` si un proceso nuevo no cabe (I-40). Sin efectos.
    fn admit_memory(&self) -> Result<(), Errno>;
    /// El proceso `pid` agoto su cuota de CPU y el planificador lo detuvo (I-40).
    fn cpu_quota_exceeded(&self, pid: u64) -> bool;
}

fn audit_process(op: crate::audit::AuditOp, subject: u64, tenant: u64, resource: u64, outcome: crate::audit::AuditOutcome) {
    crate::audit::record(subject, op, None, Some(tenant), Some(resource), outcome);
}

pub fn spawn_with<S: UserSpace, P: Platform>(
    current: ProcessContext,
    space: &S,
    plat: &P,
    procs: &Mutex<ProcTable>,
    authorize: impl FnOnce() -> Result<ProcessContext, Errno>,
    args_ptr: u64,
    args_len: u64,
) -> Result<u64, Errno> {
    // 1. Validar los argumentos (sin efectos): vacios no valen, la shell raiz no es un worker.
    let args = UserSlice::new(args_ptr, args_len)
        .and_then(|s| s.read_to_vec(space, MAX_ARGS))
        .map_err(|e| e.errno())?;
    if args.is_empty() {
        return Err(Errno::InvalidArgument);
    }
    // 2. Autorizar (y auditar).
    let ctx = authorize()?;
    // 3. Cuota de memoria: si el proceso no cabe, no se reserva nada.
    plat.admit_memory()?;
    // 4. Reservar el pid en la tabla y crear el proceso; si falla, se deshace.
    procs.lock().spawn(ctx.pid, current.pid).map_err(|_| Errno::ResourceUnavailable)?;
    if let Err(e) = plat.create_process(ctx, &args) {
        procs.lock().forget(ctx.pid);
        return Err(e);
    }
    Ok(ctx.pid)
}

/// Devuelve solo si falla (en el kernel real, `exit_current` no vuelve).
pub fn exit_with<P: Platform>(current: ProcessContext, plat: &P, procs: &Mutex<ProcTable>, code: u64) -> u64 {
    // Los codigos del rango del kernel solo los pone el kernel (I-33).
    if trunomy_abi::exit::is_kernel_terminated(code) {
        return Errno::InvalidArgument.code();
    }
    let wake = match procs.lock().exit(current.pid, code) {
        Ok(w) => w,
        // Solo un proceso lanzado (en la tabla) puede salir: la shell raiz no.
        Err(_) => return Errno::PermissionDenied.code(),
    };
    plat.exit_current(current.pid, wake);
    trunomy_abi::OK
}

/// Mata a `pid` (hijo de `current`) con `code` y lo retira del planificador. Audita el intento.
pub(super) fn kill_child<P: Platform>(
    current: ProcessContext,
    plat: &P,
    procs: &Mutex<ProcTable>,
    pid: u64,
    code: u64,
) -> Result<(), Errno> {
    use crate::audit::{AuditOp, AuditOutcome};
    use crate::capabilities::CapabilityError;
    let r = procs.lock().kill(current.pid, pid, code);
    match r {
        Ok(wake) => {
            audit_process(AuditOp::ProcessKill, current.pid, current.tenant_id, pid, AuditOutcome::Allowed);
            plat.terminate(pid, wake);
            Ok(())
        }
        Err(e) => {
            let (errno, why) = match e {
                ProcError::NotParent => (Errno::PermissionDenied, CapabilityError::PermissionDenied),
                _ => (Errno::InvalidArgument, CapabilityError::NotFound),
            };
            audit_process(AuditOp::ProcessKill, current.pid, current.tenant_id, pid, AuditOutcome::Denied(why));
            Err(errno)
        }
    }
}

pub fn kill_with<P: Platform>(
    current: ProcessContext,
    plat: &P,
    procs: &Mutex<ProcTable>,
    pid: u64,
) -> Result<u64, Errno> {
    if pid == current.pid {
        return Err(Errno::InvalidArgument); // para salir, `ProcessExit`
    }
    kill_child(current, plat, procs, pid, trunomy_abi::exit::KILLED)?;
    Ok(0)
}

/// Fallo de CPU en Ring 3 del proceso `current`: lo termina a el solo. Devuelve `false` (sin
/// hacer nada) si `current` no es un proceso lanzado, es decir, la shell raiz: el llamante debe
/// detener el sistema. En el kernel real, con `true` no se vuelve (la tarea ya no existe).
pub fn fault_with<P: Platform>(current: ProcessContext, vector: u8, plat: &P, procs: &Mutex<ProcTable>) -> bool {
    use crate::audit::{AuditOp, AuditOutcome};
    let code = trunomy_abi::exit::fault(vector);
    let r = procs.lock().terminate(current.pid, code);
    match r {
        Ok(wake) => {
            audit_process(AuditOp::ProcessFault, current.pid, current.tenant_id, code, AuditOutcome::Allowed);
            plat.exit_current(current.pid, wake);
            true
        }
        Err(_) => false,
    }
}

pub fn wait_with<S: UserSpace, P: Platform>(
    current: ProcessContext,
    space: &S,
    plat: &P,
    procs: &Mutex<ProcTable>,
    child: u64,
    out_ptr: u64,
    timeout_ticks: u64,
) -> Result<u64, Errno> {
    let out = UserSlice::new(out_ptr, trunomy_abi::output::WAIT_RESULT_SIZE as u64).map_err(|e| e.errno())?;
    // El plazo es obligatorio y acotado (I-40): sin el, un hijo colgado dejaria al padre
    // dormido para siempre. Se rechaza antes de mirar al hijo, sin efectos.
    if timeout_ticks == 0 || timeout_ticks > trunomy_abi::spawn::MAX_WAIT_TICKS {
        return Err(Errno::InvalidArgument);
    }
    let deadline = Some(plat.now().saturating_add(timeout_ticks));
    loop {
        let r = procs.lock().wait_output(current.pid, child);
        match r {
            Err(ProcError::NotParent) => return Err(Errno::PermissionDenied),
            Err(_) => return Err(Errno::InvalidArgument),
            Ok((WaitOutcome::Reaped(code), output)) => {
                plat.reap(child);
                // [code: u64][len: u64][bytes; MAX_OUTPUT]: una sola escritura, con el relleno a cero.
                let mut res = [0u8; trunomy_abi::output::WAIT_RESULT_SIZE];
                res[..8].copy_from_slice(&code.to_le_bytes());
                res[8..16].copy_from_slice(&(output.len as u64).to_le_bytes());
                res[16..16 + output.len].copy_from_slice(output.bytes());
                out.write_from(space, &res).map_err(|e| e.errno())?;
                return Ok(0);
            }
            Ok((WaitOutcome::Pending, _)) => {
                if plat.cpu_quota_exceeded(child) {
                    // El hijo agoto su CPU y esta detenido: el kernel lo termina.
                    procs.lock().cancel_wait(child);
                    kill_child(current, plat, procs, child, trunomy_abi::exit::CPU_QUOTA)?;
                    continue;
                }
                if deadline.map_or(false, |d| plat.now() >= d) {
                    // Plazo vencido y el hijo sigue vivo: el kernel lo mata. El siguiente giro del
                    // bucle lo recoge con el codigo `TIMEOUT`.
                    procs.lock().cancel_wait(child);
                    kill_child(current, plat, procs, child, trunomy_abi::exit::TIMEOUT)?;
                    continue;
                }
                plat.block_for_child(child, deadline)
            }
        }
    }
}

/// `ProcessOutput(ptr, len)`: un proceso lanzado deja su salida para su padre. Un proceso
/// que no esta en la tabla (la shell raiz) tiene consola y no usa este canal.
pub fn output_with<S: UserSpace>(
    current: ProcessContext,
    space: &S,
    procs: &Mutex<ProcTable>,
    ptr: u64,
    len: u64,
) -> Result<u64, Errno> {
    let data = UserSlice::new(ptr, len)
        .and_then(|s| s.read_to_vec(space, trunomy_abi::output::MAX_OUTPUT))
        .map_err(|e| e.errno())?;
    match procs.lock().append_output(current.pid, &data) {
        Ok(()) => Ok(0),
        Err(ProcError::OutputFull) => Err(Errno::QuotaExceeded),
        Err(_) => Err(Errno::PermissionDenied),
    }
}

// --- Entradas del dispatcher (estado global) ---

#[cfg(not(test))]
pub fn process_spawn(current: ProcessContext, actor: u64, args_ptr: u64, args_len: u64) -> u64 {
    use crate::syscall::identity;
    use crate::user_access::ActiveUserSpace;
    let r = spawn_with(
        current,
        &ActiveUserSpace,
        &crate::dispatch::HwPlatform,
        &crate::proctab::PROCS,
        || identity::authorize_spawn(current, actor),
        args_ptr,
        args_len,
    );
    r.unwrap_or_else(|e| e.code())
}

#[cfg(not(test))]
pub fn process_exit(current: ProcessContext, code: u64) -> u64 {
    exit_with(current, &crate::dispatch::HwPlatform, &crate::proctab::PROCS, code)
}

#[cfg(not(test))]
pub fn process_wait(current: ProcessContext, child: u64, out_ptr: u64, timeout_ticks: u64) -> u64 {
    use crate::user_access::ActiveUserSpace;
    wait_with(current, &ActiveUserSpace, &crate::dispatch::HwPlatform, &crate::proctab::PROCS, child, out_ptr, timeout_ticks)
        .unwrap_or_else(|e| e.code())
}

#[cfg(not(test))]
pub fn process_output(current: ProcessContext, ptr: u64, len: u64) -> u64 {
    use crate::user_access::ActiveUserSpace;
    output_with(current, &ActiveUserSpace, &crate::proctab::PROCS, ptr, len).unwrap_or_else(|e| e.code())
}

#[cfg(not(test))]
pub fn process_kill(current: ProcessContext, pid: u64) -> u64 {
    kill_with(current, &crate::dispatch::HwPlatform, &crate::proctab::PROCS, pid).unwrap_or_else(|e| e.code())
}

// En el host no hay CPU, pilas ni paginas que crear: las entradas globales responden
// "no disponible" (la logica real se prueba con `spawn_with`/`exit_with`/`wait_with`).
#[cfg(test)]
pub fn process_spawn(_current: ProcessContext, _actor: u64, _args_ptr: u64, _args_len: u64) -> u64 {
    Errno::ResourceUnavailable.code()
}

#[cfg(test)]
pub fn process_exit(_current: ProcessContext, _code: u64) -> u64 {
    Errno::ResourceUnavailable.code()
}

#[cfg(test)]
pub fn process_wait(_current: ProcessContext, _child: u64, _out_ptr: u64, _timeout_ticks: u64) -> u64 {
    Errno::ResourceUnavailable.code()
}

#[cfg(test)]
pub fn process_output(_current: ProcessContext, _ptr: u64, _len: u64) -> u64 {
    Errno::ResourceUnavailable.code()
}

#[cfg(test)]
pub fn process_kill(_current: ProcessContext, _pid: u64) -> u64 {
    Errno::ResourceUnavailable.code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{ResourceType, Rights, GLOBAL_CAPABILITY_BOOK};
    use crate::memory_validation::USER_MIN;
    use crate::process::register_process;
    use crate::syscall::identity::{Session, CAP_ADMIN};
    use crate::user_access::tests::MockUserSpace;
    use core::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        created: RefCell<alloc::vec::Vec<(ProcessContext, alloc::vec::Vec<u8>)>>,
        exited: RefCell<alloc::vec::Vec<(u64, Option<u64>)>>,
        reaped: RefCell<alloc::vec::Vec<u64>>,
        blocks: RefCell<u32>,
        terminated: RefCell<alloc::vec::Vec<(u64, Option<u64>)>>,
        deadlines: RefCell<alloc::vec::Vec<Option<u64>>>,
        /// Reloj de la plataforma de prueba; cada `block_for_child` lo adelanta `tick_on_block`.
        clock: RefCell<u64>,
        tick_on_block: u64,
        fail_create: bool,
        /// Al bloquear al padre, "el hijo" termina con este codigo.
        exit_child_on_block: RefCell<Option<(u64, u64)>>,
        procs: Option<&'static Mutex<ProcTable>>,
        memory_denied: bool,
        over_quota: RefCell<alloc::vec::Vec<u64>>,
    }

    impl Platform for Fake {
        fn admit_memory(&self) -> Result<(), Errno> {
            if self.memory_denied { Err(Errno::QuotaExceeded) } else { Ok(()) }
        }
        fn cpu_quota_exceeded(&self, pid: u64) -> bool {
            self.over_quota.borrow().contains(&pid)
        }
        fn create_process(&self, ctx: ProcessContext, args: &[u8]) -> Result<(), Errno> {
            if self.fail_create {
                return Err(Errno::ResourceUnavailable);
            }
            self.created.borrow_mut().push((ctx, args.to_vec()));
            Ok(())
        }
        fn exit_current(&self, pid: u64, wake: Option<u64>) {
            self.exited.borrow_mut().push((pid, wake));
        }
        fn reap(&self, pid: u64) {
            self.reaped.borrow_mut().push(pid);
        }
        fn now(&self) -> u64 {
            *self.clock.borrow()
        }
        fn terminate(&self, pid: u64, wake: Option<u64>) {
            self.terminated.borrow_mut().push((pid, wake));
        }
        fn block_for_child(&self, _child: u64, deadline: Option<u64>) {
            self.deadlines.borrow_mut().push(deadline);
            *self.clock.borrow_mut() += self.tick_on_block;
            *self.blocks.borrow_mut() += 1;
            if let (Some((pid, code)), Some(p)) = (self.exit_child_on_block.borrow_mut().take(), self.procs) {
                p.lock().exit(pid, code).unwrap();
            }
        }
    }

    /// Sesion de prueba: lider admin `pid`, tenant y un actor. Ids unicos por test.
    fn session(pid: u64) -> (ProcessContext, Session, u64, ProcessContext) {
        let lead = ProcessContext::new(pid, pid, pid);
        assert!(register_process(pid, lead));
        GLOBAL_CAPABILITY_BOOK.lock().try_grant(pid, pid, ResourceType::Task, CAP_ADMIN as u64, Rights::READ).unwrap();
        let mut s = Session::new(pid, pid * 1000, pid * 1000);
        let t = s.tenant_create(lead).unwrap();
        let actor = s.actor_create(lead, t).unwrap();
        let actx = crate::process::process_context(actor).unwrap();
        (lead, s, actor, actx)
    }

    fn put_args(sp: &MockUserSpace, bytes: &[u8]) {
        sp.mem.borrow_mut()[..bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn spawn_runs_the_actor_identity_with_the_given_args_and_audits_it() {
        let sp = MockUserSpace::new(4096);
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let (lead, s, actor, actx) = session(7101);
        put_args(&sp, b"hola");
        let pid = spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, actor), USER_MIN, 4).unwrap();
        assert_eq!(pid, actor);
        let created = plat.created.borrow();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].0, actx, "el hijo hereda la identidad del actor, no la del lider");
        assert_eq!(created[0].1, b"hola");
        assert_eq!(procs.lock().get(actor).unwrap().parent, lead.pid);
    }

    #[test]
    fn spawn_rejects_bad_args_before_authorizing() {
        let sp = MockUserSpace::new(4096);
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let (lead, s, actor, _) = session(7102);
        let mut authorized = false;
        // vacios
        assert_eq!(
            spawn_with(lead, &sp, &plat, &procs, || { authorized = true; s.authorize_spawn(lead, actor) }, USER_MIN, 0),
            Err(Errno::InvalidArgument)
        );
        assert!(!authorized, "con argumentos invalidos no se llega a autorizar ni a auditar");
        // demasiado largos
        assert!(spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, actor), USER_MIN, (MAX_ARGS + 1) as u64).is_err());
        // puntero fuera del espacio de usuario
        assert_eq!(
            spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, actor), 0, 4),
            Err(Errno::InvalidPointer)
        );
        assert!(plat.created.borrow().is_empty());
        assert_eq!(procs.lock().len(), 0);
    }

    #[test]
    fn spawn_requires_the_leader_and_a_session_actor() {
        let sp = MockUserSpace::new(4096);
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let (lead, s, actor, actx) = session(7103);
        put_args(&sp, b"x");
        // un actor no lanza procesos
        assert_eq!(
            spawn_with(actx, &sp, &plat, &procs, || s.authorize_spawn(actx, actor), USER_MIN, 1),
            Err(Errno::PermissionDenied)
        );
        // el lider no puede lanzar a un pid ajeno a la sesion
        assert_eq!(
            spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, 1), USER_MIN, 1),
            Err(Errno::InvalidArgument)
        );
        assert!(plat.created.borrow().is_empty());
    }

    #[test]
    fn a_live_actor_cannot_be_launched_twice_until_reaped() {
        let sp = MockUserSpace::new(4096);
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let (lead, s, actor, _) = session(7104);
        put_args(&sp, b"x");
        let go = || spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, actor), USER_MIN, 1);
        assert_eq!(go(), Ok(actor));
        assert_eq!(go(), Err(Errno::ResourceUnavailable));
        procs.lock().exit(actor, 0).unwrap();
        assert_eq!(go(), Err(Errno::ResourceUnavailable), "zombie sin recoger");
        procs.lock().wait(lead.pid, actor).unwrap();
        assert_eq!(go(), Ok(actor));
    }

    #[test]
    fn failed_process_creation_rolls_back_the_table() {
        let sp = MockUserSpace::new(4096);
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake { fail_create: true, ..Fake::default() };
        let (lead, s, actor, _) = session(7105);
        put_args(&sp, b"x");
        assert_eq!(
            spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, actor), USER_MIN, 1),
            Err(Errno::ResourceUnavailable)
        );
        assert!(procs.lock().get(actor).is_none(), "no queda un hijo fantasma");
    }

    #[test]
    fn only_a_spawned_process_can_exit_and_it_wakes_a_waiting_parent() {
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let lead = ProcessContext::new(7106, 7106, 1);
        assert_eq!(exit_with(lead, &plat, &procs, 0), Errno::PermissionDenied.code(), "la shell raiz no sale");
        assert!(plat.exited.borrow().is_empty());

        let child = ProcessContext::new(7107, 7107, 1);
        procs.lock().spawn(7107, 7106).unwrap();
        procs.lock().wait(7106, 7107).unwrap(); // el padre queda dormido
        assert_eq!(exit_with(child, &plat, &procs, 99), trunomy_abi::OK);
        assert_eq!(*plat.exited.borrow(), [(7107, Some(7106))]);
        // salir dos veces no se puede
        assert_eq!(exit_with(child, &plat, &procs, 1), Errno::PermissionDenied.code());
    }

    #[test]
    fn wait_blocks_then_reaps_and_delivers_the_code_once() {
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake { procs: Some(&PROCS), ..Fake::default() };
        let lead = ProcessContext::new(7108, 7108, 1);
        PROCS.lock().spawn(7109, 7108).unwrap();
        *plat.exit_child_on_block.borrow_mut() = Some((7109, 0xABCD));
        assert_eq!(wait_with(lead, &sp, &plat, &PROCS, 7109, USER_MIN, 1000), Ok(0));
        assert_eq!(*plat.blocks.borrow(), 1, "el hijo seguia vivo: el padre durmio una vez");
        assert_eq!(*plat.reaped.borrow(), [7109]);
        assert_eq!(&sp.mem.borrow()[..8], &0xABCDu64.to_le_bytes());
        // ya recogido: no hay segunda entrega
        assert_eq!(wait_with(lead, &sp, &plat, &PROCS, 7109, USER_MIN, 1000), Err(Errno::InvalidArgument));
    }

    #[test]
    fn a_workers_output_reaches_only_its_parent_through_wait() {
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake { procs: Some(&PROCS), ..Fake::default() };
        let lead = ProcessContext::new(7300, 7300, 1);
        let worker = ProcessContext::new(7301, 7301, 1);
        PROCS.lock().spawn(7301, 7300).unwrap();
        // el worker deja su salida (copiada una vez de su memoria)
        sp.mem.borrow_mut()[64..69].copy_from_slice(b"hola!");
        assert_eq!(output_with(worker, &sp, &PROCS, USER_MIN + 64, 5), Ok(0));
        assert_eq!(output_with(worker, &sp, &PROCS, USER_MIN + 64, 0), Ok(0), "vacia vale");
        // la shell raiz (no esta en la tabla) tiene consola: no usa este canal
        assert_eq!(output_with(lead, &sp, &PROCS, USER_MIN + 64, 5), Err(Errno::PermissionDenied));
        // mas de MAX_OUTPUT no cabe, ni de golpe ni acumulado
        assert_eq!(output_with(worker, &sp, &PROCS, USER_MIN, 257), Err(Errno::InvalidArgument), "mas que MAX_OUTPUT de golpe");
        assert_eq!(output_with(worker, &sp, &PROCS, USER_MIN + 128, 252), Err(Errno::QuotaExceeded), "5 + 252 > 256");
        assert_eq!(PROCS.lock().get(7301).unwrap().output.bytes(), b"hola!", "un intento fallido no deja restos");

        PROCS.lock().exit(7301, 3).unwrap();
        assert_eq!(output_with(worker, &sp, &PROCS, USER_MIN + 64, 5), Err(Errno::PermissionDenied), "un zombie no escribe");
        // un extrano no puede recoger (ni leer) la salida
        let stranger = ProcessContext::new(7302, 7302, 1);
        assert_eq!(wait_with(stranger, &sp, &plat, &PROCS, 7301, USER_MIN + 1024, 1000), Err(Errno::PermissionDenied));
        assert_eq!(&sp.mem.borrow()[1024..1040], &[0u8; 16], "no se escribio nada en la memoria del extrano");
        // el padre la recibe: [code][len][bytes]
        assert_eq!(wait_with(lead, &sp, &plat, &PROCS, 7301, USER_MIN + 1024, 1000), Ok(0));
        let m = sp.mem.borrow();
        assert_eq!(&m[1024..1032], &3u64.to_le_bytes());
        assert_eq!(&m[1032..1040], &5u64.to_le_bytes());
        assert_eq!(&m[1040..1045], b"hola!");
        assert!(m[1045..1024 + trunomy_abi::output::WAIT_RESULT_SIZE].iter().all(|b| *b == 0), "el resto va a cero");
    }

    #[test]
    fn wait_needs_room_for_the_whole_result() {
        let procs = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(300);
        let plat = Fake::default();
        procs.lock().spawn(7311, 7310).unwrap();
        procs.lock().exit(7311, 0).unwrap();
        let parent = ProcessContext::new(7310, 7310, 1);
        // 272 bytes no caben a partir de USER_MIN+100 en una ventana de 300: no se recoge nada
        assert!(wait_with(parent, &sp, &plat, &procs, 7311, USER_MIN + 100, 1000).is_err());
        assert!(plat.reaped.borrow().is_empty() || procs.lock().get(7311).is_none());
    }

    #[test]
    fn wait_rejects_strangers_and_bad_pointers() {
        let procs = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake::default();
        procs.lock().spawn(7111, 7110).unwrap();
        procs.lock().exit(7111, 5).unwrap();
        let stranger = ProcessContext::new(7112, 7112, 1);
        assert_eq!(wait_with(stranger, &sp, &plat, &procs, 7111, USER_MIN, 1000), Err(Errno::PermissionDenied));
        let parent = ProcessContext::new(7110, 7110, 1);
        assert_eq!(wait_with(parent, &sp, &plat, &procs, 7111, 0, 1000), Err(Errno::InvalidPointer));
        assert!(plat.reaped.borrow().is_empty(), "con un puntero invalido no se recoge nada");
        assert!(procs.lock().get(7111).is_some());
        assert_eq!(wait_with(parent, &sp, &plat, &procs, 7111, USER_MIN, 1000), Ok(0));
        assert_eq!(&sp.mem.borrow()[..8], &5u64.to_le_bytes());
    }

    #[test]
    fn a_user_cannot_exit_with_a_kernel_only_code() {
        use trunomy_abi::exit::{fault, KILLED, TIMEOUT};
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let child = ProcessContext::new(7120, 7120, 1);
        procs.lock().spawn(7120, 7119).unwrap();
        for forged in [fault(14), KILLED, TIMEOUT] {
            assert_eq!(exit_with(child, &plat, &procs, forged), Errno::InvalidArgument.code());
        }
        assert!(plat.exited.borrow().is_empty(), "no se llego a terminar el proceso");
        assert_eq!(procs.lock().get(7120).unwrap().state, crate::proctab::PState::Running);
        assert_eq!(exit_with(child, &plat, &procs, 5), trunomy_abi::OK, "un codigo normal si");
    }

    #[test]
    fn only_the_parent_can_kill_and_every_attempt_is_audited() {
        use crate::audit::{events_for_subject, AuditOp, AuditOutcome};
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let parent = ProcessContext::new(7130, 7130, 1);
        let stranger = ProcessContext::new(7132, 7132, 1);
        procs.lock().spawn(7131, 7130).unwrap();

        assert_eq!(kill_with(stranger, &plat, &procs, 7131), Err(Errno::PermissionDenied));
        assert!(plat.terminated.borrow().is_empty(), "un extrano no retira nada del planificador");
        assert_eq!(procs.lock().get(7131).unwrap().state, crate::proctab::PState::Running);
        let denied = events_for_subject(7132);
        assert!(denied.iter().any(|e| e.op == AuditOp::ProcessKill && e.resource_id == Some(7131) && matches!(e.outcome, AuditOutcome::Denied(_))));

        assert_eq!(kill_with(parent, &plat, &procs, 7130), Err(Errno::InvalidArgument), "no se mata a si mismo");
        assert_eq!(kill_with(parent, &plat, &procs, 99999), Err(Errno::InvalidArgument));
        assert_eq!(kill_with(parent, &plat, &procs, 7131), Ok(0));
        assert_eq!(*plat.terminated.borrow(), [(7131, None)]);
        assert_eq!(kill_with(parent, &plat, &procs, 7131), Err(Errno::InvalidArgument), "ya esta muerto");
        let ok = events_for_subject(7130);
        assert!(ok.iter().any(|e| e.op == AuditOp::ProcessKill && e.resource_id == Some(7131) && e.outcome == AuditOutcome::Allowed));
        // el padre recoge el codigo KILLED
        assert_eq!(procs.lock().wait(7130, 7131), Ok(WaitOutcome::Reaped(trunomy_abi::exit::KILLED)));
    }

    #[test]
    fn a_cpu_fault_terminates_only_that_process_and_wakes_the_parent() {
        use crate::audit::{events_for_subject, AuditOp, AuditOutcome};
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let child = ProcessContext::new(7141, 7141, 3);
        procs.lock().spawn(7141, 7140).unwrap();
        procs.lock().spawn(7142, 7140).unwrap(); // un hermano que no debe verse afectado
        procs.lock().wait(7140, 7141).unwrap(); // el padre duerme esperandolo

        assert!(fault_with(child, 14, &plat, &procs));
        assert_eq!(*plat.exited.borrow(), [(7141, Some(7140))], "sale el culpable y se despierta al padre");
        assert_eq!(procs.lock().get(7142).unwrap().state, crate::proctab::PState::Running);
        let code = trunomy_abi::exit::fault(14);
        assert_eq!(procs.lock().wait(7140, 7141), Ok(WaitOutcome::Reaped(code)));
        assert_eq!(trunomy_abi::exit::fault_vector(code), Some(14));
        let ev = events_for_subject(7141);
        assert!(ev.iter().any(|e| e.op == AuditOp::ProcessFault && e.resource_id == Some(code) && e.outcome == AuditOutcome::Allowed));
    }

    #[test]
    fn a_fault_in_the_root_shell_is_not_contained() {
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let root = ProcessContext::new(7150, 7150, 1);
        assert!(!fault_with(root, 13, &plat, &procs), "la raiz no esta en la tabla: el sistema debe detenerse");
        assert!(plat.exited.borrow().is_empty());
    }

    #[test]
    fn a_fault_cannot_be_reported_twice() {
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake::default();
        let child = ProcessContext::new(7161, 7161, 1);
        procs.lock().spawn(7161, 7160).unwrap();
        assert!(fault_with(child, 6, &plat, &procs));
        assert!(!fault_with(child, 6, &plat, &procs), "un proceso ya terminado no vuelve a terminar");
        assert_eq!(plat.exited.borrow().len(), 1);
    }

    #[test]
    fn wait_with_a_timeout_kills_a_hung_child_and_reports_timeout() {
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake { tick_on_block: 40, ..Fake::default() };
        let parent = ProcessContext::new(7170, 7170, 1);
        PROCS.lock().spawn(7171, 7170).unwrap(); // nunca termina por su cuenta
        assert_eq!(wait_with(parent, &sp, &plat, &PROCS, 7171, USER_MIN, 100), Ok(0));
        assert_eq!(&sp.mem.borrow()[..8], &trunomy_abi::exit::TIMEOUT.to_le_bytes());
        assert_eq!(*plat.blocks.borrow(), 3, "durmio hasta el plazo (0,40,80 -> 120 >= 100) y luego mato");
        assert!(plat.deadlines.borrow().iter().all(|d| *d == Some(100)));
        assert_eq!(*plat.terminated.borrow(), [(7171, None)]);
        assert_eq!(*plat.reaped.borrow(), [7171], "y recogio al hijo");
        assert!(PROCS.lock().get(7171).is_none());
    }

    #[test]
    fn wait_with_a_timeout_does_not_kill_a_child_that_finishes_in_time() {
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake { procs: Some(&PROCS), tick_on_block: 10, ..Fake::default() };
        let parent = ProcessContext::new(7180, 7180, 1);
        PROCS.lock().spawn(7181, 7180).unwrap();
        *plat.exit_child_on_block.borrow_mut() = Some((7181, 77));
        assert_eq!(wait_with(parent, &sp, &plat, &PROCS, 7181, USER_MIN, 100), Ok(0));
        assert_eq!(&sp.mem.borrow()[..8], &77u64.to_le_bytes());
        assert!(plat.terminated.borrow().is_empty());
    }

    #[test]
    fn wait_requires_a_deadline_and_bounds_it_before_any_effect() {
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake::default();
        let parent = ProcessContext::new(7190, 7190, 1);
        PROCS.lock().spawn(7191, 7190).unwrap();
        use trunomy_abi::spawn::MAX_WAIT_TICKS;
        assert_eq!(wait_with(parent, &sp, &plat, &PROCS, 7191, USER_MIN, 0), Err(Errno::InvalidArgument), "sin plazo no se espera");
        assert_eq!(wait_with(parent, &sp, &plat, &PROCS, 7191, USER_MIN, MAX_WAIT_TICKS + 1), Err(Errno::InvalidArgument));
        assert_eq!(wait_with(parent, &sp, &plat, &PROCS, 7191, USER_MIN, u64::MAX), Err(Errno::InvalidArgument));
        // sin efectos: el hijo sigue vivo y en la tabla, nada se durmio ni se mato
        assert_eq!(*plat.blocks.borrow(), 0);
        assert!(plat.terminated.borrow().is_empty() && plat.reaped.borrow().is_empty());
        assert!(PROCS.lock().get(7191).is_some());
        // los extremos validos si: el maximo se acepta (y vence con el reloj de la plataforma)
        let plat = Fake { tick_on_block: MAX_WAIT_TICKS, ..Fake::default() };
        assert_eq!(wait_with(parent, &sp, &plat, &PROCS, 7191, USER_MIN, MAX_WAIT_TICKS), Ok(0));
        assert_eq!(&sp.mem.borrow()[..8], &trunomy_abi::exit::TIMEOUT.to_le_bytes());
    }

    #[test]
    fn a_child_that_exhausts_its_cpu_is_killed_with_the_quota_code_and_reaped() {
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake::default();
        let parent = ProcessContext::new(7200, 7200, 1);
        PROCS.lock().spawn(7201, 7200).unwrap();
        plat.over_quota.borrow_mut().push(7201);
        assert_eq!(wait_with(parent, &sp, &plat, &PROCS, 7201, USER_MIN, 1000), Ok(0));
        assert_eq!(&sp.mem.borrow()[..8], &trunomy_abi::exit::CPU_QUOTA.to_le_bytes());
        assert_eq!(*plat.blocks.borrow(), 0, "no espera al plazo: el padre lo mata en cuanto ve la cuota agotada");
        assert_eq!(*plat.terminated.borrow(), [(7201, None)]);
        assert_eq!(*plat.reaped.borrow(), [7201]);
        assert!(PROCS.lock().get(7201).is_none());
    }

    #[test]
    fn the_quota_kill_is_audited_like_any_other_kill() {
        use crate::audit::{AuditOp, AuditOutcome};
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake::default();
        let parent = ProcessContext::new(7210, 7210, 1);
        PROCS.lock().spawn(7211, 7210).unwrap();
        plat.over_quota.borrow_mut().push(7211);
        wait_with(parent, &sp, &plat, &PROCS, 7211, USER_MIN, 1000).unwrap();
        let ev = crate::audit::events_for_subject(7210);
        assert!(ev.iter().any(|e| e.op == AuditOp::ProcessKill && e.resource_id == Some(7211) && e.outcome == AuditOutcome::Allowed));
    }

    #[test]
    fn only_the_parent_can_trigger_the_quota_kill() {
        static PROCS: Mutex<ProcTable> = Mutex::new(ProcTable::new());
        let sp = MockUserSpace::new(4096);
        let plat = Fake::default();
        let stranger = ProcessContext::new(7229, 7229, 2);
        PROCS.lock().spawn(7221, 7220).unwrap();
        plat.over_quota.borrow_mut().push(7221);
        assert_eq!(wait_with(stranger, &sp, &plat, &PROCS, 7221, USER_MIN, 1000), Err(Errno::PermissionDenied));
        assert!(plat.terminated.borrow().is_empty());
        assert!(PROCS.lock().get(7221).is_some());
    }

    #[test]
    fn spawn_over_the_memory_quota_creates_and_reserves_nothing() {
        let sp = MockUserSpace::new(4096);
        let procs = Mutex::new(ProcTable::new());
        let plat = Fake { memory_denied: true, ..Fake::default() };
        let (lead, s, actor, _) = session(7230);
        put_args(&sp, b"hola");
        assert_eq!(spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, actor), USER_MIN, 4), Err(Errno::QuotaExceeded));
        assert!(plat.created.borrow().is_empty());
        assert!(procs.lock().get(actor).is_none(), "no queda un pid reservado");
        // con memoria otra vez, el mismo spawn funciona (nada quedo a medias)
        let plat = Fake::default();
        assert_eq!(spawn_with(lead, &sp, &plat, &procs, || s.authorize_spawn(lead, actor), USER_MIN, 4), Ok(actor));
    }
}
