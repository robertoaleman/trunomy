// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

use crate::ipc::manager::IPC_MANAGER;
use crate::ipc::security::{validate_user_payload, IpcValidationError, MAX_INLINE_WORDS};
use crate::memory_validation::{validate_user_range, UserMemoryError};
use crate::syscall::{identity, info, lockdown, netctl, netio, objects, spawn};
use crate::user_access::{ActiveUserSpace, UserSlice, UserSpace};
use crate::process::{
    current_process, process_context, register_process, validate_process_capability,
};
use crate::syscall::{
    SyscallNumber, SyscallPolicy, SYSCALL_ERR_BUFFER_TOO_SMALL, SYSCALL_ERR_INVALID_ARGUMENT, SYSCALL_ERR_INVALID_CAPABILITY,
    SYSCALL_ERR_INVALID_POINTER, SYSCALL_ERR_OBJECT_NOT_FOUND, SYSCALL_ERR_PERMISSION_DENIED, SYSCALL_ERR_QUOTA_EXCEEDED,
    SYSCALL_OK,
};

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const SYSCALL_STACK_SIZE: usize = 16 * 1024;
/// RFLAGS que `syscall` pone a 0 al entrar: IF (sin interrupciones en el kernel),
/// TF (sin trazado paso a paso), DF (la ABI exige DF=0; con DF=1 las operaciones de
/// cadena del kernel recorrerian la memoria al reves) y AC (sin accesos alineados
/// forzados por el usuario).
pub const SYSCALL_RFLAGS_MASK: u64 = 0x0200 | 0x0100 | 0x0400 | 0x4_0000;
const COM1: u16 = 0x3F8;

// Pila de syscalls inicial (antes de la primera tarea), con pagina de guarda debajo (I-36).
static mut SYSCALL_STACK: crate::guard::GuardedStack<SYSCALL_STACK_SIZE> = crate::guard::GuardedStack::new();

pub fn syscall_guard_page() -> u64 {
    crate::guard::slot((&raw const SYSCALL_STACK) as u64, 0, SYSCALL_STACK_SIZE).guard
}
static mut SYSCALL_STACK_TOP: u64 = 0;
/// Solo de paso: se copia a la pila de kernel de la tarea con IF=0 antes de cualquier otra
/// cosa, de modo que otra tarea pueda hacer syscalls mientras esta espera.
static mut USER_RSP: u64 = 0;

/// Pila de kernel para las syscalls de la tarea que corre (la fija el cambio de contexto).
pub fn set_syscall_stack_top(top: u64) {
    unsafe { SYSCALL_STACK_TOP = top & !0xF };
}

#[inline]
unsafe fn wrmsr(msr: u32, val: u64) {
    core::arch::asm!("wrmsr", in("ecx") msr, in("eax") val as u32, in("edx") (val >> 32) as u32, options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    core::arch::asm!("rdmsr", out("eax") low, out("edx") high, in("ecx") msr, options(nomem, nostack, preserves_flags));
    ((high as u64) << 32) | low as u64
}

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags));
    val
}

fn serial_putchar(byte: u8) {
    unsafe {
        while inb(COM1 + 5) & 0x20 == 0 { core::hint::spin_loop(); }
        outb(COM1, byte);
    }
}

fn validate_syscall_buffer(ptr: u64, len: usize) -> Result<(), u64> {
    match validate_user_range(ptr, len) {
        Ok(()) => Ok(()),
        Err(UserMemoryError::NullPointer)
        | Err(UserMemoryError::ZeroLength)
        | Err(UserMemoryError::AddressOverflow)
        | Err(UserMemoryError::NonCanonicalAddress)
        | Err(UserMemoryError::OutsideUserRange)
        | Err(UserMemoryError::UnalignedAddress)
        | Err(UserMemoryError::PageNotMapped)
        | Err(UserMemoryError::PageNotUser)
        | Err(UserMemoryError::PagePermissionDenied) => Err(SYSCALL_ERR_INVALID_POINTER),
    }
}

/// Historico de la consola: una sola consola, asi que un solo historico (I-50).
static HISTORY: spin::Mutex<crate::lineedit::History> = spin::Mutex::new(crate::lineedit::History::new());

/// Lee una linea del serie con el editor de `lineedit` (I-50): solo ASCII imprimible, las teclas de
/// cursor no mueven nada y ↑/↓ recorren el historico. La linea se compone en una pila del kernel y
/// se copia UNA vez a la memoria de usuario al terminar, por la capa `user_access` (valida paginas y
/// usa la ventana de SMAP); no se escribe por un puntero de usuario mientras se espera teclado
/// (I-37). Al entregarla, el buffer del kernel se borra.
fn serial_read_line(buf: *mut u8, max_len: usize) -> u64 {
    use crate::lineedit::{Event, LineEditor};
    if let Err(code) = validate_syscall_buffer(buf as u64, max_len) {
        return code;
    }
    let mut editor = LineEditor::new(max_len);
    loop {
        let byte = if crate::console::irq_driven() {
            // Por interrupcion: sin dato, se duerme (otra tarea corre o la CPU hace hlt).
            loop {
                if let Some(b) = crate::console::pop_input() { break b; }
                crate::dispatch::wait_for_input();
            }
        } else { unsafe {
            while inb(COM1 + 5) & 0x01 == 0 {
                // Sin tecla: cede la CPU a otra tarea y deja entrar al timer. Vuelve aqui.
                crate::dispatch::yield_current();
                crate::interrupts::irq_window();
                core::hint::spin_loop();
            }
            inb(COM1)
        } };
        // El candado del historico se toma solo durante este byte (no hay otro candado tomado).
        let event = editor.feed(byte, &mut HISTORY.lock(), &mut serial_putchar);
        match event {
            Event::Pending => {}
            Event::Cancelled => {
                editor.wipe();
                return 0;
            }
            Event::Line => {
                let len = editor.line().len();
                let written = len == 0 || ActiveUserSpace.write(buf as u64, editor.line()).is_ok();
                editor.wipe();
                return if written { len as u64 } else { SYSCALL_ERR_INVALID_POINTER };
            }
        }
    }
}

fn validate_required_capability(syscall: SyscallNumber) -> Result<(), u64> {
    validate_required_capability_for(current_process(), syscall)
}

fn validate_required_capability_for(process: crate::process::ProcessContext, syscall: SyscallNumber) -> Result<(), u64> {
    let Some(required) = syscall.required_capability() else { return Ok(()); };
    if validate_process_capability(process, required) {
        Ok(())
    } else {
        // Consola y Halt denegados quedan auditados (I-41); el candado del libro ya se solto.
        crate::syscall::audit_privileged_denial(process, syscall);
        Err(SYSCALL_ERR_INVALID_CAPABILITY)
    }
}

fn audit_ipc_denial(process: crate::process::ProcessContext, target_pid: u64, why: crate::capabilities::CapabilityError) {
    crate::audit::record_throttled_denial(
        process.subject_id,
        crate::audit::AuditOp::Ipc,
        Some(process.tenant_id),
        Some(target_pid),
        why,
    );
}

/// Encola un mensaje ya validado; una cola llena se audita y se reporta como cuota agotada.
fn enqueue_checked(sender: crate::process::ProcessContext, target: u64, id: u32, payload: [u64; 4]) -> u64 {
    use crate::ipc::manager::IpcError;
    match IPC_MANAGER.enqueue_message(sender.pid, target, id, payload) {
        Ok(()) => SYSCALL_OK,
        Err(IpcError::Invalid) => SYSCALL_ERR_INVALID_ARGUMENT,
        Err(IpcError::TargetFull) | Err(IpcError::QueueFull) => {
            audit_ipc_denial(sender, target, crate::capabilities::CapabilityError::ObjectQuotaExceeded);
            SYSCALL_ERR_QUOTA_EXCEEDED
        }
    }
}

fn validate_ipc_dispatch_args(
    target_pid: u64,
    message_id: u64,
    payload_ptr: u64,
    payload_words: u64,
) -> Result<(), u64> {
    let process = current_process();
    if target_pid == 0 || target_pid == process.pid || message_id == 0 {
        return Err(SYSCALL_ERR_INVALID_ARGUMENT);
    }

    let words = usize::try_from(payload_words).map_err(|_| SYSCALL_ERR_INVALID_ARGUMENT)?;
    if words == 0 || words > MAX_INLINE_WORDS {
        return Err(SYSCALL_ERR_INVALID_ARGUMENT);
    }

    let byte_len = words
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(SYSCALL_ERR_INVALID_ARGUMENT)?;
    validate_syscall_buffer(payload_ptr, byte_len)?;

    let target = process_context(target_pid).ok_or(SYSCALL_ERR_INVALID_ARGUMENT)?;
    // Las denegaciones de envio quedan auditadas con el pid destino como recurso (I-43), con el
    // mismo limite anti-inundacion que la consola. El motivo que ve el llamante no cambia.
    if target.tenant_id != process.tenant_id {
        audit_ipc_denial(process, target_pid, crate::capabilities::CapabilityError::TenantMismatch);
        return Err(SYSCALL_ERR_PERMISSION_DENIED);
    }
    if !validate_process_capability(target, crate::ipc::security::CAP_IPC_RECV) {
        audit_ipc_denial(process, target_pid, crate::capabilities::CapabilityError::PermissionDenied);
        return Err(SYSCALL_ERR_PERMISSION_DENIED);
    }

    validate_user_payload(payload_ptr, words).map_err(|error| match error {
        IpcValidationError::InvalidUserPointer => SYSCALL_ERR_INVALID_POINTER,
        _ => SYSCALL_ERR_INVALID_ARGUMENT,
    })?;

    Ok(())
}

fn validate_receive_ipc_args(receiver_pid: u64, payload_ptr: u64, payload_words: u64) -> Result<(), u64> {
    if receiver_pid == 0 {
        return Err(SYSCALL_ERR_INVALID_ARGUMENT);
    }

    let words = usize::try_from(payload_words).map_err(|_| SYSCALL_ERR_INVALID_ARGUMENT)?;
    if words == 0 || words > MAX_INLINE_WORDS {
        return Err(SYSCALL_ERR_INVALID_ARGUMENT);
    }
    // El kernel siempre escribe MAX_INLINE_WORDS palabras: un buffer menor se
    // rechaza en vez de escribir fuera de lo que el usuario valido.
    if words < MAX_INLINE_WORDS {
        return Err(SYSCALL_ERR_BUFFER_TOO_SMALL);
    }

    let byte_len = words
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(SYSCALL_ERR_INVALID_ARGUMENT)?;
    validate_syscall_buffer(payload_ptr, byte_len)?;
    validate_user_payload(payload_ptr, words).map_err(|error| match error {
        IpcValidationError::InvalidUserPointer => SYSCALL_ERR_INVALID_POINTER,
        _ => SYSCALL_ERR_INVALID_ARGUMENT,
    })?;

    let current = current_process();
    if receiver_pid != current.pid {
        return Err(SYSCALL_ERR_PERMISSION_DENIED);
    }

    Ok(())
}

fn read_ipc_payload(payload_ptr: u64, words: usize) -> Result<[u64; MAX_INLINE_WORDS], u64> {
    let mut payload = [0u64; MAX_INLINE_WORDS];
    let slice = UserSlice::new(payload_ptr, (words * 8) as u64).map_err(|e| e.errno().code())?;
    slice.read_words(&ActiveUserSpace, &mut payload[..words]).map_err(|e| e.errno().code())?;
    Ok(payload)
}

fn copy_ipc_payload_to_user(payload_ptr: u64, payload: [u64; MAX_INLINE_WORDS]) -> Result<(), u64> {
    let slice = UserSlice::new(payload_ptr, (MAX_INLINE_WORDS * 8) as u64).map_err(|e| e.errno().code())?;
    slice.write_words(&ActiveUserSpace, &payload).map(|_| ()).map_err(|e| e.errno().code())
}

#[no_mangle]
pub extern "C" fn syscall_dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let syscall = match SyscallNumber::from_u64(num) {
        Some(value) => value,
        None => return SYSCALL_ERR_INVALID_ARGUMENT,
    };
    if let Err(code) = validate_required_capability(syscall) { return code; }

    match syscall {
        SyscallNumber::ConsoleWrite => { serial_putchar(a1 as u8); SYSCALL_OK }
        SyscallNumber::ConsoleRead => serial_read_line(a1 as *mut u8, a2 as usize),
        SyscallNumber::SendIpc => match validate_ipc_dispatch_args(a1, a2, a3, a4) {
            Ok(()) => {
                let current = current_process();
                let words = usize::try_from(a4).unwrap_or(0);
                let payload = match read_ipc_payload(a3, words) { Ok(p) => p, Err(code) => return code };
                enqueue_checked(current, a1, a2 as u32, payload)
            }
            Err(code) => code,
        },
        SyscallNumber::ReceiveIpc => match validate_receive_ipc_args(a1, a2, a3) {
            Ok(()) => {
                let current = current_process();
                match IPC_MANAGER.receive_message(current.pid) {
                    Some(msg) => {
                        let payload = msg.data;
                        match copy_ipc_payload_to_user(a2, payload) { Ok(()) => SYSCALL_OK, Err(code) => code }
                    }
                    None => SYSCALL_ERR_OBJECT_NOT_FOUND,
                }
            }
            Err(code) => code,
        },
        SyscallNumber::ObjectCreate => objects::object_create(current_process(), &ActiveUserSpace, a1, a2),
        SyscallNumber::ObjectRead => objects::object_read(current_process(), &ActiveUserSpace, a1, a2, a3),
        SyscallNumber::ObjectWrite => objects::object_write(current_process(), &ActiveUserSpace, a1, a2, a3),
        SyscallNumber::ObjectDelete => objects::object_delete(current_process(), a1),
        SyscallNumber::CapDerive => objects::cap_derive(current_process(), a1, a2, a3, a4),
        SyscallNumber::CapRevoke => objects::cap_revoke(current_process(), a1),
        SyscallNumber::TenantCreate => identity::tenant_create(current_process()),
        SyscallNumber::ActorCreate => identity::actor_create(current_process(), a1, a2),
        SyscallNumber::TenantPanic => lockdown::tenant_panic(current_process(), a1, a2),
        SyscallNumber::TenantThaw => lockdown::tenant_thaw(current_process(), a1),
        SyscallNumber::NetControl => netctl::net_control(current_process(), a1),
        SyscallNumber::NetBind => netio::net_bind_with(current_process(), &crate::net::ENDPOINTS, a1).unwrap_or_else(|e| e.code()),
        SyscallNumber::NetUnbind => netio::net_unbind_with(current_process(), &crate::net::ENDPOINTS, a1).unwrap_or_else(|e| e.code()),
        SyscallNumber::NetSend => netio::net_send_with(current_process(), &ActiveUserSpace, &crate::net::ENDPOINTS, &crate::net::HwNet, a1, a2, a3, a4).unwrap_or_else(|e| e.code()),
        SyscallNumber::NetRecv => netio::net_recv_with(current_process(), &ActiveUserSpace, &crate::net::ENDPOINTS, &crate::net::HwNet, a1, a2, a3).unwrap_or_else(|e| e.code()),
        SyscallNumber::ProcessSpawn => spawn::process_spawn(current_process(), a1, a2, a3),
        SyscallNumber::ProcessExit => spawn::process_exit(current_process(), a1),
        SyscallNumber::ProcessWait => spawn::process_wait(current_process(), a1, a2, a3),
        SyscallNumber::ProcessOutput => spawn::process_output(current_process(), a1, a2),
        SyscallNumber::ProcessKill => spawn::process_kill(current_process(), a1),
        SyscallNumber::SystemInfo => info::system_info(current_process(), &ActiveUserSpace, a1, a2, a3, a4),
        SyscallNumber::AuditRead => identity::audit_read(current_process(), &ActiveUserSpace, a1, a2, a3),
        SyscallNumber::ClockNow => crate::clock::now(),
        SyscallNumber::Yield => { crate::dispatch::yield_current(); SYSCALL_OK }
        SyscallNumber::Halt => {
            // Quedan constancia (anillo) y una linea por el serie: el anillo muere con la maquina.
            let who = current_process();
            crate::syscall::audit_halt_allowed(who);
            #[cfg(not(test))]
            {
                crate::print_uart("[KERNEL] Halt requested by process ");
                crate::print_uart_hex(who.pid);
                crate::print_uart(" (subject ");
                crate::print_uart_hex(who.subject_id);
                crate::print_uart("): system halted\n");
                loop { unsafe { core::arch::asm!("cli", "hlt"); } }
            }
            #[cfg(test)]
            { SYSCALL_OK }
        }
        _ => SYSCALL_ERR_PERMISSION_DENIED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::GLOBAL_CAPABILITY_BOOK;
    use crate::ipc::manager::IPC_MANAGER;
    use crate::process::ProcessContext;

    #[test]
    fn clock_now_syscall_returns_the_kernel_clock_and_never_goes_back() {
        let a = syscall_dispatch(SyscallNumber::ClockNow.number(), 0, 0, 0, 0);
        crate::clock::advance(3);
        let b = syscall_dispatch(SyscallNumber::ClockNow.number(), 0, 0, 0, 0);
        assert!(a < trunomy_abi::ERROR_BASE && b >= a + 3);
    }

    fn audit_of(subject: u64) -> alloc::vec::Vec<crate::audit::AuditEvent> {
        crate::audit::events_for_subject(subject)
    }

    #[test]
    fn a_denied_console_or_halt_is_audited_and_still_denied() {
        use crate::audit::{AuditOp, AuditOutcome};
        let p = ProcessContext::new(8801, 8801, 7);
        for sc in [SyscallNumber::ConsoleWrite, SyscallNumber::ConsoleRead, SyscallNumber::Halt] {
            assert_eq!(validate_required_capability_for(p, sc), Err(SYSCALL_ERR_INVALID_CAPABILITY), "{sc:?}");
        }
        let ev = audit_of(8801);
        let console: alloc::vec::Vec<_> = ev.iter().filter(|e| e.op == AuditOp::Console).collect();
        assert_eq!(console.len(), 2);
        assert!(console.iter().any(|e| e.resource_id == Some(SyscallNumber::ConsoleWrite.number())));
        assert!(console.iter().any(|e| e.resource_id == Some(SyscallNumber::ConsoleRead.number())));
        let halt: alloc::vec::Vec<_> = ev.iter().filter(|e| e.op == AuditOp::Halt).collect();
        assert_eq!(halt.len(), 1);
        assert_eq!(halt[0].resource_id, Some(SyscallNumber::Halt.number()));
        assert!(ev.iter().all(|e| matches!(e.outcome, AuditOutcome::Denied(_)) && e.tenant_id == Some(7)));
    }

    #[test]
    fn a_process_with_the_capability_is_allowed_and_leaves_no_denial() {
        use crate::audit::AuditOp;
        use crate::capabilities::{ResourceType, Rights};
        let p = ProcessContext::new(8802, 8802, 7);
        GLOBAL_CAPABILITY_BOOK.lock().try_grant(8802, 7, ResourceType::Task, crate::syscall::CAP_CONSOLE as u64, Rights::READ).unwrap();
        assert_eq!(validate_required_capability_for(p, SyscallNumber::ConsoleWrite), Ok(()));
        assert_eq!(validate_required_capability_for(p, SyscallNumber::ConsoleRead), Ok(()));
        assert!(audit_of(8802).iter().all(|e| e.op != AuditOp::Console), "lo permitido no se audita (ruido)");
        // y sin CAP_ADMIN su Halt sigue denegado y auditado
        assert_eq!(validate_required_capability_for(p, SyscallNumber::Halt), Err(SYSCALL_ERR_INVALID_CAPABILITY));
        assert_eq!(audit_of(8802).iter().filter(|e| e.op == AuditOp::Halt).count(), 1);
    }

    #[test]
    fn a_console_flood_is_bounded_in_the_log_but_counted() {
        use crate::audit::{AuditOp, DENIAL_BURST};
        let p = ProcessContext::new(8803, 8803, 7);
        let before = crate::audit::stats();
        for _ in 0..5000 {
            let _ = validate_required_capability_for(p, SyscallNumber::ConsoleWrite);
        }
        let stored = audit_of(8803).iter().filter(|e| e.op == AuditOp::Console).count();
        assert_eq!(stored, DENIAL_BURST as usize);
        let after = crate::audit::stats();
        assert!(after.denied_total >= before.denied_total + 5000, "ninguna denegacion se pierde en el contador");
        assert!(after.suppressed >= before.suppressed + 5000 - DENIAL_BURST as u64);
    }

    #[test]
    fn halt_denials_have_a_bigger_but_bounded_budget() {
        use crate::audit::{AuditOp, HALT_BURST};
        let p = ProcessContext::new(8804, 8804, 7);
        let before = crate::audit::stats();
        for _ in 0..(HALT_BURST + 20) {
            let _ = validate_required_capability_for(p, SyscallNumber::Halt);
        }
        let stored = audit_of(8804).iter().filter(|e| e.op == AuditOp::Halt).count();
        assert_eq!(stored, HALT_BURST as usize, "los primeros intentos de detener la maquina se guardan completos");
        assert!(stored > crate::audit::DENIAL_BURST as usize, "mas cupo que una denegacion corriente");
        assert!(crate::audit::stats().denied_total >= before.denied_total + HALT_BURST as u64 + 20, "y ninguno se pierde en el contador");
    }

    #[test]
    fn halt_allowed_is_audited_with_the_caller_identity() {
        use crate::audit::{AuditOp, AuditOutcome};
        let p = ProcessContext::new(8805, 8805, 9);
        crate::syscall::audit_halt_allowed(p);
        let ev = audit_of(8805);
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].op, ev[0].outcome, ev[0].tenant_id), (AuditOp::Halt, AuditOutcome::Allowed, Some(9)));
    }

    #[test]
    fn only_console_and_halt_are_audited_privileged_syscalls() {
        use crate::audit::AuditOp;
        assert_eq!(crate::syscall::audited_op(SyscallNumber::ConsoleWrite), Some(AuditOp::Console));
        assert_eq!(crate::syscall::audited_op(SyscallNumber::ConsoleRead), Some(AuditOp::Console));
        assert_eq!(crate::syscall::audited_op(SyscallNumber::Halt), Some(AuditOp::Halt));
        assert_eq!(crate::syscall::audited_op(SyscallNumber::ClockNow), None);
        assert_eq!(crate::syscall::audited_op(SyscallNumber::ObjectCreate), None);
    }

    #[test]
    fn ipc_send_and_receive_each_need_their_own_global_capability() {
        use crate::capabilities::{ResourceType, Rights};
        use crate::ipc::security::{CAP_IPC_RECV, CAP_IPC_SEND};
        let p = ProcessContext::new(8811, 8811, 7);
        // sin nada: ni enviar ni recibir (I-12: poder nombrar un destino no es autoridad)
        assert_eq!(validate_required_capability_for(p, SyscallNumber::SendIpc), Err(SYSCALL_ERR_INVALID_CAPABILITY));
        assert_eq!(validate_required_capability_for(p, SyscallNumber::ReceiveIpc), Err(SYSCALL_ERR_INVALID_CAPABILITY));
        // SEND no implica RECEIVE (I-13)
        GLOBAL_CAPABILITY_BOOK.lock().try_grant(8811, 7, ResourceType::Task, CAP_IPC_SEND as u64, Rights::READ).unwrap();
        assert_eq!(validate_required_capability_for(p, SyscallNumber::SendIpc), Ok(()));
        assert_eq!(validate_required_capability_for(p, SyscallNumber::ReceiveIpc), Err(SYSCALL_ERR_INVALID_CAPABILITY));
        GLOBAL_CAPABILITY_BOOK.lock().try_grant(8811, 7, ResourceType::Task, CAP_IPC_RECV as u64, Rights::READ).unwrap();
        assert_eq!(validate_required_capability_for(p, SyscallNumber::ReceiveIpc), Ok(()));
        // otro sujeto del mismo tenant no hereda nada
        let other = ProcessContext::new(8812, 8812, 7);
        assert_eq!(validate_required_capability_for(other, SyscallNumber::SendIpc), Err(SYSCALL_ERR_INVALID_CAPABILITY));
    }

    #[test]
    fn runtime_ipc_rejects_unknown_receiver() {
        assert_eq!(validate_ipc_dispatch_args(9999, 1, 0x4000_0000, 1), Err(SYSCALL_ERR_INVALID_ARGUMENT));
    }

    #[test]
    fn runtime_ipc_rejects_cross_tenant_receiver() {
        register_process(200, ProcessContext::new(200, 200, 2));
        assert_eq!(validate_ipc_dispatch_args(200, 1, 0x4000_0000, 1), Err(SYSCALL_ERR_PERMISSION_DENIED));
    }

    #[test]
    fn a_denied_send_is_audited_with_the_target_as_resource() {
        use crate::audit::{AuditOp, AuditOutcome};
        // otro tenant (el proceso actual de las pruebas no es el 2): se rechaza y queda constancia
        register_process(8821, ProcessContext::new(8821, 8821, 2));
        let me = current_process();
        assert_eq!(validate_ipc_dispatch_args(8821, 1, 0x4000_0000, 1), Err(SYSCALL_ERR_PERMISSION_DENIED));
        let hit = audit_of(me.subject_id)
            .into_iter()
            .filter(|e| e.op == AuditOp::Ipc && e.resource_id == Some(8821))
            .collect::<alloc::vec::Vec<_>>();
        assert!(!hit.is_empty());
        assert!(hit.iter().all(|e| matches!(e.outcome, AuditOutcome::Denied(_)) && e.tenant_id == Some(me.tenant_id)));
        // destino del mismo tenant pero sin CAP_IPC_RECV: tambien denegado y auditado
        register_process(8822, ProcessContext::new(8822, 8822, me.tenant_id));
        assert_eq!(validate_ipc_dispatch_args(8822, 1, 0x4000_0000, 1), Err(SYSCALL_ERR_PERMISSION_DENIED));
        assert!(audit_of(me.subject_id).iter().any(|e| e.op == AuditOp::Ipc && e.resource_id == Some(8822)));
    }

    #[test]
    fn a_missing_ipc_capability_is_audited_and_throttled() {
        use crate::audit::AuditOp;
        let p = ProcessContext::new(8823, 8823, 7);
        for _ in 0..50 {
            assert_eq!(validate_required_capability_for(p, SyscallNumber::SendIpc), Err(SYSCALL_ERR_INVALID_CAPABILITY));
        }
        let stored = audit_of(8823).iter().filter(|e| e.op == AuditOp::Ipc).count();
        assert!(stored >= 1 && stored <= crate::audit::DENIAL_BURST as usize, "{stored}");
    }

    #[test]
    fn a_full_queue_is_a_quota_error_and_is_audited() {
        use crate::audit::AuditOp;
        use crate::ipc::manager::MAX_QUEUED_PER_TARGET;
        let sender = ProcessContext::new(8824, 8824, 7);
        // pid destino propio de esta prueba: la cola global la comparten otras pruebas
        let target = 8825;
        let mut full = false;
        for _ in 0..=MAX_QUEUED_PER_TARGET {
            if enqueue_checked(sender, target, 1, [0; 4]) == SYSCALL_ERR_QUOTA_EXCEEDED {
                full = true;
                break;
            }
        }
        assert!(full, "la cola de un destino no puede crecer sin limite");
        assert!(audit_of(8824).iter().any(|e| e.op == AuditOp::Ipc && e.resource_id == Some(target)));
        while IPC_MANAGER.receive_message(target).is_some() {}
    }

    #[test]
    fn runtime_ipc_rejects_invalid_payload() {
        assert_eq!(validate_ipc_dispatch_args(2, 1, 0, 1), Err(SYSCALL_ERR_INVALID_POINTER));
        assert_eq!(validate_ipc_dispatch_args(2, 1, 0x4000_0000, 0), Err(SYSCALL_ERR_INVALID_ARGUMENT));
        assert_eq!(validate_ipc_dispatch_args(2, 1, 0x4000_0000, (MAX_INLINE_WORDS + 1) as u64), Err(SYSCALL_ERR_INVALID_ARGUMENT));
    }

    #[test]
    fn ipc_policy_requires_send_capability_for_current_process() {
        let book = GLOBAL_CAPABILITY_BOOK.lock();
        assert!(!book.has_capability_for(999, 999, crate::ipc::security::CAP_IPC_SEND));
        drop(book);
        assert_eq!(SyscallNumber::SendIpc.required_capability(), Some(crate::ipc::security::CAP_IPC_SEND));
    }

    #[test]
    fn network_syscalls_need_their_global_capability_and_a_denial_is_audited_with_limit() {
        use crate::audit::AuditOp;
        use crate::syscall::{CAP_NET_RECV, CAP_NET_SEND};
        assert_eq!(SyscallNumber::NetSend.required_capability(), Some(CAP_NET_SEND));
        for sc in [SyscallNumber::NetBind, SyscallNumber::NetUnbind, SyscallNumber::NetRecv] {
            assert_eq!(sc.required_capability(), Some(CAP_NET_RECV), "{sc:?}");
        }
        let p = ProcessContext::new(8821, 8821, 7);
        for sc in [SyscallNumber::NetSend, SyscallNumber::NetBind, SyscallNumber::NetUnbind, SyscallNumber::NetRecv] {
            assert_eq!(validate_required_capability_for(p, sc), Err(SYSCALL_ERR_INVALID_CAPABILITY), "{sc:?}");
        }
        let net: alloc::vec::Vec<_> = audit_of(8821).into_iter().filter(|e| e.op == AuditOp::Net).collect();
        assert_eq!(net.len(), 4);
        assert!(net.iter().any(|e| e.resource_id == Some(SyscallNumber::NetSend.number())));
    }

    #[test]
    fn ipc_manager_enqueues_for_target() {
        IPC_MANAGER.clear();
        assert!(IPC_MANAGER.enqueue_message(1, 2, 7, [10, 20, 30, 40]).is_ok());
        let msg = IPC_MANAGER.receive_message(2).unwrap();
        assert_eq!(msg.sender_pid, 1);
        assert_eq!(msg.target_pid, 2);
        assert_eq!(msg.message_id, 7);
        assert_eq!(msg.data, [10, 20, 30, 40]);
    }

    #[test]
    fn syscall_entry_masks_if_tf_df_and_ac() {
        for (name, bit) in [("IF", 1u64 << 9), ("TF", 1 << 8), ("DF", 1 << 10), ("AC", 1 << 18)] {
            assert_ne!(SYSCALL_RFLAGS_MASK & bit, 0, "{name} debe enmascararse");
        }
    }

    #[test]
    fn receive_ipc_rejects_buffers_smaller_than_a_message() {
        for words in 1..MAX_INLINE_WORDS as u64 {
            assert_eq!(
                validate_receive_ipc_args(1, 0x4000_0000, words),
                Err(SYSCALL_ERR_BUFFER_TOO_SMALL)
            );
        }
    }

    #[test]
    fn receive_ipc_validates_buffer_and_target() {
        assert_eq!(validate_receive_ipc_args(0, 0x4000_0000, 1), Err(SYSCALL_ERR_INVALID_ARGUMENT));
        assert_eq!(validate_receive_ipc_args(1, 0, MAX_INLINE_WORDS as u64), Err(SYSCALL_ERR_INVALID_POINTER));
        assert_eq!(validate_receive_ipc_args(1, 0x4000_0000, 0), Err(SYSCALL_ERR_INVALID_ARGUMENT));
    }
}

/// Entrada de SYSCALL. El `rsp` de usuario se guarda en la pila de kernel de la tarea (no en
/// un global que otra tarea pisaria si esta se suspende dentro de la syscall). 9 qwords de
/// empujes + 1 de relleno mantienen `rsp` alineado a 16 en el `call`.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn asm_syscall_entry() {
    core::arch::naked_asm!(
        "mov [rip + {user_rsp}], rsp", "mov rsp, [rip + {stack_top}]",
        "push qword ptr [rip + {user_rsp}]", "sub rsp, 8",
        "push rcx", "push r11", "push r10", "push r9", "push r8", "push rdi", "push rsi", "push rdx",
        "mov r8, r10", "mov rcx, rdx", "mov rdx, rsi", "mov rsi, rdi", "mov rdi, rax", "call {dispatch}",
        "pop rdx", "pop rsi", "pop rdi", "pop r8", "pop r9", "pop r10", "pop r11", "pop rcx",
        "add rsp, 8", "pop rsp", "sysretq",
        user_rsp = sym USER_RSP, stack_top = sym SYSCALL_STACK_TOP, dispatch = sym syscall_dispatch,
    )
}

pub unsafe fn init_syscall_msrs(handler_addr: u64) {
    SYSCALL_STACK_TOP = crate::guard::slot((&raw mut SYSCALL_STACK) as u64, 0, SYSCALL_STACK_SIZE).top & !0xF;
    // SCE (syscall) y NXE (bit 11): sin NXE el bit NX de las paginas seria un bit reservado.
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | 1 | (1 << 11));
    wrmsr(IA32_LSTAR, handler_addr);
    wrmsr(IA32_STAR, ((0x0013u64) << 48) | ((0x0008u64) << 32));
    wrmsr(IA32_FMASK, SYSCALL_RFLAGS_MASK);
}

pub fn init_root_capabilities() {
    crate::capabilities::seed_root_capabilities();
    register_process(1, crate::process::ProcessContext::new(1, 1, 1));
}
