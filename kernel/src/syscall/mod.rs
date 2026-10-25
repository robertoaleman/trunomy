// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/syscall/mod.rs

pub use trunomy_abi::{Errno, Syscall as SyscallNumber};

use crate::capabilities::CapabilityError;

pub const CAP_OBJECT_CREATE: u32 = 0x0004;
/// Consola serie del operador (I-35): solo la shell raiz la tiene; ningun worker.
pub const CAP_CONSOLE: u32 = 0x0006;
/// Detener la maquina: la misma capability de administracion del lider (`identity::CAP_ADMIN`).
pub const CAP_HALT: u32 = 0x0005;

/// Red de los actores (I-47): enviar, y ligar/soltar/recibir puertos.
pub const CAP_NET_SEND: u32 = 0x0012;
pub const CAP_NET_RECV: u32 = 0x0013;

pub mod identity;
pub mod info;
pub mod lockdown;
pub mod netctl;
pub mod netio;
pub mod objects;
pub mod spawn;

/// Politica del kernel por syscall (el contrato de numeros vive en `trunomy-abi`).
pub trait SyscallPolicy {
    fn required_capability(&self) -> Option<u32>;
}

impl SyscallPolicy for SyscallNumber {
    fn required_capability(&self) -> Option<u32> {
        match self {
            Self::Yield | Self::ClockNow => None,
            // La consola es del operador y detener la maquina es administracion (I-35).
            Self::ConsoleWrite | Self::ConsoleRead => Some(CAP_CONSOLE),
            Self::Halt => Some(CAP_HALT),
            Self::CreatePipe | Self::WritePipe | Self::ReadPipe => Some(0x0001),
            Self::SendIpc => Some(0x0010),
            Self::ReceiveIpc => Some(0x0011),
            Self::ReadMetadata => Some(0x0002),
            Self::ProcessSpawn => Some(0x0003),
            // Crear objetos exige la capability global CAP_OBJECT_CREATE; el resto
            // se autoriza solo con el handle presentado.
            Self::ObjectCreate => Some(CAP_OBJECT_CREATE),
            Self::ObjectRead | Self::ObjectWrite | Self::ObjectDelete | Self::CapDerive | Self::CapRevoke => None,
            // Autorizacion explicita en identity.rs: la capability CAP_ADMIN es del lider de sesion.
            Self::TenantCreate | Self::ActorCreate | Self::AuditRead => None,
            // Cortar o reabrir un tenant: autorizacion y auditoria explicitas en lockdown.rs (I-45).
            Self::TenantPanic | Self::TenantThaw => None,
            // Poner en marcha o apagar la red: solo el lider, autorizado y auditado en netctl.rs (I-44).
            Self::NetControl => None,
            // Red de los actores: la capability global es la puerta; el dueno del puerto se comprueba en netio.rs.
            Self::NetSend => Some(CAP_NET_SEND),
            Self::NetBind | Self::NetUnbind | Self::NetRecv => Some(CAP_NET_RECV),
            // La autorizacion es por `kind` dentro de info.rs (I-42).
            Self::SystemInfo => None,
            // Salir y esperar a un hijo: la autorizacion esta en la tabla de procesos (solo el padre).
            Self::ProcessExit | Self::ProcessWait | Self::ProcessKill | Self::ProcessOutput => None,
        }
    }
}

/// Syscalls privilegiadas cuyo resultado se audita (I-41): la operacion de auditoria que les toca.
/// `ConsoleWrite` permitida no se audita (una por caracter); `Halt` si, siempre; un `SendIpc`/`ReceiveIpc`
/// permitido tampoco (solo sus denegaciones, I-43).
pub fn audited_op(syscall: SyscallNumber) -> Option<crate::audit::AuditOp> {
    use crate::audit::AuditOp;
    match syscall {
        SyscallNumber::ConsoleWrite | SyscallNumber::ConsoleRead => Some(AuditOp::Console),
        SyscallNumber::Halt => Some(AuditOp::Halt),
        SyscallNumber::SendIpc | SyscallNumber::ReceiveIpc => Some(AuditOp::Ipc),
        SyscallNumber::NetSend | SyscallNumber::NetBind | SyscallNumber::NetUnbind | SyscallNumber::NetRecv => Some(AuditOp::Net),
        _ => None,
    }
}

/// Audita que `process` fue denegado en `syscall` por no tener la capability global que exige.
/// Toda denegacion esta limitada por el propio registro (rafaga por clave y tope por sujeto y operacion,
/// I-41/I-48); las de `Halt`, raras y graves, tienen un cupo mayor. Todas se cuentan.
/// No hace nada para syscalls que no son privilegiadas.
pub fn audit_privileged_denial(process: crate::process::ProcessContext, syscall: SyscallNumber) {
    use crate::audit;
    let Some(op) = audited_op(syscall) else { return };
    // La misma causa que ve el llamante (`InvalidCapability`): no tiene la capability global.
    let why = CapabilityError::NotFound;
    audit::record_throttled_denial(process.subject_id, op, Some(process.tenant_id), Some(syscall.number()), why);
}

/// Audita un `Halt` permitido: la maquina se detiene y el anillo (en memoria) no sobrevive, asi
/// que el llamante ademas lo imprime por el serie.
pub fn audit_halt_allowed(process: crate::process::ProcessContext) {
    use crate::audit::{self, AuditOp, AuditOutcome};
    audit::record(
        process.subject_id,
        AuditOp::Halt,
        None,
        Some(process.tenant_id),
        Some(SyscallNumber::Halt.number()),
        AuditOutcome::Allowed,
    );
}

pub const SYSCALL_OK: u64 = trunomy_abi::OK;
pub const SYSCALL_ERR_INVALID_ARGUMENT: u64 = Errno::InvalidArgument.code();
pub const SYSCALL_ERR_INVALID_POINTER: u64 = Errno::InvalidPointer.code();
pub const SYSCALL_ERR_INVALID_CAPABILITY: u64 = Errno::InvalidCapability.code();
pub const SYSCALL_ERR_PERMISSION_DENIED: u64 = Errno::PermissionDenied.code();
pub const SYSCALL_ERR_OBJECT_NOT_FOUND: u64 = Errno::ObjectNotFound.code();
pub const SYSCALL_ERR_QUOTA_EXCEEDED: u64 = Errno::QuotaExceeded.code();
pub const SYSCALL_ERR_BUFFER_TOO_SMALL: u64 = Errno::BufferTooSmall.code();

/// Traduce un error del libro de capabilities al contrato de syscalls.
///
/// Un handle desconocido o de otro tipo es `InvalidCapability`; uno que existio y
/// ya no vale (revocado o con generacion vieja) es `RevokedCapability`, para que
/// un agente sepa que su sesion termino sin poder sondear handles ajenos.
pub fn errno_of(error: CapabilityError) -> Errno {
    match error {
        CapabilityError::NotFound | CapabilityError::WrongResourceType => Errno::InvalidCapability,
        CapabilityError::InvalidGeneration | CapabilityError::Revoked => Errno::RevokedCapability,
        CapabilityError::PermissionDenied | CapabilityError::InvalidDelegation => {
            Errno::PermissionDenied
        }
        CapabilityError::TenantMismatch => Errno::TenantMismatch,
        CapabilityError::PayloadTooLarge => Errno::InvalidArgument,
        CapabilityError::ObjectQuotaExceeded | CapabilityError::CapabilityQuotaExceeded => {
            Errno::QuotaExceeded
        }
        CapabilityError::ResourceIdExhausted | CapabilityError::OutOfMemory => {
            Errno::ResourceUnavailable
        }
        CapabilityError::Expired => Errno::Expired,
        CapabilityError::UsesExhausted => Errno::UsesExhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_uses_dedicated_send_capability() {
        assert_eq!(SyscallNumber::SendIpc.required_capability(), Some(0x0010));
    }

    #[test]
    fn ipc_uses_dedicated_receive_capability() {
        assert_eq!(SyscallNumber::ReceiveIpc.required_capability(), Some(0x0011));
    }

    #[test]
    fn syscall_numbers_round_trip() {
        assert_eq!(SyscallNumber::from_u64(SyscallNumber::SendIpc as u64), Some(SyscallNumber::SendIpc));
        assert_eq!(SyscallNumber::from_u64(u64::MAX), None);
    }

    #[test]
    fn every_syscall_has_a_defined_policy() {
        // Falla al compilar si se anade una syscall sin decidir su politica.
        for s in SyscallNumber::ALL {
            let _ = s.required_capability();
        }
    }

    #[test]
    fn capability_errors_map_to_the_documented_errno() {
        use CapabilityError as E;
        let table = [
            (E::NotFound, Errno::InvalidCapability),
            (E::WrongResourceType, Errno::InvalidCapability),
            (E::InvalidGeneration, Errno::RevokedCapability),
            (E::Revoked, Errno::RevokedCapability),
            (E::PermissionDenied, Errno::PermissionDenied),
            (E::InvalidDelegation, Errno::PermissionDenied),
            (E::TenantMismatch, Errno::TenantMismatch),
            (E::PayloadTooLarge, Errno::InvalidArgument),
            (E::ObjectQuotaExceeded, Errno::QuotaExceeded),
            (E::CapabilityQuotaExceeded, Errno::QuotaExceeded),
            (E::ResourceIdExhausted, Errno::ResourceUnavailable),
            (E::OutOfMemory, Errno::ResourceUnavailable),
            (E::Expired, Errno::Expired),
            (E::UsesExhausted, Errno::UsesExhausted),
        ];
        for (error, expected) in table {
            assert_eq!(errno_of(error), expected, "{error:?}");
        }
    }

    #[test]
    fn legacy_error_constants_keep_their_values() {
        assert_eq!(SYSCALL_ERR_INVALID_ARGUMENT, 0xFFFF_FFFF_FFFF_0001);
        assert_eq!(SYSCALL_ERR_OBJECT_NOT_FOUND, 0xFFFF_FFFF_FFFF_0006);
        assert_eq!(SYSCALL_ERR_QUOTA_EXCEEDED, 0xFFFF_FFFF_FFFF_0007);
    }

    #[test]
    fn object_syscalls_require_only_the_documented_authority() {
        assert_eq!(SyscallNumber::ObjectCreate.required_capability(), Some(CAP_OBJECT_CREATE));
        for s in [SyscallNumber::ObjectRead, SyscallNumber::ObjectWrite, SyscallNumber::ObjectDelete, SyscallNumber::CapDerive, SyscallNumber::CapRevoke] {
            assert_eq!(s.required_capability(), None);
        }
    }

    #[test]
    fn console_and_halt_require_authority() {
        // I-35: la consola es del operador y detener la maquina es administracion.
        assert_eq!(SyscallNumber::ConsoleWrite.required_capability(), Some(CAP_CONSOLE));
        assert_eq!(SyscallNumber::ConsoleRead.required_capability(), Some(CAP_CONSOLE));
        assert_eq!(SyscallNumber::Halt.required_capability(), Some(CAP_HALT));
        assert_eq!(CAP_HALT, crate::syscall::identity::CAP_ADMIN);
        // ninguna otra capability global se reutiliza para la consola
        assert_ne!(CAP_CONSOLE, CAP_OBJECT_CREATE);
        assert_ne!(CAP_CONSOLE, CAP_HALT);
        // los actores solo reciben CAP_OBJECT_CREATE (ver identity::actor_create)
    }

    #[test]
    fn abi_rights_match_kernel_rights() {
        use crate::capabilities::Rights;
        assert_eq!(trunomy_abi::rights::READ, 1);
        assert!(Rights::READ.contains(Rights::READ));
        assert_eq!(trunomy_abi::rights::ALL, 0b11111);
    }
}
