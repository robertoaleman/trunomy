// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Contrato de syscalls de Trunomy OS: UNA sola fuente para kernel y userland.
//!
//! Convencion de llamada (x86_64, instruccion `syscall`):
//! - numero en `rax`; argumentos en `rdi, rsi, rdx, r10`; resultado en `rax`.
//! - `rcx` y `r11` los destruye la instruccion `syscall`; el kernel conserva el resto.
//! - Un resultado `>= ERROR_BASE` es un error (`Errno`); cualquier otro valor es exito y
//!   puede llevar un dato (por ejemplo, una longitud).
//!
//! Contratos por syscall (argumentos tras el numero):
//! - `SendIpc(target_pid, message_id, payload_ptr, payload_words)`
//! - `ReceiveIpc(receiver_pid, payload_ptr, payload_words)`; el buffer debe tener al
//!   menos `MAX_INLINE_WORDS` palabras y el kernel escribe exactamente esas.
//!
//! Este crate no tiene dependencias y es `no_std`: se prueba en el host.

#![no_std]

/// Palabras de 64 bits de la carga util en linea de un mensaje IPC.
pub const MAX_INLINE_WORDS: usize = 4;

/// Ticks del reloj del kernel por segundo (el PIT se programa a esta frecuencia).
pub const TICK_HZ: u64 = 100;

/// Resultado de exito sin dato.
pub const OK: u64 = 0;

/// Todo resultado `>= ERROR_BASE` es un `Errno`.
pub const ERROR_BASE: u64 = 0xFFFF_FFFF_FFFF_0000;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u64)]
pub enum Syscall {
    ConsoleWrite = 0x01,
    ConsoleRead = 0x10,
    CreatePipe = 0x20,
    WritePipe = 0x21,
    ReadPipe = 0x22,
    SendIpc = 0x30,
    ReadMetadata = 0x31,
    ProcessSpawn = 0x32,
    ReceiveIpc = 0x33,
    ProcessExit = 0x34,
    ProcessWait = 0x35,
    ProcessKill = 0x36,
    ProcessOutput = 0x37,
    Yield = 0x40,
    Halt = 0x41,
    ClockNow = 0x42,
    ObjectCreate = 0x50,
    ObjectRead = 0x51,
    ObjectWrite = 0x52,
    ObjectDelete = 0x53,
    CapDerive = 0x54,
    CapRevoke = 0x55,
    TenantCreate = 0x56,
    ActorCreate = 0x57,
    SystemInfo = 0x58,
    AuditRead = 0x59,
    TenantPanic = 0x5A,
    TenantThaw = 0x5B,
    NetControl = 0x5C,
    NetBind = 0x5D,
    NetUnbind = 0x5E,
    NetSend = 0x5F,
    NetRecv = 0x60,
}

impl Syscall {
    /// Todas las syscalls, para pruebas de contrato.
    pub const ALL: [Syscall; 33] = [
        Syscall::ConsoleWrite,
        Syscall::ConsoleRead,
        Syscall::CreatePipe,
        Syscall::WritePipe,
        Syscall::ReadPipe,
        Syscall::SendIpc,
        Syscall::ReadMetadata,
        Syscall::ProcessSpawn,
        Syscall::ReceiveIpc,
        Syscall::ProcessExit,
        Syscall::ProcessWait,
        Syscall::ProcessKill,
        Syscall::ProcessOutput,
        Syscall::Yield,
        Syscall::Halt,
        Syscall::ClockNow,
        Syscall::ObjectCreate,
        Syscall::ObjectRead,
        Syscall::ObjectWrite,
        Syscall::ObjectDelete,
        Syscall::CapDerive,
        Syscall::CapRevoke,
        Syscall::TenantCreate,
        Syscall::ActorCreate,
        Syscall::SystemInfo,
        Syscall::AuditRead,
        Syscall::TenantPanic,
        Syscall::TenantThaw,
        Syscall::NetControl,
        Syscall::NetBind,
        Syscall::NetUnbind,
        Syscall::NetSend,
        Syscall::NetRecv,
    ];

    pub const fn number(self) -> u64 {
        self as u64
    }

    pub fn from_u64(value: u64) -> Option<Self> {
        let mut i = 0;
        while i < Self::ALL.len() {
            if Self::ALL[i] as u64 == value {
                return Some(Self::ALL[i]);
            }
            i += 1;
        }
        None
    }
}

pub mod image;

/// Claves de firma de arranque (I-18, I-19, I-39).
///
/// Dos claves publicas Ed25519 con ROL distinto: quien firma la shell no puede firmar un
/// kernel. El bootloader verifica el kernel con `KERNEL_SIGNING_PUBLIC_KEY` y la imagen de
/// la shell con `SHELL_SIGNING_PUBLIC_KEY`; el kernel verifica la shell con la segunda.
/// `build_os.sh` comprueba que cada constante coincide con su PEM en `.keys/` y aborta si no;
/// `scripts/provision-keys.sh` genera la clave de la shell y reescribe la constante.
/// La confianza no se deduce de los bytes de la clave: no existe modo desarrollo. Una clave
/// sin aprovisionar (todo ceros) la rechaza bootcore (`BadKey`): falla cerrado.
pub mod trust {
    /// Firma el kernel (ELF + `.sig`). Verificada en el bootloader.
    pub const KERNEL_SIGNING_PUBLIC_KEY: [u8; 32] = [
        0x0b, 0xb9, 0x35, 0x36, 0x5a, 0x76, 0x92, 0xa8, 0xab, 0x6c, 0x00, 0xfe, 0xd9, 0x8b, 0xde,
        0x08, 0x82, 0x75, 0xb4, 0xaa, 0x57, 0x75, 0xc1, 0x1c, 0x50, 0x02, 0xdb, 0x17, 0x9a, 0x5f,
        0x97, 0x07,
    ];

    /// Firma la imagen de la shell. Verificada en el bootloader (`LOAD_SHELL`) y en el kernel.
    /// Todo ceros = sin aprovisionar (se rechaza); `scripts/provision-keys.sh` la rellena.
    pub const SHELL_SIGNING_PUBLIC_KEY: [u8; 32] = [
        0xfb, 0xc7, 0xa3, 0x99, 0x55, 0x92, 0xde, 0x5e, 0x96, 0x24, 0x63, 0x97, 0x13, 0x5e, 0x97,
        0xe0, 0x8e, 0x03, 0x37, 0x0d, 0xe8, 0x9c, 0xd9, 0x68, 0x58, 0x48, 0xfb, 0xbe, 0x90, 0x84,
        0x26, 0xd1,
    ];
}


/// Codigos de salida que SOLO el kernel puede producir (I-33).
///
/// Un proceso que sale por su cuenta (`ProcessExit`) no puede usar este rango: el kernel lo
/// rechaza, de modo que un padre que ve uno de estos codigos sabe que el proceso fue
/// terminado por el kernel y no que "decidio" salir asi. El rango (bits 63..48 = 0xFFFE)
/// queda por debajo de los `Errno` (0xFFFF...) y solo un handle con generacion >= 0xFFFE0000
/// (4.29e9 revocaciones del mismo slot) podria caer en el; si ocurriera, `ProcessExit` lo
/// rechaza (falla cerrado).
pub mod exit {
    const PREFIX: u64 = 0xFFFE_0000_0000_0000;
    const MASK: u64 = 0xFFFF_0000_0000_0000;

    /// Terminado por una excepcion de CPU; los 8 bits bajos son el vector (14 = #PF).
    pub const FAULT: u64 = PREFIX | 0x0100;
    /// Terminado por `ProcessKill`.
    pub const KILLED: u64 = PREFIX | 0x0200;
    /// Terminado por el kernel al vencer el plazo de `ProcessWait`.
    pub const TIMEOUT: u64 = PREFIX | 0x0300;
    /// Terminado por el kernel al agotar su cuota de CPU (I-40).
    pub const CPU_QUOTA: u64 = PREFIX | 0x0400;

    pub const fn fault(vector: u8) -> u64 {
        FAULT | vector as u64
    }

    pub const fn is_kernel_terminated(code: u64) -> bool {
        code & MASK == PREFIX
    }

    /// Vector de la excepcion si `code` es un codigo de fallo.
    pub const fn fault_vector(code: u64) -> Option<u8> {
        if is_kernel_terminated(code) && code & 0xFF00 == 0x0100 {
            Some((code & 0xFF) as u8)
        } else {
            None
        }
    }

    pub const fn exception_name(vector: u8) -> &'static str {
        match vector {
            0 => "#DE divide error",
            1 => "#DB debug",
            3 => "#BP breakpoint",
            4 => "#OF overflow",
            5 => "#BR bound range",
            6 => "#UD invalid opcode",
            7 => "#NM device not available",
            10 => "#TS invalid TSS",
            11 => "#NP segment not present",
            12 => "#SS stack fault",
            13 => "#GP general protection",
            14 => "#PF page fault",
            16 => "#MF x87 fault",
            17 => "#AC alignment check",
            19 => "#XM SIMD fault",
            _ => "exception",
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{Errno, ERROR_BASE};

        #[test]
        fn kernel_codes_never_collide_with_errors_or_handles() {
            for e in Errno::ALL {
                assert!(!is_kernel_terminated(e.code()));
            }
            assert!(FAULT < ERROR_BASE && KILLED < ERROR_BASE && TIMEOUT < ERROR_BASE && CPU_QUOTA < ERROR_BASE);
            // handles con generaciones realistas (< 0xFFFE0000) quedan fuera del rango
            assert!(!is_kernel_terminated(0xFFFD_FFFF_FFFF_FFFF));
            assert!(!is_kernel_terminated(0x0000_FFFF_FFFF_FFFF));
            assert!(!is_kernel_terminated(0));
        }

        #[test]
        fn fault_codes_carry_the_vector() {
            assert_eq!(fault_vector(fault(14)), Some(14));
            assert_eq!(fault_vector(fault(255)), Some(255));
            assert_eq!(fault_vector(KILLED), None);
            assert_eq!(fault_vector(TIMEOUT), None);
            assert_eq!(fault_vector(CPU_QUOTA), None);
            assert!(is_kernel_terminated(CPU_QUOTA));
            assert!(![FAULT, KILLED, TIMEOUT].contains(&CPU_QUOTA));
            assert_eq!(fault_vector(7), None);
            assert!(is_kernel_terminated(fault(0)));
            assert_eq!(exception_name(14), "#PF page fault");
        }
    }
}

/// Contrato de lanzamiento de procesos (`ProcessSpawn`): donde el kernel deja los argumentos.
pub mod output {
    //! Salida de un worker (I-35): un worker no tiene consola; deja su resultado en el kernel con
    //! `ProcessOutput(ptr, len)` y el padre lo recibe con `ProcessWait`.
    /// Maximo de bytes de salida por proceso (los que sobran se rechazan, no se truncan en silencio).
    pub const MAX_OUTPUT: usize = 256;
    /// Tamano del buffer de `ProcessWait`: `[code: u64][len: u64][bytes; MAX_OUTPUT]`.
    pub const WAIT_RESULT_SIZE: usize = 16 + MAX_OUTPUT;
}

pub mod spawn {
    /// Pagina de argumentos de solo lectura de todo proceso: `[len: u64 LE][bytes...]`.
    /// En la shell raiz `len` es 0; un worker recibe aqui su orden.
    pub const ARGS_VADDR: u64 = 0x0000_0000_7FFE_F000;
    /// Maximo de bytes de argumentos de `ProcessSpawn`.
    pub const MAX_ARGS: usize = 256;
    /// Plazo maximo de `ProcessWait`: 60 s (100 ticks por segundo). El plazo es obligatorio:
    /// `0` o mas que esto es `InvalidArgument` (I-40).
    pub const MAX_WAIT_TICKS: u64 = 6000;
    /// Plazo que usa `libtrunomy::process::wait` cuando el llamante no elige uno: 10 s.
    pub const DEFAULT_WAIT_TICKS: u64 = 1000;
}

/// Contrato bootloader -> kernel (puntero a `BootInfo` en RDI). Una sola definicion, usada
/// por ambos lados, para que no puedan divergir.
pub mod boot {
    /// "TRNMBOOT" en little-endian.
    pub const BOOT_INFO_MAGIC: u64 = 0x544F_4F42_4D4E_5254;

    /// Region de memoria que el firmware declaro libre para el sistema operativo
    /// (EfiConventionalMemory tras ExitBootServices).
    pub const REGION_USABLE: u32 = 1;
    /// Todo lo demas: codigo/datos del loader, servicios de firmware, ACPI, MMIO, no fiable...
    /// El kernel NO lo reutiliza (ni siquiera BootServices*, porque las tablas de paginacion
    /// heredadas de UEFI viven alli).
    pub const REGION_RESERVED: u32 = 2;

    /// Capacidad maxima de la tabla de regiones que entrega el bootloader.
    pub const MAX_REGIONS: usize = 2048;

    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct MemRegion {
        /// Direccion fisica de inicio (multiplo de 4 KiB).
        pub base: u64,
        /// Numero de paginas de 4 KiB.
        pub pages: u64,
        pub kind: u32,
        pub _pad: u32,
    }

    impl MemRegion {
        pub const SIZE: usize = 24;
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct BootInfo {
        pub magic: u64,
        /// PML4 (fisica) activa al entrar al kernel.
        pub pml4_pa: u64,
        pub kernel_base: u64,
        pub kernel_size: u64,
        /// shell.bin en RAM, tal cual en disco: payload + 64 bytes de firma (0/0 si no hay).
        pub shell_ptr: u64,
        pub shell_size: u64,
        /// Tabla de `MemRegion` (0/0/0 si el bootloader no pudo entregarla).
        pub mmap_ptr: u64,
        /// Numero de regiones.
        pub mmap_len: u64,
        /// `size_of::<MemRegion>()`: versiona el formato.
        pub mmap_desc_size: u64,
    }
}

/// Mascara de derechos de una capability (argumento de `CapDerive`).
pub mod rights {
    pub const READ: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const SEND: u64 = 1 << 2;
    pub const RECEIVE: u64 = 1 << 3;
    pub const DELEGATE: u64 = 1 << 4;
    pub const ALL: u64 = READ | WRITE | SEND | RECEIVE | DELEGATE;
}

/// `TenantPanic(tenant, flags)` y `TenantThaw(tenant)`: corte de emergencia de un tenant (I-45).
/// Solo el lider administrador. El resultado de `TenantPanic` empaqueta tres contadores.
pub mod panic {
    /// Ademas de cortar el tenant, borra (con zero-on-free) todos sus objetos.
    pub const FLAG_WIPE: u64 = 1 << 0;
    pub const KNOWN_FLAGS: u64 = FLAG_WIPE;

    const FIELD: u64 = 0xFFFF;

    const fn sat(v: u64) -> u64 {
        if v > FIELD { FIELD } else { v }
    }

    /// Empaqueta (procesos matados, capabilities revocadas, objetos borrados), cada uno saturado a 16 bits.
    pub const fn pack(killed: u64, revoked: u64, wiped: u64) -> u64 {
        sat(killed) | sat(revoked) << 16 | sat(wiped) << 32
    }

    pub const fn unpack(v: u64) -> (u64, u64, u64) {
        (v & FIELD, (v >> 16) & FIELD, (v >> 32) & FIELD)
    }
}

/// Banderas de `ActorCreate(tenant, flags)`. Un bit desconocido se rechaza (falla cerrado).
pub mod actor {
    /// El actor recibe las capabilities globales `CAP_IPC_SEND` y `CAP_IPC_RECV`. Sin esta bandera
    /// un actor no puede enviar ni recibir mensajes (minimo privilegio).
    pub const FLAG_IPC: u64 = 1 << 0;
    /// El actor recibe `CAP_NET_SEND` y `CAP_NET_RECV` (red: ligar puertos, enviar y recibir tramas).
    pub const FLAG_NET: u64 = 1 << 1;
    pub const KNOWN_FLAGS: u64 = FLAG_IPC | FLAG_NET;
}

pub mod netproto;

/// Syscalls de red de los actores (I-47). Todas exigen una capability global: `NetSend` pide `CAP_NET_SEND`;
/// `NetBind`, `NetUnbind` y `NetRecv` piden `CAP_NET_RECV`.
///
/// - `NetBind(port)` / `NetUnbind(port)`: liga o suelta un puerto (1..=65535); el dueno es el llamante.
/// - `NetSend(src_port, dst_port, ptr, len)`: el buffer es `[MAC destino (6 bytes)] ++ carga util`
///   (`len` = 6 + carga, carga <= `netproto::MAX_PAYLOAD`). `src_port` debe ser del llamante. Una MAC
///   destino igual a la propia, o `SELF_MAC` (todo ceros), entrega la trama por dentro, sin pasar por el dispositivo.
/// - `NetRecv(port, ptr, len)`: el buffer debe tener al menos `RECV_MIN_BUF` bytes. Devuelve 0 si no hay
///   mensaje, o el total escrito: `[MAC del par (6)] ++ [puerto del par u16 LE] ++ carga util`.
///   MAC y puerto del par son datos SIN autenticar.
pub mod netio {
    /// MAC destino "esta maquina": la trama se entrega por dentro, sin pasar por el dispositivo.
    pub const SELF_MAC: [u8; 6] = [0; 6];
    pub const SEND_HEADER: usize = 6;
    pub const RECV_HEADER: usize = 8;
    pub const RECV_MIN_BUF: usize = RECV_HEADER + crate::netproto::MAX_PAYLOAD;
    pub const SEND_MAX: usize = SEND_HEADER + crate::netproto::MAX_PAYLOAD;
}
/// `NetControl(op)`: poner en marcha o apagar el dispositivo de red y comprobarlo (solo el lider administrador).
pub mod netctl {
    /// Negocia de nuevo, reserva las colas, enciende bus master y DRIVER_OK. Devuelve 0.
    pub const UP: u64 = 1;
    /// Apaga: bus master fuera, reinicio, memoria borrada y devuelta. Devuelve 0 (limpio) o 1 (memoria retenida).
    pub const DOWN: u64 = 2;
    /// Envia un ARP al gateway de QEMU (10.0.2.2) y espera su respuesta. Devuelve 1 (respondio) o 0 (sin respuesta).
    pub const SELFTEST: u64 = 3;

    pub const fn is_known(op: u64) -> bool {
        op == UP || op == DOWN || op == SELFTEST
    }
}

/// `SystemInfo(kind, out_ptr, out_len, arg)`: estado REAL del kernel, en palabras u64 little endian.
/// Devuelve cuantas palabras (kinds fijos) o registros (listas) escribio; la autorizacion la decide
/// el kernel por kind (ver `kernel/src/syscall/info.rs`).
pub mod sysinfo {
    /// pid, tenant, subject del llamante. Cualquiera.
    pub const IDENTITY: u64 = 1;
    /// frames_total, frames_free, heap_total, heap_used. Solo el lider administrador.
    pub const MEMORY: u64 = 2;
    /// objetos, max_objetos, bytes, max_bytes_por_objeto del tenant del llamante. Cualquiera (el suyo).
    pub const TENANT_USAGE: u64 = 3;
    /// Registros [pid, parent, state] (state 0 = running, 1 = zombie). Solo el lider administrador.
    pub const PROCESSES: u64 = 4;
    /// Registros de capabilities activas de `arg` (0 = el llamante). Otro sujeto: solo el lider.
    pub const CAPS: u64 = 5;
    /// Registros [pid, tenant, estado] de los actores de la sesion (estado: bits `ACTOR_*`). Solo el lider administrador.
    pub const ACTORS: u64 = 6;
    /// Dispositivo de red: [estado, pci(bus<<16|dev<<8|func), vendor<<16|device, mac (48 bits), host_features|guest_features<<32, enlace].
    /// Solo el lider administrador (es inventario de hardware de toda la maquina).
    pub const NET: u64 = 7;

    pub const NET_WORDS: usize = 6;
    /// Estados de `NET`: no hay dispositivo, hay uno reconocido y negociado, hay uno que no se puede usar.
    pub const NET_ABSENT: u64 = 0;
    pub const NET_NEGOTIATED: u64 = 1;
    pub const NET_UNSUPPORTED: u64 = 2;
    /// Colas registradas, bus master y DRIVER_OK: el dispositivo esta en marcha (`NetControl(UP)`).
    pub const NET_ACTIVE: u64 = 3;
    /// Contadores del camino de datos: [enviadas, recibidas, envios rechazados por buffers, recibidas descartadas,
    /// cola envenenada (0 = no; `NET_POISON_*`), tramas descartadas por el protocolo (mal formadas, MAC ajena, sin endpoint o cola llena)]. Solo el lider administrador.
    pub const NET_STATS: u64 = 8;
    pub const NET_STATS_WORDS: usize = 6;
    pub const NET_POISON_USED_OVERRUN: u64 = 1;
    pub const NET_POISON_BAD_ID: u64 = 2;
    pub const NET_POISON_BAD_LEN: u64 = 3;
    /// Enlace: la palabra 5 de `NET`.
    pub const LINK_UNKNOWN: u64 = 0;
    pub const LINK_DOWN: u64 = 1;
    pub const LINK_UP: u64 = 2;
    /// Dispositivo virtio-net "moderno" (solo MMIO), que el kernel todavia no usa.
    pub const VIRTIO_NET_MODERN_ID: u64 = 0x1AF4_1041;

    pub const IDENTITY_WORDS: usize = 3;
    pub const MEMORY_WORDS: usize = 4;
    pub const TENANT_USAGE_WORDS: usize = 4;
    pub const PROCESS_RECORD_WORDS: usize = 3;
    /// [resource_type, resource_id, rights, remaining_uses (UNLIMITED = sin limite)]
    pub const CAP_RECORD_WORDS: usize = 4;
    pub const ACTOR_RECORD_WORDS: usize = 3;
    /// Bits del estado de un actor: identidad retirada por un `TenantPanic` (no vuelve a lanzarse) y tenant congelado.
    pub const ACTOR_RETIRED: u64 = 1 << 0;
    pub const ACTOR_TENANT_FROZEN: u64 = 1 << 1;
    pub const UNLIMITED: u64 = u64::MAX;

    pub const RES_DATA: u64 = 0;
    pub const RES_PIPE: u64 = 1;
    pub const RES_ENDPOINT: u64 = 2;
    pub const RES_TASK: u64 = 3;

    /// Nombre de una capability GLOBAL (resource_type Task con id pequeno); las de datos llevan el id del objeto.
    pub const fn global_cap_name(id: u64) -> Option<&'static str> {
        match id {
            1 => Some("pipe.create"),
            2 => Some("metadata.read"),
            3 => Some("process.spawn"),
            4 => Some("object.create"),
            5 => Some("admin(halt,session)"),
            6 => Some("console"),
            0x10 => Some("ipc.send"),
            0x11 => Some("ipc.recv"),
            0x12 => Some("net.send"),
            0x13 => Some("net.recv"),
            _ => None,
        }
    }
}

/// Registro de auditoria tal como lo entrega `AuditRead` (48 bytes, little endian).
///   0..8 seq | 8..16 subject | 16..24 tenant (0 = n/d) | 24..32 resource (0 = n/d)
///   32..40 handle crudo (0 = n/d) | 40 op | 41 outcome (0 = permitido, si no, byte bajo del Errno) | 42..48 cero
pub mod audit {
    pub const RECORD_SIZE: usize = 48;

    pub const OP_READ: u8 = 1;
    pub const OP_WRITE: u8 = 2;
    pub const OP_DELETE: u8 = 3;
    pub const OP_GRANT: u8 = 4;
    pub const OP_DELEGATE: u8 = 5;
    pub const OP_REVOKE: u8 = 6;
    pub const OP_CREATE: u8 = 7;
    pub const OP_IDENTITY: u8 = 8;
    /// Un proceso fue terminado por una excepcion de CPU en Ring 3 (resource = codigo de salida).
    pub const OP_FAULT: u8 = 9;
    /// `ProcessKill` (subject = quien lo pidio, resource = pid del objetivo).
    pub const OP_KILL: u8 = 10;
    /// Denegacion de `ConsoleWrite`/`ConsoleRead` (resource = numero de syscall).
    pub const OP_CONSOLE: u8 = 11;
    /// `Halt`, permitido o denegado.
    pub const OP_HALT: u8 = 12;
    /// Denegacion de `SendIpc`/`ReceiveIpc` (resource = pid destino, o numero de syscall si faltaba la capability).
    pub const OP_IPC: u8 = 13;
    /// `TenantPanic` (resource = tenant), permitido o denegado.
    pub const OP_PANIC: u8 = 14;
    /// `TenantThaw` (resource = tenant), permitido o denegado.
    pub const OP_THAW: u8 = 15;
    /// `NetControl` (resource = operacion), permitido o denegado.
    pub const OP_NET: u8 = 16;

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct Record {
        pub seq: u64,
        pub subject: u64,
        pub tenant: u64,
        pub resource: u64,
        pub handle: u64,
        pub op: u8,
        pub outcome: u8,
    }

    impl Record {
        pub fn encode(&self) -> [u8; RECORD_SIZE] {
            let mut b = [0u8; RECORD_SIZE];
            b[0..8].copy_from_slice(&self.seq.to_le_bytes());
            b[8..16].copy_from_slice(&self.subject.to_le_bytes());
            b[16..24].copy_from_slice(&self.tenant.to_le_bytes());
            b[24..32].copy_from_slice(&self.resource.to_le_bytes());
            b[32..40].copy_from_slice(&self.handle.to_le_bytes());
            b[40] = self.op;
            b[41] = self.outcome;
            b
        }

        pub fn decode(b: &[u8]) -> Option<Record> {
            if b.len() < RECORD_SIZE {
                return None;
            }
            let u = |r: core::ops::Range<usize>| u64::from_le_bytes(b[r].try_into().unwrap());
            Some(Record {
                seq: u(0..8),
                subject: u(8..16),
                tenant: u(16..24),
                resource: u(24..32),
                handle: u(32..40),
                op: b[40],
                outcome: b[41],
            })
        }
    }

    pub const fn op_name(op: u8) -> &'static str {
        match op {
            OP_READ => "read",
            OP_WRITE => "write",
            OP_DELETE => "delete",
            OP_GRANT => "grant",
            OP_DELEGATE => "delegate",
            OP_REVOKE => "revoke",
            OP_CREATE => "create",
            OP_IDENTITY => "identity",
            OP_FAULT => "fault",
            OP_KILL => "kill",
            OP_CONSOLE => "console",
            OP_HALT => "halt",
            OP_IPC => "ipc",
            OP_PANIC => "panic",
            OP_THAW => "thaw",
            OP_NET => "net",
            _ => "?",
        }
    }
}

/// Errores de syscall (taxonomia del Security Model).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u64)]
pub enum Errno {
    InvalidArgument = ERROR_BASE + 0x01,
    InvalidPointer = ERROR_BASE + 0x02,
    InvalidCapability = ERROR_BASE + 0x03,
    PermissionDenied = ERROR_BASE + 0x04,
    RevokedCapability = ERROR_BASE + 0x05,
    ObjectNotFound = ERROR_BASE + 0x06,
    QuotaExceeded = ERROR_BASE + 0x07,
    TenantMismatch = ERROR_BASE + 0x08,
    BufferTooSmall = ERROR_BASE + 0x09,
    Expired = ERROR_BASE + 0x0A,
    UsesExhausted = ERROR_BASE + 0x0B,
    ResourceUnavailable = ERROR_BASE + 0x0C,
}

impl Errno {
    pub const ALL: [Errno; 12] = [
        Errno::InvalidArgument,
        Errno::InvalidPointer,
        Errno::InvalidCapability,
        Errno::PermissionDenied,
        Errno::RevokedCapability,
        Errno::ObjectNotFound,
        Errno::QuotaExceeded,
        Errno::TenantMismatch,
        Errno::BufferTooSmall,
        Errno::Expired,
        Errno::UsesExhausted,
        Errno::ResourceUnavailable,
    ];

    pub const fn code(self) -> u64 {
        self as u64
    }

    pub const fn name(self) -> &'static str {
        match self {
            Errno::InvalidArgument => "InvalidArgument",
            Errno::InvalidPointer => "InvalidPointer",
            Errno::InvalidCapability => "InvalidCapability",
            Errno::PermissionDenied => "PermissionDenied",
            Errno::RevokedCapability => "RevokedCapability",
            Errno::ObjectNotFound => "ObjectNotFound",
            Errno::QuotaExceeded => "QuotaExceeded",
            Errno::TenantMismatch => "TenantMismatch",
            Errno::BufferTooSmall => "BufferTooSmall",
            Errno::Expired => "Expired",
            Errno::UsesExhausted => "UsesExhausted",
            Errno::ResourceUnavailable => "ResourceUnavailable",
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        let mut i = 0;
        while i < Self::ALL.len() {
            if Self::ALL[i] as u64 == code {
                return Some(Self::ALL[i]);
            }
            i += 1;
        }
        None
    }
}

/// Interpreta el valor devuelto por `syscall`: `Ok(dato)` o `Err(errno)`.
/// Un codigo en el rango de errores que este contrato no conoce se reporta como
/// `InvalidArgument` (fail-closed).
pub fn decode(ret: u64) -> Result<u64, Errno> {
    if ret >= ERROR_BASE {
        Err(Errno::from_code(ret).unwrap_or(Errno::InvalidArgument))
    } else {
        Ok(ret)
    }
}

/// Handle opaco de capability: generacion en los 32 bits altos, slot en los bajos.
/// La generacion nunca es 0, de modo que `Handle(0)` es siempre invalido.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Handle(pub u64);

impl Handle {
    pub const INVALID: Handle = Handle(0);

    pub const fn new(slot: u32, generation: u32) -> Self {
        Handle(((generation as u64) << 32) | slot as u64)
    }

    pub const fn slot(self) -> u32 {
        self.0 as u32
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn is_valid(self) -> bool {
        self.generation() != 0
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn panic_counters_pack_and_saturate_without_bleeding_into_each_other() {
        assert_eq!(panic::unpack(panic::pack(3, 17, 2)), (3, 17, 2));
        assert_eq!(panic::unpack(panic::pack(0, 0, 0)), (0, 0, 0));
        assert_eq!(panic::unpack(panic::pack(1 << 20, 5, 6)), (0xFFFF, 5, 6), "el desborde satura, no contamina al vecino");
        assert!(panic::pack(0xFFFF, 0xFFFF, 0xFFFF) < ERROR_BASE, "un resultado empaquetado nunca parece un Errno");
        assert_eq!(panic::KNOWN_FLAGS, panic::FLAG_WIPE);
    }

    use super::*;

    #[test]
    fn net_control_is_registered_and_only_knows_its_three_operations() {
        assert_eq!(Syscall::from_u64(0x5C), Some(Syscall::NetControl));
        assert!(netctl::is_known(netctl::UP) && netctl::is_known(netctl::DOWN) && netctl::is_known(netctl::SELFTEST));
        assert!(!netctl::is_known(0) && !netctl::is_known(4) && !netctl::is_known(u64::MAX));
    }

    #[test]
    fn sysinfo_kinds_are_unique_and_the_syscall_is_registered() {
        use sysinfo::*;
        let kinds = [IDENTITY, MEMORY, TENANT_USAGE, PROCESSES, CAPS, ACTORS, NET, NET_STATS];
        for (i, a) in kinds.iter().enumerate() {
            assert!(*a != 0);
            assert!(kinds[i + 1..].iter().all(|b| a != b));
        }
        assert_eq!(Syscall::SystemInfo.number(), 0x58);
        assert_eq!(Syscall::from_u64(0x58), Some(Syscall::SystemInfo));
        // las capabilities globales conocidas tienen nombre; un id de objeto cualquiera no
        for id in [1, 2, 3, 4, 5, 6, 0x10, 0x11, 0x12, 0x13] {
            assert!(global_cap_name(id).is_some(), "{id}");
        }
        assert_eq!(global_cap_name(1234), None);
    }

    #[test]
    fn wait_deadlines_are_consistent() {
        use spawn::{DEFAULT_WAIT_TICKS, MAX_WAIT_TICKS};
        assert!(DEFAULT_WAIT_TICKS > 0 && DEFAULT_WAIT_TICKS <= MAX_WAIT_TICKS);
        assert_eq!(MAX_WAIT_TICKS, 60 * 100, "60 s a 100 Hz");
    }

    #[test]
    fn audit_op_codes_are_unique_and_named() {
        use audit::*;
        let ops = [OP_READ, OP_WRITE, OP_DELETE, OP_GRANT, OP_DELEGATE, OP_REVOKE, OP_CREATE, OP_IDENTITY, OP_FAULT, OP_KILL, OP_CONSOLE, OP_HALT, OP_IPC, OP_PANIC, OP_THAW, OP_NET];
        for (i, a) in ops.iter().enumerate() {
            assert_ne!(op_name(*a), "?", "op {a} sin nombre");
            for b in &ops[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!((op_name(OP_CONSOLE), op_name(OP_HALT)), ("console", "halt"));
        assert_eq!(op_name(OP_IPC), "ipc");
        assert_eq!((op_name(OP_PANIC), op_name(OP_THAW), op_name(OP_NET)), ("panic", "thaw", "net"));
    }

    #[test]
    fn kernel_and_shell_signing_keys_are_distinct_roles() {
        use trust::*;
        assert_ne!(KERNEL_SIGNING_PUBLIC_KEY, SHELL_SIGNING_PUBLIC_KEY);
        assert_ne!(KERNEL_SIGNING_PUBLIC_KEY, [0u8; 32], "la clave del kernel esta aprovisionada");
    }


    #[test]
    fn syscall_numbers_are_unique_and_round_trip() {
        for (i, a) in Syscall::ALL.iter().enumerate() {
            assert_eq!(Syscall::from_u64(a.number()), Some(*a));
            for b in &Syscall::ALL[i + 1..] {
                assert_ne!(a.number(), b.number(), "{a:?} y {b:?} comparten numero");
            }
        }
        assert_eq!(Syscall::from_u64(0), None);
        assert_eq!(Syscall::from_u64(u64::MAX), None);
    }

    #[test]
    fn syscall_numbers_never_collide_with_the_error_range() {
        for s in Syscall::ALL {
            assert!(s.number() < ERROR_BASE);
        }
    }

    #[test]
    fn errno_codes_are_unique_and_in_the_error_range() {
        for (i, a) in Errno::ALL.iter().enumerate() {
            assert!(a.code() >= ERROR_BASE);
            assert_eq!(Errno::from_code(a.code()), Some(*a));
            for b in &Errno::ALL[i + 1..] {
                assert_ne!(a.code(), b.code());
            }
        }
        assert_eq!(Errno::from_code(0), None);
    }

    /// Los valores numericos ya expuestos al userland no cambian.
    #[test]
    fn legacy_error_codes_are_stable() {
        assert_eq!(Errno::InvalidArgument.code(), 0xFFFF_FFFF_FFFF_0001);
        assert_eq!(Errno::InvalidPointer.code(), 0xFFFF_FFFF_FFFF_0002);
        assert_eq!(Errno::InvalidCapability.code(), 0xFFFF_FFFF_FFFF_0003);
        assert_eq!(Errno::PermissionDenied.code(), 0xFFFF_FFFF_FFFF_0004);
        assert_eq!(Errno::RevokedCapability.code(), 0xFFFF_FFFF_FFFF_0005);
        assert_eq!(Errno::ObjectNotFound.code(), 0xFFFF_FFFF_FFFF_0006);
        assert_eq!(Errno::QuotaExceeded.code(), 0xFFFF_FFFF_FFFF_0007);
    }

    #[test]
    fn boot_contract_layout_is_stable() {
        assert_eq!(core::mem::size_of::<boot::MemRegion>(), boot::MemRegion::SIZE);
        assert_eq!(core::mem::size_of::<boot::BootInfo>(), 9 * 8);
        assert_eq!(boot::BOOT_INFO_MAGIC, u64::from_le_bytes(*b"TRNMBOOT"));
    }

    #[test]
    fn audit_record_round_trips() {
        let r = audit::Record { seq: 9, subject: 3, tenant: 100, resource: 55, handle: (1 << 32) | 2, op: audit::OP_REVOKE, outcome: 0x05 };
        let bytes = r.encode();
        assert_eq!(bytes.len(), audit::RECORD_SIZE);
        assert_eq!(audit::Record::decode(&bytes), Some(r));
        assert_eq!(audit::Record::decode(&bytes[..47]), None);
    }

    #[test]
    fn errno_names_are_unique() {
        for (i, a) in Errno::ALL.iter().enumerate() {
            for b in &Errno::ALL[i + 1..] {
                assert_ne!(a.name(), b.name());
            }
        }
    }

    #[test]
    fn decode_separates_data_from_errors() {
        assert_eq!(decode(OK), Ok(0));
        assert_eq!(decode(42), Ok(42));
        assert_eq!(decode(Errno::Expired.code()), Err(Errno::Expired));
        // Un codigo de error desconocido es un error, nunca un exito.
        assert_eq!(decode(ERROR_BASE + 0x7FFF), Err(Errno::InvalidArgument));
        assert_eq!(decode(u64::MAX), Err(Errno::InvalidArgument));
    }

    #[test]
    fn handle_packs_slot_and_generation() {
        let h = Handle::new(7, 3);
        assert_eq!((h.slot(), h.generation()), (7, 3));
        assert!(h.is_valid());
        assert!(!Handle::INVALID.is_valid());
        assert_eq!(Handle::new(u32::MAX, u32::MAX).slot(), u32::MAX);
        assert_eq!(Handle::new(u32::MAX, u32::MAX).generation(), u32::MAX);
    }
}
