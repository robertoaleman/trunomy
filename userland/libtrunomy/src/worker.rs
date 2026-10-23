// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Protocolo shell raiz <-> worker (parche 16).
//!
//! La shell raiz es solo un intermediario con nombres: cada operacion de un usuario la ejecuta un
//! PROCESO lanzado con la identidad de ese usuario (`process::spawn`), que recibe la orden en su
//! pagina de argumentos, la ejecuta con syscalls normales (el kernel decide) y termina con un
//! codigo de salida = el resultado de la syscall (un handle, 0, o un `Errno`).
//! Este modulo es codigo puro de codec + el mapeo orden -> syscall, probado en el host.
//!
//! Formato (<= 256 bytes): `tag(1)` + campos. Enteros en little endian.
//! `C data` | `R h` | `W h data` | `D h` | `G h target rights uses` | `V h` | `T` | `A tenant` | `U` | `X kind` | `I what` | `H` | `S target data` | `M`

use crate::{Errno, Handle, ERROR_BASE};

pub const MAX_REQUEST: usize = trunomy_abi::spawn::MAX_ARGS;

/// Bytes de texto de un mensaje IPC (4 palabras de 64 bits) y su identificador fijo.
/// Texto maximo de `NetSend`/`NetLoopback` (cabe en `MAX_REQUEST` con su cabecera).
pub const NET_TEXT_MAX: usize = 128;
pub const IPC_TEXT_MAX: usize = trunomy_abi::MAX_INLINE_WORDS * 8;
const IPC_TEXT_ID: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    ObjectCreate { data: &'a [u8] },
    ObjectRead { handle: u64 },
    ObjectWrite { handle: u64, data: &'a [u8] },
    ObjectDelete { handle: u64 },
    CapDerive { handle: u64, target: u64, rights: u64, uses: u64 },
    CapRevoke { handle: u64 },
    TenantCreate,
    ActorCreate { tenant: u64, ipc: bool, net: bool },
    /// Liga `src`, envia `text` a `mac`:`dst` y suelta `src`. Necesita `net` (I-47).
    NetSend { src: u16, dst: u16, mac: [u8; 6], text: &'a [u8] },
    /// Liga `port` y espera hasta `ticks` (100 por segundo) un mensaje; lo muestra y suelta el puerto.
    NetListen { port: u16, ticks: u16 },
    /// Prueba de extremo a extremo sin cable: liga dos puertos propios, se envia `text` a si mismo
    /// (`SELF_MAC`), lo recibe y lo muestra.
    NetLoopback { text: &'a [u8] },
    /// Corte de emergencia de un tenant (solo el lider; a un usuario el kernel se lo deniega y lo audita).
    TenantPanic { tenant: u64, wipe: bool },
    TenantThaw { tenant: u64 },
    /// Red: `trunomy_abi::netctl` (`UP`, `DOWN`, `SELFTEST`). Solo el lider; a un usuario el kernel se lo deniega y lo audita.
    NetControl { op: u8 },
    /// Intenta leer la auditoria (solo el lider puede; sirve para que un actor reciba el veredicto).
    AuditProbe,
    /// Prueba de contencion: el worker provoca un fallo de CPU (`b'f'` #PF, `b'u'` #UD) o se
    /// cuelga (`b'h'`). El kernel debe terminar SOLO a este proceso (I-33).
    SelfTest { kind: u8 },
    /// Consulta de estado real al kernel (`SystemInfo`, I-42): `b'w'` identidad, `b'i'` id,
    /// `b'f'` memoria (raiz) o cuota del tenant (usuario), `b'p'` procesos, `b'c'` capabilities, `b'n'` red, `b's'` contadores de red (solo raiz).
    Info { what: u8 },
    /// Envia hasta 32 bytes de texto (relleno con ceros) al actor `target` por `SendIpc`.
    IpcSend { target: u64, data: &'a [u8] },
    /// Recibe el siguiente mensaje propio y lo muestra como texto.
    IpcRecv,
    /// Pide detener la maquina. Solo la raiz puede; a un usuario el kernel se lo deniega y lo audita.
    Halt,
}

fn le(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

impl<'a> Request<'a> {
    /// Serializa en `out`; `None` si no cabe en `MAX_REQUEST`.
    pub fn encode(&self, out: &mut [u8; MAX_REQUEST]) -> Option<usize> {
        let mut n = 0usize;
        fn put(out: &mut [u8; MAX_REQUEST], n: &mut usize, bytes: &[u8]) -> Option<()> {
            let end = n.checked_add(bytes.len())?;
            out.get_mut(*n..end)?.copy_from_slice(bytes);
            *n = end;
            Some(())
        }
        match *self {
            Request::ObjectCreate { data } => { put(out, &mut n, b"C")?; put(out, &mut n, data)?; }
            Request::ObjectRead { handle } => { put(out, &mut n, b"R")?; put(out, &mut n, &handle.to_le_bytes())?; }
            Request::ObjectWrite { handle, data } => {
                put(out, &mut n, b"W")?; put(out, &mut n, &handle.to_le_bytes())?; put(out, &mut n, data)?;
            }
            Request::ObjectDelete { handle } => { put(out, &mut n, b"D")?; put(out, &mut n, &handle.to_le_bytes())?; }
            Request::CapDerive { handle, target, rights, uses } => {
                put(out, &mut n, b"G")?;
                for v in [handle, target, rights, uses] { put(out, &mut n, &v.to_le_bytes())?; }
            }
            Request::CapRevoke { handle } => { put(out, &mut n, b"V")?; put(out, &mut n, &handle.to_le_bytes())?; }
            Request::TenantCreate => put(out, &mut n, b"T")?,
            Request::ActorCreate { tenant, ipc, net } => { put(out, &mut n, b"A")?; put(out, &mut n, &tenant.to_le_bytes())?; put(out, &mut n, &[ipc as u8 | (net as u8) << 1])?; }
            Request::NetSend { src, dst, mac, text } => {
                put(out, &mut n, b"E")?; put(out, &mut n, &src.to_le_bytes())?; put(out, &mut n, &dst.to_le_bytes())?; put(out, &mut n, &mac)?; put(out, &mut n, text)?;
            }
            Request::NetListen { port, ticks } => { put(out, &mut n, b"L")?; put(out, &mut n, &port.to_le_bytes())?; put(out, &mut n, &ticks.to_le_bytes())?; }
            Request::NetLoopback { text } => { put(out, &mut n, b"O")?; put(out, &mut n, text)?; }
            Request::TenantPanic { tenant, wipe } => { put(out, &mut n, b"P")?; put(out, &mut n, &tenant.to_le_bytes())?; put(out, &mut n, &[wipe as u8])?; }
            Request::TenantThaw { tenant } => { put(out, &mut n, b"Z")?; put(out, &mut n, &tenant.to_le_bytes())?; }
            Request::NetControl { op } => { put(out, &mut n, b"N")?; put(out, &mut n, &[op])?; }
            Request::IpcSend { target, data } => { put(out, &mut n, b"S")?; put(out, &mut n, &target.to_le_bytes())?; put(out, &mut n, data)?; }
            Request::IpcRecv => put(out, &mut n, b"M")?,
            Request::AuditProbe => put(out, &mut n, b"U")?,
            Request::SelfTest { kind } => { put(out, &mut n, b"X")?; put(out, &mut n, &[kind])?; }
            Request::Info { what } => { put(out, &mut n, b"I")?; put(out, &mut n, &[what])?; }
            Request::Halt => put(out, &mut n, b"H")?,
        }
        Some(n)
    }

    /// Interpreta una orden; `None` si esta mal formada (longitud o etiqueta incorrectas).
    pub fn decode(bytes: &'a [u8]) -> Option<Request<'a>> {
        let (&tag, rest) = bytes.split_first()?;
        let exact = |n: usize| if rest.len() == n { Some(()) } else { None };
        Some(match tag {
            b'C' => Request::ObjectCreate { data: rest },
            b'R' => { exact(8)?; Request::ObjectRead { handle: le(rest, 0)? } }
            b'W' => { if rest.len() < 8 { return None; } Request::ObjectWrite { handle: le(rest, 0)?, data: &rest[8..] } }
            b'D' => { exact(8)?; Request::ObjectDelete { handle: le(rest, 0)? } }
            b'G' => { exact(32)?; Request::CapDerive { handle: le(rest, 0)?, target: le(rest, 8)?, rights: le(rest, 16)?, uses: le(rest, 24)? } }
            b'V' => { exact(8)?; Request::CapRevoke { handle: le(rest, 0)? } }
            b'T' => { exact(0)?; Request::TenantCreate }
            b'A' => { exact(9)?; if rest[8] > 3 { return None; } Request::ActorCreate { tenant: le(rest, 0)?, ipc: rest[8] & 1 != 0, net: rest[8] & 2 != 0 } }
            b'E' => {
                if rest.len() < 10 || rest.len() > 10 + NET_TEXT_MAX { return None; }
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&rest[4..10]);
                Request::NetSend { src: u16::from_le_bytes([rest[0], rest[1]]), dst: u16::from_le_bytes([rest[2], rest[3]]), mac, text: &rest[10..] }
            }
            b'L' => { exact(4)?; Request::NetListen { port: u16::from_le_bytes([rest[0], rest[1]]), ticks: u16::from_le_bytes([rest[2], rest[3]]) } }
            b'O' => { if rest.len() > NET_TEXT_MAX { return None; } Request::NetLoopback { text: rest } }
            b'P' => { exact(9)?; Request::TenantPanic { tenant: le(rest, 0)?, wipe: match rest[8] { 0 => false, 1 => true, _ => return None } } }
            b'Z' => { exact(8)?; Request::TenantThaw { tenant: le(rest, 0)? } }
            b'N' => { exact(1)?; Request::NetControl { op: rest[0] } }
            b'S' => { if rest.len() < 8 || rest.len() > 8 + IPC_TEXT_MAX { return None; } Request::IpcSend { target: le(rest, 0)?, data: &rest[8..] } }
            b'M' => { exact(0)?; Request::IpcRecv }
            b'U' => { exact(0)?; Request::AuditProbe }
            b'X' => { exact(1)?; Request::SelfTest { kind: *rest.first()? } }
            b'I' => { exact(1)?; Request::Info { what: *rest.first()? } }
            b'H' => { exact(0)?; Request::Halt }
            _ => return None,
        })
    }
}

/// Codigo de salida de un resultado: el valor, o el `Errno` (siempre `>= ERROR_BASE`).
pub fn code_of(r: Result<u64, Errno>) -> u64 {
    r.unwrap_or_else(|e| e.code())
}

/// Interpreta un codigo de salida como resultado de syscall.
pub fn result_of(code: u64) -> Result<u64, Errno> {
    crate::decode(code)
}

/// Ejecuta la orden con las syscalls normales. Lo que haya que mostrar (el contenido leido) se
/// entrega a `show`. Devuelve el codigo de salida. Lo ejecutan tanto la shell raiz (como lider)
/// como un worker (como el actor): la unica diferencia es QUIEN es el proceso, y eso lo decide el
/// kernel.
pub fn execute(req: &Request, show: &mut dyn FnMut(&[u8])) -> u64 {
    use crate::{objects, session};
    code_of(match *req {
        Request::ObjectCreate { data } => objects::object_create(data).map(|h| h.0),
        Request::ObjectRead { handle } => {
            let mut buf = [0u8; 256];
            objects::object_read(Handle(handle), &mut buf).map(|n| { show(&buf[..n]); 0 })
        }
        Request::ObjectWrite { handle, data } => objects::object_write(Handle(handle), data).map(|_| 0),
        Request::ObjectDelete { handle } => objects::object_delete(Handle(handle)).map(|_| 0),
        Request::CapDerive { handle, target, rights, uses } => {
            let uses = u32::try_from(uses).unwrap_or(u32::MAX);
            objects::cap_derive(Handle(handle), target, rights, uses).map(|h| h.0)
        }
        Request::CapRevoke { handle } => objects::cap_revoke(Handle(handle)).map(|_| 0),
        Request::TenantCreate => session::tenant_create(),
        Request::ActorCreate { tenant, ipc, net } => session::actor_create(tenant, ipc, net),
        Request::NetSend { src, dst, mac, text } => net_send(src, dst, mac, text),
        Request::NetListen { port, ticks } => net_listen(port, ticks, show),
        Request::NetLoopback { text } => net_loopback(text, show),
        Request::TenantPanic { tenant, wipe } => session::tenant_panic(tenant, wipe),
        Request::TenantThaw { tenant } => session::tenant_thaw(tenant),
        Request::NetControl { op } => session::net_control(op as u64),
        Request::IpcSend { target, data } => {
            let mut words = [0u64; trunomy_abi::MAX_INLINE_WORDS];
            for (i, b) in data.iter().take(IPC_TEXT_MAX).enumerate() {
                words[i / 8] |= (*b as u64) << (8 * (i % 8));
            }
            crate::ipc_client::send_ipc_message(target, IPC_TEXT_ID, &words).map(|_| 0)
        }
        Request::IpcRecv => ipc_recv(show),
        Request::AuditProbe => {
            let mut recs = [crate::abi_audit::Record { seq: 0, subject: 0, tenant: 0, resource: 0, handle: 0, op: 0, outcome: 0 }; 1];
            session::audit_read(&mut recs, u64::MAX).map(|_| 0)
        }
        Request::SelfTest { kind } => self_test(kind),
        Request::Info { what } => info(what, show),
        Request::Halt => crate::decode(unsafe { crate::syscall4(crate::SyscallNumber::Halt.number(), 0, 0, 0, 0) }),
    })
}

/// Recibe un mensaje propio y lo muestra (los ceros del relleno se descartan). Sin mensajes: `ObjectNotFound`.
/// Ticks maximos de espera de `NetListen`: el worker tiene su cuota de CPU (`quota`), y esperar
/// cediendo la CPU tambien cuenta; mas que esto el kernel lo cortaria.
pub const NET_LISTEN_MAX_TICKS: u16 = 150;

fn net_send(src: u16, dst: u16, mac: [u8; 6], text: &[u8]) -> Result<u64, Errno> {
    use crate::net;
    net::bind(src)?;
    let r = net::send(src, dst, mac, text);
    let _ = net::unbind(src);
    r.map(|_| 0)
}

/// Linea "from <mac>:<puerto>: <texto>". Todo lo del par es dato sin autenticar.
fn received_line(m: &crate::net::Received, line: &mut crate::sysinfo::Line) {
    line.str("from ");
    for (i, b) in m.peer_mac.iter().enumerate() {
        if i > 0 {
            line.str(":");
        }
        line.hex(*b as u64, 2);
    }
    line.str(" port ").num(m.peer_port as u64).str(": ").bytes(m.payload());
}

fn net_listen(port: u16, ticks: u16, show: &mut dyn FnMut(&[u8])) -> Result<u64, Errno> {
    use crate::{net, session, sysinfo::Line};
    let ticks = ticks.min(NET_LISTEN_MAX_TICKS) as u64;
    net::bind(port)?;
    let start = session::clock_ticks().unwrap_or(0);
    let got = loop {
        match net::recv(port) {
            Ok(Some(m)) => break Ok(Some(m)),
            Ok(None) => {}
            Err(e) => break Err(e),
        }
        if session::clock_ticks().unwrap_or(u64::MAX).saturating_sub(start) >= ticks {
            break Ok(None);
        }
        crate::yield_now();
    };
    let _ = net::unbind(port);
    match got? {
        Some(m) => {
            let mut line = Line::new();
            received_line(&m, &mut line);
            show(line.finish());
            Ok(1)
        }
        None => Ok(0),
    }
}

/// Puertos de la prueba de bucle local (de usuario, altos).
const LOOP_A: u16 = 40001;
const LOOP_B: u16 = 40002;

fn net_loopback(text: &[u8], show: &mut dyn FnMut(&[u8])) -> Result<u64, Errno> {
    use crate::{net, sysinfo::Line};
    net::bind(LOOP_A)?;
    let r = (|| {
        net::bind(LOOP_B)?;
        let r = (|| {
            net::send(LOOP_A, LOOP_B, trunomy_abi::netio::SELF_MAC, text)?;
            let m = net::recv(LOOP_B)?.ok_or(Errno::ObjectNotFound)?;
            let mut line = Line::new();
            received_line(&m, &mut line);
            show(line.finish());
            Ok(1)
        })();
        let _ = net::unbind(LOOP_B);
        r
    })();
    let _ = net::unbind(LOOP_A);
    r
}

fn ipc_recv(show: &mut dyn FnMut(&[u8])) -> Result<u64, Errno> {
    let mut who = [0u64; 3];
    crate::sysinfo::query(trunomy_abi::sysinfo::IDENTITY, 0, &mut who)?;
    let mut words = [0u64; trunomy_abi::MAX_INLINE_WORDS];
    crate::ipc_client::receive_ipc_message(who[0], &mut words)?;
    let mut text = [0u8; IPC_TEXT_MAX];
    for (i, w) in words.iter().enumerate() {
        text[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    let len = text.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    show(&text[..len]);
    Ok(0)
}

/// Muestra estado real del kernel. Cada llamada a `show` es una linea.
fn info(what: u8, show: &mut dyn FnMut(&[u8])) -> Result<u64, Errno> {
    use crate::sysinfo::{self as si, Line};
    use trunomy_abi::sysinfo as k;
    let mut w = [0u64; 4];
    let mut line = Line::new();
    match what {
        b'w' | b'i' => {
            si::query(k::IDENTITY, 0, &mut w)?;
            si::identity_line(&w, &mut line);
        }
        b'f' => {
            si::query(k::IDENTITY, 0, &mut w)?;
            if w[2] == 1 {
                si::query(k::MEMORY, 0, &mut w)?;
                si::memory_line(&w, &mut line);
            } else {
                si::query(k::TENANT_USAGE, 0, &mut w)?;
                si::tenant_usage_line(&w, &mut line);
            }
        }
        b'p' => {
            let mut recs = [0u64; 3 * 9];
            let n = si::query(k::PROCESSES, 0, &mut recs)?;
            for r in recs.chunks_exact(3).take(n) {
                let mut l = Line::new();
                si::process_line(r, &mut l);
                show(l.finish());
            }
            return Ok(0);
        }
        b'n' => {
            let mut nw = [0u64; k::NET_WORDS];
            si::query(k::NET, 0, &mut nw)?;
            si::net_line(&nw, &mut line);
        }
        b's' => {
            let mut sw = [0u64; k::NET_STATS_WORDS];
            si::query(k::NET_STATS, 0, &mut sw)?;
            si::net_stats_line(&sw, &mut line);
        }
        b'c' => {
            let mut recs = [0u64; 4 * 16];
            let n = si::query(k::CAPS, 0, &mut recs)?;
            if n == 0 {
                line.str("(no capabilities)");
            }
            for (i, r) in recs.chunks_exact(4).take(n).enumerate() {
                if i > 0 {
                    line.str("; ");
                }
                si::cap_text(r, &mut line);
            }
        }
        _ => return Err(Errno::InvalidArgument),
    }
    show(line.finish());
    Ok(0)
}

/// Recursion que usa pila de verdad (el buffer se lee despues de la llamada).
#[allow(unconditional_recursion)]
#[inline(never)]
fn overflow_stack(n: u64) -> u64 {
    let buf = [n as u8; 512];
    let r = overflow_stack(n.wrapping_add(1));
    core::hint::black_box(&buf);
    r.wrapping_add(buf[0] as u64)
}

/// Provoca a proposito un fallo o un cuelgue. Solo para pruebas de contencion, y solo debe
/// ejecutarlo un worker (en la shell raiz detendria la sesion).
fn self_test(kind: u8) -> Result<u64, Errno> {
    match kind {
        // Escritura en una pagina sin mapear: #PF.
        b'f' => unsafe { core::ptr::write_volatile(0x10 as *mut u64, 1); Ok(0) },
        // Instruccion invalida: #UD.
        #[cfg(target_arch = "x86_64")]
        b'u' => unsafe { core::arch::asm!("ud2", options(noreturn)) },
        // Recursion sin fin: desborda la pila de usuario contra su pagina de guarda (#PF).
        b's' => Ok(overflow_stack(1)),
        // Bucle infinito: lo mata la cuota de CPU (o, si no, el plazo de `wait_timeout`).
        b'h' => loop { core::hint::spin_loop() },
        // Intenta usar la consola del operador y detener la maquina. El kernel debe denegar
        // ambas (I-35) y dejarlo auditado (I-41): el veredicto es el error de la primera denegada.
        b'c' => unsafe {
            let w = crate::syscall4(crate::SyscallNumber::ConsoleWrite.number(), b'X' as u64, 0, 0, 0);
            let h = crate::syscall4(crate::SyscallNumber::Halt.number(), 0, 0, 0, 0);
            match (crate::decode(w), crate::decode(h)) {
                (Err(e), Err(_)) => Err(e),
                // Algo no se denego: se devuelve OK para que la shell lo marque como inesperado.
                _ => Ok(0),
            }
        },
        _ => Err(Errno::InvalidArgument),
    }
}

/// Un byte de salida ajena es seguro para la consola del operador solo si es ASCII imprimible:
/// el resto (ESC, retorno de carro, controles, UTF-8 suelto) se muestra como `.` y asi un
/// worker no puede mover el cursor, borrar la pantalla ni falsificar lineas del operador (I-35).
pub const fn printable(b: u8) -> u8 {
    if b >= 0x20 && b <= 0x7E { b } else { b'.' }
}

/// Orden que el kernel dejo en la pagina de argumentos de este proceso; vacia en la shell raiz.
/// Solo valida en un proceso del kernel de Trunomy (la pagina existe siempre, ver `image.rs`).
pub unsafe fn startup_args() -> &'static [u8] {
    let base = trunomy_abi::spawn::ARGS_VADDR as *const u8;
    let len = core::ptr::read_volatile(base as *const u64) as usize;
    let len = len.min(MAX_REQUEST);
    core::slice::from_raw_parts(base.add(8), len)
}

/// Un worker nunca devuelve un codigo que se confunda con un valor valido: los errores son
/// `>= ERROR_BASE` y los handles y contadores quedan por debajo.
pub const fn is_error_code(code: u64) -> bool {
    code >= ERROR_BASE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(r: Request) {
        let mut buf = [0u8; MAX_REQUEST];
        let n = r.encode(&mut buf).expect("cabe");
        assert_eq!(Request::decode(&buf[..n]), Some(r));
    }

    #[test]
    fn every_request_survives_encode_decode() {
        roundtrip(Request::ObjectCreate { data: b"hola-mundo" });
        roundtrip(Request::ObjectCreate { data: b"" });
        roundtrip(Request::ObjectRead { handle: 0x0000_0001_0000_0002 });
        roundtrip(Request::ObjectWrite { handle: 7, data: b"hackeado" });
        roundtrip(Request::ObjectWrite { handle: 7, data: b"" });
        roundtrip(Request::ObjectDelete { handle: 9 });
        roundtrip(Request::CapDerive { handle: 1, target: 1001, rights: 1, uses: 3 });
        roundtrip(Request::CapRevoke { handle: u64::MAX >> 1 });
        roundtrip(Request::TenantCreate);
        for (ipc, net) in [(false, false), (true, false), (false, true), (true, true)] {
            roundtrip(Request::ActorCreate { tenant: 1000, ipc, net });
        }
        roundtrip(Request::NetSend { src: 40001, dst: 7, mac: [2, 0, 0, 0, 0, 9], text: b"hola" });
        roundtrip(Request::NetSend { src: 1, dst: 65535, mac: [0xFF; 6], text: &[b'x'; NET_TEXT_MAX] });
        roundtrip(Request::NetListen { port: 100, ticks: 150 });
        roundtrip(Request::NetLoopback { text: b"vuelta" });
        roundtrip(Request::TenantPanic { tenant: 1000, wipe: false });
        roundtrip(Request::TenantPanic { tenant: 1000, wipe: true });
        roundtrip(Request::TenantThaw { tenant: 1000 });
        roundtrip(Request::NetControl { op: 3 });
        roundtrip(Request::IpcSend { target: 1001, data: b"hola" });
        roundtrip(Request::IpcSend { target: 1001, data: &[b'x'; IPC_TEXT_MAX] });
        roundtrip(Request::IpcRecv);
        roundtrip(Request::AuditProbe);
        roundtrip(Request::SelfTest { kind: b'f' });
        roundtrip(Request::SelfTest { kind: b'h' });
        roundtrip(Request::SelfTest { kind: b's' });
        roundtrip(Request::Info { what: b'f' });
        roundtrip(Request::Halt);
    }

    #[test]
    fn tenant_panic_requests_are_strict() {
        let mut buf = [0u8; MAX_REQUEST];
        let n = Request::TenantPanic { tenant: 1000, wipe: true }.encode(&mut buf).unwrap();
        assert_eq!(Request::decode(&buf[..n - 1]), None, "truncada");
        let mut bad = buf;
        bad[n - 1] = 2;
        assert_eq!(Request::decode(&bad[..n]), None, "la bandera solo vale 0 o 1");
        assert_eq!(Request::decode(b"Z"), None);
        assert_eq!(Request::decode(b"P\x01"), None);
    }

    #[test]
    fn untrusted_output_cannot_carry_terminal_controls() {
        for b in 0u8..=255 {
            let p = printable(b);
            assert!((0x20..=0x7E).contains(&p), "byte {b:#x} -> {p:#x}");
        }
        assert_eq!(printable(b'a'), b'a');
        assert_eq!(printable(0x1B), b'.', "ESC");
        assert_eq!(printable(b'\r'), b'.');
        assert_eq!(printable(b'\n'), b'.', "un worker no inventa lineas");
        assert_eq!(printable(0x7F), b'.');
        assert_eq!(printable(0xC3), b'.');
    }

    #[test]
    fn ipc_requests_are_strict() {
        // el texto de un mensaje cabe en 4 palabras: 33 bytes de texto no se decodifican
        let mut raw = [0u8; 1 + 8 + IPC_TEXT_MAX + 1];
        raw[0] = b'S';
        assert_eq!(Request::decode(&raw), None);
        assert!(Request::decode(&raw[..raw.len() - 1]).is_some(), "32 bytes caben justo");
        assert_eq!(Request::decode(b"S\x01"), None, "sin destino completo");
        assert_eq!(Request::decode(b"M!"), None);
        assert_eq!(Request::decode(&[b'A', 1, 0, 0, 0, 0, 0, 0, 0, 4]), None, "banderas invalidas");
        assert_eq!(Request::decode(&[b'A', 1, 0, 0, 0, 0, 0, 0, 0]), None, "falta la bandera");
    }

    #[test]
    fn info_and_halt_requests_are_strict() {
        assert_eq!(Request::decode(b"I"), None);
        assert_eq!(Request::decode(b"Ifp"), None);
        assert_eq!(Request::decode(b"H!"), None);
    }

    #[test]
    fn self_test_requests_are_strict() {
        assert_eq!(Request::decode(b"X"), None, "sin tipo");
        assert_eq!(Request::decode(b"Xfh"), None, "bytes sobrantes");
    }

    #[test]
    fn kernel_termination_codes_are_not_syscall_results() {
        use crate::abi_exit;
        // Un codigo del kernel no es un handle ni un Errno: la shell debe mirarlo ANTES de
        // interpretarlo como resultado de syscall.
        assert!(abi_exit::is_kernel_terminated(abi_exit::fault(14)));
        assert!(!is_error_code(abi_exit::fault(14)));
        assert!(!is_error_code(abi_exit::TIMEOUT));
    }

    #[test]
    fn oversized_requests_do_not_encode() {
        let mut buf = [0u8; MAX_REQUEST];
        let big = [b'x'; MAX_REQUEST];
        assert_eq!(Request::ObjectCreate { data: &big }.encode(&mut buf), None);
        assert_eq!(Request::ObjectWrite { handle: 1, data: &big[..MAX_REQUEST - 8] }.encode(&mut buf), None);
        // el maximo justo cabe
        assert_eq!(Request::ObjectCreate { data: &big[..MAX_REQUEST - 1] }.encode(&mut buf), Some(MAX_REQUEST));
        assert_eq!(Request::ObjectWrite { handle: 1, data: &big[..MAX_REQUEST - 9] }.encode(&mut buf), Some(MAX_REQUEST));
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert_eq!(Request::decode(b""), None);
        assert_eq!(Request::decode(b"Z"), None, "etiqueta desconocida");
        assert_eq!(Request::decode(b"R\x01\x02"), None, "handle truncado");
        assert_eq!(Request::decode(&[b'R', 1, 2, 3, 4, 5, 6, 7, 8, 9]), None, "bytes sobrantes");
        assert_eq!(Request::decode(b"T!"), None);
        assert_eq!(Request::decode(b"W\x01"), None, "sin handle completo");
        assert_eq!(Request::decode(&[b'G'; 20]), None, "G exige 32 bytes de campos");
        let mut a = [0u8; 10];
        a[0] = b'A';
        a[9] = 4;
        assert_eq!(Request::decode(&a), None, "banderas de actor desconocidas");
        assert_eq!(Request::decode(b"E\x01\x00\x02\x00abcde"), None, "NetSend sin la MAC completa");
        assert_eq!(Request::decode(&[b'E'; 11 + NET_TEXT_MAX + 1]), None, "texto demasiado largo");
        assert_eq!(Request::decode(b"L\x01\x00\x02"), None, "NetListen truncado");
        assert_eq!(Request::decode(&[b'O'; 2 + NET_TEXT_MAX]), None);
    }

    #[test]
    fn exit_codes_never_confuse_values_with_errors() {
        use crate::Errno;
        for e in Errno::ALL {
            let code = code_of(Err(e));
            assert!(is_error_code(code));
            assert_eq!(result_of(code), Err(e), "el padre recupera el mismo error");
        }
        let h = Handle::new(0xFFFF_FFFF, 0xFFFF).0;
        assert!(!is_error_code(h), "un handle valido nunca parece un error");
        assert_eq!(result_of(code_of(Ok(h))), Ok(h));
        assert_eq!(result_of(code_of(Ok(0))), Ok(0));
    }
}
