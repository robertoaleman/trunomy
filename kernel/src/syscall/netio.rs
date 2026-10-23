// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! `NetBind`, `NetUnbind`, `NetSend`, `NetRecv` (I-47): la red como servicio de un actor con capability.
//!
//! Ya antes de llegar aqui el dispatcher exige la capability global (`CAP_NET_SEND` para enviar,
//! `CAP_NET_RECV` para ligar, soltar y recibir) y audita (con limite) la denegacion. Este modulo agrega
//! lo que una capability no dice:
//! - el DUENO de un puerto lo fija el kernel (el llamante), y solo el dueno recibe, suelta o envia
//!   desde el; usar un puerto ajeno se ve como un puerto inexistente (`ObjectNotFound`) y queda
//!   auditado con limite (resource = puerto);
//! - lo que llega por el cable es hostil: se analiza con `abi::netproto`, se filtra por MAC y se
//!   entrega solo al endpoint del puerto destino; lo demas se descarta y se cuenta;
//! - todo esta acotado: tabla, cola por endpoint, tramas procesadas por llamada (`PUMP_MAX`);
//! - la recepcion es por sondeo: cada `NetRecv` primero recoge del dispositivo hasta `PUMP_MAX` tramas.
//!
//! El dispositivo queda detras de `NetPort` para probar todo en el host.

use alloc::vec::Vec;
use spin::Mutex;
use trunomy_abi::{netio, netproto, Errno};

use crate::audit::{self, AuditOp};
use crate::capabilities::CapabilityError;
use crate::net::endpoint::{BindError, Fate, Owner, Table};
use crate::net::nic::{RecvError, SendError};
use crate::process::ProcessContext;
use crate::user_access::{UserSlice, UserSpace};

/// Tramas del dispositivo que se procesan por llamada a `NetRecv`.
pub const PUMP_MAX: usize = 16;

/// El dispositivo de red visto por las syscalls. En el kernel real es el `Nic` activo (si lo hay).
pub trait NetPort {
    /// Nuestra MAC, si el dispositivo esta en marcha.
    fn our_mac(&self) -> Option<[u8; 6]>;
    fn send_frame(&self, frame: &[u8]) -> Result<(), SendError>;
    fn recv_frame(&self) -> Result<Option<Vec<u8>>, RecvError>;
}

fn port_of(v: u64) -> Result<u16, Errno> {
    u16::try_from(v).ok().filter(|p| *p != 0).ok_or(Errno::InvalidArgument)
}

fn deny_foreign_port(current: ProcessContext, port: u16) {
    audit::record_throttled_denial(current.subject_id, AuditOp::Net, Some(current.tenant_id), Some(port as u64), CapabilityError::NotFound);
}

fn check_owner(current: ProcessContext, table: &Mutex<Table>, port: u16) -> Result<(), Errno> {
    let owns = table.lock().owns(port, current.pid);
    if owns {
        Ok(())
    } else {
        deny_foreign_port(current, port);
        Err(Errno::ObjectNotFound)
    }
}

pub fn net_bind_with(current: ProcessContext, table: &Mutex<Table>, port: u64) -> Result<u64, Errno> {
    let port = port_of(port)?;
    let r = table.lock().bind(port, Owner { pid: current.pid, tenant: current.tenant_id, subject: current.subject_id });
    r.map(|_| 0).map_err(|e| match e {
        BindError::ZeroPort => Errno::InvalidArgument,
        BindError::InUse | BindError::TableFull => Errno::ResourceUnavailable,
        BindError::TenantQuota => Errno::QuotaExceeded,
    })
}

pub fn net_unbind_with(current: ProcessContext, table: &Mutex<Table>, port: u64) -> Result<u64, Errno> {
    let port = port_of(port)?;
    let r = table.lock().unbind(port, current.pid);
    match r {
        Ok(()) => Ok(0),
        Err(_) => {
            deny_foreign_port(current, port);
            Err(Errno::ObjectNotFound)
        }
    }
}

pub fn net_send_with<S: UserSpace, P: NetPort>(
    current: ProcessContext,
    space: &S,
    table: &Mutex<Table>,
    nic: &P,
    src_port: u64,
    dst_port: u64,
    ptr: u64,
    len: u64,
) -> Result<u64, Errno> {
    let (src, dst) = (port_of(src_port)?, port_of(dst_port)?);
    let slice = UserSlice::new(ptr, len).map_err(|e| e.errno())?;
    if slice.len() < netio::SEND_HEADER || slice.len() > netio::SEND_MAX {
        return Err(Errno::InvalidArgument);
    }
    let buf = slice.read_to_vec(space, netio::SEND_MAX).map_err(|e| e.errno())?;
    check_owner(current, table, src)?;
    let ours = nic.our_mac().ok_or(Errno::ResourceUnavailable)?;
    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&buf[..netio::SEND_HEADER]);
    let to_self = dst_mac == ours || dst_mac == netio::SELF_MAC;
    if to_self {
        dst_mac = ours;
    }
    let mut frame = [0u8; netproto::MAX_FRAME_LEN];
    let n = netproto::build(&mut frame, dst_mac, ours, src, dst, &buf[netio::SEND_HEADER..]).map_err(|_| Errno::InvalidArgument)?;
    if to_self {
        // Hacia uno mismo: se entrega por dentro, con las mismas reglas que una trama del cable.
        let _ = table.lock().deliver_frame(&frame[..n], ours);
        return Ok(0);
    }
    nic.send_frame(&frame[..n]).map(|_| 0).map_err(|e| match e {
        SendError::Full => Errno::QuotaExceeded,
        SendError::BadLength => Errno::InvalidArgument,
        SendError::Poisoned(_) => Errno::ResourceUnavailable,
    })
}

/// Recoge del dispositivo hasta `PUMP_MAX` tramas y las entrega a los endpoints.
fn pump<P: NetPort>(table: &Mutex<Table>, nic: &P, ours: [u8; 6]) {
    for _ in 0..PUMP_MAX {
        match nic.recv_frame() {
            Ok(Some(frame)) => {
                let fate = table.lock().deliver_frame(&frame, ours);
                let _ = matches!(fate, Fate::Queued);
            }
            // Sin mas tramas, o cola envenenada (queda visible en `net stats`): se deja de sondear.
            Ok(None) | Err(_) => break,
        }
    }
}

pub fn net_recv_with<S: UserSpace, P: NetPort>(
    current: ProcessContext,
    space: &S,
    table: &Mutex<Table>,
    nic: &P,
    port: u64,
    ptr: u64,
    len: u64,
) -> Result<u64, Errno> {
    let port = port_of(port)?;
    let out = UserSlice::new(ptr, len).map_err(|e| e.errno())?;
    if out.len() < netio::RECV_MIN_BUF {
        return Err(Errno::BufferTooSmall);
    }
    check_owner(current, table, port)?;
    if let Some(ours) = nic.our_mac() {
        pump(table, nic, ours);
    }
    let msg = table.lock().recv(port, current.pid).map_err(|_| Errno::ObjectNotFound)?;
    let Some(m) = msg else { return Ok(0) };
    let mut data = Vec::with_capacity(netio::RECV_HEADER + m.data.len());
    data.extend_from_slice(&m.peer_mac);
    data.extend_from_slice(&m.peer_port.to_le_bytes());
    data.extend_from_slice(&m.data);
    out.write_from(space, &data).map_err(|e| e.errno())?;
    Ok(data.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_access::tests::MockUserSpace;
    use crate::memory_validation::USER_MIN;
    use core::cell::RefCell;

    const OURS: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const PEER: [u8; 6] = [2, 0, 0, 0, 0, 9];
    const ANA: ProcessContext = ProcessContext::new(7801, 7801, 10);
    const ANA2: ProcessContext = ProcessContext::new(7802, 7802, 10);
    const EVE: ProcessContext = ProcessContext::new(7811, 7811, 20);

    #[derive(Default)]
    struct Fake {
        up: bool,
        sent: RefCell<Vec<Vec<u8>>>,
        inbox: RefCell<Vec<Vec<u8>>>,
        full: bool,
        polls: RefCell<usize>,
    }
    impl NetPort for Fake {
        fn our_mac(&self) -> Option<[u8; 6]> {
            self.up.then_some(OURS)
        }
        fn send_frame(&self, f: &[u8]) -> Result<(), SendError> {
            if self.full {
                return Err(SendError::Full);
            }
            self.sent.borrow_mut().push(f.to_vec());
            Ok(())
        }
        fn recv_frame(&self) -> Result<Option<Vec<u8>>, RecvError> {
            *self.polls.borrow_mut() += 1;
            let mut i = self.inbox.borrow_mut();
            Ok(if i.is_empty() { None } else { Some(i.remove(0)) })
        }
    }

    fn up() -> Fake {
        Fake { up: true, ..Default::default() }
    }

    fn wire(dst_mac: [u8; 6], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = [0u8; netproto::MAX_FRAME_LEN];
        let n = netproto::build(&mut b, dst_mac, PEER, src_port, dst_port, payload).unwrap();
        b[..n].to_vec()
    }

    fn put(sp: &MockUserSpace, off: usize, data: &[u8]) {
        sp.mem.borrow_mut()[off..off + data.len()].copy_from_slice(data);
    }

    fn send(sp: &MockUserSpace, t: &Mutex<Table>, n: &Fake, who: ProcessContext, src: u64, dst: u64, mac: [u8; 6], payload: &[u8]) -> Result<u64, Errno> {
        let mut buf = mac.to_vec();
        buf.extend_from_slice(payload);
        put(sp, 0, &buf);
        net_send_with(who, sp, t, n, src, dst, USER_MIN, buf.len() as u64)
    }

    fn recv(sp: &MockUserSpace, t: &Mutex<Table>, n: &Fake, who: ProcessContext, port: u64) -> Result<Option<(Vec<u8>, u16, Vec<u8>)>, Errno> {
        let got = net_recv_with(who, sp, t, n, port, USER_MIN + 1024, netio::RECV_MIN_BUF as u64)?;
        if got == 0 {
            return Ok(None);
        }
        let m = sp.mem.borrow()[1024..1024 + got as usize].to_vec();
        Ok(Some((m[..6].to_vec(), u16::from_le_bytes([m[6], m[7]]), m[8..].to_vec())))
    }

    #[test]
    fn bind_checks_the_port_and_maps_every_refusal_to_an_errno() {
        let t = Mutex::new(Table::new());
        assert_eq!(net_bind_with(ANA, &t, 0), Err(Errno::InvalidArgument));
        assert_eq!(net_bind_with(ANA, &t, 70_000), Err(Errno::InvalidArgument));
        assert_eq!(net_bind_with(ANA, &t, 100), Ok(0));
        assert_eq!(net_bind_with(EVE, &t, 100), Err(Errno::ResourceUnavailable), "ocupado");
        for p in 101..=103 {
            net_bind_with(ANA, &t, p).unwrap();
        }
        assert_eq!(net_bind_with(ANA2, &t, 104), Err(Errno::QuotaExceeded), "cuota del tenant");
    }

    #[test]
    fn a_frame_from_the_wire_reaches_only_the_owner_with_its_peer_data() {
        let (sp, t, n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        net_bind_with(EVE, &t, 200).unwrap();
        n.inbox.borrow_mut().push(wire(OURS, 55, 100, b"para ana"));
        assert_eq!(recv(&sp, &t, &n, EVE, 200), Ok(None), "eve recibe lo suyo, que no hay");
        let (mac, port, data) = recv(&sp, &t, &n, ANA, 100).unwrap().unwrap();
        assert_eq!((mac, port, data), (PEER.to_vec(), 55, b"para ana".to_vec()));
        assert_eq!(recv(&sp, &t, &n, ANA, 100), Ok(None));
    }

    #[test]
    fn a_foreign_or_unbound_port_looks_nonexistent_for_recv_send_and_unbind_and_is_audited() {
        let (sp, t, n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        assert_eq!(recv(&sp, &t, &n, EVE, 100), Err(Errno::ObjectNotFound));
        assert_eq!(recv(&sp, &t, &n, ANA2, 100), Err(Errno::ObjectNotFound), "ni otro actor del mismo tenant");
        assert_eq!(recv(&sp, &t, &n, EVE, 999), Err(Errno::ObjectNotFound), "igual que uno inexistente");
        assert_eq!(net_unbind_with(EVE, &t, 100), Err(Errno::ObjectNotFound));
        assert_eq!(send(&sp, &t, &n, EVE, 100, 5, PEER, b"suplanto"), Err(Errno::ObjectNotFound), "no se envia desde un puerto ajeno");
        assert!(n.sent.borrow().is_empty());
        let ev = audit::events_for_subject(EVE.subject_id);
        assert!(ev.iter().filter(|e| e.op == AuditOp::Net).count() >= 1, "los intentos quedan auditados");
        assert!(ev.iter().all(|e| matches!(e.outcome, audit::AuditOutcome::Denied(_))));
    }

    #[test]
    fn send_puts_a_correct_frame_on_the_wire_with_our_mac_and_the_owned_source_port() {
        let (sp, t, n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        assert_eq!(send(&sp, &t, &n, ANA, 100, 7, PEER, b"hola"), Ok(0));
        let f = n.sent.borrow()[0].clone();
        let p = netproto::parse(&f).unwrap();
        assert_eq!((p.dst_mac, p.src_mac, p.src_port, p.dst_port, p.payload), (PEER, OURS, 100, 7, &b"hola"[..]));
    }

    #[test]
    fn send_validates_sizes_and_reports_a_full_queue_as_quota() {
        let (sp, t, mut n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        assert_eq!(net_send_with(ANA, &sp, &t, &n, 100, 7, USER_MIN, 5), Err(Errno::InvalidArgument), "falta la MAC");
        assert_eq!(net_send_with(ANA, &sp, &t, &n, 100, 7, USER_MIN, (netio::SEND_MAX + 1) as u64), Err(Errno::InvalidArgument));
        assert_eq!(net_send_with(ANA, &sp, &t, &n, 0, 7, USER_MIN, 8), Err(Errno::InvalidArgument));
        assert_eq!(send(&sp, &t, &n, ANA, 100, 0, PEER, b"x"), Err(Errno::InvalidArgument));
        assert_eq!(net_send_with(ANA, &sp, &t, &n, 100, 7, 0, 8), Err(Errno::InvalidPointer));
        n.full = true;
        assert_eq!(send(&sp, &t, &n, ANA, 100, 7, PEER, b"x"), Err(Errno::QuotaExceeded));
        let down = Fake::default();
        assert_eq!(send(&sp, &t, &down, ANA, 100, 7, PEER, b"x"), Err(Errno::ResourceUnavailable), "sin `net up`");
    }

    #[test]
    fn sending_to_our_own_mac_loops_back_inside_the_kernel_under_the_same_rules() {
        let (sp, t, n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        net_bind_with(ANA2, &t, 101).unwrap();
        assert_eq!(send(&sp, &t, &n, ANA, 100, 101, OURS, b"vuelta"), Ok(0));
        assert!(n.sent.borrow().is_empty(), "no toca el dispositivo");
        let (mac, port, data) = recv(&sp, &t, &n, ANA2, 101).unwrap().unwrap();
        assert_eq!((mac, port, data), (OURS.to_vec(), 100, b"vuelta".to_vec()));
        assert_eq!(recv(&sp, &t, &n, ANA, 100), Ok(None));
        // la MAC "esta maquina" (todo ceros) hace lo mismo y el par ve nuestra MAC real
        assert_eq!(send(&sp, &t, &n, ANA, 100, 101, netio::SELF_MAC, b"otra"), Ok(0));
        let (mac, _, data) = recv(&sp, &t, &n, ANA2, 101).unwrap().unwrap();
        assert_eq!((mac, data), (OURS.to_vec(), b"otra".to_vec()));
        assert!(n.sent.borrow().is_empty());
    }

    #[test]
    fn recv_needs_a_big_enough_buffer_and_does_not_consume_a_message_it_cannot_deliver() {
        let (sp, t, n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        n.inbox.borrow_mut().push(wire(OURS, 5, 100, b"x"));
        assert_eq!(net_recv_with(ANA, &sp, &t, &n, 100, USER_MIN, (netio::RECV_MIN_BUF - 1) as u64), Err(Errno::BufferTooSmall));
        assert!(recv(&sp, &t, &n, ANA, 100).unwrap().is_some(), "el mensaje sigue ahi");
    }

    #[test]
    fn hostile_frames_are_dropped_counted_and_never_reach_anyone() {
        let (sp, t, n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        let mut bad = wire(OURS, 5, 100, b"x");
        bad[16] = 9; // version desconocida
        n.inbox.borrow_mut().extend([bad, wire([9; 6], 5, 100, b"ajena"), alloc::vec![0xAA; 70], wire(OURS, 5, 777, b"nadie")]);
        assert_eq!(recv(&sp, &t, &n, ANA, 100), Ok(None));
        let s = t.lock().stats();
        assert_eq!((s.malformed, s.wrong_mac, s.no_endpoint, s.delivered), (2, 1, 1, 0));
    }

    #[test]
    fn one_recv_processes_at_most_pump_max_frames_so_a_flood_cannot_monopolise_the_kernel() {
        let (sp, t, n) = (MockUserSpace::new(4096), Mutex::new(Table::new()), up());
        net_bind_with(ANA, &t, 100).unwrap();
        for _ in 0..100 {
            n.inbox.borrow_mut().push(wire(OURS, 5, 100, b"flood"));
        }
        recv(&sp, &t, &n, ANA, 100).unwrap();
        assert_eq!(*n.polls.borrow(), PUMP_MAX);
        assert_eq!(n.inbox.borrow().len(), 100 - PUMP_MAX);
    }
}
