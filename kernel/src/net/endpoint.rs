// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Endpoints de red (I-47): el unico lugar donde una trama recibida se convierte en un mensaje para
//! alguien, y donde se decide quien es "alguien".
//!
//! - Un endpoint es un puerto numerico ligado por un proceso. El dueno (pid, tenant, subject) lo
//!   fija el KERNEL al ligar, a partir del llamante; nada de lo que diga una trama cambia eso.
//! - Todo esta acotado: 16 endpoints en total, 4 por tenant, 8 mensajes de hasta 256 bytes por
//!   endpoint (32 KiB como maximo en toda la tabla). Lo que no cabe se descarta y se cuenta; la red
//!   no puede hacer crecer la memoria del kernel.
//! - Recibir y desligar solo puede hacerlo el dueno. Un puerto ajeno es indistinguible de uno
//!   inexistente (`NotFound`): no se revela quien tiene que.
//! - Cuando el dueno muere, o su tenant se corta (`tenant panic`), sus endpoints se cierran y su cola
//!   se descarta (`close_pid`, `close_tenant`).
//! - `peer_mac` y `peer_port` de un mensaje son datos del otro extremo, sin autenticar: sirven para
//!   responder, nunca para decidir permisos (I-09).
//!
//! Logica pura: el parser (`abi::netproto`) y el hardware (`nic`) estan fuera.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use trunomy_abi::netproto::{self, ParseError, Parsed};

pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_PER_TENANT: usize = 4;
pub const QUEUE_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub pid: u64,
    pub tenant: u64,
    pub subject: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Datos del par, sin autenticar.
    pub peer_mac: [u8; 6],
    pub peer_port: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    ZeroPort,
    InUse,
    /// 16 endpoints en total.
    TableFull,
    /// El tenant ya tiene `MAX_PER_TENANT`.
    TenantQuota,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    /// No existe, o no es tuyo: no se distingue.
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Queued,
    /// Ningun endpoint ligado a ese puerto.
    NoEndpoint,
    /// El endpoint existe pero su cola esta llena: se descarta.
    QueueFull,
}

/// Que paso con una trama cruda que llego del dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    Queued,
    /// No es una trama del protocolo (o esta mal formada): se descarta.
    Malformed(ParseError),
    /// No va dirigida a esta maquina (ni difusion).
    WrongMac,
    NoEndpoint,
    QueueFull,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TableStats {
    pub delivered: u64,
    pub no_endpoint: u64,
    pub queue_full: u64,
    pub malformed: u64,
    pub wrong_mac: u64,
}

impl TableStats {
    /// Tramas recibidas del cable y descartadas por el protocolo (todo lo que no llego a un dueno).
    pub fn dropped(&self) -> u64 {
        self.no_endpoint + self.queue_full + self.malformed + self.wrong_mac
    }
}

struct Endpoint {
    port: u16,
    owner: Owner,
    queue: VecDeque<Message>,
}

pub struct Table {
    eps: Vec<Endpoint>,
    stats: TableStats,
}

impl Table {
    pub const fn new() -> Self {
        Table { eps: Vec::new(), stats: TableStats { delivered: 0, no_endpoint: 0, queue_full: 0, malformed: 0, wrong_mac: 0 } }
    }

    pub fn stats(&self) -> TableStats {
        self.stats
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.eps.len()
    }

    pub fn count_for_tenant(&self, tenant: u64) -> usize {
        self.eps.iter().filter(|e| e.owner.tenant == tenant).count()
    }

    pub fn bind(&mut self, port: u16, owner: Owner) -> Result<(), BindError> {
        if port == 0 {
            return Err(BindError::ZeroPort);
        }
        if self.eps.iter().any(|e| e.port == port) {
            return Err(BindError::InUse);
        }
        if self.eps.len() >= MAX_ENDPOINTS {
            return Err(BindError::TableFull);
        }
        if self.count_for_tenant(owner.tenant) >= MAX_PER_TENANT {
            return Err(BindError::TenantQuota);
        }
        self.eps.push(Endpoint { port, owner, queue: VecDeque::new() });
        Ok(())
    }

    fn index_owned(&self, port: u16, pid: u64) -> Result<usize, AccessError> {
        self.eps.iter().position(|e| e.port == port && e.owner.pid == pid).ok_or(AccessError::NotFound)
    }

    /// El proceso `pid` es el dueno de `port` (para autorizar un envio desde ese puerto).
    pub fn owns(&self, port: u16, pid: u64) -> bool {
        self.index_owned(port, pid).is_ok()
    }

    pub fn unbind(&mut self, port: u16, pid: u64) -> Result<(), AccessError> {
        let i = self.index_owned(port, pid)?;
        self.eps.remove(i);
        Ok(())
    }

    /// Entrega una trama ya parseada al endpoint de su puerto destino. Copia la carga util (el buffer de
    /// recepcion se reutiliza); nunca crece mas alla de `QUEUE_DEPTH` por endpoint.
    pub fn deliver(&mut self, p: &Parsed) -> Delivery {
        let Some(e) = self.eps.iter_mut().find(|e| e.port == p.dst_port) else {
            self.stats.no_endpoint += 1;
            return Delivery::NoEndpoint;
        };
        if e.queue.len() >= QUEUE_DEPTH {
            self.stats.queue_full += 1;
            return Delivery::QueueFull;
        }
        e.queue.push_back(Message { peer_mac: p.src_mac, peer_port: p.src_port, data: p.payload.to_vec() });
        self.stats.delivered += 1;
        Delivery::Queued
    }

    /// Una trama cruda del dispositivo: la analiza, comprueba que va para `our_mac` (o difusion) y la
    /// entrega. Todo lo que no llega a un dueno se descarta y se cuenta.
    pub fn deliver_frame(&mut self, frame: &[u8], our_mac: [u8; 6]) -> Fate {
        let p = match netproto::parse(frame) {
            Ok(p) => p,
            Err(e) => {
                self.stats.malformed += 1;
                return Fate::Malformed(e);
            }
        };
        if p.dst_mac != our_mac && p.dst_mac != netproto::BROADCAST {
            self.stats.wrong_mac += 1;
            return Fate::WrongMac;
        }
        match self.deliver(&p) {
            Delivery::Queued => Fate::Queued,
            Delivery::NoEndpoint => Fate::NoEndpoint,
            Delivery::QueueFull => Fate::QueueFull,
        }
    }

    pub fn recv(&mut self, port: u16, pid: u64) -> Result<Option<Message>, AccessError> {
        let i = self.index_owned(port, pid)?;
        Ok(self.eps[i].queue.pop_front())
    }

    /// El proceso murio: cierra sus endpoints y descarta sus colas. Devuelve cuantos cerro.
    pub fn close_pid(&mut self, pid: u64) -> usize {
        let before = self.eps.len();
        self.eps.retain(|e| e.owner.pid != pid);
        before - self.eps.len()
    }

    /// El tenant se corto (`tenant panic`): cierra todos sus endpoints.
    pub fn close_tenant(&mut self, tenant: u64) -> usize {
        let before = self.eps.len();
        self.eps.retain(|e| e.owner.tenant != tenant);
        before - self.eps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trunomy_abi::netproto::{build, parse, MAX_FRAME_LEN};

    const ANA: Owner = Owner { pid: 1001, tenant: 10, subject: 1001 };
    const ANA2: Owner = Owner { pid: 1002, tenant: 10, subject: 1002 };
    const EVE: Owner = Owner { pid: 2001, tenant: 20, subject: 2001 };
    const PEER: [u8; 6] = [2, 0, 0, 0, 0, 9];

    fn deliver(t: &mut Table, dst: u16, payload: &[u8]) -> Delivery {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = build(&mut buf, [1; 6], PEER, 77, dst, payload).unwrap();
        t.deliver(&parse(&buf[..n]).unwrap())
    }

    #[test]
    fn a_frame_reaches_only_the_owner_of_the_destination_port() {
        let mut t = Table::new();
        t.bind(100, ANA).unwrap();
        t.bind(200, EVE).unwrap();
        assert_eq!(deliver(&mut t, 100, b"para ana"), Delivery::Queued);
        assert_eq!(t.recv(200, EVE.pid), Ok(None), "eve no recibe lo de ana");
        let m = t.recv(100, ANA.pid).unwrap().unwrap();
        assert_eq!((m.data.as_slice(), m.peer_port, m.peer_mac), (&b"para ana"[..], 77, PEER));
        assert_eq!(t.recv(100, ANA.pid), Ok(None));
    }

    #[test]
    fn only_the_owner_can_receive_or_unbind_and_a_foreign_port_looks_nonexistent() {
        let mut t = Table::new();
        t.bind(100, ANA).unwrap();
        deliver(&mut t, 100, b"x");
        assert_eq!(t.recv(100, EVE.pid), Err(AccessError::NotFound));
        assert_eq!(t.recv(100, ANA2.pid), Err(AccessError::NotFound), "ni siquiera otro proceso del mismo tenant");
        assert_eq!(t.recv(555, ANA.pid), Err(AccessError::NotFound), "igual que uno inexistente");
        assert_eq!(t.unbind(100, EVE.pid), Err(AccessError::NotFound));
        assert!(!t.owns(100, EVE.pid) && t.owns(100, ANA.pid));
        assert_eq!(t.unbind(100, ANA.pid), Ok(()));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn binding_is_exclusive_and_bounded_globally_and_per_tenant() {
        let mut t = Table::new();
        assert_eq!(t.bind(0, ANA), Err(BindError::ZeroPort));
        t.bind(100, ANA).unwrap();
        assert_eq!(t.bind(100, EVE), Err(BindError::InUse), "nadie le quita el puerto");
        for p in 101..=103 {
            t.bind(p, ANA).unwrap();
        }
        assert_eq!(t.bind(104, ANA2), Err(BindError::TenantQuota), "el tenant ya tiene 4");
        assert_eq!(t.bind(104, EVE), Ok(()), "otro tenant no se ve afectado");
        let mut t = Table::new();
        for i in 0..MAX_ENDPOINTS as u64 {
            t.bind(1 + i as u16, Owner { pid: 5000 + i, tenant: 5000 + i, subject: 5000 + i }).unwrap();
        }
        assert_eq!(t.bind(999, EVE), Err(BindError::TableFull));
    }

    #[test]
    fn queues_are_bounded_and_the_excess_is_dropped_and_counted() {
        let mut t = Table::new();
        t.bind(100, ANA).unwrap();
        for i in 0..QUEUE_DEPTH {
            assert_eq!(deliver(&mut t, 100, &[i as u8]), Delivery::Queued);
        }
        assert_eq!(deliver(&mut t, 100, b"de mas"), Delivery::QueueFull);
        assert_eq!(deliver(&mut t, 999, b"a nadie"), Delivery::NoEndpoint);
        let s = t.stats();
        assert_eq!((s.delivered, s.queue_full, s.no_endpoint), (QUEUE_DEPTH as u64, 1, 1));
        // en orden, y al vaciar vuelve a caber
        for i in 0..QUEUE_DEPTH {
            assert_eq!(t.recv(100, ANA.pid).unwrap().unwrap().data, alloc::vec![i as u8]);
        }
        assert_eq!(deliver(&mut t, 100, b"ya cabe"), Delivery::Queued);
    }

    #[test]
    fn raw_frames_are_parsed_filtered_by_mac_and_counted_when_dropped() {
        let ours = [1u8; 6];
        let mut t = Table::new();
        t.bind(100, ANA).unwrap();
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = build(&mut buf, ours, PEER, 5, 100, b"hola").unwrap();
        assert_eq!(t.deliver_frame(&buf[..n], ours), Fate::Queued);
        let n = build(&mut buf, netproto::BROADCAST, PEER, 5, 100, b"todos").unwrap();
        assert_eq!(t.deliver_frame(&buf[..n], ours), Fate::Queued, "la difusion tambien");
        let n = build(&mut buf, [9; 6], PEER, 5, 100, b"ajena").unwrap();
        assert_eq!(t.deliver_frame(&buf[..n], ours), Fate::WrongMac);
        assert_eq!(t.deliver_frame(&[0u8; 5], ours), Fate::Malformed(ParseError::TooShort));
        assert_eq!(t.deliver_frame(&[0x55u8; 70], ours), Fate::Malformed(ParseError::WrongEthertype), "p. ej. un ARP o IPv4 ajenos");
        let n = build(&mut buf, ours, PEER, 5, 777, b"x").unwrap();
        assert_eq!(t.deliver_frame(&buf[..n], ours), Fate::NoEndpoint);
        let s = t.stats();
        assert_eq!((s.delivered, s.wrong_mac, s.malformed, s.no_endpoint, s.dropped()), (2, 1, 2, 1, 4));
    }

    #[test]
    fn a_flooding_peer_cannot_starve_another_endpoint() {
        let mut t = Table::new();
        t.bind(100, ANA).unwrap();
        t.bind(200, EVE).unwrap();
        for _ in 0..1000 {
            deliver(&mut t, 100, b"flood");
        }
        assert_eq!(deliver(&mut t, 200, b"legitimo"), Delivery::Queued, "la cola llena de uno no afecta a otro");
    }

    #[test]
    fn closing_by_pid_or_tenant_removes_endpoints_and_discards_queued_messages() {
        let mut t = Table::new();
        t.bind(100, ANA).unwrap();
        t.bind(101, ANA2).unwrap();
        t.bind(200, EVE).unwrap();
        deliver(&mut t, 100, b"secreto");
        assert_eq!(t.close_pid(ANA.pid), 1);
        assert_eq!(deliver(&mut t, 100, b"x"), Delivery::NoEndpoint, "el endpoint ya no existe");
        // otro proceso liga el mismo puerto: no hereda nada
        t.bind(100, ANA2).unwrap();
        assert_eq!(t.recv(100, ANA2.pid), Ok(None), "la cola anterior se descarto");
        assert_eq!(t.close_tenant(10), 2);
        assert_eq!(t.count_for_tenant(10), 0);
        assert_eq!(t.len(), 1, "el tenant ajeno sigue intacto");
        assert_eq!(t.close_tenant(10), 0, "idempotente");
    }
}
