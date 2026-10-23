// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Red de los actores (I-47): ligar un puerto, enviar y recibir tramas del protocolo de Trunomy.
//! Contrato: `trunomy_abi::netio` y kernel/src/syscall/netio.rs. Todas exigen una capability global
//! (el usuario se crea con `net`); sin ella el kernel responde `InvalidCapability` y lo audita.

use crate::{decode, syscall4, Errno, SyscallNumber};
use trunomy_abi::netio;

pub fn bind(port: u16) -> Result<(), Errno> {
    decode(unsafe { syscall4(SyscallNumber::NetBind.number(), port as u64, 0, 0, 0) }).map(|_| ())
}

pub fn unbind(port: u16) -> Result<(), Errno> {
    decode(unsafe { syscall4(SyscallNumber::NetUnbind.number(), port as u64, 0, 0, 0) }).map(|_| ())
}

/// Envia `payload` (como mucho `netproto::MAX_PAYLOAD`) a `dst_mac`:`dst_port` desde `src_port`, que
/// debe ser tuyo. `netio::SELF_MAC` = esta maquina.
pub fn send(src_port: u16, dst_port: u16, dst_mac: [u8; 6], payload: &[u8]) -> Result<(), Errno> {
    let mut buf = [0u8; netio::SEND_MAX];
    if payload.len() > trunomy_abi::netproto::MAX_PAYLOAD {
        return Err(Errno::InvalidArgument);
    }
    buf[..6].copy_from_slice(&dst_mac);
    buf[6..6 + payload.len()].copy_from_slice(payload);
    decode(unsafe {
        syscall4(SyscallNumber::NetSend.number(), src_port as u64, dst_port as u64, buf.as_ptr() as u64, (6 + payload.len()) as u64)
    })
    .map(|_| ())
}

/// Un mensaje recibido. `peer_mac` y `peer_port` son datos del otro extremo SIN autenticar.
pub struct Received {
    pub peer_mac: [u8; 6],
    pub peer_port: u16,
    len: usize,
    buf: [u8; trunomy_abi::netproto::MAX_PAYLOAD],
}

impl Received {
    pub fn payload(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// `Ok(None)` si no hay mensaje.
pub fn recv(port: u16) -> Result<Option<Received>, Errno> {
    let mut raw = [0u8; netio::RECV_MIN_BUF];
    let n = decode(unsafe { syscall4(SyscallNumber::NetRecv.number(), port as u64, raw.as_mut_ptr() as u64, raw.len() as u64, 0) })? as usize;
    if n == 0 {
        return Ok(None);
    }
    if n < netio::RECV_HEADER || n > raw.len() {
        return Err(Errno::InvalidArgument);
    }
    let mut peer_mac = [0u8; 6];
    peer_mac.copy_from_slice(&raw[..6]);
    let len = n - netio::RECV_HEADER;
    let mut buf = [0u8; trunomy_abi::netproto::MAX_PAYLOAD];
    buf[..len].copy_from_slice(&raw[netio::RECV_HEADER..n]);
    Ok(Some(Received { peer_mac, peer_port: u16::from_le_bytes([raw[6], raw[7]]), len, buf }))
}
