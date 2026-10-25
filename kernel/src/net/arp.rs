// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Autocomprobacion de la red con un ARP real (QEMU `-netdev user`: el gateway 10.0.2.2 responde).
//! Es lo unico que prueba, de extremo a extremo, que el dispositivo recibe y entrega tramas.
//! Logica pura: la trama se construye y se reconoce aqui; el envio y la espera usan `Nic`.

use super::io::Io;
use super::nic::{DmaHost, Nic, RecvError, SendError};

pub const OUR_IP: [u8; 4] = [10, 0, 2, 15];
pub const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const FRAME_LEN: usize = 60; // minimo Ethernet sin FCS

/// ARP "quien tiene `target`" en difusion.
pub fn request(mac: [u8; 6], sender: [u8; 4], target: [u8; 4]) -> [u8; FRAME_LEN] {
    let mut f = [0u8; FRAME_LEN];
    f[0..6].copy_from_slice(&[0xFF; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ETHERTYPE_ARP);
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]); // Ethernet, IPv4, hlen 6, plen 4, peticion
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&sender);
    f[38..42].copy_from_slice(&target);
    f
}

/// Si `frame` es la respuesta ARP de `from_ip` dirigida a `our_mac`, devuelve la MAC de quien responde.
pub fn reply_from(frame: &[u8], from_ip: [u8; 4], our_mac: [u8; 6]) -> Option<[u8; 6]> {
    if frame.len() < 42 || frame[12..14] != ETHERTYPE_ARP || frame[14..20] != [0, 1, 8, 0, 6, 4] || frame[20..22] != [0, 2] {
        return None;
    }
    if frame[28..32] != from_ip || frame[32..38] != our_mac || frame[0..6] != our_mac {
        return None;
    }
    let mut peer = [0u8; 6];
    peer.copy_from_slice(&frame[22..28]);
    Some(peer)
}

#[derive(Debug, PartialEq, Eq)]
pub enum SelftestError {
    Send(SendError),
    Recv(RecvError),
}

/// Envia el ARP y sondea hasta `max_polls` veces. `Ok(Some(mac))` = respondio el gateway.
pub fn selftest<I: Io, H: DmaHost>(nic: &mut Nic<H>, io: &mut I, mac: [u8; 6], max_polls: u32) -> Result<Option<[u8; 6]>, SelftestError> {
    nic.send(io, &request(mac, OUR_IP, GATEWAY_IP)).map_err(SelftestError::Send)?;
    for _ in 0..max_polls {
        match nic.recv(io).map_err(SelftestError::Recv)? {
            Some(f) => {
                if let Some(peer) = reply_from(&f, GATEWAY_IP, mac) {
                    return Ok(Some(peer));
                }
            }
            None => core::hint::spin_loop(),
        }
    }
    Ok(None)
}

/// Respuesta ARP que un gateway honesto daria a `req` (para las pruebas).
#[cfg(test)]
pub fn answer(req: &[u8], gateway_mac: [u8; 6]) -> Option<alloc::vec::Vec<u8>> {
    if req.len() < 42 || req[12..14] != ETHERTYPE_ARP || req[20..22] != [0, 1] {
        return None;
    }
    let mut r = req.to_vec();
    r[0..6].copy_from_slice(&req[6..12]);
    r[6..12].copy_from_slice(&gateway_mac);
    r[20..22].copy_from_slice(&[0, 2]);
    r[22..28].copy_from_slice(&gateway_mac);
    r[28..32].copy_from_slice(&req[38..42]);
    r[32..38].copy_from_slice(&req[22..28]);
    r[38..42].copy_from_slice(&req[28..32]);
    Some(r)
}
