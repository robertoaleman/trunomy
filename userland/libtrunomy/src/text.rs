// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Utilidades de texto sin asignaciones, comprobables en el host.

use trunomy_abi::rights;

/// "READ,WRITE" / "read+delegate" -> mascara de derechos. None si hay un nombre desconocido o esta vacio.
/// (No usa '|': el shell lo reserva para pipelines.)
pub fn parse_rights(s: &[u8]) -> Option<u64> {
    let mut mask = 0u64;
    let mut any = false;
    for part in s.split(|b| *b == b',' || *b == b'+') {
        let bit = if eq_ci(part, b"read") {
            rights::READ
        } else if eq_ci(part, b"write") {
            rights::WRITE
        } else if eq_ci(part, b"send") {
            rights::SEND
        } else if eq_ci(part, b"receive") {
            rights::RECEIVE
        } else if eq_ci(part, b"delegate") {
            rights::DELEGATE
        } else {
            return None;
        };
        mask |= bit;
        any = true;
    }
    any.then_some(mask)
}

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_lowercase() == *y)
}

pub fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

/// Escribe `v` en decimal al final de `buf`; devuelve el trozo usado.
pub fn format_u64(mut v: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

pub fn format_hex(v: u64, buf: &mut [u8; 16]) -> &[u8] {
    const D: &[u8; 16] = b"0123456789abcdef";
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = D[((v >> (60 - 4 * i)) & 0xF) as usize];
    }
    &buf[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_parse() {
        assert_eq!(parse_rights(b"READ"), Some(rights::READ));
        assert_eq!(parse_rights(b"read,Write"), Some(rights::READ | rights::WRITE));
        assert_eq!(parse_rights(b"read+delegate"), Some(rights::READ | rights::DELEGATE));
        assert_eq!(parse_rights(b""), None);
        assert_eq!(parse_rights(b"read,"), None);
        assert_eq!(parse_rights(b"root"), None);
    }

    #[test]
    fn numbers_round_trip() {
        assert_eq!(parse_u64(b"1000"), Some(1000));
        assert_eq!(parse_u64(b"12a"), None);
        assert_eq!(parse_u64(b"99999999999999999999999"), None);
        let mut b = [0u8; 20];
        assert_eq!(format_u64(0, &mut b), b"0");
        let mut b = [0u8; 20];
        assert_eq!(format_u64(u64::MAX, &mut b), b"18446744073709551615");
        let mut h = [0u8; 16];
        assert_eq!(format_hex(0x1_0000_0002, &mut h), b"0000000100000002");
    }
}
