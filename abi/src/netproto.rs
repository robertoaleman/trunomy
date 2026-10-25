// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Protocolo de tramas de Trunomy sobre Ethernet (EtherType 0x88B5, el de uso experimental local).
//!
//! No es TCP/IP: es lo minimo para que dos VMs (o una VM y un script del host) intercambien mensajes
//! entre ENDPOINTS. Un mensaje por trama:
//!
//! ```text
//!  0..6   MAC destino      6..12  MAC origen      12..14  EtherType 0x88B5
//! 14..16  magia 'T','N'    16     version (1)     17      tipo (1 = datos)
//! 18..20  puerto origen    20..22 puerto destino  22..24  largo (todo en big endian)
//! 24..    carga util (`largo` bytes, como mucho `MAX_PAYLOAD`), luego relleno de ceros hasta 60
//! ```
//!
//! Reglas (I-09, I-47): TODO lo que llega por la red es hostil. El parser es total (nunca entra en
//! panico, nunca lee fuera de la trama) y estricto: rechaza magia o version desconocidas, puertos
//! cero, largos que no caben, y relleno que no sea cero (nada se esconde tras la carga util). Los
//! campos de la trama (puertos, MAC) son datos del par: el kernel NUNCA los usa como identidad de
//! nadie; quien es el dueno de un endpoint lo dice la tabla del kernel, no la red.
//! Sin dependencias, `no_std`, probado en el host.

pub const ETHERTYPE: u16 = 0x88B5;
pub const MAGIC: [u8; 2] = *b"TN";
pub const VERSION: u8 = 1;
pub const KIND_DATA: u8 = 1;
pub const ETH_HEADER: usize = 14;
pub const HEADER_LEN: usize = 24;
/// Carga util maxima: acotada para que ninguna cola del kernel crezca con la red.
pub const MAX_PAYLOAD: usize = 256;
/// Largo minimo de una trama Ethernet sin FCS: se rellena con ceros.
pub const MIN_FRAME: usize = 60;
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD;
pub const BROADCAST: [u8; 6] = [0xFF; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    WrongEthertype,
    BadMagic,
    BadVersion,
    BadKind,
    ZeroPort,
    /// El largo declarado supera `MAX_PAYLOAD`.
    TooLong,
    /// El largo declarado no cabe en la trama recibida.
    Truncated,
    /// Tras la carga util hay bytes distintos de cero.
    DirtyPadding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    ZeroPort,
    TooLong,
    /// `out` no tiene espacio para la trama.
    OutTooSmall,
}

/// Una trama valida, mirando dentro del buffer recibido. Todo es dato del par, no identidad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse(frame: &[u8]) -> Result<Parsed<'_>, ParseError> {
    if frame.len() < HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    if frame[12..14] != ETHERTYPE.to_be_bytes() {
        return Err(ParseError::WrongEthertype);
    }
    if frame[14..16] != MAGIC {
        return Err(ParseError::BadMagic);
    }
    if frame[16] != VERSION {
        return Err(ParseError::BadVersion);
    }
    if frame[17] != KIND_DATA {
        return Err(ParseError::BadKind);
    }
    let src_port = u16::from_be_bytes([frame[18], frame[19]]);
    let dst_port = u16::from_be_bytes([frame[20], frame[21]]);
    if src_port == 0 || dst_port == 0 {
        return Err(ParseError::ZeroPort);
    }
    let len = u16::from_be_bytes([frame[22], frame[23]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(ParseError::TooLong);
    }
    let end = HEADER_LEN + len;
    if end > frame.len() {
        return Err(ParseError::Truncated);
    }
    if frame[end..].iter().any(|b| *b != 0) {
        return Err(ParseError::DirtyPadding);
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    src_mac.copy_from_slice(&frame[6..12]);
    Ok(Parsed { dst_mac, src_mac, src_port, dst_port, payload: &frame[HEADER_LEN..end] })
}

/// Escribe una trama en `out` (rellenada con ceros hasta `MIN_FRAME`) y devuelve su largo.
pub fn build(out: &mut [u8], dst_mac: [u8; 6], src_mac: [u8; 6], src_port: u16, dst_port: u16, payload: &[u8]) -> Result<usize, BuildError> {
    if src_port == 0 || dst_port == 0 {
        return Err(BuildError::ZeroPort);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(BuildError::TooLong);
    }
    let total = (HEADER_LEN + payload.len()).max(MIN_FRAME);
    if out.len() < total {
        return Err(BuildError::OutTooSmall);
    }
    out[..total].fill(0);
    out[0..6].copy_from_slice(&dst_mac);
    out[6..12].copy_from_slice(&src_mac);
    out[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
    out[14..16].copy_from_slice(&MAGIC);
    out[16] = VERSION;
    out[17] = KIND_DATA;
    out[18..20].copy_from_slice(&src_port.to_be_bytes());
    out[20..22].copy_from_slice(&dst_port.to_be_bytes());
    out[22..24].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const B: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x57];

    /// El mismo vector que `GOLDEN_HEX` en scripts/nettest.py (segunda implementacion, escrita desde la
    /// especificacion): `ci.sh nettest` comprueba que ambas constantes son identicas.
    const GOLDEN_HEX: &str = "52540012345752540012345688b5544e0101000700090004686f6c610000000000000000000000000000000000000000000000000000000000000000";

    fn frame(payload: &[u8]) -> ([u8; MAX_FRAME_LEN], usize) {
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = build(&mut buf, B, A, 7, 9, payload).unwrap();
        (buf, n)
    }

    fn unhex(h: &str) -> [u8; MIN_FRAME] {
        let mut out = [0u8; MIN_FRAME];
        assert_eq!(h.len(), 2 * MIN_FRAME);
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn golden_vector_matches_the_python_harness() {
        let golden = unhex(GOLDEN_HEX);
        let (buf, n) = frame(b"hola");
        assert_eq!(&buf[..n], &golden[..], "build() no produce el vector fijo");
        // `frame` usa B como destino y A como origen, puertos 7 -> 9, igual que el script.
        let p = parse(&golden).unwrap();
        assert_eq!((p.dst_mac, p.src_mac, p.src_port, p.dst_port, p.payload), (B, A, 7, 9, &b"hola"[..]));
    }

    #[test]
    fn a_built_frame_parses_back_exactly_and_is_padded_to_the_ethernet_minimum() {
        let (buf, n) = frame(b"hola");
        assert_eq!(n, MIN_FRAME);
        let p = parse(&buf[..n]).unwrap();
        assert_eq!((p.dst_mac, p.src_mac, p.src_port, p.dst_port, p.payload), (B, A, 7, 9, &b"hola"[..]));
    }

    #[test]
    fn empty_and_maximum_payloads_round_trip() {
        let (buf, n) = frame(b"");
        assert_eq!(parse(&buf[..n]).unwrap().payload, b"");
        let big = [0xABu8; MAX_PAYLOAD];
        let (buf, n) = frame(&big);
        assert_eq!(n, MAX_FRAME_LEN);
        assert_eq!(parse(&buf[..n]).unwrap().payload, &big[..]);
    }

    #[test]
    fn build_refuses_what_parse_would_refuse() {
        let mut buf = [0u8; MAX_FRAME_LEN];
        assert_eq!(build(&mut buf, B, A, 0, 9, b"x"), Err(BuildError::ZeroPort));
        assert_eq!(build(&mut buf, B, A, 7, 0, b"x"), Err(BuildError::ZeroPort));
        assert_eq!(build(&mut buf, B, A, 7, 9, &[0u8; MAX_PAYLOAD + 1]), Err(BuildError::TooLong));
        assert_eq!(build(&mut buf[..30], B, A, 7, 9, b"x"), Err(BuildError::OutTooSmall));
    }

    #[test]
    fn every_header_field_is_checked() {
        let (good, n) = frame(b"abc");
        let mutate = |i: usize, v: u8| {
            let mut f = good;
            f[i] = v;
            f
        };
        assert_eq!(parse(&mutate(12, 0x08)[..n]), Err(ParseError::WrongEthertype));
        assert_eq!(parse(&mutate(14, b'X')[..n]), Err(ParseError::BadMagic));
        assert_eq!(parse(&mutate(15, b'X')[..n]), Err(ParseError::BadMagic));
        assert_eq!(parse(&mutate(16, 2)[..n]), Err(ParseError::BadVersion));
        assert_eq!(parse(&mutate(17, 2)[..n]), Err(ParseError::BadKind));
        let mut z = good;
        z[18] = 0;
        z[19] = 0;
        assert_eq!(parse(&z[..n]), Err(ParseError::ZeroPort));
        let mut z = good;
        z[20] = 0;
        z[21] = 0;
        assert_eq!(parse(&z[..n]), Err(ParseError::ZeroPort));
    }

    #[test]
    fn a_length_that_does_not_fit_or_is_too_big_is_refused() {
        let (good, n) = frame(b"abc");
        let mut f = good;
        f[22..24].copy_from_slice(&((MAX_PAYLOAD + 1) as u16).to_be_bytes());
        assert_eq!(parse(&f[..n]), Err(ParseError::TooLong));
        f[22..24].copy_from_slice(&((n - HEADER_LEN + 1) as u16).to_be_bytes());
        assert_eq!(parse(&f[..n]), Err(ParseError::Truncated), "declara un byte mas de los que hay");
        f[22..24].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(parse(&f[..n]), Err(ParseError::TooLong));
    }

    #[test]
    fn nothing_hides_after_the_payload() {
        let (good, n) = frame(b"abc");
        let mut f = good;
        f[n - 1] = 1;
        assert_eq!(parse(&f[..n]), Err(ParseError::DirtyPadding));
        // un largo menor que el real deja bytes de carga como "relleno": tambien se rechaza
        let mut f = good;
        f[22..24].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(parse(&f[..n]), Err(ParseError::DirtyPadding));
    }

    #[test]
    fn every_truncation_of_a_valid_frame_is_an_error_or_a_consistent_parse_and_never_a_panic() {
        let (good, n) = frame(&[7u8; 40]);
        for cut in 0..=n {
            match parse(&good[..cut]) {
                Ok(p) => assert!(cut >= HEADER_LEN + p.payload.len()),
                Err(e) => assert!(matches!(e, ParseError::TooShort | ParseError::Truncated)),
            }
        }
    }

    #[test]
    fn deterministic_garbage_never_panics_and_only_valid_frames_parse() {
        // xorshift: sin dependencias, reproducible
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut parsed = 0;
        for _ in 0..20_000 {
            let len = (next() % 80) as usize;
            let mut f = [0u8; 80];
            for b in f.iter_mut() {
                *b = next() as u8;
            }
            // a veces, un encabezado casi valido para que el parser llegue lejos
            if next() % 2 == 0 && len >= HEADER_LEN {
                f[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
                f[14..16].copy_from_slice(&MAGIC);
                f[16] = VERSION;
                f[17] = KIND_DATA;
                f[22] = 0;
                f[23] = (next() % 60) as u8;
            }
            if let Ok(p) = parse(&f[..len]) {
                parsed += 1;
                assert!(p.src_port != 0 && p.dst_port != 0 && p.payload.len() <= MAX_PAYLOAD);
                assert!(f[HEADER_LEN + p.payload.len()..len].iter().all(|b| *b == 0));
            }
        }
        assert!(parsed > 0, "la prueba debe alcanzar tramas validas");
    }
}
