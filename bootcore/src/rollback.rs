// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Proteccion contra rollback del kernel (I-49): una imagen firmada pero ANTIGUA no debe arrancar.
//!
//! La firma sola no basta: un kernel viejo con una vulnerabilidad ya corregida sigue teniendo una firma
//! valida. Por eso cada kernel lleva una VERSION DE SEGURIDAD (`config/security-version`, un entero que se
//! sube a proposito al publicar una correccion, no un numero de compilacion) y esa version va DENTRO del
//! mensaje firmado:
//!
//! ```text
//! firma = Ed25519( IMAGE_DOMAIN || version (u64, little endian) || ELF del kernel )
//! kernel_x86_64.elf.ver = version (8 bytes)     kernel_x86_64.elf.sig = firma (64 bytes)
//! ```
//!
//! El bootloader guarda en una variable UEFI no volatil el MAYOR numero aceptado y se niega a arrancar una
//! version menor. Orden de operaciones (probado aqui): primero se verifica la firma, y solo despues se compara
//! y se sube el contador; si se subiera con una version sin firmar, cualquiera con acceso al disco podria
//! dejar la maquina sin arrancar escribiendo un numero alto.
//!
//! Limite honesto: un contador en NVRAM de firmware sin hardware dedicado (TPM, RPMB) lo puede borrar quien
//! escriba en el NVRAM; protege contra restaurar un kernel viejo en el DISCO, no contra control del firmware.
//! Todo esto es logica pura (sin UEFI): se prueba en el host.

use crate::sig::{verify_detached, VerifyError};
use alloc::vec::Vec;

/// Separador de dominio del mensaje firmado: una firma de otra cosa (la shell, un archivo cualquiera)
/// nunca puede pasar por la de un kernel.
pub const IMAGE_DOMAIN: &[u8; 24] = b"TRUNOMY-KERNEL-IMAGE-v2\0";
/// Tamano de `kernel_x86_64.elf.ver` y de la variable UEFI del contador.
pub const VERSION_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackError {
    /// `kernel_x86_64.elf.ver` no mide exactamente 8 bytes.
    BadVersionFile,
    /// La version 0 no existe (los kernels empiezan en 1).
    ZeroVersion,
    /// La variable del contador no mide exactamente 8 bytes: esta corrupta o la tocaron.
    BadCounter,
    /// La firma no cubre este ELF con esta version.
    Signature(VerifyError),
    /// El kernel es mas antiguo que el minimo ya aceptado.
    Rollback { version: u64, minimum: u64 },
}

impl RollbackError {
    pub fn as_str(self) -> &'static str {
        match self {
            RollbackError::BadVersionFile => "kernel_x86_64.elf.ver is not 8 bytes long",
            RollbackError::ZeroVersion => "security version 0 is not valid",
            RollbackError::BadCounter => "the NVRAM version counter is corrupt (not 8 bytes long)",
            RollbackError::Signature(e) => e.as_str(),
            RollbackError::Rollback { .. } => "kernel older than the minimum already accepted (rollback)",
        }
    }
}

/// Lo que hay que hacer con un kernel cuya firma ya es valida.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Arrancar; si `ratchet` es `Some(v)`, guardar `v` como nuevo minimo.
    Accept { ratchet: Option<u64> },
    /// No arrancar: `version < minimum`.
    Rollback { minimum: u64 },
}

pub fn parse_version(bytes: &[u8]) -> Result<u64, RollbackError> {
    let raw: [u8; VERSION_LEN] = bytes.try_into().map_err(|_| RollbackError::BadVersionFile)?;
    match u64::from_le_bytes(raw) {
        0 => Err(RollbackError::ZeroVersion),
        v => Ok(v),
    }
}

pub fn encode_counter(version: u64) -> [u8; VERSION_LEN] {
    version.to_le_bytes()
}

pub fn decode_counter(bytes: &[u8]) -> Result<u64, RollbackError> {
    let raw: [u8; VERSION_LEN] = bytes.try_into().map_err(|_| RollbackError::BadCounter)?;
    Ok(u64::from_le_bytes(raw))
}

/// El mensaje exacto que se firma (y que `build_os.sh` firma con openssl): dominio, version y ELF.
pub fn signed_message(version: u64, elf: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(IMAGE_DOMAIN.len() + VERSION_LEN + elf.len());
    m.extend_from_slice(IMAGE_DOMAIN);
    m.extend_from_slice(&version.to_le_bytes());
    m.extend_from_slice(elf);
    m
}

/// Verifica la firma de un kernel con su version.
pub fn verify_kernel(elf: &[u8], sig: &[u8], version: u64, key: &[u8; 32]) -> Result<(), VerifyError> {
    verify_detached(&signed_message(version, elf), sig, key)
}

/// Compara una version YA VERIFICADA con el minimo guardado (`None` = primer arranque).
pub fn decide(stored: Option<u64>, version: u64) -> Decision {
    match stored {
        None => Decision::Accept { ratchet: Some(version) },
        Some(minimum) if version < minimum => Decision::Rollback { minimum },
        Some(minimum) if version == minimum => Decision::Accept { ratchet: None },
        Some(_) => Decision::Accept { ratchet: Some(version) },
    }
}

/// Todo el camino del bootloader, en el orden que importa: lee la version, VERIFICA la firma y solo entonces
/// decide contra el contador guardado. Devuelve la version aceptada y que hacer con el contador.
pub fn check_kernel(
    elf: &[u8],
    sig: &[u8],
    version_file: &[u8],
    key: &[u8; 32],
    stored: Option<u64>,
) -> Result<(u64, Decision), RollbackError> {
    let version = parse_version(version_file)?;
    verify_kernel(elf, sig, version, key).map_err(RollbackError::Signature)?;
    match decide(stored, version) {
        Decision::Rollback { minimum } => Err(RollbackError::Rollback { version, minimum }),
        d => Ok((version, d)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sign(sk: &SigningKey, version: u64, elf: &[u8]) -> [u8; 64] {
        sk.sign(&signed_message(version, elf)).to_bytes()
    }

    const ELF: &[u8] = b"\x7fELF fake kernel image";

    #[test]
    fn the_signed_message_layout_is_fixed() {
        // build_os.sh arma el mismo mensaje con printf: dominio || version LE || ELF
        let m = signed_message(0x0102, b"AB");
        assert_eq!(&m[..24], b"TRUNOMY-KERNEL-IMAGE-v2\0");
        assert_eq!(&m[24..32], &[2, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&m[32..], b"AB");
        assert_eq!(m.len(), 24 + 8 + 2);
    }

    #[test]
    fn a_first_boot_accepts_and_records_the_version() {
        let (sk, pk) = keypair(1);
        let sig = sign(&sk, 3, ELF);
        assert_eq!(
            check_kernel(ELF, &sig, &3u64.to_le_bytes(), &pk, None),
            Ok((3, Decision::Accept { ratchet: Some(3) }))
        );
    }

    #[test]
    fn the_same_version_boots_without_touching_the_counter() {
        let (sk, pk) = keypair(1);
        let sig = sign(&sk, 3, ELF);
        assert_eq!(
            check_kernel(ELF, &sig, &3u64.to_le_bytes(), &pk, Some(3)),
            Ok((3, Decision::Accept { ratchet: None }))
        );
    }

    #[test]
    fn a_newer_version_boots_and_ratchets_the_counter_up() {
        let (sk, pk) = keypair(1);
        let sig = sign(&sk, 5, ELF);
        assert_eq!(
            check_kernel(ELF, &sig, &5u64.to_le_bytes(), &pk, Some(3)),
            Ok((5, Decision::Accept { ratchet: Some(5) }))
        );
    }

    #[test]
    fn an_older_validly_signed_kernel_is_refused() {
        let (sk, pk) = keypair(1);
        let sig = sign(&sk, 2, ELF);
        assert_eq!(
            check_kernel(ELF, &sig, &2u64.to_le_bytes(), &pk, Some(3)),
            Err(RollbackError::Rollback { version: 2, minimum: 3 })
        );
    }

    #[test]
    fn editing_the_version_file_invalidates_the_signature() {
        // el atacante sube el .ver de un kernel viejo para pasar el minimo: la firma ya no corresponde
        let (sk, pk) = keypair(1);
        let old_sig = sign(&sk, 2, ELF);
        assert_eq!(
            check_kernel(ELF, &old_sig, &9u64.to_le_bytes(), &pk, Some(3)),
            Err(RollbackError::Signature(VerifyError::BadSignature))
        );
        // y al reves: bajar el .ver de un kernel nuevo para esquivar el contador tampoco funciona
        let new_sig = sign(&sk, 9, ELF);
        assert_eq!(
            check_kernel(ELF, &new_sig, &2u64.to_le_bytes(), &pk, Some(3)),
            Err(RollbackError::Signature(VerifyError::BadSignature))
        );
    }

    #[test]
    fn an_unsigned_version_never_moves_the_counter() {
        // el orden importa: sin firma valida no se llega a `decide`, asi que no hay Decision que suba nada
        let (_, pk) = keypair(1);
        let (other, _) = keypair(2);
        let sig = sign(&other, u64::MAX, ELF);
        let r = check_kernel(ELF, &sig, &u64::MAX.to_le_bytes(), &pk, Some(3));
        assert_eq!(r, Err(RollbackError::Signature(VerifyError::BadSignature)));
    }

    #[test]
    fn a_signature_over_the_bare_elf_is_not_a_kernel_signature() {
        // la firma antigua (solo del ELF, sin dominio ni version) ya no vale: no hay camino sin version
        let (sk, pk) = keypair(1);
        let bare = sk.sign(ELF).to_bytes();
        assert_eq!(
            check_kernel(ELF, &bare, &1u64.to_le_bytes(), &pk, None),
            Err(RollbackError::Signature(VerifyError::BadSignature))
        );
    }

    #[test]
    fn a_modified_elf_is_refused_whatever_the_version() {
        let (sk, pk) = keypair(1);
        let sig = sign(&sk, 4, ELF);
        let mut bad = ELF.to_vec();
        bad[10] ^= 1;
        assert_eq!(
            check_kernel(&bad, &sig, &4u64.to_le_bytes(), &pk, None),
            Err(RollbackError::Signature(VerifyError::BadSignature))
        );
    }

    #[test]
    fn the_version_file_must_be_exactly_eight_nonzero_bytes() {
        for n in [0usize, 1, 7, 9, 16] {
            assert_eq!(parse_version(&[1u8; 16][..n]), Err(RollbackError::BadVersionFile), "len {n}");
        }
        assert_eq!(parse_version(&[0u8; 8]), Err(RollbackError::ZeroVersion));
        assert_eq!(parse_version(&7u64.to_le_bytes()), Ok(7));
        assert_eq!(parse_version(&u64::MAX.to_le_bytes()), Ok(u64::MAX));
    }

    #[test]
    fn the_counter_round_trips_and_a_wrong_size_is_corruption() {
        for v in [0u64, 1, 255, 256, u64::MAX] {
            assert_eq!(decode_counter(&encode_counter(v)), Ok(v));
        }
        for n in [0usize, 1, 7, 9] {
            assert_eq!(decode_counter(&[0u8; 16][..n]), Err(RollbackError::BadCounter), "len {n}");
        }
    }

    #[test]
    fn decide_is_monotonic_for_every_pair() {
        for stored in 0..6u64 {
            for v in 1..6u64 {
                match decide(Some(stored), v) {
                    Decision::Rollback { minimum } => assert!(v < stored && minimum == stored),
                    Decision::Accept { ratchet: Some(r) } => assert!(v > stored && r == v),
                    Decision::Accept { ratchet: None } => assert_eq!(v, stored),
                }
            }
        }
    }

    #[test]
    fn upgrading_then_trying_the_old_kernel_is_the_whole_story() {
        // simula tres arranques con el contador persistente
        let (sk, pk) = keypair(1);
        let mut nvram: Option<u64> = None;
        let boot = |v: u64, nvram: &mut Option<u64>| -> Result<u64, RollbackError> {
            let sig = sign(&sk, v, ELF);
            let (ver, d) = check_kernel(ELF, &sig, &v.to_le_bytes(), &pk, *nvram)?;
            if let Decision::Accept { ratchet: Some(n) } = d {
                *nvram = Some(n);
            }
            Ok(ver)
        };
        assert_eq!(boot(1, &mut nvram), Ok(1));
        assert_eq!(boot(2, &mut nvram), Ok(2), "actualizar funciona");
        assert_eq!(boot(1, &mut nvram), Err(RollbackError::Rollback { version: 1, minimum: 2 }), "volver atras no");
        assert_eq!(boot(2, &mut nvram), Ok(2), "el kernel actual sigue arrancando");
        assert_eq!(nvram, Some(2));
    }
}
