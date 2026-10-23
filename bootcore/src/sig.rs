// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Verificacion de firmas Ed25519 (I-18, I-19).
//!
//! No hay modo desarrollo ni "clave de prueba": toda imagen se verifica contra la
//! clave que se pasa, y cualquier fallo es un error. La clave se rechaza si es
//! debil (orden pequeno), como la de ceros, en vez de interpretarse como "sin firma".

use ed25519_dalek::{Signature, VerifyingKey};

pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// La clave no es un punto valido de la curva o es de orden pequeno.
    BadKey,
    /// La firma no mide 64 bytes (o es demasiado corta la imagen para contenerla).
    BadSignatureLength,
    /// La firma no corresponde a los datos y a la clave, o no es canonica.
    BadSignature,
}

impl VerifyError {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyError::BadKey => "invalid or weak public key",
            VerifyError::BadSignatureLength => "the signature is not 64 bytes",
            VerifyError::BadSignature => "the signature does not match",
        }
    }
}

/// Verifica una firma separada `sig` de `data` con `key`.
///
/// Usa `verify_strict`: rechaza firmas no canonicas y componentes de orden pequeno,
/// de modo que una imagen no tiene dos firmas validas distintas.
pub fn verify_detached(data: &[u8], sig: &[u8], key: &[u8; 32]) -> Result<(), VerifyError> {
    if sig.len() != SIGNATURE_LEN {
        return Err(VerifyError::BadSignatureLength);
    }
    let vk = VerifyingKey::from_bytes(key).map_err(|_| VerifyError::BadKey)?;
    if vk.is_weak() {
        return Err(VerifyError::BadKey);
    }
    let sig = Signature::from_slice(sig).map_err(|_| VerifyError::BadSignatureLength)?;
    vk.verify_strict(data, &sig)
        .map_err(|_| VerifyError::BadSignature)
}

/// Formato `payload || firma(64)` (el de `shell.bin`). Devuelve el payload verificado.
pub fn verify_appended<'a>(blob: &'a [u8], key: &[u8; 32]) -> Result<&'a [u8], VerifyError> {
    if blob.len() <= SIGNATURE_LEN {
        return Err(VerifyError::BadSignatureLength);
    }
    let (payload, sig) = blob.split_at(blob.len() - SIGNATURE_LEN);
    verify_detached(payload, sig, key)?;
    Ok(payload)
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

    #[test]
    fn valid_signature_is_accepted() {
        let (sk, pk) = keypair(1);
        let data = b"kernel image";
        let sig = sk.sign(data).to_bytes();
        assert_eq!(verify_detached(data, &sig, &pk), Ok(()));
    }

    #[test]
    fn modified_data_is_rejected() {
        let (sk, pk) = keypair(1);
        let sig = sk.sign(b"kernel image").to_bytes();
        assert_eq!(
            verify_detached(b"kernel imagE", &sig, &pk),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn every_single_bit_flip_in_signature_is_rejected() {
        let (sk, pk) = keypair(1);
        let data = b"kernel image";
        let sig = sk.sign(data).to_bytes();
        for i in 0..64 {
            for b in 0..8 {
                let mut bad = sig;
                bad[i] ^= 1 << b;
                assert!(verify_detached(data, &bad, &pk).is_err(), "byte {i} bit {b}");
            }
        }
    }

    #[test]
    fn signature_by_another_key_is_rejected() {
        let (sk, _) = keypair(1);
        let (_, other_pk) = keypair(2);
        let sig = sk.sign(b"x").to_bytes();
        assert_eq!(
            verify_detached(b"x", &sig, &other_pk),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn wrong_signature_length_is_rejected() {
        let (_, pk) = keypair(1);
        for n in [0usize, 1, 63, 65, 128] {
            let sig = [0u8; 128];
            assert_eq!(
                verify_detached(b"x", &sig[..n], &pk),
                Err(VerifyError::BadSignatureLength)
            );
        }
    }

    #[test]
    fn all_zero_key_is_not_a_bypass() {
        // I-19: una clave de ceros no significa "modo desarrollo": se rechaza.
        let zero_key = [0u8; 32];
        let zero_sig = [0u8; 64];
        assert_eq!(
            verify_detached(b"anything", &zero_sig, &zero_key),
            Err(VerifyError::BadKey)
        );
        assert!(verify_appended(&[0u8; 100], &zero_key).is_err());
    }

    #[test]
    fn small_order_keys_are_rejected() {
        // El elemento neutro (y=1) es de orden 1: con el se pueden falsificar firmas
        // en verificadores no estrictos.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            verify_detached(b"x", &[0u8; 64], &identity),
            Err(VerifyError::BadKey)
        );
    }

    #[test]
    fn non_canonical_s_is_rejected() {
        // Firma maleable: S + L (L = orden del grupo) valida en verificadores
        // laxos pero no en `verify_strict`.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let (sk, pk) = keypair(3);
        let data = b"payload";
        let sig = sk.sign(data).to_bytes();
        let mut bad = sig;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = sig[32 + i] as u16 + L[i] as u16 + carry;
            bad[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert!(verify_detached(data, &bad, &pk).is_err());
    }

    #[test]
    fn appended_format_roundtrip_and_tamper() {
        let (sk, pk) = keypair(4);
        let payload = b"shell payload bytes";
        let mut blob = payload.to_vec();
        blob.extend_from_slice(&sk.sign(payload).to_bytes());
        assert_eq!(verify_appended(&blob, &pk), Ok(&payload[..]));

        blob[0] ^= 0xFF;
        assert!(verify_appended(&blob, &pk).is_err());
        assert_eq!(
            verify_appended(&blob[..64], &pk),
            Err(VerifyError::BadSignatureLength)
        );
    }
}
