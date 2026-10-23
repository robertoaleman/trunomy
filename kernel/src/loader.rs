// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/loader.rs
use crate::memory::frame_allocator::BITMAP_ALLOCATOR;
use crate::memory::process_paging::ProcessPml4;
use trunomy_bootcore::sig::verify_detached;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TrunomyHeader {
    pub magic: [u8; 8],
    pub version: u16,
    pub arch: u16,
    pub flags: u32,
    pub payload_size: u64,
    pub entry_point: u64,
    pub cap_offset: u64,
    pub cap_count: u32,
    pub _reserved1: u32,
    pub payload_hash: [u8; 32],
    pub _reserved2: [u8; 48],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityEntry {
    pub cap_id: u32,
    pub cap_scope: u32,
}

#[derive(Debug)]
pub enum LoaderError {
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedArch,
    InvalidHeaderOffset,
    SignatureVerificationFailed,
    BufferTooSmall,
}

/// Mensaje (para el serie) de un layout W^X invalido: la imagen no se carga.
pub fn layout_error_text(e: trunomy_abi::image::LayoutError) -> &'static str {
    use trunomy_abi::image::LayoutError::*;
    match e {
        TooShort => "image without a W^X layout descriptor (too short)",
        BadMagic => "image without a W^X layout descriptor (magic): rebuild with the new linker.ld",
        Reserved => "W^X layout descriptor with non-zero reserved fields",
        Misaligned => "W^X layout descriptor misaligned or with regions that do not add up",
        Inconsistent => "W^X layout descriptor inconsistent with the image size",
        EntryOutsideText => "the image entry point is not in the code region",
    }
}

pub struct LoadedBinary<'a> {
    pub entry_point: u64,
    pub payload: &'a [u8],
    /// Capabilities que declara la imagen. El kernel todavia no las usa: las concede el kernel, no la imagen.
    #[allow(dead_code)]
    pub capabilities: &'a [CapabilityEntry],
}

impl TrunomyHeader {
    pub const MAGIC: &'static [u8; 8] = b"TRUNOMY\0";
    pub const HEADER_SIZE: usize = 128;
    pub const SIGNATURE_SIZE: usize = 64;
}

impl LoadedBinary<'_> {
    pub unsafe fn load_into_user_space(
        &self,
        pml4: &mut ProcessPml4,
        user_code_base: u64,
        user_stack_base: u64,
    ) -> Result<(), &'static str> {
        let page_size = 4096usize;

        // W^X: el layout viene del propio payload verificado; sin el, no se carga nada.
        let layout = trunomy_abi::image::ImageLayout::parse(self.payload, self.entry_point)
            .map_err(layout_error_text)?;

        for i in 0..layout.pages() {
            let perm = layout.perm_of_page(i).ok_or("page outside the layout")?;
            let chunk = &self.payload[i * page_size..(i + 1) * page_size];
            let virt_addr = user_code_base + (i as u64 * 4096);

            let frame_phys = BITMAP_ALLOCATOR
                .lock()
                .allocate_frame()
                .ok_or("Out of memory for the shell")?;

            let phys_ptr = frame_phys as *mut u8;
            core::ptr::write_bytes(phys_ptr, 0, page_size);
            core::ptr::copy_nonoverlapping(chunk.as_ptr(), phys_ptr, chunk.len());

            pml4.map_user_page(virt_addr, frame_phys, perm.writable(), perm.executable())?;
        }

        let stack_pages = 4;
        for i in 0..stack_pages {
            let page_addr = user_stack_base + (i * 4096);

            let frame_phys = BITMAP_ALLOCATOR
                .lock()
                .allocate_frame()
                .ok_or("Out of memory for the user stack")?;

            let phys_ptr = frame_phys as *mut u8;
            core::ptr::write_bytes(phys_ptr, 0, page_size);

            pml4.map_user_page(page_addr, frame_phys, true, false)?;
        }

        Ok(())
    }
}

pub struct TrunomyLoader;

impl TrunomyLoader {
    /// Soporta dos formatos de carga:
    /// - binario plano con firma anexada al final (shell.bin + 64 bytes de firma)
    /// - formato TRUNOMY con header + payload + firma
    /// En ambos casos, la firma debe validarse; no hay bypass de dev-mode.
    pub fn parse_and_verify<'a>(
        binary_data: &'a [u8],
        public_key: &[u8; 32],
    ) -> Result<LoadedBinary<'a>, LoaderError> {
        // Formato plano firmado: raw_payload || 64-byte signature
        if binary_data.len() >= 64 {
            let payload_len = binary_data.len() - 64;
            let payload = &binary_data[..payload_len];
            let signature = &binary_data[payload_len..];

            if verify_ed25519_signature(payload, signature, public_key) {
                return Ok(LoadedBinary {
                    entry_point: 0,
                    payload,
                    capabilities: &[],
                });
            }
        }

        if binary_data.len() >= TrunomyHeader::HEADER_SIZE
            && binary_data.starts_with(TrunomyHeader::MAGIC)
        {
            if binary_data.len() < TrunomyHeader::HEADER_SIZE + TrunomyHeader::SIGNATURE_SIZE {
                return Err(LoaderError::BufferTooSmall);
            }

            let header_ptr = binary_data.as_ptr() as *const TrunomyHeader;
            let header = unsafe { core::ptr::read_unaligned(header_ptr) };

            if header.version != 1 {
                return Err(LoaderError::UnsupportedVersion);
            }
            if header.arch != 1 {
                return Err(LoaderError::UnsupportedArch);
            }

            let total_size = binary_data.len();
            let signed_data_len = total_size - TrunomyHeader::SIGNATURE_SIZE;
            let signed_data = &binary_data[..signed_data_len];
            let signature_bytes = &binary_data[signed_data_len..];

            if !verify_ed25519_signature(signed_data, signature_bytes, public_key) {
                return Err(LoaderError::SignatureVerificationFailed);
            }

            let cap_start = header.cap_offset as usize;
            let cap_bytes_len =
                (header.cap_count as usize) * core::mem::size_of::<CapabilityEntry>();

            if cap_start < TrunomyHeader::HEADER_SIZE || cap_start + cap_bytes_len > signed_data_len {
                return Err(LoaderError::InvalidHeaderOffset);
            }

            let caps_slice = unsafe {
                core::slice::from_raw_parts(
                    binary_data.as_ptr().add(cap_start) as *const CapabilityEntry,
                    header.cap_count as usize,
                )
            };

            let payload_start = cap_start + cap_bytes_len;
            if payload_start + (header.payload_size as usize) > signed_data_len {
                return Err(LoaderError::InvalidHeaderOffset);
            }

            let payload =
                &binary_data[payload_start..payload_start + (header.payload_size as usize)];

            Ok(LoadedBinary {
                entry_point: header.entry_point,
                payload,
                capabilities: caps_slice,
            })
        } else {
            Err(LoaderError::InvalidMagic)
        }
    }
}

/// Verifica firma Ed25519 estricta (I-18). Sin bypass: toda imagen se comprueba contra
/// la clave recibida; una clave nula o débil se rechaza, no activa ningún modo (I-19).
fn verify_ed25519_signature(data: &[u8], signature: &[u8], public_key: &[u8; 32]) -> bool {
    verify_detached(data, signature, public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_flat(payload: &[u8]) -> ([u8; 32], std::vec::Vec<u8>) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut blob = payload.to_vec();
        blob.extend_from_slice(&sk.sign(payload).to_bytes());
        (sk.verifying_key().to_bytes(), blob)
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let data = b"test payload";
        let invalid_sig = [0u8; 64];
        let pubkey = [0u8; 32];

        assert!(!verify_ed25519_signature(data, &invalid_sig, &pubkey));
    }

    #[test]
    fn wrong_signature_length_is_rejected() {
        let data = b"test payload";
        let wrong_sig = [0u8; 63];
        let pubkey = [0u8; 32];

        assert!(!verify_ed25519_signature(data, &wrong_sig, &pubkey));
    }

    #[test]
    fn valid_flat_image_is_accepted() {
        let (pk, blob) = signed_flat(b"shell image bytes");
        let loaded = TrunomyLoader::parse_and_verify(&blob, &pk).expect("firma valida");
        assert_eq!(loaded.payload, b"shell image bytes");
    }

    #[test]
    fn tampered_flat_image_is_rejected() {
        let (pk, mut blob) = signed_flat(b"shell image bytes");
        blob[3] ^= 1;
        assert!(TrunomyLoader::parse_and_verify(&blob, &pk).is_err());
    }

    #[test]
    fn image_signed_by_another_key_is_rejected() {
        let (_, blob) = signed_flat(b"shell image bytes");
        let other = SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        assert!(TrunomyLoader::parse_and_verify(&blob, &other).is_err());
    }

    #[test]
    fn zero_key_is_not_a_dev_mode() {
        // I-19: ni la clave de ceros ni una firma de ceros abren nada.
        let blob = [0u8; 200];
        assert!(TrunomyLoader::parse_and_verify(&blob, &[0u8; 32]).is_err());
        let (_, good) = signed_flat(b"x");
        assert!(TrunomyLoader::parse_and_verify(&good, &[0u8; 32]).is_err());
    }

    #[test]
    fn embedded_signing_keys_are_real_keys_or_fail_closed() {
        use trunomy_abi::trust::{KERNEL_SIGNING_PUBLIC_KEY, SHELL_SIGNING_PUBLIC_KEY};
        use trunomy_bootcore::sig::{verify_detached, VerifyError};
        // La del kernel es una clave real, no un marcador.
        assert_ne!(KERNEL_SIGNING_PUBLIC_KEY, [0u8; 32]);
        assert_ne!(verify_detached(b"x", &[0u8; 64], &KERNEL_SIGNING_PUBLIC_KEY), Err(VerifyError::BadKey));
        // La de la shell: o esta aprovisionada (clave valida) o es el marcador de ceros, que
        // se rechaza (fail-closed, nunca modo desarrollo). Nunca puede ser la del kernel (I-39).
        assert_ne!(SHELL_SIGNING_PUBLIC_KEY, KERNEL_SIGNING_PUBLIC_KEY);
        if SHELL_SIGNING_PUBLIC_KEY == [0u8; 32] {
            let (_, good) = signed_flat(b"x");
            assert!(TrunomyLoader::parse_and_verify(&good, &SHELL_SIGNING_PUBLIC_KEY).is_err());
        } else {
            assert_ne!(verify_detached(b"x", &[0u8; 64], &SHELL_SIGNING_PUBLIC_KEY), Err(VerifyError::BadKey));
        }
    }

    #[test]
    fn image_signed_with_the_kernel_role_key_is_not_a_shell_image() {
        // I-39: el verificador de la shell no acepta una firma hecha por otra clave, aunque
        // sea valida como firma de kernel. Se simula con dos claves distintas.
        let (_, blob) = signed_flat(b"shell image bytes");
        let kernel_role = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert!(TrunomyLoader::parse_and_verify(&blob, &kernel_role).is_err());
    }
}
