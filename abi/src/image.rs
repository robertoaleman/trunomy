// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Layout W^X de una imagen de usuario (parche 17).
//!
//! La imagen es un binario plano (`objcopy -O binary`) enlazado con `linker.ld`, que alinea a
//! pagina cada region y deja al FINAL un descriptor de `DESC_SIZE` bytes. El kernel lo lee del
//! payload ya verificado (Ed25519) y mapea cada pagina con sus permisos:
//! - `text`   : R-X (el punto de entrada esta aqui)
//! - `rodata` : R-- sin ejecucion
//! - `data`   : RW- sin ejecucion (`.data` y `.bss`)
//! Ninguna pagina es escribible y ejecutable a la vez. Si el descriptor falta o es incoherente,
//! la imagen no se carga (falla cerrado).
//!
//! Descriptor: 8 `u64` little endian:
//! `magic, text_len, rodata_len, data_len, total_len, entry_max, 0, 0`
//! (`text_off = 0`; `rodata_off = text_len`; `data_off = text_len + rodata_len`; todo en bytes y
//! multiplo de `PAGE`; `total_len` = bytes de paginas = `payload.len() - DESC_SIZE`).

pub const PAGE: usize = 4096;
pub const DESC_SIZE: usize = 64;
/// "TRUNLAY1" como `u64` little endian (el mismo literal esta en `userland/shell/linker.ld`).
pub const MAGIC: u64 = u64::from_le_bytes(*b"TRUNLAY1");

/// Permisos de una pagina de la imagen. Ninguno combina escritura y ejecucion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagePerm {
    ReadExec,
    ReadOnly,
    ReadWrite,
}

impl PagePerm {
    pub const fn writable(self) -> bool {
        matches!(self, PagePerm::ReadWrite)
    }
    pub const fn executable(self) -> bool {
        matches!(self, PagePerm::ReadExec)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    TooShort,
    BadMagic,
    /// Un campo reservado no es cero.
    Reserved,
    /// Longitud no multiplo de pagina o regiones que no suman el total.
    Misaligned,
    /// `text` vacio, o regiones que no cubren exactamente las paginas del payload.
    Inconsistent,
    /// El punto de entrada cae fuera de `text`.
    EntryOutsideText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageLayout {
    pub text_len: usize,
    pub rodata_len: usize,
    pub data_len: usize,
}

fn word(bytes: &[u8], i: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
    u64::from_le_bytes(w)
}

impl ImageLayout {
    /// Lee y valida el descriptor del final de `payload`. `entry` es el offset del punto de
    /// entrada dentro de la imagen.
    pub fn parse(payload: &[u8], entry: u64) -> Result<Self, LayoutError> {
        if payload.len() < DESC_SIZE + PAGE {
            return Err(LayoutError::TooShort);
        }
        let desc = &payload[payload.len() - DESC_SIZE..];
        if word(desc, 0) != MAGIC {
            return Err(LayoutError::BadMagic);
        }
        if word(desc, 6) != 0 || word(desc, 7) != 0 {
            return Err(LayoutError::Reserved);
        }
        let to_usize = |v: u64| usize::try_from(v).map_err(|_| LayoutError::Misaligned);
        let text = to_usize(word(desc, 1))?;
        let ro = to_usize(word(desc, 2))?;
        let data = to_usize(word(desc, 3))?;
        let total = to_usize(word(desc, 4))?;
        let entry_max = word(desc, 5);

        for len in [text, ro, data, total] {
            if len % PAGE != 0 {
                return Err(LayoutError::Misaligned);
            }
        }
        let sum = text
            .checked_add(ro)
            .and_then(|s| s.checked_add(data))
            .ok_or(LayoutError::Misaligned)?;
        if sum != total {
            return Err(LayoutError::Misaligned);
        }
        if text == 0 || total != payload.len() - DESC_SIZE {
            return Err(LayoutError::Inconsistent);
        }
        // `entry_max` lo escribe el enlazador (= text_len): el kernel lo contrasta con lo suyo.
        if entry_max != text as u64 {
            return Err(LayoutError::Inconsistent);
        }
        if entry >= text as u64 {
            return Err(LayoutError::EntryOutsideText);
        }
        Ok(Self { text_len: text, rodata_len: ro, data_len: data })
    }

    /// Paginas que se mapean (el descriptor no se mapea).
    pub fn pages(&self) -> usize {
        (self.text_len + self.rodata_len + self.data_len) / PAGE
    }

    /// Permisos de la pagina `index` (0 = primera). `None` fuera de la imagen.
    pub fn perm_of_page(&self, index: usize) -> Option<PagePerm> {
        let off = index.checked_mul(PAGE)?;
        if off < self.text_len {
            Some(PagePerm::ReadExec)
        } else if off < self.text_len + self.rodata_len {
            Some(PagePerm::ReadOnly)
        } else if off < self.text_len + self.rodata_len + self.data_len {
            Some(PagePerm::ReadWrite)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn image(text: usize, ro: usize, data: usize) -> Vec<u8> {
        let total = text + ro + data;
        let mut v = alloc::vec![0xAAu8; total];
        for w in [MAGIC, text as u64, ro as u64, data as u64, total as u64, text as u64, 0, 0] {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    #[test]
    fn magic_literal_matches_the_linker_script() {
        // El mismo valor esta escrito a mano en userland/shell/linker.ld.
        assert_eq!(MAGIC, 0x3159_414C_4E55_5254);
    }

    #[test]
    fn valid_layout_assigns_rx_r_rw_by_page_and_never_wx() {
        let img = image(2 * PAGE, PAGE, 3 * PAGE);
        let l = ImageLayout::parse(&img, 0).unwrap();
        assert_eq!(l.pages(), 6);
        let perms: Vec<_> = (0..6).map(|i| l.perm_of_page(i).unwrap()).collect();
        assert_eq!(
            perms,
            [
                PagePerm::ReadExec, PagePerm::ReadExec, PagePerm::ReadOnly,
                PagePerm::ReadWrite, PagePerm::ReadWrite, PagePerm::ReadWrite
            ]
        );
        assert_eq!(l.perm_of_page(6), None, "el descriptor no es una pagina de la imagen");
        for p in perms {
            assert!(!(p.writable() && p.executable()), "W^X");
        }
    }

    #[test]
    fn regions_may_be_empty_except_text() {
        assert!(ImageLayout::parse(&image(PAGE, 0, 0), 0).is_ok());
        assert!(ImageLayout::parse(&image(PAGE, PAGE, 0), 0).is_ok());
        assert_eq!(ImageLayout::parse(&image(0, PAGE, PAGE), 0), Err(LayoutError::Inconsistent));
    }

    #[test]
    fn missing_or_wrong_descriptor_fails_closed() {
        assert_eq!(ImageLayout::parse(&[], 0), Err(LayoutError::TooShort));
        assert_eq!(ImageLayout::parse(&alloc::vec![0u8; 2 * PAGE], 0), Err(LayoutError::BadMagic));
        let mut img = image(PAGE, PAGE, PAGE);
        let n = img.len();
        img[n - DESC_SIZE] ^= 1; // magic roto
        assert_eq!(ImageLayout::parse(&img, 0), Err(LayoutError::BadMagic));
        let mut img = image(PAGE, PAGE, PAGE);
        let n = img.len();
        img[n - 8] = 1; // campo reservado
        assert_eq!(ImageLayout::parse(&img, 0), Err(LayoutError::Reserved));
    }

    #[test]
    fn inconsistent_sizes_are_rejected() {
        // longitud no multiplo de pagina
        let mut img = image(PAGE, PAGE, PAGE);
        let n = img.len();
        img[n - DESC_SIZE + 8..n - DESC_SIZE + 16].copy_from_slice(&((PAGE as u64) + 1).to_le_bytes());
        assert_eq!(ImageLayout::parse(&img, 0), Err(LayoutError::Misaligned));
        // las regiones no suman el total
        let mut img = image(PAGE, PAGE, PAGE);
        img[n - DESC_SIZE + 24..n - DESC_SIZE + 32].copy_from_slice(&(2 * PAGE as u64).to_le_bytes());
        assert_eq!(ImageLayout::parse(&img, 0), Err(LayoutError::Misaligned));
        // el total no es lo que mide el payload
        let mut img = image(PAGE, PAGE, PAGE);
        img.extend_from_slice(&[0u8; PAGE]);
        assert!(ImageLayout::parse(&img, 0).is_err());
        // desbordamiento
        let mut img = image(PAGE, PAGE, PAGE);
        img[n - DESC_SIZE + 16..n - DESC_SIZE + 24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ImageLayout::parse(&img, 0).is_err());
    }

    #[test]
    fn entry_must_lie_inside_text() {
        let img = image(2 * PAGE, PAGE, PAGE);
        assert!(ImageLayout::parse(&img, 0).is_ok());
        assert!(ImageLayout::parse(&img, 2 * PAGE as u64 - 1).is_ok());
        assert_eq!(ImageLayout::parse(&img, 2 * PAGE as u64), Err(LayoutError::EntryOutsideText));
        assert_eq!(ImageLayout::parse(&img, u64::MAX), Err(LayoutError::EntryOutsideText));
    }
}
