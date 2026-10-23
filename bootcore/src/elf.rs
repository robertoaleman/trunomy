// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Validacion y carga del ELF del kernel (I-18).
//!
//! `plan_load` examina los PT_LOAD y devuelve un [`LoadPlan`] solo si todo es
//! coherente; `load_into` copia siguiendo ese plan sobre un `&mut [u8]` (en el
//! bootloader, las paginas recien reservadas). Toda aritmetica es comprobada y
//! cada indexacion esta acotada: un ELF malicioso o corrupto produce un error, no
//! una escritura fuera de la region.

use xmas_elf::header::{Class, Machine, Type as ElfType};
use xmas_elf::program::{ProgramHeader, Type as PhType};
use xmas_elf::ElfFile;

pub const PAGE_SIZE: u64 = 4096;
/// Maximo de segmentos PT_LOAD admitidos (el kernel actual usa 4).
pub const MAX_SEGMENTS: usize = 8;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    Malformed,
    NotX86_64,
    NotExecutable,
    NoLoadSegments,
    TooManySegments,
    FileSizeExceedsMemSize,
    AddressOverflow,
    SegmentOutsideFile,
    SegmentOutsideRegion,
    SegmentsOverlap,
    WritableAndExecutable,
    BaseMismatch,
    EntryNotInExecutableSegment,
    ImageBufferMismatch,
}

impl ElfError {
    pub fn as_str(self) -> &'static str {
        match self {
            ElfError::Malformed => "malformed ELF",
            ElfError::NotX86_64 => "the ELF is not 64-bit little-endian x86_64",
            ElfError::NotExecutable => "the kernel must be linked as ET_EXEC (not PIE)",
            ElfError::NoLoadSegments => "the ELF has no PT_LOAD segments",
            ElfError::TooManySegments => "too many PT_LOAD segments",
            ElfError::FileSizeExceedsMemSize => "PT_LOAD segment with file_size > mem_size",
            ElfError::AddressOverflow => "arithmetic overflow in a PT_LOAD segment",
            ElfError::SegmentOutsideFile => "PT_LOAD segment outside the ELF file",
            ElfError::SegmentOutsideRegion => "PT_LOAD segment outside the reserved region",
            ElfError::SegmentsOverlap => "overlapping PT_LOAD segments",
            ElfError::WritableAndExecutable => "PT_LOAD segment that is writable and executable (W^X)",
            ElfError::BaseMismatch => "the kernel is not linked at the expected base",
            ElfError::EntryNotInExecutableSegment => {
                "the entry point is not inside an executable segment"
            }
            ElfError::ImageBufferMismatch => "the destination buffer does not match the plan",
        }
    }
}

/// Region fisica reservada para el kernel: `[base, base + max_size)`.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub base: u64,
    pub max_size: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct LoadPlan {
    pub entry: u64,
    pub base: u64,
    /// Bytes que hay que reservar: multiplo de la pagina, desde `base`.
    pub image_size: u64,
    count: usize,
    segments: [Segment; MAX_SEGMENTS],
}

impl LoadPlan {
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }
    pub fn pages(&self) -> usize {
        (self.image_size / PAGE_SIZE) as usize
    }
}

/// Valida el ELF y calcula el plan de carga. No escribe nada.
pub fn plan_load(elf_bytes: &[u8], region: Region) -> Result<LoadPlan, ElfError> {
    let elf = ElfFile::new(elf_bytes).map_err(|_| ElfError::Malformed)?;

    let h = &elf.header;
    if h.pt1.class() != Class::SixtyFour
        || h.pt2.machine().as_machine() != Machine::X86_64
        || h.pt1.data() != xmas_elf::header::Data::LittleEndian
    {
        return Err(ElfError::NotX86_64);
    }
    if h.pt2.type_().as_type() != ElfType::Executable {
        return Err(ElfError::NotExecutable);
    }

    // xmas-elf indexa la tabla de cabeceras sin comprobar limites (entra en panico con
    // un ELF truncado): se comprueba aqui antes de iterar.
    let ph_end = h
        .pt2
        .ph_offset()
        .checked_add(
            (h.pt2.ph_count() as u64)
                .checked_mul(h.pt2.ph_entry_size() as u64)
                .ok_or(ElfError::AddressOverflow)?,
        )
        .ok_or(ElfError::AddressOverflow)?;
    if h.pt2.ph_entry_size() != 56 || ph_end > elf_bytes.len() as u64 {
        return Err(ElfError::Malformed);
    }

    let region_end = region
        .base
        .checked_add(region.max_size)
        .ok_or(ElfError::AddressOverflow)?;

    let mut segments = [Segment::default(); MAX_SEGMENTS];
    let mut count = 0usize;
    let mut lowest = u64::MAX;
    let mut highest = 0u64;

    for ph in elf.program_iter() {
        let ph64 = match ph {
            ProgramHeader::Ph64(p) => p,
            _ => return Err(ElfError::NotX86_64),
        };
        if ph.get_type() != Ok(PhType::Load) {
            continue;
        }

        let seg = Segment {
            vaddr: ph.virtual_addr(),
            mem_size: ph.mem_size(),
            file_offset: ph.offset(),
            file_size: ph.file_size(),
            flags: ph64.flags.0,
        };

        if seg.mem_size == 0 && seg.file_size == 0 {
            continue; // segmento vacio: no carga nada
        }
        if seg.file_size > seg.mem_size {
            return Err(ElfError::FileSizeExceedsMemSize);
        }
        let seg_end = seg
            .vaddr
            .checked_add(seg.mem_size)
            .ok_or(ElfError::AddressOverflow)?;
        let file_end = seg
            .file_offset
            .checked_add(seg.file_size)
            .ok_or(ElfError::AddressOverflow)?;
        if file_end > elf_bytes.len() as u64 {
            return Err(ElfError::SegmentOutsideFile);
        }
        if seg.vaddr < region.base || seg_end > region_end {
            return Err(ElfError::SegmentOutsideRegion);
        }
        if seg.flags & PF_W != 0 && seg.flags & PF_X != 0 {
            return Err(ElfError::WritableAndExecutable);
        }
        for prev in &segments[..count] {
            let prev_end = prev.vaddr + prev.mem_size; // ya comprobado al guardarlo
            if seg.vaddr < prev_end && prev.vaddr < seg_end {
                return Err(ElfError::SegmentsOverlap);
            }
        }
        if count == MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }

        segments[count] = seg;
        count += 1;
        lowest = lowest.min(seg.vaddr);
        highest = highest.max(seg_end);
    }

    if count == 0 {
        return Err(ElfError::NoLoadSegments);
    }
    if lowest & !(PAGE_SIZE - 1) != region.base {
        return Err(ElfError::BaseMismatch);
    }

    let span = highest - region.base; // highest >= lowest >= base
    let image_size = span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(ElfError::AddressOverflow)?
        & !(PAGE_SIZE - 1);
    if image_size == 0 || image_size > region.max_size {
        return Err(ElfError::SegmentOutsideRegion);
    }

    let entry = h.pt2.entry_point();
    let entry_ok = segments[..count]
        .iter()
        .any(|s| s.flags & PF_X != 0 && entry >= s.vaddr && entry < s.vaddr + s.mem_size);
    if !entry_ok {
        return Err(ElfError::EntryNotInExecutableSegment);
    }

    Ok(LoadPlan {
        entry,
        base: region.base,
        image_size,
        count,
        segments,
    })
}

/// Copia los segmentos del plan en `image` (que cubre `[base, base + image_size)`).
/// Deja a cero todo lo que no es contenido de archivo (huecos, .bss, colas de pagina).
pub fn load_into(plan: &LoadPlan, elf_bytes: &[u8], image: &mut [u8]) -> Result<(), ElfError> {
    if image.len() as u64 != plan.image_size {
        return Err(ElfError::ImageBufferMismatch);
    }
    image.fill(0);

    for s in plan.segments() {
        let dst_start = s.vaddr.checked_sub(plan.base).ok_or(ElfError::SegmentOutsideRegion)?;
        let dst_end = dst_start
            .checked_add(s.file_size)
            .ok_or(ElfError::AddressOverflow)?;
        let src_end = s
            .file_offset
            .checked_add(s.file_size)
            .ok_or(ElfError::AddressOverflow)?;
        let dst = image
            .get_mut(dst_start as usize..dst_end as usize)
            .ok_or(ElfError::SegmentOutsideRegion)?;
        let src = elf_bytes
            .get(s.file_offset as usize..src_end as usize)
            .ok_or(ElfError::SegmentOutsideFile)?;
        dst.copy_from_slice(src);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const BASE: u64 = 0x20_0000;
    const REGION: Region = Region { base: BASE, max_size: 16 << 20 };

    #[derive(Clone)]
    struct Seg {
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        flags: u32,
        offset: u64,
        data: Vec<u8>,
    }

    fn seg(vaddr: u64, data: &[u8], memsz: u64, flags: u32, offset: u64) -> Seg {
        Seg { vaddr, filesz: data.len() as u64, memsz, flags, offset, data: data.to_vec() }
    }

    /// Construye un ELF64 x86_64 minimo con los PT_LOAD dados.
    fn build(e_type: u16, entry: u64, segs: &[Seg]) -> Vec<u8> {
        let phoff = 64u64;
        let mut f = Vec::new();
        f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        f.extend_from_slice(&[0u8; 8]);
        f.extend_from_slice(&e_type.to_le_bytes());
        f.extend_from_slice(&62u16.to_le_bytes()); // x86_64
        f.extend_from_slice(&1u32.to_le_bytes());
        f.extend_from_slice(&entry.to_le_bytes());
        f.extend_from_slice(&phoff.to_le_bytes());
        f.extend_from_slice(&0u64.to_le_bytes()); // shoff
        f.extend_from_slice(&0u32.to_le_bytes());
        f.extend_from_slice(&64u16.to_le_bytes()); // ehsize
        f.extend_from_slice(&56u16.to_le_bytes()); // phentsize
        f.extend_from_slice(&(segs.len() as u16).to_le_bytes());
        f.extend_from_slice(&64u16.to_le_bytes()); // shentsize
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        for s in segs {
            f.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            f.extend_from_slice(&s.flags.to_le_bytes());
            f.extend_from_slice(&s.offset.to_le_bytes());
            f.extend_from_slice(&s.vaddr.to_le_bytes());
            f.extend_from_slice(&s.vaddr.to_le_bytes());
            f.extend_from_slice(&s.filesz.to_le_bytes());
            f.extend_from_slice(&s.memsz.to_le_bytes());
            f.extend_from_slice(&0x1000u64.to_le_bytes());
        }
        for s in segs {
            let off = s.offset as usize;
            if f.len() < off + s.data.len() {
                f.resize(off + s.data.len(), 0);
            }
            f[off..off + s.data.len()].copy_from_slice(&s.data);
        }
        f
    }

    /// Como `build`, pero anade el segmento de cabecera en la base (como `.boot` del kernel real).
    fn build_k(entry: u64, segs: &[Seg]) -> Vec<u8> {
        let mut v = std::vec![seg(BASE, &[0x11; 12], 12, 4, 0x200)];
        v.extend_from_slice(segs);
        build(2, entry, &v)
    }

    fn set_u64(f: &mut [u8], pos: usize, val: u64) {
        f[pos..pos + 8].copy_from_slice(&val.to_le_bytes());
    }

    fn good() -> Vec<u8> {
        build_k(
            BASE + 0x1000,
            &[
                seg(BASE + 0x1000, &[0xAA; 64], 64, 5, 0x1000),     // R-X
                seg(BASE + 0x2000, &[0xBB; 16], 16, 4, 0x2000),     // R--
                seg(BASE + 0x3000, &[0xCC; 8], 0x2000, 6, 0x3000),  // RW- con .bss
            ],
        )
    }

    #[test]
    fn well_formed_kernel_is_planned_and_loaded() {
        let elf = good();
        let plan = plan_load(&elf, REGION).unwrap();
        assert_eq!(plan.entry, BASE + 0x1000);
        assert_eq!(plan.segments().len(), 4);
        assert_eq!(plan.pages(), 5); // 0x200000..0x205000
        let mut img = std::vec![0xFFu8; plan.image_size as usize];
        load_into(&plan, &elf, &mut img).unwrap();
        assert_eq!(img[0x1000], 0xAA);
        assert_eq!(img[0x1000 + 64], 0); // cola de pagina a cero
        assert_eq!(img[0x2000], 0xBB);
        assert_eq!(img[0x3000], 0xCC);
        assert_eq!(img[0x3008], 0); // .bss a cero
        assert_eq!(img[0], 0x11);
        assert_eq!(img[12], 0); // hueco a cero, no el 0xFF previo
    }

    #[test]
    fn garbage_is_malformed() {
        assert_eq!(plan_load(&[], REGION).unwrap_err(), ElfError::Malformed);
        assert_eq!(plan_load(&[0u8; 200], REGION).unwrap_err(), ElfError::Malformed);
        assert_eq!(plan_load(b"\x7fELF", REGION).unwrap_err(), ElfError::Malformed);
    }

    #[test]
    fn pie_is_rejected() {
        let elf = build(3, BASE + 0x1000, &[seg(BASE + 0x1000, &[1; 8], 8, 5, 0x1000)]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::NotExecutable);
    }

    #[test]
    fn no_load_segments_is_rejected() {
        let elf = build(2, BASE, &[]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::NoLoadSegments);
    }

    #[test]
    fn file_size_larger_than_mem_size_is_rejected() {
        let mut s = seg(BASE + 0x1000, &[1; 32], 32, 5, 0x1000);
        s.memsz = 16;
        let elf = build_k(BASE + 0x1000, &[s]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::FileSizeExceedsMemSize);
    }

    #[test]
    fn segment_below_region_is_rejected() {
        let elf = build_k(BASE + 0x1000, &[
            seg(BASE - 0x1000, &[1; 8], 8, 4, 0x1000),
            seg(BASE + 0x1000, &[1; 8], 8, 5, 0x2000),
        ]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::SegmentOutsideRegion);
    }

    #[test]
    fn segment_beyond_region_is_rejected() {
        let elf = build_k(BASE + 0x1000, &[
            seg(BASE + 0x1000, &[1; 8], 8, 5, 0x1000),
            seg(BASE + (16 << 20), &[1; 8], 8, 4, 0x2000),
        ]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::SegmentOutsideRegion);
    }

    #[test]
    fn huge_mem_size_is_rejected_without_overflow() {
        let mut s = seg(BASE + 0x1000, &[1; 8], 8, 5, 0x1000);
        s.memsz = u64::MAX - 100;
        let elf = build_k(BASE + 0x1000, &[s]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::AddressOverflow);

        let mut s = seg(u64::MAX - 4, &[1; 8], 8, 5, 0x1000);
        s.memsz = 8;
        let elf = build_k(BASE + 0x1000, &[s]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::AddressOverflow);
    }

    #[test]
    fn source_beyond_file_is_rejected() {
        let mut s = seg(BASE + 0x1000, &[1; 8], 8, 5, 0x1000);
        s.filesz = 0x10_0000; // el archivo no tiene tanto
        s.memsz = 0x10_0000;
        let elf = build_k(BASE + 0x1000, &[s]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::SegmentOutsideFile);

        // p_offset + p_filesz desborda u64: se parchea el campo a mano.
        let mut elf = build_k(BASE + 0x1000, &[seg(BASE + 0x1000, &[1; 8], 8, 5, 0x1000)]);
        set_u64(&mut elf, 64 + 56 + 8, u64::MAX - 2); // segmento 1, p_offset
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::AddressOverflow);
    }

    #[test]
    fn overlapping_segments_are_rejected() {
        let elf = build_k(BASE + 0x1000, &[
            seg(BASE + 0x1000, &[1; 0x100], 0x100, 5, 0x1000),
            seg(BASE + 0x1080, &[2; 0x100], 0x100, 4, 0x2000),
        ]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::SegmentsOverlap);
    }

    #[test]
    fn writable_and_executable_is_rejected() {
        let elf = build_k(BASE + 0x1000, &[seg(BASE + 0x1000, &[1; 8], 8, 7, 0x1000)]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::WritableAndExecutable);
    }

    #[test]
    fn wrong_base_is_rejected() {
        let elf = build(2, BASE + 0x3000, &[seg(BASE + 0x3000, &[1; 8], 8, 5, 0x1000)]);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::BaseMismatch);
    }

    #[test]
    fn entry_must_be_inside_an_executable_segment() {
        let segs = || [
            seg(BASE + 0x1000, &[1; 64], 64, 5, 0x1000),
            seg(BASE + 0x2000, &[2; 64], 64, 4, 0x2000),
        ];
        // fuera de toda imagen
        let elf = build_k(BASE + 0x9000, &segs());
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::EntryNotInExecutableSegment);
        // dentro de la imagen pero en un segmento de solo lectura
        let elf = build_k(BASE + 0x2000, &segs());
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::EntryNotInExecutableSegment);
        // justo despues del final del segmento ejecutable
        let elf = build_k(BASE + 0x1000 + 64, &segs());
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::EntryNotInExecutableSegment);
    }

    #[test]
    fn too_many_segments_are_rejected() {
        let mut v = Vec::new();
        for i in 0..(MAX_SEGMENTS as u64 + 1) {
            v.push(seg(BASE + i * 0x1000, &[1; 8], 8, 5, 0x1000 + i * 0x1000));
        }
        let elf = build(2, BASE, &v);
        assert_eq!(plan_load(&elf, REGION).unwrap_err(), ElfError::TooManySegments);
    }

    #[test]
    fn load_into_rejects_a_wrong_buffer() {
        let elf = good();
        let plan = plan_load(&elf, REGION).unwrap();
        let mut small = std::vec![0u8; plan.image_size as usize - 1];
        assert_eq!(load_into(&plan, &elf, &mut small).unwrap_err(), ElfError::ImageBufferMismatch);
    }

    #[test]
    fn truncated_elf_never_panics() {
        // Cualquier prefijo del ELF valido da Ok o un error, nunca un panico.
        let elf = good();
        for n in 0..elf.len() {
            let _ = plan_load(&elf[..n], REGION);
        }
    }

    #[test]
    fn region_arithmetic_overflow_is_an_error() {
        let elf = good();
        let r = Region { base: u64::MAX - 10, max_size: 100 };
        assert_eq!(plan_load(&elf, r).unwrap_err(), ElfError::AddressOverflow);
    }
}
