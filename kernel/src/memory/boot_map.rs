// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Lectura y validacion del `BootInfo` y del mapa de memoria que entrega el bootloader.
//!
//! El kernel no se fia del puntero: comprueba nulo, alineacion, que este dentro del
//! identity map (< 4 GiB), el magic, el tamano del descriptor y que la tabla de regiones
//! quepa. Si algo falla devuelve un error y el llamante usa los valores por defecto
//! (4 GiB, primeros 32 MiB reservados) avisando por el puerto serie.

use trunomy_abi::boot::{BootInfo, MemRegion, BOOT_INFO_MAGIC, MAX_REGIONS};

/// El bootloader entrega todo por debajo de 4 GiB (identity map).
pub const LOW_LIMIT: u64 = 0x1_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMapError {
    NullInfo,
    Misaligned,
    AboveLowLimit,
    BadMagic,
    NoMap,
    BadDescSize,
    TooManyRegions,
    TableOutOfRange,
}

impl BootMapError {
    pub const fn name(self) -> &'static str {
        match self {
            BootMapError::NullInfo => "NullInfo",
            BootMapError::Misaligned => "Misaligned",
            BootMapError::AboveLowLimit => "AboveLowLimit",
            BootMapError::BadMagic => "BadMagic",
            BootMapError::NoMap => "NoMap",
            BootMapError::BadDescSize => "BadDescSize",
            BootMapError::TooManyRegions => "TooManyRegions",
            BootMapError::TableOutOfRange => "TableOutOfRange",
        }
    }
}

/// Comprueba un `BootInfo` ya copiado al kernel.
pub fn validate(info: &BootInfo, limit: u64) -> Result<(), BootMapError> {
    if info.magic != BOOT_INFO_MAGIC {
        return Err(BootMapError::BadMagic);
    }
    if info.mmap_ptr == 0 || info.mmap_len == 0 {
        return Err(BootMapError::NoMap);
    }
    if info.mmap_desc_size != MemRegion::SIZE as u64 {
        return Err(BootMapError::BadDescSize);
    }
    if info.mmap_len > MAX_REGIONS as u64 {
        return Err(BootMapError::TooManyRegions);
    }
    if info.mmap_ptr % 8 != 0 {
        return Err(BootMapError::Misaligned);
    }
    let bytes = info.mmap_len * MemRegion::SIZE as u64; // <= 2048*24: no desborda
    match info.mmap_ptr.checked_add(bytes) {
        Some(end) if end <= limit => Ok(()),
        _ => Err(BootMapError::TableOutOfRange),
    }
}

/// Lee `BootInfo` y la tabla de regiones. `limit` es el tope de direcciones aceptable
/// (`LOW_LIMIT` en el kernel real; mas alto en los tests del host).
///
/// # Safety
/// `info_ptr` debe apuntar a memoria legible del bootloader si pasa las comprobaciones;
/// el bootloader garantiza que sigue intacta tras ExitBootServices.
pub unsafe fn read_with_limit(
    info_ptr: u64,
    limit: u64,
) -> Result<(BootInfo, &'static [MemRegion]), BootMapError> {
    if info_ptr == 0 {
        return Err(BootMapError::NullInfo);
    }
    if info_ptr % 8 != 0 {
        return Err(BootMapError::Misaligned);
    }
    match info_ptr.checked_add(core::mem::size_of::<BootInfo>() as u64) {
        Some(end) if end <= limit => {}
        _ => return Err(BootMapError::AboveLowLimit),
    }
    let info = core::ptr::read_volatile(info_ptr as *const BootInfo);
    validate(&info, limit)?;
    let regions = core::slice::from_raw_parts(info.mmap_ptr as *const MemRegion, info.mmap_len as usize);
    Ok((info, regions))
}

pub unsafe fn read(info_ptr: u64) -> Result<(BootInfo, &'static [MemRegion]), BootMapError> {
    read_with_limit(info_ptr, LOW_LIMIT)
}

/// Rangos fisicos que el kernel nunca debe repartir aunque el mapa los diga libres:
/// imagen del kernel, shell cargada por el bootloader, la pagina del `BootInfo` y la tabla
/// de regiones. (Si el firmware los marco como LOADER_* ya estan reservados; esto es defensa
/// en profundidad ante un mapa incorrecto.) `(0, 0)` = ausente.
pub fn reserved_ranges(info: &BootInfo, info_ptr: u64) -> [(u64, u64); 4] {
    let span = |start: u64, len: u64| {
        if start == 0 || len == 0 { (0, 0) } else { (start, start.saturating_add(len)) }
    };
    [
        span(info.kernel_base, info.kernel_size),
        span(info.shell_ptr, info.shell_size),
        span(info_ptr, core::mem::size_of::<BootInfo>() as u64),
        span(info.mmap_ptr, info.mmap_len.saturating_mul(MemRegion::SIZE as u64)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use trunomy_abi::boot::REGION_USABLE;

    fn info(mmap_ptr: u64, len: u64) -> BootInfo {
        BootInfo {
            magic: BOOT_INFO_MAGIC,
            pml4_pa: 0x1000,
            kernel_base: 0x20_0000,
            kernel_size: 0x1_0001,
            shell_ptr: 0,
            shell_size: 0,
            mmap_ptr,
            mmap_len: len,
            mmap_desc_size: MemRegion::SIZE as u64,
        }
    }

    #[test]
    fn valid_info_passes_and_each_defect_is_named() {
        assert_eq!(validate(&info(0x8000, 10), LOW_LIMIT), Ok(()));
        let mut i = info(0x8000, 10);
        i.magic ^= 1;
        assert_eq!(validate(&i, LOW_LIMIT), Err(BootMapError::BadMagic));
        assert_eq!(validate(&info(0, 10), LOW_LIMIT), Err(BootMapError::NoMap));
        assert_eq!(validate(&info(0x8000, 0), LOW_LIMIT), Err(BootMapError::NoMap));
        let mut i = info(0x8000, 10);
        i.mmap_desc_size = 40;
        assert_eq!(validate(&i, LOW_LIMIT), Err(BootMapError::BadDescSize));
        assert_eq!(validate(&info(0x8000, MAX_REGIONS as u64 + 1), LOW_LIMIT), Err(BootMapError::TooManyRegions));
        assert_eq!(validate(&info(0x8004, 10), LOW_LIMIT), Err(BootMapError::Misaligned));
        assert_eq!(validate(&info(LOW_LIMIT - 16, 10), LOW_LIMIT), Err(BootMapError::TableOutOfRange));
        assert_eq!(validate(&info(u64::MAX - 7, 10), LOW_LIMIT), Err(BootMapError::TableOutOfRange));
    }

    #[test]
    fn read_rejects_bad_pointers_before_touching_memory() {
        unsafe {
            assert_eq!(read(0).err(), Some(BootMapError::NullInfo));
            assert_eq!(read(0x1003).err(), Some(BootMapError::Misaligned));
            assert_eq!(read(LOW_LIMIT).err(), Some(BootMapError::AboveLowLimit));
            assert_eq!(read(u64::MAX - 7).err(), Some(BootMapError::AboveLowLimit));
        }
    }

    #[test]
    fn read_round_trips_a_real_table() {
        let regions = [
            MemRegion { base: 0x10_0000, pages: 16, kind: REGION_USABLE, _pad: 0 },
            MemRegion { base: 0x20_0000, pages: 8, kind: 2, _pad: 0 },
        ];
        let boxed = alloc::boxed::Box::new(info(regions.as_ptr() as u64, 2));
        let ptr = &*boxed as *const BootInfo as u64;
        let (got, table) = unsafe { read_with_limit(ptr, u64::MAX) }.unwrap();
        assert_eq!(got, *boxed);
        assert_eq!(table, &regions);
    }

    #[test]
    fn reserved_ranges_cover_kernel_shell_info_and_table() {
        let mut i = info(0x8000, 3);
        i.shell_ptr = 0x90_0000;
        i.shell_size = 0x1234;
        let r = reserved_ranges(&i, 0x7000);
        assert_eq!(r[0], (0x20_0000, 0x21_0001));
        assert_eq!(r[1], (0x90_0000, 0x90_1234));
        assert_eq!(r[2], (0x7000, 0x7000 + 72));
        assert_eq!(r[3], (0x8000, 0x8000 + 72));
        // sin shell
        assert_eq!(reserved_ranges(&info(0x8000, 1), 0x7000)[1], (0, 0));
    }
}
