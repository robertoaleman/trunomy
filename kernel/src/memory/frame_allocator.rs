// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/memory/frame_allocator.rs

use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysFrame(pub u64);

impl PhysFrame {
    pub const SIZE: u64 = 4096;
    pub fn start_address(&self) -> u64 {
        self.0
    }
}

const BITMAP_SIZE_BYTES: usize = 131072;

/// Por que se rechazo liberar un marco (I-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// La direccion no es multiplo del tamano de pagina.
    Unaligned,
    /// Fuera de la memoria gestionada.
    OutOfRange,
    /// El marco no esta asignado por este allocator: doble liberacion, nunca asignado,
    /// o reservado (kernel/firmware). Solo se puede liberar lo que `allocate_frame` entrego.
    NotOwned,
}

pub struct BitmapFrameAllocator {
    bitmap: [u8; BITMAP_SIZE_BYTES],
    /// Bit a 1 = el marco fue entregado por `allocate_frame` y sigue vivo. Separado de
    /// `bitmap` para distinguir "reservado" de "asignado" (I-17).
    owned: [u8; BITMAP_SIZE_BYTES],
    total_frames: usize,
    last_allocated_index: usize,
}

impl BitmapFrameAllocator {
    pub const fn new() -> Self {
        Self {
            bitmap: [0xFF; BITMAP_SIZE_BYTES],
            owned: [0; BITMAP_SIZE_BYTES],
            total_frames: 0,
            last_allocated_index: 0,
        }
    }

    pub fn init(&mut self, total_memory_bytes: u64) {
        self.total_frames = (total_memory_bytes / PhysFrame::SIZE) as usize;

        // 1. Marcar por defecto todo como reservado/usado
        for i in 0..BITMAP_SIZE_BYTES {
            self.bitmap[i] = 0xFF;
            self.owned[i] = 0;
        }

        // 2. Liberar memoria disponible omitiendo el primer 1 MB (primeros 256 marcos)
        // Esto evita que allocate_frame devuelva memoria reservada de BIOS/EBDA (0x9F000 - 0xBFFFF)
        let reserved_frames = 256;
        if self.total_frames > reserved_frames {
            for frame_idx in reserved_frames..self.total_frames {
                let byte_idx = frame_idx / 8;
                let bit_idx = frame_idx % 8;
                if byte_idx < BITMAP_SIZE_BYTES {
                    self.bitmap[byte_idx] &= !(1 << bit_idx);
                }
            }
        }

        self.last_allocated_index = reserved_frames;
    }

    /// Inicializa desde el mapa de memoria real del firmware. Fail-closed: todo es
    /// "reservado" salvo lo que el firmware declaro `REGION_USABLE`, y despues se quita
    /// de nuevo lo que cae en una region no usable, en el primer MiB o en `reserved`
    /// (kernel, shell, BootInfo, tabla del mapa). Las regiones mal formadas (sin paginas,
    /// desalineadas o que desbordan) se ignoran. Solo se gestiona memoria < 4 GiB, que es
    /// lo que cubre el bitmap y el identity map. Devuelve el numero de marcos libres.
    pub fn init_from_regions(
        &mut self,
        regions: &[trunomy_abi::boot::MemRegion],
        reserved: &[(u64, u64)],
    ) -> usize {
        use trunomy_abi::boot::REGION_USABLE;
        const LIMIT_FRAMES: usize = BITMAP_SIZE_BYTES * 8; // 4 GiB
        const LOW_RESERVED_FRAMES: usize = 256; // primer MiB: BIOS/EBDA/vectores

        for i in 0..BITMAP_SIZE_BYTES {
            self.bitmap[i] = 0xFF;
            self.owned[i] = 0;
        }
        self.last_allocated_index = LOW_RESERVED_FRAMES;

        let valid = |r: &trunomy_abi::boot::MemRegion| -> Option<(usize, usize)> {
            if r.pages == 0 || r.base % PhysFrame::SIZE != 0 {
                return None;
            }
            let bytes = r.pages.checked_mul(PhysFrame::SIZE)?;
            let end = r.base.checked_add(bytes)?;
            let first = (r.base / PhysFrame::SIZE) as usize;
            let last = ((end / PhysFrame::SIZE) as usize).min(LIMIT_FRAMES);
            if first >= last { None } else { Some((first, last)) }
        };

        let mut highest = 0usize;
        // Pasada 1: lo usable queda libre.
        for r in regions.iter().filter(|r| r.kind == REGION_USABLE) {
            if let Some((first, last)) = valid(r) {
                for f in first..last {
                    self.bitmap[f / 8] &= !(1 << (f % 8));
                }
                highest = highest.max(last);
            }
        }
        // Pasada 2: lo no usable gana siempre sobre lo usable (regiones solapadas).
        for r in regions.iter().filter(|r| r.kind != REGION_USABLE) {
            if let Some((first, last)) = valid(r) {
                for f in first..last {
                    self.bitmap[f / 8] |= 1 << (f % 8);
                }
            }
        }
        // Reservas explicitas del kernel (redondeadas a paginas, hacia afuera).
        for &(start, end) in reserved {
            if end <= start {
                continue;
            }
            let first = (start / PhysFrame::SIZE) as usize;
            let last = (((end - 1) / PhysFrame::SIZE) as usize + 1).min(LIMIT_FRAMES);
            for f in first..last {
                self.bitmap[f / 8] |= 1 << (f % 8);
            }
        }
        for f in 0..LOW_RESERVED_FRAMES {
            self.bitmap[f / 8] |= 1 << (f % 8);
        }

        self.total_frames = highest;
        let mut free = 0;
        for f in 0..highest {
            if self.bitmap[f / 8] & (1 << (f % 8)) == 0 {
                free += 1;
            }
        }
        free
    }

    pub fn set_frame_used(&mut self, frame: PhysFrame, used: bool) {
        let frame_idx = (frame.start_address() / PhysFrame::SIZE) as usize;
        if frame_idx >= self.total_frames {
            return;
        }

        let byte_idx = frame_idx / 8;
        let bit_idx = frame_idx % 8;

        if byte_idx < BITMAP_SIZE_BYTES {
            if used {
                self.bitmap[byte_idx] |= 1 << bit_idx;
            } else {
                self.bitmap[byte_idx] &= !(1 << bit_idx);
            }
        }
    }

    pub fn allocate_frame(&mut self) -> Option<u64> {
        if self.total_frames == 0 {
            return None;
        }

        let start = self.last_allocated_index;

        for i in 0..self.total_frames {
            let frame_idx = (start + i) % self.total_frames;
            let byte_idx = frame_idx / 8;
            let bit_idx = frame_idx % 8;

            if byte_idx >= BITMAP_SIZE_BYTES {
                break;
            }

            if (self.bitmap[byte_idx] & (1 << bit_idx)) == 0 {
                self.bitmap[byte_idx] |= 1 << bit_idx;
                self.owned[byte_idx] |= 1 << bit_idx;
                self.last_allocated_index = frame_idx + 1;
                return Some((frame_idx as u64) * PhysFrame::SIZE);
            }
        }

        None
    }

    /// Reserva `count` marcos CONSECUTIVOS (para colas de DMA, que el dispositivo ve como una sola
    /// region). Devuelve la direccion del primero; todos quedan asignados (`owned`) y se liberan uno a
    /// uno con `deallocate_frame`. Si no hay un hueco asi, no cambia nada.
    pub fn allocate_contiguous(&mut self, count: usize) -> Option<u64> {
        if count == 0 || count > self.total_frames {
            return None;
        }
        let is_free = |a: &Self, f: usize| a.bitmap[f / 8] & (1 << (f % 8)) == 0;
        let mut run = 0usize;
        for f in 0..self.total_frames.min(BITMAP_SIZE_BYTES * 8) {
            run = if is_free(self, f) { run + 1 } else { 0 };
            if run == count {
                let first = f + 1 - count;
                for g in first..=f {
                    self.bitmap[g / 8] |= 1 << (g % 8);
                    self.owned[g / 8] |= 1 << (g % 8);
                }
                return Some(first as u64 * PhysFrame::SIZE);
            }
        }
        None
    }

    /// Marcos libres ahora mismo (para el log de arranque y las pruebas).
    pub fn total_frame_count(&self) -> usize {
        self.total_frames
    }

    pub fn free_frames(&self) -> usize {
        (0..self.total_frames).filter(|f| self.bitmap[f / 8] & (1 << (f % 8)) == 0).count()
    }

    #[cfg(test)]
    pub fn is_owned(&self, frame_addr: u64) -> bool {
        let idx = (frame_addr / PhysFrame::SIZE) as usize;
        idx < self.total_frames && self.owned[idx / 8] & (1 << (idx % 8)) != 0
    }

    /// Libera un marco asignado: valida, BORRA el contenido con `scrub` y solo entonces lo
    /// marca libre (I-16, I-17). El borrado ocurre bajo el candado del allocator, de modo que
    /// nadie puede reasignar el marco antes de que quede a cero. Si algo falla no se borra
    /// nada y el estado no cambia.
    pub fn deallocate_frame_with(
        &mut self,
        frame_addr: u64,
        scrub: &mut dyn FnMut(u64),
    ) -> Result<(), FrameError> {
        if frame_addr % PhysFrame::SIZE != 0 {
            return Err(FrameError::Unaligned);
        }
        let idx = (frame_addr / PhysFrame::SIZE) as usize;
        if idx >= self.total_frames || idx / 8 >= BITMAP_SIZE_BYTES {
            return Err(FrameError::OutOfRange);
        }
        let (byte_idx, bit) = (idx / 8, 1u8 << (idx % 8));
        if self.owned[byte_idx] & bit == 0 {
            return Err(FrameError::NotOwned);
        }
        scrub(frame_addr);
        self.owned[byte_idx] &= !bit;
        self.bitmap[byte_idx] &= !bit;
        Ok(())
    }

    /// Libera con el borrado real de memoria fisica.
    #[allow(dead_code)]
    pub fn deallocate_frame(&mut self, frame_addr: u64) -> Result<(), FrameError> {
        self.deallocate_frame_with(frame_addr, &mut scrub_frame_phys)
    }
}

/// Pone a cero un marco fisico (identity map del kernel). Escrituras volatiles: el
/// compilador no puede eliminarlas por "memoria que ya no se lee".
#[cfg(not(test))]
fn scrub_frame_phys(frame_addr: u64) {
    let ptr = frame_addr as *mut u8;
    for i in 0..PhysFrame::SIZE as usize {
        unsafe { core::ptr::write_volatile(ptr.add(i), 0) };
    }
}

/// En tests no se toca memoria fisica real; se usa `deallocate_frame_with`.
#[cfg(test)]
fn scrub_frame_phys(_frame_addr: u64) {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    fn allocator() -> Box<BitmapFrameAllocator> {
        let mut a = Box::new(BitmapFrameAllocator::new());
        a.init(8 * 1024 * 1024);
        a
    }

    #[test]
    fn allocated_frames_are_unique_and_owned() {
        let mut a = allocator();
        let mut seen = Vec::new();
        for _ in 0..64 {
            let f = a.allocate_frame().unwrap();
            assert!(a.is_owned(f));
            assert!(!seen.contains(&f), "aliasing: marco entregado dos veces");
            seen.push(f);
        }
    }

    #[test]
    fn contiguous_runs_are_consecutive_owned_and_skip_holes_that_are_too_small() {
        let mut a = allocator();
        let first = a.allocate_contiguous(10).unwrap();
        for i in 0..10 {
            assert!(a.is_owned(first + i * PhysFrame::SIZE));
        }
        // un hueco de 2 marcos entre dos ocupados no sirve para 4
        let hole = a.allocate_contiguous(2).unwrap();
        let _after = a.allocate_contiguous(1).unwrap();
        a.deallocate_frame_with(hole, &mut |_| {}).unwrap();
        a.deallocate_frame_with(hole + PhysFrame::SIZE, &mut |_| {}).unwrap();
        let four = a.allocate_contiguous(4).unwrap();
        assert!(four + 4 * PhysFrame::SIZE <= hole || four >= hole + 2 * PhysFrame::SIZE, "no debe invadir lo ocupado");
        assert_eq!(a.allocate_contiguous(0), None);
        assert_eq!(a.allocate_contiguous(usize::MAX), None);
    }

    #[test]
    fn a_failed_contiguous_request_changes_nothing() {
        let mut a = allocator();
        let free = a.free_frames();
        assert_eq!(a.allocate_contiguous(free + 1), None);
        assert_eq!(a.free_frames(), free);
    }

    #[test]
    fn free_scrubs_before_the_frame_can_be_reused() {
        let mut a = allocator();
        let f = a.allocate_frame().unwrap();
        // memoria fisica simulada: el marco contiene un secreto
        let mut mem = alloc::vec![0xAAu8; 4096];
        let mut calls = 0;
        a.deallocate_frame_with(f, &mut |addr| {
            assert_eq!(addr, f);
            mem.iter_mut().for_each(|b| *b = 0);
            calls += 1;
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert!(mem.iter().all(|b| *b == 0));
        assert!(!a.is_owned(f));
        // se puede volver a asignar (el siguiente marco libre; recorre en circulo)
        let mut again = Vec::new();
        while let Some(x) = a.allocate_frame() {
            again.push(x);
        }
        assert!(again.contains(&f));
    }

    #[test]
    fn double_free_is_rejected_and_does_not_scrub() {
        let mut a = allocator();
        let f = a.allocate_frame().unwrap();
        a.deallocate_frame_with(f, &mut |_| {}).unwrap();
        let mut scrubbed = false;
        assert_eq!(a.deallocate_frame_with(f, &mut |_| scrubbed = true), Err(FrameError::NotOwned));
        assert!(!scrubbed);
    }

    #[test]
    fn reserved_and_never_allocated_frames_cannot_be_freed() {
        let mut a = allocator();
        // por debajo de 1 MiB: reservado desde init
        assert_eq!(a.deallocate_frame_with(0x9F000, &mut |_| panic!("no debe borrar")), Err(FrameError::NotOwned));
        // marcado como usado a mano (kernel): no es "owned"
        a.set_frame_used(PhysFrame(0x40_0000), true);
        assert_eq!(a.deallocate_frame_with(0x40_0000, &mut |_| panic!("no debe borrar")), Err(FrameError::NotOwned));
        // libre y nunca asignado
        assert_eq!(a.deallocate_frame_with(0x70_0000, &mut |_| panic!()), Err(FrameError::NotOwned));
    }

    #[test]
    fn unaligned_and_out_of_range_are_rejected() {
        let mut a = allocator();
        let f = a.allocate_frame().unwrap();
        assert_eq!(a.deallocate_frame_with(f + 8, &mut |_| panic!()), Err(FrameError::Unaligned));
        assert_eq!(a.deallocate_frame_with(0x1_0000_0000, &mut |_| panic!()), Err(FrameError::OutOfRange));
        assert!(a.is_owned(f)); // sin cambios
    }

    use trunomy_abi::boot::{MemRegion, REGION_RESERVED, REGION_USABLE};

    fn region(base: u64, pages: u64, kind: u32) -> MemRegion {
        MemRegion { base, pages, kind, _pad: 0 }
    }

    fn is_free(a: &BitmapFrameAllocator, addr: u64) -> bool {
        let f = (addr / PhysFrame::SIZE) as usize;
        f < a.total_frames && a.bitmap[f / 8] & (1 << (f % 8)) == 0
    }

    #[test]
    fn only_usable_regions_become_free() {
        let mut a = Box::new(BitmapFrameAllocator::new());
        let free = a.init_from_regions(
            &[
                region(0x0, 0x9F, REGION_USABLE),         // usable pero bajo 1 MiB: reservado igual
                region(0x10_0000, 0x100, REGION_USABLE),  // 1..2 MiB
                region(0x20_0000, 0x40, REGION_RESERVED), // kernel
                region(0x24_0000, 0x1C0, REGION_USABLE),
            ],
            &[],
        );
        assert_eq!(free, 0x100 + 0x1C0);
        assert!(!is_free(&a, 0x9000));
        assert!(is_free(&a, 0x10_0000));
        assert!(!is_free(&a, 0x20_0000));
        assert!(is_free(&a, 0x24_0000));
        assert!(!is_free(&a, 0x40_0000), "fuera de toda region usable");
    }

    #[test]
    fn reserved_wins_over_overlapping_usable_and_explicit_ranges_are_removed() {
        let mut a = Box::new(BitmapFrameAllocator::new());
        let free = a.init_from_regions(
            &[region(0x10_0000, 0x100, REGION_USABLE), region(0x10_8000, 4, REGION_RESERVED)],
            &[(0x11_0001, 0x11_2000)], // desalineado: se redondea hacia afuera a 0x11_0000..0x11_2000
        );
        assert!(is_free(&a, 0x10_7000));
        assert!(!is_free(&a, 0x10_8000));
        assert!(!is_free(&a, 0x10_B000));
        assert!(is_free(&a, 0x10_C000));
        assert!(!is_free(&a, 0x11_0000));
        assert!(!is_free(&a, 0x11_1000));
        assert!(is_free(&a, 0x11_2000));
        assert_eq!(free, 0x100 - 4 - 2);
    }

    #[test]
    fn malformed_and_overflowing_regions_are_ignored() {
        let mut a = Box::new(BitmapFrameAllocator::new());
        let free = a.init_from_regions(
            &[
                region(0x10_0001, 4, REGION_USABLE),        // desalineada
                region(0x20_0000, 0, REGION_USABLE),        // sin paginas
                region(u64::MAX - 0xFFF, 8, REGION_USABLE), // desborda
                region(0x1_0000_0000, 16, REGION_USABLE),   // por encima de 4 GiB
                region(0x30_0000, 4, REGION_USABLE),        // la unica valida
            ],
            &[],
        );
        assert_eq!(free, 4);
        assert!(is_free(&a, 0x30_0000));
    }

    #[test]
    fn allocation_only_returns_frames_from_usable_memory() {
        let mut a = Box::new(BitmapFrameAllocator::new());
        a.init_from_regions(&[region(0x50_0000, 8, REGION_USABLE)], &[(0x50_2000, 0x50_3000)]);
        let mut got = Vec::new();
        while let Some(f) = a.allocate_frame() {
            got.push(f);
        }
        got.sort();
        let expected: Vec<u64> = (0..8u64).filter(|i| *i != 2).map(|i| 0x50_0000 + i * 0x1000).collect();
        assert_eq!(got, expected);
        assert_eq!(a.deallocate_frame_with(0x50_2000, &mut |_| panic!()), Err(FrameError::NotOwned));
    }
}

pub static BITMAP_ALLOCATOR: Mutex<BitmapFrameAllocator> = Mutex::new(BitmapFrameAllocator::new());
