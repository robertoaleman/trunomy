// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Virtqueue "split" (formato legacy) con el dispositivo como parte NO confiable (I-46).
//!
//! Este modulo es logica pura sobre una memoria abstracta (`Mem`): se prueba en el host contra un
//! "dispositivo" simulado, honesto y hostil. No toca hardware: la reserva de marcos, el registro de la
//! cola en el dispositivo y el bus master son de `nic`.
//!
//! Reglas (lo que el kernel garantiza aunque el dispositivo mienta):
//! - Estado en sombra: lo que se publico (direccion, largo, sentido de cada buffer) vive en memoria del
//!   kernel; la tabla de descriptores en memoria compartida NUNCA se vuelve a leer.
//! - Ventana de DMA: el kernel solo programa direcciones dentro de `[window_start, window_end)`, con
//!   aritmetica comprobada y largo no nulo. (Sin IOMMU esto limita lo que el kernel PIDE, no lo que un
//!   dispositivo malicioso podria intentar por su cuenta: eso solo lo cubre un IOMMU.)
//! - Lo que informa el dispositivo se valida: `used.idx` no puede adelantarse mas de lo publicado, el id
//!   debe ser de un descriptor en vuelo, no puede completarse dos veces y `len` no puede exceder el
//!   buffer. Cualquier violacion ENVENENA la cola: no se vuelve a leer ni a publicar (falla cerrado).
//! - Los indices son de 16 bits con desbordamiento, como pide virtio.

use alloc::vec::Vec;

/// Tamano maximo de cola que se acepta (el dispositivo lo fija; el kernel no lo elige en legacy).
pub const MAX_QUEUE_SIZE: u16 = 256;
const PAGE: usize = 4096;

const DESC_SIZE: usize = 16;
pub const DESC_F_WRITE: u16 = 2;

/// Acceso a la memoria compartida con el dispositivo. Los desplazamientos son relativos al inicio de la cola.
pub trait Mem {
    fn len(&self) -> usize;
    fn read_u16(&self, off: usize) -> u16;
    fn read_u32(&self, off: usize) -> u32;
    fn write_u16(&mut self, off: usize, v: u16);
    fn write_u32(&mut self, off: usize, v: u32);
    fn write_u64(&mut self, off: usize, v: u64);
    /// Barrera de memoria entre escribir descriptores/anillo y publicar el indice (y al reves al leer).
    fn barrier(&self);
    /// Pone a cero toda la region.
    fn zero(&mut self);
    /// Copia `out.len()` bytes desde `off` (el llamador ya comprobo el rango).
    fn read_bytes(&self, off: usize, out: &mut [u8]);
    /// Copia `data` a partir de `off` (el llamador ya comprobo el rango).
    fn write_bytes(&mut self, off: usize, data: &[u8]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// No es potencia de dos entre 1 y `MAX_QUEUE_SIZE`.
    BadSize,
    /// La memoria ofrecida no alcanza para el formato.
    MemTooSmall,
    /// La ventana de DMA esta vacia o invertida.
    BadWindow,
}

/// Desplazamientos del formato legacy para una cola de `size` entradas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub size: u16,
    pub avail: usize,
    pub used: usize,
    /// Bytes totales, redondeados a pagina.
    pub total: usize,
}

impl Layout {
    pub fn for_size(size: u16) -> Result<Layout, LayoutError> {
        if size == 0 || size > MAX_QUEUE_SIZE || !size.is_power_of_two() {
            return Err(LayoutError::BadSize);
        }
        let n = size as usize;
        let avail = DESC_SIZE * n;
        let avail_end = avail + 4 + 2 * n + 2;
        let used = (avail_end + PAGE - 1) / PAGE * PAGE;
        let used_end = used + 4 + 8 * n + 2;
        Ok(Layout { size, avail, used, total: (used_end + PAGE - 1) / PAGE * PAGE })
    }
    pub(super) fn avail_idx(&self) -> usize { self.avail + 2 }
    pub(super) fn avail_ring(&self, slot: usize) -> usize { self.avail + 4 + 2 * slot }
    pub(super) fn used_idx(&self) -> usize { self.used + 2 }
    pub(super) fn used_ring(&self, slot: usize) -> usize { self.used + 4 + 8 * slot }
}

/// Por que se envenena una cola: el dispositivo informo algo imposible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// `used.idx` avanzo mas que los buffers publicados.
    UsedOverrun,
    /// El id devuelto no es un descriptor valido o no estaba en vuelo (incluye completarlo dos veces).
    BadId,
    /// El largo informado excede el del buffer.
    BadLen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostError {
    /// Direccion/largo fuera de la ventana de DMA, largo cero o desbordamiento.
    OutsideWindow,
    /// Todos los descriptores estan en vuelo.
    Full,
    /// La cola esta envenenada: no se publica nada mas.
    Poisoned(RingError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Posted {
    addr: u64,
    cap: u32,
}

/// Un buffer devuelto por el dispositivo, ya validado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub id: u16,
    pub addr: u64,
    /// Bytes que el dispositivo dice haber escrito (siempre `<=` al buffer).
    pub len: u32,
}

pub struct Vring<M: Mem> {
    mem: M,
    layout: Layout,
    window: (u64, u64),
    free: Vec<u16>,
    inflight: Vec<Option<Posted>>,
    avail_idx: u16,
    last_used: u16,
    poisoned: Option<RingError>,
}

impl<M: Mem> Vring<M> {
    /// Prepara una cola de `size` entradas sobre `mem` (que se pone a cero). Los buffers que se
    /// publiquen deben caer en `[window_start, window_end)`.
    pub fn new(mut mem: M, size: u16, window_start: u64, window_end: u64) -> Result<Self, LayoutError> {
        let layout = Layout::for_size(size)?;
        if mem.len() < layout.total {
            return Err(LayoutError::MemTooSmall);
        }
        if window_start >= window_end {
            return Err(LayoutError::BadWindow);
        }
        mem.zero();
        Ok(Self {
            mem,
            layout,
            window: (window_start, window_end),
            free: (0..size).rev().collect(),
            inflight: alloc::vec![None; size as usize],
            avail_idx: 0,
            last_used: 0,
            poisoned: None,
        })
    }

    pub fn layout(&self) -> Layout { self.layout }
    pub fn poisoned(&self) -> Option<RingError> { self.poisoned }
    pub fn in_flight(&self) -> usize { self.layout.size as usize - self.free.len() }
    #[cfg(test)]
    pub fn mem(&self) -> &M { &self.mem }

    /// Publica un buffer de `len` bytes en `addr`. `device_writes`: el dispositivo escribira en el
    /// (recepcion); si no, solo lo lee (envio). Devuelve el id del descriptor. El llamante debe avisar
    /// despues al dispositivo (notificacion).
    pub fn post(&mut self, addr: u64, len: u32, device_writes: bool) -> Result<u16, PostError> {
        if let Some(e) = self.poisoned {
            return Err(PostError::Poisoned(e));
        }
        let end = addr.checked_add(len as u64).ok_or(PostError::OutsideWindow)?;
        if len == 0 || addr < self.window.0 || end > self.window.1 {
            return Err(PostError::OutsideWindow);
        }
        let id = self.free.pop().ok_or(PostError::Full)?;
        let d = id as usize * DESC_SIZE;
        self.mem.write_u64(d, addr);
        self.mem.write_u32(d + 8, len);
        self.mem.write_u16(d + 12, if device_writes { DESC_F_WRITE } else { 0 });
        self.mem.write_u16(d + 14, 0);
        self.inflight[id as usize] = Some(Posted { addr, cap: len });
        let slot = self.avail_idx as usize % self.layout.size as usize;
        self.mem.write_u16(self.layout.avail_ring(slot), id);
        self.mem.barrier();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.mem.write_u16(self.layout.avail_idx(), self.avail_idx);
        Ok(id)
    }

    /// Recoge el siguiente buffer devuelto. `Ok(None)`: no hay nada nuevo. `Err`: el dispositivo
    /// mintio y la cola queda envenenada para siempre.
    pub fn poll(&mut self) -> Result<Option<Completion>, RingError> {
        if let Some(e) = self.poisoned {
            return Err(e);
        }
        let dev_idx = self.mem.read_u16(self.layout.used_idx());
        self.mem.barrier();
        let pending = dev_idx.wrapping_sub(self.last_used) as usize;
        if pending == 0 {
            return Ok(None);
        }
        if pending > self.in_flight() {
            return Err(self.poison(RingError::UsedOverrun));
        }
        let slot = self.last_used as usize % self.layout.size as usize;
        let id = self.mem.read_u32(self.layout.used_ring(slot));
        let len = self.mem.read_u32(self.layout.used_ring(slot) + 4);
        let Some(posted) = u16::try_from(id).ok().and_then(|i| self.inflight.get(i as usize).copied().flatten()) else {
            return Err(self.poison(RingError::BadId));
        };
        if len > posted.cap {
            return Err(self.poison(RingError::BadLen));
        }
        let id = id as u16;
        self.inflight[id as usize] = None;
        self.free.push(id);
        self.last_used = self.last_used.wrapping_add(1);
        Ok(Some(Completion { id, addr: posted.addr, len }))
    }

    fn poison(&mut self, e: RingError) -> RingError {
        self.poisoned = Some(e);
        e
    }
}

/// Reserva de buffers de DMA de tamano fijo dentro de una region: el kernel solo entrega al dispositivo
/// direcciones que salieron de aqui. Contabilidad pura (los datos viven en la region real).
pub struct DmaPool {
    base: u64,
    slot_size: u32,
    used: Vec<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// Direccion que no es el inicio de un slot de este pool.
    NotASlot,
    /// El slot no estaba reservado (doble liberacion).
    NotAllocated,
}

impl DmaPool {
    pub fn new(base: u64, slot_size: u32, slots: usize) -> Option<Self> {
        if slot_size == 0 || slots == 0 || base.checked_add(slot_size as u64 * slots as u64).is_none() {
            return None;
        }
        Some(Self { base, slot_size, used: alloc::vec![false; slots] })
    }

    pub fn window(&self) -> (u64, u64) {
        (self.base, self.base + self.slot_size as u64 * self.used.len() as u64)
    }

    #[cfg(test)]
    pub fn slot_size(&self) -> u32 { self.slot_size }

    #[cfg(test)]
    pub fn free_slots(&self) -> usize { self.used.iter().filter(|u| !**u).count() }

    pub fn alloc(&mut self) -> Option<u64> {
        let i = self.used.iter().position(|u| !*u)?;
        self.used[i] = true;
        Some(self.base + i as u64 * self.slot_size as u64)
    }

    fn index_of(&self, addr: u64) -> Result<usize, PoolError> {
        let off = addr.checked_sub(self.base).ok_or(PoolError::NotASlot)?;
        if off % self.slot_size as u64 != 0 || (off / self.slot_size as u64) as usize >= self.used.len() {
            return Err(PoolError::NotASlot);
        }
        Ok((off / self.slot_size as u64) as usize)
    }

    pub fn free(&mut self, addr: u64) -> Result<(), PoolError> {
        let i = self.index_of(addr)?;
        if !self.used[i] {
            return Err(PoolError::NotAllocated);
        }
        self.used[i] = false;
        Ok(())
    }
}

#[cfg(test)]
pub mod sim {
    use super::*;

    /// Memoria simulada: un `Vec<u8>` con el mismo formato que veria el dispositivo.
    pub struct SimMem(pub Vec<u8>);

    impl SimMem {
        pub fn new(len: usize) -> Self { SimMem(alloc::vec![0xAA; len]) } // basura previa: `new` debe ponerla a cero
        pub fn r16(&self, o: usize) -> u16 { u16::from_le_bytes(self.0[o..o + 2].try_into().unwrap()) }
        pub fn r32(&self, o: usize) -> u32 { u32::from_le_bytes(self.0[o..o + 4].try_into().unwrap()) }
        pub fn r64(&self, o: usize) -> u64 { u64::from_le_bytes(self.0[o..o + 8].try_into().unwrap()) }
    }

    impl Mem for SimMem {
        fn len(&self) -> usize { self.0.len() }
        fn read_u16(&self, o: usize) -> u16 { self.r16(o) }
        fn read_u32(&self, o: usize) -> u32 { self.r32(o) }
        fn write_u16(&mut self, o: usize, v: u16) { self.0[o..o + 2].copy_from_slice(&v.to_le_bytes()) }
        fn write_u32(&mut self, o: usize, v: u32) { self.0[o..o + 4].copy_from_slice(&v.to_le_bytes()) }
        fn write_u64(&mut self, o: usize, v: u64) { self.0[o..o + 8].copy_from_slice(&v.to_le_bytes()) }
        fn barrier(&self) {}
        fn zero(&mut self) { self.0.iter_mut().for_each(|b| *b = 0) }
        fn read_bytes(&self, o: usize, out: &mut [u8]) { out.copy_from_slice(&self.0[o..o + out.len()]) }
        fn write_bytes(&mut self, o: usize, d: &[u8]) { self.0[o..o + d.len()].copy_from_slice(d) }
    }

    /// El "dispositivo": escribe entradas en el anillo usado como lo haria el hardware (o mintiendo).
    pub fn device_complete(ring: &mut Vring<SimMem>, id: u32, len: u32) {
        let l = ring.layout;
        let idx = ring.mem.r16(l.used_idx());
        let slot = idx as usize % l.size as usize;
        ring.mem.write_u32(l.used_ring(slot), id);
        ring.mem.write_u32(l.used_ring(slot) + 4, len);
        ring.mem.write_u16(l.used_idx(), idx.wrapping_add(1));
    }

    pub fn device_set_used_idx(ring: &mut Vring<SimMem>, idx: u16) {
        let o = ring.layout.used_idx();
        ring.mem.write_u16(o, idx);
    }
}

#[cfg(test)]
mod tests {
    use super::sim::*;
    use super::*;

    const WIN: (u64, u64) = (0x10_0000, 0x10_0000 + 16 * 2048);

    fn ring(size: u16) -> Vring<SimMem> {
        let l = Layout::for_size(size).unwrap();
        Vring::new(SimMem::new(l.total), size, WIN.0, WIN.1).unwrap()
    }

    #[test]
    fn the_layout_follows_the_legacy_format_and_rejects_bad_sizes() {
        let l = Layout::for_size(256).unwrap();
        assert_eq!(l.avail, 4096, "256 descriptores de 16 bytes");
        assert_eq!(l.used, 8192, "el anillo usado empieza en la pagina siguiente al disponible");
        assert_eq!(l.total, 12288);
        let one = Layout::for_size(1).unwrap();
        assert_eq!((one.avail, one.used, one.total), (16, 4096, 8192));
        for bad in [0u16, 3, 100, 257, 512, 1024, u16::MAX] {
            assert_eq!(Layout::for_size(bad), Err(LayoutError::BadSize), "{bad}");
        }
    }

    #[test]
    fn construction_zeroes_the_memory_and_checks_its_arguments() {
        let r = ring(8);
        assert!(r.mem().0.iter().all(|b| *b == 0), "la memoria del dispositivo empieza limpia");
        let l = Layout::for_size(8).unwrap();
        assert!(matches!(Vring::new(SimMem::new(l.total - 1), 8, WIN.0, WIN.1), Err(LayoutError::MemTooSmall)));
        assert!(matches!(Vring::new(SimMem::new(l.total), 8, WIN.1, WIN.0), Err(LayoutError::BadWindow)));
        assert!(matches!(Vring::new(SimMem::new(l.total), 8, 5, 5), Err(LayoutError::BadWindow)));
        assert!(matches!(Vring::new(SimMem::new(l.total), 6, WIN.0, WIN.1), Err(LayoutError::BadSize)));
    }

    #[test]
    fn a_posted_buffer_lands_in_the_descriptor_table_and_the_available_ring() {
        let mut r = ring(8);
        let id = r.post(WIN.0 + 2048, 1514, true).unwrap();
        let l = r.layout();
        let d = id as usize * 16;
        assert_eq!(r.mem().r64(d), WIN.0 + 2048);
        assert_eq!(r.mem().r32(d + 8), 1514);
        assert_eq!(r.mem().r16(d + 12), DESC_F_WRITE, "recepcion: el dispositivo escribe");
        assert_eq!(r.mem().r16(l.avail + 4), id, "primera entrada del anillo disponible");
        assert_eq!(r.mem().r16(l.avail + 2), 1, "idx publicado");
        let tx = r.post(WIN.0, 60, false).unwrap();
        assert_eq!(r.mem().r16(tx as usize * 16 + 12), 0, "envio: el dispositivo solo lee");
        assert_eq!(r.mem().r16(l.avail + 2), 2);
        assert_eq!(r.in_flight(), 2);
    }

    #[test]
    fn only_addresses_inside_the_dma_window_are_ever_programmed() {
        let mut r = ring(8);
        let before = r.mem().0.clone();
        for (addr, len) in [
            (WIN.0 - 1, 16),               // empieza antes
            (WIN.1, 1),                    // empieza al final
            (WIN.1 - 8, 16),               // cruza el final
            (0, 4096),                     // la memoria baja del kernel
            (u64::MAX, 2),                 // desbordamiento
            (u64::MAX - 3, 4),             // el fin cae exacto sobre el desborde
            (WIN.0, 0),                    // largo cero
        ] {
            assert_eq!(r.post(addr, len, true), Err(PostError::OutsideWindow), "{addr:#x}+{len}");
        }
        assert_eq!(r.mem().0, before, "una publicacion rechazada no escribe nada");
        assert_eq!(r.in_flight(), 0);
        assert!(r.post(WIN.1 - 16, 16, true).is_ok(), "el ultimo byte de la ventana si");
    }

    #[test]
    fn completions_come_back_in_order_and_ids_are_recycled() {
        let mut r = ring(4);
        let a = r.post(WIN.0, 100, true).unwrap();
        let b = r.post(WIN.0 + 2048, 100, true).unwrap();
        assert_eq!(r.poll(), Ok(None), "el dispositivo aun no devolvio nada");
        device_complete(&mut r, b as u32, 60); // el dispositivo puede devolver en cualquier orden
        let c = r.poll().unwrap().unwrap();
        assert_eq!((c.id, c.addr, c.len), (b, WIN.0 + 2048, 60));
        device_complete(&mut r, a as u32, 100);
        let c = r.poll().unwrap().unwrap();
        assert_eq!((c.id, c.addr, c.len), (a, WIN.0, 100));
        assert_eq!(r.poll(), Ok(None));
        assert_eq!(r.in_flight(), 0);
        assert!(r.post(WIN.0, 10, false).is_ok(), "los descriptores devueltos se reutilizan");
    }

    #[test]
    fn a_full_queue_refuses_more_until_something_returns() {
        let mut r = ring(4);
        let ids: Vec<u16> = (0..4).map(|i| r.post(WIN.0 + i * 2048, 64, true).unwrap()).collect();
        assert_eq!(r.post(WIN.0, 64, true), Err(PostError::Full));
        device_complete(&mut r, ids[2] as u32, 10);
        r.poll().unwrap().unwrap();
        assert!(r.post(WIN.0, 64, true).is_ok());
    }

    #[test]
    fn sixteen_bit_indices_wrap_without_losing_buffers() {
        let mut r = ring(4);
        for round in 0..70_000u32 {
            let id = r.post(WIN.0, 64, true).unwrap();
            device_complete(&mut r, id as u32, (round % 65) as u32);
            let c = r.poll().unwrap().expect("hay una completion");
            assert_eq!((c.id, c.len), (id, round % 65));
        }
        assert_eq!(r.in_flight(), 0);
        assert_eq!(r.poisoned(), None);
    }

    #[test]
    fn a_device_that_claims_more_completions_than_were_posted_poisons_the_queue() {
        let mut r = ring(8);
        r.post(WIN.0, 64, true).unwrap();
        device_set_used_idx(&mut r, 5);
        assert_eq!(r.poll(), Err(RingError::UsedOverrun));
        assert_eq!(r.poisoned(), Some(RingError::UsedOverrun));
        assert_eq!(r.poll(), Err(RingError::UsedOverrun), "envenenada para siempre");
        assert_eq!(r.post(WIN.0, 64, true), Err(PostError::Poisoned(RingError::UsedOverrun)), "y no acepta mas buffers");
    }

    #[test]
    fn an_id_that_is_out_of_range_or_not_in_flight_is_rejected() {
        for bad_id in [8u32, 200, 0x1_0000, u32::MAX] {
            let mut r = ring(8);
            r.post(WIN.0, 64, true).unwrap();
            device_complete(&mut r, bad_id, 1);
            assert_eq!(r.poll(), Err(RingError::BadId), "id {bad_id:#x}");
        }
        // un descriptor libre (nunca publicado)
        let mut r = ring(8);
        let id = r.post(WIN.0, 64, true).unwrap();
        let other = (id + 1) % 8;
        device_complete(&mut r, other as u32, 1);
        assert_eq!(r.poll(), Err(RingError::BadId));
    }

    #[test]
    fn completing_the_same_buffer_twice_is_a_lie() {
        let mut r = ring(8);
        let id = r.post(WIN.0, 64, true).unwrap();
        r.post(WIN.0 + 2048, 64, true).unwrap();
        device_complete(&mut r, id as u32, 10);
        assert!(r.poll().unwrap().is_some());
        device_complete(&mut r, id as u32, 10); // hay otro en vuelo, asi que el desborde no lo caza: el id si
        assert_eq!(r.poll(), Err(RingError::BadId));
    }

    #[test]
    fn a_length_larger_than_the_buffer_is_rejected() {
        for len in [65u32, 4096, u32::MAX] {
            let mut r = ring(8);
            let id = r.post(WIN.0, 64, true).unwrap();
            device_complete(&mut r, id as u32, len);
            assert_eq!(r.poll(), Err(RingError::BadLen), "len {len}");
        }
        let mut r = ring(8);
        let id = r.post(WIN.0, 64, true).unwrap();
        device_complete(&mut r, id as u32, 64);
        assert_eq!(r.poll().unwrap().unwrap().len, 64, "el largo exacto vale");
    }

    #[test]
    fn what_the_device_does_to_the_descriptor_table_is_never_believed() {
        let mut r = ring(8);
        let id = r.post(WIN.0 + 4096, 128, true).unwrap();
        // el dispositivo (o algo con DMA) reescribe el descriptor para apuntar a la memoria del kernel
        let d = id as usize * 16;
        r.mem.write_u64(d, 0xDEAD_0000);
        r.mem.write_u32(d + 8, 0x10_0000);
        device_complete(&mut r, id as u32, 100);
        let c = r.poll().unwrap().unwrap();
        assert_eq!(c.addr, WIN.0 + 4096, "la direccion sale del estado del kernel, no de la tabla compartida");
        assert_eq!(r.poll(), Ok(None));
    }

    #[test]
    fn a_poisoned_queue_stays_silent_even_if_the_device_recovers() {
        let mut r = ring(4);
        let id = r.post(WIN.0, 64, true).unwrap();
        device_complete(&mut r, 99, 0);
        assert!(r.poll().is_err());
        device_set_used_idx(&mut r, 0); // el dispositivo "se corrige"
        device_complete(&mut r, id as u32, 1);
        assert!(r.poll().is_err(), "no hay vuelta atras");
    }

    #[test]
    fn the_pool_hands_out_distinct_slots_and_takes_back_only_its_own() {
        let mut p = DmaPool::new(0x20_0000, 2048, 4).unwrap();
        assert_eq!(p.window(), (0x20_0000, 0x20_0000 + 4 * 2048));
        let a = p.alloc().unwrap();
        let b = p.alloc().unwrap();
        assert_ne!(a, b);
        assert_eq!(p.free_slots(), 2);
        assert_eq!(p.free(a), Ok(()));
        assert_eq!(p.free(a), Err(PoolError::NotAllocated), "doble liberacion");
        assert_eq!(p.free(b + 1), Err(PoolError::NotASlot), "a mitad de un slot");
        assert_eq!(p.free(0x20_0000 - 2048), Err(PoolError::NotASlot), "antes del pool");
        assert_eq!(p.free(0x20_0000 + 4 * 2048), Err(PoolError::NotASlot), "justo despues del pool");
        assert_eq!(p.free(0), Err(PoolError::NotASlot));
        for _ in 0..3 { p.alloc().unwrap(); }
        assert_eq!(p.alloc(), None, "agotado");
        assert!(DmaPool::new(u64::MAX - 10, 2048, 4).is_none(), "el pool no puede desbordar el espacio de direcciones");
        assert!(DmaPool::new(0, 0, 4).is_none() && DmaPool::new(0, 2048, 0).is_none());
    }

    #[test]
    fn a_ring_built_on_a_pool_window_only_accepts_pool_addresses() {
        let mut p = DmaPool::new(0x30_0000, 2048, 8).unwrap();
        let (s, e) = p.window();
        let mut r = Vring::new(SimMem::new(Layout::for_size(8).unwrap().total), 8, s, e).unwrap();
        let a = p.alloc().unwrap();
        assert!(r.post(a, p.slot_size(), true).is_ok());
        assert_eq!(r.post(e, 16, true), Err(PostError::OutsideWindow));
    }
}
