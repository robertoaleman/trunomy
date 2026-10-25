// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Activacion de virtio-net y camino de datos (I-44, I-46): colas reales, bus master, tramas.
//!
//! Orden de activacion (cada paso solo ocurre si el anterior salio bien):
//! 1. por cada cola (0 = recepcion, 1 = envio): leer su tamano (lo fija el dispositivo), exigir que
//!    no este en uso, reservar marcos CONTIGUOS (anillo + buffers), construir y poner a cero el anillo;
//! 2. recepcion: publicar todos sus buffers; 3. registrar las dos colas en el dispositivo;
//! 4. SOLO ahora, bus master; 5. DRIVER_OK y comprobar que el dispositivo no lo rechazo; 6. avisar.
//! Si algo falla se apaga el bus master, se reinicia el dispositivo y, solo si el reinicio se
//! confirmo, se devuelven los marcos (borrados). Si el dispositivo no confirma el reinicio, los marcos
//! NO se devuelven: podria seguir escribiendolos, y reutilizarlos seria darle memoria ajena (se pierden
//! a proposito; el estado lo cuenta `Shutdown::Leaked`).
//!
//! Camino de datos: un descriptor por buffer de 2 KiB (10 bytes de cabecera virtio-net + trama),
//! 16 buffers por cola. Todo se sondea (sin interrupciones). Cada buffer se borra al soltarlo. El
//! dispositivo se trata como no confiable (`vring`): una mentira envenena la cola y todo falla cerrado.
//!
//! Lo que esto NO prueba: en QEMU no hay IOMMU ni tiempos reales; un dispositivo hostil con bus master
//! podria escribir en cualquier parte. Aqui solo se limita lo que el kernel le PIDE y lo que acepta.

use alloc::vec;
use alloc::vec::Vec;

use super::io::Io;
use super::pci::{self, PciAddress};
use super::virtio::{self, NetDevice, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, STATUS_NEEDS_RESET};
use super::vring::{DmaPool, Layout, Mem, PostError, RingError, Vring};

// Registros legacy de colas (desplazamientos desde el BAR0 de E/S).
const REG_QUEUE_PFN: u16 = 8;
const REG_QUEUE_SIZE: u16 = 12;
const REG_QUEUE_SEL: u16 = 14;
const REG_QUEUE_NOTIFY: u16 = 16;

pub const RX_QUEUE: u16 = 0;
pub const TX_QUEUE: u16 = 1;
/// Buffers por cola y su tamano. 2 KiB cubre cabecera + una trama Ethernet maxima.
pub const SLOTS: usize = 16;
pub const SLOT_SIZE: u32 = 2048;
/// Cabecera virtio-net sin caracteristicas extra negociadas.
pub const HDR_LEN: usize = 10;
pub const MIN_FRAME: usize = 14;
pub const MAX_FRAME: usize = 1514;
const PAGE: usize = 4096;
/// El registro de la cola guarda el numero de pagina en 32 bits: la region debe quedar bajo 2^44.
const DMA_LIMIT: u64 = 1 << 44;
const ZERO_SLOT: [u8; SLOT_SIZE as usize] = [0; SLOT_SIZE as usize];

/// Marcos de DMA contiguos. En el kernel son del allocator de marcos; en las pruebas, memoria simulada.
pub trait DmaHost {
    type M: Mem;
    /// Reserva `pages` paginas consecutivas; devuelve la direccion fisica de la primera.
    fn alloc(&mut self, pages: usize) -> Option<u64>;
    /// Devuelve (y borra) las paginas.
    fn release(&mut self, base: u64, pages: usize);
    /// Vista de `len` bytes de una region reservada con `alloc`.
    fn region(&self, base: u64, len: usize) -> Self::M;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivateError {
    /// El dispositivo no tiene esa cola (tamano 0).
    NoQueue(u16),
    /// La cola ya estaba registrada (tras un reinicio deberia estar libre).
    QueueBusy(u16),
    /// Tamano que no es potencia de dos entre 1 y 256.
    BadQueueSize(u16),
    NoMemory,
    /// Los marcos reservados no caben en el registro de pagina del dispositivo.
    AddressTooHigh,
    /// El dispositivo rechazo DRIVER_OK o pidio reinicio.
    Rejected,
}

impl ActivateError {
    pub const fn text(self) -> &'static str {
        match self {
            ActivateError::NoQueue(_) => "the device does not offer the queue",
            ActivateError::QueueBusy(_) => "the queue was already in use",
            ActivateError::BadQueueSize(_) => "invalid queue size",
            ActivateError::NoMemory => "no contiguous frames for the queues",
            ActivateError::AddressTooHigh => "queue memory out of the device's reach",
            ActivateError::Rejected => "the device rejected DRIVER_OK",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// Fuera de `MIN_FRAME..=MAX_FRAME`.
    BadLength,
    /// No quedan buffers libres de envio (el dispositivo aun no devolvio los anteriores).
    Full,
    /// La cola fue envenenada por una mentira del dispositivo: no se usa mas.
    Poisoned(RingError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    Poisoned(RingError),
}

/// Que paso con la memoria al apagar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shutdown {
    /// Reinicio confirmado: marcos borrados y devueltos.
    Clean,
    /// El dispositivo no confirmo el reinicio: sus `pages` paginas se retienen, no se reutilizan.
    Leaked { pages: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub tx_frames: u64,
    pub rx_frames: u64,
    /// Envios rechazados por falta de buffers.
    pub tx_full: u64,
    /// Recibidos descartados: mas cortos que una cabecera Ethernet o mas largos que `MAX_FRAME`.
    pub rx_dropped: u64,
}

struct Queue<M: Mem> {
    ring: Vring<M>,
    bufs: M,
    pool: DmaPool,
    buf_base: u64,
    base: u64,
    pages: usize,
}

impl<M: Mem> Queue<M> {
    fn offset(&self, addr: u64) -> usize {
        (addr - self.buf_base) as usize
    }
    /// Borra el buffer entero (I-16): ninguna trama sobrevive a su uso.
    fn scrub(&mut self, addr: u64) {
        let off = self.offset(addr);
        self.bufs.write_bytes(off, &ZERO_SLOT);
    }
}

pub struct Nic<H: DmaHost> {
    host: H,
    addr: PciAddress,
    io_base: u16,
    rx: Queue<H::M>,
    tx: Queue<H::M>,
    stats: Stats,
}

fn build_queue<I: Io, H: DmaHost>(io: &mut I, io_base: u16, host: &mut H, index: u16) -> Result<Queue<H::M>, ActivateError> {
    io.outw(io_base + REG_QUEUE_SEL, index);
    let size = io.inw(io_base + REG_QUEUE_SIZE);
    if size == 0 {
        return Err(ActivateError::NoQueue(index));
    }
    if io.inl(io_base + REG_QUEUE_PFN) != 0 {
        return Err(ActivateError::QueueBusy(index));
    }
    let layout = Layout::for_size(size).map_err(|_| ActivateError::BadQueueSize(index))?;
    let buf_len = SLOTS * SLOT_SIZE as usize;
    let pages = (layout.total + buf_len) / PAGE;
    let base = host.alloc(pages).ok_or(ActivateError::NoMemory)?;
    let end = base.checked_add((pages * PAGE) as u64);
    if base % PAGE as u64 != 0 || end.map_or(true, |e| e > DMA_LIMIT) {
        host.release(base, pages);
        return Err(ActivateError::AddressTooHigh);
    }
    let buf_base = base + layout.total as u64;
    let mut bufs = host.region(buf_base, buf_len);
    bufs.zero();
    let Some(pool) = DmaPool::new(buf_base, SLOT_SIZE, SLOTS) else {
        host.release(base, pages);
        return Err(ActivateError::NoMemory);
    };
    let (w0, w1) = pool.window();
    let Ok(ring) = Vring::new(host.region(base, layout.total), size, w0, w1) else {
        host.release(base, pages);
        return Err(ActivateError::BadQueueSize(index));
    };
    Ok(Queue { ring, bufs, pool, buf_base, base, pages })
}

/// Bus master fuera, reinicio y espera acotada. `true` = el dispositivo ya no puede tocar memoria.
fn quiesce<I: Io>(io: &mut I, addr: PciAddress, io_base: u16) -> bool {
    let off = pci::disable_bus_master(io, addr);
    io.outb(io_base + virtio::REG_DEVICE_STATUS, 0);
    let mut reset = false;
    for _ in 0..virtio::RESET_SPINS {
        if io.inb(io_base + virtio::REG_DEVICE_STATUS) == 0 {
            reset = true;
            break;
        }
    }
    off && reset
}

/// Activa el dispositivo ya negociado. Si falla, lo deja apagado y sin memoria retenida (o cuenta lo retenido).
pub fn activate<I: Io, H: DmaHost>(io: &mut I, dev: &NetDevice, mut host: H) -> Result<Nic<H>, ActivateError> {
    let io_base = dev.io_base;
    let mut queues: Vec<Queue<H::M>> = Vec::new();
    let mut failure = None;
    for index in [RX_QUEUE, TX_QUEUE] {
        match build_queue(io, io_base, &mut host, index) {
            Ok(q) => queues.push(q),
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
    }
    let abort = |io: &mut I, host: &mut H, queues: Vec<Queue<H::M>>, registered: bool, e: ActivateError| -> ActivateError {
        // Si ya se registro algo, antes de soltar la memoria hay que garantizar que el dispositivo no la usa.
        let safe = !registered || quiesce(io, dev.addr, io_base);
        if safe {
            for q in queues {
                host.release(q.base, q.pages);
            }
        } else {
            core::mem::forget(queues);
            io.outb(io_base + virtio::REG_DEVICE_STATUS, STATUS_FAILED);
        }
        e
    };
    if let Some(e) = failure {
        return Err(abort(io, &mut host, queues, false, e));
    }
    let tx = queues.pop().expect("two queues");
    let mut rx = queues.pop().expect("two queues");

    // Recepcion: todos los buffers publicados antes de registrar la cola.
    for _ in 0..SLOTS.min(rx.ring.layout().size as usize) {
        let ok = rx.pool.alloc().is_some_and(|a| rx.ring.post(a, SLOT_SIZE, true).is_ok());
        if !ok {
            return Err(abort(io, &mut host, vec![rx, tx], false, ActivateError::NoMemory));
        }
    }
    // Registro en el dispositivo (todavia sin bus master: no puede leer ni escribir nada).
    for (index, q) in [(RX_QUEUE, &rx), (TX_QUEUE, &tx)] {
        io.outw(io_base + REG_QUEUE_SEL, index);
        io.outl(io_base + REG_QUEUE_PFN, (q.base / PAGE as u64) as u32);
    }
    // Solo con las dos colas validadas y registradas: bus master y DRIVER_OK.
    let master = pci::enable_bus_master(io, dev.addr);
    io.outb(io_base + virtio::REG_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK);
    let status = io.inb(io_base + virtio::REG_DEVICE_STATUS);
    if !master || status & STATUS_DRIVER_OK == 0 || status & (STATUS_FAILED | STATUS_NEEDS_RESET) != 0 {
        return Err(abort(io, &mut host, vec![rx, tx], true, ActivateError::Rejected));
    }
    io.outw(io_base + REG_QUEUE_NOTIFY, RX_QUEUE);
    Ok(Nic { host, addr: dev.addr, io_base, rx, tx, stats: Stats::default() })
}

impl<H: DmaHost> Nic<H> {
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Mentira detectada en alguna cola (si la hay).
    pub fn poisoned(&self) -> Option<RingError> {
        self.rx.ring.poisoned().or(self.tx.ring.poisoned())
    }

    /// Recoge los buffers de envio que el dispositivo ya devolvio (los borra y los libera).
    pub fn reap<I: Io>(&mut self, _io: &mut I) -> Result<(), RingError> {
        loop {
            match self.tx.ring.poll() {
                Ok(Some(c)) => {
                    self.tx.scrub(c.addr);
                    let _ = self.tx.pool.free(c.addr);
                    self.stats.tx_frames += 1;
                }
                Ok(None) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Envio: recoge los buffers que el dispositivo ya devolvio y publica la trama.
    pub fn send<I: Io>(&mut self, io: &mut I, frame: &[u8]) -> Result<(), SendError> {
        if !(MIN_FRAME..=MAX_FRAME).contains(&frame.len()) {
            return Err(SendError::BadLength);
        }
        self.reap(io).map_err(SendError::Poisoned)?;
        let Some(addr) = self.tx.pool.alloc() else {
            self.stats.tx_full += 1;
            return Err(SendError::Full);
        };
        let off = self.tx.offset(addr);
        self.tx.bufs.write_bytes(off, &[0u8; HDR_LEN]);
        self.tx.bufs.write_bytes(off + HDR_LEN, frame);
        match self.tx.ring.post(addr, (HDR_LEN + frame.len()) as u32, false) {
            Ok(_) => {}
            Err(e) => {
                self.tx.scrub(addr);
                let _ = self.tx.pool.free(addr);
                return Err(match e {
                    PostError::Poisoned(r) => SendError::Poisoned(r),
                    _ => SendError::Full,
                });
            }
        }
        io.outw(self.io_base + REG_QUEUE_NOTIFY, TX_QUEUE);
        Ok(())
    }

    /// Recepcion de UNA trama valida (las demasiado cortas o largas se descartan y se cuentan).
    /// El buffer se borra y se vuelve a publicar siempre.
    pub fn recv<I: Io>(&mut self, io: &mut I) -> Result<Option<Vec<u8>>, RecvError> {
        for _ in 0..=SLOTS {
            let c = match self.rx.ring.poll() {
                Ok(Some(c)) => c,
                Ok(None) => return Ok(None),
                Err(e) => return Err(RecvError::Poisoned(e)),
            };
            let len = c.len as usize;
            let frame = if len >= HDR_LEN + MIN_FRAME && len - HDR_LEN <= MAX_FRAME {
                let mut v = vec![0u8; len - HDR_LEN];
                self.rx.bufs.read_bytes(self.rx.offset(c.addr) + HDR_LEN, &mut v);
                self.stats.rx_frames += 1;
                Some(v)
            } else {
                self.stats.rx_dropped += 1;
                None
            };
            self.rx.scrub(c.addr);
            let _ = self.rx.pool.free(c.addr);
            let reposted = self.rx.pool.alloc().map(|a| self.rx.ring.post(a, SLOT_SIZE, true));
            match reposted {
                Some(Ok(_)) => io.outw(self.io_base + REG_QUEUE_NOTIFY, RX_QUEUE),
                Some(Err(PostError::Poisoned(r))) => return Err(RecvError::Poisoned(r)),
                _ => {} // sin buffer que republicar: la cola se vaciara y recv devolvera None
            }
            if frame.is_some() {
                return Ok(frame);
            }
        }
        Ok(None)
    }

    /// Apaga: bus master fuera, reinicio, y solo si se confirmo, marcos borrados y devueltos.
    pub fn shutdown<I: Io>(mut self, io: &mut I) -> Shutdown {
        if quiesce(io, self.addr, self.io_base) {
            for q in [&self.rx, &self.tx] {
                self.host.release(q.base, q.pages);
            }
            Shutdown::Clean
        } else {
            io.outb(self.io_base + virtio::REG_DEVICE_STATUS, STATUS_FAILED);
            let pages = self.rx.pages + self.tx.pages;
            core::mem::forget(self);
            Shutdown::Leaked { pages }
        }
    }
}

/// Memoria fisica real (identity map del kernel, Ring 0). Solo se construye sobre regiones que el
/// allocator de marcos entrego a `FrameDma`.
#[cfg(not(test))]
pub struct PhysMem {
    base: u64,
    len: usize,
}

#[cfg(not(test))]
impl PhysMem {
    fn ptr<T>(&self, off: usize) -> Option<*mut T> {
        let end = off.checked_add(core::mem::size_of::<T>())?;
        if end > self.len || (self.base as usize + off) % core::mem::align_of::<T>() != 0 {
            return None;
        }
        Some((self.base as usize + off) as *mut T)
    }
}

#[cfg(not(test))]
impl Mem for PhysMem {
    fn len(&self) -> usize {
        self.len
    }
    fn read_u16(&self, off: usize) -> u16 {
        self.ptr::<u16>(off).map_or(0, |p| unsafe { core::ptr::read_volatile(p) })
    }
    fn read_u32(&self, off: usize) -> u32 {
        self.ptr::<u32>(off).map_or(0, |p| unsafe { core::ptr::read_volatile(p) })
    }
    fn write_u16(&mut self, off: usize, v: u16) {
        if let Some(p) = self.ptr::<u16>(off) {
            unsafe { core::ptr::write_volatile(p, v) }
        }
    }
    fn write_u32(&mut self, off: usize, v: u32) {
        if let Some(p) = self.ptr::<u32>(off) {
            unsafe { core::ptr::write_volatile(p, v) }
        }
    }
    fn write_u64(&mut self, off: usize, v: u64) {
        if let Some(p) = self.ptr::<u64>(off) {
            unsafe { core::ptr::write_volatile(p, v) }
        }
    }
    fn barrier(&self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
    fn zero(&mut self) {
        for i in 0..self.len {
            unsafe { core::ptr::write_volatile((self.base as usize + i) as *mut u8, 0) };
        }
    }
    fn read_bytes(&self, off: usize, out: &mut [u8]) {
        if off.checked_add(out.len()).is_some_and(|e| e <= self.len) {
            for (i, b) in out.iter_mut().enumerate() {
                *b = unsafe { core::ptr::read_volatile((self.base as usize + off + i) as *const u8) };
            }
        }
    }
    fn write_bytes(&mut self, off: usize, data: &[u8]) {
        if off.checked_add(data.len()).is_some_and(|e| e <= self.len) {
            for (i, b) in data.iter().enumerate() {
                unsafe { core::ptr::write_volatile((self.base as usize + off + i) as *mut u8, *b) };
            }
        }
    }
}

/// Marcos del allocator del kernel. `release` usa `deallocate_frame`, que borra cada marco antes de liberarlo.
#[cfg(not(test))]
pub struct FrameDma;

#[cfg(not(test))]
impl DmaHost for FrameDma {
    type M = PhysMem;
    fn alloc(&mut self, pages: usize) -> Option<u64> {
        crate::memory::frame_allocator::BITMAP_ALLOCATOR.lock().allocate_contiguous(pages)
    }
    fn release(&mut self, base: u64, pages: usize) {
        for i in 0..pages {
            let _ = crate::memory::frame_allocator::BITMAP_ALLOCATOR.lock().deallocate_frame(base + (i * PAGE) as u64);
        }
    }
    fn region(&self, base: u64, len: usize) -> PhysMem {
        PhysMem { base, len }
    }
}

#[cfg(test)]
mod tests;
