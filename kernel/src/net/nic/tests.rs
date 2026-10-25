// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Pruebas del driver contra un virtio-net simulado: honesto (hace lo que dice el protocolo) y
//! hostil (miente en lo que devuelve). El dispositivo simulado ademas VIGILA al driver: cuenta
//! cualquier acceso a memoria antes de DRIVER_OK o del bus master.

use super::*;
use crate::net::pci::sim::*;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::cell::RefCell;

const PORTS: u16 = 0xC040;
const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const PHYS0: u64 = 0x10_0000;

struct Pool {
    mem: Vec<u8>,
    phys0: u64,
    next: usize,
    limit_pages: usize,
    allocs: Vec<(u64, usize)>,
    released: Vec<(u64, usize)>,
}

#[derive(Clone)]
struct SimDma(Rc<RefCell<Pool>>);

impl SimDma {
    fn new(pages: usize) -> Self {
        Self::at(PHYS0, pages)
    }
    fn at(phys0: u64, pages: usize) -> Self {
        // memoria con basura: el driver debe poner a cero lo que va a usar
        SimDma(Rc::new(RefCell::new(Pool { mem: alloc::vec![0xAA; pages * PAGE], phys0, next: 0, limit_pages: pages, allocs: Vec::new(), released: Vec::new() })))
    }
    fn leaked_pages(&self) -> usize {
        let p = self.0.borrow();
        p.allocs.iter().map(|a| a.1).sum::<usize>() - p.released.iter().map(|a| a.1).sum::<usize>()
    }
}

struct SharedMem {
    pool: Rc<RefCell<Pool>>,
    start: usize,
    len: usize,
}

impl SharedMem {
    fn bytes<R>(&self, off: usize, n: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
        assert!(off + n <= self.len, "el driver se salio de su region: {off}+{n} > {}", self.len);
        let mut p = self.pool.borrow_mut();
        f(&mut p.mem[self.start + off..self.start + off + n])
    }
}

impl Mem for SharedMem {
    fn len(&self) -> usize { self.len }
    fn read_u16(&self, o: usize) -> u16 { self.bytes(o, 2, |b| u16::from_le_bytes([b[0], b[1]])) }
    fn read_u32(&self, o: usize) -> u32 { self.bytes(o, 4, |b| u32::from_le_bytes(b.try_into().unwrap())) }
    fn write_u16(&mut self, o: usize, v: u16) { self.bytes(o, 2, |b| b.copy_from_slice(&v.to_le_bytes())) }
    fn write_u32(&mut self, o: usize, v: u32) { self.bytes(o, 4, |b| b.copy_from_slice(&v.to_le_bytes())) }
    fn write_u64(&mut self, o: usize, v: u64) { self.bytes(o, 8, |b| b.copy_from_slice(&v.to_le_bytes())) }
    fn barrier(&self) {}
    fn zero(&mut self) { self.bytes(0, self.len, |b| b.iter_mut().for_each(|x| *x = 0)) }
    fn read_bytes(&self, o: usize, out: &mut [u8]) { self.bytes(o, out.len(), |b| out.copy_from_slice(b)) }
    fn write_bytes(&mut self, o: usize, d: &[u8]) { self.bytes(o, d.len(), |b| b.copy_from_slice(d)) }
}

impl DmaHost for SimDma {
    type M = SharedMem;
    fn alloc(&mut self, pages: usize) -> Option<u64> {
        let mut p = self.0.borrow_mut();
        if p.next + pages > p.limit_pages {
            return None;
        }
        let base = p.phys0 + (p.next * PAGE) as u64;
        p.next += pages;
        p.allocs.push((base, pages));
        Some(base)
    }
    fn release(&mut self, base: u64, pages: usize) {
        let mut p = self.0.borrow_mut();
        let start = (base - p.phys0) as usize;
        p.mem[start..start + pages * PAGE].iter_mut().for_each(|b| *b = 0); // como deallocate_frame
        p.released.push((base, pages));
    }
    fn region(&self, base: u64, len: usize) -> SharedMem {
        let start = (base - self.0.borrow().phys0) as usize;
        SharedMem { pool: self.0.clone(), start, len }
    }
}

/// Dispositivo virtio-net legacy simulado, con el bus PCI de `pci::sim` para la configuracion.
struct Fake {
    pci: SimIo,
    pool: Rc<RefCell<Pool>>,
    status: u8,
    sel: u16,
    pfn: [u32; 2],
    qsize: [u16; 2],
    last_avail: [u16; 2],
    used_idx: [u16; 2],
    notifies: Vec<u16>,
    tx_log: Vec<Vec<u8>>,
    tx_headers: Vec<Vec<u8>>,
    reset_ignored: bool,
    needs_reset_on_ok: bool,
    tx_paused: bool,
    dma_violations: u32,
    master_ever: bool,
    master_set_without_queues: bool,
    backlog: VecDeque<Vec<u8>>,
    lie_len: Option<u32>,
    responder: Option<fn(&[u8]) -> Option<Vec<u8>>>,
}

impl Fake {
    fn new(qsize: [u16; 2], dma: &SimDma) -> Self {
        let mut pci = SimIo::new();
        pci.add(0, 3, 0, SimDevice::new(virtio::VENDOR, virtio::DEVICE_NET_LEGACY, 0x02, 0x00, 0x00, PORTS as u32 | 1));
        Fake {
            pci,
            pool: dma.0.clone(),
            status: 0,
            sel: 0,
            pfn: [0; 2],
            qsize,
            last_avail: [0; 2],
            used_idx: [0; 2],
            notifies: Vec::new(),
            tx_log: Vec::new(),
            tx_headers: Vec::new(),
            reset_ignored: false,
            needs_reset_on_ok: false,
            tx_paused: false,
            dma_violations: 0,
            master_ever: false,
            master_set_without_queues: false,
            backlog: VecDeque::new(),
            lie_len: None,
            responder: None,
        }
    }

    fn command(&mut self) -> u16 {
        (self.pci.devices.get(&(0, 3, 0)).unwrap().cfg[1] & 0xFFFF) as u16
    }
    fn master(&mut self) -> bool {
        self.command() & pci::COMMAND_BUS_MASTER != 0
    }
    fn track_master(&mut self) {
        if self.master() && !self.master_ever {
            self.master_ever = true;
            self.master_set_without_queues = self.pfn[0] == 0 || self.pfn[1] == 0;
        }
    }

    fn image(&self) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0..4].copy_from_slice(&(virtio::F_MAC | virtio::F_STATUS | 1 << 15).to_le_bytes());
        let s = self.sel as usize;
        if s < 2 {
            r[8..12].copy_from_slice(&self.pfn[s].to_le_bytes());
            r[12..14].copy_from_slice(&self.qsize[s].to_le_bytes());
        }
        r[18] = self.status;
        r[20..26].copy_from_slice(&MAC);
        r[26] = 1;
        r
    }
    fn read(&self, port: u16, width: usize) -> u32 {
        let off = (port - PORTS) as usize;
        let img = self.image();
        (0..width).fold(0u32, |v, i| v | (img[off + i] as u32) << (8 * i))
    }
    fn mine(port: u16) -> bool {
        (PORTS..PORTS + 28).contains(&port)
    }
    fn write(&mut self, port: u16, v: u32) {
        match port - PORTS {
            8 => {
                if (self.sel as usize) < 2 {
                    self.pfn[self.sel as usize] = v;
                }
            }
            14 => self.sel = v as u16,
            16 => {
                self.notifies.push(v as u16);
                match v {
                    0 => self.deliver(),
                    1 => self.process_tx(),
                    _ => {}
                }
            }
            18 => {
                let v = v as u8;
                if v == 0 {
                    if !self.reset_ignored {
                        self.status = 0;
                        self.pfn = [0; 2];
                        self.last_avail = [0; 2];
                        self.used_idx = [0; 2];
                    }
                } else if v & virtio::STATUS_DRIVER_OK != 0 && self.needs_reset_on_ok {
                    self.status = v | virtio::STATUS_NEEDS_RESET;
                } else {
                    self.status = v;
                }
            }
            _ => {}
        }
    }

    // --- acceso del dispositivo a la memoria fisica ---
    fn mem<R>(&self, addr: u64, n: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
        let mut p = self.pool.borrow_mut();
        let o = (addr - p.phys0) as usize;
        f(&mut p.mem[o..o + n])
    }
    fn rd16(&self, a: u64) -> u16 { self.mem(a, 2, |b| u16::from_le_bytes([b[0], b[1]])) }
    fn rd32(&self, a: u64) -> u32 { self.mem(a, 4, |b| u32::from_le_bytes(b.try_into().unwrap())) }
    fn rd64(&self, a: u64) -> u64 { self.mem(a, 8, |b| u64::from_le_bytes(b.try_into().unwrap())) }
    fn wr16(&self, a: u64, v: u16) { self.mem(a, 2, |b| b.copy_from_slice(&v.to_le_bytes())) }
    fn wr32(&self, a: u64, v: u32) { self.mem(a, 4, |b| b.copy_from_slice(&v.to_le_bytes())) }

    /// El dispositivo solo toca memoria con DRIVER_OK y bus master: si no, es una falta del driver.
    fn dma_ok(&mut self) -> bool {
        let ok = self.master() && self.status & virtio::STATUS_DRIVER_OK != 0;
        if !ok {
            self.dma_violations += 1;
        }
        ok
    }

    fn queue(&self, q: usize) -> Option<(u64, Layout)> {
        (self.pfn[q] != 0).then(|| (self.pfn[q] as u64 * PAGE as u64, Layout::for_size(self.qsize[q]).unwrap()))
    }

    fn complete(&mut self, q: usize, id: u16, len: u32) {
        let (base, l) = self.queue(q).unwrap();
        let slot = self.used_idx[q] as usize % self.qsize[q] as usize;
        self.wr32(base + l.used_ring(slot) as u64, id as u32);
        self.wr32(base + l.used_ring(slot) as u64 + 4, len);
        self.used_idx[q] = self.used_idx[q].wrapping_add(1);
        self.wr16(base + l.used_idx() as u64, self.used_idx[q]);
    }

    fn next_avail(&mut self, q: usize) -> Option<(u16, u64, u32)> {
        let (base, l) = self.queue(q)?;
        if self.rd16(base + l.avail_idx() as u64) == self.last_avail[q] {
            return None;
        }
        let slot = self.last_avail[q] as usize % self.qsize[q] as usize;
        let id = self.rd16(base + l.avail_ring(slot) as u64);
        let d = base + id as u64 * 16;
        let (addr, len) = (self.rd64(d), self.rd32(d + 8));
        self.last_avail[q] = self.last_avail[q].wrapping_add(1);
        Some((id, addr, len))
    }

    fn process_tx(&mut self) {
        if self.tx_paused || !self.dma_ok() {
            return;
        }
        while let Some((id, addr, len)) = self.next_avail(1) {
            let data = self.mem(addr, len as usize, |b| b.to_vec());
            self.tx_headers.push(data[..HDR_LEN].to_vec());
            let frame = data[HDR_LEN..].to_vec();
            if let Some(f) = self.responder {
                if let Some(reply) = f(&frame) {
                    self.backlog.push_back(reply);
                }
            }
            self.tx_log.push(frame);
            self.complete(1, id, 0);
        }
        self.deliver();
    }

    fn deliver(&mut self) {
        while !self.backlog.is_empty() {
            if !self.dma_ok() {
                return;
            }
            let Some((id, addr, cap)) = self.next_avail(0) else { return };
            let frame = self.backlog.pop_front().unwrap();
            let total = HDR_LEN + frame.len();
            assert!(total as u32 <= cap, "el driver publico un buffer demasiado pequeno");
            self.mem(addr, total, |b| {
                b[..HDR_LEN].fill(0);
                b[HDR_LEN..].copy_from_slice(&frame);
            });
            let len = self.lie_len.take().unwrap_or(total as u32);
            self.complete(0, id, len);
        }
    }

    fn inject(&mut self, frame: &[u8]) {
        self.backlog.push_back(frame.to_vec());
        self.deliver();
    }

    fn poke_used_idx(&mut self, q: usize, v: u16) {
        let (base, l) = self.queue(q).unwrap();
        self.wr16(base + l.used_idx() as u64, v);
    }
}

impl Io for Fake {
    fn inb(&mut self, p: u16) -> u8 { if Self::mine(p) { self.read(p, 1) as u8 } else { self.pci.inb(p) } }
    fn inw(&mut self, p: u16) -> u16 { if Self::mine(p) { self.read(p, 2) as u16 } else { self.pci.inw(p) } }
    fn inl(&mut self, p: u16) -> u32 { if Self::mine(p) { self.read(p, 4) } else { self.pci.inl(p) } }
    fn outb(&mut self, p: u16, v: u8) { if Self::mine(p) { self.write(p, v as u32) } else { self.pci.outb(p, v) } }
    fn outw(&mut self, p: u16, v: u16) {
        if Self::mine(p) { self.write(p, v as u32) } else { self.pci.outw(p, v); self.track_master() }
    }
    fn outl(&mut self, p: u16, v: u32) {
        if Self::mine(p) { self.write(p, v) } else { self.pci.outl(p, v); self.track_master() }
    }
}

fn setup(qsize: [u16; 2], pages: usize) -> (Fake, NetDevice, SimDma) {
    let dma = SimDma::new(pages);
    let mut fake = Fake::new(qsize, &dma);
    let devs = pci::scan(&mut fake);
    let dev = virtio::init(&mut fake, &devs[0]).expect("negociacion");
    (fake, dev, dma)
}

fn frame(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag.wrapping_add(i as u8)).collect()
}

fn up() -> (Fake, Nic<SimDma>, SimDma) {
    let (mut fake, dev, dma) = setup([16, 16], 64);
    let nic = activate(&mut fake, &dev, dma.clone()).expect("activacion");
    (fake, nic, dma)
}

// --- activacion ---

#[test]
fn activation_registers_both_queues_then_enables_bus_master_then_driver_ok() {
    let (mut fake, nic, dma) = up();
    assert_ne!(fake.pfn[0], 0);
    assert_ne!(fake.pfn[1], 0);
    assert_ne!(fake.pfn[0], fake.pfn[1], "colas distintas, memoria distinta");
    assert!(fake.master_ever && !fake.master_set_without_queues, "bus master solo con las dos colas registradas");
    assert!(fake.master());
    assert_eq!(fake.status, virtio::STATUS_ACKNOWLEDGE | virtio::STATUS_DRIVER | virtio::STATUS_DRIVER_OK);
    assert_eq!(fake.dma_violations, 0);
    assert_eq!(fake.notifies, alloc::vec![RX_QUEUE], "avisa de los buffers de recepcion");
    // los 16 buffers de recepcion estan publicados (avail.idx = 16)
    let (base, l) = fake.queue(0).unwrap();
    assert_eq!(fake.rd16(base + l.avail_idx() as u64), 16);
    // regiones contiguas de 2 paginas de anillo + 8 de buffers cada una
    assert_eq!(dma.0.borrow().allocs, alloc::vec![(PHYS0, 10), (PHYS0 + 10 * PAGE as u64, 10)]);
    assert_eq!(nic.stats(), Stats::default());
}

#[test]
fn a_queue_of_256_entries_uses_three_ring_pages_and_still_works() {
    let (mut fake, dev, dma) = setup([256, 256], 64);
    let mut nic = activate(&mut fake, &dev, dma.clone()).unwrap();
    assert_eq!(dma.0.borrow().allocs[0].1, 3 + 8);
    nic.send(&mut fake, &frame(1, 60)).unwrap();
    assert_eq!(fake.tx_log.len(), 1);
}

#[test]
fn a_missing_queue_fails_closed_without_bus_master_and_returns_the_memory() {
    let (mut fake, dev, dma) = setup([16, 0], 64);
    assert!(matches!(activate(&mut fake, &dev, dma.clone()), Err(ActivateError::NoQueue(1))));
    assert!(!fake.master_ever, "nunca se encendio el bus master");
    assert_eq!(fake.pfn, [0, 0], "nada registrado");
    assert_eq!(dma.leaked_pages(), 0);
    assert_eq!(fake.dma_violations, 0);
}

#[test]
fn invalid_queue_sizes_are_rejected() {
    for bad in [3u16, 100, 512, 1024] {
        let (mut fake, dev, dma) = setup([bad, 16], 64);
        let r = activate(&mut fake, &dev, dma.clone());
        assert!(matches!(r, Err(ActivateError::BadQueueSize(0))), "tamano {bad}");
        assert!(!fake.master_ever);
        assert_eq!(dma.leaked_pages(), 0);
    }
}

#[test]
fn a_queue_that_is_already_registered_is_refused() {
    let (mut fake, dev, dma) = setup([16, 16], 64);
    fake.pfn[1] = 0x1234;
    assert!(matches!(activate(&mut fake, &dev, dma.clone()), Err(ActivateError::QueueBusy(1))));
    assert!(!fake.master_ever);
    assert_eq!(dma.leaked_pages(), 0);
}

#[test]
fn running_out_of_contiguous_memory_is_an_error_not_a_partial_activation() {
    let (mut fake, dev, dma) = setup([16, 16], 15); // alcanza para una cola (10), no para dos
    assert!(matches!(activate(&mut fake, &dev, dma.clone()), Err(ActivateError::NoMemory)));
    assert!(!fake.master_ever);
    assert_eq!(dma.leaked_pages(), 0, "lo reservado de la primera cola se devolvio");
}

#[test]
fn memory_above_what_the_queue_register_can_address_is_refused() {
    let dma = SimDma::at(DMA_LIMIT - 5 * PAGE as u64, 64);
    let mut fake = Fake::new([16, 16], &dma);
    let devs = pci::scan(&mut fake);
    let dev = virtio::init(&mut fake, &devs[0]).unwrap();
    assert!(matches!(activate(&mut fake, &dev, dma.clone()), Err(ActivateError::AddressTooHigh)));
    assert!(!fake.master_ever);
    assert_eq!(dma.leaked_pages(), 0);
}

#[test]
fn a_device_that_rejects_driver_ok_is_reset_and_its_memory_returned() {
    let (mut fake, dev, dma) = setup([16, 16], 64);
    fake.needs_reset_on_ok = true;
    assert!(matches!(activate(&mut fake, &dev, dma.clone()), Err(ActivateError::Rejected)));
    assert_eq!(fake.status, 0, "reiniciado");
    assert!(!fake.master(), "bus master apagado");
    assert_eq!(fake.pfn, [0, 0]);
    assert_eq!(dma.leaked_pages(), 0);
    assert_eq!(fake.dma_violations, 0);
}

#[test]
fn a_rejecting_device_that_will_not_reset_keeps_its_memory_out_of_circulation() {
    let (mut fake, dev, dma) = setup([16, 16], 64);
    fake.needs_reset_on_ok = true;
    fake.reset_ignored = true;
    assert!(matches!(activate(&mut fake, &dev, dma.clone()), Err(ActivateError::Rejected)));
    assert!(!fake.master(), "al menos el bus master si se apago");
    assert_eq!(dma.leaked_pages(), 20, "sin reinicio confirmado no se devuelve memoria que el dispositivo podria escribir");
}

// --- envio ---

#[test]
fn a_sent_frame_reaches_the_device_byte_exact_behind_a_zero_header() {
    let (mut fake, mut nic, _) = up();
    let f = frame(7, 60);
    nic.send(&mut fake, &f).unwrap();
    assert_eq!(fake.tx_log, alloc::vec![f]);
    assert_eq!(fake.tx_headers, alloc::vec![alloc::vec![0u8; HDR_LEN]]);
    assert_eq!(fake.notifies.last(), Some(&TX_QUEUE));
    assert_eq!(fake.dma_violations, 0);
}

#[test]
fn send_rejects_frames_outside_the_ethernet_range() {
    let (mut fake, mut nic, _) = up();
    assert_eq!(nic.send(&mut fake, &frame(0, MIN_FRAME - 1)), Err(SendError::BadLength));
    assert_eq!(nic.send(&mut fake, &frame(0, MAX_FRAME + 1)), Err(SendError::BadLength));
    assert!(nic.send(&mut fake, &frame(0, MIN_FRAME)).is_ok());
    assert!(nic.send(&mut fake, &frame(0, MAX_FRAME)).is_ok());
}

#[test]
fn the_send_queue_is_bounded_and_frees_up_when_the_device_returns_buffers() {
    let (mut fake, mut nic, _) = up();
    fake.tx_paused = true;
    for i in 0..SLOTS {
        nic.send(&mut fake, &frame(i as u8, 64)).unwrap();
    }
    assert_eq!(nic.send(&mut fake, &frame(99, 64)), Err(SendError::Full));
    assert_eq!(nic.stats().tx_full, 1);
    fake.tx_paused = false;
    fake.write(PORTS + 16, TX_QUEUE as u32); // el dispositivo se pone al dia
    nic.send(&mut fake, &frame(100, 64)).unwrap();
    assert_eq!(nic.stats().tx_frames, SLOTS as u64, "los 16 anteriores quedaron completados");
    assert_eq!(fake.tx_log.len(), SLOTS + 1);
}

#[test]
fn many_more_frames_than_slots_flow_through_and_indices_wrap() {
    let (mut fake, mut nic, _) = up();
    for i in 0..5000u32 {
        nic.send(&mut fake, &frame(i as u8, 64)).unwrap();
    }
    assert_eq!(fake.tx_log.len(), 5000);
    assert!(fake.tx_log.iter().enumerate().all(|(i, f)| *f == frame(i as u8, 64)));
}

// --- recepcion ---

#[test]
fn a_received_frame_is_delivered_exactly_and_the_buffer_is_scrubbed_and_reposted() {
    let (mut fake, mut nic, _) = up();
    assert_eq!(nic.recv(&mut fake), Ok(None));
    let f = frame(0x40, 100);
    fake.inject(&f);
    assert_eq!(nic.recv(&mut fake), Ok(Some(f)));
    assert_eq!(nic.recv(&mut fake), Ok(None));
    assert_eq!(nic.stats().rx_frames, 1);
    // el buffer volvio a publicarse (16 buffers en vuelo otra vez) y quedo sin rastro de la trama
    assert_eq!(nic.rx.ring.in_flight(), SLOTS);
    let mut all = alloc::vec![0u8; SLOTS * SLOT_SIZE as usize];
    nic.rx.bufs.read_bytes(0, &mut all);
    assert!(all.iter().all(|b| *b == 0), "ninguna trama sobrevive en los buffers");
}

#[test]
fn rx_keeps_working_across_many_more_frames_than_buffers() {
    let (mut fake, mut nic, _) = up();
    for i in 0..3000u32 {
        let f = frame(i as u8, 64 + (i % 100) as usize);
        fake.inject(&f);
        assert_eq!(nic.recv(&mut fake), Ok(Some(f)), "trama {i}");
    }
    assert_eq!(nic.stats().rx_frames, 3000);
}

#[test]
fn runts_and_oversize_frames_are_dropped_and_counted_not_delivered() {
    let (mut fake, mut nic, _) = up();
    fake.inject(&frame(1, 5)); // 15 bytes con cabecera: menos que una cabecera Ethernet
    fake.inject(&frame(2, 1600));
    let good = frame(3, 80);
    fake.inject(&good);
    assert_eq!(nic.recv(&mut fake), Ok(Some(good)), "salta las descartadas");
    assert_eq!(nic.stats().rx_dropped, 2);
    assert_eq!(nic.stats().rx_frames, 1);
}

#[test]
fn frames_arrive_in_order() {
    let (mut fake, mut nic, _) = up();
    for i in 0..10u8 {
        fake.inject(&frame(i, 60));
    }
    for i in 0..10u8 {
        assert_eq!(nic.recv(&mut fake), Ok(Some(frame(i, 60))));
    }
}

#[test]
fn a_flood_beyond_the_buffers_is_held_by_the_device_not_by_the_kernel() {
    let (mut fake, mut nic, _) = up();
    for i in 0..40u8 {
        fake.inject(&frame(i, 60));
    }
    assert_eq!(fake.backlog.len(), 40 - SLOTS, "el exceso espera en el dispositivo; el kernel no reserva memoria extra");
    for i in 0..16u8 {
        assert_eq!(nic.recv(&mut fake), Ok(Some(frame(i, 60))));
    }
}

// --- dispositivo hostil ---

#[test]
fn a_length_longer_than_the_buffer_poisons_the_queue_and_everything_fails_closed() {
    let (mut fake, mut nic, _) = up();
    fake.lie_len = Some(SLOT_SIZE + 1);
    fake.inject(&frame(1, 60));
    assert_eq!(nic.recv(&mut fake), Err(RecvError::Poisoned(RingError::BadLen)));
    assert_eq!(nic.poisoned(), Some(RingError::BadLen));
    assert_eq!(nic.recv(&mut fake), Err(RecvError::Poisoned(RingError::BadLen)), "no se vuelve a leer");
}

#[test]
fn a_used_index_that_runs_ahead_poisons_the_receive_queue() {
    let (mut fake, mut nic, _) = up();
    fake.poke_used_idx(0, 40);
    assert_eq!(nic.recv(&mut fake), Err(RecvError::Poisoned(RingError::UsedOverrun)));
}

#[test]
fn a_used_index_that_runs_ahead_on_the_send_queue_stops_sending() {
    let (mut fake, mut nic, _) = up();
    fake.tx_paused = true;
    nic.send(&mut fake, &frame(1, 60)).unwrap();
    fake.poke_used_idx(1, 9);
    assert_eq!(nic.send(&mut fake, &frame(2, 60)), Err(SendError::Poisoned(RingError::UsedOverrun)));
    assert_eq!(nic.send(&mut fake, &frame(3, 60)), Err(SendError::Poisoned(RingError::UsedOverrun)));
}

// --- apagado ---

#[test]
fn shutdown_turns_off_bus_master_resets_scrubs_and_returns_every_page() {
    let (mut fake, mut nic, dma) = up();
    nic.send(&mut fake, &frame(0xEE, 200)).unwrap();
    fake.inject(&frame(0xDD, 200));
    assert_eq!(nic.shutdown(&mut fake), Shutdown::Clean);
    assert!(!fake.master());
    assert_eq!(fake.status, 0);
    assert_eq!(dma.leaked_pages(), 0);
    assert!(dma.0.borrow().mem[..20 * PAGE].iter().all(|b| *b == 0), "ni rastro de lo enviado o recibido");
}

#[test]
fn shutdown_of_a_device_that_ignores_reset_leaks_on_purpose_but_still_cuts_bus_master() {
    let (mut fake, nic, dma) = up();
    fake.reset_ignored = true;
    assert_eq!(nic.shutdown(&mut fake), Shutdown::Leaked { pages: 20 });
    assert!(!fake.master());
    assert_eq!(dma.leaked_pages(), 20);
}

#[test]
fn the_device_can_be_brought_up_again_after_a_clean_shutdown() {
    let (mut fake, nic, _) = up();
    assert_eq!(nic.shutdown(&mut fake), Shutdown::Clean);
    let devs = pci::scan(&mut fake);
    let dev = virtio::init(&mut fake, &devs[0]).unwrap();
    let dma2 = SimDma::new(64);
    fake.pool = dma2.0.clone();
    let mut nic = activate(&mut fake, &dev, dma2).unwrap();
    nic.send(&mut fake, &frame(1, 60)).unwrap();
    assert_eq!(fake.tx_log.len(), 1);
}

// --- autocomprobacion ARP ---

const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];

fn gateway(req: &[u8]) -> Option<Vec<u8>> {
    crate::net::arp::answer(req, GW_MAC)
}

#[test]
fn arp_selftest_gets_the_gateways_mac_through_the_whole_path() {
    let (mut fake, mut nic, _) = up();
    fake.responder = Some(gateway);
    let r = crate::net::arp::selftest(&mut nic, &mut fake, MAC, 10);
    assert_eq!(r, Ok(Some(GW_MAC)));
    assert_eq!(fake.tx_log[0], crate::net::arp::request(MAC, crate::net::arp::OUR_IP, crate::net::arp::GATEWAY_IP).to_vec());
}

#[test]
fn arp_selftest_without_an_answer_reports_none_and_ignores_foreign_frames() {
    let (mut fake, mut nic, _) = up();
    fake.inject(&frame(9, 60)); // trama ajena: no es la respuesta
    assert_eq!(crate::net::arp::selftest(&mut nic, &mut fake, MAC, 10), Ok(None));
}

#[test]
fn a_reply_from_the_wrong_host_or_to_another_mac_is_not_accepted() {
    use crate::net::arp::*;
    let req = request(MAC, OUR_IP, GATEWAY_IP);
    let good = answer(&req, GW_MAC).unwrap();
    assert_eq!(reply_from(&good, GATEWAY_IP, MAC), Some(GW_MAC));
    assert_eq!(reply_from(&good, [10, 0, 2, 3], MAC), None, "otro anfitrion");
    assert_eq!(reply_from(&good, GATEWAY_IP, [1; 6]), None, "dirigida a otra MAC");
    assert_eq!(reply_from(&req, GATEWAY_IP, MAC), None, "una peticion no es respuesta");
    assert_eq!(reply_from(&good[..30], GATEWAY_IP, MAC), None, "truncada");
}

#[test]
fn reaping_makes_the_sent_counter_current_without_another_send() {
    let (mut fake, mut nic, _) = up();
    nic.send(&mut fake, &frame(1, 60)).unwrap();
    assert_eq!(nic.stats().tx_frames, 0, "todavia sin recoger");
    nic.reap(&mut fake).unwrap();
    assert_eq!(nic.stats().tx_frames, 1);
    assert_eq!(nic.tx.pool.free_slots(), SLOTS);
}
