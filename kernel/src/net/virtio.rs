// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! virtio-net por la interfaz "legacy" (puertos de E/S en el BAR0), la mas simple: sin MMIO ni
//! capabilities PCI. QEMU la ofrece con `-device virtio-net-pci,disable-modern=on`.
//!
//! Este modulo llega hasta el apreton de manos del dispositivo (I-44): reinicio, reconocimiento,
//! negociacion de caracteristicas y lectura de la MAC y del estado del enlace. NO configura colas ni
//! activa DRIVER_OK ni bus master: el dispositivo queda negociado pero inactivo, sin poder hacer DMA
//! hacia la memoria del kernel. La activacion (colas validadas, bus master, DRIVER_OK) es de `nic`.

use super::io::Io;
use super::pci::{self, PciAddress, PciDevice};

pub const VENDOR: u16 = 0x1AF4;
/// virtio-net "transicional": interfaz legacy por E/S (la que usamos).
pub const DEVICE_NET_LEGACY: u16 = 0x1000;
/// virtio-net "moderno": solo MMIO + capabilities; el kernel todavia no lo soporta.
pub const DEVICE_NET_MODERN: u16 = 0x1041;

// Registros legacy (desplazamientos desde el BAR0 de E/S).
const REG_HOST_FEATURES: u16 = 0;
const REG_GUEST_FEATURES: u16 = 4;
pub const REG_DEVICE_STATUS: u16 = 18;
const REG_CONFIG: u16 = 20; // virtio-net: mac[6] en 20..26, status (u16) en 26..28

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
/// El dispositivo pide un reinicio: dejo de funcionar.
pub const STATUS_NEEDS_RESET: u8 = 0x40;
pub const STATUS_FAILED: u8 = 0x80;

pub const F_MAC: u32 = 1 << 5;
pub const F_STATUS: u32 = 1 << 16;
/// Lo unico que el kernel acepta. Cualquier otra caracteristica que ofrezca el anfitrion se rechaza.
pub const ACCEPTED_FEATURES: u32 = F_MAC | F_STATUS;
const NET_S_LINK_UP: u16 = 1;

/// Lecturas del estado tras pedir el reinicio antes de darlo por colgado.
pub const RESET_SPINS: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Unknown,
    Down,
    Up,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// BAR0 no es de E/S (dispositivo solo MMIO) o su base no cabe en un puerto de 16 bits.
    NotIoBar,
    /// El firmware no asigno puertos al BAR0 (base 0).
    Unassigned,
    /// El dispositivo no confirmo el reinicio en `RESET_SPINS` lecturas.
    ResetTimeout,
    /// No ofrece MAC: sin ella el dispositivo no es util para nosotros.
    NoMac,
    /// La MAC es nula o de grupo (multicast): no puede ser la direccion de una interfaz.
    BadMac,
}

impl InitError {
    pub const fn text(self) -> &'static str {
        match self {
            InitError::NotIoBar => "BAR0 is not I/O",
            InitError::Unassigned => "BAR0 unassigned",
            InitError::ResetTimeout => "the device did not complete the reset",
            InitError::NoMac => "the device does not offer a MAC",
            InitError::BadMac => "invalid MAC",
        }
    }
}

/// Un virtio-net reconocido y negociado. Inactivo: sin colas, sin DRIVER_OK, sin bus master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDevice {
    pub addr: PciAddress,
    pub vendor: u16,
    pub device: u16,
    pub io_base: u16,
    pub mac: [u8; 6],
    pub host_features: u32,
    pub guest_features: u32,
    pub link: Link,
}

fn status<I: Io>(io: &mut I, base: u16) -> u8 {
    io.inb(base + REG_DEVICE_STATUS)
}

/// Apreton de manos legacy hasta la lectura de la MAC. Si algo falla tras tocar el dispositivo, se
/// marca FAILED para que no quede a medias.
pub fn init<I: Io>(io: &mut I, dev: &PciDevice) -> Result<NetDevice, InitError> {
    if dev.bar0 & 1 == 0 || dev.bar0 > 0xFFFF {
        return Err(InitError::NotIoBar);
    }
    let io_base = (dev.bar0 & 0xFFFC) as u16;
    if io_base == 0 {
        return Err(InitError::Unassigned);
    }
    if !pci::enable_io_space(io, dev.addr) {
        return Err(InitError::NotIoBar);
    }

    // 1. Reinicio: escribir 0 y esperar a leer 0.
    io.outb(io_base + REG_DEVICE_STATUS, 0);
    let mut reset = false;
    for _ in 0..RESET_SPINS {
        if status(io, io_base) == 0 {
            reset = true;
            break;
        }
    }
    if !reset {
        io.outb(io_base + REG_DEVICE_STATUS, STATUS_FAILED);
        return Err(InitError::ResetTimeout);
    }
    // 2. ACKNOWLEDGE: el SO vio el dispositivo. 3. DRIVER: sabemos manejarlo.
    io.outb(io_base + REG_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
    io.outb(io_base + REG_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // 4. Caracteristicas: se acepta la interseccion con lo que sabemos usar.
    let host = io.inl(io_base + REG_HOST_FEATURES);
    if host & F_MAC == 0 {
        io.outb(io_base + REG_DEVICE_STATUS, STATUS_FAILED);
        return Err(InitError::NoMac);
    }
    let guest = host & ACCEPTED_FEATURES;
    io.outl(io_base + REG_GUEST_FEATURES, guest);

    // 5. MAC y enlace (la configuracion del dispositivo es de solo lectura).
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = io.inb(io_base + REG_CONFIG + i as u16);
    }
    if mac == [0; 6] || mac[0] & 1 != 0 {
        io.outb(io_base + REG_DEVICE_STATUS, STATUS_FAILED);
        return Err(InitError::BadMac);
    }
    let link = if guest & F_STATUS != 0 {
        if io.inw(io_base + REG_CONFIG + 6) & NET_S_LINK_UP != 0 { Link::Up } else { Link::Down }
    } else {
        Link::Unknown
    };

    Ok(NetDevice { addr: dev.addr, vendor: dev.vendor, device: dev.device, io_base, mac, host_features: host, guest_features: guest, link })
}

#[cfg(test)]
mod tests {
    use super::super::pci::sim::*;
    use super::*;

    const BASE: u16 = 0xC040;

    /// Registros legacy de un virtio-net con las caracteristicas y el enlace pedidos.
    fn regs(host: u32, mac: [u8; 6], link_up: bool) -> alloc::vec::Vec<u8> {
        let mut r = alloc::vec![0u8; 32];
        r[0..4].copy_from_slice(&host.to_le_bytes());
        r[20..26].copy_from_slice(&mac);
        r[26] = link_up as u8;
        r
    }

    fn setup(host: u32, mac: [u8; 6], link_up: bool) -> (SimIo, PciDevice) {
        let mut io = SimIo::new();
        io.add(0, 3, 0, SimDevice::new(VENDOR, DEVICE_NET_LEGACY, 0x02, 0x00, 0x00, BASE as u32 | 1));
        io.device_ports = Some((BASE, regs(host, mac, link_up)));
        let dev = pci::scan(&mut io)[0];
        (io, dev)
    }

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    #[test]
    fn a_legacy_net_device_is_negotiated_with_its_mac_and_link() {
        let (mut io, dev) = setup(F_MAC | F_STATUS, MAC, true);
        let n = init(&mut io, &dev).unwrap();
        assert_eq!((n.mac, n.link, n.io_base), (MAC, Link::Up, BASE));
        assert_eq!(n.addr, PciAddress { bus: 0, dev: 3, func: 0 });
        let (mut io, dev) = setup(F_MAC | F_STATUS, MAC, false);
        assert_eq!(init(&mut io, &dev).unwrap().link, Link::Down);
    }

    #[test]
    fn only_the_features_the_kernel_can_use_are_accepted() {
        // el anfitrion ofrece de todo (TSO, mergeable buffers, control queue...): solo MAC y STATUS pasan
        let (mut io, dev) = setup(0xFFFF_FFFF, MAC, true);
        let n = init(&mut io, &dev).unwrap();
        assert_eq!(n.host_features, 0xFFFF_FFFF);
        assert_eq!(n.guest_features, ACCEPTED_FEATURES);
        // y eso es lo que se escribio en el dispositivo
        let written = io.device_ports.as_ref().unwrap().1[4..8].to_vec();
        assert_eq!(u32::from_le_bytes(written.try_into().unwrap()), ACCEPTED_FEATURES);
    }

    #[test]
    fn without_the_status_feature_the_link_is_unknown_not_assumed_up() {
        let (mut io, dev) = setup(F_MAC, MAC, true);
        assert_eq!(init(&mut io, &dev).unwrap().link, Link::Unknown);
    }

    #[test]
    fn the_handshake_stops_before_driver_ok_and_bus_master() {
        let (mut io, dev) = setup(F_MAC | F_STATUS, MAC, true);
        init(&mut io, &dev).unwrap();
        let st = io.device_ports.as_ref().unwrap().1[18];
        assert_eq!(st, STATUS_ACKNOWLEDGE | STATUS_DRIVER, "sin DRIVER_OK: el dispositivo no esta activo");
        assert_eq!(pci::command(&mut io, dev.addr) & 0x0004, 0, "sin bus master: no puede hacer DMA");
        // ninguna escritura toco los registros de colas (8..18)
        assert!(io.port_writes.iter().all(|(p, _)| !(BASE + 8..BASE + 18).contains(p)));
    }

    #[test]
    fn a_missing_mac_feature_or_a_bad_mac_fails_closed_and_marks_failed() {
        let (mut io, dev) = setup(F_STATUS, MAC, true);
        assert_eq!(init(&mut io, &dev), Err(InitError::NoMac));
        assert_eq!(io.device_ports.as_ref().unwrap().1[18], STATUS_FAILED);
        for bad in [[0u8; 6], [0x01, 0x00, 0x5E, 0, 0, 1]] {
            let (mut io, dev) = setup(F_MAC | F_STATUS, bad, true);
            assert_eq!(init(&mut io, &dev), Err(InitError::BadMac), "{bad:?}");
            assert_eq!(io.device_ports.as_ref().unwrap().1[18], STATUS_FAILED);
        }
    }

    #[test]
    fn a_device_that_never_finishes_the_reset_times_out_instead_of_hanging() {
        let (mut io, dev) = setup(F_MAC, MAC, true);
        io.device_ports.as_mut().unwrap().1[18] = STATUS_ACKNOWLEDGE; // el estado no vuelve a 0
        io.reset_never_completes = true;
        assert_eq!(init(&mut io, &dev), Err(InitError::ResetTimeout));
    }

    #[test]
    fn a_memory_bar_or_an_unassigned_bar_is_rejected_before_touching_the_device() {
        for (bar0, expected) in [(0xFEBC_0000u32, InitError::NotIoBar), (0x0001_0001, InitError::NotIoBar), (1, InitError::Unassigned)] {
            let mut io = SimIo::new();
            io.add(0, 3, 0, SimDevice::new(VENDOR, DEVICE_NET_LEGACY, 0x02, 0, 0, bar0));
            io.device_ports = Some((BASE, regs(F_MAC, MAC, true)));
            let dev = pci::scan(&mut io)[0];
            assert_eq!(init(&mut io, &dev), Err(expected), "{bar0:#x}");
            assert!(io.port_writes.is_empty(), "no se escribio nada al dispositivo");
        }
    }
}
