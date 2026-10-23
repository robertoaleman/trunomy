// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Enumeracion PCI por el mecanismo 1 (puertos 0xCF8/0xCFC).
//!
//! Acotada a proposito (I-44): solo los buses `0..MAX_BUS`, no se siguen puentes y se guardan como
//! mucho `MAX_DEVICES` dispositivos. Leer la configuracion no cambia nada en el dispositivo; lo unico
//! que este modulo escribe es el bit de "espacio de E/S" del registro de comando, y solo si se pide.

use alloc::vec::Vec;

use super::io::Io;

pub const CONFIG_ADDRESS: u16 = 0xCF8;
pub const CONFIG_DATA: u16 = 0xCFC;
/// Buses explorados: 0..MAX_BUS. QEMU (q35 y pc) pone sus dispositivos integrados en el bus 0.
pub const MAX_BUS: u8 = 8;
pub const MAX_DEVICES: usize = 64;

const OFF_VENDOR_DEVICE: u8 = 0x00;
const OFF_COMMAND: u8 = 0x04;
const OFF_CLASS: u8 = 0x08;
const OFF_HEADER: u8 = 0x0C;
const OFF_BAR0: u8 = 0x10;
/// Bit 0 del comando: el dispositivo responde a los puertos de E/S.
pub const COMMAND_IO_SPACE: u16 = 1 << 0;
/// Bit 2 del comando: bus master, es decir, el dispositivo puede hacer DMA. Solo lo enciende `nic`,
/// despues de validar las colas (I-44); `scan` y `enable_io_space` nunca lo tocan.
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

impl PciAddress {
    /// bus<<16 | dev<<8 | func, como lo entrega `SystemInfo`.
    pub const fn packed(self) -> u64 {
        ((self.bus as u64) << 16) | ((self.dev as u64) << 8) | self.func as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    pub addr: PciAddress,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub header_type: u8,
    /// BAR0 crudo; solo se lee en cabeceras de tipo 0 (si no, 0).
    pub bar0: u32,
}

fn config_address(a: PciAddress, offset: u8) -> u32 {
    0x8000_0000 | (a.bus as u32) << 16 | ((a.dev & 0x1F) as u32) << 11 | ((a.func & 0x07) as u32) << 8 | (offset & 0xFC) as u32
}

pub fn read32<I: Io>(io: &mut I, a: PciAddress, offset: u8) -> u32 {
    io.outl(CONFIG_ADDRESS, config_address(a, offset));
    io.inl(CONFIG_DATA)
}

pub fn read16<I: Io>(io: &mut I, a: PciAddress, offset: u8) -> u16 {
    io.outl(CONFIG_ADDRESS, config_address(a, offset));
    io.inw(CONFIG_DATA + (offset & 2) as u16)
}

/// Escritura de 16 bits. No se hace nunca un 32 bits sobre el comando: la mitad alta es el registro de
/// estado, cuyos bits se limpian al escribir un 1.
pub fn write16<I: Io>(io: &mut I, a: PciAddress, offset: u8, value: u16) {
    io.outl(CONFIG_ADDRESS, config_address(a, offset));
    io.outw(CONFIG_DATA + (offset & 2) as u16, value);
}

fn read_device<I: Io>(io: &mut I, addr: PciAddress) -> Option<PciDevice> {
    let id = read32(io, addr, OFF_VENDOR_DEVICE);
    let vendor = id as u16;
    if vendor == 0xFFFF {
        return None;
    }
    let class = read32(io, addr, OFF_CLASS);
    let header_type = (read32(io, addr, OFF_HEADER) >> 16) as u8;
    let bar0 = if header_type & 0x7F == 0 { read32(io, addr, OFF_BAR0) } else { 0 };
    Some(PciDevice {
        addr,
        vendor,
        device: (id >> 16) as u16,
        class: (class >> 24) as u8,
        subclass: (class >> 16) as u8,
        header_type,
        bar0,
    })
}

/// Dispositivos de los buses `0..MAX_BUS`, como mucho `MAX_DEVICES`.
pub fn scan<I: Io>(io: &mut I) -> Vec<PciDevice> {
    let mut found = Vec::new();
    for bus in 0..MAX_BUS {
        for dev in 0..32u8 {
            let f0 = PciAddress { bus, dev, func: 0 };
            let Some(d0) = read_device(io, f0) else { continue };
            let multifunction = d0.header_type & 0x80 != 0;
            if found.len() < MAX_DEVICES {
                found.push(d0);
            }
            if multifunction {
                for func in 1..8u8 {
                    if let Some(d) = read_device(io, PciAddress { bus, dev, func }) {
                        if found.len() < MAX_DEVICES {
                            found.push(d);
                        }
                    }
                }
            }
        }
    }
    found
}

/// Activa el espacio de E/S del dispositivo (y nada mas). Devuelve si el bit quedo puesto.
pub fn enable_io_space<I: Io>(io: &mut I, a: PciAddress) -> bool {
    let cmd = read16(io, a, OFF_COMMAND);
    if cmd & COMMAND_IO_SPACE == 0 {
        write16(io, a, OFF_COMMAND, cmd | COMMAND_IO_SPACE);
    }
    read16(io, a, OFF_COMMAND) & COMMAND_IO_SPACE != 0
}

/// Enciende el bus master y devuelve si quedo puesto. SOLO para dispositivos ya validados (I-44).
pub fn enable_bus_master<I: Io>(io: &mut I, a: PciAddress) -> bool {
    let cmd = read16(io, a, OFF_COMMAND);
    write16(io, a, OFF_COMMAND, cmd | COMMAND_BUS_MASTER);
    read16(io, a, OFF_COMMAND) & COMMAND_BUS_MASTER != 0
}

/// Apaga el bus master (el dispositivo deja de poder hacer DMA) y devuelve si quedo apagado.
pub fn disable_bus_master<I: Io>(io: &mut I, a: PciAddress) -> bool {
    let cmd = read16(io, a, OFF_COMMAND);
    write16(io, a, OFF_COMMAND, cmd & !COMMAND_BUS_MASTER);
    read16(io, a, OFF_COMMAND) & COMMAND_BUS_MASTER == 0
}

/// Solo lo usan las pruebas (comprobar el estado del comando).
#[cfg(test)]
pub fn command<I: Io>(io: &mut I, a: PciAddress) -> u16 {
    read16(io, a, OFF_COMMAND)
}

/// Bus PCI simulado para las pruebas (tambien lo usa la prueba de `net`).
#[cfg(test)]
pub mod sim {
    use super::*;
    use alloc::collections::BTreeMap;

    /// Configuracion de un dispositivo: 64 dwords.
    pub struct SimDevice {
        pub cfg: [u32; 64],
    }

    impl SimDevice {
        pub fn new(vendor: u16, device: u16, class: u8, subclass: u8, header_type: u8, bar0: u32) -> Self {
            let mut cfg = [0u32; 64];
            cfg[0] = (device as u32) << 16 | vendor as u32;
            cfg[1] = 0x0210_0000; // estado con bits RW1C puestos y comando en 0
            cfg[2] = (class as u32) << 24 | (subclass as u32) << 16;
            cfg[3] = (header_type as u32) << 16;
            cfg[4] = bar0;
            Self { cfg }
        }
    }

    /// Bus + un registro de puertos de dispositivo (virtio legacy) en `io_base`.
    pub struct SimIo {
        pub devices: BTreeMap<(u8, u8, u8), SimDevice>,
        selected: u32,
        /// Escrituras a 0xCFC con 32 bits al comando: debe quedar en 0 (la mitad alta es RW1C).
        pub command_dword_writes: u32,
        pub device_ports: Option<(u16, alloc::vec::Vec<u8>)>,
        pub port_writes: alloc::vec::Vec<(u16, u32)>,
        /// Simula un dispositivo que ignora el reinicio (el estado no vuelve a 0).
        pub reset_never_completes: bool,
    }

    impl SimIo {
        pub fn new() -> Self {
            Self { devices: BTreeMap::new(), selected: 0, command_dword_writes: 0, device_ports: None, port_writes: alloc::vec::Vec::new(), reset_never_completes: false }
        }
        pub fn add(&mut self, bus: u8, dev: u8, func: u8, d: SimDevice) {
            self.devices.insert((bus, dev, func), d);
        }
        fn current(&mut self) -> Option<(&mut SimDevice, usize)> {
            if self.selected & 0x8000_0000 == 0 {
                return None;
            }
            let key = (((self.selected >> 16) & 0xFF) as u8, ((self.selected >> 11) & 0x1F) as u8, ((self.selected >> 8) & 0x07) as u8);
            let reg = ((self.selected >> 2) & 0x3F) as usize;
            self.devices.get_mut(&key).map(|d| (d, reg))
        }
    }

    impl Io for SimIo {
        fn inl(&mut self, port: u16) -> u32 {
            if port == CONFIG_DATA {
                return self.current().map_or(0xFFFF_FFFF, |(d, r)| d.cfg[r]);
            }
            self.dev_read(port, 4)
        }
        fn inw(&mut self, port: u16) -> u16 {
            if (CONFIG_DATA..CONFIG_DATA + 4).contains(&port) {
                let shift = 8 * (port - CONFIG_DATA) as u32;
                return self.current().map_or(0xFFFF, |(d, r)| (d.cfg[r] >> shift) as u16);
            }
            self.dev_read(port, 2) as u16
        }
        fn inb(&mut self, port: u16) -> u8 {
            self.dev_read(port, 1) as u8
        }
        fn outl(&mut self, port: u16, value: u32) {
            if port == CONFIG_ADDRESS {
                self.selected = value;
            } else if port == CONFIG_DATA {
                // 32 bits sobre el registro de comando/estado: el estado es RW1C
                if let Some((d, r)) = self.current() {
                    if r == 1 {
                        d.cfg[1] = (d.cfg[1] & 0xFFFF_0000 & !(value & 0xFFFF_0000)) | (value & 0xFFFF);
                    } else {
                        d.cfg[r] = value;
                    }
                    if r == 1 {
                        self.command_dword_writes += 1;
                    }
                }
            } else {
                self.dev_write(port, value, 4);
            }
        }
        fn outw(&mut self, port: u16, value: u16) {
            if (CONFIG_DATA..CONFIG_DATA + 4).contains(&port) {
                let shift = 8 * (port - CONFIG_DATA) as u32;
                if let Some((d, r)) = self.current() {
                    d.cfg[r] = (d.cfg[r] & !(0xFFFFu32 << shift)) | (value as u32) << shift;
                }
                return;
            }
            self.dev_write(port, value as u32, 2);
        }
        fn outb(&mut self, port: u16, value: u8) {
            self.dev_write(port, value as u32, 1);
        }
    }

    impl SimIo {
        fn dev_read(&mut self, port: u16, width: usize) -> u32 {
            if let Some((base, regs)) = &self.device_ports {
                if port >= *base && (port - base) as usize + width <= regs.len() {
                    let off = (port - base) as usize;
                    let mut v = 0u32;
                    for i in 0..width {
                        v |= (regs[off + i] as u32) << (8 * i);
                    }
                    return v;
                }
            }
            0xFFFF_FFFF >> (32 - 8 * width as u32)
        }
        fn dev_write(&mut self, port: u16, value: u32, width: usize) {
            self.port_writes.push((port, value));
            let never = self.reset_never_completes;
            if let Some((base, regs)) = &mut self.device_ports {
                if port >= *base && (port - *base) as usize + width <= regs.len() {
                    let off = (port - *base) as usize;
                    // offset 18 = DEVICE_STATUS: escribir 0 reinicia (salvo que se simule un cuelgue)
                    if off == 18 && value == 0 && never {
                        return;
                    }
                    // las caracteristicas del anfitrion (offset 0..4) y la configuracion (20..) son de solo lectura
                    if off < 4 || off >= 20 {
                        return;
                    }
                    for i in 0..width {
                        regs[off + i] = (value >> (8 * i)) as u8;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sim::*;
    use super::*;

    fn bus_with_two_devices() -> SimIo {
        let mut io = SimIo::new();
        io.add(0, 0, 0, SimDevice::new(0x8086, 0x29C0, 0x06, 0x00, 0x00, 0));
        io.add(0, 3, 0, SimDevice::new(0x1AF4, 0x1000, 0x02, 0x00, 0x00, 0xC041));
        io
    }

    #[test]
    fn scan_finds_devices_and_decodes_their_ids_and_bar0() {
        let mut io = bus_with_two_devices();
        let found = scan(&mut io);
        assert_eq!(found.len(), 2);
        let nic = found.iter().find(|d| d.vendor == 0x1AF4).unwrap();
        assert_eq!((nic.device, nic.class, nic.subclass, nic.bar0), (0x1000, 0x02, 0x00, 0xC041));
        assert_eq!(nic.addr, PciAddress { bus: 0, dev: 3, func: 0 });
        assert_eq!(nic.addr.packed(), 0x0003_00);
    }

    #[test]
    fn an_empty_bus_finds_nothing() {
        assert!(scan(&mut SimIo::new()).is_empty());
    }

    #[test]
    fn multifunction_devices_expose_their_other_functions_and_single_function_ones_do_not() {
        let mut io = SimIo::new();
        io.add(0, 5, 0, SimDevice::new(0x1111, 0x0001, 0x0C, 0x03, 0x80, 0));
        io.add(0, 5, 2, SimDevice::new(0x1111, 0x0002, 0x0C, 0x03, 0x00, 0));
        // funcion 1 de un dispositivo de una sola funcion: no se explora
        io.add(0, 6, 0, SimDevice::new(0x2222, 0x0001, 0x01, 0x00, 0x00, 0));
        io.add(0, 6, 1, SimDevice::new(0x2222, 0x0002, 0x01, 0x00, 0x00, 0));
        let found = scan(&mut io);
        let ids: Vec<(u16, u16)> = found.iter().map(|d| (d.vendor, d.device)).collect();
        assert!(ids.contains(&(0x1111, 0x0001)) && ids.contains(&(0x1111, 0x0002)));
        assert!(ids.contains(&(0x2222, 0x0001)) && !ids.contains(&(0x2222, 0x0002)));
    }

    #[test]
    fn only_the_first_buses_are_scanned_and_the_list_is_bounded() {
        let mut io = SimIo::new();
        io.add(MAX_BUS, 0, 0, SimDevice::new(0x1234, 0x0001, 0, 0, 0, 0)); // fuera de rango
        assert!(scan(&mut io).is_empty());
        let mut io = SimIo::new();
        for bus in 0..MAX_BUS {
            for dev in 0..32u8 {
                io.add(bus, dev, 0, SimDevice::new(0x1234, dev as u16, 0, 0, 0, 0));
            }
        }
        assert_eq!(scan(&mut io).len(), MAX_DEVICES);
    }

    #[test]
    fn a_header_that_is_not_type_0_has_no_bar0() {
        let mut io = SimIo::new();
        io.add(0, 1, 0, SimDevice::new(0x8086, 0x1234, 0x06, 0x04, 0x01, 0xDEAD_BEEF));
        assert_eq!(scan(&mut io)[0].bar0, 0);
    }

    #[test]
    fn enabling_io_space_changes_only_that_bit_and_never_touches_the_status() {
        let mut io = bus_with_two_devices();
        let a = PciAddress { bus: 0, dev: 3, func: 0 };
        // el firmware dejo bus master puesto (bit 2): se conserva, no se apaga ni se enciende por nuestra cuenta
        io.devices.get_mut(&(0, 3, 0)).unwrap().cfg[1] |= 0x0004;
        assert!(enable_io_space(&mut io, a));
        let cmd = command(&mut io, a);
        assert_eq!(cmd & COMMAND_IO_SPACE, COMMAND_IO_SPACE);
        assert_eq!(cmd & 0x0004, 0x0004, "no se toca el resto del comando");
        assert_eq!(io.devices[&(0, 3, 0)].cfg[1] >> 16, 0x0210, "los bits de estado siguen puestos");
        assert_eq!(io.command_dword_writes, 0, "nunca se escribe el comando con 32 bits");
    }

    #[test]
    fn io_space_is_not_enabled_twice_and_bus_master_is_never_enabled_by_us() {
        let mut io = bus_with_two_devices();
        let a = PciAddress { bus: 0, dev: 3, func: 0 };
        assert!(enable_io_space(&mut io, a));
        assert_eq!(command(&mut io, a), COMMAND_IO_SPACE, "solo E/S, sin bus master");
    }
}
