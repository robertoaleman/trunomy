// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Red, primera capa (I-44): descubrir el dispositivo y dejarlo negociado, sin activarlo.
//!
//! El kernel enumera PCI, reconoce un virtio-net legacy y hace el apreton de manos (ver `virtio`).
//! Con `NetControl(UP)` (solo el lider) se activa (`nic`): colas, bus master, tramas. Todavia no hay
//! autoridad de red para los tenants: eso llega en los parches siguientes. El arranque registra lo
//! encontrado y `SystemInfo(NET)` lo entrega al lider (`net info` en la shell).

pub mod arp;
pub mod endpoint;
pub mod io;
pub mod pci;
pub mod nic;
pub mod virtio;
pub mod vring;

use alloc::format;
use alloc::string::String;
use spin::Mutex;
use trunomy_abi::sysinfo as k;

use io::Io;
use virtio::{InitError, Link, NetDevice};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetState {
    /// No hay ningun dispositivo de red reconocible en los buses explorados.
    Absent,
    /// Hay un virtio-net que el kernel no puede usar todavia (con la razon).
    Unsupported { addr: pci::PciAddress, vendor: u16, device: u16, reason: &'static str },
    /// Reconocido y negociado; inactivo.
    Negotiated(NetDevice),
    /// En marcha (`NetControl(UP)`): colas registradas, bus master y DRIVER_OK.
    Active(NetDevice),
}

static NET: Mutex<NetState> = Mutex::new(NetState::Absent);

/// Busca el primer virtio-net y lo negocia. Puro respecto al hardware: todo pasa por `Io`.
pub fn probe<I: Io>(io: &mut I) -> (NetState, usize) {
    let devices = pci::scan(io);
    let count = devices.len();
    let nic = devices.iter().find(|d| {
        d.vendor == virtio::VENDOR && (d.device == virtio::DEVICE_NET_LEGACY || d.device == virtio::DEVICE_NET_MODERN)
    });
    let state = match nic {
        None => NetState::Absent,
        Some(d) if d.device == virtio::DEVICE_NET_MODERN => NetState::Unsupported {
            addr: d.addr,
            vendor: d.vendor,
            device: d.device,
            reason: "modern virtio (MMIO only): start QEMU with disable-modern=on",
        },
        Some(d) => match virtio::init(io, d) {
            Ok(n) => NetState::Negotiated(n),
            Err(e) => NetState::Unsupported { addr: d.addr, vendor: d.vendor, device: d.device, reason: reason_of(e) },
        },
    };
    (state, count)
}

fn reason_of(e: InitError) -> &'static str {
    e.text()
}

/// Arranque del kernel: sondea el hardware real y guarda el resultado. Devuelve la linea de registro.
pub fn init() -> String {
    let (state, count) = probe(&mut io::HwIo);
    *NET.lock() = state;
    boot_line(&state, count)
}

pub fn state() -> NetState {
    *NET.lock()
}

pub fn format_mac(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

fn pci_text(a: pci::PciAddress) -> String {
    format!("{:02x}:{:02x}.{}", a.bus, a.dev, a.func)
}

fn link_text(l: Link) -> &'static str {
    match l {
        Link::Up => "up",
        Link::Down => "down",
        Link::Unknown => "unknown",
    }
}

/// Linea del registro de arranque.
pub fn boot_line(state: &NetState, pci_count: usize) -> String {
    match state {
        NetState::Absent => format!("[KERNEL] Network: no device ({pci_count} PCI devices on buses 0..{})\n", pci::MAX_BUS - 1),
        NetState::Unsupported { addr, vendor, device, reason } => {
            format!("[KERNEL] Network: {:04x}:{:04x} at PCI {} not usable: {reason}\n", vendor, device, pci_text(*addr))
        }
        NetState::Negotiated(n) => format!(
            "[KERNEL] Network: virtio-net at PCI {} MAC {} link {} (negotiated: inactive until `net up`)\n",
            pci_text(n.addr),
            format_mac(n.mac),
            link_text(n.link)
        ),
        NetState::Active(n) => format!("[KERNEL] Network: virtio-net at PCI {} MAC {} active\n", pci_text(n.addr), format_mac(n.mac)),
    }
}

/// Palabras de `SystemInfo(NET)`. Los campos que no aplican van a cero.
pub fn info_words(state: &NetState) -> [u64; k::NET_WORDS] {
    match state {
        NetState::Absent => [k::NET_ABSENT, 0, 0, 0, 0, k::LINK_UNKNOWN],
        NetState::Unsupported { addr, vendor, device, .. } => {
            [k::NET_UNSUPPORTED, addr.packed(), (*vendor as u64) << 16 | *device as u64, 0, 0, k::LINK_UNKNOWN]
        }
        NetState::Negotiated(n) | NetState::Active(n) => {
            let state = if matches!(state, NetState::Active(_)) { k::NET_ACTIVE } else { k::NET_NEGOTIATED };
            let mut mac = 0u64;
            for (i, b) in n.mac.iter().enumerate() {
                mac |= (*b as u64) << (8 * i);
            }
            [
                state,
                n.addr.packed(),
                (n.vendor as u64) << 16 | n.device as u64,
                mac,
                n.host_features as u64 | (n.guest_features as u64) << 32,
                match n.link {
                    Link::Unknown => k::LINK_UNKNOWN,
                    Link::Down => k::LINK_DOWN,
                    Link::Up => k::LINK_UP,
                },
            ]
        }
    }
}

/// Contadores del camino de datos para `SystemInfo(NET_STATS)`. Sin dispositivo en marcha, todo a cero.
pub fn stats_words() -> [u64; k::NET_STATS_WORDS] {
    #[cfg(not(test))]
    if let Some(n) = LIVE.lock().as_mut() {
        // Las completaciones de envio se cuentan al recogerlas: se recogen antes de informar.
        let _ = n.reap(&mut io::HwIo);
        let s = n.stats();
        let poison = match n.poisoned() {
            None => 0,
            Some(vring::RingError::UsedOverrun) => k::NET_POISON_USED_OVERRUN,
            Some(vring::RingError::BadId) => k::NET_POISON_BAD_ID,
            Some(vring::RingError::BadLen) => k::NET_POISON_BAD_LEN,
        };
        let drops = ENDPOINTS.lock().stats().dropped();
        return [s.tx_frames, s.rx_frames, s.tx_full, s.rx_dropped, poison, drops];
    }
    [0; k::NET_STATS_WORDS]
}

/// Endpoints de red de los actores (I-47). Se cierran al morir el dueno y al cortarse su tenant.
pub static ENDPOINTS: Mutex<endpoint::Table> = Mutex::new(endpoint::Table::new());

/// El proceso `pid` termino: sus endpoints y mensajes pendientes se descartan.
pub fn close_pid(pid: u64) {
    ENDPOINTS.lock().close_pid(pid);
}

/// El dispositivo en marcha, visto por las syscalls de red.
pub struct HwNet;

/// En las pruebas de host no hay dispositivo: las syscalls se prueban con un `NetPort` simulado.
#[cfg(test)]
impl crate::syscall::netio::NetPort for HwNet {
    fn our_mac(&self) -> Option<[u8; 6]> {
        None
    }
    fn send_frame(&self, _frame: &[u8]) -> Result<(), nic::SendError> {
        Err(nic::SendError::Full)
    }
    fn recv_frame(&self) -> Result<Option<alloc::vec::Vec<u8>>, nic::RecvError> {
        Ok(None)
    }
}

#[cfg(not(test))]
impl crate::syscall::netio::NetPort for HwNet {
    fn our_mac(&self) -> Option<[u8; 6]> {
        match state() {
            NetState::Active(d) => Some(d.mac),
            _ => None,
        }
    }
    fn send_frame(&self, frame: &[u8]) -> Result<(), nic::SendError> {
        match LIVE.lock().as_mut() {
            Some(n) => n.send(&mut io::HwIo, frame),
            None => Err(nic::SendError::Full),
        }
    }
    fn recv_frame(&self) -> Result<Option<alloc::vec::Vec<u8>>, nic::RecvError> {
        match LIVE.lock().as_mut() {
            Some(n) => n.recv(&mut io::HwIo),
            None => Ok(None),
        }
    }
}

#[cfg(not(test))]
static LIVE: Mutex<Option<nic::Nic<nic::FrameDma>>> = Mutex::new(None);

/// Sondeos maximos de la autocomprobacion (sin reloj fiable en este punto: acotado por iteraciones).
#[cfg(not(test))]
const SELFTEST_POLLS: u32 = 50_000_000;

/// `NetControl`: se llama solo tras autorizar al lider (ver `syscall::netctl`). Los candados `NET` y
/// `LIVE` se toman por separado, nunca anidados.
#[cfg(not(test))]
pub fn control(op: u64) -> Result<u64, trunomy_abi::Errno> {
    use trunomy_abi::{netctl, Errno};
    let log = |m: &str| crate::print_uart(m);
    let mut io = io::HwIo;
    match op {
        netctl::UP => {
            if LIVE.lock().is_some() {
                return Ok(0);
            }
            // Se vuelve a negociar siempre: tras un fallo o un apagado el dispositivo esta reiniciado.
            let found = pci::scan(&mut io)
                .into_iter()
                .find(|d| d.vendor == virtio::VENDOR && d.device == virtio::DEVICE_NET_LEGACY)
                .ok_or(Errno::ResourceUnavailable)?;
            let dev = virtio::init(&mut io, &found).map_err(|e| {
                log(&format!("[KERNEL] Network: negotiation failed: {}\n", e.text()));
                Errno::ResourceUnavailable
            })?;
            match nic::activate(&mut io, &dev, nic::FrameDma) {
                Ok(n) => {
                    *LIVE.lock() = Some(n);
                    *NET.lock() = NetState::Active(dev);
                    log(&boot_line(&NetState::Active(dev), 0));
                    Ok(0)
                }
                Err(e) => {
                    log(&format!("[KERNEL] Network: activation failed: {}\n", e.text()));
                    Err(Errno::ResourceUnavailable)
                }
            }
        }
        netctl::DOWN => {
            let Some(n) = LIVE.lock().take() else { return Err(Errno::ResourceUnavailable) };
            let dev = match state() {
                NetState::Active(d) => d,
                _ => return Err(Errno::ResourceUnavailable),
            };
            match n.shutdown(&mut io) {
                nic::Shutdown::Clean => {
                    *NET.lock() = NetState::Negotiated(dev);
                    log("[KERNEL] Network: shut down (bus master off, memory wiped and returned)\n");
                    Ok(0)
                }
                nic::Shutdown::Leaked { pages } => {
                    *NET.lock() = NetState::Unsupported { addr: dev.addr, vendor: dev.vendor, device: dev.device, reason: "reset not confirmed: queue memory retained" };
                    log(&format!("[KERNEL] Network: the device did not confirm the reset; {pages} pages retained\n"));
                    Ok(1)
                }
            }
        }
        netctl::SELFTEST => {
            let mac = match state() {
                NetState::Active(d) => d.mac,
                _ => return Err(Errno::ResourceUnavailable),
            };
            let mut live = LIVE.lock();
            let nic = live.as_mut().ok_or(Errno::ResourceUnavailable)?;
            match arp::selftest(nic, &mut io, mac, SELFTEST_POLLS) {
                Ok(Some(_)) => Ok(1),
                Ok(None) => Ok(0),
                Err(_) => Err(Errno::ResourceUnavailable),
            }
        }
        _ => Err(Errno::InvalidArgument),
    }
}

/// En las pruebas de host no hay hardware: la autorizacion se prueba con un `run` simulado.
#[cfg(test)]
pub fn control(_op: u64) -> Result<u64, trunomy_abi::Errno> {
    Err(trunomy_abi::Errno::ResourceUnavailable)
}

#[cfg(test)]
mod tests {
    use super::pci::sim::*;
    use super::*;

    const BASE: u16 = 0xC040;
    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn q35_like(nic: Option<(u16, u32)>) -> SimIo {
        let mut io = SimIo::new();
        io.add(0, 0, 0, SimDevice::new(0x8086, 0x29C0, 0x06, 0x00, 0x00, 0)); // host bridge
        io.add(0, 1, 0, SimDevice::new(0x8086, 0x2922, 0x01, 0x06, 0x00, 0)); // SATA (el disco de arranque)
        if let Some((device, bar0)) = nic {
            io.add(0, 3, 0, SimDevice::new(virtio::VENDOR, device, 0x02, 0x00, 0x00, bar0));
            let mut regs = alloc::vec![0u8; 32];
            regs[0..4].copy_from_slice(&(virtio::F_MAC | virtio::F_STATUS | 1 << 15).to_le_bytes());
            regs[20..26].copy_from_slice(&MAC);
            regs[26] = 1;
            io.device_ports = Some((BASE, regs));
        }
        io
    }

    #[test]
    fn no_nic_means_absent_and_the_other_devices_are_not_mistaken_for_one() {
        let (state, count) = probe(&mut q35_like(None));
        assert_eq!((state, count), (NetState::Absent, 2));
        assert_eq!(info_words(&state), [k::NET_ABSENT, 0, 0, 0, 0, k::LINK_UNKNOWN]);
        assert!(boot_line(&state, count).contains("no device (2 PCI devices"));
    }

    #[test]
    fn a_legacy_virtio_net_is_found_negotiated_and_described() {
        let (state, count) = probe(&mut q35_like(Some((virtio::DEVICE_NET_LEGACY, BASE as u32 | 1))));
        assert_eq!(count, 3);
        let NetState::Negotiated(n) = state else { panic!("{state:?}") };
        assert_eq!(n.mac, MAC);
        assert_eq!(format_mac(n.mac), "52:54:00:12:34:56");
        let line = boot_line(&state, count);
        assert!(line.contains("virtio-net at PCI 00:03.0 MAC 52:54:00:12:34:56 link up"), "{line}");
        assert!(line.contains("inactive"), "no se promete mas de lo que hay: {line}");
        let w = info_words(&state);
        assert_eq!(w[0], k::NET_NEGOTIATED);
        assert_eq!(w[1], 0x0003_00);
        assert_eq!(w[2], 0x1AF4_1000);
        assert_eq!(w[3], 0x5634_1200_5452, "{:#x}", w[3]);
        assert_eq!(w[4] & 0xFFFF_FFFF, (virtio::F_MAC | virtio::F_STATUS | 1 << 15) as u64);
        assert_eq!(w[4] >> 32, (virtio::F_MAC | virtio::F_STATUS) as u64, "el kernel solo acepta MAC y STATUS");
        assert_eq!(w[5], k::LINK_UP);
    }

    #[test]
    fn the_mac_is_packed_little_endian_so_the_shell_can_print_it_in_order() {
        let (state, _) = probe(&mut q35_like(Some((virtio::DEVICE_NET_LEGACY, BASE as u32 | 1))));
        let w = info_words(&state);
        let bytes: alloc::vec::Vec<u8> = (0..6).map(|i| (w[3] >> (8 * i)) as u8).collect();
        assert_eq!(bytes, MAC);
    }

    #[test]
    fn a_modern_only_virtio_net_is_reported_as_unsupported_with_the_fix() {
        let (state, count) = probe(&mut q35_like(Some((virtio::DEVICE_NET_MODERN, 0xFEBC_0000))));
        let NetState::Unsupported { reason, device, .. } = state else { panic!("{state:?}") };
        assert_eq!(device, 0x1041);
        assert!(reason.contains("disable-modern=on"));
        assert_eq!(info_words(&state)[2], k::VIRTIO_NET_MODERN_ID);
        assert!(boot_line(&state, count).contains("not usable"));
    }

    #[test]
    fn a_legacy_device_that_fails_the_handshake_is_unsupported_not_ready() {
        // BAR0 de memoria en un dispositivo "legacy": no se toca y se explica
        let (state, _) = probe(&mut q35_like(Some((virtio::DEVICE_NET_LEGACY, 0xFEBC_0000))));
        let NetState::Unsupported { reason, .. } = state else { panic!("{state:?}") };
        assert_eq!(reason, "BAR0 is not I/O");
    }
}
