// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! `SystemInfo` (I-42): consulta al kernel y formato de sus respuestas.
//!
//! Los formateadores son funciones puras sobre palabras ya leidas (probadas en el host): lo que
//! muestra la shell es exactamente lo que el kernel dijo, nunca texto fijo. Cada linea cabe en
//! `LINE` bytes para que un worker pueda entregarla por `ProcessOutput`.

use crate::text::format_u64;
use crate::{decode, syscall4, Errno, SyscallNumber};
use trunomy_abi::sysinfo as k;

pub const LINE: usize = trunomy_abi::output::MAX_OUTPUT;

/// Linea de texto de tamano fijo; lo que no cabe se corta y se marca con `...`.
pub struct Line {
    buf: [u8; LINE],
    len: usize,
    cut: bool,
}

impl Line {
    pub const fn new() -> Self {
        Self { buf: [0; LINE], len: 0, cut: false }
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        for &c in b {
            if self.len < LINE - 3 {
                self.buf[self.len] = c;
                self.len += 1;
            } else {
                self.cut = true;
            }
        }
        self
    }

    pub fn num(&mut self, v: u64) -> &mut Self {
        let mut t = [0u8; 20];
        let s = format_u64(v, &mut t);
        self.bytes(s)
    }

    /// `v` en hexadecimal con exactamente `digits` cifras (minusculas).
    pub fn hex(&mut self, v: u64, digits: u32) -> &mut Self {
        for i in (0..digits).rev() {
            let d = ((v >> (4 * i)) & 0xF) as u8;
            self.bytes(&[if d < 10 { b'0' + d } else { b'a' + d - 10 }]);
        }
        self
    }

    /// Cierra la linea: si se corto, termina en `...`.
    pub fn finish(&mut self) -> &[u8] {
        if self.cut {
            self.buf[self.len..self.len + 3].copy_from_slice(b"...");
            self.len += 3;
            self.cut = false;
        }
        &self.buf[..self.len]
    }
}

/// Lee `kind` del kernel en `out`; devuelve el numero de palabras (kinds fijos) o registros (listas).
pub fn query(kind: u64, arg: u64, out: &mut [u64]) -> Result<usize, Errno> {
    let n = decode(unsafe { syscall4(SyscallNumber::SystemInfo.number(), kind, out.as_mut_ptr() as u64, (out.len() * 8) as u64, arg) })?;
    Ok(n as usize)
}

/// "read,write,delegate" (o "-" sin derechos).
pub fn rights_text(bits: u64, line: &mut Line) {
    const NAMES: [(u64, &str); 5] = [
        (trunomy_abi::rights::READ, "read"),
        (trunomy_abi::rights::WRITE, "write"),
        (trunomy_abi::rights::SEND, "send"),
        (trunomy_abi::rights::RECEIVE, "receive"),
        (trunomy_abi::rights::DELEGATE, "delegate"),
    ];
    let mut first = true;
    for (bit, name) in NAMES {
        if bits & bit != 0 {
            if !first {
                line.str(",");
            }
            line.str(name);
            first = false;
        }
    }
    if first {
        line.str("-");
    }
}

/// Una capability: `object.create` (global) o `data#12:read,write uses=3`.
pub fn cap_text(rec: &[u64], line: &mut Line) {
    let (ty, id, rights, uses) = (rec[0], rec[1], rec[2], rec[3]);
    match (ty, k::global_cap_name(id)) {
        (k::RES_TASK, Some(name)) => {
            line.str(name);
        }
        _ => {
            line.str(match ty {
                k::RES_DATA => "data",
                k::RES_PIPE => "pipe",
                k::RES_ENDPOINT => "endpoint",
                _ => "task",
            });
            line.str("#").num(id).str(":");
            rights_text(rights, line);
            if uses != k::UNLIMITED {
                line.str(" uses=").num(uses);
            }
        }
    }
}

pub fn identity_line(w: &[u64], line: &mut Line) {
    line.str("pid=").num(w[0]).str(" tenant=").num(w[1]).str(" subject=").num(w[2]);
}

fn kib(frames: u64) -> u64 {
    frames * 4
}

pub fn memory_line(w: &[u64], line: &mut Line) {
    line.str("frames: ").num(kib(w[1])).str(" KiB free of ").num(kib(w[0])).str(" KiB | kernel heap: ").num(w[3] / 1024).str(" KiB used of ").num(w[2] / 1024).str(" KiB");
}

pub fn tenant_usage_line(w: &[u64], line: &mut Line) {
    line.str("tenant quota: objects ").num(w[0]).str("/").num(w[1]).str(" | stored ").num(w[2]).str(" bytes (max ").num(w[3]).str(" per object)");
}

pub fn process_line(rec: &[u64], line: &mut Line) {
    line.str("pid=").num(rec[0]).str(" parent=").num(rec[1]).str(if rec[2] == 0 { " running" } else { " zombie" });
}

/// Linea de `net stats` a partir de las palabras de `SystemInfo(NET_STATS)`.
pub fn net_stats_line(w: &[u64], line: &mut Line) {
    line.str("net stats: tx ").num(w[0]).str(" rx ").num(w[1]).str(" | tx full ").num(w[2]).str(" rx dropped ").num(w[3]).str(" | protocol drops ").num(w[5]);
    line.str(match w[4] {
        0 => " | queues ok",
        k::NET_POISON_USED_OVERRUN => " | QUEUE POISONED: device ran ahead of its buffers",
        k::NET_POISON_BAD_ID => " | QUEUE POISONED: device returned a bad id",
        k::NET_POISON_BAD_LEN => " | QUEUE POISONED: device reported an impossible length",
        _ => " | QUEUE POISONED",
    });
}

/// Linea de `net info` a partir de las palabras de `SystemInfo(NET)`.
pub fn net_line(w: &[u64], line: &mut Line) {
    match w[0] {
        k::NET_NEGOTIATED | k::NET_ACTIVE => {
            line.str("net: virtio-net ").hex(w[2] >> 16, 4).str(":").hex(w[2] & 0xFFFF, 4);
            line.str(" pci ").hex(w[1] >> 16, 2).str(":").hex((w[1] >> 8) & 0xFF, 2).str(".").num(w[1] & 0xFF);
            line.str(" mac ");
            for i in 0..6 {
                if i > 0 {
                    line.str(":");
                }
                line.hex(w[3] >> (8 * i), 2);
            }
            line.str(match w[5] {
                k::LINK_UP => " link up",
                k::LINK_DOWN => " link down",
                _ => " link unknown",
            });
            line.str(if w[0] == k::NET_ACTIVE { " | ACTIVE (queues registered, bus master on)" } else { " | negotiated: inactive (net up)" });
        }
        k::NET_UNSUPPORTED => {
            line.str("net: ").hex(w[2] >> 16, 4).str(":").hex(w[2] & 0xFFFF, 4).str(" found, not usable");
            if w[2] == k::VIRTIO_NET_MODERN_ID {
                line.str(" (modern virtio: run QEMU with disable-modern=on)");
            }
        }
        _ => {
            line.str("net: no device");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(f: impl FnOnce(&mut Line)) -> alloc::string::String {
        let mut l = Line::new();
        f(&mut l);
        alloc::string::String::from_utf8(l.finish().to_vec()).unwrap()
    }

    #[test]
    fn identity_and_usage_show_the_kernels_numbers() {
        assert_eq!(text(|l| identity_line(&[1001, 1000, 1001], l)), "pid=1001 tenant=1000 subject=1001");
        assert_eq!(
            text(|l| tenant_usage_line(&[3, 64, 25, 4096], l)),
            "tenant quota: objects 3/64 | stored 25 bytes (max 4096 per object)"
        );
    }

    #[test]
    fn free_reports_the_real_free_frames_not_a_constant() {
        let a = text(|l| memory_line(&[0x6000, 0x542D, 102400, 20480], l));
        let b = text(|l| memory_line(&[0x6000, 0x5416, 102400, 20480], l));
        assert_ne!(a, b, "dos estados distintos dan salidas distintas");
        assert!(a.contains("kernel heap: 20 KiB used of 100 KiB"), "{a}");
        assert!(!a.contains("64K"));
    }

    #[test]
    fn net_active_and_stats_lines_say_what_the_kernel_reports() {
        let act = [k::NET_ACTIVE, 0x0002_00, 0x1AF4_1000, 0x5634_1200_5452, 0, k::LINK_UP];
        let t = text(|l| net_line(&act, l));
        assert!(t.contains("ACTIVE") && t.contains("mac 52:54:00:12:34:56"), "{t}");
        assert_eq!(text(|l| net_stats_line(&[3, 2, 1, 4, 0, 6], l)), "net stats: tx 3 rx 2 | tx full 1 rx dropped 4 | protocol drops 6 | queues ok");
        assert!(text(|l| net_stats_line(&[0, 0, 0, 0, k::NET_POISON_BAD_LEN, 0], l)).contains("POISONED"));
    }

    #[test]
    fn net_info_shows_what_the_kernel_found() {
        // MAC 52:54:00:12:34:56 empaquetada little-endian
        let up = [k::NET_NEGOTIATED, 0x0003_00, 0x1AF4_1000, 0x5634_1200_5452, 0, k::LINK_UP];
        assert_eq!(
            text(|l| net_line(&up, l)),
            "net: virtio-net 1af4:1000 pci 00:03.0 mac 52:54:00:12:34:56 link up | negotiated: inactive (net up)"
        );
        let down = [k::NET_NEGOTIATED, 0x0100, 0x1AF4_1000, 0x5634_1200_5452, 0, k::LINK_DOWN];
        assert!(text(|l| net_line(&down, l)).contains("pci 00:01.0"));
        assert!(text(|l| net_line(&down, l)).contains("link down"));
        assert_eq!(text(|l| net_line(&[k::NET_ABSENT, 0, 0, 0, 0, 0], l)), "net: no device");
        let modern = [k::NET_UNSUPPORTED, 0x0003_00, k::VIRTIO_NET_MODERN_ID, 0, 0, 0];
        assert!(text(|l| net_line(&modern, l)).contains("disable-modern=on"));
    }

    #[test]
    fn rights_are_named_and_empty_is_dash() {
        use trunomy_abi::rights::*;
        assert_eq!(text(|l| rights_text(READ | WRITE | DELEGATE, l)), "read,write,delegate");
        assert_eq!(text(|l| rights_text(0, l)), "-");
    }

    #[test]
    fn caps_global_by_name_and_data_with_rights_and_uses() {
        assert_eq!(text(|l| cap_text(&[k::RES_TASK, 4, 1, k::UNLIMITED], l)), "object.create");
        assert_eq!(text(|l| cap_text(&[k::RES_DATA, 12, 1, 3], l)), "data#12:read uses=3");
        assert_eq!(text(|l| cap_text(&[k::RES_DATA, 4, 3, k::UNLIMITED], l)), "data#4:read,write");
        // un objeto con id 4 NO se confunde con la capability global 4
    }

    #[test]
    fn process_states() {
        assert_eq!(text(|l| process_line(&[1, 0, 0], l)), "pid=1 parent=0 running");
        assert_eq!(text(|l| process_line(&[1001, 1, 1], l)), "pid=1001 parent=1 zombie");
    }

    #[test]
    fn lines_never_overflow_and_mark_the_cut() {
        let long = text(|l| {
            for _ in 0..100 {
                l.str("abcdefghij");
            }
        });
        assert_eq!(long.len(), LINE);
        assert!(long.ends_with("..."));
        let short = text(|l| {
            l.str("ok");
        });
        assert_eq!(short, "ok");
    }
}
