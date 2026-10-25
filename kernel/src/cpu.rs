// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Endurecimiento de la CPU (parche 22, I-37): NX, proteccion de escritura del kernel y
//! SMEP/SMAP.
//!
//! - NX (EFER.NXE): imprescindible antes de poner el bit NX en las tablas del kernel; sin NXE ese
//!   bit es reservado y el primer acceso fallaria. Es obligatorio: sin NX no hay W^X.
//! - CR0.WP: sin el, el kernel ignora el bit de solo lectura de sus propias paginas.
//! - SMEP (CR4.20): el kernel no puede EJECUTAR paginas de usuario.
//! - SMAP (CR4.21): el kernel no puede LEER ni ESCRIBIR paginas de usuario salvo dentro de
//!   `user_window` (`stac`/`clac`), que es el unico sitio que toca memoria de usuario.
//!   Con SMAP activo, un puntero de usuario olvidado en una syscall es un fallo, no una fuga.
//! - SMEP/SMAP dependen de la CPU (en QEMU hace falta `-cpu max` o `host`). Si faltan se avisa y
//!   el kernel sigue, salvo que `REQUIRE_SMEP_SMAP` sea true.

use core::sync::atomic::{AtomicBool, Ordering};

pub const CR0_WP: u64 = 1 << 16;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
pub const EFER_NXE: u64 = 1 << 11;

/// Si es true, el kernel no arranca en una CPU sin SMEP o sin SMAP.
pub const REQUIRE_SMEP_SMAP: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
}

/// Decodifica CPUID.80000001h:EDX (bit 20 = NX) y CPUID.(7,0):EBX (bit 7 = SMEP, 20 = SMAP).
pub const fn decode(ext1_edx: u32, leaf7_ebx: u32) -> Features {
    Features {
        nx: ext1_edx & (1 << 20) != 0,
        smep: leaf7_ebx & (1 << 7) != 0,
        smap: leaf7_ebx & (1 << 20) != 0,
    }
}

/// Valor de CR4 con SMEP/SMAP activados solo para lo que la CPU soporta. No toca otros bits.
pub const fn cr4_with(cr4: u64, f: Features) -> u64 {
    let mut v = cr4;
    if f.smep {
        v |= CR4_SMEP;
    }
    if f.smap {
        v |= CR4_SMAP;
    }
    v
}

static SMAP_ON: AtomicBool = AtomicBool::new(false);

pub fn smap_enabled() -> bool {
    SMAP_ON.load(Ordering::Relaxed)
}

/// Ejecuta `f` con los accesos a memoria de usuario permitidos (`stac` ... `clac`). Con SMAP
/// apagado (CPU sin soporte, o pruebas en el host) solo ejecuta `f`: `stac` en una CPU sin SMAP
/// seria #UD. `f` debe ser corto y no ceder la CPU: el flag AC no se guarda por tarea.
#[inline]
pub fn user_window<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(not(test))]
    {
        if smap_enabled() {
            // SAFETY: SMAP esta activo, luego `stac`/`clac` existen. Sin `nomem`: actuan de
            // barrera para que el compilador no mueva los accesos fuera de la ventana.
            unsafe { core::arch::asm!("stac", options(nostack)) };
            let r = f();
            unsafe { core::arch::asm!("clac", options(nostack)) };
            return r;
        }
    }
    f()
}

#[cfg(not(test))]
pub use hw::harden;

#[cfg(not(test))]
mod hw {
    use super::*;
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    const IA32_EFER: u32 = 0xC000_0080;

    pub fn read_features() -> Features {
        // CPUID existe en todo x86_64 (el intrinseco es seguro); se comprueba la hoja maxima
        // antes de pedir cada una.
        let max = __cpuid(0).eax;
        let max_ext = __cpuid(0x8000_0000).eax;
        let ext1 = if max_ext >= 0x8000_0001 { __cpuid(0x8000_0001).edx } else { 0 };
        let l7 = if max >= 7 { __cpuid_count(7, 0).ebx } else { 0 };
        decode(ext1, l7)
    }

    unsafe fn rdmsr(msr: u32) -> u64 {
        let (lo, hi): (u32, u32);
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
        ((hi as u64) << 32) | lo as u64
    }

    unsafe fn wrmsr(msr: u32, val: u64) {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") val as u32, in("edx") (val >> 32) as u32, options(nomem, nostack, preserves_flags));
    }

    /// Activa NX, WP y SMEP/SMAP. Tras volver bien, el kernel puede usar el bit NX en sus tablas.
    pub unsafe fn harden() -> Result<Features, &'static str> {
        let f = read_features();
        if !f.nx {
            return Err("the CPU does not support NX: without NX there is no W^X");
        }
        if REQUIRE_SMEP_SMAP && !(f.smep && f.smap) {
            return Err("the CPU does not support SMEP/SMAP and REQUIRE_SMEP_SMAP is set");
        }
        wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_NXE);
        if rdmsr(IA32_EFER) & EFER_NXE == 0 {
            return Err("could not enable EFER.NXE");
        }
        let cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr0, {}", in(reg) cr0 | CR0_WP, options(nostack, preserves_flags));
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        let want = cr4_with(cr4, f);
        if want != cr4 {
            core::arch::asm!("mov cr4, {}", in(reg) want, options(nostack, preserves_flags));
        }
        // SMAP_ON solo tras escribir CR4: a partir de aqui `user_window` usa stac/clac.
        SMAP_ON.store(f.smap, Ordering::SeqCst);
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuid_bits_decode_to_the_right_features() {
        assert_eq!(decode(0, 0), Features { nx: false, smep: false, smap: false });
        assert_eq!(decode(1 << 20, 0), Features { nx: true, smep: false, smap: false });
        assert_eq!(decode(0, 1 << 7), Features { nx: false, smep: true, smap: false });
        assert_eq!(decode(0, 1 << 20), Features { nx: false, smep: false, smap: true });
        // los otros bits no se confunden con ellos
        assert_eq!(decode(!(1 << 20), !((1 << 7) | (1 << 20))), Features { nx: false, smep: false, smap: false });
    }

    #[test]
    fn cr4_only_gets_the_bits_the_cpu_supports_and_keeps_the_rest() {
        let base = 0x0000_0000_0000_06F0u64; // PAE, PGE, OSFXSR... como los deja el firmware
        let all = Features { nx: true, smep: true, smap: true };
        assert_eq!(cr4_with(base, all), base | CR4_SMEP | CR4_SMAP);
        let only_smep = Features { nx: true, smep: true, smap: false };
        assert_eq!(cr4_with(base, only_smep), base | CR4_SMEP);
        let none = Features { nx: true, smep: false, smap: false };
        assert_eq!(cr4_with(base, none), base);
        assert_eq!(cr4_with(base, all) & base, base, "no apaga nada");
        assert_eq!(CR4_SMEP, 0x0010_0000);
        assert_eq!(CR4_SMAP, 0x0020_0000);
    }

    #[test]
    fn user_window_runs_the_closure_once_and_returns_its_value() {
        let mut n = 0;
        let r = user_window(|| { n += 1; 7 });
        assert_eq!((n, r), (1, 7));
        assert!(!smap_enabled(), "en el host SMAP nunca se activa");
    }
}
