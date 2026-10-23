// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Excepciones de CPU (parche 19, I-33): un fallo en Ring 3 mata al proceso culpable, no al sistema.
//!
//! Antes, cualquier #PF/#GP/#UD/#DE caia en un `loop { hlt }` y paraba la maquina entera: un solo
//! worker con un puntero nulo detenia a todos los tenants. Ahora cada excepcion entra por un stub
//! que apila `(vector, codigo de error)` y llama a `exception_entry`:
//!
//! - **CS.RPL == 3** (el fallo ocurrio en Ring 3): se termina SOLO ese proceso con el codigo
//!   `abi::exit::fault(vector)`, se audita y se despierta al padre. Si el proceso es la shell raiz
//!   (no esta en la tabla de procesos) no hay a quien devolver el control: se detiene el sistema.
//! - **CS.RPL == 0** (bug del kernel): se imprime el estado y se detiene la CPU, como antes. Un
//!   fallo del propio kernel nunca se "contiene".
//!
//! La excepcion de Ring 3 llega por `TSS.rsp0` = la pila de kernel de la propia tarea, igual que
//! una syscall, asi que terminar la tarea desde aqui es el mismo camino que `ProcessExit`.
//! La decision (`origin`, `has_error_code`) es codigo puro, probado en el host; los stubs y la
//! entrada solo existen en el kernel real.

#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    User,
    Kernel,
}

/// Nivel de privilegio del codigo interrumpido, segun el CS guardado por la CPU.
pub const fn origin(cs: u64) -> Origin {
    if cs & 3 == 3 {
        Origin::User
    } else {
        Origin::Kernel
    }
}

/// Excepciones para las que la CPU empuja un codigo de error.
pub const fn has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

/// Vectores que contiene este modulo (todas las excepciones de CPU que un proceso de usuario
/// puede provocar). #DF (8) tiene su propia pila IST y detiene el sistema; #NMI (2) y #MC (18)
/// no dependen del proceso.
pub const CONTAINED: [u8; 15] = [0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 16, 17, 19];

/// CR2 solo significa algo en un #PF; en los demas vectores guarda la direccion del ultimo fallo
/// de pagina anterior (posiblemente de otro proceso): mostrarla filtraria ese dato.
pub const fn shows_cr2(vector: u64) -> bool {
    vector == 14
}

#[cfg(not(test))]
pub use hw::stub_table;

#[cfg(not(test))]
mod hw {
    use super::*;
    use crate::syscall::spawn::fault_with;

    #[unsafe(naked)]
    unsafe extern "C" fn exc_common() {
        // Pila al entrar: [vector][codigo de error][rip][cs][rflags][rsp][ss]. No se vuelve nunca:
        // no hace falta guardar registros.
        core::arch::naked_asm!(
            "cld",
            "mov rdi, [rsp]",
            "mov rsi, [rsp + 8]",
            "mov rdx, [rsp + 16]",
            "mov rcx, [rsp + 24]",
            "mov r8, cr2",
            "and rsp, -16",
            "call {entry}",
            "2:",
            "hlt",
            "jmp 2b",
            entry = sym exception_entry,
        )
    }

    macro_rules! stub {
        ($name:ident, $vec:literal, err) => {
            #[unsafe(naked)]
            unsafe extern "C" fn $name() {
                core::arch::naked_asm!("push {v}", "jmp {c}", v = const $vec, c = sym exc_common)
            }
        };
        ($name:ident, $vec:literal, noerr) => {
            #[unsafe(naked)]
            unsafe extern "C" fn $name() {
                core::arch::naked_asm!("push 0", "push {v}", "jmp {c}", v = const $vec, c = sym exc_common)
            }
        };
    }

    stub!(exc0, 0, noerr);
    stub!(exc1, 1, noerr);
    stub!(exc3, 3, noerr);
    stub!(exc4, 4, noerr);
    stub!(exc5, 5, noerr);
    stub!(exc6, 6, noerr);
    stub!(exc7, 7, noerr);
    stub!(exc10, 10, err);
    stub!(exc11, 11, err);
    stub!(exc12, 12, err);
    stub!(exc13, 13, err);
    stub!(exc14, 14, err);
    stub!(exc16, 16, noerr);
    stub!(exc17, 17, err);
    stub!(exc19, 19, noerr);

    /// `(vector, direccion del stub)` de todas las excepciones contenidas.
    pub fn stub_table() -> [(usize, u64); 15] {
        let f = |v: usize, a: unsafe extern "C" fn()| (v, a as usize as u64);
        [
            f(0, exc0), f(1, exc1), f(3, exc3), f(4, exc4), f(5, exc5), f(6, exc6), f(7, exc7),
            f(10, exc10), f(11, exc11), f(12, exc12), f(13, exc13), f(14, exc14),
            f(16, exc16), f(17, exc17), f(19, exc19),
        ]
    }

    fn halt_forever() -> ! {
        loop {
            unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
        }
    }

    fn report(prefix: &str, vector: u64, error: u64, rip: u64, cr2: u64) {
        let p = |s: &str| crate::print_uart(s);
        let h = |v: u64| crate::print_uart_hex(v);
        p(prefix);
        p(" vector=0x");
        h(vector);
        p(" error=0x");
        h(error);
        p(" rip=0x");
        h(rip);
        if shows_cr2(vector) {
            p(" cr2=0x");
            h(cr2);
        }
        p("\n");
    }

    extern "C" fn exception_entry(vector: u64, error: u64, rip: u64, cs: u64, cr2: u64) -> ! {
        match origin(cs) {
            Origin::Kernel => {
                report("\n[KERNEL EXCEPTION] system halted:", vector, error, rip, cr2);
                halt_forever()
            }
            Origin::User => {
                let current = crate::process::current_process();
                crate::print_uart("\n[FAULT] process 0x");
                crate::print_uart_hex(current.pid);
                crate::print_uart(": ");
                crate::print_uart(trunomy_abi::exit::exception_name(vector as u8));
                report("", vector, error, rip, cr2);
                if fault_with(current, vector as u8, &crate::dispatch::HwPlatform, &crate::proctab::PROCS) {
                    // `exit_current` no vuelve; si lo hiciera, es un bug del kernel.
                    report("[KERNEL EXCEPTION] exit_current returned:", vector, error, rip, cr2);
                } else {
                    crate::print_uart("[FAULT] it was the root shell: there is no one to hand control back to, system halted\n");
                }
                halt_forever()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr2_is_shown_only_for_page_faults() {
        assert!(shows_cr2(14));
        for v in 0..=255u64 {
            if v != 14 { assert!(!shows_cr2(v), "vector {v}"); }
        }
    }

    #[test]
    fn origin_follows_the_requested_privilege_level_of_cs() {
        assert_eq!(origin(0x08), Origin::Kernel, "CS del kernel");
        assert_eq!(origin(0x23), Origin::User, "CS de Ring 3");
        assert_eq!(origin(0x1B), Origin::User);
        // RPL 1 y 2 no se usan: no cuentan como usuario (no se contienen)
        assert_eq!(origin(0x09), Origin::Kernel);
        assert_eq!(origin(0x0A), Origin::Kernel);
    }

    #[test]
    fn error_code_table_matches_the_intel_manual() {
        for v in 0..32u8 {
            let expected = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30].contains(&v);
            assert_eq!(has_error_code(v), expected, "vector {v}");
        }
    }

    #[test]
    fn contained_vectors_are_sorted_unique_and_exclude_double_fault() {
        assert!(CONTAINED.windows(2).all(|w| w[0] < w[1]));
        assert!(!CONTAINED.contains(&8), "#DF no se contiene");
        assert!(!CONTAINED.contains(&2) && !CONTAINED.contains(&18));
        assert!(CONTAINED.iter().all(|v| *v < 32));
    }
}
