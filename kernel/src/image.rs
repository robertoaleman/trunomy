// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Imagen de usuario verificada y espacio de direcciones de los procesos lanzados (parche 16).
//!
//! La unica imagen que el kernel sabe lanzar es la shell que ya verifico con Ed25519 al arrancar
//! (`register` solo se llama con el resultado de `parse_and_verify`): ningun proceso puede
//! aportar su propio codigo. Disposicion de un proceso (igual para todos):
//! - codigo  : `USER_CODE_BASE`, RWX como lo carga el loader actual (W^X pendiente)
//! - pila    : `USER_STACK_BASE` (4 paginas), RW- sin ejecucion; cima `USER_STACK_TOP`; la pagina
//!   de debajo (entre args y pila) queda SIN mapear: un desbordamiento falla en ella (I-36)
//! - VGA     : 0xB8000 (como la shell raiz)
//! - args    : `ARGS_VADDR`, una pagina R-- sin ejecucion: `[len: u64 LE][bytes...]`
//!   (`len = 0` en la shell raiz; un worker lanzado con `ProcessSpawn` recibe su orden aqui)

use spin::Mutex;

use crate::loader::LoadedBinary;
use crate::memory::ProcessPml4;

pub const USER_CODE_BASE: u64 = 0x0000_0000_4000_0000;
/// Un hueco sin mapear de al menos una pagina (guarda, I-36) separa la pila de la pagina de args.
pub const USER_STACK_BASE: u64 = 0x0000_0000_7FFF_1000;
pub const USER_STACK_TOP: u64 = USER_STACK_BASE + 0x4000;
pub const ARGS_VADDR: u64 = trunomy_abi::spawn::ARGS_VADDR;
pub const MAX_ARGS: usize = trunomy_abi::spawn::MAX_ARGS;

static IMAGE: Mutex<Option<(&'static [u8], u64)>> = Mutex::new(None);

/// Registra la imagen YA verificada (payload sin firma) y su punto de entrada relativo.
pub fn register(payload: &'static [u8], entry_point: u64) {
    *IMAGE.lock() = Some((payload, entry_point));
}

pub fn registered() -> Option<(&'static [u8], u64)> {
    *IMAGE.lock()
}

/// Rellena una pagina de argumentos: longitud (8 bytes) + datos, resto a cero. Escribe en el sitio
/// (la pila de kernel es de 16 KiB: no se construye una pagina temporal).
pub fn fill_args_page(page: &mut [u8], args: &[u8]) {
    let n = args.len().min(MAX_ARGS);
    page.fill(0);
    page[..8].copy_from_slice(&(n as u64).to_le_bytes());
    page[8..8 + n].copy_from_slice(&args[..n]);
}

/// Mapea la pagina de argumentos (solo lectura, sin ejecucion) en `pml4`.
pub unsafe fn map_args(pml4: &mut ProcessPml4, args: &[u8]) -> Result<(), &'static str> {
    let frame = crate::memory::BITMAP_ALLOCATOR.lock().allocate_frame().ok_or("out of memory for the arguments")?;
    fill_args_page(core::slice::from_raw_parts_mut(frame as *mut u8, 4096), args);
    pml4.map_user_page(ARGS_VADDR, frame, false, false)
}

/// Carga codigo, pila, VGA y argumentos en `pml4`. Devuelve el RIP inicial.
pub unsafe fn populate(
    pml4: &mut ProcessPml4,
    payload: &'static [u8],
    entry_point: u64,
    args: &[u8],
) -> Result<u64, &'static str> {
    let bin = LoadedBinary { entry_point, payload, capabilities: &[] };
    bin.load_into_user_space(pml4, USER_CODE_BASE, USER_STACK_BASE)?;
    pml4.map_user_page(0x000B_8000, 0x000B_8000, true, false)?;
    map_args(pml4, args)?;
    Ok(USER_CODE_BASE + entry_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_page_has_length_prefix_and_zero_padding() {
        let mut p = [0u8; 4096];
        fill_args_page(&mut p, b"hola");
        assert_eq!(&p[..8], &4u64.to_le_bytes());
        assert_eq!(&p[8..12], b"hola");
        assert!(p[12..].iter().all(|b| *b == 0));
        fill_args_page(&mut p, b"");
        assert_eq!(&p[..8], &0u64.to_le_bytes(), "la shell raiz: longitud 0");
        assert!(p.iter().all(|b| *b == 0), "se borra lo anterior");
    }

    #[test]
    fn args_are_clamped_to_the_maximum() {
        let big = [7u8; MAX_ARGS + 50];
        let mut p = [0u8; 4096];
        fill_args_page(&mut p, &big);
        assert_eq!(&p[..8], &(MAX_ARGS as u64).to_le_bytes());
        assert!(p[8 + MAX_ARGS..].iter().all(|b| *b == 0));
    }

    #[test]
    fn layout_regions_do_not_overlap_and_stay_in_user_space() {
        let code_end = USER_CODE_BASE + 0x10_0000; // margen de 1 MiB para la imagen
        assert!(code_end < ARGS_VADDR);
        assert!(ARGS_VADDR + 0x1000 <= USER_STACK_BASE);
        // guarda: al menos una pagina sin mapear entre args y pila, y otra sobre la cima
        assert!(ARGS_VADDR + 0x2000 <= USER_STACK_BASE, "hueco de guarda bajo la pila");
        assert_eq!(USER_STACK_BASE % 4096, 0);
        assert!(USER_STACK_TOP < 0x7FFF_F000, "no pisa la pila del spinner (spinner::STACK_PAGE)");
        assert!(USER_STACK_TOP < 0x0000_8000_0000_0000);
        assert_eq!(ARGS_VADDR % 4096, 0);
    }
}
