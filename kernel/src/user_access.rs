// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Capa unica de acceso del kernel a memoria de usuario.
//!
//! Reglas:
//! - El kernel nunca desreferencia un puntero de usuario fuera de esta capa.
//! - Lectura = UNA copia a memoria del kernel; despues solo se usa la copia
//!   (sin doble lectura => sin TOCTOU sobre el contenido).
//! - Se copia exactamente la longitud pedida por el llamante, acotada por un
//!   maximo del kernel; nunca se escribe mas de lo que el usuario ofrecio.
//! - Primero rango (canonico, mitad baja, sin overflow); si hay PML4 de usuario
//!   activa, ademas permisos de pagina (presente, U/S, escritura).
#![allow(dead_code)]

use alloc::vec::Vec;
use trunomy_abi::Errno;

use crate::memory_validation::{validate_user_range, validate_user_read, validate_user_write, UserMemoryError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAccessError {
    Memory(UserMemoryError),
    /// La longitud pedida supera el maximo que el kernel acepta para esta operacion.
    TooLong,
    /// El buffer de usuario es mas pequeno que los datos a entregar.
    BufferTooSmall { needed: usize },
}

impl UserAccessError {
    pub fn errno(self) -> Errno {
        match self {
            UserAccessError::Memory(_) => Errno::InvalidPointer,
            UserAccessError::TooLong => Errno::InvalidArgument,
            UserAccessError::BufferTooSmall { .. } => Errno::BufferTooSmall,
        }
    }
}

impl From<UserMemoryError> for UserAccessError {
    fn from(e: UserMemoryError) -> Self {
        UserAccessError::Memory(e)
    }
}

/// Espacio de direcciones de usuario sobre el que opera el kernel.
/// En el kernel real es `ActiveUserSpace`; en tests, una memoria simulada.
pub trait UserSpace {
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), UserMemoryError>;
    fn write(&self, addr: u64, src: &[u8]) -> Result<(), UserMemoryError>;
}

/// Espacio de usuario actual. Valida rango siempre y paginas cuando hay una PML4
/// de usuario registrada.
pub struct ActiveUserSpace;

impl UserSpace for ActiveUserSpace {
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), UserMemoryError> {
        validate_user_range(addr, dst.len())?;
        if crate::memory::current_user_pml4().is_some() {
            validate_user_read(addr, dst.len())?;
        }
        // SAFETY: rango validado arriba; copia unica a memoria del kernel, dentro de la ventana
        // de SMAP (I-37): es el unico sitio que lee memoria de usuario.
        crate::cpu::user_window(|| unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, dst.as_mut_ptr(), dst.len()) });
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), UserMemoryError> {
        validate_user_range(addr, src.len())?;
        if crate::memory::current_user_pml4().is_some() {
            validate_user_write(addr, src.len())?;
        }
        // SAFETY: rango validado arriba; dentro de la ventana de SMAP (I-37).
        crate::cpu::user_window(|| unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), addr as *mut u8, src.len()) });
        Ok(())
    }
}

/// Region de usuario (puntero, longitud) ya validada en rango. Es solo un
/// descriptor: no concede acceso sin pasar por un `UserSpace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserSlice {
    ptr: u64,
    len: usize,
}

impl UserSlice {
    /// `len == 0` es valido (region vacia, no se toca memoria).
    pub fn new(ptr: u64, len: u64) -> Result<Self, UserAccessError> {
        let len = usize::try_from(len).map_err(|_| UserAccessError::Memory(UserMemoryError::AddressOverflow))?;
        if len > 0 {
            validate_user_range(ptr, len)?;
        }
        Ok(Self { ptr, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copia toda la region a un Vec del kernel. Rechaza regiones > `max_len`
    /// ANTES de reservar memoria (un usuario no puede forzar asignaciones grandes).
    pub fn read_to_vec<S: UserSpace>(&self, space: &S, max_len: usize) -> Result<Vec<u8>, UserAccessError> {
        if self.len > max_len {
            return Err(UserAccessError::TooLong);
        }
        let mut buf = alloc::vec![0u8; self.len];
        if self.len > 0 {
            space.read(self.ptr, &mut buf)?;
        }
        Ok(buf)
    }

    /// Copia la region a `dst`; la longitud de la region debe coincidir exactamente.
    pub fn read_exact<S: UserSpace>(&self, space: &S, dst: &mut [u8]) -> Result<(), UserAccessError> {
        if dst.len() != self.len {
            return Err(UserAccessError::TooLong);
        }
        if self.len > 0 {
            space.read(self.ptr, dst)?;
        }
        Ok(())
    }

    /// Lee `out.len()` palabras u64 (little endian). La region debe medir exactamente 8*N.
    pub fn read_words<S: UserSpace>(&self, space: &S, out: &mut [u64]) -> Result<(), UserAccessError> {
        let bytes = out.len().checked_mul(8).ok_or(UserAccessError::TooLong)?;
        if bytes != self.len {
            return Err(UserAccessError::TooLong);
        }
        let mut raw = alloc::vec![0u8; bytes];
        self.read_exact(space, &mut raw)?;
        for (w, c) in out.iter_mut().zip(raw.chunks_exact(8)) {
            *w = u64::from_le_bytes(c.try_into().unwrap());
        }
        Ok(())
    }

    /// Entrega `data` al usuario. Si la region es menor, no escribe nada y
    /// devuelve `BufferTooSmall{needed}`. Escribe exactamente `data.len()` bytes.
    pub fn write_from<S: UserSpace>(&self, space: &S, data: &[u8]) -> Result<usize, UserAccessError> {
        if data.len() > self.len {
            return Err(UserAccessError::BufferTooSmall { needed: data.len() });
        }
        if !data.is_empty() {
            space.write(self.ptr, data)?;
        }
        Ok(data.len())
    }

    pub fn write_words<S: UserSpace>(&self, space: &S, words: &[u64]) -> Result<usize, UserAccessError> {
        let mut raw = Vec::with_capacity(words.len() * 8);
        for w in words {
            raw.extend_from_slice(&w.to_le_bytes());
        }
        self.write_from(space, &raw)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::memory_validation::USER_MIN;
    use core::cell::RefCell;

    /// Memoria simulada: una ventana [base, base+len) con permisos.
    pub struct MockUserSpace {
        pub base: u64,
        pub mem: RefCell<Vec<u8>>,
        pub writable: bool,
        pub reads: RefCell<usize>,
    }

    impl MockUserSpace {
        pub fn new(len: usize) -> Self {
            Self { base: USER_MIN, mem: RefCell::new(alloc::vec![0; len]), writable: true, reads: RefCell::new(0) }
        }
        fn span(&self, addr: u64, len: usize) -> Result<usize, UserMemoryError> {
            validate_user_range(addr, len)?;
            let off = addr.checked_sub(self.base).ok_or(UserMemoryError::PageNotMapped)? as usize;
            if off + len > self.mem.borrow().len() {
                return Err(UserMemoryError::PageNotMapped);
            }
            Ok(off)
        }
    }

    impl UserSpace for MockUserSpace {
        fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), UserMemoryError> {
            let off = self.span(addr, dst.len())?;
            dst.copy_from_slice(&self.mem.borrow()[off..off + dst.len()]);
            *self.reads.borrow_mut() += 1;
            Ok(())
        }
        fn write(&self, addr: u64, src: &[u8]) -> Result<(), UserMemoryError> {
            if !self.writable {
                return Err(UserMemoryError::PagePermissionDenied);
            }
            let off = self.span(addr, src.len())?;
            self.mem.borrow_mut()[off..off + src.len()].copy_from_slice(src);
            Ok(())
        }
    }

    #[test]
    fn read_copies_exactly_once_and_honours_length() {
        let sp = MockUserSpace::new(64);
        sp.mem.borrow_mut()[..5].copy_from_slice(b"hello");
        let s = UserSlice::new(USER_MIN, 5).unwrap();
        assert_eq!(s.read_to_vec(&sp, 16).unwrap(), b"hello");
        assert_eq!(*sp.reads.borrow(), 1);
    }

    #[test]
    fn oversized_request_is_rejected_before_allocating_or_reading() {
        let sp = MockUserSpace::new(64);
        let s = UserSlice::new(USER_MIN, 1 << 40).unwrap();
        assert_eq!(s.read_to_vec(&sp, 4096), Err(UserAccessError::TooLong));
        assert_eq!(*sp.reads.borrow(), 0);
    }

    #[test]
    fn bad_pointers_are_rejected_at_construction() {
        assert!(matches!(UserSlice::new(0, 8), Err(UserAccessError::Memory(UserMemoryError::NullPointer))));
        assert!(matches!(UserSlice::new(u64::MAX - 1, 8), Err(UserAccessError::Memory(UserMemoryError::AddressOverflow))));
        assert!(matches!(UserSlice::new(0xFFFF_8000_0000_0000, 8), Err(UserAccessError::Memory(_))));
        assert!(UserSlice::new(0, 0).unwrap().is_empty());
    }

    #[test]
    fn unmapped_memory_is_an_invalid_pointer() {
        let sp = MockUserSpace::new(8);
        let s = UserSlice::new(USER_MIN, 64).unwrap();
        let e = s.read_to_vec(&sp, 64).unwrap_err();
        assert_eq!(e.errno(), Errno::InvalidPointer);
    }

    #[test]
    fn write_never_exceeds_the_data_and_never_overruns_the_user_buffer() {
        let sp = MockUserSpace::new(64);
        sp.mem.borrow_mut().fill(0xAA);
        let s = UserSlice::new(USER_MIN, 8).unwrap();
        assert_eq!(s.write_from(&sp, b"abc").unwrap(), 3);
        assert_eq!(&sp.mem.borrow()[..4], b"abc\xAA");
        let small = UserSlice::new(USER_MIN, 2).unwrap();
        let e = small.write_from(&sp, b"abc").unwrap_err();
        assert_eq!(e, UserAccessError::BufferTooSmall { needed: 3 });
        assert_eq!(e.errno(), Errno::BufferTooSmall);
        assert_eq!(&sp.mem.borrow()[..3], b"abc"); // sin cambios
    }

    #[test]
    fn write_to_readonly_memory_fails() {
        let mut sp = MockUserSpace::new(64);
        sp.writable = false;
        let s = UserSlice::new(USER_MIN, 8).unwrap();
        assert_eq!(s.write_from(&sp, b"x").unwrap_err().errno(), Errno::InvalidPointer);
    }

    // I-20: validar y acceder son UN solo paso. `UserSlice` guarda solo (puntero, longitud): no es
    // una "prueba de validez" que sobreviva al cambio de mapeo; cada acceso vuelve a mirar el
    // espacio de usuario en el momento de tocarlo.

    #[test]
    fn a_slice_is_not_a_proof_of_validity_the_mapping_is_checked_at_access_time() {
        let sp = MockUserSpace::new(64);
        sp.mem.borrow_mut().fill(0x5A);
        let s = UserSlice::new(USER_MIN, 64).unwrap(); // el rango era valido al crearla
        // el mapeo cambia DESPUES de crear el descriptor (la memoria "desaparece")
        sp.mem.borrow_mut().truncate(8);
        let mut dst = [0xEEu8; 64];
        assert_eq!(s.read_exact(&sp, &mut dst).unwrap_err().errno(), Errno::InvalidPointer);
        assert!(dst.iter().all(|b| *b == 0xEE), "un acceso fallido no entrega datos a medias");
        assert_eq!(s.read_to_vec(&sp, 64).unwrap_err().errno(), Errno::InvalidPointer);
    }

    #[test]
    fn a_permission_that_changes_after_the_slice_was_built_is_honoured() {
        let mut sp = MockUserSpace::new(64);
        let s = UserSlice::new(USER_MIN, 8).unwrap();
        assert_eq!(s.write_from(&sp, b"ok").unwrap(), 2);
        sp.writable = false; // la pagina pasa a solo lectura
        assert_eq!(s.write_from(&sp, b"no").unwrap_err().errno(), Errno::InvalidPointer);
        assert_eq!(&sp.mem.borrow()[..2], b"ok", "la escritura denegada no modifica nada");
    }

    #[test]
    fn a_rejected_write_leaves_the_user_memory_untouched() {
        let sp = MockUserSpace::new(8);
        sp.mem.borrow_mut().fill(0x11);
        // el descriptor cabe en el rango canonico, pero la memoria real es mas corta
        let s = UserSlice::new(USER_MIN, 64).unwrap();
        assert!(s.write_from(&sp, &[0xFF; 64]).is_err());
        assert!(sp.mem.borrow().iter().all(|b| *b == 0x11), "ni un byte parcial");
    }

    #[test]
    fn words_round_trip_little_endian() {
        let sp = MockUserSpace::new(64);
        let s = UserSlice::new(USER_MIN, 32).unwrap();
        s.write_words(&sp, &[1, 2, 3, 0xDEAD_BEEF]).unwrap();
        let mut out = [0u64; 4];
        s.read_words(&sp, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 0xDEAD_BEEF]);
        let mut wrong = [0u64; 3];
        assert_eq!(s.read_words(&sp, &mut wrong), Err(UserAccessError::TooLong));
    }
}
