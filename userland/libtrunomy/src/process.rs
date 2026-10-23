// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Procesos: lanzar un worker con la identidad de un actor, esperarlo y salir.
//! Contrato: kernel/src/syscall/spawn.rs. Solo el lider de la sesion puede lanzar.

use crate::{decode, syscall4, Errno, SyscallNumber};

/// Lanza un proceso que corre como `actor` y recibe `args` (1..=256 bytes). Devuelve su pid.
pub fn spawn(actor: u64, args: &[u8]) -> Result<u64, Errno> {
    decode(unsafe { syscall4(SyscallNumber::ProcessSpawn.number(), actor, args.as_ptr() as u64, args.len() as u64, 0) })
}

/// Espera a que el hijo `pid` termine (plazo por defecto: `DEFAULT_WAIT_TICKS`, 10 s); devuelve su
/// codigo de salida (y el kernel lo recoge). Si el hijo no termina a tiempo, el kernel lo mata.
pub fn wait(pid: u64) -> Result<u64, Errno> {
    wait_output(pid, trunomy_abi::spawn::DEFAULT_WAIT_TICKS).map(|w| w.code)
}

/// Como `wait`, con plazo propio: si el hijo sigue vivo tras `timeout_ticks` (100 por segundo) el
/// kernel lo mata y el codigo es `abi_exit::TIMEOUT`. El plazo es obligatorio: `0` o mas de
/// `abi::spawn::MAX_WAIT_TICKS` es `InvalidArgument`. Un hijo que agota su cuota de CPU termina
/// antes con `abi_exit::CPU_QUOTA`.
pub fn wait_timeout(pid: u64, timeout_ticks: u64) -> Result<u64, Errno> {
    wait_output(pid, timeout_ticks).map(|w| w.code)
}

/// Resultado de esperar a un hijo: su codigo y la salida que dejo (`output`), ya recogido.
pub struct Waited {
    pub code: u64,
    buf: [u8; trunomy_abi::output::MAX_OUTPUT],
    len: usize,
}

impl Waited {
    /// Salida del hijo. Es dato NO confiable: viene de un proceso de otro actor.
    pub fn output(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Como `wait_timeout`, y ademas devuelve la salida del hijo (`ProcessOutput`).
pub fn wait_output(pid: u64, timeout_ticks: u64) -> Result<Waited, Errno> {
    let mut raw = [0u8; trunomy_abi::output::WAIT_RESULT_SIZE];
    decode(unsafe { syscall4(SyscallNumber::ProcessWait.number(), pid, raw.as_mut_ptr() as u64, timeout_ticks, 0) })?;
    let code = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let len = (u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize).min(trunomy_abi::output::MAX_OUTPUT);
    let mut buf = [0u8; trunomy_abi::output::MAX_OUTPUT];
    buf[..len].copy_from_slice(&raw[16..16 + len]);
    Ok(Waited { code, buf, len })
}

/// Un worker deja aqui su salida para su padre (no tiene consola). Hasta `MAX_OUTPUT` bytes en total.
pub fn output(data: &[u8]) -> Result<(), Errno> {
    decode(unsafe { syscall4(SyscallNumber::ProcessOutput.number(), data.as_ptr() as u64, data.len() as u64, 0, 0) }).map(|_| ())
}

/// Mata al hijo `pid` (solo su padre puede). Despues hay que recogerlo con `wait`, que devuelve
/// `abi_exit::KILLED`.
pub fn kill(pid: u64) -> Result<(), Errno> {
    decode(unsafe { syscall4(SyscallNumber::ProcessKill.number(), pid, 0, 0, 0) }).map(|_| ())
}

/// Termina el proceso con `code`. Los codigos del rango `abi_exit` los rechaza el kernel. La shell raiz no puede salir: el kernel lo rechaza y esta
/// funcion cede la CPU indefinidamente (no deberia llamarse desde ella).
pub fn exit(code: u64) -> ! {
    unsafe { syscall4(SyscallNumber::ProcessExit.number(), code, 0, 0, 0) };
    loop {
        unsafe { syscall4(SyscallNumber::Yield.number(), 0, 0, 0, 0) };
    }
}
