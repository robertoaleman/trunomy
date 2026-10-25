// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

pub mod ipc_client;
pub mod net;
pub mod objects;
pub mod process;
pub mod session;
pub mod sysinfo;
pub mod table;
pub mod text;
pub mod worker;


pub use trunomy_abi::audit as abi_audit;
pub use trunomy_abi::exit as abi_exit;
pub use trunomy_abi::panic as abi_panic;
pub use trunomy_abi::netctl as abi_netctl;
pub use trunomy_abi::netio as abi_netio;
pub use trunomy_abi::sysinfo as abi_sysinfo;
pub use trunomy_abi::{decode, TICK_HZ, rights, Errno, Handle, Syscall as SyscallNumber, ERROR_BASE, MAX_INLINE_WORDS};

pub const SYSCALL_PIPE_WRITE: u64 = SyscallNumber::WritePipe as u64;
pub const SYSCALL_PIPE_READ: u64 = SyscallNumber::ReadPipe as u64;
pub const SYSCALL_YIELD: u64 = SyscallNumber::Yield as u64;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum TrunomyObject {
    FileMetadata {
        name: Vec<u8>,
        size_bytes: u64,
        is_directory: bool,
        permissions_hash: [u8; 32],
    },
    NetworkPacket {
        source_ip: [u8; 4],
        payload: Vec<u8>,
    },
    SystemStatus {
        cpu_usage_pct: u8,
        allocated_mem_mb: u32,
    },
}

pub struct StructuredPipe<T> {
    pub pipe_handle: u64,
    _marker: PhantomData<T>,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> StructuredPipe<T> {
    pub fn new(handle: u64) -> Self {
        Self {
            pipe_handle: handle,
            _marker: PhantomData,
        }
    }

    pub fn send(&self, object: &T) -> Result<(), &'static str> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(object, &mut buffer)
            .map_err(|_| "Failed to serialize the binary object")?;

        unsafe {
            let result = syscall_write_pipe(self.pipe_handle, buffer.as_ptr(), buffer.len());
            if result != 0 {
                return Err("Security violation or pipe closed by the kernel");
            }
        }
        Ok(())
    }

    pub fn receive(&self) -> Result<T, &'static str> {
        let mut buffer = Vec::with_capacity(4096);

        unsafe {
            let bytes_read = syscall_read_pipe(self.pipe_handle, buffer.as_mut_ptr(), 4096);
            if bytes_read <= 0 {
                return Err("No data available, or access denied for lack of a capability");
            }
            buffer.set_len(bytes_read as usize);
        }

        let object: T = ciborium::de::from_reader(&buffer[..]).map_err(|_| {
            "Data corruption detected: the binary object does not match the expected type"
        })?;

        Ok(object)
    }
}

#[inline(always)]
pub unsafe fn syscall4(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
    );
    ret
}

pub fn yield_now() {
    unsafe {
        syscall4(SYSCALL_YIELD, 0, 0, 0, 0);
    }
}

unsafe fn syscall_write_pipe(handle: u64, ptr: *const u8, len: usize) -> i64 {
    syscall4(SYSCALL_PIPE_WRITE, handle, ptr as u64, len as u64, 0) as i64
}

unsafe fn syscall_read_pipe(handle: u64, ptr: *mut u8, max_len: usize) -> i64 {
    syscall4(SYSCALL_PIPE_READ, handle, ptr as u64, max_len as u64, 0) as i64
}
