// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// module: kernel/src/idt/handlers.rs

fn print_uart_byte(byte: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3F8u16,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

pub fn print_uart(msg: &str) {
    for byte in msg.bytes() {
        print_uart_byte(byte);
    }
}

pub extern "sysv64" fn double_fault_handler() {
    print_uart("\n[CRITICAL EXCEPTION]: #DF Double Fault (IST1 stack)!\n");
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
