// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

#![no_std]
#![no_main]

extern crate alloc;

mod ops;

use libtrunomy::*;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_SIZE: usize = 16 * 1024;
static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[inline(always)]
pub unsafe fn syscall4(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // El heap debe existir antes de la primera asignacion (Vec en los comandos).
    // Sin esto, la primera asignacion falla, el panic handler llama a Halt y el
    // sistema se queda parado justo tras el primer comando que asigna.
    unsafe { ALLOCATOR.lock().init(core::ptr::addr_of_mut!(HEAP_MEM) as *mut u8, HEAP_SIZE); }
    // Si el kernel nos lanzo como worker (ProcessSpawn), la orden esta en la pagina de argumentos:
    // se ejecuta con la identidad del actor y se sale con el resultado. La shell raiz la tiene vacia.
    let startup = unsafe { libtrunomy::worker::startup_args() };
    if !startup.is_empty() {
        run_worker(startup);
    }
    let vga = 0xb8000 as *mut u8;
    unsafe {
        *vga.offset(0) = b'O';
        *vga.offset(1) = 0x0F;
        *vga.offset(2) = b'K';
        *vga.offset(3) = 0x0F;
    }

    initialize_gpu_terminal();
    print_raw(concat!("Welcome to Trunomy OS - True Zero Trust CLI v", env!("CARGO_PKG_VERSION"), "\n"));
    print_raw("Platform: x86_64 | Security Level: Multi-Ring Isolated\n\n");

    loop {
        match ops::current_user_name() {
            Some(name) => { print_raw("λ ["); print_bytes(&name); print_raw("] > "); }
            None => print_raw("λ [Trunomy] > "),
        }

        let mut input_buffer = [0u8; 256];
        let bytes_read = unsafe { syscall_read_keyboard(input_buffer.as_mut_ptr(), 256) };

        if bytes_read <= 0 {
            continue;
        }

        let command_line = &input_buffer[..bytes_read as usize];

        if is_pipeline(command_line) {
            print_raw("pipelines are not implemented in this kernel (CreatePipe is a stub)\n");
        } else {
            execute_single_command(command_line);
        }
    }
}

fn run_worker(args: &[u8]) -> ! {
    use libtrunomy::worker::{execute, Request};
    let code = match Request::decode(args) {
        Some(req) => execute(&req, &mut |b| { let _ = libtrunomy::process::output(b); }),
        None => Errno::InvalidArgument.code(),
    };
    libtrunomy::process::exit(code)
}

fn execute_single_command(command_line: &[u8]) {
    let command_line = trim_ascii(command_line);
    if command_line.is_empty() { return; }
    let (command, arguments) = split_first_word(command_line);

    match command {
        b"help" => cmd_help(),
        b"echo" => cmd_echo(arguments),
        b"status" | b"uname" => cmd_status(),
        b"version" => print_raw(concat!("Trunomy OS v", env!("CARGO_PKG_VERSION"), "\n")),
        b"pwd" => print_raw("/\n"),
        b"ls" => ops::cmd_ls(),
        b"cat" => cmd_cat(arguments),
        b"whoami" => ops::cmd_info(b'w'),
        b"id" => ops::cmd_info(b'i'),
        b"caps" => ops::cmd_info(b'c'),
        b"ps" => ops::cmd_info(b'p'),
        b"free" => ops::cmd_info(b'f'),
        b"net" if trim_ascii(arguments) == b"demo" => ops::cmd_net_demo(execute_single_command),
        b"net" => ops::cmd_net(arguments),
        b"uptime" => ops::cmd_uptime(),
        b"clear" => print_raw("\x1b[2J\x1b[H"),
        b"pipe-demo" => print_raw("pipe-demo: pipes are not implemented in this kernel (CreatePipe is a stub)\n"),
        b"tenant" => ops::cmd_tenant(arguments),
        b"user" => ops::cmd_user(arguments),
        b"su" => ops::cmd_su(arguments),
        b"object" => ops::cmd_object(arguments),
        b"cap" => ops::cmd_cap(arguments),
        b"ipc" => ops::cmd_ipc(arguments),
        b"audit" => ops::cmd_audit(arguments),
        b"selftest" => ops::cmd_selftest(arguments),
        b"demo" => ops::cmd_demo(execute_single_command),
        b"true" => {}
        b"false" => print_raw("false\n"),
        b"halt" | b"poweroff" | b"shutdown" => ops::cmd_halt(),
        b"reboot" => print_raw("reboot: not supported (use halt)\n"),
        b"exit" => print_raw("exit: not available yet\n"),
        _ => {
            print_raw("trunomy: command not found: ");
            print_bytes(command);
            print_raw("\nType 'help' for available commands.\n");
        }
    }
}

fn cmd_help() { print_raw("Built-in commands:\n help       show this help\n echo       print arguments\n status     show kernel/userland status\n version    show OS version\n pwd        print current path\n ls         list object names this identity holds (no filesystem)\n cat        not implemented (no filesystem)\n whoami     name + real pid/tenant/subject from the kernel\n id         real uid/tenant from the kernel\n caps       this identity\'s real capabilities\n ps         kernel process table (root only)\n free       root: real memory; user: own tenant quota\n net        net info|stats|up|down|selftest (root; up enables DMA) | demo (guided tour, root) | loopback <text> | listen <port> [secs] | send <src> <mac|self|bcast> <dst> <text> (users created with `net`)\n uptime     show uptime status\n clear      clear the terminal\n tenant     tenant create <name> | tenant list (tenants, users, permissions; root) | tenant panic <name> [wipe] (emergency cut-off; root) | tenant thaw <name>\n user       user create <name> <tenant> [ipc] [net]\n su         su <user>|root\n object     object create|read|write|delete <name> [text]\n cap        cap grant <user> <name> <rights> [uses] | revoke <name> | forge <user> <name>\n ipc        ipc send <user> <text> | ipc recv (needs `ipc` at user creation; same tenant only)\n audit      show new audit records\n selftest   selftest fault|ud|hang|stack|console (worker containment)\n demo       run the security demo\n true       return success\n false      return failure\n halt       halt the machine (root only; others are denied and audited)\n"); }
fn cmd_echo(arguments: &[u8]) { print_bytes(arguments); print_raw("\n"); }
fn cmd_status() { print_raw(concat!("Trunomy OS v", env!("CARGO_PKG_VERSION"), "\n Kernel: Ring 0\n Shell: Ring 3\n IPC: enabled\n Capabilities: enabled\n Paging: PML4 enabled\n")); }
fn cmd_cat(arguments: &[u8]) { if arguments.is_empty() { print_raw("cat: missing operand\n"); } else { print_raw("cat: filesystem access is not implemented: "); print_bytes(arguments); print_raw("\n"); } }
fn split_first_word(input: &[u8]) -> (&[u8], &[u8]) { match input.iter().position(|&byte| byte == b' ' || byte == b'\t') { Some(index) => (&input[..index], trim_ascii(&input[index..])), None => (input, &[]) } }
fn trim_ascii(input: &[u8]) -> &[u8] { let mut start = 0; let mut end = input.len(); while start < end && matches!(input[start], b' ' | b'\t' | b'\r' | b'\n') { start += 1; } while end > start && matches!(input[end - 1], b' ' | b'\t' | b'\r' | b'\n') { end -= 1; } &input[start..end] }
fn print_bytes(bytes: &[u8]) { for &byte in bytes { unsafe { syscall4(SyscallNumber::ConsoleWrite as u64, byte as u64, 0, 0, 0); } } }
fn is_pipeline(input: &[u8]) -> bool { input.iter().any(|&b| b == b'|') }
unsafe fn syscall_read_keyboard(ptr: *mut u8, max_len: usize) -> i64 { syscall4(SyscallNumber::ConsoleRead as u64, ptr as u64, max_len as u64, 0, 0) as i64 }
fn initialize_gpu_terminal() {}
fn print_raw(msg: &str) { for &byte in msg.as_bytes() { unsafe { syscall4(SyscallNumber::ConsoleWrite as u64, byte as u64, 0, 0, 0); } } }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Un worker que entra en panico termina solo el (sin consola ni Halt: se lo niega el kernel);
    // la shell raiz, que no puede salir, detiene la maquina.
    unsafe {
        syscall4(SyscallNumber::ProcessExit as u64, Errno::ResourceUnavailable.code(), 0, 0, 0);
        syscall4(SyscallNumber::Halt as u64, 0, 0, 0, 0);
    }
    loop {}
}
