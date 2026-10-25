// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
// En las pruebas de host no se compilan el arranque ni el hardware (main, UART, GDT/IDT, MSR, paginas de
// proceso reales): lo que solo ellos usan queda sin llamar. En la build real si se avisa de todo.
#![cfg_attr(test, allow(dead_code))]

const MULTIBOOT1_MAGIC: u32 = 0x1BADB002;
const MULTIBOOT1_FLAGS: u32 = 0x00000003;
const MULTIBOOT1_CHECKSUM: u32 = 0u32.wrapping_sub(MULTIBOOT1_MAGIC + MULTIBOOT1_FLAGS);

#[link_section = ".boot"]
#[used]
static MULTIBOOT_HEADER: [u32; 3] = [MULTIBOOT1_MAGIC, MULTIBOOT1_FLAGS, MULTIBOOT1_CHECKSUM];

extern crate alloc;

mod allocator;
mod audit;
mod capabilities;
mod clock;
mod cpu;
mod console;
// El harness de depuracion de dos tenants solo existe en las pruebas: ejecutarlo en cada arranque
// registraba pids 10/20 en los tenants 1/2 y consumia ids de objeto bajos (hallazgo 3 de la revision).
#[cfg(test)]
mod debug;
mod dispatch;
mod faults;
mod guard;
mod gdt;
mod idt;
mod image;
mod interrupts;
mod kmap;
mod lineedit;
mod ipc;
mod loader;
mod memory;
mod memory_validation;
mod net;
mod pic;
mod pit;
mod process;
mod proctab;
mod quota;
// #[cfg(test)]
// mod scenario_agent_support;
mod sched;
#[cfg(not(test))]
mod spinner;
mod syscall;
mod syscalls;
mod user_access;
mod zero_alloc;

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
static SHELL_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/x86_64-unknown-none/release/shell.bin"
));

#[cfg(test)]
static SHELL_BYTES: &[u8] = &[];

fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }
}

fn init_uart() {
    outb(0x3F9, 0);
    outb(0x3FB, 0x80);
    outb(0x3F8, 3);
    outb(0x3F9, 0);
    outb(0x3FB, 3);
    outb(0x3FA, 0xC7);
    outb(0x3FC, 0x0B);
}

fn print_uart(msg: &str) {
    for byte in msg.bytes() {
        outb(0x3F8, byte);
    }
}

fn print_uart_hex(value: u64) {
    let mut buf = [0u8; 16];
    let mut v = value;
    for i in (0..16).rev() {
        let n = (v & 0xF) as u8;
        buf[i] = if n < 10 { b'0' + n } else { b'A' + n - 10 };
        v >>= 4;
    }
    for b in buf {
        outb(0x3F8, b);
    }
}

#[cfg(not(test))]
#[no_mangle]
#[link_section = ".text._start"]
pub extern "sysv64" fn _start(boot_info_ptr: u64) -> ! {
    unsafe {
        core::arch::asm!("cli");
    }
    init_uart();
    print_uart("\n====================================================\n  TRUNOMY OS MICROKERNEL RUNNING IN RING 0\n====================================================\n");
    gdt::init();
    interrupts::init_stacks();
    print_uart("[KERNEL] GDT and TSS loaded (CS: 0x08)\n");
    idt::init();
    print_uart("[KERNEL] IDT initialized\n");
    allocator::init();
    print_uart("[KERNEL] Global allocator ready\n");
    print_uart("[KERNEL] Initializing bitmap allocator + PML4...\n");
    let boot = unsafe { memory::boot_map::read(boot_info_ptr) };
    let plan = match boot {
        Ok((info, regions)) => {
            print_uart("[KERNEL] Bootloader memory map: 0x");
            print_uart_hex(regions.len() as u64);
            print_uart(" regions\n");
            Some((boot_info_ptr, info, regions))
        }
        Err(e) => {
            print_uart("[KERNEL_WARN] BootInfo/memory map not available (");
            print_uart(e.name());
            print_uart("): using the defaults (4 GiB, 32 MiB reserved)\n");
            None
        }
    };
    let mut shell_pml4 = unsafe { memory::init_memory_system(plan) };
    print_uart(if memory::ident::own_tables() {
        "[KERNEL] Own page tables active (identity 0..4 GiB, in kernel frames)\n"
    } else {
        "[KERNEL] Firmware page tables (the kernel's own are not active)\n"
    });
    // Paginas de guarda bajo todas las pilas del kernel (I-36). Antes de crear mas espacios de
    // direcciones: heredan las tablas base. Sin ellas no se sigue (falla cerrado).
    match unsafe { guard::install_base() } {
        Ok(n) => {
            print_uart("[KERNEL] Guard pages active: 0x");
            print_uart_hex(n as u64);
            print_uart("\n");
        }
        Err(_) => {
            print_uart("[KERNEL_ERROR] Could not enable the guard pages (I-36): system halted\n");
            loop {
                unsafe { core::arch::asm!("cli", "hlt"); }
            }
        }
    }
    // NX, WP y SMEP/SMAP (I-37) y W^X del mapa del kernel. Tambien antes de crear mas espacios de
    // direcciones. NX es obligatorio: sin el no hay W^X y el kernel se detiene.
    match unsafe { cpu::harden() } {
        Ok(f) => {
            print_uart("[KERNEL] CPU: NX=");
            print_uart(if f.nx { "yes" } else { "no" });
            print_uart(" SMEP=");
            print_uart(if f.smep { "yes" } else { "NO (warning)" });
            print_uart(" SMAP=");
            print_uart(if f.smap { "yes" } else { "NO (warning)" });
            print_uart("\n");
        }
        Err(e) => {
            print_uart("[KERNEL_ERROR] ");
            print_uart(e);
            print_uart(": system halted\n");
            loop {
                unsafe { core::arch::asm!("cli", "hlt"); }
            }
        }
    }
    match unsafe { kmap::apply_base() } {
        Ok(()) => print_uart("[KERNEL] Kernel W^X active (text R-X, rodata R--, data/bss RW-, rest of RAM non-executable)\n"),
        Err(_) => {
            print_uart("[KERNEL_ERROR] Could not apply W^X to the kernel map (I-37): system halted\n");
            loop {
                unsafe { core::arch::asm!("cli", "hlt"); }
            }
        }
    }
    // Segundo espacio de direcciones (tarea de prueba): se crea ANTES de cargar la shell para
    // partir de las tablas del firmware y no heredar nada de la shell.
    let mut spinner_pml4 = if dispatch::SCHEDULER_ENABLED && dispatch::SPINNER_ENABLED {
        unsafe { memory::ProcessPml4::create_user_space() }
    } else {
        None
    };
    print_uart("[KERNEL] Free frames: 0x");
    print_uart_hex(memory::BITMAP_ALLOCATOR.lock().free_frames() as u64);
    print_uart("\n");
    syscalls::init_root_capabilities();

    print_uart("[KERNEL] Configuring MSRs for SYSCALL/SYSRET...\n");
    unsafe {
        syscalls::init_syscall_msrs(syscalls::asm_syscall_entry as *const () as u64);
    }
    print_uart("[KERNEL] Parsing and verifying the shell...\n");
    let loaded_shell = match loader::TrunomyLoader::parse_and_verify(SHELL_BYTES, &trunomy_abi::trust::SHELL_SIGNING_PUBLIC_KEY) {
        Ok(bin) => bin,
        Err(e) => {
            print_uart("[KERNEL_ERROR] Could not parse the shell: ");
            print_uart(match e {
                loader::LoaderError::InvalidMagic => "InvalidMagic",
                loader::LoaderError::UnsupportedVersion => "UnsupportedVersion",
                loader::LoaderError::UnsupportedArch => "UnsupportedArch",
                loader::LoaderError::InvalidHeaderOffset => "InvalidHeaderOffset",
                loader::LoaderError::SignatureVerificationFailed => "SignatureVerificationFailed",
                loader::LoaderError::BufferTooSmall => "BufferTooSmall",
            });
            print_uart("\n");
            loop {
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    };
    let user_code_base = image::USER_CODE_BASE;
    let user_stack_base = image::USER_STACK_BASE;
    let user_stack_top = image::USER_STACK_TOP;
    // Solo la imagen que acaba de pasar la verificacion de firma puede lanzarse despues.
    image::register(loaded_shell.payload, loaded_shell.entry_point);
    print_uart("[KERNEL] Mapping the shell into user space...\n");
    if let Err(e) = unsafe {
        loaded_shell.load_into_user_space(&mut shell_pml4, user_code_base, user_stack_base)
    } {
        print_uart("[KERNEL_ERROR] Failed to map the shell: ");
        print_uart(e);
        loop {
            unsafe { core::arch::asm!("hlt"); }
        }
    }
    if let Err(e) = shell_pml4.map_user_page(0x000B_8000, 0x000B_8000, true, false) {
        print_uart("[KERNEL_ERROR] Failed to map VGA: ");
        print_uart(e);
        loop {
            unsafe { core::arch::asm!("hlt"); }
        }
    }
    // La shell raiz tambien tiene pagina de argumentos (longitud 0): asi un worker y la raiz
    // arrancan igual y se distinguen solo por ella.
    if let Err(e) = unsafe { image::map_args(&mut shell_pml4, &[]) } {
        print_uart("[KERNEL_ERROR] Failed to map the shell arguments: ");
        print_uart(e);
        loop {
            unsafe { core::arch::asm!("hlt"); }
        }
    }
    if let Ok(l) = trunomy_abi::image::ImageLayout::parse(loaded_shell.payload, loaded_shell.entry_point) {
        print_uart("[KERNEL] W^X image: text pages R-X=0x");
        print_uart_hex((l.text_len / 4096) as u64);
        print_uart(" rodata R--=0x");
        print_uart_hex((l.rodata_len / 4096) as u64);
        print_uart(" data RW-=0x");
        print_uart_hex((l.data_len / 4096) as u64);
        print_uart("\n");
    }
    let shell_entry = user_code_base + loaded_shell.entry_point;
    print_uart("[KERNEL] Shell mapped successfully, entry=0x");
    print_uart_hex(shell_entry);
    if interrupts::TIMER_ENABLED {
        let divisor = interrupts::start_timer();
        print_uart("[KERNEL] Timer: PIT divisor 0x");
        print_uart_hex(divisor as u64);
        print_uart(" (100 Hz), PIC remapped to 0x20, only IRQ0 enabled\n");
    } else {
        print_uart("[KERNEL] Timer disabled (TIMER_ENABLED=false)\n");
    }
    if console::CONSOLE_IRQ_ENABLED && interrupts::TIMER_ENABLED {
        interrupts::start_serial_irq();
        print_uart("[KERNEL] Console: COM1 via IRQ4 (1-byte FIFO), blocking reads\n");
    } else {
        print_uart("[KERNEL] Console: polling (no IRQ4)\n");
    }
    print_uart(&net::init());
    if dispatch::SCHEDULER_ENABLED {
        let shell_process = process::current_process();
        let mut tasks = 0;
        unsafe {
            if let Err(e) = dispatch::create_task(
                shell_process.pid, shell_pml4.cr3_phys, shell_entry, user_stack_top, shell_process,
            ) {
                print_uart("[KERNEL_ERROR] Shell task: ");
                print_uart(e);
                loop { core::arch::asm!("hlt"); }
            }
            tasks += 1;
            if let Some(pml4) = spinner_pml4.as_mut() {
                match spinner::load(pml4) {
                    Ok((rip, rsp)) => {
                        // Sin capabilities: subject 2 no tiene ninguna concedida.
                        let ctx = process::ProcessContext::new(2, 2, 1);
                        match dispatch::create_task(2, pml4.cr3_phys, rip, rsp, ctx) {
                            Ok(()) => tasks += 1,
                            Err(e) => { print_uart("[KERNEL_WARN] Spinner task: "); print_uart(e); print_uart("\n"); }
                        }
                    }
                    Err(e) => { print_uart("[KERNEL_WARN] Could not load the spinner: "); print_uart(e); print_uart("\n"); }
                }
            }
        }
        print_uart("\n[KERNEL] Scheduler: 0x");
        print_uart_hex(tasks);
        print_uart(" tasks, quantum 5 ticks; entering Ring 3...\n");
        unsafe { dispatch::start() }
    }
    print_uart("\n[KERNEL] Switching CR3 and jumping to Ring 3...\n");
    unsafe {
        shell_pml4.switch_to();
        jump_to_ring3(shell_entry, user_stack_top);
    }
}

#[inline(always)]
unsafe fn jump_to_ring3(entry_point: u64, stack_pointer: u64) -> ! {
    core::arch::asm!("cli", "mov rsp, {stack}", "sysretq", stack = in(reg) stack_pointer, in("rcx") entry_point, in("r11") interrupts::user_rflags(interrupts::TIMER_ENABLED), options(noreturn));
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    print_uart("\n!!! KERNEL PANIC DETECTED !!!\n");
    loop {
        unsafe { core::arch::asm!("cli; hlt"); }
    }
}
