// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Interrupciones: pilas, vectores del temporizador y arranque del tick.
//!
//! - Ring 3 -> Ring 0 por interrupcion usa `TSS.rsp0` (pila propia); #DF usa IST1.
//! - IRQ0 (PIT, 100 Hz) -> `clock::advance(1)`, EOI y `dispatch::on_timer_tick()` (planificador
//!   con `try_lock`; puede cambiar de tarea). Las interrupciones solo estan abiertas donde el
//!   codigo interrumpido no tiene candados: Ring 3 e `irq_window()`.
//! - Las syscalls entran con IF=0 (FMASK). Solo `ConsoleRead` abre ventanas breves de
//!   interrupciones mientras espera teclado, para que el reloj siga avanzando.
//! - Interruptor de biseccion: `TIMER_ENABLED = false` deja el kernel como antes (sin PIC/PIT,
//!   Ring 3 con IF=0).

/// `false`: no se programa PIC/PIT y el shell arranca con IF=0 (comportamiento anterior).
pub const TIMER_ENABLED: bool = true;

/// RFLAGS inicial de Ring 3: bit 1 (reservado, siempre 1) + IF segun el interruptor.
pub const fn user_rflags(timer_enabled: bool) -> u64 {
    if timer_enabled { 0x202 } else { 0x002 }
}

/// Ventana corta con interrupciones abiertas dentro de una syscall que espera E/S: una IRQ
/// pendiente en el PIC se entrega en cuanto IF=1, y siempre se vuelve a cerrar. Sin timer
/// configurado no hace nada (con el PIC sin remapear, abrir IF seria peligroso).
#[inline]
pub fn irq_window() {
    #[cfg(not(test))]
    if TIMER_ENABLED {
        unsafe { core::arch::asm!("sti", "nop", "nop", "cli", options(nomem, nostack)) };
    }
}

#[cfg(not(test))]
mod hw {
    use crate::clock;
    use crate::pic::{self, HwPorts, IRQ_BASE};
    use crate::guard::GuardedStack;
    use crate::pit;

    const INT_STACK_SIZE: usize = 16 * 1024;
    const DF_STACK_SIZE: usize = 8 * 1024;

    // Con pagina de guarda debajo (I-36): un desbordamiento falla en vez de pisar memoria vecina.
    // En #DF (pila IST1) el fallo sobre la guarda acaba en fallo triple: el sistema se detiene.
    static mut INT_STACK: GuardedStack<INT_STACK_SIZE> = GuardedStack::new();
    static mut DF_STACK: GuardedStack<DF_STACK_SIZE> = GuardedStack::new();

    pub fn int_guard_page() -> u64 {
        crate::guard::slot((&raw const INT_STACK) as u64, 0, INT_STACK_SIZE).guard
    }

    pub fn df_guard_page() -> u64 {
        crate::guard::slot((&raw const DF_STACK) as u64, 0, DF_STACK_SIZE).guard
    }

    /// Pilas de interrupcion en el TSS. Se llama tras `gdt::init`.
    pub fn init_stacks() {
        let int_top = crate::guard::slot((&raw const INT_STACK) as u64, 0, INT_STACK_SIZE).top;
        let df_top = crate::guard::slot((&raw const DF_STACK) as u64, 0, DF_STACK_SIZE).top;
        crate::gdt::set_rsp0(int_top);
        crate::gdt::set_ist1(df_top);
    }

    /// Reloj + EOI + planificador. El EOI va ANTES del posible cambio de tarea: la tarea
    /// entrante no termina este manejador, y sin EOI el PIC no entregaria mas ticks.
    extern "C" fn timer_tick() {
        clock::advance(1);
        pic::eoi(&mut HwPorts, 0);
        crate::dispatch::on_timer_tick();
    }

    /// IRQ0. Guarda los registros que el codigo Rust puede modificar, llama al tick y vuelve
    /// con iretq. Alineacion: la CPU alinea rsp a 16 y empuja 5 qwords; con 9 pushes mas rsp
    /// queda multiplo de 16 en el `call`.
    #[unsafe(naked)]
    #[no_mangle]
    pub unsafe extern "C" fn irq0_timer_stub() {
        core::arch::naked_asm!(
            "push rax", "push rcx", "push rdx", "push rsi", "push rdi",
            "push r8", "push r9", "push r10", "push r11",
            "cld",
            "call {tick}",
            "pop r11", "pop r10", "pop r9", "pop r8",
            "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
            "iretq",
            tick = sym timer_tick,
        )
    }

    const COM1: u16 = 0x3F8;

    fn inb(port: u16) -> u8 {
        let v: u8;
        unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
        v
    }

    fn outb(port: u16, v: u8) {
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
    }

    /// Vacia el FIFO de la UART hacia el buffer de consola (hasta 64 bytes por IRQ; si queda
    /// algo, la UART vuelve a interrumpir). Despues EOI y despierta a quien espera entrada.
    extern "C" fn serial_irq() {
        let mut n = 0;
        while inb(COM1 + 5) & 0x01 != 0 && n < 64 {
            crate::console::push_input(inb(COM1));
            n += 1;
        }
        pic::eoi(&mut HwPorts, 4);
        crate::dispatch::wake_console_waiter();
    }

    /// IRQ4 (COM1). Mismo esquema de guardado y alineacion que el stub del timer.
    #[unsafe(naked)]
    #[no_mangle]
    pub unsafe extern "C" fn irq4_serial_stub() {
        core::arch::naked_asm!(
            "push rax", "push rcx", "push rdx", "push rsi", "push rdi",
            "push r8", "push r9", "push r10", "push r11",
            "cld",
            "call {irq}",
            "pop r11", "pop r10", "pop r9", "pop r8",
            "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
            "iretq",
            irq = sym serial_irq,
        )
    }

    pub fn serial_handler_addr() -> u64 {
        irq4_serial_stub as *const () as u64
    }

    /// Entrada de consola por IRQ4: FIFO a 1 byte, interrupcion de "dato recibido" y IRQ4
    /// desenmascarada en el PIC. Requiere que `start_timer` ya haya remapeado el PIC.
    pub fn start_serial_irq() {
        // Descarta lo que hubiera en el FIFO para que la linea quede desasertada.
        while inb(COM1 + 5) & 0x01 != 0 {
            let _ = inb(COM1);
        }
        outb(COM1 + 2, 0x07); // FCR: FIFO on, limpia RX/TX, disparo a 1 byte
        outb(COM1 + 4, 0x0B); // MCR: DTR|RTS|OUT2 (OUT2 conecta la UART al PIC)
        outb(COM1 + 1, 0x01); // IER: solo "dato recibido"
        let mut ports = HwPorts;
        pic::set_irq_masked(&mut ports, 4, false);
        crate::console::set_irq_driven(true);
    }

    pub const VECTOR_SERIAL: usize = IRQ_BASE as usize + 4;

    /// IRQ7 espuria del PIC maestro: no se envia EOI.
    #[unsafe(naked)]
    #[no_mangle]
    pub unsafe extern "C" fn irq7_spurious_stub() {
        core::arch::naked_asm!("iretq")
    }

    /// IRQ15 espuria del esclavo: EOI solo al maestro (por la cascada).
    #[unsafe(naked)]
    #[no_mangle]
    pub unsafe extern "C" fn irq15_spurious_stub() {
        core::arch::naked_asm!("push rax", "mov al, 0x20", "out 0x20, al", "pop rax", "iretq")
    }

    pub fn handler_addrs() -> (u64, u64, u64) {
        (
            irq0_timer_stub as *const () as u64,
            irq7_spurious_stub as *const () as u64,
            irq15_spurious_stub as *const () as u64,
        )
    }

    /// Remapea el PIC, programa el PIT a `TICK_HZ` y habilita solo IRQ0. No ejecuta `sti`:
    /// las interrupciones se activan al entrar en Ring 3 (RFLAGS.IF=1 via sysret).
    pub fn start_timer() -> u16 {
        let mut ports = HwPorts;
        pic::remap_and_mask_all(&mut ports);
        let divisor = pit::program(&mut ports, clock::TICK_HZ as u32);
        pic::set_irq_masked(&mut ports, 0, false);
        divisor
    }

    pub const VECTOR_TIMER: usize = IRQ_BASE as usize;
    pub const VECTOR_SPURIOUS_MASTER: usize = IRQ_BASE as usize + 7;
    pub const VECTOR_SPURIOUS_SLAVE: usize = IRQ_BASE as usize + 15;
}

#[cfg(not(test))]
pub use hw::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_rflags_have_if_only_when_the_timer_runs() {
        assert_eq!(user_rflags(true) & 0x200, 0x200);
        assert_eq!(user_rflags(false) & 0x200, 0);
        // bit 1 siempre a 1, nunca IOPL ni NT ni TF/DF
        for on in [true, false] {
            let f = user_rflags(on);
            assert_eq!(f & 0x2, 0x2);
            assert_eq!(f & (0x3000 | 0x4000 | 0x100 | 0x400), 0);
        }
    }
}
