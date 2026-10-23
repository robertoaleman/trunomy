// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! PIC 8259 (legacy). Se remapea sobre vectores >= 0x20 (los 0..31 son excepciones de la
//! CPU) y arranca con TODAS las lineas enmascaradas; cada fuente se habilita explicitamente.
//! El acceso a puertos va detras de `Ports` para poder comprobar la secuencia en el host.

#![allow(dead_code)]

pub const PIC1_CMD: u16 = 0x20;
pub const PIC1_DATA: u16 = 0x21;
pub const PIC2_CMD: u16 = 0xA0;
pub const PIC2_DATA: u16 = 0xA1;
/// Vector de la IRQ0; la IRQn llega en `IRQ_BASE + n`.
pub const IRQ_BASE: u8 = 0x20;
const EOI: u8 = 0x20;

pub trait Ports {
    fn outb(&mut self, port: u16, value: u8);
    fn inb(&mut self, port: u16) -> u8;
    /// Pequena espera entre escrituras al PIC (hardware antiguo).
    fn io_wait(&mut self) {
        self.outb(0x80, 0);
    }
}

/// Puertos reales (solo Ring 0).
pub struct HwPorts;

impl Ports for HwPorts {
    fn outb(&mut self, port: u16, value: u8) {
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)) };
    }
    fn inb(&mut self, port: u16) -> u8 {
        let v: u8;
        unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
        v
    }
}

/// ICW1..4 con desplazamiento 0x20/0x28 y todas las IRQ enmascaradas.
pub fn remap_and_mask_all<P: Ports>(p: &mut P) {
    p.outb(PIC1_CMD, 0x11); // ICW1: init + ICW4
    p.io_wait();
    p.outb(PIC2_CMD, 0x11);
    p.io_wait();
    p.outb(PIC1_DATA, IRQ_BASE); // ICW2: vector base del maestro
    p.io_wait();
    p.outb(PIC2_DATA, IRQ_BASE + 8); // esclavo
    p.io_wait();
    p.outb(PIC1_DATA, 0x04); // ICW3: esclavo en IRQ2
    p.io_wait();
    p.outb(PIC2_DATA, 0x02); // identidad en cascada
    p.io_wait();
    p.outb(PIC1_DATA, 0x01); // ICW4: modo 8086
    p.io_wait();
    p.outb(PIC2_DATA, 0x01);
    p.io_wait();
    p.outb(PIC1_DATA, 0xFF); // todo enmascarado
    p.outb(PIC2_DATA, 0xFF);
}

/// Enmascara o habilita una IRQ (0..15), conservando el resto de la mascara.
pub fn set_irq_masked<P: Ports>(p: &mut P, irq: u8, masked: bool) {
    debug_assert!(irq < 16);
    let (port, bit) = if irq < 8 { (PIC1_DATA, irq) } else { (PIC2_DATA, irq - 8) };
    let mut mask = p.inb(port);
    if masked {
        mask |= 1 << bit;
    } else {
        mask &= !(1 << bit);
    }
    p.outb(port, mask);
    // Una IRQ del esclavo solo llega si la cascada (IRQ2) esta habilitada.
    if irq >= 8 && !masked {
        let m1 = p.inb(PIC1_DATA);
        p.outb(PIC1_DATA, m1 & !(1 << 2));
    }
}

/// Fin de interrupcion de la IRQ `irq`.
pub fn eoi<P: Ports>(p: &mut P, irq: u8) {
    if irq >= 8 {
        p.outb(PIC2_CMD, EOI);
    }
    p.outb(PIC1_CMD, EOI);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Puertos simulados: registra escrituras y guarda los registros de mascara.
    pub struct MockPorts {
        pub writes: Vec<(u16, u8)>,
        pub mask1: u8,
        pub mask2: u8,
    }

    impl MockPorts {
        pub fn new() -> Self {
            Self { writes: Vec::new(), mask1: 0xFF, mask2: 0xFF }
        }
    }

    impl Ports for MockPorts {
        fn outb(&mut self, port: u16, value: u8) {
            match port {
                // El ultimo valor escrito en cada puerto de datos es la mascara vigente
                // (la secuencia de init termina escribiendo 0xFF en ambos).
                PIC1_DATA => self.mask1 = value,
                PIC2_DATA => self.mask2 = value,
                _ => {}
            }
            self.writes.push((port, value));
        }
        fn inb(&mut self, port: u16) -> u8 {
            match port {
                PIC1_DATA => self.mask1,
                PIC2_DATA => self.mask2,
                _ => 0,
            }
        }
    }

    #[test]
    fn remap_sends_the_standard_sequence_and_masks_everything() {
        let mut p = MockPorts::new();
        remap_and_mask_all(&mut p);
        let w: Vec<_> = p.writes.iter().filter(|(port, _)| *port != 0x80).copied().collect();
        assert_eq!(
            w,
            [
                (PIC1_CMD, 0x11), (PIC2_CMD, 0x11),
                (PIC1_DATA, 0x20), (PIC2_DATA, 0x28),
                (PIC1_DATA, 0x04), (PIC2_DATA, 0x02),
                (PIC1_DATA, 0x01), (PIC2_DATA, 0x01),
                (PIC1_DATA, 0xFF), (PIC2_DATA, 0xFF),
            ]
        );
    }

    #[test]
    fn vectors_do_not_overlap_cpu_exceptions() {
        assert!(IRQ_BASE >= 32);
    }

    #[test]
    fn unmasking_one_irq_leaves_the_others_masked() {
        let mut p = MockPorts::new();
        remap_and_mask_all(&mut p);
        set_irq_masked(&mut p, 0, false);
        assert_eq!(p.mask1, 0xFE);
        assert_eq!(p.mask2, 0xFF);
        set_irq_masked(&mut p, 0, true);
        assert_eq!(p.mask1, 0xFF);
    }

    #[test]
    fn slave_irq_also_opens_the_cascade() {
        let mut p = MockPorts::new();
        remap_and_mask_all(&mut p);
        set_irq_masked(&mut p, 8, false);
        assert_eq!(p.mask2, 0xFE);
        assert_eq!(p.mask1, 0xFB);
    }

    #[test]
    fn eoi_goes_to_the_slave_first_only_for_irq_8_and_up() {
        let mut p = MockPorts::new();
        eoi(&mut p, 0);
        assert_eq!(p.writes, [(PIC1_CMD, 0x20)]);
        let mut p = MockPorts::new();
        eoi(&mut p, 9);
        assert_eq!(p.writes, [(PIC2_CMD, 0x20), (PIC1_CMD, 0x20)]);
    }
}
