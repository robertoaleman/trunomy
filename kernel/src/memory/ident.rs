// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Mapa de identidad PROPIO del kernel (parche 25, I-38).
//!
//! Hasta ahora el kernel heredaba las tablas de paginas del firmware (`SWITCH_CR3=false`): tablas
//! que no controla (pueden ser de solo lectura, tener paginas globales o grandes distintas) y que
//! viven en memoria que el mapa de memoria puede declarar utilizable. Aqui el kernel construye en
//! marcos que reserva el propio allocator una jerarquia PML4 -> PDPT -> 4 PD con paginas de 2 MiB
//! (`0..4 GiB`, RW, presentes, sin USER ni NX: `kmap` las endurece despues) y cambia CR3 a ella.
//! 4 GiB es lo que gestiona el allocator de marcos, asi que ningun marco que reparta queda fuera.
//!
//! Antes de cambiar CR3 se comprueba que lo que el kernel esta usando AHORA (el codigo que corre,
//! la pila, la propia tabla nueva y el `BootInfo`) esta mapeado con identidad en la tabla nueva;
//! si algo falta no se cambia y se sigue con las tablas del firmware (con aviso).

use crate::guard::Tables;
use crate::memory::paging::PageTableEntry;

pub const GIB: u64 = 1 << 30;
pub const PAGE_2M: u64 = 0x20_0000;
/// Memoria mapeada con identidad (= lo que gestiona el allocator de marcos).
pub const IDENTITY_LIMIT: u64 = 4 * GIB;
/// Interruptor de biseccion: `false` = seguir con las tablas del firmware.
pub const OWN_PAGE_TABLES: bool = true;

const P: u64 = PageTableEntry::PRESENT;
const W: u64 = PageTableEntry::WRITABLE;
const PS: u64 = PageTableEntry::HUGE;

/// Construye la jerarquia y devuelve la direccion fisica de la PML4. `None` si no hay marcos.
pub fn build<T: Tables>(t: &mut T) -> Option<u64> {
    let root = t.alloc_table()?;
    t.table(root).clear();
    let pdpt = t.alloc_table()?;
    t.table(pdpt).clear();
    t.table(root).entries[0] = PageTableEntry::new(pdpt, P | W);
    for g in 0..(IDENTITY_LIMIT / GIB) {
        let pd = t.alloc_table()?;
        let table = t.table(pd);
        for i in 0..512u64 {
            table.entries[i as usize] = PageTableEntry::new(g * GIB + i * PAGE_2M, P | W | PS);
        }
        t.table(pdpt).entries[g as usize] = PageTableEntry::new(pd, P | W);
    }
    Some(root)
}

/// Direcciones que deben quedar mapeadas con identidad en `root` antes de cambiar CR3.
pub fn check_identity<T: Tables>(t: &mut T, root: u64, must_map: &[u64]) -> Result<(), u64> {
    for &a in must_map {
        let page = a & !0xFFF;
        if page >= IDENTITY_LIMIT || !crate::guard::is_mapped(t, root, page) {
            return Err(a);
        }
    }
    Ok(())
}

#[cfg(not(test))]
pub use hw::*;

#[cfg(not(test))]
mod hw {
    use super::*;
    use crate::guard::PhysTables;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OWN: AtomicBool = AtomicBool::new(false);

    /// `true` si el kernel corre con sus propias tablas base.
    pub fn own_tables() -> bool {
        OWN.load(Ordering::Relaxed)
    }

    /// Vacia la TLB incluidas las entradas globales (CR4.PGE) y carga `root` en CR3.
    unsafe fn switch_cr3(root: u64) {
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
        if cr4 & (1 << 7) != 0 {
            core::arch::asm!("mov cr4, {}", in(reg) cr4 & !(1u64 << 7), options(nostack, preserves_flags));
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        }
    }

    /// Construye y activa las tablas propias. Devuelve la PML4 nueva, o el motivo por el que se
    /// sigue con las del firmware (en ese caso CR3 no se ha tocado).
    pub unsafe fn install(boot_info_ptr: u64) -> Result<u64, &'static str> {
        if !OWN_PAGE_TABLES {
            return Err("disabled (OWN_PAGE_TABLES=false)");
        }
        let root = build(&mut PhysTables).ok_or("no frames for the kernel's own page tables")?;
        let local = 0u8;
        let must_map = [
            install as *const () as usize as u64, // el codigo que corre
            (&raw const local) as u64,     // la pila actual
            root,                          // la tabla nueva
            boot_info_ptr,                 // el BootInfo
            0xB_8000,                      // VGA (la shell la mapea)
        ];
        if check_identity(&mut PhysTables, root, &must_map).is_err() {
            return Err("the kernel uses memory that the new table does not identity-map");
        }
        switch_cr3(root);
        OWN.store(true, Ordering::SeqCst);
        Ok(root)
    }
}

/// En el host no hay CR3 que cambiar.
#[cfg(test)]
pub unsafe fn install(_boot_info_ptr: u64) -> Result<u64, &'static str> {
    Err("host tests")
}

#[cfg(test)]
pub fn own_tables() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{install as install_guards, is_mapped};
    use crate::memory::paging::PageTable;
    use std::collections::HashMap;

    struct Mem {
        tables: HashMap<u64, Box<PageTable>>,
        next: u64,
        /// Marcos disponibles (`None` = ilimitado).
        budget: Option<usize>,
    }

    impl Mem {
        fn new(budget: Option<usize>) -> Self {
            Mem { tables: HashMap::new(), next: 0x1000, budget }
        }
    }

    impl Tables for Mem {
        fn table(&mut self, phys: u64) -> &mut PageTable {
            self.tables.get_mut(&phys).expect("tabla inexistente")
        }
        fn alloc_table(&mut self) -> Option<u64> {
            if let Some(b) = self.budget.as_mut() {
                if *b == 0 {
                    return None;
                }
                *b -= 1;
            }
            let p = self.next;
            self.next += 0x1000;
            // contenido basura: `build` no debe depender de que el marco venga a cero
            let mut t = Box::new(PageTable::empty());
            for e in t.entries.iter_mut() {
                e.0 = 0xDEAD_BEEF_DEAD_BEEF;
            }
            self.tables.insert(p, t);
            Some(p)
        }
    }

    #[test]
    fn the_table_maps_exactly_the_first_4_gib_with_identity_and_plain_rw() {
        let mut m = Mem::new(None);
        let root = build(&mut m).unwrap();
        assert_eq!(m.tables.len(), 6, "PML4 + PDPT + 4 PD");
        // la PML4 solo tiene la entrada 0
        for (i, e) in m.table(root).entries.iter().enumerate() {
            assert_eq!(e.is_present(), i == 0, "PML4[{i}]");
        }
        let pdpt = m.table(root).entries[0].address();
        for (i, e) in m.table(pdpt).entries.iter().enumerate() {
            assert_eq!(e.is_present(), i < 4, "PDPT[{i}]");
        }
        for g in 0..4u64 {
            let pd = m.table(pdpt).entries[g as usize].address();
            for i in 0..512u64 {
                let e = m.table(pd).entries[i as usize];
                assert_eq!(e.0, (g * GIB + i * PAGE_2M) | 0x83, "pagina {g}/{i}: identidad, P|RW|PS y nada mas");
            }
        }
        // ni USER ni NX en ningun nivel superior
        for e in [m.table(root).entries[0], m.table(pdpt).entries[0]] {
            assert_eq!(e.flags(), 0x3);
        }
    }

    #[test]
    fn running_out_of_frames_fails_instead_of_returning_a_half_built_table() {
        for budget in 0..6 {
            assert_eq!(build(&mut Mem::new(Some(budget))), None, "con {budget} marcos");
        }
        assert!(build(&mut Mem::new(Some(6))).is_some());
    }

    #[test]
    fn the_identity_check_catches_anything_the_new_table_does_not_map() {
        let mut m = Mem::new(None);
        let root = build(&mut m).unwrap();
        assert_eq!(check_identity(&mut m, root, &[0x20_1928, 0x7C82008, 0xB_8000, 0xFFFF_F000]), Ok(()));
        assert_eq!(check_identity(&mut m, root, &[0x20_1928, 0x1_0000_0000]), Err(0x1_0000_0000), "fuera de 4 GiB");
        assert_eq!(check_identity(&mut m, root, &[0xFFFF_8000_0000_0000]), Err(0xFFFF_8000_0000_0000));
        // una pagina desmapeada (p. ej. una guarda) tampoco cuenta
        install_guards(&mut m, root, &[0x20_5000]).unwrap();
        assert_eq!(check_identity(&mut m, root, &[0x20_5000]), Err(0x20_5000));
    }

    #[test]
    fn guards_and_wx_compose_on_top_of_the_new_tables() {
        use crate::kmap::{apply, effective, verify, Eff, Layout, SAMPLES};
        let mut m = Mem::new(None);
        let root = build(&mut m).unwrap();
        let l = Layout { start: 0x20_0000, text: 0x20_1000, rodata: 0x20_4000, data: 0x20_6000, end: 0x20_C000 };
        install_guards(&mut m, root, &[0x20_7000, 0x20_A000]).unwrap();
        apply(&mut m, root, &l).unwrap();
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Ok(()));
        assert_eq!(effective(&mut m, root, 0x20_2000), Some(Eff { write: false, exec: true }));
        assert_eq!(effective(&mut m, root, 0x20_8000), Some(Eff { write: true, exec: false }));
        assert!(!is_mapped(&mut m, root, 0x20_7000));
        assert_eq!(effective(&mut m, root, 0x1000_0000), Some(Eff { write: true, exec: false }), "RAM: RW sin ejecucion");
        // un espacio de usuario copia la PML4 y hereda todo
        let proc_root = m.alloc_table().unwrap();
        for i in 0..512 {
            let e = m.table(root).entries[i];
            m.table(proc_root).entries[i] = e;
        }
        assert_eq!(verify(&mut m, proc_root, &l, &SAMPLES), Ok(()));
        assert!(!is_mapped(&mut m, proc_root, 0x20_A000));
    }

    #[test]
    fn identity_limit_matches_what_the_frame_allocator_manages() {
        // 4 GiB: el bitmap del allocator cubre BITMAP_SIZE_BYTES * 8 marcos de 4 KiB
        assert_eq!(IDENTITY_LIMIT, 4 * 1024 * 1024 * 1024);
        assert_eq!(crate::kmap::IDENTITY_LIMIT, IDENTITY_LIMIT);
        assert_eq!(IDENTITY_LIMIT % PAGE_2M, 0);
    }
}
