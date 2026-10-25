// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! W^X del mapa del kernel (parche 22, I-37).
//!
//! El bootloader entrega el kernel con todo el mapa de identidad como RWX (paginas de 2 MiB).
//! Aqui se endurece en las tablas BASE, antes de crear procesos:
//! - cabecera de la imagen y `.rodata`: solo lectura, sin ejecucion
//! - `.text`: lectura y ejecucion, nunca escritura
//! - `.data` y `.bss`: lectura y escritura, sin ejecucion
//! - el resto de la RAM mapeada (`0..IDENTITY_LIMIT`): sin ejecucion (los datos, pilas, marcos y
//!   tablas de paginas no son codigo)
//!
//! Orden: primero la imagen y despues el resto, de modo que `.text` NUNCA tenga NX en las tablas
//! mientras el kernel se ejecuta desde el (un instante con NX en el codigo en curso seria un
//! fallo del que el kernel no puede recuperarse). Las paginas de 2 MiB que cruzan los limites se
//! parten a 4 KiB con los mismos permisos (`guard::split`); las paginas no presentes (las guardas
//! de I-36) no se tocan. Requiere EFER.NXE ya activo (`cpu::harden`).

use crate::guard::{idx, split, Tables, GUARD_SIZE, PAGE_2M};
use crate::memory::paging::PageTableEntry;

/// RAM mapeada con identidad (la misma que construye `memory::ident`).
pub use crate::memory::ident::IDENTITY_LIMIT;
const PAGE: u64 = GUARD_SIZE as u64;
const W: u64 = PageTableEntry::WRITABLE;
const NX: u64 = PageTableEntry::NO_EXECUTE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    BadLayout,
    NoMemory,
    /// La pagina `va` no tiene los permisos que la politica exige.
    Violation(u64),
}

/// Limites de la imagen del kernel: `[start, text)` cabecera, `[text, rodata)` codigo,
/// `[rodata, data)` solo lectura, `[data, end)` datos y bss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub start: u64,
    pub text: u64,
    pub rodata: u64,
    pub data: u64,
    pub end: u64,
}

impl Layout {
    pub fn validate(&self) -> Result<(), MapError> {
        let b = [self.start, self.text, self.rodata, self.data, self.end];
        if b.iter().any(|v| v % PAGE != 0) {
            return Err(MapError::BadLayout);
        }
        let ordered = self.start <= self.text && self.text < self.rodata && self.rodata <= self.data && self.data < self.end;
        if !ordered || self.end > IDENTITY_LIMIT {
            return Err(MapError::BadLayout);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn update_table<T: Tables>(
    t: &mut T,
    table: u64,
    level: u32,
    base: u64,
    start: u64,
    end: u64,
    set: u64,
    clear: u64,
) -> Result<(), MapError> {
    let size: u64 = 1u64 << (12 + 9 * (level - 1));
    for i in 0..512usize {
        let va = base + i as u64 * size;
        let vend = va + size;
        if vend <= start || va >= end {
            continue;
        }
        let e = t.table(table).entries[i];
        if !e.is_present() {
            continue;
        }
        let covered = start <= va && vend <= end;
        let leaf = level == 1 || e.is_huge();
        if leaf && (covered || level == 1) {
            t.table(table).entries[i] = PageTableEntry((e.0 | set) & !clear);
        } else if leaf {
            // Pagina grande que solo se cubre en parte: se parte con los mismos permisos.
            let ne = split(t, e, size / 512).map_err(|_| MapError::NoMemory)?;
            t.table(table).entries[i] = ne;
            update_table(t, ne.address(), level - 1, va, start, end, set, clear)?;
        } else {
            update_table(t, e.address(), level - 1, va, start, end, set, clear)?;
        }
    }
    Ok(())
}

/// Pone `set` y quita `clear` en las hojas presentes de `[start, end)` (4 KiB alineados, mitad
/// baja). Las paginas grandes que se cubren enteras cambian de una vez; las que se cubren en
/// parte se parten antes.
pub fn update<T: Tables>(t: &mut T, root: u64, start: u64, end: u64, set: u64, clear: u64) -> Result<(), MapError> {
    if start % PAGE != 0 || end % PAGE != 0 || start >= end || end > (1u64 << 47) {
        return Err(MapError::BadLayout);
    }
    for i in 0..256usize {
        let va = (i as u64) << 39;
        if va + (1u64 << 39) <= start || va >= end {
            continue;
        }
        let e = t.table(root).entries[i];
        if !e.is_present() {
            continue;
        }
        update_table(t, e.address(), 3, va, start, end, set, clear)?;
    }
    Ok(())
}

/// Aplica la politica a las tablas `root`. La imagen primero, el resto de la RAM despues.
pub fn apply<T: Tables>(t: &mut T, root: u64, l: &Layout) -> Result<(), MapError> {
    l.validate()?;
    if l.start < l.text {
        update(t, root, l.start, l.text, NX, W)?; // cabecera: R--
    }
    update(t, root, l.text, l.rodata, 0, W | NX)?; // codigo: R-X
    if l.rodata < l.data {
        update(t, root, l.rodata, l.data, NX, W)?; // rodata: R--
    }
    update(t, root, l.data, l.end, NX | W, 0)?; // datos y bss: RW-
    // Resto de la RAM: sin ejecucion (los permisos de escritura no se tocan).
    if l.start > 0 {
        update(t, root, 0, l.start, NX, 0)?;
    }
    update(t, root, l.end, IDENTITY_LIMIT, NX, 0)?;
    Ok(())
}

/// Permisos efectivos de una pagina: escritura = todos los niveles escribibles; ejecucion = ningun
/// nivel con NX. `None` si no esta mapeada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eff {
    pub write: bool,
    pub exec: bool,
}

pub fn effective<T: Tables>(t: &mut T, root: u64, va: u64) -> Option<Eff> {
    let mut write = true;
    let mut exec = true;
    let mut table = root;
    for (level, shift) in [(4u32, 39u32), (3, 30), (2, 21), (1, 12)] {
        let e = t.table(table).entries[idx(va, shift)];
        if !e.is_present() {
            return None;
        }
        write &= e.flags() & W != 0;
        exec &= e.flags() & NX == 0;
        if level == 1 || (level > 1 && level < 4 && e.is_huge()) {
            return Some(Eff { write, exec });
        }
        table = e.address();
    }
    None
}

/// Comprueba que `root` cumple la politica: cada pagina presente de la imagen tiene los permisos
/// de su region, ninguna es escribible y ejecutable a la vez, y las `samples` (RAM fuera de la
/// imagen) no son ejecutables.
pub fn verify<T: Tables>(t: &mut T, root: u64, l: &Layout, samples: &[u64]) -> Result<(), MapError> {
    l.validate()?;
    let mut va = l.start;
    while va < l.end {
        if let Some(e) = effective(t, root, va) {
            let (w, x) = if va < l.text {
                (false, false)
            } else if va < l.rodata {
                (false, true)
            } else if va < l.data {
                (false, false)
            } else {
                (true, false)
            };
            if e.write != w || e.exec != x {
                return Err(MapError::Violation(va));
            }
        }
        va += PAGE;
    }
    for &s in samples {
        if let Some(e) = effective(t, root, s & !(PAGE - 1)) {
            if e.exec {
                return Err(MapError::Violation(s));
            }
        }
    }
    Ok(())
}

/// Paginas de RAM fuera de la imagen que se muestrean al comprobar un espacio de direcciones.
pub const SAMPLES: [u64; 5] = [0x0010_0000, 0x0100_0000, 0x1000_0000, 0x8000_0000, 0xC000_0000 - PAGE_2M];

#[cfg(not(test))]
pub use hw::*;

#[cfg(not(test))]
mod hw {
    use super::*;
    use crate::guard::PhysTables;

    extern "C" {
        static __kernel_start: u8;
        static __text_start: u8;
        static __rodata_start: u8;
        static __data_start: u8;
        static __kernel_end: u8;
    }

    pub fn layout() -> Layout {
        // Simbolos del linker: solo se toma su direccion (`&raw const` de un extern static es seguro).
        Layout {
            start: (&raw const __kernel_start) as u64,
            text: (&raw const __text_start) as u64,
            rodata: (&raw const __rodata_start) as u64,
            data: (&raw const __data_start) as u64,
            end: (&raw const __kernel_end) as u64,
        }
    }

    /// Vacia la TLB entera, incluidas las entradas globales (CR4.PGE).
    fn flush_all() {
        unsafe {
            let cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            if cr4 & (1 << 7) != 0 {
                core::arch::asm!("mov cr4, {}", in(reg) cr4 & !(1u64 << 7), options(nostack, preserves_flags));
                core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
            }
            core::arch::asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _, options(nostack, preserves_flags));
        }
    }

    /// Aplica la politica a las tablas base y la comprueba. Requiere `cpu::harden` hecho antes.
    pub unsafe fn apply_base() -> Result<(), MapError> {
        let root = crate::memory::base_pml4().ok_or(MapError::BadLayout)?;
        let l = layout();
        // Las tablas base son del firmware y pueden ser de solo lectura: se editan con WP apagado.
        crate::guard::without_write_protect(|| apply(&mut PhysTables, root, &l))?;
        flush_all();
        verify(&mut PhysTables, root, &l, &SAMPLES)
    }

    /// Comprueba un espacio de direcciones nuevo.
    pub fn verify_space(cr3: u64) -> Result<(), MapError> {
        verify(&mut PhysTables, cr3, &layout(), &SAMPLES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::install;
    use crate::memory::paging::PageTable;
    use std::collections::HashMap;

    const PAGE_1G: u64 = 0x4000_0000;

    struct Mem {
        tables: HashMap<u64, Box<PageTable>>,
        next: u64,
    }

    impl Mem {
        fn new_table(&mut self) -> u64 {
            let p = self.next;
            self.next += 0x1000;
            self.tables.insert(p, Box::new(PageTable::empty()));
            p
        }
        /// Mapa del bootloader: 4 GiB con paginas de 2 MiB, RWX (0x83).
        fn identity() -> (Self, u64) {
            let mut m = Mem { tables: HashMap::new(), next: 0x1000 };
            let root = m.new_table();
            let pdpt = m.new_table();
            m.tables.get_mut(&root).unwrap().entries[0] = PageTableEntry::new(pdpt, 0x3);
            for g in 0..4u64 {
                let pd = m.new_table();
                m.tables.get_mut(&pdpt).unwrap().entries[g as usize] = PageTableEntry::new(pd, 0x3);
                for i in 0..512u64 {
                    m.tables.get_mut(&pd).unwrap().entries[i as usize] =
                        PageTableEntry::new(g * PAGE_1G + i * PAGE_2M, 0x83);
                }
            }
            (m, root)
        }
    }

    impl Tables for Mem {
        fn table(&mut self, phys: u64) -> &mut PageTable {
            self.tables.get_mut(&phys).expect("tabla inexistente")
        }
        fn alloc_table(&mut self) -> Option<u64> {
            Some(self.new_table())
        }
    }

    /// Kernel de ejemplo en 0x20_0000: cabecera 1 pagina, text 3, rodata 2, data+bss 6.
    fn layout() -> Layout {
        Layout { start: 0x20_0000, text: 0x20_1000, rodata: 0x20_4000, data: 0x20_6000, end: 0x20_C000 }
    }

    #[test]
    fn layout_validation_rejects_unaligned_unordered_and_empty_text() {
        assert_eq!(layout().validate(), Ok(()));
        assert_eq!(Layout { text: 0x20_1001, ..layout() }.validate(), Err(MapError::BadLayout));
        assert_eq!(Layout { rodata: 0x20_1000, ..layout() }.validate(), Err(MapError::BadLayout), "text vacio");
        assert_eq!(Layout { data: 0x20_3000, ..layout() }.validate(), Err(MapError::BadLayout), "desordenado");
        assert_eq!(Layout { end: 0x20_6000, ..layout() }.validate(), Err(MapError::BadLayout), "sin data");
        assert_eq!(Layout { rodata: 0x20_6000, ..layout() }.validate(), Ok(()), "sin rodata es valido");
    }

    #[test]
    fn apply_gives_every_region_its_permissions() {
        let (mut m, root) = Mem::identity();
        let l = layout();
        apply(&mut m, root, &l).unwrap();
        let eff = |m: &mut Mem, va| effective(m, root, va).unwrap();
        assert_eq!(eff(&mut m, 0x20_0000), Eff { write: false, exec: false }, "cabecera R--");
        for va in (0x20_1000..0x20_4000).step_by(0x1000) {
            assert_eq!(eff(&mut m, va), Eff { write: false, exec: true }, "text R-X {va:#x}");
        }
        for va in (0x20_4000..0x20_6000).step_by(0x1000) {
            assert_eq!(eff(&mut m, va), Eff { write: false, exec: false }, "rodata R-- {va:#x}");
        }
        for va in (0x20_6000..0x20_C000).step_by(0x1000) {
            assert_eq!(eff(&mut m, va), Eff { write: true, exec: false }, "data RW- {va:#x}");
        }
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Ok(()));
    }

    #[test]
    fn the_rest_of_ram_is_writable_but_not_executable_and_nothing_is_wx() {
        let (mut m, root) = Mem::identity();
        let l = layout();
        apply(&mut m, root, &l).unwrap();
        for va in [0x1000u64, 0x10_0000, 0x20_D000, 0x40_0000, 0x1000_0000, 0x8000_0000, 0xFFFF_F000] {
            if let Some(e) = effective(&mut m, root, va) {
                assert!(!e.exec, "{va:#x} sin ejecucion");
                assert!(e.write, "{va:#x} conserva la escritura");
            }
        }
        // ninguna pagina de los 4 GiB (salvo text) es ejecutable, y ninguna es W+X
        for va in (0..IDENTITY_LIMIT).step_by(PAGE_2M as usize) {
            let e = effective(&mut m, root, va).unwrap();
            assert!(!(e.write && e.exec), "{va:#x} W+X");
            if !(0x20_0000..0x40_0000).contains(&va) {
                assert!(!e.exec, "{va:#x}");
            }
        }
    }

    #[test]
    fn the_running_text_is_never_nx_at_any_intermediate_step() {
        // Se aplica la politica paso a paso, como `apply`, y tras cada uno el codigo sigue siendo X.
        let (mut m, root) = Mem::identity();
        let l = layout();
        let text_ok = |m: &mut Mem| (l.text..l.rodata).step_by(0x1000).all(|va| effective(m, root, va).unwrap().exec);
        update(&mut m, root, l.start, l.text, NX, W).unwrap();
        assert!(text_ok(&mut m));
        update(&mut m, root, l.text, l.rodata, 0, W | NX).unwrap();
        assert!(text_ok(&mut m));
        update(&mut m, root, l.rodata, l.data, NX, W).unwrap();
        assert!(text_ok(&mut m));
        update(&mut m, root, l.data, l.end, NX | W, 0).unwrap();
        assert!(text_ok(&mut m));
        update(&mut m, root, 0, l.start, NX, 0).unwrap();
        assert!(text_ok(&mut m));
        update(&mut m, root, l.end, IDENTITY_LIMIT, NX, 0).unwrap();
        assert!(text_ok(&mut m));
    }

    #[test]
    fn guard_pages_stay_unmapped_and_apply_is_idempotent() {
        let (mut m, root) = Mem::identity();
        let l = layout();
        let guards = [0x20_7000u64, 0x20_A000];
        install(&mut m, root, &guards).unwrap();
        apply(&mut m, root, &l).unwrap();
        for g in guards {
            assert!(effective(&mut m, root, g).is_none(), "{g:#x} sigue sin mapear");
        }
        let n = m.tables.len();
        apply(&mut m, root, &l).unwrap();
        assert_eq!(m.tables.len(), n, "repetir no reserva tablas");
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Ok(()));
        assert!(effective(&mut m, root, 0x20_8000).unwrap().write);
    }

    #[test]
    fn verify_catches_a_writable_text_a_nx_text_and_an_executable_data_page() {
        let (mut m, root) = Mem::identity();
        let l = layout();
        apply(&mut m, root, &l).unwrap();
        // pagina de codigo escribible
        update(&mut m, root, 0x20_2000, 0x20_3000, W, 0).unwrap();
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Err(MapError::Violation(0x20_2000)));
        update(&mut m, root, 0x20_2000, 0x20_3000, 0, W).unwrap();
        // codigo no ejecutable
        update(&mut m, root, 0x20_1000, 0x20_2000, NX, 0).unwrap();
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Err(MapError::Violation(0x20_1000)));
        update(&mut m, root, 0x20_1000, 0x20_2000, 0, NX).unwrap();
        // dato ejecutable
        update(&mut m, root, 0x20_8000, 0x20_9000, 0, NX).unwrap();
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Err(MapError::Violation(0x20_8000)));
        update(&mut m, root, 0x20_8000, 0x20_9000, NX, 0).unwrap();
        // RAM fuera de la imagen ejecutable
        update(&mut m, root, 0x1000_0000, 0x1000_1000, 0, NX).unwrap();
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Err(MapError::Violation(0x1000_0000)));
        update(&mut m, root, 0x1000_0000, 0x1000_1000, NX, 0).unwrap();
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Ok(()));
    }

    #[test]
    fn an_address_space_built_before_the_policy_is_detected() {
        let (mut m, root) = Mem::identity();
        let l = layout();
        // un espacio nuevo que NO paso por `apply`: la imagen sigue RWX
        assert_eq!(verify(&mut m, root, &l, &SAMPLES), Err(MapError::Violation(0x20_0000)));
        apply(&mut m, root, &l).unwrap();
        // un proceso copia la PML4 base y comparte las tablas de abajo: hereda la politica
        let p = m.new_table();
        for i in 0..512 {
            let e = m.table(root).entries[i];
            m.table(p).entries[i] = e;
        }
        assert_eq!(verify(&mut m, p, &l, &SAMPLES), Ok(()));
    }

    #[test]
    fn split_pages_keep_the_flags_of_the_original() {
        // una pagina de 2 MiB con NX ya puesto se parte conservando NX en las vecinas
        let (mut m, root) = Mem::identity();
        update(&mut m, root, 0x40_0000, 0x60_0000, NX, 0).unwrap();
        update(&mut m, root, 0x40_1000, 0x40_2000, 0, W).unwrap();
        assert_eq!(effective(&mut m, root, 0x40_1000), Some(Eff { write: false, exec: false }));
        assert_eq!(effective(&mut m, root, 0x40_2000), Some(Eff { write: true, exec: false }), "vecina intacta");
        assert_eq!(effective(&mut m, root, 0x40_0000), Some(Eff { write: true, exec: false }));
    }
}
