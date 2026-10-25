// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Paginas de guarda (parche 21, I-36): un desbordamiento de pila se convierte en un fallo
//! inmediato en vez de corromper en silencio lo que haya debajo.
//!
//! - `GuardedStack<N>`: pila estatica con una pagina de guarda de 4 KiB justo debajo (direcciones
//!   menores; la pila crece hacia abajo). Todas las pilas del kernel (por tarea, de interrupcion,
//!   de #DF y de syscall) usan este tipo.
//! - `unmap_page`/`is_mapped`: edicion y recorrido de tablas de paginas, independientes de la CPU
//!   (el acceso a las tablas va detras del trait `Tables`; en el kernel real son las tablas
//!   fisicas con identidad y en las pruebas, un doble).
//! - El mapa de identidad del bootloader usa paginas de 2 MiB: para quitar UNA pagina de 4 KiB
//!   hay que partir la de 2 MiB en 512 de 4 KiB (con los mismos permisos) y borrar solo la hoja.
//! - La edicion se hace en las tablas BASE, antes de crear procesos: las PML4 de los procesos
//!   copian las entradas de la base y comparten sus tablas inferiores, asi que heredan las
//!   guardas. Aun asi `verify` comprueba, por cada espacio de direcciones nuevo, que ninguna
//!   guarda esta mapeada (falla cerrado, no se asume el orden).

use crate::memory::paging::{PageTable, PageTableEntry};

pub const GUARD_SIZE: usize = 4096;
pub(crate) const PAGE_2M: u64 = 0x20_0000;
/// Bit PAT: en una entrada grande es el bit 12, que en una de 4 KiB seria parte de la direccion.
const PAT_LARGE: u64 = 1 << 12;
/// Bits de direccion que debe tener una direccion canonica de la mitad baja.
const LOW_HALF_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Pila estatica con pagina de guarda debajo. `N` debe ser multiplo de 4 KiB para que la guarda
/// de la pila siguiente (en un arreglo) tambien quede alineada a pagina.
#[repr(C, align(4096))]
pub struct GuardedStack<const N: usize> {
    guard: [u8; GUARD_SIZE],
    stack: [u8; N],
}

impl<const N: usize> GuardedStack<N> {
    pub const fn new() -> Self {
        assert!(N % GUARD_SIZE == 0 && N >= GUARD_SIZE);
        Self { guard: [0; GUARD_SIZE], stack: [0; N] }
    }
}

/// Geometria de la pila `idx` de un arreglo de `GuardedStack<size>` que empieza en `array`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// Pagina de guarda (la que se desmapea).
    pub guard: u64,
    /// Primer byte utilizable de la pila.
    pub base: u64,
    /// Cima (un byte tras el ultimo utilizable).
    pub top: u64,
}

pub const fn slot(array: u64, idx: usize, size: usize) -> Slot {
    let stride = (size + GUARD_SIZE) as u64;
    let guard = array + idx as u64 * stride;
    let base = guard + GUARD_SIZE as u64;
    Slot { guard, base, top: base + size as u64 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    Unaligned,
    /// Direccion fuera de la mitad baja canonica: no es del mapa de identidad.
    OutOfRange,
    NoMemory,
    /// La guarda sigue mapeada tras desmapearla (o en un espacio de direcciones nuevo).
    StillMapped(u64),
}

/// Acceso a las tablas de paginas por direccion fisica.
pub trait Tables {
    fn table(&mut self, phys: u64) -> &mut PageTable;
    /// Reserva un marco para una tabla nueva (se rellena entero antes de usarse).
    fn alloc_table(&mut self) -> Option<u64>;
}

pub(crate) fn idx(virt: u64, shift: u32) -> usize {
    ((virt >> shift) & 0x1FF) as usize
}

/// Convierte la entrada grande `e` (1 GiB o 2 MiB) en una tabla de 512 entradas del nivel
/// inferior con los mismos permisos y la misma memoria. `child_size` = 2 MiB o 4 KiB.
pub(crate) fn split<T: Tables>(t: &mut T, e: PageTableEntry, child_size: u64) -> Result<PageTableEntry, GuardError> {
    let frame = t.alloc_table().ok_or(GuardError::NoMemory)?;
    // Sin OWNED: son tablas compartidas por todos los espacios de direcciones (como las del
    // bootloader); `destroy` no las libera y un proceso las copia si necesita cambiarlas.
    let mut child = e.flags() & !PageTableEntry::OWNED & !PAT_LARGE;
    if child_size == PAGE_2M {
        child |= PageTableEntry::HUGE;
    } else {
        child &= !PageTableEntry::HUGE;
    }
    let base = e.address();
    let table = t.table(frame);
    for i in 0..512u64 {
        table.entries[i as usize] = PageTableEntry::new(base + i * child_size, child);
    }
    // La entrada que apunta a la tabla nueva es PERMISIVA (escribible, ejecutable): los permisos
    // los fijan las hojas, que ya llevan los del original. Si heredara NX, despues no se podria
    // dar ejecucion a una hoja (permiso efectivo = el mas restrictivo de todos los niveles).
    let ptr_flags = (e.flags() & !PageTableEntry::OWNED & !PageTableEntry::HUGE & !PAT_LARGE & !PageTableEntry::NO_EXECUTE)
        | PageTableEntry::WRITABLE;
    Ok(PageTableEntry::new(frame, ptr_flags))
}

/// Quita del mapa la pagina de 4 KiB en `virt` (identidad). Idempotente: si ya no esta, no hace
/// nada. Parte las paginas de 1 GiB / 2 MiB que la contengan. No toca las entradas de la PML4.
pub fn unmap_page<T: Tables>(t: &mut T, root: u64, virt: u64) -> Result<(), GuardError> {
    if virt % GUARD_SIZE as u64 != 0 {
        return Err(GuardError::Unaligned);
    }
    if virt >= LOW_HALF_LIMIT {
        return Err(GuardError::OutOfRange);
    }
    let pml4e = t.table(root).entries[idx(virt, 39)];
    if !pml4e.is_present() {
        return Ok(());
    }
    let pdpt = pml4e.address();
    let mut pdpte = t.table(pdpt).entries[idx(virt, 30)];
    if !pdpte.is_present() {
        return Ok(());
    }
    if pdpte.is_huge() {
        pdpte = split(t, pdpte, PAGE_2M)?;
        t.table(pdpt).entries[idx(virt, 30)] = pdpte;
    }
    let pd = pdpte.address();
    let mut pde = t.table(pd).entries[idx(virt, 21)];
    if !pde.is_present() {
        return Ok(());
    }
    if pde.is_huge() {
        pde = split(t, pde, GUARD_SIZE as u64)?;
        t.table(pd).entries[idx(virt, 21)] = pde;
    }
    let pt = pde.address();
    t.table(pt).entries[idx(virt, 12)] = PageTableEntry(0);
    Ok(())
}

/// Recorre las tablas de `root` y dice si `virt` esta mapeada (con cualquier tamano de pagina).
pub fn is_mapped<T: Tables>(t: &mut T, root: u64, virt: u64) -> bool {
    let e = t.table(root).entries[idx(virt, 39)];
    if !e.is_present() {
        return false;
    }
    let e = t.table(e.address()).entries[idx(virt, 30)];
    if !e.is_present() {
        return false;
    }
    if e.is_huge() {
        return true;
    }
    let e = t.table(e.address()).entries[idx(virt, 21)];
    if !e.is_present() {
        return false;
    }
    if e.is_huge() {
        return true;
    }
    t.table(e.address()).entries[idx(virt, 12)].is_present()
}

/// Desmapea todas las guardas en `root`.
pub fn install<T: Tables>(t: &mut T, root: u64, guards: &[u64]) -> Result<(), GuardError> {
    for &g in guards {
        unmap_page(t, root, g)?;
    }
    verify(t, root, guards)
}

/// Falla si alguna guarda esta mapeada en el espacio de direcciones `root`.
pub fn verify<T: Tables>(t: &mut T, root: u64, guards: &[u64]) -> Result<(), GuardError> {
    for &g in guards {
        if is_mapped(t, root, g) {
            return Err(GuardError::StillMapped(g));
        }
    }
    Ok(())
}

#[cfg(not(test))]
pub use hw::*;

#[cfg(not(test))]
mod hw {
    use super::*;
    use crate::memory::frame_allocator::BITMAP_ALLOCATOR;

    /// Tablas fisicas con identidad (el kernel corre con el mapa de identidad).
    pub struct PhysTables;

    impl Tables for PhysTables {
        fn table(&mut self, phys: u64) -> &mut PageTable {
            unsafe { &mut *(phys as *mut PageTable) }
        }
        fn alloc_table(&mut self) -> Option<u64> {
            BITMAP_ALLOCATOR.lock().allocate_frame()
        }
    }

    /// Todas las paginas de guarda del kernel.
    pub const MAX_GUARDS: usize = crate::dispatch::MAX_KTASKS + 3;

    pub fn all_guards() -> [u64; MAX_GUARDS] {
        let mut g = [0u64; MAX_GUARDS];
        for i in 0..crate::dispatch::MAX_KTASKS {
            g[i] = crate::dispatch::kstack_slot(i).guard;
        }
        g[crate::dispatch::MAX_KTASKS] = crate::interrupts::int_guard_page();
        g[crate::dispatch::MAX_KTASKS + 1] = crate::interrupts::df_guard_page();
        g[crate::dispatch::MAX_KTASKS + 2] = crate::syscalls::syscall_guard_page();
        g
    }

    fn flush_tlb() {
        unsafe {
            core::arch::asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _, options(nostack, preserves_flags));
        }
    }

    /// Ejecuta `f` con CR0.WP apagado y las interrupciones cerradas. Las tablas base son las del
    /// firmware, que puede tenerlas mapeadas como solo lectura (con WP activo, escribirlas es un
    /// #PF de proteccion: P=1, W=1). Solo para editar tablas durante el arranque.
    pub unsafe fn without_write_protect<R>(f: impl FnOnce() -> R) -> R {
        const CR0_WP: u64 = 1 << 16;
        let flags: u64;
        core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags);
        let cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        if cr0 & CR0_WP != 0 {
            core::arch::asm!("mov cr0, {}", in(reg) cr0 & !CR0_WP, options(nostack, preserves_flags));
        }
        let r = f();
        if cr0 & CR0_WP != 0 {
            core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
        }
        if flags & 0x200 != 0 {
            core::arch::asm!("sti");
        }
        r
    }

    /// Desmapea las guardas en las tablas base. Hay que llamarla antes de crear procesos.
    pub unsafe fn install_base() -> Result<usize, GuardError> {
        let root = crate::memory::base_pml4().ok_or(GuardError::OutOfRange)?;
        let guards = all_guards();
        without_write_protect(|| install(&mut PhysTables, root, &guards))?;
        flush_tlb();
        Ok(guards.len())
    }

    /// Comprueba un espacio de direcciones nuevo: ninguna guarda mapeada.
    pub fn verify_space(cr3: u64) -> Result<(), GuardError> {
        verify(&mut PhysTables, cr3, &all_guards())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const PAGE_1G: u64 = 0x4000_0000;

    /// Memoria fisica simulada: tablas por direccion (0x1000, 0x2000, ...).
    struct Mem {
        tables: HashMap<u64, Box<PageTable>>,
        next: u64,
        limit: usize,
    }

    impl Mem {
        fn new() -> Self {
            Mem { tables: HashMap::new(), next: 0x1000, limit: usize::MAX }
        }
        fn new_table(&mut self) -> u64 {
            let p = self.next;
            self.next += 0x1000;
            self.tables.insert(p, Box::new(PageTable::empty()));
            p
        }
        /// Mapa como el del bootloader: PML4 -> PDPT -> PD con paginas de 2 MiB RW sin NX
        /// para los primeros `gib` GiB.
        fn identity_2m(gib: u64) -> (Self, u64) {
            let mut m = Mem::new();
            let root = m.new_table();
            let pdpt = m.new_table();
            m.tables.get_mut(&root).unwrap().entries[0] = PageTableEntry::new(pdpt, 0x3);
            for g in 0..gib {
                let pd = m.new_table();
                m.tables.get_mut(&pdpt).unwrap().entries[g as usize] = PageTableEntry::new(pd, 0x3);
                for i in 0..512u64 {
                    let pa = g * PAGE_1G + i * PAGE_2M;
                    m.tables.get_mut(&pd).unwrap().entries[i as usize] = PageTableEntry::new(pa, 0x83);
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
            if self.tables.len() >= self.limit {
                return None;
            }
            Some(self.new_table())
        }
    }

    /// Traduce `virt` con las tablas: (direccion fisica, flags de la hoja) o None.
    fn translate(m: &mut Mem, root: u64, virt: u64) -> Option<(u64, u64)> {
        let e = m.table(root).entries[idx(virt, 39)];
        if !e.is_present() { return None; }
        let e = m.table(e.address()).entries[idx(virt, 30)];
        if !e.is_present() { return None; }
        if e.is_huge() { return Some((e.address() + (virt & (PAGE_1G - 1)), e.flags())); }
        let e = m.table(e.address()).entries[idx(virt, 21)];
        if !e.is_present() { return None; }
        if e.is_huge() { return Some((e.address() + (virt & (PAGE_2M - 1)), e.flags())); }
        let e = m.table(e.address()).entries[idx(virt, 12)];
        if !e.is_present() { return None; }
        Some((e.address() + (virt & 0xFFF), e.flags()))
    }

    #[test]
    fn slot_geometry_puts_a_guard_right_below_every_stack() {
        let array = 0x20_0000u64;
        let size = 16 * 1024;
        let mut prev_top = None;
        for i in 0..8 {
            let s = slot(array, i, size);
            assert_eq!(s.guard % 4096, 0);
            assert_eq!(s.base, s.guard + 4096, "la guarda esta pegada bajo la pila");
            assert_eq!(s.top - s.base, size as u64);
            if let Some(t) = prev_top {
                assert_eq!(s.guard, t, "la guarda de la siguiente empieza donde acaba la anterior");
            }
            prev_top = Some(s.top);
        }
        // el tamano en bytes coincide con la geometria
        assert_eq!(core::mem::size_of::<GuardedStack<{ 16 * 1024 }>>(), 16 * 1024 + 4096);
        assert_eq!(core::mem::align_of::<GuardedStack<{ 8 * 1024 }>>(), 4096);
    }

    #[test]
    fn unmapping_one_page_splits_a_2m_page_and_keeps_everything_else() {
        let (mut m, root) = Mem::identity_2m(1);
        let guard = 0x20_0000 + 5 * 4096;
        assert!(is_mapped(&mut m, root, guard));
        unmap_page(&mut m, root, guard).unwrap();
        assert!(!is_mapped(&mut m, root, guard));
        // las 511 vecinas de la misma pagina de 2 MiB siguen con la misma traduccion y permisos
        for p in 0..512u64 {
            let va = 0x20_0000 + p * 4096;
            if va == guard { continue; }
            let (pa, flags) = translate(&mut m, root, va).expect("vecina mapeada");
            assert_eq!(pa, va, "identidad");
            assert_eq!(flags & !PageTableEntry::HUGE, 0x3, "mismos permisos (P|RW)");
            assert_eq!(flags & PageTableEntry::HUGE, 0, "ahora son de 4 KiB");
        }
        // otras paginas de 2 MiB no se tocan
        let (_, f) = translate(&mut m, root, 0x40_0000).unwrap();
        assert_ne!(f & PageTableEntry::HUGE, 0);
        let (_, f) = translate(&mut m, root, 0).unwrap();
        assert_ne!(f & PageTableEntry::HUGE, 0);
    }

    #[test]
    fn a_split_keeps_the_leaf_flags_but_the_pointer_entry_is_permissive() {
        // pagina de 2 MiB con NX y solo lectura: las hojas la heredan, la entrada-puntero no restringe
        let (mut m, root) = Mem::identity_2m(1);
        let pdpt = m.table(root).entries[0].address();
        let pd = m.table(pdpt).entries[0].address();
        m.table(pd).entries[1] = PageTableEntry::new(0x20_0000, 0x81 | PageTableEntry::NO_EXECUTE);
        unmap_page(&mut m, root, 0x20_0000).unwrap();
        let pde = m.table(pd).entries[1];
        assert_eq!(pde.flags() & PageTableEntry::NO_EXECUTE, 0, "el puntero no hereda NX");
        assert_ne!(pde.flags() & PageTableEntry::WRITABLE, 0);
        let pt = pde.address();
        let leaf = m.table(pt).entries[1];
        assert_ne!(leaf.flags() & PageTableEntry::NO_EXECUTE, 0, "la hoja si");
        assert_eq!(leaf.flags() & PageTableEntry::WRITABLE, 0, "y sigue de solo lectura");
    }

    #[test]
    fn the_new_tables_are_not_owned_so_destroy_never_frees_them() {
        let (mut m, root) = Mem::identity_2m(1);
        unmap_page(&mut m, root, 0x20_0000).unwrap();
        let pdpt = m.table(root).entries[0].address();
        let pd = m.table(pdpt).entries[0].address();
        let pde = m.table(pd).entries[1];
        assert!(pde.is_present() && !pde.is_huge() && !pde.is_owned());
        assert_eq!(pde.flags() & PAT_LARGE, 0);
    }

    #[test]
    fn splitting_a_1g_page_goes_through_2m_and_is_idempotent() {
        let mut m = Mem::new();
        let root = m.new_table();
        let pdpt = m.new_table();
        m.tables.get_mut(&root).unwrap().entries[0] = PageTableEntry::new(pdpt, 0x3);
        m.tables.get_mut(&pdpt).unwrap().entries[0] = PageTableEntry::new(0, 0x83); // 1 GiB
        let g = 0x30_1000;
        unmap_page(&mut m, root, g).unwrap();
        assert!(!is_mapped(&mut m, root, g));
        assert!(is_mapped(&mut m, root, g + 0x1000));
        assert!(is_mapped(&mut m, root, 0x1000_0000), "el resto del GiB sigue mapeado");
        let before = m.tables.len();
        unmap_page(&mut m, root, g).unwrap();
        assert_eq!(m.tables.len(), before, "repetir no reserva tablas");
        // dos guardas en la misma pagina de 2 MiB comparten tabla
        unmap_page(&mut m, root, 0x30_3000).unwrap();
        assert_eq!(m.tables.len(), before);
        assert!(!is_mapped(&mut m, root, 0x30_3000) && !is_mapped(&mut m, root, g));
    }

    #[test]
    fn bad_addresses_and_allocation_failure_are_errors() {
        let (mut m, root) = Mem::identity_2m(1);
        assert_eq!(unmap_page(&mut m, root, 0x20_0001), Err(GuardError::Unaligned));
        assert_eq!(unmap_page(&mut m, root, 0xFFFF_8000_0000_0000), Err(GuardError::OutOfRange));
        // una direccion que ya no esta mapeada (fuera del GiB) no es un error
        assert_eq!(unmap_page(&mut m, root, 0x8000_0000), Ok(()));
        m.limit = m.tables.len();
        assert_eq!(unmap_page(&mut m, root, 0x20_0000), Err(GuardError::NoMemory));
        assert!(is_mapped(&mut m, root, 0x20_0000), "si falla, no queda a medias");
    }

    #[test]
    fn install_unmaps_every_guard_and_verify_catches_a_mapped_one() {
        let (mut m, root) = Mem::identity_2m(4);
        let guards = [0x20_0000u64, 0x20_5000, 0x21_0000, 0xFFFF_F000, 0x3FFF_F000];
        install(&mut m, root, &guards).unwrap();
        for g in guards {
            assert!(!is_mapped(&mut m, root, g), "{g:#x}");
        }
        assert_eq!(verify(&mut m, root, &guards), Ok(()));
        // un espacio de direcciones que no heredo las guardas es detectado
        let (mut other, other_root) = Mem::identity_2m(4);
        assert_eq!(verify(&mut other, other_root, &guards), Err(GuardError::StillMapped(0x20_0000)));
    }

    #[test]
    fn a_process_that_copies_the_base_pml4_inherits_the_guards() {
        // Como `create_user_space_from`: copia las entradas de la PML4 y comparte lo de abajo.
        let (mut m, base) = Mem::identity_2m(1);
        let guard = 0x20_6000;
        install(&mut m, base, &[guard]).unwrap();
        let proc_root = m.new_table();
        for i in 0..512 {
            let e = m.table(base).entries[i];
            m.table(proc_root).entries[i] = PageTableEntry(e.0 & !PageTableEntry::OWNED);
        }
        assert!(!is_mapped(&mut m, proc_root, guard));
        assert!(is_mapped(&mut m, proc_root, guard + 0x1000));
        assert_eq!(verify(&mut m, proc_root, &[guard]), Ok(()));
    }
}
