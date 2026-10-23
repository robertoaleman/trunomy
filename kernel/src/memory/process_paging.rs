// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/memory/process_paging.rs

use super::paging::{PageTable, PageTableEntry};
use crate::memory::frame_allocator::BITMAP_ALLOCATOR;

pub const PHYS_OFFSET: u64 = 0x0000_0000_0000_0000;
pub const PAGE_SIZE: u64 = 0x1000;
const PAGE_SIZE_1G: u64 = 0x4000_0000;
const PAGE_SIZE_2M: u64 = 0x20_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPagePermissions {
    pub present: bool,
    pub user: bool,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl UserPagePermissions {
    fn from_entry(entry: PageTableEntry) -> Self {
        Self {
            present: entry.is_present(),
            user: (entry.flags() & PageTableEntry::USER) != 0,
            readable: entry.is_present(),
            writable: (entry.flags() & PageTableEntry::WRITABLE) != 0,
            executable: (entry.flags() & PageTableEntry::NO_EXECUTE) == 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPageError {
    UnalignedAddress,
    NotMapped,
    NotUserPage,
    PermissionDenied,
}

#[inline]
fn phys_to_virt(phys: u64) -> *mut u8 {
    (phys + PHYS_OFFSET) as *mut u8
}

#[inline]
fn pml4_index(virt: u64) -> usize { ((virt >> 39) & 0x1FF) as usize }
#[inline]
fn pdpt_index(virt: u64) -> usize { ((virt >> 30) & 0x1FF) as usize }
#[inline]
fn pd_index(virt: u64) -> usize { ((virt >> 21) & 0x1FF) as usize }
#[inline]
fn pt_index(virt: u64) -> usize { ((virt >> 12) & 0x1FF) as usize }

#[derive(Debug, Clone, Copy)]
pub struct ProcessPml4 {
    pub cr3_phys: u64,
}

impl ProcessPml4 {
    pub unsafe fn switch_to(&self) {
        super::set_active_user_pml4(self.cr3_phys);
        core::arch::asm!("mov cr3, {0}", in(reg) self.cr3_phys, options(nostack, preserves_flags));
    }

    pub unsafe fn create_user_space() -> Option<Self> {
        let current_cr3: u64;
        core::arch::asm!("mov {0}, cr3", out(reg) current_cr3);
        let pml4 = Self::create_user_space_from(current_cr3 & !0xFFF)?;
        super::set_active_user_pml4(pml4.cr3_phys);
        Some(pml4)
    }

    /// Crea un espacio de direcciones nuevo copiando solo la PML4 base (`base_pml4_phys`), que
    /// debe ser una PML4 sin mapeos de usuario (la del firmware). Las tablas inferiores se
    /// comparten sin dueno y se copian al primer cambio, de modo que la base nunca se modifica.
    pub unsafe fn create_user_space_from(base_pml4_phys: u64) -> Option<Self> {
        let active_pml4 = &*(phys_to_virt(base_pml4_phys) as *const PageTable);

        let pml4_phys = BITMAP_ALLOCATOR.lock().allocate_frame()?;
        let pml4_ptr = phys_to_virt(pml4_phys) as *mut PageTable;
        (*pml4_ptr).clear();
        for i in 0..512 {
            (*pml4_ptr).entries[i] = PageTableEntry(active_pml4.entries[i].0 & !PageTableEntry::OWNED);
        }
        Some(Self { cr3_phys: pml4_phys })
    }

    /// Destruye un espacio de direcciones que ya no esta en uso (no es el CR3 actual): libera las
    /// tablas que creo el kernel (marca OWNED) y las paginas de usuario mapeadas con
    /// `map_user_page` (hoja con USER). Nunca libera marcos que el allocator no asigno (el
    /// mapa de identidad del firmware, la VGA): `deallocate_frame` los rechaza (I-17). Cada marco
    /// liberado se borra antes de reutilizarse (I-16). Devuelve cuantos marcos libero.
    pub unsafe fn destroy(self) -> usize {
        let mut freed = 0usize;
        let pml4 = &*(phys_to_virt(self.cr3_phys) as *const PageTable);
        for e in pml4.entries.iter() {
            if e.is_present() && e.is_owned() && !e.is_huge() {
                freed += free_table(e.address(), 3);
            }
        }
        if free_frame(self.cr3_phys) {
            freed += 1;
        }
        freed
    }

    pub unsafe fn user_page_permissions(&self, virt_addr: u64) -> Result<UserPagePermissions, UserPageError> {
        if virt_addr & (PAGE_SIZE - 1) != 0 {
            return Err(UserPageError::UnalignedAddress);
        }

        let pml4 = &*(phys_to_virt(self.cr3_phys) as *const PageTable);
        let pml4e = pml4.entries[pml4_index(virt_addr)];
        if !pml4e.is_present() { return Err(UserPageError::NotMapped); }
        if (pml4e.flags() & PageTableEntry::USER) == 0 { return Err(UserPageError::NotUserPage); }

        let pdpt = &*(phys_to_virt(pml4e.address()) as *const PageTable);
        let pdpte = pdpt.entries[pdpt_index(virt_addr)];
        if !pdpte.is_present() { return Err(UserPageError::NotMapped); }
        if (pdpte.flags() & PageTableEntry::USER) == 0 { return Err(UserPageError::NotUserPage); }
        if pdpte.is_huge() { return Ok(UserPagePermissions::from_entry(pdpte)); }

        let pd = &*(phys_to_virt(pdpte.address()) as *const PageTable);
        let pde = pd.entries[pd_index(virt_addr)];
        if !pde.is_present() { return Err(UserPageError::NotMapped); }
        if (pde.flags() & PageTableEntry::USER) == 0 { return Err(UserPageError::NotUserPage); }
        if pde.is_huge() { return Ok(UserPagePermissions::from_entry(pde)); }

        let pt = &*(phys_to_virt(pde.address()) as *const PageTable);
        let pte = pt.entries[pt_index(virt_addr)];
        if !pte.is_present() { return Err(UserPageError::NotMapped); }
        if (pte.flags() & PageTableEntry::USER) == 0 { return Err(UserPageError::NotUserPage); }
        Ok(UserPagePermissions::from_entry(pte))
    }

    pub unsafe fn validate_user_page_range(
        &self,
        virt_addr: u64,
        len: usize,
        write: bool,
        execute: bool,
    ) -> Result<(), UserPageError> {
        crate::memory_validation::validate_user_range(virt_addr, len)
            .map_err(|_| UserPageError::NotMapped)?;
        let len = u64::try_from(len).map_err(|_| UserPageError::NotMapped)?;
        let end = virt_addr.checked_add(len - 1).ok_or(UserPageError::NotMapped)?;
        let mut page = virt_addr & !(PAGE_SIZE - 1);
        let last_page = end & !(PAGE_SIZE - 1);

        loop {
            let permissions = self.user_page_permissions(page)?;
            if !permissions.present || !permissions.user {
                return Err(UserPageError::NotUserPage);
            }
            if write && !permissions.writable {
                return Err(UserPageError::PermissionDenied);
            }
            if execute && !permissions.executable {
                return Err(UserPageError::PermissionDenied);
            }
            if page == last_page { break; }
            page = page.checked_add(PAGE_SIZE).ok_or(UserPageError::NotMapped)?;
        }

        Ok(())
    }

    pub fn map_user_page(
        &mut self,
        virt_addr: u64,
        phys_frame: u64,
        writable: bool,
        executable: bool,
    ) -> Result<(), &'static str> {
        if virt_addr & (PAGE_SIZE - 1) != 0 || phys_frame & (PAGE_SIZE - 1) != 0 {
            return Err("unaligned user page");
        }
        if !wx_allowed(writable, executable) {
            return Err("W^X: user page that is writable and executable");
        }
        unsafe {
            let pml4 = &mut *(phys_to_virt(self.cr3_phys) as *mut PageTable);
            let pml4e = &mut pml4.entries[pml4_index(virt_addr)];
            let pdpt = get_or_create_subtable(pml4e, 0)?;
            let pdpte = &mut pdpt.entries[pdpt_index(virt_addr)];
            let pd = get_or_create_subtable(pdpte, PAGE_SIZE_1G)?;
            let pde = &mut pd.entries[pd_index(virt_addr)];
            let pt = get_or_create_subtable(pde, PAGE_SIZE_2M)?;
            let pte = &mut pt.entries[pt_index(virt_addr)];
            let mut flags = PageTableEntry::PRESENT | PageTableEntry::USER;
            if writable { flags |= PageTableEntry::WRITABLE; }
            if !executable { flags |= PageTableEntry::NO_EXECUTE; }
            *pte = PageTableEntry::new(phys_frame, flags);
            core::arch::asm!("invlpg [{}]", in(reg) virt_addr, options(nostack, preserves_flags));
        }
        Ok(())
    }
}

unsafe fn get_or_create_subtable(entry: &mut PageTableEntry, huge_page_size: u64) -> Result<&'static mut PageTable, &'static str> {
    let table_flags = PageTableEntry::PRESENT | PageTableEntry::WRITABLE | PageTableEntry::USER | PageTableEntry::OWNED;
    if !entry.is_present() {
        let frame = alloc_table()?;
        (*(phys_to_virt(frame) as *mut PageTable)).clear();
        *entry = PageTableEntry::new(frame, table_flags);
    } else if huge_page_size != 0 && entry.is_huge() {
        let base = entry.address();
        let child_size = huge_page_size / 512;
        let mut child_flags = entry.flags() & !PageTableEntry::HUGE & !PageTableEntry::OWNED;
        if child_size == PAGE_SIZE_2M { child_flags |= PageTableEntry::HUGE; }
        let frame = alloc_table()?;
        let table = &mut *(phys_to_virt(frame) as *mut PageTable);
        for i in 0..512u64 {
            table.entries[i as usize] = PageTableEntry::new(base + i * child_size, child_flags);
        }
        *entry = PageTableEntry::new(frame, table_flags);
    } else if !entry.is_owned() {
        let source = &*(phys_to_virt(entry.address()) as *const PageTable);
        let frame = alloc_table()?;
        let table = &mut *(phys_to_virt(frame) as *mut PageTable);
        for i in 0..512 {
            table.entries[i] = PageTableEntry(source.entries[i].0 & !PageTableEntry::OWNED);
        }
        *entry = PageTableEntry::new(frame, table_flags);
    } else {
        entry.0 |= PageTableEntry::USER | PageTableEntry::WRITABLE;
    }
    Ok(&mut *(phys_to_virt(entry.address()) as *mut PageTable))
}

/// Politica W^X del kernel: ninguna pagina de usuario es escribible y ejecutable a la vez.
pub const fn wx_allowed(writable: bool, executable: bool) -> bool {
    !(writable && executable)
}

fn alloc_table() -> Result<u64, &'static str> {
    BITMAP_ALLOCATOR.lock().allocate_frame().ok_or("Out of memory")
}

fn free_frame(phys: u64) -> bool {
    BITMAP_ALLOCATOR.lock().deallocate_frame(phys).is_ok()
}

/// Libera recursivamente una tabla propia. `level`: 3 = PDPT, 2 = PD, 1 = PT (hojas).
unsafe fn free_table(table_phys: u64, level: u8) -> usize {
    let mut freed = 0usize;
    let table = &*(phys_to_virt(table_phys) as *const PageTable);
    for e in table.entries.iter() {
        if !e.is_present() || e.is_huge() {
            continue;
        }
        if level > 1 {
            // Solo se desciende por tablas del kernel; las compartidas del firmware se dejan.
            if e.is_owned() {
                freed += free_table(e.address(), level - 1);
            }
        } else if e.flags() & PageTableEntry::USER != 0 && free_frame(e.address()) {
            freed += 1;
        }
    }
    if free_frame(table_phys) {
        freed += 1;
    }
    freed
}

#[cfg(test)]
mod wx_tests {
    use super::wx_allowed;

    #[test]
    fn no_user_page_is_writable_and_executable() {
        assert!(wx_allowed(false, true), "codigo R-X");
        assert!(wx_allowed(true, false), "datos RW-");
        assert!(wx_allowed(false, false), "solo lectura");
        assert!(!wx_allowed(true, true), "W^X");
    }
}
