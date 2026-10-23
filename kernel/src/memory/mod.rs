// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// kernel/src/memory/mod.rs

pub mod boot_map;
pub mod frame_allocator;
pub mod ident;
pub mod paging;
pub mod process_paging;

pub use frame_allocator::BITMAP_ALLOCATOR;
pub use process_paging::ProcessPml4;

/// PML4 del firmware sin mapeos de usuario: plantilla de todo proceso nuevo.
pub static BASE_PML4: spin::Mutex<u64> = spin::Mutex::new(0);

pub fn base_pml4() -> Option<u64> {
    match *BASE_PML4.lock() {
        0 => None,
        v => Some(v),
    }
}

pub static ACTIVE_USER_PML4: spin::Mutex<u64> = spin::Mutex::new(0);

pub fn set_active_user_pml4(cr3_phys: u64) {
    *ACTIVE_USER_PML4.lock() = cr3_phys;
}

pub fn current_user_pml4() -> Option<ProcessPml4> {
    let cr3 = *ACTIVE_USER_PML4.lock();
    if cr3 == 0 { None } else { Some(ProcessPml4 { cr3_phys: cr3 }) }
}

/// Plan de arranque: puntero al `BootInfo`, su copia validada y la tabla de regiones.
pub type BootPlan = (u64, trunomy_abi::boot::BootInfo, &'static [trunomy_abi::boot::MemRegion]);

/// Inicializa el allocator de marcos y crea el espacio de usuario.
///
/// Con `plan` (mapa real del firmware): solo se reparte memoria que el firmware declaro libre,
/// menos kernel, shell, BootInfo y la tabla del mapa. Sin `plan`: valores por defecto
/// anteriores (4 GiB asumidos, 32 MiB reservados); el llamante debe avisarlo.
pub unsafe fn init_memory_system(plan: Option<BootPlan>) -> ProcessPml4 {
    let boot_info_ptr = plan.as_ref().map_or(0, |(p, _, _)| *p);
    {
        let mut allocator = BITMAP_ALLOCATOR.lock();

        match plan {
            Some((info_ptr, info, regions)) => {
                let reserved = boot_map::reserved_ranges(&info, info_ptr);
                allocator.init_from_regions(regions, &reserved);
            }
            None => {
                // Inicializar para 4 GB
                allocator.init(0x1_0000_0000);

                // MARCAR COMO USADOS los primeros 32 MB (kernel + bootloader + estructuras)
                let reserve_until = 0x2000000u64; // 32 MB
                let mut addr = 0u64;
                while addr < reserve_until {
                    allocator.set_frame_used(frame_allocator::PhysFrame(addr), true);
                    addr += 4096;
                }
            }
        }
    }

    // Tablas base PROPIAS (I-38): en marcos del allocator, no las del firmware. Si no se pueden
    // activar se sigue con las del firmware (CR3 intacto) y se avisa.
    if let Err(why) = ident::install(boot_info_ptr) {
        crate::print_uart("[KERNEL_WARN] Own page tables not active: ");
        crate::print_uart(why);
        crate::print_uart(" (using the firmware's)\n");
    }
    {
        let cr3: u64;
        core::arch::asm!("mov {0}, cr3", out(reg) cr3);
        *BASE_PML4.lock() = cr3 & !0xFFF;
    }
    ProcessPml4::create_user_space().expect("[MEMORY_ERROR] Failed to create the user PML4")
}
