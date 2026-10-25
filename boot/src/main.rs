// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// =============================================================================
// TRUNOMY OS - UEFI BOOTLOADER (CAPA 0) - Carga de Kernel y Shell
// =============================================================================
//
// Cambios respecto a la versión anterior:
//   1. Pila de entrada alineada (rsp ≡ 8 mod 16, como tras un `call` SysV).
//   2. Sin asm con clobbers sin declarar: el puerto serie se escribe con
//      `serial_putc` y el salto final usa registros explícitos.
//   3. El salto usa `real_entry_point` y entrega un `BootInfo` en RDI.
//   4. (SWITCH_CR3=true) Tablas de paginación PROPIAS (PML4/PDPT/PD nuevas, no
//      se toca nada de UEFI) y `mov cr3` justo antes del salto. Con
//      SWITCH_CR3=false el kernel hereda las tablas de UEFI, sin tocarlas.
//   5. (LOAD_SHELL=true) shell.bin (payload || firma Ed25519 de 64 bytes, como
//      la empaqueta build_os.sh) se carga y se verifica; firma inválida => panic.
//      Con LOAD_SHELL=false la shell va embebida en el kernel, que la valida.
//   6. Se validan los segmentos PT_LOAD y el entry point del ELF, se comprueba
//      que las lecturas devuelvan el tamaño completo y toda la memoria que se
//      entrega (kernel, pila, shell, tablas) se pone a cero antes de usarla.
//
// Los valores por defecto de SWITCH_CR3 y LOAD_SHELL reproducen el traspaso de
// la rama que ya llega a la shell. Se activan de uno en uno para ver cuál rompe.
// =============================================================================

#![no_std]
#![no_main]

use trunomy_abi::trust::{KERNEL_SIGNING_PUBLIC_KEY, SHELL_SIGNING_PUBLIC_KEY};
use trunomy_bootcore::elf::{load_into, plan_load, Region};
use trunomy_bootcore::rollback::{check_kernel, decode_counter, encode_counter, Decision, RollbackError};
use trunomy_bootcore::sig::verify_appended;
use uefi::prelude::*;
use uefi::proto::media::file::{
    Directory, File, FileAttribute, FileInfo, FileMode, FileType, RegularFile,
};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{
    AllocateType, BootServices, MemoryType, OpenProtocolAttributes, OpenProtocolParams, SearchType,
};
use uefi::table::runtime::{RuntimeServices, VariableAttributes, VariableVendor};
use uefi::CStr16;
use uefi::Identify;
use trunomy_abi::boot::{
    BootInfo, MemRegion, BOOT_INFO_MAGIC, MAX_REGIONS, REGION_RESERVED, REGION_USABLE,
};

/// Tamaño máximo de la región del kernel (I-18): ningún segmento puede salir de
/// `[KERNEL_LOAD_ADDR, KERNEL_LOAD_ADDR + KERNEL_MAX_SIZE)`.
const KERNEL_MAX_SIZE: u64 = 16 * 1024 * 1024;

const KERNEL_LOAD_ADDR: u64 = 0x200000;
const PAGE_SIZE: u64 = 4096;
const PAGE_2M: u64 = 0x20_0000;

/// Todo lo que el bootloader entrega al kernel (pila, BootInfo, shell y tablas
/// de paginación) se asigna por debajo de 4 GiB, dentro del identity map.
const MAX_LOW_ADDR: u64 = 0xFFFF_FFFF;

/// Contador anti-rollback del kernel (I-49): variable UEFI no volatil con el mayor `security-version` aceptado.
/// Solo `BOOTSERVICE_ACCESS`: no es accesible en tiempo de ejecucion, asi que el kernel ni el userland la pueden
/// tocar desde dentro del sistema arrancado.
const ROLLBACK_VENDOR: VariableVendor = VariableVendor(uefi::guid!("524ef05b-cf1e-4c81-ab8a-978310a107cf"));

fn read_rollback_counter(rt: &RuntimeServices) -> Option<u64> {
    let mut buf = [0u8; 16];
    match rt.get_variable(cstr16!("TrunomyMinKernelVersion"), &ROLLBACK_VENDOR, &mut buf) {
        Ok((data, _)) => match decode_counter(data) {
            Ok(v) => Some(v),
            Err(e) => panic!("{} (I-49): not booting", e.as_str()),
        },
        Err(e) if e.status() == Status::NOT_FOUND => None,
        // Mas grande que el buffer, o un error del firmware: no se sabe cual es el minimo, asi que no se arranca.
        Err(e) if e.status() == Status::BUFFER_TOO_SMALL => panic!("{} (I-49): not booting", RollbackError::BadCounter.as_str()),
        Err(e) => panic!("could not read the anti-rollback counter: {:?} (I-49): not booting", e.status()),
    }
}

/// Sube el minimo aceptado. Si el firmware no lo guarda, el kernel arranca igual (ya esta verificado) pero se
/// avisa: la proteccion contra rollback queda sin efecto en este arranque.
fn store_rollback_counter(rt: &RuntimeServices, version: u64) {
    let attrs = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
    let written = rt
        .set_variable(cstr16!("TrunomyMinKernelVersion"), &ROLLBACK_VENDOR, attrs, &encode_counter(version))
        .is_ok();
    if written && read_rollback_counter(rt) == Some(version) {
        log::info!("[BOOT] Rollback: minimum accepted = {} (stored in NVRAM)", version);
    } else {
        log::warn!("[BOOT] Rollback: could NOT store the minimum {} in NVRAM: no rollback protection on this boot", version);
    }
}

/// Rango que se mapea con identidad (páginas de 2 MiB, RW, sin NX).
const IDENTITY_LIMIT: u64 = 0x1_0000_0000; // 4 GiB

/// Bits 51:12 de una entrada de tabla de paginación.
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// --- Interruptores de bisección (probar con el kernel real, de uno en uno) ---

/// `false` (por defecto): el kernel arranca con las tablas de UEFI, sin tocarlas,
/// como en la rama que ya llega a la shell.
/// `true`: el bootloader construye un identity map propio de 4 GiB y lo activa
/// con `mov cr3` justo antes del salto.
const SWITCH_CR3: bool = false;

/// `false` (por defecto): la shell va embebida en el kernel y la valida el propio
/// kernel (la rama que funciona no la carga el bootloader).
/// `true`: el bootloader carga shell.bin (payload || firma), la verifica y la
/// entrega en `BootInfo`.
const LOAD_SHELL: bool = false;

/// `true`: rsp ≡ 8 (mod 16) al entrar al kernel (ABI SysV, como tras un `call`).
/// `false`: rsp = stack_top (alineado a 16), como en la versión anterior.
const ABI_ALIGNED_STACK: bool = true;

// `BootInfo` y `MemRegion` viven en `trunomy-abi` (una sola definición para bootloader y kernel).

/// Escribe un byte en COM1 (0x3F8). Los registros se declaran como entradas:
/// el compilador sabe qué ocupan y no se pisa ningún valor suyo.
#[inline(always)]
unsafe fn serial_putc(c: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") 0x3F8u16,
        in("al") c,
        options(nomem, nostack, preserves_flags)
    );
}

/// Dirección aproximada del código que se está ejecutando (RIP actual).
#[inline(always)]
fn current_rip() -> u64 {
    let rip: u64;
    unsafe {
        core::arch::asm!(
            "lea {}, [rip]",
            out(reg) rip,
            options(nomem, nostack, preserves_flags)
        );
    }
    rip
}

/// CR3 activo (el de UEFI mientras no hagamos `mov cr3`).
#[inline(always)]
fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr3",
            out(reg) cr3,
            options(nomem, nostack, preserves_flags)
        );
    }
    cr3
}

/// Búfer alineado a 8 bytes para `get_info::<FileInfo>` (FileInfo exige alineación).
#[repr(C, align(8))]
struct InfoBuf([u8; 1024]);

/// Abre el primer archivo regular que exista entre `paths`.
fn open_first_regular(root_dir: &mut Directory, paths: &[&CStr16]) -> Option<RegularFile> {
    for path in paths.iter() {
        if let Ok(entry) = root_dir.open(*path, FileMode::Read, FileAttribute::empty()) {
            if let Ok(FileType::Regular(f)) = entry.into_type() {
                log::info!("[BOOT] Opened: {}", *path);
                return Some(f);
            }
        }
    }
    None
}

/// Lee el archivo completo a páginas LOADER_DATA ya puestas a cero.
/// Devuelve (puntero, tamaño en bytes). Falla si la lectura queda incompleta.
fn read_file_to_pages(
    boot_services: &BootServices,
    file: &mut RegularFile,
    alloc_type: AllocateType,
) -> Result<(*mut u8, usize), &'static str> {
    let mut info_buf = InfoBuf([0u8; 1024]);
    let size = match file.get_info::<FileInfo>(&mut info_buf.0) {
        Ok(info) => info.file_size() as usize,
        Err(_) => return Err("could not read the file information"),
    };

    if size == 0 {
        return Err("the file is empty");
    }

    let pages = (size + 4095) / 4096;
    let addr = match boot_services.allocate_pages(alloc_type, MemoryType::LOADER_DATA, pages) {
        Ok(a) => a as u64,
        Err(_) => return Err("out of memory for the buffer"),
    };

    let ptr = addr as *mut u8;
    unsafe {
        core::ptr::write_bytes(ptr, 0, pages * 4096);
    }

    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
    match file.read(buf) {
        Ok(n) if n == size => Ok((ptr, size)),
        Ok(_) => Err("incomplete read"),
        Err(_) => Err("read error"),
    }
}

/// Asigna una página (por debajo de 4 GiB) y la pone a cero.
unsafe fn alloc_low_page(boot_services: &BootServices, mem_type: MemoryType) -> u64 {
    let pa = boot_services
        .allocate_pages(AllocateType::MaxAddress(MAX_LOW_ADDR), mem_type, 1)
        .expect("alloc page below 4 GiB") as u64;

    core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE as usize);
    pa
}

/// Devuelve la tabla de nivel inferior de `table_pa[index]`, creándola
/// (a cero, Present+RW) si todavía no existe. Solo se usa sobre tablas propias.
unsafe fn next_table(boot_services: &BootServices, table_pa: u64, index: usize) -> u64 {
    let slot = (table_pa as *mut u64).add(index);
    let entry = core::ptr::read_volatile(slot);

    if entry & 0x1 == 0 {
        let pa = alloc_low_page(boot_services, MemoryType::LOADER_DATA);
        core::ptr::write_volatile(slot, pa | 0x3);
        pa
    } else {
        entry & PTE_ADDR_MASK
    }
}

/// Mapea con identidad la página de 2 MiB que contiene `vaddr`:
/// Present + RW + PS, sin NX (bring-up: todo RWX, el kernel lo endurece).
unsafe fn map_2m_identity(boot_services: &BootServices, pml4_pa: u64, vaddr: u64) {
    let base = vaddr & !(PAGE_2M - 1);

    let pdpt_pa = next_table(boot_services, pml4_pa, ((base >> 39) & 0x1FF) as usize);
    let pd_pa = next_table(boot_services, pdpt_pa, ((base >> 30) & 0x1FF) as usize);

    core::ptr::write_volatile(
        (pd_pa as *mut u64).add(((base >> 21) & 0x1FF) as usize),
        base | 0x83,
    );
}

/// Construye una jerarquía de paginación NUEVA e independiente de la de UEFI:
///   - identity map de 0..4 GiB con páginas de 2 MiB
///   - ventana de 3 páginas de 2 MiB alrededor de `code_va` (el código del
///     propio bootloader), para seguir ejecutándolo tras `mov cr3` aunque el
///     firmware haya cargado la imagen por encima de 4 GiB.
/// Devuelve la dirección física de la PML4.
unsafe fn build_identity_tables(boot_services: &BootServices, code_va: u64) -> u64 {
    let pml4_pa = alloc_low_page(boot_services, MemoryType::LOADER_DATA);

    let mut va = 0u64;
    while va < IDENTITY_LIMIT {
        map_2m_identity(boot_services, pml4_pa, va);
        va += PAGE_2M;
    }

    let center = code_va & !(PAGE_2M - 1);
    let mut va = center.saturating_sub(PAGE_2M);
    let end = center + 2 * PAGE_2M;
    while va < end {
        map_2m_identity(boot_services, pml4_pa, va);
        va += PAGE_2M;
    }

    pml4_pa
}

/// Recorre las tablas `pml4_pa` para una VA y registra cada nivel.
/// Se ejecuta antes de ExitBootServices(), cuando el logger de UEFI sigue activo.
unsafe fn log_mapping(pml4_pa: u64, virt: u64, name: &str) {
    let pml4_index = ((virt >> 39) & 0x1FF) as usize;
    let pml4e = core::ptr::read_volatile((pml4_pa as *const u64).add(pml4_index));

    log::info!(
        "[BOOT] MAP {} VA=0x{:X} PML4=0x{:X} PML4E=0x{:X}",
        name, virt, pml4_pa, pml4e
    );

    if (pml4e & 1) == 0 {
        log::info!("[BOOT] MAP {} -> PML4 NOT PRESENT", name);
        return;
    }

    let pdpt_pa = pml4e & PTE_ADDR_MASK;
    let pdpt_index = ((virt >> 30) & 0x1FF) as usize;
    let pdpte = core::ptr::read_volatile((pdpt_pa as *const u64).add(pdpt_index));

    log::info!(
        "[BOOT] MAP {} PDPTE=0x{:016X} P={} RW={} US={} PS={} NX={}",
        name,
        pdpte,
        (pdpte & 1) != 0,
        (pdpte & 2) != 0,
        (pdpte & 4) != 0,
        (pdpte & (1u64 << 7)) != 0,
        (pdpte & (1u64 << 63)) != 0
    );

    if (pdpte & 1) == 0 || (pdpte & (1u64 << 7)) != 0 {
        return;
    }

    let pd_pa = pdpte & PTE_ADDR_MASK;
    let pd_index = ((virt >> 21) & 0x1FF) as usize;
    let pde = core::ptr::read_volatile((pd_pa as *const u64).add(pd_index));

    log::info!(
        "[BOOT] MAP {} PDE=0x{:016X} P={} RW={} US={} PS={} NX={}",
        name,
        pde,
        (pde & 1) != 0,
        (pde & 2) != 0,
        (pde & 4) != 0,
        (pde & (1u64 << 7)) != 0,
        (pde & (1u64 << 63)) != 0
    );

    if (pde & 1) == 0 || (pde & (1u64 << 7)) != 0 {
        return;
    }

    let pt_pa = pde & PTE_ADDR_MASK;
    let pt_index = ((virt >> 12) & 0x1FF) as usize;
    let pte = core::ptr::read_volatile((pt_pa as *const u64).add(pt_index));

    log::info!(
        "[BOOT] MAP {} PTE=0x{:016X} P={} RW={} US={} NX={}",
        name,
        pte,
        (pte & 1) != 0,
        (pte & 2) != 0,
        (pte & 4) != 0,
        (pte & (1u64 << 63)) != 0
    );
}

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();

    // Todo lo que necesitamos después de ExitBootServices() sale de este bloque.
    let (pml4_pa, stack_top, real_entry_point, info_ptr, mmap_table_pa) = {
        let boot_services = system_table.boot_services();

        log::info!("====================================================");
        log::info!("  TRUNOMY OS v{} - UEFI Bootloader", env!("CARGO_PKG_VERSION"));
        log::info!("  Platform: x86_64 | Architecture: Zero Trust");
        log::info!("====================================================");

        log::info!("[BOOT] Loading kernel...");

        let fs_handles = boot_services
            .locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID))
            .expect("SimpleFileSystem not found");

        let kernel_paths = [cstr16!("\\system\\kernel_x86_64.elf"), cstr16!("\\kernel_x86_64.elf")];
        let sig_paths = [cstr16!("\\system\\kernel_x86_64.elf.sig"), cstr16!("\\kernel_x86_64.elf.sig")];
        let ver_paths = [cstr16!("\\system\\kernel_x86_64.elf.ver"), cstr16!("\\kernel_x86_64.elf.ver")];
        let shell_paths = [cstr16!("\\system\\shell.bin"), cstr16!("\\shell.bin")];

        let mut temp_ptr: *mut u8 = core::ptr::null_mut();
        let mut elf_size: usize = 0;
        let mut found = false;
        let mut signature_bytes = [0u8; 64];
        let mut shell_ptr: *mut u8 = core::ptr::null_mut();
        let mut shell_size: usize = 0;

        for handle in fs_handles.iter() {
            let mut fs = match unsafe {
                boot_services.open_protocol::<SimpleFileSystem>(
                    OpenProtocolParams {
                        handle: *handle,
                        agent: image_handle,
                        controller: None,
                    },
                    OpenProtocolAttributes::Exclusive,
                )
            } {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut root_dir = match fs.open_volume() {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Buscar kernel
            let mut kernel_file = match open_first_regular(&mut root_dir, &kernel_paths) {
                Some(f) => f,
                None => continue,
            };

            // Leer ELF completo a un buffer temporal (a cero y con tamaño verificado)
            let (p, size) = match read_file_to_pages(boot_services, &mut kernel_file, AllocateType::AnyPages) {
                Ok(v) => v,
                Err(e) => panic!("Error reading the ELF: {}", e),
            };
            temp_ptr = p;
            elf_size = size;

            // Leer firma. Un kernel sin firma nunca se carga, y se dice claro.
            let mut sig_file = match open_first_regular(&mut root_dir, &sig_paths) {
                Some(f) => f,
                None => panic!("Kernel found but kernel_x86_64.elf.sig is missing: not loading (I-18)"),
            };

            let sig_len = sig_file.read(&mut signature_bytes).expect("Could not read the kernel signature");
            if sig_len != 64 {
                panic!("The kernel signature is not 64 bytes");
            }

            // Version de seguridad (I-49): va dentro del mensaje firmado, asi que editarla invalida la firma.
            let mut ver_file = match open_first_regular(&mut root_dir, &ver_paths) {
                Some(f) => f,
                None => panic!("Kernel found but kernel_x86_64.elf.ver is missing: not loading (I-49)"),
            };
            let mut ver_bytes = [0u8; 9]; // uno de mas: un archivo largo se nota
            let ver_len = ver_file.read(&mut ver_bytes).expect("Could not read the kernel version");

            let elf_bytes = unsafe { core::slice::from_raw_parts(temp_ptr, elf_size) };
            let stored = read_rollback_counter(system_table.runtime_services());
            // Primero firma, despues contador: una version sin firmar nunca sube el minimo.
            let (version, decision) = match check_kernel(elf_bytes, &signature_bytes, &ver_bytes[..ver_len], &KERNEL_SIGNING_PUBLIC_KEY, stored) {
                Ok(v) => v,
                Err(RollbackError::Rollback { version, minimum }) => panic!(
                    "ROLLBACK REJECTED: kernel with security version {} < minimum accepted {} (I-49)",
                    version, minimum
                ),
                Err(e) => panic!("INVALID KERNEL SIGNATURE: {}", e.as_str()),
            };
            log::info!("[BOOT] Kernel security version {} (previous minimum: {:?})", version, stored);
            if let Decision::Accept { ratchet: Some(v) } = decision {
                store_rollback_counter(system_table.runtime_services(), v);
            }

            log::info!("[BOOT] Valid Ed25519 signature (volume found)");

            // --- Cargar Shell en RAM antes de salir de Boot Services ---
            if !LOAD_SHELL {
                log::info!("[BOOT] LOAD_SHELL=false: the shell is embedded in the kernel");
            } else if let Some(mut shell_file) = open_first_regular(&mut root_dir, &shell_paths) {
                let (ptr, size) = match read_file_to_pages(
                    boot_services,
                    &mut shell_file,
                    AllocateType::MaxAddress(MAX_LOW_ADDR),
                ) {
                    Ok(v) => v,
                    Err(e) => panic!("Error reading shell.bin: {}", e),
                };

                // build_os.sh empaqueta shell.bin como: payload || firma Ed25519
                // (64 bytes finales, firma del payload). Se verifica el payload
                // con la firma incrustada, siempre y sin modo de bypass. El
                // archivo COMPLETO (payload + firma) se entrega tal cual al
                // kernel, cuyo loader lo vuelve a validar. El shell.bin.sig
                // suelto de la imagen es solo para auditoría y no se usa aquí.
                if size <= 64 {
                    panic!(
                        "shell.bin too small to hold payload + signature ({} bytes)",
                        size
                    );
                }

                let shell_bytes = unsafe { core::slice::from_raw_parts(ptr, size) };
                if let Err(e) = verify_appended(shell_bytes, &SHELL_SIGNING_PUBLIC_KEY) {
                    panic!(
                        "INVALID SHELL SIGNATURE: {} (shell.bin: {} bytes, payload: {} bytes)",
                        e.as_str(),
                        size,
                        size - 64
                    );
                }
                log::info!(
                    "[BOOT] Valid Ed25519 shell signature (payload {} bytes + 64-byte signature)",
                    size - 64
                );

                shell_ptr = ptr;
                shell_size = size;
                log::info!("[BOOT] Shell loaded in RAM: ptr=0x{:X}, size={}", shell_ptr as u64, shell_size);
            } else {
                log::warn!("[BOOT] shell.bin not found: the kernel boots without a shell");
            }

            found = true;
            break;
        }

        if !found {
            panic!(r"kernel_x86_64.elf not found in \system or in the root");
        }

        // Validar el ELF completo ANTES de copiar nada (I-18): tipo, rangos, solapes,
        // W^X y entry point. Toda la lógica vive en `trunomy-bootcore` (probada en el host).
        let elf_bytes = unsafe { core::slice::from_raw_parts(temp_ptr, elf_size) };
        let plan = match plan_load(
            elf_bytes,
            Region { base: KERNEL_LOAD_ADDR, max_size: KERNEL_MAX_SIZE },
        ) {
            Ok(p) => p,
            Err(e) => panic!("Kernel ELF rejected: {}", e.as_str()),
        };

        let elf_entry = plan.entry;
        let load_base = plan.base;
        let pages_needed = plan.pages();
        let kernel_size = plan.image_size as usize;
        log::info!("[BOOT] ELF Entry Point (virtual): 0x{:X}", elf_entry);
        log::info!("[BOOT] Total kernel size: {} bytes ({} pages)", kernel_size, pages_needed);
        log::info!("[BOOT] Loading kernel at its link address: 0x{:X}", load_base);

        // Reservar la región física de carga en su dirección de enlace (IDENTITY)
        boot_services
            .allocate_pages(
                AllocateType::Address(load_base),
                MemoryType::LOADER_CODE,
                pages_needed,
            )
            .expect("Could not reserve memory at 0x200000.");

        // `load_into` pone a cero toda la región (huecos, .bss, colas de página) y copia
        // solo contenido de archivo, con todos los índices acotados.
        let image = unsafe { core::slice::from_raw_parts_mut(load_base as *mut u8, kernel_size) };
        if let Err(e) = load_into(&plan, elf_bytes, image) {
            panic!("Could not load the kernel: {}", e.as_str());
        }
        for s in plan.segments() {
            log::info!(
                "[BOOT] Segment loaded: vaddr=0x{:X} -> physical=0x{:X} (size={}, flags={})",
                s.vaddr, s.vaddr, s.mem_size, s.flags
            );
        }


        // --- Pila del kernel (por debajo de 4 GiB, a cero) ---
        let stack_pages = 64usize; // 256 KiB
        let stack_pa = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(MAX_LOW_ADDR),
                MemoryType::LOADER_DATA,
                stack_pages,
            )
            .expect("alloc stack failed") as u64;

        unsafe {
            core::ptr::write_bytes(stack_pa as *mut u8, 0, stack_pages * 4096);
        }

        let stack_top = stack_pa + (stack_pages as u64) * PAGE_SIZE;

        // --- Paginación ---
        // SWITCH_CR3=true: tablas propias (no se modifica nada de UEFI). El CR3
        // de UEFI sigue activo hasta el `mov cr3` final, así que no hay que tocar
        // CR0.WP: solo escribimos en páginas que acabamos de asignar.
        // SWITCH_CR3=false: no se construye ni se toca nada; el kernel hereda
        // el CR3 de UEFI.
        let rip = current_rip();
        let pml4_pa = if SWITCH_CR3 {
            let pa = unsafe { build_identity_tables(boot_services, rip) };

            log::info!(
                "[BOOT] Own identity map: 0x0..0x{:X} (2 MiB, RW) + bootloader window at 0x{:X}",
                IDENTITY_LIMIT,
                rip & !(PAGE_2M - 1)
            );
            log::info!("[BOOT] Own PML4: 0x{:X}", pa);
            pa
        } else {
            let pa = read_cr3() & PTE_ADDR_MASK;
            log::info!("[BOOT] SWITCH_CR3=false: the kernel inherits the UEFI tables (PML4=0x{:X})", pa);
            pa
        };

        // --- Tabla de regiones de memoria para el kernel ---
        // Se reserva AHORA (después de ExitBootServices ya no se puede asignar) y se rellena
        // justo después, con el mapa final. Queda como LOADER_DATA, así que el propio mapa
        // la marca como no usable. Si algo falla, BootInfo.mmap_* queda en 0 y el kernel
        // arranca con sus valores por defecto avisando por serie.
        let mmap_table_bytes = MAX_REGIONS * core::mem::size_of::<MemRegion>();
        let mmap_table_pages = (mmap_table_bytes + 4095) / 4096;
        let mmap_table_pa = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(MAX_LOW_ADDR),
                MemoryType::LOADER_DATA,
                mmap_table_pages,
            )
            .expect("alloc memory region table") as u64;
        unsafe {
            core::ptr::write_bytes(mmap_table_pa as *mut u8, 0, mmap_table_pages * 4096);
        }
        log::info!("[BOOT] Memory region table reserved at 0x{:X} ({} pages)", mmap_table_pa, mmap_table_pages);

        // --- BootInfo para el kernel (se entrega en RDI) ---
        let info_pa = unsafe { alloc_low_page(boot_services, MemoryType::LOADER_DATA) };
        unsafe {
            core::ptr::write(
                info_pa as *mut BootInfo,
                BootInfo {
                    magic: BOOT_INFO_MAGIC,
                    pml4_pa,
                    kernel_base: load_base,
                    kernel_size: kernel_size as u64,
                    shell_ptr: shell_ptr as u64,
                    shell_size: shell_size as u64,
                    mmap_ptr: 0,
                    mmap_len: 0,
                    mmap_desc_size: 0,
                },
            );
        }
        log::info!("[BOOT] BootInfo at 0x{:X}", info_pa);

        // Leer los primeros 16 bytes del entrypoint confirma qué código fue
        // realmente colocado en 0x201000.
        unsafe {
            let entry_ptr = elf_entry as *const u32;
            let w0 = core::ptr::read_unaligned(entry_ptr);
            let w1 = core::ptr::read_unaligned(entry_ptr.add(1));
            let w2 = core::ptr::read_unaligned(entry_ptr.add(2));
            let w3 = core::ptr::read_unaligned(entry_ptr.add(3));

            log::info!(
                "[BOOT] DEBUG ENTRY bytes: {:08X} {:08X} {:08X} {:08X}",
                w0,
                w1,
                w2,
                w3
            );
        }

        log::info!("[BOOT] Entry Point real: 0x{:X}", elf_entry);

        // Diagnóstico sobre las tablas que verá el kernel (las propias si
        // SWITCH_CR3, si no las de UEFI). KERNEL_ENTRY, STACK, SHELL, BOOTINFO y
        // BOOTLOADER deben estar PRESENT + RW.
        unsafe {
            log_mapping(pml4_pa, elf_entry, "KERNEL_ENTRY");
            log_mapping(pml4_pa, stack_top - 8, "STACK");
            if !shell_ptr.is_null() {
                log_mapping(pml4_pa, shell_ptr as u64, "SHELL");
            }
            log_mapping(pml4_pa, info_pa, "BOOTINFO");
            log_mapping(pml4_pa, rip, "BOOTLOADER");
        }

        // PRUEBA DE ExitBootServices():
        // P = justo antes de ExitBootServices
        // E = ExitBootServices regresó correctamente
        // S = CR3 nuevo + pila nueva activos, justo antes del salto al kernel
        unsafe {
            // `cli` modifica IF: por eso aquí NO va `preserves_flags`.
            core::arch::asm!("cli", options(nomem, nostack));
            serial_putc(b'P');
        }

        (pml4_pa, stack_top, elf_entry, info_pa, mmap_table_pa)
    };

    // Si este punto no se alcanza, el fallo está en ExitBootServices()
    // o en el retorno desde su wrapper Rust.
    let (_runtime_table, memory_map) = system_table.exit_boot_services();

    // Convertir el mapa final de UEFI a nuestra tabla de regiones (formato de trunomy-abi).
    // Solo EfiConventionalMemory es REGION_USABLE; todo lo demás (loader, servicios de
    // firmware, ACPI, MMIO...) es REGION_RESERVED y el kernel no lo reutiliza. Las regiones
    // contiguas del mismo tipo se fusionan. Si la tabla se llena, el resto queda fuera
    // (el kernel lo trata como reservado: fail-closed).
    unsafe {
        let table = mmap_table_pa as *mut MemRegion;
        let mut n = 0usize;
        for d in memory_map.entries() {
            let kind = if d.ty == MemoryType::CONVENTIONAL { REGION_USABLE } else { REGION_RESERVED };
            if n > 0 {
                let last = &mut *table.add(n - 1);
                if last.kind == kind && last.base + last.pages * PAGE_SIZE == d.phys_start {
                    last.pages += d.page_count;
                    continue;
                }
            }
            if n == MAX_REGIONS {
                break;
            }
            core::ptr::write(
                table.add(n),
                MemRegion { base: d.phys_start, pages: d.page_count, kind, _pad: 0 },
            );
            n += 1;
        }
        if n > 0 {
            let info = info_ptr as *mut BootInfo;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*info).mmap_ptr), mmap_table_pa);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*info).mmap_len), n as u64);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*info).mmap_desc_size),
                core::mem::size_of::<MemRegion>() as u64,
            );
        }
    }

    unsafe {
        serial_putc(b'E');

        // - mov cr3 (solo con SWITCH_CR3): activa nuestras tablas (el código de
        //   este bloque está dentro de la ventana mapeada alrededor del bootloader).
        // - rsp = stack_top - 8: [rsp] = 0 (pila a cero) hace de dirección de
        //   retorno falsa y deja rsp ≡ 8 (mod 16), como tras un `call` SysV.
        // - rdi = &BootInfo (primer argumento de `kmain(info: *const BootInfo)`).
        // Sin clobbers: dx/al/rdi son entradas explícitas; el resto lo asigna
        // el compilador y no coincide con ellas.
        let entry_rsp = if ABI_ALIGNED_STACK { stack_top - 8 } else { stack_top };

        if SWITCH_CR3 {
            core::arch::asm!(
                "mov cr3, {pml4}",
                "mov rsp, {stk}",
                "out dx, al", // 'S'
                "jmp {entry}",
                pml4 = in(reg) pml4_pa,
                stk = in(reg) entry_rsp,
                entry = in(reg) real_entry_point,
                in("dx") 0x3F8u16,
                in("al") b'S',
                in("rdi") info_ptr,
                options(noreturn)
            );
        } else {
            core::arch::asm!(
                "mov rsp, {stk}",
                "out dx, al", // 'S'
                "jmp {entry}",
                stk = in(reg) entry_rsp,
                entry = in(reg) real_entry_point,
                in("dx") 0x3F8u16,
                in("al") b'S',
                in("rdi") info_ptr,
                options(noreturn)
            );
        }
    }
}
