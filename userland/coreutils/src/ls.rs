// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

// =============================================================================
// TRUNOMY OS - USERLAND COREUTILS (Ring 3)
// file: userland/coreutils/src/ls.rs
// =============================================================================

#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec;
use libtrunomy::ipc_client::{StructuredPipe, TrunomyObject};

/// PUNTO DE ENTRADA DEL COMANDO 'ls'
/// Invocado por el planificador del kernel tras verificar la firma del binario.
/// Recibe el 'pipe_handle' en caso de estar interconectado en una tubería.
#[no_mangle]
pub extern "sysv64" fn _start(pipe_handle: u64) -> ! {
    
    // 1. Verificar si estamos conectados a un Pipe Estructurado de salida
    // Si pipe_handle es 0, significa que el comando se ejecuta directo en consola.
    let has_pipe = pipe_handle != 0;

    // 2. Simulación de lectura del sistema de archivos inmutable
    // En el SO real, invocamos una syscall de lectura de directorio. 
    // El kernel a través de 'capabilities.rs' comprobará si poseemos 'CAP_READ_METADATA'.
    // Si no la tenemos, el proceso es destruido inmediatamente.
    let mut buffer_crudo_archivos = [0u8; 512];
    let total_archivos = unsafe { 
        syscall_fetch_dir_metadata(buffer_crudo_archivos.as_mut_ptr(), 512) 
    };

    if total_archivos <= 0 {
        unsafe { syscall_exit(0); }
    }

    // 3. Crear el descriptor del Pipe tipado usando el SDK si aplica
    let pipe: Option<StructuredPipe<TrunomyObject>> = if has_pipe {
        Some(unsafe { core::mem::transmute(pipe_handle) })
    } else {
        None
    };

    // 4. Bucle de procesamiento de archivos (Simulación de 2 archivos encontrados)
    for i in 0..2 {
        // Construimos el objeto binario estructurado nativo de Trunomy OS
        let archivo_objeto = if i == 0 {
            TrunomyObject::FileMetadata {
                name: vec![b's', b'y', b's', b't', b'e', b'm', b'.', b't', b'o', b'm', b'l'],
                size_bytes: 1420,
                is_directory: false,
                permissions_hash: [0xAA; 32], // Hash criptográfico de su política
            }
        } else {
            TrunomyObject::FileMetadata {
                name: vec![b'w', b'o', b'r', b'k', b's', b'p', b'a', b'c', b'e'],
                size_bytes: 4096,
                is_directory: true,
                permissions_hash: [0xBB; 32],
            }
        };

        // 5. ENRUTAMIENTO DE DATOS INTELIGENTE
        if let Some(ref active_pipe) = pipe {
            // Caso A: Hay un pipe activo (ej: ls | filter). Enviamos el objeto binario puro (CBOR)
            // El kernel validará la capacidad 'CapIpcShareRead' antes de moverlo en RAM.
            let _ = active_pipe.send(&archivo_objeto);
        } else {
            // Caso B: Ejecución directa en consola sin pipe. 
            // Renderizamos los datos de manera amigable para el humano usando la GPU terminal.
            print_file_to_console(&archivo_objeto);
        }
    }

    // 6. Notificar fin de ejecución exitoso al Kernel
    unsafe { syscall_exit(0); }
}

// -----------------------------------------------------------------------------
// SUBSISTEMAS DE RENDERIZADO INTERNO (Para modo sin pipe)
// -----------------------------------------------------------------------------
fn print_file_to_console(obj: &TrunomyObject) {
    if let TrunomyObject::FileMetadata { name, size_bytes, is_directory, .. } = obj {
        // Enviar caracteres directos al render de fuentes vectoriales de la pantalla
        if *is_directory { print_str("[DIR] "); } else { print_str("[FILE] "); }
        
        for &byte in name { print_char(byte); }
        
        print_str(" - ");
        // Aquí se formatearía el tamaño en bytes dinámicamente...
        print_str("Bytes\n");
    }
}

fn print_char(byte: u8) {
    unsafe { core::arch::asm!("syscall", in("rax") 1, in("rdi") byte as u64); }
}

fn print_str(msg: &str) {
    for byte in msg.bytes() { print_char(byte); }
}

// -----------------------------------------------------------------------------
// LLAMADAS AL SISTEMA (SYSCALLS DE X86_64)
// -----------------------------------------------------------------------------
unsafe fn syscall_fetch_dir_metadata(ptr: *mut u8, max_len: usize) -> i64 {
    let result: i64;
    core::arch::asm!(
        "syscall",
        in("rax") 30,         // Syscall 30: Leer metadatos del directorio actual
        in("rdi") ptr,
        in("rsi") max_len,
        lateout("rax") result,
        clobber_abi("sysv64")
    );
    result
}

unsafe fn syscall_exit(code: i32) -> ! {
    core::arch::asm!("syscall", in("rax") 60, in("rdi") code as u64);
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { syscall_exit(1); }
}
