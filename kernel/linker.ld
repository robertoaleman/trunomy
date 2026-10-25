/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Trunomy OS - capability-based microkernel for isolating AI agents
 * Copyright (C) 2026 Roberto C. Aleman F.
 * https://github.com/robertoaleman/trunomy
 */

ENTRY(_start)

/* El bootloader UEFI carga el kernel en las direcciones físicas indicadas por
   los segmentos PT_LOAD (identidad), por lo que la dirección de enlace y la de
   carga deben coincidir. */
KERNEL_BASE = 2M;

SECTIONS
{
    . = KERNEL_BASE;
    __kernel_start = .;

    .boot :
    {
        KEEP(*(.boot))
        KEEP(*(.multiboot_header))
    }

    /* Limites de seccion para W^X del mapa del kernel (I-37). Cada seccion empieza alineada a
       4 KiB, asi que estos simbolos lo estan tambien (no cambian la disposicion). */
    .text : ALIGN(4K)
    {
        __text_start = .;
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : ALIGN(4K)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K)
    {
        __data_start = .;
        *(.got .got.plt)
        *(.data .data.*)
    }

    .bss : ALIGN(4K)
    {
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4K);
    }

    __kernel_end = .;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
