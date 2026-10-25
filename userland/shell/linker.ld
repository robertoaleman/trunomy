/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Trunomy OS - capability-based microkernel for isolating AI agents
 * Copyright (C) 2026 Roberto C. Aleman F.
 * https://github.com/robertoaleman/trunomy
 */

ENTRY(_start)

/* La shell se mapea en el espacio de usuario en USER_CODE_BASE y el kernel
   salta a (base + entry_point). Al enlazar aquí y volcar a binario plano,
   _start queda en el offset 0 de la imagen.

   W^X (parche 17): cada región ocupa páginas enteras y el kernel la mapea con
   sus propios permisos: text R-X, rodata R--, data+bss RW-. Al final va un
   descriptor de 64 bytes (formato en abi/src/image.rs) que el kernel lee del
   payload ya verificado. Si falta o es incoherente, la imagen no se carga. */
USER_CODE_BASE = 0x40000000;
PAGE = 0x1000;

SECTIONS
{
    . = USER_CODE_BASE;

    .text :
    {
        *(.text._start)
        *(.text .text.*)
    }
    . = ALIGN(PAGE);
    __text_end = .;

    .rodata :
    {
        *(.rodata .rodata.*)
    }
    . = ALIGN(PAGE);
    __rodata_end = .;

    .data :
    {
        *(.got .got.plt)
        *(.data .data.*)
    }

    .bss :
    {
        *(.bss .bss.*)
        *(COMMON)
    }
    . = ALIGN(PAGE);
    __data_end = .;

    /* Descriptor: magic "TRUNLAY1" (u64 LE), text_len, rodata_len, data_len,
       total_len, entry_max (= text_len), 0, 0. */
    .layout :
    {
        QUAD(0x3159414C4E555254)
        QUAD(__text_end   - USER_CODE_BASE)
        QUAD(__rodata_end - __text_end)
        QUAD(__data_end   - __rodata_end)
        QUAD(__data_end   - USER_CODE_BASE)
        QUAD(__text_end   - USER_CODE_BASE)
        QUAD(0)
        QUAD(0)
    }

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
