#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Arma los dos archivos del kernel que dependen de su version de seguridad (I-49):
#   <ver>  8 bytes: la version, u64 little endian (kernel_x86_64.elf.ver en la imagen)
#   <msg>  lo que se FIRMA: "TRUNOMY-KERNEL-IMAGE-v2\0" || <ver> || ELF
# Es el mismo formato que bootcore::rollback::signed_message; build_os.sh lo usa para firmar y una prueba de
# bootcore (tests/openssl_interop.rs) lo ejecuta tal cual y verifica con el codigo Rust, para que no se separen.
#
#   scripts/kernel-message.sh <version> <kernel.elf> <salida.ver> <salida.msg>
set -euo pipefail
version="${1:?missing security version}"; elf="${2:?missing ELF}"; ver_out="${3:?missing .ver output}"; msg_out="${4:?missing .msg output}"
case "$version" in ''|*[!0-9]*|0) echo "[ERROR] the security version must be a positive integer (it is '$version')" >&2; exit 1 ;; esac
[ "${#version}" -le 18 ] || { echo "[ERROR] the security version is too large" >&2; exit 1; }
[ -f "$elf" ] || { echo "[ERROR] $elf does not exist" >&2; exit 1; }
{ for i in 0 1 2 3 4 5 6 7; do printf "\\x$(printf %02x $(( (version >> (8 * i)) & 255 )))"; done; } >"$ver_out"
[ "$(stat -c '%s' "$ver_out")" -eq 8 ] || { echo "[ERROR] $ver_out is not 8 bytes long" >&2; exit 1; }
{ printf 'TRUNOMY-KERNEL-IMAGE-v2\0'; cat "$ver_out" "$elf"; } >"$msg_out"
