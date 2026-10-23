#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Funciones comunes para las claves de firma (I-19, I-39). Se usa con `source`.
# Dos roles: kernel y shell. Cada uno tiene su PEM en .keys/ y su constante en abi/src/lib.rs.

ZERO_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000

# Hex (64 chars) de la constante `NAME: [u8; 32]` de abi/src/lib.rs.
code_key_hex() {
    local file="${2:-abi/src/lib.rs}" body
    body=$(awk -v n="$1" '$0 ~ ("pub const " n ":"){f=1} f{print} f&&/\];/{exit}' "$file")
    # `[0; 32]` es el marcador de clave sin aprovisionar.
    if printf '%s' "$body" | grep -q '= \[0; 32\];'; then
        printf '%s' "$ZERO_KEY_HEX"
        return 0
    fi
    printf '%s' "$body" | { grep -o '0x[0-9a-fA-F][0-9a-fA-F]' || true; } | sed 's/0x//' | tr -d '\n' | tr 'A-F' 'a-f'
}

# Hex (64 chars) de la clave publica Ed25519 de un PEM.
pem_key_hex() {
    openssl pkey -pubin -in "$1" -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'
}

# check_role ROL CONSTANTE PEM_PUBLICO -> 0 si la constante esta aprovisionada y coincide.
check_role() {
    local role="$1" name="$2" pem="$3" code pemhex
    code=$(code_key_hex "$name")
    if [ "${#code}" -ne 64 ]; then
        echo "[ERROR] Could not read $name from abi/src/lib.rs"; return 1
    fi
    if [ "$code" = "$ZERO_KEY_HEX" ]; then
        echo "[ERROR] $name is not provisioned (all zeros). Run scripts/provision-keys.sh"; return 1
    fi
    if [ ! -f "$pem" ]; then
        echo "[ERROR] The public key for $role does not exist: $pem"; return 1
    fi
    pemhex=$(pem_key_hex "$pem")
    if [ "$code" != "$pemhex" ]; then
        echo "[ERROR] abi::trust::$name does not match $pem"
        echo "        code:   $code"
        echo "        pem:    $pemhex"
        return 1
    fi
    echo "[OK] $name matches the public key for $role"
}

# I-39: las dos claves publicas deben ser distintas.
check_roles_distinct() {
    local k s
    k=$(code_key_hex KERNEL_SIGNING_PUBLIC_KEY); s=$(code_key_hex SHELL_SIGNING_PUBLIC_KEY)
    if [ "$k" = "$s" ]; then
        echo "[ERROR] The shell key and the kernel key are the same (I-39)"; return 1
    fi
    echo "[OK] Kernel and shell keys are different"
}
