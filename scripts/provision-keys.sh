#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Aprovisiona las claves de firma (I-39). Ejecutar UNA vez en la maquina de build.
#  - Genera .keys/shell-ed25519-{private,public}.pem si no existen (la clave privada solo se
#    crea aqui, nunca viaja en el repositorio: .keys/ esta en .gitignore).
#  - Reescribe abi::trust::SHELL_SIGNING_PUBLIC_KEY con la publica del PEM.
#  - La clave del kernel (.keys/kernel-ed25519-*) debe existir ya; no se toca.
# Es idempotente. No sustituye nunca una clave privada existente.
#
# --own-keys: para quien clona el repositorio SIN la clave privada del autor (otra maquina, un fork,
#   una instalacion limpia). Genera ademas la clave del KERNEL si no existe y reescribe tambien
#   abi::trust::KERNEL_SIGNING_PUBLIC_KEY. El resultado es una cadena de confianza PROPIA: el
#   bootloader solo arrancara kernels y shells firmados con esas claves. Sin esta bandera, la falta
#   de la clave del kernel es un error (no se genera una por accidente).
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/keys-lib.sh
source scripts/keys-lib.sh

OWN_KEYS=0
case "${1:-}" in
    --own-keys) OWN_KEYS=1 ;;
    "") ;;
    *) echo "usage: $0 [--own-keys]" >&2; exit 2 ;;
esac

mkdir -p .keys
chmod 700 .keys
KPUB=.keys/kernel-ed25519-public.pem
KPRIV=.keys/kernel-ed25519-private.pem
SPRIV=.keys/shell-ed25519-private.pem
SPUB=.keys/shell-ed25519-public.pem

if [ ! -f "$KPUB" ] || [ ! -f "$KPRIV" ]; then
    if [ "$OWN_KEYS" -eq 1 ]; then
        [ ! -f "$KPRIV" ] || { echo "[ERROR] $KPRIV exists but $KPUB is missing: restore the public key (openssl pkey -in $KPRIV -pubout)"; exit 1; }
        echo "[INFO] Generating the kernel key (your own chain of trust)..."
        ( umask 077; openssl genpkey -algorithm ed25519 -out "$KPRIV" )
        chmod 600 "$KPRIV"
        openssl pkey -in "$KPRIV" -pubout -out "$KPUB"
        NEW_KERNEL_KEY=1
    else
        echo "[ERROR] The kernel key is missing from .keys/ (kernel-ed25519-{private,public}.pem)."
        echo "        If you cloned the repository and do not have the author's key, use: $0 --own-keys"
        exit 1
    fi
fi
NEW_KERNEL_KEY="${NEW_KERNEL_KEY:-0}"

if [ ! -f "$SPRIV" ]; then
    echo "[INFO] Generating the shell key..."
    umask 077
    openssl genpkey -algorithm ed25519 -out "$SPRIV"
fi
chmod 600 "$SPRIV"
openssl pkey -in "$SPRIV" -pubout -out "$SPUB"

HEX=$(pem_key_hex "$SPUB")
[ "${#HEX}" -eq 64 ] || { echo "[ERROR] invalid shell public key"; exit 1; }
KHEX=$(pem_key_hex "$KPUB")
if [ "$HEX" = "$KHEX" ]; then
    echo "[ERROR] The shell key is the same as the kernel key; delete $SPRIV and try again"; exit 1
fi

# Reescribe una constante `[u8; 32]` de abi/src/lib.rs con la clave publica (hex) dada.
rewrite_const() {
python3 - "$1" "$2" <<'PY'
import re, sys
name, hexs = sys.argv[1], sys.argv[2]
bs = [f"0x{hexs[i:i+2]}" for i in range(0, 64, 2)]
lines = []
for i in range(0, 32, 15):
    lines.append("        " + ", ".join(bs[i:i+15]) + ",")
new = f"    pub const {name}: [u8; 32] = [\n" + "\n".join(lines) + "\n    ];"
p = "abi/src/lib.rs"
s = open(p).read()
pat = re.compile(r"    pub const " + name + r": \[u8; 32\] = (\[0; 32\];|\[[^\]]*\];)")
s2, n = pat.subn(new, s)
if n != 1:
    sys.exit(f"[ERROR] could not find {name} in abi/src/lib.rs")
open(p, "w").write(s2)
PY
}

rewrite_const SHELL_SIGNING_PUBLIC_KEY "$HEX"
if [ "$NEW_KERNEL_KEY" -eq 1 ]; then
    rewrite_const KERNEL_SIGNING_PUBLIC_KEY "$KHEX"
fi
check_role shell SHELL_SIGNING_PUBLIC_KEY "$SPUB"
check_role kernel KERNEL_SIGNING_PUBLIC_KEY "$KPUB"
check_roles_distinct
echo "[OK] Keys provisioned. Commit the change to abi/src/lib.rs (it is public); do NOT commit .keys/."
[ "$NEW_KERNEL_KEY" -eq 0 ] || echo "[INFO] Your OWN chain of trust: other people's images (with a different kernel key) will not boot with this bootloader, and vice versa."
