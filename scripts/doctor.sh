#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Comprueba que esta maquina tiene lo necesario para compilar (y, aparte, para arrancar) Trunomy OS.
#   ./scripts/doctor.sh        sale con 1 si falta algo NECESARIO PARA COMPILAR
# Las herramientas de ejecucion (QEMU, OVMF) solo se avisan: sin ellas se compila pero no se arranca.
cd "$(dirname "$0")/.."

missing=0
ok()   { printf '  [OK]       %s\n' "$*"; }
bad()  { printf '  [MISSING]  %s\n' "$*"; missing=1; }
warn() { printf '  [WARN]     %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "Build tools"
for t in rustup cargo rustc git python3 objcopy readelf nm openssl sha256sum; do
    if have "$t"; then ok "$t"; else bad "$t"; fi
done
for t in mkfs.vfat mmd mcopy mdir; do
    if have "$t"; then ok "$t"; else bad "$t (dosfstools / mtools: for trunomy.img)"; fi
done
if have openssl; then
    if openssl genpkey -algorithm ed25519 -out /dev/null >/dev/null 2>&1; then ok "openssl con Ed25519"
    else bad "openssl without Ed25519 (OpenSSL >= 1.1.1 is required)"; fi
fi

echo "Rust toolchain"
if [ -f rust-toolchain.toml ]; then
    pin=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
    ok "rust-toolchain.toml pins rustc $pin"
    if have rustc; then
        act=$(rustc --version | awk '{print $2}')
        if [ "$act" = "$pin" ]; then ok "active rustc = $act"
        else bad "active rustc $act != $pin (rustup toolchain install $pin)"; fi
    fi
else
    bad "rust-toolchain.toml does not exist (run ./scripts/pin-toolchain.sh and commit it)"
fi
if have rustup; then
    for tg in x86_64-unknown-none x86_64-unknown-uefi; do
        if rustup target list --installed 2>/dev/null | grep -qx "$tg"; then ok "target $tg"
        else bad "target $tg (rustup target add $tg)"; fi
    done
fi

echo "Signing keys (I-39)"
if [ -n "${DOCTOR_SKIP_KEYS:-}" ]; then
    :  # build_os.sh las comprueba (y ofrece generarlas) en su propia etapa
elif [ -f .keys/kernel-ed25519-private.pem ] && [ -f .keys/shell-ed25519-private.pem ]; then
    ok ".keys/ holds both private keys"
else
    # No es un requisito para compilar: `./trunomy build` ofrece generar las claves propias en su primera etapa.
    warn "no keys in .keys/: ./trunomy build offers to generate yours (or ./scripts/provision-keys.sh --own-keys)"
fi

echo "Running (optional for building)"
q=""
for c in "${QEMU:-}" /usr/libexec/qemu-kvm qemu-system-x86_64 qemu-kvm; do
    [ -n "$c" ] && { have "$c" || [ -x "$c" ]; } && { q="$c"; break; }
done
if [ -n "$q" ]; then ok "QEMU: $q"; else warn "no QEMU (dnf install qemu-kvm | apt install qemu-system-x86)"; fi
ovmf=""
for f in "${OVMF_CODE:-}" /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/x64/OVMF_CODE.fd /usr/share/qemu/OVMF_CODE.fd; do
    [ -n "$f" ] && [ -f "$f" ] && { ovmf="$f"; break; }
done
if [ -n "$ovmf" ]; then ok "OVMF: $ovmf"; else warn "no OVMF_CODE.fd (dnf install edk2-ovmf | apt install ovmf) or set OVMF_CODE=path"; fi
if [ -w /dev/kvm ]; then ok "/dev/kvm accessible"; else warn "no /dev/kvm: QEMU will emulate (slower)"; fi

echo
if [ "$missing" -eq 0 ]; then echo "[OK] you can build: ./build_os.sh"; else echo "[ERROR] missing build requirements (see above)"; fi
exit "$missing"
