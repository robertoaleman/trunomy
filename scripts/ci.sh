#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Verificaciones de integracion continua de Trunomy OS. Las usa .github/workflows/ci.yml y se
# pueden correr igual en local: ./scripts/ci.sh <host|baremetal|docs|lock|keys|toolchain|nettest|security-version|all>
#
#   lock       Cargo.lock al dia con los Cargo.toml (reproducibilidad de la cadena de suministro)
#   host       pruebas unitarias de cada crate en el host (sin QEMU ni hardware)
#   baremetal  compila bootloader, shell y kernel para sus targets reales y comprueba el ELF
#   keys       claves de firma de kernel y shell aprovisionadas, no nulas y distintas (I-39)
#   toolchain  rust-toolchain.toml fija una version estable exacta de rustc y los dos targets
#   security-version  config/security-version es un entero positivo y no baja respecto al commit anterior (I-49)
#   nettest    el codec de tramas de scripts/nettest.py contra su vector fijo (compartido con abi/netproto)
#   docs       cada invariante de docs/invariants.md tiene su fila de trazabilidad
#
# Limite: nada de esto arranca el sistema. La verificacion en QEMU/hardware sigue siendo manual.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HOST_TARGET="${HOST_TARGET:-x86_64-unknown-linux-gnu}"
# --locked por defecto (reproducible). CI_LOCKED="" lo quita (solo para pruebas locales sin Cargo.lock al dia).
LOCKED="${CI_LOCKED---locked}"

step() { echo; echo "==> $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

# cargo con la salida a la vista, pero un aviso del compilador cuenta como fallo: la compilacion se mantiene
# limpia. `cargo test` y `cargo build` repiten los avisos aunque el crate ya este compilado.
cg() {
    local log rc=0 n
    log=$(mktemp)
    set +e; cargo "$@" 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}; set -e
    n=$(grep -E '^warning' "$log" | grep -vcE 'generated [0-9]+ warning' || true)
    rm -f "$log"
    [ "$rc" -eq 0 ] || exit "$rc"
    [ "$n" -eq 0 ] || fail "the compiler emitted $n warning(s): fix them (or justify an #[allow] with a comment)"
}

ci_lock() {
    step "Cargo.lock up to date"
    cargo metadata --locked --format-version 1 >/dev/null 2>&1 \
        || fail "Cargo.lock does not match the Cargo.toml files: run 'cargo build' and commit Cargo.lock"
    echo "[OK] Cargo.lock up to date"
}

# Reproducibilidad: sin toolchain fijado, "la ultima estable" cambia el binario (y a veces rompe el
# build) sin tocar una linea del repositorio.
ci_toolchain() {
    step "pinned toolchain (rust-toolchain.toml)"
    [ -f rust-toolchain.toml ] || fail "rust-toolchain.toml is missing: run ./scripts/pin-toolchain.sh and commit it"
    local ch
    ch=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
    printf '%s' "$ch" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || fail "channel '$ch' is not an exact stable version (X.Y.Z): 'stable'/'nightly' are not reproducible"
    for t in x86_64-unknown-none x86_64-unknown-uefi; do
        grep -q "\"$t\"" rust-toolchain.toml || fail "rust-toolchain.toml does not declare the target $t"
    done
    echo "[OK] rustc $ch pinned, with its targets"
}

ci_host() {
    step "abi"
    cg test $LOCKED --target "$HOST_TARGET" -p trunomy-abi
    step "bootcore (with ELF and the openssl interoperability test)"
    cg test $LOCKED --target "$HOST_TARGET" -p trunomy-bootcore --features elf
    step "libtrunomy"
    cg test $LOCKED --target "$HOST_TARGET" -p libtrunomy
    step "kernel"
    cg test $LOCKED --target "$HOST_TARGET" -p trunomy-kernel
}

# El kernel incluye shell.bin con include_bytes!; en CI no hay clave privada, asi que se firma con
# 64 bytes a cero: sirve para COMPILAR y comprobar el ELF, nunca para arrancar (la firma no vale).
ci_baremetal() {
    rustup target add x86_64-unknown-none x86_64-unknown-uefi
    local out=target/x86_64-unknown-none/release

    step "UEFI bootloader"
    cg build $LOCKED --release -p trunomy-bootloader --target x86_64-unknown-uefi

    step "shell"
    cg build $LOCKED --release -p trunomy-shell --target x86_64-unknown-none
    objcopy --set-section-flags .bss=alloc,load,contents -O binary "$out/trunomy-shell" "$out/shell.bin" 2>/dev/null \
        || objcopy -O binary "$out/trunomy-shell" "$out/shell.bin"
    head -c 64 /dev/zero >> "$out/shell.bin"

    step "kernel"
    cg build $LOCKED --release -p trunomy-kernel --target x86_64-unknown-none
    local elf="$out/trunomy-kernel"

    step "kernel ELF: no RWE segments (I-18)"
    if readelf -lW "$elf" | awk '$1=="LOAD" {f=""; for(i=7;i<NF;i++) f=f $i; if (f ~ /W/ && f ~ /E/) bad=1} END{exit !bad}'; then
        readelf -lW "$elf" | grep LOAD
        fail "PT_LOAD segment that is writable and executable"
    fi
    echo "[OK] no RWE"

    step "kernel ELF: section boundaries for W^X (I-37)"
    sym() { nm "$elf" | awk -v s="$1" '$3==s {print "0x" $1}'; }
    local ks ts rs ds ke
    ks=$(sym __kernel_start); ts=$(sym __text_start); rs=$(sym __rodata_start)
    ds=$(sym __data_start); ke=$(sym __kernel_end)
    for v in "$ks" "$ts" "$rs" "$ds" "$ke"; do
        [ -n "$v" ] || fail "a linker boundary symbol is missing (__kernel_start/__text_start/__rodata_start/__data_start/__kernel_end)"
        [ $(( v % 4096 )) -eq 0 ] || fail "boundary $v is not 4 KiB aligned"
    done
    [ $(( ks )) -le $(( ts )) ] && [ $(( ts )) -lt $(( rs )) ] && [ $(( rs )) -le $(( ds )) ] && [ $(( ds )) -lt $(( ke )) ] \
        || fail "boundaries out of order: $ks $ts $rs $ds $ke"
    echo "[OK] start=$ks text=$ts rodata=$rs data=$ds end=$ke"
}

ci_docs() {
    step "invariants I-16 and later have a traceability row (earlier ones carry their tests in their own section)"
    local missing=0 id
    for id in $(grep -oE '^### I-[0-9]+' docs/invariants.md | sed 's/### //' | awk -F- '$2 >= 16' | sort -u); do
        if ! grep -qE "^${id} +\|" docs/invariants.md; then
            echo "[ERROR] ${id} has no row in the traceability table"
            missing=1
        fi
    done
    [ "$missing" -eq 0 ] || exit 1
    echo "[OK] all I-16+ invariants have a traceability row"
}

# CI no tiene claves privadas: solo se comprueban las constantes publicas (y, si existe .keys/ en
# local, que coincidan con sus PEM).
ci_keys() {
    step "signing keys: kernel and shell (I-39)"
    # shellcheck source=scripts/keys-lib.sh
    source scripts/keys-lib.sh
    local k s
    k=$(code_key_hex KERNEL_SIGNING_PUBLIC_KEY); s=$(code_key_hex SHELL_SIGNING_PUBLIC_KEY)
    [ "${#k}" -eq 64 ] && [ "${#s}" -eq 64 ] || fail "could not read the constants in abi/src/lib.rs"
    [ "$k" != "$ZERO_KEY_HEX" ] || fail "KERNEL_SIGNING_PUBLIC_KEY is all zeros"
    [ "$s" != "$ZERO_KEY_HEX" ] || fail "SHELL_SIGNING_PUBLIC_KEY is not provisioned: run scripts/provision-keys.sh and commit abi/src/lib.rs"
    check_roles_distinct || exit 1
    if [ -f .keys/kernel-ed25519-public.pem ] && [ -f .keys/shell-ed25519-public.pem ]; then
        check_role kernel KERNEL_SIGNING_PUBLIC_KEY .keys/kernel-ed25519-public.pem || exit 1
        check_role shell SHELL_SIGNING_PUBLIC_KEY .keys/shell-ed25519-public.pem || exit 1
    fi
    echo "[OK] kernel and shell keys provisioned and different"
}

ci_security_version() {
    step "config/security-version: positive integer that never goes down (I-49)"
    local v prev
    v="$(tr -d '[:space:]' < config/security-version 2>/dev/null || true)"
    case "$v" in ''|*[!0-9]*|0) fail "config/security-version must be a positive integer (it is '$v')" ;; esac
    [ "${#v}" -le 18 ] || fail "config/security-version is too large"
    # Si hay historia, la version no puede bajar respecto al commit anterior: bajarla reabriria el rollback.
    prev="$(git show HEAD~1:config/security-version 2>/dev/null | tr -d '[:space:]' || true)"
    if [ -n "$prev" ] && [ "$v" -lt "$prev" ] 2>/dev/null; then
        fail "config/security-version went down from $prev to $v: a lower version cannot be released (I-49)"
    fi
    echo "[OK] security-version $v"
}

ci_nettest() {
    step "scripts/nettest.py: host frame codec against the fixed vector in abi/netproto"
    command -v python3 >/dev/null 2>&1 || fail "python3 is missing"
    python3 -I scripts/nettest.py --selftest
    local f
    for f in scripts/nettest2.py scripts/audittest.py scripts/rollbacktest.py scripts/netdemotest.py scripts/linetest.py; do
        python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f" || fail "$f does not compile"
    done
    # El vector fijo debe ser identico en Rust y en Python.
    local hex_py hex_rs
    hex_py=$(python3 -I -c 'import runpy;print(runpy.run_path("scripts/nettest.py")["GOLDEN_HEX"])')
    hex_rs=$(grep -oE 'GOLDEN_HEX: &str = "[0-9a-f]+"' abi/src/netproto.rs | grep -oE '[0-9a-f]{20,}')
    [ -n "$hex_rs" ] && [ "$hex_py" = "$hex_rs" ] || fail "the fixed vector in nettest.py and the one in abi/src/netproto.rs differ"
    echo "[OK] codec and fixed vector match"
}

case "${1:-all}" in
    lock) ci_lock ;;
    toolchain) ci_toolchain ;;
    host) ci_host ;;
    baremetal) ci_baremetal ;;
    docs) ci_docs ;;
    nettest) ci_nettest ;;
    security-version) ci_security_version ;;
    keys) ci_keys ;;
    all) ci_toolchain; ci_lock; ci_docs; ci_nettest; ci_security_version; ci_keys; ci_host; ci_baremetal; step "ci.sh all"; echo "[OK] all green" ;;
    *) echo "usage: $0 <lock|toolchain|host|baremetal|docs|keys|nettest|security-version|all>" >&2; exit 2 ;;
esac
