#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Comprueba que el build es REPRODUCIBLE: compila dos veces desde clones limpios del HEAD, en rutas
# distintas y con targets vacios, y compara el sha256 de cada artefacto. Si coinciden, el binario
# depende solo del codigo, del Cargo.lock y del toolchain fijado, no de la maquina ni de la ruta.
#   ./scripts/repro-check.sh [--allow-dirty]
# Dentro de un repositorio git compila clones del HEAD. En un arbol SIN git (por ejemplo un `git archive`
# descomprimido) compila dos copias del directorio, sin .git, target/ ni .keys/ (las claves privadas no entran).
# Compila SIN firmar (como `ci.sh baremetal`): la firma Ed25519 es determinista pero necesita la clave
# privada; lo que se compara es el codigo. Requiere rust-toolchain.toml (./scripts/pin-toolchain.sh).
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ALLOW_DIRTY=0
[ "${1:-}" = "--allow-dirty" ] && ALLOW_DIRTY=1
fail() { echo "[ERROR] $*" >&2; exit 1; }

[ -f rust-toolchain.toml ] || fail "rust-toolchain.toml is missing: run ./scripts/pin-toolchain.sh and commit it"
# Hay git "propio" solo si este directorio ES la raiz de un repositorio (no uno padre que lo contenga por casualidad).
HAVE_GIT=0
if top="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" && [ "$(cd "$top" && pwd -P)" = "$(pwd -P)" ]; then
    HAVE_GIT=1
fi
# Los clones salen del HEAD: lo que no este commiteado NO se compila y el resultado enganaria.
if [ "$HAVE_GIT" -eq 1 ] && [ "$ALLOW_DIRTY" -eq 0 ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    git status --short --untracked-files=no
    fail "there are uncommitted changes: this would build HEAD, not your tree. Commit them or use --allow-dirty"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# Rutas de distinta longitud y nombre: una ruta absoluta filtrada en el binario cambiaria el hash.
DIRS=("$WORK/a/trunomy-one" "$WORK/bb/trunomy-second-copy")
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

# Sin git: copia del arbol sin .git, target/, .keys/ (claves privadas), la imagen ni zips (no son codigo).
copy_tree() {
    mkdir -p "$1"
    tar -C "$ROOT" --exclude=./.git --exclude=./target --exclude=./.keys --exclude=./trunomy.img --exclude='./*.zip' -cf - . \
        | tar -C "$1" -xf - || fail "could not copy the tree to $1"
}

build_one() {
    local d="$1"
    mkdir -p "$(dirname "$d")"
    if [ "$HAVE_GIT" -eq 1 ]; then
        git clone -q --no-hardlinks "$ROOT" "$d" || fail "git clone of $ROOT into $d failed"
    else
        copy_tree "$d"
    fi
    (
        cd "$d"
        # --config se SUMA a las rustflags de .cargo/config.toml (no las sustituye, a diferencia de RUSTFLAGS).
        remap() { printf 'target.%s.rustflags=["--remap-path-prefix=%s=/trunomy","--remap-path-prefix=%s=/cargo"]' "$1" "$d" "$CARGO_HOME_DIR"; }
        local out=target/x86_64-unknown-none/release
        cargo build --locked --release -p trunomy-bootloader --target x86_64-unknown-uefi --config "$(remap x86_64-unknown-uefi)"
        cargo build --locked --release -p trunomy-shell --target x86_64-unknown-none --config "$(remap x86_64-unknown-none)"
        objcopy --set-section-flags .bss=alloc,load,contents -O binary "$out/trunomy-shell" "$out/shell.bin" 2>/dev/null \
            || objcopy -O binary "$out/trunomy-shell" "$out/shell.bin"
        head -c 64 /dev/zero >> "$out/shell.bin"
        cargo build --locked --release -p trunomy-kernel --target x86_64-unknown-none --config "$(remap x86_64-unknown-none)"
    ) >"$d.log" 2>&1 || { tail -30 "$d.log"; fail "the build in $d failed (full log: $d.log)"; }
}

if [ "$HAVE_GIT" -eq 1 ]; then
    echo "==> rustc: $(rustc --version)  (HEAD $(git rev-parse --short HEAD))"
else
    echo "==> rustc: $(rustc --version)  (tree without git: two copies of the directory are built, without .git, target/ or .keys/)"
fi
for d in "${DIRS[@]}"; do
    echo "==> clean build in $d"
    build_one "$d"
done

ARTIFACTS=(
    "target/x86_64-unknown-none/release/trunomy-kernel"
    "target/x86_64-unknown-none/release/trunomy-shell"
    "target/x86_64-unknown-none/release/shell.bin"
    "target/x86_64-unknown-uefi/release/trunomy-bootloader.efi"
)
echo
printf '%-58s %s\n' ARTIFACT RESULT
diffs=0
for a in "${ARTIFACTS[@]}"; do
    h1=$(sha256sum "${DIRS[0]}/$a" | cut -d' ' -f1)
    h2=$(sha256sum "${DIRS[1]}/$a" | cut -d' ' -f1)
    if [ "$h1" = "$h2" ]; then
        printf '%-58s SAME       %s\n' "$a" "$h1"
    else
        printf '%-58s DIFFERENT\n   copy 1: %s\n   copy 2: %s\n' "$a" "$h1" "$h2"
        diffs=1
        # Diagnostico: rutas absolutas dentro del binario, bytes distintos y, en un PE, la fecha de cabecera.
        leaked=$(strings -a "${DIRS[0]}/$a" | grep -cE "^$WORK|$CARGO_HOME_DIR|^/(home|root|tmp)/" || true)
        echo "   absolute paths visible in copy 1: $leaked"
        echo "   differing bytes: $(cmp -l "${DIRS[0]}/$a" "${DIRS[1]}/$a" 2>/dev/null | wc -l) (first offsets, 1-indexed: $(cmp -l "${DIRS[0]}/$a" "${DIRS[1]}/$a" 2>/dev/null | head -8 | awk '{printf "%s ", $1}'))"
        case "$a" in *.efi)
            python3 - "${DIRS[0]}/$a" "${DIRS[1]}/$a" <<'PY'
import struct, sys
a, b = (open(f, "rb").read() for f in sys.argv[1:3])
pe = struct.unpack_from("<I", a, 0x3C)[0]
nsec, = struct.unpack_from("<H", a, pe + 6)
optsz, = struct.unpack_from("<H", a, pe + 20)
opt = pe + 24
magic, = struct.unpack_from("<H", a, opt)
dd = opt + (112 if magic == 0x20B else 96)           # directorios de datos
dbg_rva, dbg_sz = struct.unpack_from("<II", a, dd + 6 * 8)
secs = []
for k in range(nsec):
    o = opt + optsz + 40 * k
    name = a[o:o + 8].rstrip(b"\0").decode("latin1")
    vsz, va, rsz, raw = struct.unpack_from("<IIII", a, o + 8)
    secs.append((name, va, vsz, raw, rsz))
def where(off):
    if off < opt + optsz:
        fields = {pe + 8: "FileHeader.TimeDateStamp", opt + 64: "OptionalHeader.CheckSum"}
        return fields.get(off & ~3, "PE header")
    for name, va, vsz, raw, rsz in secs:
        if raw <= off < raw + rsz:
            rva = va + off - raw
            tag = " (debug directory)" if dbg_rva and dbg_rva <= rva < dbg_rva + dbg_sz else ""
            return f"section {name} +{off - raw:#x}{tag}"
    return "outside sections"
diff = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
print(f"   size: {len(a)} / {len(b)}")
last = None
for i in diff:
    w = where(i)
    if w != last:
        print(f"   {i:#08x}: {w}   copy1={a[i:i+8].hex()} copy2={b[i:i+8].hex()}")
        last = w
PY
            ;;
        esac
    fi
done
echo
if [ "$diffs" -eq 0 ]; then
    echo "[OK] reproducible build: two clean clones in different paths give identical binaries"
else
    echo "[ERROR] the build is NOT reproducible (see DIFFERENT above). Record the artifact and the reason in docs/reproducible-demo.md"
    exit 1
fi
