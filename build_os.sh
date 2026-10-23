#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Compila, firma y empaqueta Trunomy OS en trunomy.img. Cada etapa dice QUE hace y POR QUE; la salida de
# cargo va a target/build-logs/ (se muestra entera solo si algo falla o con --verbose).
#
#   ./build_os.sh               compila todo
#   ./build_os.sh --run         compila y arranca en QEMU
#   ./build_os.sh --own-keys    si no tienes las claves del autor, genera las tuyas (cadena de confianza propia)
#   ./build_os.sh --verbose     muestra la salida completa de cargo
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

usage() {
    cat <<'EOF_USAGE'
Builds, signs and packages Trunomy OS into trunomy.img. Each stage says WHAT it does and WHY; cargo output goes
to target/build-logs/ (shown in full only if something fails, or with --verbose).

  ./build_os.sh               build everything
  ./build_os.sh --run         build and boot in QEMU
  ./build_os.sh --own-keys    if you do not have the author's keys, generate your own (your own chain of trust)
  ./build_os.sh --verbose     show the full cargo output
EOF_USAGE
}

VERBOSE=0; RUN=0; OWN_KEYS=0
for a in "$@"; do
    case "$a" in
        -v|--verbose) VERBOSE=1 ;;
        --run) RUN=1 ;;
        --own-keys) OWN_KEYS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
    esac
done

# --- presentacion ----------------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; Z=$'\033[0m'
else B=""; G=""; Y=""; R=""; D=""; Z=""; fi
TOTAL=6; N=0; T0=$SECONDS
LOGDIR="$ROOT_DIR/target/build-logs"; mkdir -p "$LOGDIR"

stage() { N=$((N + 1)); printf '\n%s[%d/%d] %s%s\n' "$B" "$N" "$TOTAL" "$1" "$Z"; shift; for l in "$@"; do printf '      %s%s%s\n' "$D" "$l" "$Z"; done; }
ok()    { printf '      %s[OK]%s %s\n' "$G" "$Z" "$*"; }
warn()  { printf '      %s[WARN]%s %s\n' "$Y" "$Z" "$*"; }
die()   { printf '\n%s[ERROR]%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }

# run NOMBRE comando...  -> guarda la salida en target/build-logs/NOMBRE.log; si falla, la muestra.
# Deja en LAST_WARNINGS el numero de avisos del compilador de esa orden.
run() {
    local name="$1" log="$LOGDIR/$1.log" rc=0; shift
    if [ "$VERBOSE" -eq 1 ]; then
        set +e; "$@" 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}; set -e
    else
        "$@" >"$log" 2>&1 || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        [ "$VERBOSE" -eq 1 ] || { echo "      ${D}--- last lines of $name.log ---${Z}" >&2; tail -n 40 "$log" | sed 's/^/      /' >&2; }
        die "'$name' failed. Full log: ${log#"$ROOT_DIR"/}"
    fi
    LAST_WARNINGS=$(grep -E '^warning' "$log" | grep -vcE 'generated [0-9]+ warning' || true)
}
built() { # built NOMBRE ARTEFACTO: resumen de una compilacion
    local t=$((SECONDS - $3))
    if [ "${LAST_WARNINGS:-0}" -eq 0 ]; then ok "$1 built in ${t}s, no warnings"
    else warn "$1 built with $LAST_WARNINGS warnings (see ${LOGDIR#"$ROOT_DIR"/}/$2.log)"; fi
}
short() { sha256sum "$1" | cut -c1-16; }
size()  { stat -c '%s' "$1"; }

printf '%s====================================================%s\n' "$B" "$Z"
printf '%s  Trunomy OS: build, signing and boot image%s\n' "$B" "$Z"
printf '%s====================================================%s\n' "$B" "$Z"

# --- 1. Requisitos y claves --------------------------------------------------------------------------
stage "Requirements and signing keys" \
    "Trunomy only runs signed code: the bootloader verifies the kernel and the shell with Ed25519." \
    "Everything is checked BEFORE compiling so the build does not fail halfway."

if ! DOCTOR_SKIP_KEYS=1 ./scripts/doctor.sh >"$LOGDIR/doctor.log" 2>&1; then
    grep -E 'MISSING' "$LOGDIR/doctor.log" | sed 's/^/      /' >&2
    die "missing build requirements. Details: ./scripts/doctor.sh"
fi
ok "tools, Rust toolchain and targets available"

# shellcheck source=scripts/keys-lib.sh
source "$ROOT_DIR/scripts/keys-lib.sh"
KERNEL_PRIVATE_KEY="$ROOT_DIR/.keys/kernel-ed25519-private.pem"; KERNEL_PUBLIC_KEY="$ROOT_DIR/.keys/kernel-ed25519-public.pem"
SHELL_PRIVATE_KEY="$ROOT_DIR/.keys/shell-ed25519-private.pem";   SHELL_PUBLIC_KEY="$ROOT_DIR/.keys/shell-ed25519-public.pem"

if [ ! -f "$KERNEL_PRIVATE_KEY" ] || [ ! -f "$KERNEL_PUBLIC_KEY" ]; then
    if [ "$OWN_KEYS" -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
        echo "      There are no signing keys in .keys/ (normal right after cloning the repository)."
        echo "      I can generate yours: your OWN chain of trust. The private keys stay in"
        echo "      .keys/ (ignored by git) and the public keys are written to abi/src/lib.rs."
        read -r -p "      Generate your own keys now? [Y/n] " ans
        case "${ans:-Y}" in [nN]*) die "cannot sign without keys. Use --own-keys or ./scripts/provision-keys.sh" ;; *) OWN_KEYS=1 ;; esac
    fi
    [ "$OWN_KEYS" -eq 1 ] || die "the signing keys are missing from .keys/. If you do not have the author's: ./build_os.sh --own-keys"
fi
if [ "$OWN_KEYS" -eq 1 ] || [ ! -f "$SHELL_PRIVATE_KEY" ] || [ ! -f "$SHELL_PUBLIC_KEY" ]; then
    run keys ./scripts/provision-keys.sh $([ "$OWN_KEYS" -eq 1 ] && echo --own-keys)
    ok "keys provisioned (the change in abi/src/lib.rs is public: commit it; NEVER .keys/)"
fi
chmod 600 "$KERNEL_PRIVATE_KEY" "$SHELL_PRIVATE_KEY"

# I-19: la constante compilada debe ser EXACTAMENTE la publica del PEM, y las dos claves distintas (I-39).
(check_role kernel KERNEL_SIGNING_PUBLIC_KEY "$KERNEL_PUBLIC_KEY" \
    && check_role shell SHELL_SIGNING_PUBLIC_KEY "$SHELL_PUBLIC_KEY" \
    && check_roles_distinct) >"$LOGDIR/keys-check.log" 2>&1 \
    || { cat "$LOGDIR/keys-check.log" >&2; die "the keys do not match the constants in abi/src/lib.rs"; }
ok "kernel  public key ${D}$(pem_key_hex "$KERNEL_PUBLIC_KEY" | cut -c1-16)...${Z}"
ok "shell   public key ${D}$(pem_key_hex "$SHELL_PUBLIC_KEY" | cut -c1-16)...${Z}  (different: one cannot sign for the other)"

rustup target add x86_64-unknown-uefi x86_64-unknown-none >"$LOGDIR/targets.log" 2>&1 || true

# --- 2. Bootloader -----------------------------------------------------------------------------------
stage "UEFI bootloader" \
    "It is the first thing the firmware runs. It embeds the public keys and refuses to" \
    "boot a kernel or a shell whose signature is not valid."
t=$SECONDS
run bootloader cargo build --release -p trunomy-bootloader --target x86_64-unknown-uefi
BOOTLOADER=target/x86_64-unknown-uefi/release/trunomy-bootloader.efi
built "bootloader" bootloader "$t"

# --- 3. Shell ----------------------------------------------------------------------------------------
stage "User shell (Ring 3)" \
    "The only part that talks to the operator. It runs unprivileged: everything it does goes through the kernel." \
    "It is dumped to a flat binary and signed with the SHELL key."
t=$SECONDS
run shell cargo build --release -p trunomy-shell --target x86_64-unknown-none
built "shell" shell "$t"
SHELL_ELF=target/x86_64-unknown-none/release/trunomy-shell
SHELL_BIN=target/x86_64-unknown-none/release/shell.bin
SHELL_SIG="$SHELL_BIN.sig"
objcopy --set-section-flags .bss=alloc,load,contents -O binary "$SHELL_ELF" "$SHELL_BIN" 2>/dev/null \
    || objcopy -O binary "$SHELL_ELF" "$SHELL_BIN"
openssl pkeyutl -sign -rawin -inkey "$SHELL_PRIVATE_KEY" -in "$SHELL_BIN" -out "$SHELL_SIG"
[ "$(size "$SHELL_SIG")" -eq 64 ] || die "the shell signature is not 64 bytes"
openssl pkeyutl -verify -rawin -pubin -inkey "$SHELL_PUBLIC_KEY" -in "$SHELL_BIN" -sigfile "$SHELL_SIG" >/dev/null \
    || die "the shell signature does not verify with its public key"
ok "shell signed and verified ($(size "$SHELL_BIN") bytes, sha256 $(short "$SHELL_BIN")...)"
# El kernel la incrusta (payload + 64 bytes de firma) y la vuelve a verificar al arrancar.
cat "$SHELL_BIN" "$SHELL_SIG" >"$SHELL_BIN.signed" && mv "$SHELL_BIN.signed" "$SHELL_BIN"
ok "signature appended to the payload: the kernel embeds it and checks it again when launching the shell"

# --- 4. Kernel ---------------------------------------------------------------------------------------
stage "Microkernel (bare metal)" \
    "Built AFTER the shell because it embeds it. The ELF is checked before signing:" \
    "no segment may be writable and executable at once (W^X), or the bootloader would reject it."
t=$SECONDS
run kernel cargo build --release -p trunomy-kernel --target x86_64-unknown-none
built "kernel" kernel "$t"
KERNEL_DIR=target/x86_64-unknown-none/release
KERNEL_ELF="$KERNEL_DIR/kernel_x86_64.elf"; KERNEL_SIG="$KERNEL_ELF.sig"
cp "$KERNEL_DIR/trunomy-kernel" "$KERNEL_ELF"
if readelf -lW "$KERNEL_ELF" | awk '$1=="LOAD" {f=""; for(i=7;i<NF;i++) f=f $i; if (f ~ /W/ && f ~ /E/) bad=1} END{exit !bad}'; then
    readelf -lW "$KERNEL_ELF" | grep LOAD >&2
    die "the kernel has a PT_LOAD segment that is both writable AND executable (RWE)"
fi
ok "PT_LOAD segments without RWE (W^X)"
# Version de seguridad (I-49): un entero que se sube a proposito al publicar una correccion. Va DENTRO del mensaje
# firmado (dominio || version u64 little endian || ELF), de modo que un kernel viejo no puede hacerse pasar por
# nuevo ni al reves, y el bootloader se niega a arrancar uno menor que el mayor ya aceptado.
SECURITY_VERSION="$(tr -d '[:space:]' < config/security-version 2>/dev/null)"
case "$SECURITY_VERSION" in ''|*[!0-9]*|0) die "config/security-version must be a positive integer (it is '$SECURITY_VERSION')" ;; esac
[ "${#SECURITY_VERSION}" -le 18 ] || die "config/security-version is too large"
KERNEL_VER="$KERNEL_ELF.ver"; KERNEL_MSG="$KERNEL_ELF.msg"
scripts/kernel-message.sh "$SECURITY_VERSION" "$KERNEL_ELF" "$KERNEL_VER" "$KERNEL_MSG" || die "could not build the signed kernel message"
openssl pkeyutl -sign -rawin -inkey "$KERNEL_PRIVATE_KEY" -in "$KERNEL_MSG" -out "$KERNEL_SIG"
[ "$(size "$KERNEL_SIG")" -eq 64 ] || die "the kernel signature is not 64 bytes"
openssl pkeyutl -verify -rawin -pubin -inkey "$KERNEL_PUBLIC_KEY" -in "$KERNEL_MSG" -sigfile "$KERNEL_SIG" >/dev/null \
    || die "the kernel signature does not verify with its public key"
rm -f "$KERNEL_MSG"
ok "kernel signed and verified, security version $SECURITY_VERSION ($(size "$KERNEL_ELF") bytes, sha256 $(short "$KERNEL_ELF")...)"

# --- 5. Imagen ---------------------------------------------------------------------------------------
stage "Disk image (trunomy.img)" \
    "A 64 MiB FAT32 partition laid out the way UEFI firmware knows how to boot:" \
    "/EFI/BOOT/BOOTX64.EFI is the bootloader; /system holds the kernel, the shell and their signatures."
export MTOOLS_SKIP_CHECK=1
rm -f trunomy.img
dd if=/dev/zero of=trunomy.img bs=1M count=64 status=none
mkfs.vfat -F 32 trunomy.img >/dev/null
for d in EFI EFI/BOOT system; do mmd -i trunomy.img "::/$d"; done
mcopy -i trunomy.img "$BOOTLOADER"  ::/EFI/BOOT/BOOTX64.EFI
mcopy -i trunomy.img "$KERNEL_ELF"  ::/system/kernel_x86_64.elf
mcopy -i trunomy.img "$KERNEL_SIG"  ::/system/kernel_x86_64.elf.sig
mcopy -i trunomy.img "$KERNEL_VER"  ::/system/kernel_x86_64.elf.ver
mcopy -i trunomy.img "$SHELL_BIN"   ::/system/shell.bin
mcopy -i trunomy.img "$SHELL_SIG"   ::/system/shell.bin.sig
ok "image written: $(mdir -b -i trunomy.img ::/system 2>/dev/null | wc -l) files in /system"

# --- 6. Resumen --------------------------------------------------------------------------------------
stage "Summary"
printf '      %-34s %10s  %s\n' ARTIFACT BYTES SHA256
for f in "$BOOTLOADER" "$KERNEL_ELF" "$SHELL_BIN" trunomy.img; do
    printf '      %-34s %10s  %s...\n' "$(basename "$f")" "$(size "$f")" "$(short "$f")"
done
echo
printf '%s====================================================%s\n' "$G" "$Z"
printf '%s  Done in %ss%s\n' "$G" "$((SECONDS - T0))" "$Z"
printf '%s====================================================%s\n' "$G" "$Z"
cat <<EOF
  Chain of trust:   firmware -> bootloader -> kernel (signature) -> shell (signature)
  Boot:             ./run_os.sh        (leave QEMU: Ctrl-A, then X)
  Once inside:      help   and then   demo
  Reproducibility:  ./scripts/repro-check.sh
EOF
if [ "$RUN" -eq 1 ]; then
    echo
    exec "$ROOT_DIR/run_os.sh"
fi
