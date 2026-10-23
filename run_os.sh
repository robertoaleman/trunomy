#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Arranca trunomy.img en QEMU con OVMF (UEFI). Detecta QEMU y OVMF en las distros habituales; se pueden
# forzar con QEMU=/ruta/qemu y OVMF_CODE=/ruta/OVMF_CODE.fd. Sin KVM accesible usa emulacion.
cd "$(dirname "$0")"

QEMU_BIN=""
for c in "${QEMU:-}" /usr/libexec/qemu-kvm qemu-system-x86_64 qemu-kvm; do
    [ -n "$c" ] || continue
    if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then QEMU_BIN="$c"; break; fi
done
[ -n "$QEMU_BIN" ] || { echo "[ERROR] cannot find QEMU (dnf install qemu-kvm | apt install qemu-system-x86; or QEMU=/path)"; exit 1; }

OVMF=""
for f in "${OVMF_CODE:-}" /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/x64/OVMF_CODE.fd /usr/share/qemu/OVMF_CODE.fd ./OVMF_CODE.fd; do
    [ -n "$f" ] && [ -f "$f" ] && { OVMF="$f"; break; }
done
[ -n "$OVMF" ] || { echo "[ERROR] cannot find OVMF_CODE.fd (dnf install edk2-ovmf | apt install ovmf; or OVMF_CODE=/path)"; exit 1; }
IMG="${IMG:-trunomy.img}"
[ -f "$IMG" ] || { echo "[ERROR] $IMG does not exist: run ./build_os.sh"; exit 1; }

ARGS=(-machine q35 -cpu max)
# qemu-kvm ya habilita KVM; con qemu-system-x86_64 se pide solo si /dev/kvm es usable.
case "$QEMU_BIN" in *qemu-kvm) ;; *) [ -w /dev/kvm ] && ARGS+=(-enable-kvm) ;; esac
[ -d /usr/share/qemu ] && ARGS+=(-L /usr/share/qemu)

echo "===================================================="
echo "  Starting Trunomy OS in QEMU...                    "
echo "  QEMU: $QEMU_BIN | OVMF: $OVMF"
echo "  Quit: Ctrl-A then X   |   Inside: help, demo"
echo "===================================================="

# Red (I-44): un virtio-net legacy aislado (restrict=on: el invitado no alcanza la red del host).
# El kernel solo habla virtio legacy por puertos de E/S, de ahi disable-modern=on. NET=0 la quita.
# NETDEV="socket,udp=127.0.0.1:P1,localaddr=127.0.0.1:P2" sustituye el backend (lo usan scripts/nettest*.py para
# hablar tramas reales con el invitado: un script del host o una segunda VM); sin el, el invitado no alcanza nada
# fuera de QEMU. NETMAC=52:54:00:12:34:58 cambia la MAC del dispositivo (dos VMs en un mismo enlace necesitan MAC
# distintas). SNAPSHOT=1 no escribe la imagen (varias VMs pueden compartir trunomy.img sin pisarse).
NETDEVICE="virtio-net-pci,netdev=n0,disable-modern=on,disable-legacy=off,romfile="
[ -n "${NETMAC:-}" ] && NETDEVICE="$NETDEVICE,mac=$NETMAC"
if [ "${NET:-1}" = "0" ]; then
    NETARGS=(-net none)
elif [ -n "${NETDEV:-}" ]; then
    NETARGS=(-netdev "$NETDEV,id=n0" -device "$NETDEVICE")
else
    NETARGS=(-netdev user,id=n0,restrict=on -device "$NETDEVICE")
fi
[ "${SNAPSHOT:-0}" = "1" ] && ARGS+=(-snapshot)

# NVRAM persistente (I-49): el contador anti-rollback del kernel vive en una variable UEFI. Sin OVMF_VARS el
# firmware de QEMU guarda las variables solo en RAM y el contador no sobrevive al apagado (en hardware real el
# NVRAM si persiste). OVMF_VARS=/ruta/vars.fd es una COPIA de OVMF_VARS.fd del mismo paquete que OVMF_CODE.fd
# (se modifica): scripts/rollbacktest.py la prepara. IMG=otra.img arranca otra imagen.
VARSARGS=()
if [ -n "${OVMF_VARS:-}" ]; then
    [ -f "$OVMF_VARS" ] || { echo "[ERROR] OVMF_VARS=$OVMF_VARS does not exist"; exit 1; }
    VARSARGS=(-drive if=pflash,format=raw,unit=1,file="$OVMF_VARS")
fi

# Mapeo por bloques pflash para evadir restricciones heredadas de BIOS
exec "$QEMU_BIN" "${ARGS[@]}" \
    -drive if=pflash,format=raw,unit=0,file="$OVMF",readonly=on \
    "${VARSARGS[@]}" \
    -drive file="$IMG",format=raw,if=ide \
    "${NETARGS[@]}" \
    -nographic
