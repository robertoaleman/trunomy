#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

# Fija el toolchain de Rust en rust-toolchain.toml (reproducibilidad). Ejecutar UNA vez, en la
# maquina donde el sistema ya compila y arranca, y commitear el archivo: cualquier otra maquina
# (y el CI) usara exactamente esa version de rustc, no "la ultima estable".
#   ./scripts/pin-toolchain.sh            fija la version de rustc activa
#   ./scripts/pin-toolchain.sh 1.97.0     fija una version concreta
# Solo acepta versiones estables exactas (X.Y.Z): ni nightly, ni beta, ni "stable".
set -euo pipefail
cd "$(dirname "$0")/.."

VER="${1:-}"
if [ -z "$VER" ]; then
    # El archivo existente fijaria otra version: se mira la del compilador por defecto del sistema.
    VER=$(cd /tmp && rustc --version | awk '{print $2}')
fi
if ! printf '%s' "$VER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "[ERROR] '$VER' is not an exact stable version (X.Y.Z). Install one with: rustup toolchain install 1.97.0" >&2
    exit 1
fi

cat > rust-toolchain.toml <<EOF
# Toolchain fijado: reproducibilidad (scripts/pin-toolchain.sh). Cambiarlo es una decision explicita:
# se hace con el script, se corre ./scripts/ci.sh all y se commitea junto con lo que cambie.
[toolchain]
channel = "$VER"
profile = "minimal"
targets = ["x86_64-unknown-none", "x86_64-unknown-uefi"]
EOF
echo "[OK] rust-toolchain.toml -> rustc $VER. Commit it: git add rust-toolchain.toml"
