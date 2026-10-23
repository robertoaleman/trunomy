// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let linker_script = manifest_dir.join("linker.ld");

    println!("cargo:rustc-link-arg=-T{}", linker_script.display());

    // Igual que el kernel: sin PIE no hay GOT que reubicar en el binario plano.
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");
    println!("cargo:rustc-link-arg=-znorelro");

    println!("cargo:rerun-if-changed=linker.ld");
}
