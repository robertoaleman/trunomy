// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Interoperabilidad con la herramienta real de firma de `build_os.sh`
//! (`openssl pkeyutl -sign -rawin`): la verificacion estricta debe aceptar sus firmas.
//! Se omite (con aviso) si `openssl` no esta instalado.

use std::path::PathBuf;
use std::process::Command;
use trunomy_bootcore::sig::{verify_appended, verify_detached};

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().map(|o| o.status.success()).unwrap_or(false)
}

fn run(args: &[&str]) -> bool {
    Command::new("openssl").args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

#[test]
fn strict_verifier_accepts_openssl_signatures_and_the_raw_public_key() {
    if !have_openssl() {
        eprintln!("openssl no disponible: prueba omitida");
        return;
    }
    let dir: PathBuf = std::env::temp_dir().join(format!("trunomy-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).to_string_lossy().into_owned();

    assert!(run(&["genpkey", "-algorithm", "ed25519", "-out", &p("priv.pem")]));
    assert!(run(&["pkey", "-in", &p("priv.pem"), "-pubout", "-out", &p("pub.pem")]));
    // Clave publica cruda = ultimos 32 bytes del DER (como hace build_os.sh).
    assert!(run(&["pkey", "-pubin", "-in", &p("pub.pem"), "-outform", "DER", "-out", &p("pub.der")]));
    let der = std::fs::read(dir.join("pub.der")).unwrap();
    let key: [u8; 32] = der[der.len() - 32..].try_into().unwrap();

    let payload: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
    std::fs::write(dir.join("img.bin"), &payload).unwrap();
    assert!(run(&["pkeyutl", "-sign", "-rawin", "-inkey", &p("priv.pem"), "-in", &p("img.bin"), "-out", &p("img.sig")]));
    let sig = std::fs::read(dir.join("img.sig")).unwrap();
    assert_eq!(sig.len(), 64);

    assert_eq!(verify_detached(&payload, &sig, &key), Ok(()));

    // Mismo empaquetado que shell.bin: payload || firma.
    let mut blob = payload.clone();
    blob.extend_from_slice(&sig);
    assert_eq!(verify_appended(&blob, &key), Ok(&payload[..]));

    let mut bad = payload.clone();
    bad[100] ^= 1;
    assert!(verify_detached(&bad, &sig, &key).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// El camino REAL de `build_os.sh`: `scripts/kernel-message.sh` arma el `.ver` y el mensaje, openssl firma el
/// mensaje, y `check_kernel` (el codigo del bootloader) lo acepta, rechaza el rollback y rechaza cualquier
/// edicion de la version. Si el script y `bootcore::rollback::signed_message` se separaran, esto falla.
#[test]
fn the_real_build_script_message_verifies_with_the_bootloader_logic() {
    use trunomy_bootcore::rollback::{check_kernel, Decision, RollbackError};
    if !have_openssl() {
        eprintln!("openssl no disponible: prueba omitida");
        return;
    }
    let script: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/kernel-message.sh");
    let dir: PathBuf = std::env::temp_dir().join(format!("trunomy-rollback-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).to_string_lossy().into_owned();

    assert!(run(&["genpkey", "-algorithm", "ed25519", "-out", &p("priv.pem")]));
    assert!(run(&["pkey", "-in", &p("priv.pem"), "-pubout", "-out", &p("pub.pem")]));
    assert!(run(&["pkey", "-pubin", "-in", &p("pub.pem"), "-outform", "DER", "-out", &p("pub.der")]));
    let der = std::fs::read(dir.join("pub.der")).unwrap();
    let key: [u8; 32] = der[der.len() - 32..].try_into().unwrap();

    let elf: Vec<u8> = (0..6000u32).map(|i| (i * 13 + 1) as u8).collect();
    std::fs::write(dir.join("k.elf"), &elf).unwrap();

    // Firma el kernel con una version dada, igual que build_os.sh; devuelve (.ver, firma)
    let sign_with = |version: &str| -> (Vec<u8>, Vec<u8>) {
        let ok = Command::new("bash")
            .args([script.to_str().unwrap(), version, &p("k.elf"), &p("k.ver"), &p("k.msg")])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kernel-message.sh {version}");
        assert!(run(&["pkeyutl", "-sign", "-rawin", "-inkey", &p("priv.pem"), "-in", &p("k.msg"), "-out", &p("k.sig")]));
        (std::fs::read(dir.join("k.ver")).unwrap(), std::fs::read(dir.join("k.sig")).unwrap())
    };

    let (ver2, sig2) = sign_with("2");
    assert_eq!(ver2, 2u64.to_le_bytes());
    assert_eq!(check_kernel(&elf, &sig2, &ver2, &key, None), Ok((2, Decision::Accept { ratchet: Some(2) })));
    assert_eq!(check_kernel(&elf, &sig2, &ver2, &key, Some(2)), Ok((2, Decision::Accept { ratchet: None })));
    assert_eq!(
        check_kernel(&elf, &sig2, &ver2, &key, Some(3)),
        Err(RollbackError::Rollback { version: 2, minimum: 3 }),
        "un kernel viejo con firma valida se rechaza"
    );
    // editar el .ver (subirlo para pasar el minimo) rompe la firma
    let forged = 9u64.to_le_bytes();
    assert!(matches!(check_kernel(&elf, &sig2, &forged, &key, Some(3)), Err(RollbackError::Signature(_))));
    // y una version grande (varios bytes) se codifica en little endian
    let (ver_big, sig_big) = sign_with("258");
    assert_eq!(ver_big, [2, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(check_kernel(&elf, &sig_big, &ver_big, &key, Some(2)), Ok((258, Decision::Accept { ratchet: Some(258) })));
    // el script rechaza versiones que no son enteros positivos
    for bad in ["0", "-1", "1.5", "abc", ""] {
        let st = Command::new("bash")
            .args([script.to_str().unwrap(), bad, &p("k.elf"), &p("k.ver"), &p("k.msg")])
            .output()
            .unwrap();
        assert!(!st.status.success(), "version '{bad}' debe rechazarse");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
