#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

"""Kernel rollback protection (I-49) in QEMU: a signed but OLD kernel does not boot.

With a real NVRAM (persistent OVMF_VARS) it boots the image in five scenarios:
  1. kernel with version N+1, fresh NVRAM         -> boots and the bootloader stores N+1
  2. kernel with version N (the one in trunomy.img) -> REJECTED: a valid kernel, but older than the minimum
  3. kernel N+1 with an edited .ver, not re-signed -> rejected by the signature, and the counter does NOT go up
  4. kernel N+1 again                             -> boots (the earlier rejection did not brick the machine)
  5. kernel N with the NVRAM RESTORED to fresh    -> boots: the honest limit, whoever can write the NVRAM wipes it

    scripts/rollbacktest.py [--vars-template OVMF_VARS.fd]     # needs trunomy.img and .keys/ (./trunomy build)

Needs mtools (mcopy), openssl and the OVMF_VARS.fd from the SAME package as OVMF_CODE.fd. It works on copies:
it does not touch trunomy.img. It does not use -snapshot (that would discard the writes to the NVRAM).
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nettest  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOOT_TIMEOUT = 240
OK_PATTERNS = [b"] > ", b"ROLLBACK REJECTED", b"INVALID KERNEL SIGNATURE"]


def find_vars_template(explicit):
    if explicit:
        return explicit
    codes = [os.environ.get("OVMF_CODE", ""), "/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_CODE.fd",
             "/usr/share/edk2/x64/OVMF_CODE.fd", "/usr/share/qemu/OVMF_CODE.fd", os.path.join(ROOT, "OVMF_CODE.fd")]
    for code in codes:
        if code and os.path.isfile(code):
            d, name = os.path.split(code)
            cand = os.path.join(d, name.replace("CODE", "VARS"))
            if os.path.isfile(cand):
                return cand
    for pat in ("/usr/share/edk2/ovmf/OVMF_VARS*.fd", "/usr/share/OVMF/OVMF_VARS*.fd"):
        found = sorted(glob.glob(pat))
        if found:
            return found[0]
    return None


def mtools(*args):
    env = dict(os.environ, MTOOLS_SKIP_CHECK="1")
    subprocess.run(["mcopy", *args], check=True, env=env, stdout=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vars-template", help="OVMF_VARS.fd from the same package as OVMF_CODE.fd")
    ap.add_argument("--image", default=os.path.join(ROOT, "trunomy.img"))
    args = ap.parse_args()

    template = find_vars_template(args.vars_template)
    key = os.path.join(ROOT, ".keys", "kernel-ed25519-private.pem")
    for what, path in (("image", args.image), ("kernel private key", key), ("OVMF_VARS.fd (--vars-template)", template)):
        if not path or not os.path.isfile(path):
            print("[ERROR] missing %s: %s" % (what, path))
            return 2
    for tool in ("mcopy", "openssl"):
        if not shutil.which(tool):
            print("[ERROR] missing %s" % tool)
            return 2

    work = tempfile.mkdtemp(prefix="trunomy-rollback-")
    results = []

    def check(name, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else "  -> " + detail))
        results.append(cond)

    try:
        old_img = os.path.join(work, "old.img")
        new_img = os.path.join(work, "new.img")
        bad_img = os.path.join(work, "tampered.img")
        for dst in (old_img, new_img, bad_img):
            shutil.copy(args.image, dst)

        # version N de la imagen actual y el ELF, sacados de la propia imagen
        elf, ver = os.path.join(work, "k.elf"), os.path.join(work, "k.ver")
        mtools("-i", old_img, "::/system/kernel_x86_64.elf", elf)
        mtools("-i", old_img, "::/system/kernel_x86_64.elf.ver", ver)
        n = int.from_bytes(open(ver, "rb").read(), "little")
        print("current image: security version %d; %d will be used as the 'new' one" % (n, n + 1))

        # imagen "nueva": misma ELF, version N+1, firmada igual que build_os.sh
        subprocess.run([os.path.join(ROOT, "scripts", "kernel-message.sh"), str(n + 1), elf,
                        os.path.join(work, "n.ver"), os.path.join(work, "n.msg")], check=True)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", os.path.join(work, "n.msg"),
                        "-out", os.path.join(work, "n.sig")], check=True)
        mtools("-o", "-i", new_img, os.path.join(work, "n.ver"), "::/system/kernel_x86_64.elf.ver")
        mtools("-o", "-i", new_img, os.path.join(work, "n.sig"), "::/system/kernel_x86_64.elf.sig")
        # imagen manipulada: .ver subido a N+5 SIN re-firmar (la firma es la de N+1)
        mtools("-o", "-i", bad_img, os.path.join(work, "n.sig"), "::/system/kernel_x86_64.elf.sig")
        with open(os.path.join(work, "t.ver"), "wb") as f:
            f.write((n + 5).to_bytes(8, "little"))
        mtools("-o", "-i", bad_img, os.path.join(work, "t.ver"), "::/system/kernel_x86_64.elf.ver")

        vars_file = os.path.join(work, "vars.fd")
        shutil.copy(template, vars_file)

        def boot(img, vars_path):
            g = nettest.Guest(0, 0, extra_env={"NET": "0", "IMG": img, "OVMF_VARS": vars_path})
            try:
                first = g.wait_any(OK_PATTERNS, BOOT_TIMEOUT)
                return first, g.text()
            finally:
                g.close()

        first, log = boot(new_img, vars_file)
        check("1. kernel N+1 with a fresh NVRAM boots", first == b"] > ", log[-300:])
        check("   and the bootloader stores N+1", "minimum accepted = %d (stored in NVRAM)" % (n + 1) in log, log[-600:])

        first, log = boot(old_img, vars_file)
        check("2. kernel N (valid, signed) is REJECTED", first == b"ROLLBACK REJECTED", log[-300:])
        check("   with the reason", ("security version %d < minimum accepted %d" % (n, n + 1)) in log, log[-400:])
        check("   and the shell never starts", "] > " not in log)

        first, log = boot(bad_img, vars_file)
        check("3. edited .ver without re-signing: invalid signature", first == b"INVALID KERNEL SIGNATURE", log[-300:])

        first, log = boot(new_img, vars_file)
        check("4. kernel N+1 still boots", first == b"] > ", log[-300:])
        check("   and the fake .ver did not raise the counter (previous minimum N+1)",
              ("previous minimum: Some(%d)" % (n + 1)) in log, log[-600:])

        shutil.copy(template, vars_file)  # NVRAM restaurada: lo que hace quien la puede escribir
        first, log = boot(old_img, vars_file)
        check("5. with the NVRAM wiped, kernel N boots (limit documented in I-49)", first == b"] > ", log[-300:])
    except (TimeoutError, RuntimeError, subprocess.CalledProcessError) as e:
        print("  FAIL %s" % e)
        results.append(False)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    ok = bool(results) and all(results)
    print("rollbacktest: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
