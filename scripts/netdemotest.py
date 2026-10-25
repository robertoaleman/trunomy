#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

"""The shell's `net demo` runs from start to finish and shows what it says it shows, in QEMU.

Boots ONE VM (QEMU user-mode network, image in -snapshot mode; rebuild the image first with ./trunomy build),
runs `net demo` as root and checks the output: network active, real ARP against the gateway, nora's message
coming back through the kernel, frame to the network accepted, omar denied on send and receive, and those denials
in `audit`. Then it repeats the demo to check that it can run twice in a row.

    scripts/netdemotest.py [--transcript FILE]     # needs trunomy.img (./trunomy build)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nettest  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript", help="save everything the VM printed here")
    args = ap.parse_args()

    # Red de usuario de QEMU (gateway 10.0.2.2), igual que el valor por defecto de run_os.sh (el Guest agrega el id).
    g = nettest.Guest(0, 0, netdev="user,restrict=on", extra_env={"SNAPSHOT": "1"})
    results = []

    def check(name, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else "  -> " + detail))
        results.append(cond)

    try:
        g.wait_prompt(120)
        out = g.run("net demo", 120)
        stale = "net: unknown" in out or "usage: net" in out
        check("the shell knows `net demo`", not stale,
              "the image predates patch 72: run ./trunomy build and repeat")
        if stale:
            raise RuntimeError("image without net demo")
        check("1. the network comes up", "net up: ok" in out and "ACTIVE" in out, out[:400])
        check("2. real ARP against the gateway", "net selftest: OK" in out, out)
        check("3. nora and omar are created in netlab", "user nora" in out and "user omar" in out, out)
        check("3. `tenant list` is a table with its headers",
              "| Tenant ID" in out and "| Entity (Role / User)" in out and "| PID" in out
              and "| Permissions / Capabilities" in out, out)
        nora = [l for l in out.split("\n") if l.startswith("|") and " nora " in l]
        check("3. nora's row shows her tenant and pid", len(nora) == 1 and "netlab" in nora[0], out)
        check("4. nora's message comes back through the kernel", "hello-from-nora" in out, out)
        check("5. the frame to the network is accepted by the NIC", "net send: ok" in out, out)
        denied = [l for l in out.split("\n") if l.startswith("denied")]
        check("6. omar is denied on send and listen (%d)" % len(denied), len(denied) >= 2, out)
        check("7. the queues stay healthy", "queues ok" in out, out)
        lines = out.split("\n")
        check("7. `audit` shows the network denials",
              any("DENIED" in l and "net" in l for l in lines), out[-600:])
        who = g.run("whoami")
        check("the demo returns the session to root", "name: root" in who, who)
        out2 = g.run("net demo", 120)
        check("it can be repeated (it does not fail on already-created tenant/users)",
              "net selftest: OK" in out2 and "hello-from-nora" in out2 and "unknown" not in out2, out2)
        g.run("net down")
    except (TimeoutError, RuntimeError) as e:
        print("  FAIL %s" % e)
        results.append(False)
    finally:
        if args.transcript:
            with open(args.transcript, "wb") as f:
                f.write(bytes(g.transcript))
        g.close()
    ok = bool(results) and all(results)
    print("netdemotest: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
