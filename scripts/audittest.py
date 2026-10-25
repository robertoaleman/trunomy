#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

"""A user who repeats denials cannot fill or wipe the audit log (I-41, I-48), in QEMU.

Boots ONE VM (no network, image in -snapshot mode; rebuild the image first with ./trunomy build) and, as an
unprivileged user, repeats `halt` 40 times and `selftest console` 10 times (which also tries Halt: 50 attempts).
Then, as root, it reads `audit` and checks that: the machine is still alive, only a bounded number of denied
`halt`/`console` records exist (not 50), and the earlier history (the allowed `cap grant`) is still there. The total
counters are not visible from the shell: the kernel tests (`audit::tests`) cover those; this confirms the real
dispatcher path.

    scripts/audittest.py [--transcript FILE]     # needs trunomy.img (./trunomy build)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nettest  # noqa: E402

HALT_BURST = 16      # audit.rs: HALT_BURST
CONSOLE_MAX = 2 * 4  # audit.rs: DENIAL_BURST por (sujeto, syscall): ConsoleRead y ConsoleWrite


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript", help="save everything the VM printed here")
    args = ap.parse_args()

    g = nettest.Guest(0, 0, extra_env={"NET": "0", "SNAPSHOT": "1"})
    results = []

    def check(name, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else "  -> " + detail))
        results.append(cond)

    try:
        g.wait_prompt(120)
        for cmd in ("tenant create acme", "user create alice acme", "user create bob acme",
                    "su alice", "object create secret hola", "cap grant bob secret read", "su bob"):
            g.run(cmd)
        halts = [g.run("halt") for _ in range(40)]
        check("every halt by a user is denied", all("denied" in h for h in halts), halts[-1])
        consoles = [g.run("selftest console") for _ in range(10)]
        check("selftest console is denied and the machine stays alive", all("denied" in c for c in consoles), consoles[-1])
        g.run("su root")
        out = g.run("audit", 60)
        lines = out.split("\n")
        n_halt = sum(1 for l in lines if "halt -> DENIED" in l)
        n_console = sum(1 for l in lines if "console -> DENIED" in l)
        check("denied halts are recorded (%d)" % n_halt, n_halt >= 1)
        # 40 `halt` + 10 `selftest console` (que tambien intenta Halt) = 50 intentos: con 50 registros no hubo limite.
        check("but bounded: %d <= %d of 50 attempts" % (n_halt, HALT_BURST), n_halt <= HALT_BURST,
              "50 records = no limit: the image predates patch 65 (I-48); "
              "`git am` and `ci.sh all` do not regenerate trunomy.img, run ./trunomy build and repeat")
        check("denied console attempts are bounded (%d <= %d of 10)" % (n_console, CONSOLE_MAX),
              1 <= n_console <= CONSOLE_MAX)
        check("the earlier history is intact (allowed cap grant)",
              any("-> allowed" in l and ("grant" in l or "delegate" in l) for l in lines))
        check("the shell responds after the burst", g.run("whoami").strip() != "")
    except (TimeoutError, RuntimeError) as e:
        print("  FAIL the VM did not respond: %s" % e)
        results.append(False)
    finally:
        if args.transcript:
            with open(args.transcript, "wb") as f:
                f.write(bytes(g.transcript))
        g.close()
    ok = bool(results) and all(results)
    print("audittest: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
