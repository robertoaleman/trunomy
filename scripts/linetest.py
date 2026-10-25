#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

"""The console line editor (I-50) in QEMU: the cursor stays on the line and the history works.

Boots ONE VM (no network, image in -snapshot mode; rebuild the image first with ./trunomy build) and types for
real, byte by byte, like a terminal: arrow keys (`ESC [ D`), backspace on an empty line, Ctrl-C and the history
up/down arrows. It checks what the terminal would receive: no ESC in the echo, no stray backspace, and that
recalled commands run.

    scripts/linetest.py [--transcript FILE]     # needs trunomy.img (./trunomy build)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nettest  # noqa: E402

LEFT, RIGHT, UP, DOWN = b"\x1b[D", b"\x1b[C", b"\x1b[A", b"\x1b[B"


def keys(g, data, timeout=20):
    """Teclea bytes crudos y devuelve lo que imprimio la VM hasta el siguiente prompt (eco incluido)."""
    g.proc.stdin.write(data)
    g.proc.stdin.flush()
    return g.wait_prompt(timeout)


def lines_of(out):
    return [l.strip("\r") for l in out.split("\n")]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript", help="save everything the VM printed here")
    args = ap.parse_args()

    g = nettest.Guest(0, 0, extra_env={"NET": "0", "SNAPSHOT": "1"})
    results = []

    def check(name, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else "  -> " + repr(detail)))
        results.append(cond)

    try:
        g.wait_prompt(120)

        out = keys(g, b"echo abc" + LEFT * 3 + RIGHT + b"X\r")
        check("arrow keys move nothing: typing always goes at the end", "abcX" in lines_of(out), out)
        check("and no escape sequence reaches the terminal", "\x1b" not in out, out)

        out = keys(g, b"\x7f\x7f\x08echo ok\r")
        check("backspace on an empty line does nothing", "\x08" not in out and "ok" in lines_of(out), out)

        out = keys(g, b"abc\x03")
        check("Ctrl-C cancels the line and returns to the prompt", "^C" in out, out)

        out = keys(g, b"echo xyz\x15echo borrada\r")
        check("Ctrl-U erases the line", "borrada" in lines_of(out) and "xyz" not in lines_of(out), out)

        keys(g, b"echo uno\r")
        keys(g, b"echo dos\r")
        out = keys(g, UP + b"\r")
        check("up arrow recalls the last command", "dos" in lines_of(out) and "uno" not in lines_of(out), out)
        out = keys(g, UP + UP + b"\r")
        check("twice, the one before", "uno" in lines_of(out) and "dos" not in lines_of(out), out)
        out = keys(g, UP + UP + DOWN + b"\r")
        check("down arrow goes back to a more recent command", "uno" in lines_of(out) and "dos" not in lines_of(out), out)
        out = keys(g, UP + DOWN + b"echo nueva\r")
        check("down past the most recent leaves the line empty", "nueva" in lines_of(out), out)

        out = keys(g, UP + b"\x7f" * 5 + b"editada\r")
        check("a recalled command can be edited before running it", "editada" in lines_of(out), out)

        out = keys(g, b"whoami\r")
        check("the shell keeps responding", "name: root" in out, out)
    except (TimeoutError, RuntimeError) as e:
        print("  FAIL the VM did not respond: %s" % e)
        results.append(False)
    finally:
        if args.transcript:
            with open(args.transcript, "wb") as f:
                f.write(bytes(g.transcript))
        g.close()
    ok = bool(results) and all(results)
    print("linetest: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
