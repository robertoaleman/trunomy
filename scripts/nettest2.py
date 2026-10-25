#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

"""Two Trunomy VMs connected to each other: messages from one tenant to another over the network, without TCP/IP.

Each VM is an instance of run_os.sh with `-netdev socket,udp=...`; the two backends point at each other, so every
frame one VM emits reaches the other as a frame (the host script does not see the traffic, it only drives the two
serial consoles). Each VM has its own MAC and boots the image in `-snapshot` mode: they do not step on each other.

    scripts/nettest2.py [--transcript-dir DIR]     # needs trunomy.img (./trunomy build)

What it tests: an actor on VM A sends to a port on VM B and B receives it (and the reverse), with the other end's
MAC shown only as DATA (I-09); a frame for a third MAC does not arrive; without the `net.recv` capability the
receiver is denied; the longest message (128 bytes) arrives intact; 10 messages in a row.
What it does NOT test: real DMA, IOMMU, hardware timing or peer authentication (it does not exist: I-47).
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nettest  # noqa: E402  (mismo directorio: codec, Guest y utilidades)

MAC_A = "52:54:00:12:34:56"
MAC_B = "52:54:00:12:34:58"
THIRD_MAC = "52:54:00:12:34:99"
PORT_RX = 7
PORT_TX = 40001


def exchange(rx, tx, dst_mac, text, rx_port=PORT_RX, tries=6):
    """`rx` escucha un puerto (~1 s) mientras `tx` envia a `dst_mac`; reintenta si el envio cayo fuera de la
    ventana (el receptor no avisa cuando empieza a escuchar). Devuelve lo que imprimio el receptor."""
    out = ""
    for _ in range(tries):
        box = []
        t = threading.Thread(target=lambda: box.append(rx.run("net listen %d" % rx_port)))
        t.start()
        time.sleep(0.25)  # el worker del receptor tarda en ligar el puerto
        tx.run("net send %d %s %d %s" % (PORT_TX, dst_mac, rx_port, text))
        t.join()
        out = box[0]
        if text in out:
            break
    return out


def drain(g, port=PORT_RX):
    """Vacia lo pendiente en el anillo de recepcion para que el siguiente escenario parta de cero."""
    for _ in range(12):
        if "nothing arrived" in g.run("net listen %d" % port):
            return


def prepare(g):
    g.wait_prompt(120)
    g.run("net up", 30)
    g.run("tenant create lab")
    g.run("user create nora lab net")
    g.run("user create omar lab")


def scenarios(a, b):
    results = []

    def check(name, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else "  -> " + detail))
        results.append(cond)

    threads = [threading.Thread(target=prepare, args=(g,)) for g in (a, b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("both VMs have the network active", "ACTIVE" in a.run("net info") and "ACTIVE" in b.run("net info"))
    check("with different MACs", MAC_A in a.run("net info") and MAC_B in b.run("net info"))

    a.run("su nora")
    b.run("su nora")

    out = exchange(b, a, MAC_B, "hola de A")
    check("A -> B: the message arrives", "port %d: hola de A" % PORT_TX in out, out)
    check("B sees A's MAC only as data", "from %s" % MAC_A in out, out)

    out = exchange(a, b, MAC_A, "respuesta de B", rx_port=PORT_RX)
    check("B -> A: the reply arrives", "port %d: respuesta de B" % PORT_TX in out, out)
    check("A sees B's MAC", "from %s" % MAC_B in out, out)

    text = "x" * 120 + "FIN-8bytes"[:8]
    out = exchange(b, a, MAC_B, text)
    check("128 bytes arrive intact", text in out, out)

    # una trama para una tercera MAC no llega al receptor
    box = []
    t = threading.Thread(target=lambda: box.append(b.run("net listen %d" % PORT_RX)))
    t.start()
    time.sleep(0.25)
    a.run("net send %d %s %d perdido" % (PORT_TX, THIRD_MAC, PORT_RX))
    t.join()
    check("a frame for another MAC is not delivered", "perdido" not in box[0] and "nothing arrived" in box[0], box[0])
    drain(b)

    # sin net.recv el receptor es denegado y el emisor sin net.send tambien
    b.run("su omar")
    out = b.run("net listen %d" % PORT_RX)
    check("without net.recv the receiver is denied", "denied" in out, out)
    a.run("su omar")
    out = a.run("net send %d %s %d intruso" % (PORT_TX, MAC_B, PORT_RX))
    check("without net.send the sender is denied", "denied" in out, out)
    a.run("su nora")
    b.run("su nora")
    drain(b)

    # varios mensajes seguidos, todos distintos
    got = 0
    for i in range(10):
        msg = "msg-%02d" % i
        if msg in exchange(b, a, MAC_B, msg):
            got += 1
    check("10 messages in a row arrive (%d/10)" % got, got == 10)

    # el kernel de B sigue sano
    b.run("su root")
    out = b.run("net stats")
    check("B's queues stay healthy", "queues ok" in out, out)
    a.run("su root")
    out = a.run("net stats")
    check("A's queues stay healthy", "queues ok" in out, out)

    for g in (a, b):
        g.run("net down")
    return all(results)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript-dir", help="save everything the VM printed here")
    args = ap.parse_args()

    pa, pb = nettest.free_udp_port(), nettest.free_udp_port()
    # A recibe en pa y envia a pb; B al reves.
    a = nettest.Guest(0, 0, netdev="socket,udp=127.0.0.1:%d,localaddr=127.0.0.1:%d" % (pb, pa),
                      extra_env={"NETMAC": MAC_A, "SNAPSHOT": "1"})
    b = nettest.Guest(0, 0, netdev="socket,udp=127.0.0.1:%d,localaddr=127.0.0.1:%d" % (pa, pb),
                      extra_env={"NETMAC": MAC_B, "SNAPSHOT": "1"})
    ok = False
    try:
        ok = scenarios(a, b)
    except (TimeoutError, RuntimeError) as e:
        print("  FAIL a VM did not respond: %s" % e)
    finally:
        if args.transcript_dir:
            os.makedirs(args.transcript_dir, exist_ok=True)
            for name, g in (("vm-a.log", a), ("vm-b.log", b)):
                with open(os.path.join(args.transcript_dir, name), "wb") as f:
                    f.write(bytes(g.transcript))
        a.close()
        b.close()
    print("nettest2: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
