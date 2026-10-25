#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Trunomy OS - capability-based microkernel for isolating AI agents
# Copyright (C) 2026 Roberto C. Aleman F.
# https://github.com/robertoaleman/trunomy

"""Trunomy network tests from the host, with real frames (no dependencies, standard library only).

QEMU is started with `-netdev socket,udp=...`: every Ethernet frame the guest emits reaches this script as a UDP
datagram, and every datagram this script sends reaches the guest as a frame. This tests the kernel against a
second, INDEPENDENT implementation of the protocol (`abi/src/netproto.rs`), written here from the specification,
not translated from the Rust code.

    scripts/nettest.py --selftest     # only this script's codec (needs neither QEMU nor an image)
    scripts/nettest.py                # starts ./run_os.sh (needs trunomy.img) and runs the scenarios

What it does NOT test (see docs/invariants.md, I-44): real DMA, IOMMU or hardware timing; QEMU does not model them.
The other end (this script) is unauthenticated data: nothing it sends is taken as identity (I-09).
"""
import argparse
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time

ETHERTYPE = 0x88B5
HEADER_LEN = 24
MAX_PAYLOAD = 256
MIN_FRAME = 60
BROADCAST = b"\xff" * 6
GUEST_MAC = bytes.fromhex("525400123456")
HOST_MAC = bytes.fromhex("525400123457")

# Vector fijo: el MISMO que `golden_vector_matches_the_python_harness` en abi/src/netproto.rs.
GOLDEN_HEX = (
    "525400123457" "525400123456" "88b5"   # MAC destino, MAC origen, EtherType
    "544e" "01" "01" "0007" "0009" "0004"  # magia, version, tipo, puerto origen, puerto destino, largo
    "686f6c61" + "00" * 32                  # "hola" y relleno hasta 60 bytes
)


def build_frame(dst, src, sport, dport, payload):
    if not 1 <= sport <= 0xFFFF or not 1 <= dport <= 0xFFFF:
        raise ValueError("zero port")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too long")
    body = struct.pack(">6s6sHBBBBHHH", dst, src, ETHERTYPE, 0x54, 0x4E, 1, 1, sport, dport, len(payload))
    frame = body + payload
    return frame + b"\x00" * max(0, MIN_FRAME - len(frame))


def parse_frame(frame):
    """Estricto, igual que el kernel: devuelve (dst, src, sport, dport, payload) o lanza ValueError."""
    if len(frame) < HEADER_LEN:
        raise ValueError("too short")
    dst, src, et, m0, m1, ver, kind, sport, dport, ln = struct.unpack(">6s6sHBBBBHHH", frame[:HEADER_LEN])
    if et != ETHERTYPE:
        raise ValueError("ethertype")
    if (m0, m1) != (0x54, 0x4E):
        raise ValueError("magic")
    if ver != 1:
        raise ValueError("version")
    if kind != 1:
        raise ValueError("kind")
    if sport == 0 or dport == 0:
        raise ValueError("zero port")
    if ln > MAX_PAYLOAD:
        raise ValueError("length")
    if HEADER_LEN + ln > len(frame):
        raise ValueError("truncated")
    if any(frame[HEADER_LEN + ln:]):
        raise ValueError("dirty padding")
    return dst, src, sport, dport, frame[HEADER_LEN:HEADER_LEN + ln]


def hostile_frames(to_mac, good_dport):
    """Tramas que el kernel debe descartar sin efecto alguno (cada una rompe UNA regla)."""
    ok = build_frame(to_mac, HOST_MAC, 4242, good_dport, b"x")
    bad = []
    bad.append(b"\x00" * 5)                                           # mas corta que una cabecera
    bad.append(ok[:12] + b"\x08\x00" + ok[14:])                       # otro EtherType
    bad.append(ok[:14] + b"XX" + ok[16:])                             # magia
    bad.append(ok[:16] + b"\x02" + ok[17:])                           # version
    bad.append(ok[:17] + b"\x09" + ok[18:])                           # tipo
    bad.append(ok[:18] + b"\x00\x00" + ok[20:])                       # puerto origen cero
    bad.append(ok[:20] + b"\x00\x00" + ok[22:])                       # puerto destino cero
    bad.append(ok[:22] + struct.pack(">H", MAX_PAYLOAD + 1) + ok[24:])  # largo > maximo
    bad.append(ok[:22] + struct.pack(">H", 40) + ok[24:HEADER_LEN + 1])  # largo > trama
    bad.append(ok[:40] + b"\x01" + ok[41:])                           # relleno distinto de cero
    bad.append(build_frame(HOST_MAC, HOST_MAC, 4242, good_dport, b"x"))  # para otra MAC
    return bad


def selftest():
    failures = []

    def check(name, cond):
        print(("  ok   " if cond else "  FAIL ") + name)
        if not cond:
            failures.append(name)

    golden = bytes.fromhex(GOLDEN_HEX)
    check("the fixed vector is 60 bytes", len(golden) == MIN_FRAME)
    check("build_frame reproduces the fixed vector", build_frame(HOST_MAC, GUEST_MAC, 7, 9, b"hola") == golden)
    check("parse_frame reads the fixed vector", parse_frame(golden) == (HOST_MAC, GUEST_MAC, 7, 9, b"hola"))
    big = bytes(range(256))
    check("maximum payload round trip", parse_frame(build_frame(BROADCAST, GUEST_MAC, 1, 65535, big))[4] == big)
    check("empty payload round trip", parse_frame(build_frame(BROADCAST, GUEST_MAC, 1, 2, b""))[4] == b"")
    for payload_len in (0, 1, 36, 37, 256):
        f = build_frame(BROADCAST, GUEST_MAC, 1, 2, b"a" * payload_len)
        check("frame length %d" % payload_len, len(f) == max(MIN_FRAME, HEADER_LEN + payload_len))
    refused = 0
    for i, f in enumerate(hostile_frames(GUEST_MAC, 40001)[:-1]):  # la ultima solo es hostil por la MAC
        try:
            parse_frame(f)
        except ValueError:
            refused += 1
        else:
            check("hostile frame %d rejected" % i, False)
    check("hostile malformed frames are rejected", refused == len(hostile_frames(GUEST_MAC, 40001)) - 1)
    for bad_ports in ((0, 1), (1, 0)):
        try:
            build_frame(BROADCAST, GUEST_MAC, *bad_ports, b"")
            check("build_frame rejects port zero %r" % (bad_ports,), False)
        except ValueError:
            check("build_frame rejects port zero %r" % (bad_ports,), True)
    try:
        build_frame(BROADCAST, GUEST_MAC, 1, 2, b"a" * (MAX_PAYLOAD + 1))
        check("build_frame rejects payload > maximum", False)
    except ValueError:
        check("build_frame rejects payload > maximum", True)
    print("selftest: %s" % ("FAILED (%d)" % len(failures) if failures else "OK"))
    return not failures


# ---------------------------------------------------------------- QEMU

PROMPT = b"] > "


class Guest:
    """Un invitado Trunomy bajo QEMU, manejado por el puerto serie (stdin/stdout de run_os.sh)."""

    def __init__(self, host_rx_port, qemu_port, extra_env=None, netdev=None):
        env = dict(os.environ)
        env["NET"] = "1"
        env["NETDEV"] = netdev or "socket,udp=127.0.0.1:%d,localaddr=127.0.0.1:%d" % (host_rx_port, qemu_port)
        env.update(extra_env or {})
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.proc = subprocess.Popen([os.path.join(root, "run_os.sh")], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=root)
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.transcript = bytearray()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            chunk = os.read(self.proc.stdout.fileno(), 4096)
            if not chunk:
                return
            with self.lock:
                self.buf += chunk
                self.transcript += chunk

    def wait_prompt(self, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self.lock:
                i = self.buf.find(PROMPT)
                if i >= 0:
                    out = bytes(self.buf[:i + len(PROMPT)])
                    del self.buf[:i + len(PROMPT)]
                    return out.decode("utf-8", "replace")
            if self.proc.poll() is not None:
                raise RuntimeError("QEMU exited")
            time.sleep(0.02)
        raise TimeoutError("no prompt after %.0f s; last text: %r" % (timeout, bytes(self.buf[-300:])))

    def wait_any(self, patterns, timeout):
        """Espera a que aparezca alguno de los `patterns` (bytes) en TODO lo que imprimio la VM desde que
        arranco; devuelve el primero que aparece. Sirve para arranques que terminan en un mensaje de error."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self.lock:
                text = bytes(self.transcript)
            for p in patterns:
                if p in text:
                    return p
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        raise TimeoutError("none of %r after %.0f s; last text: %r" % (patterns, timeout, bytes(self.transcript[-400:])))

    def text(self):
        with self.lock:
            return bytes(self.transcript).decode("utf-8", "replace")

    def run(self, command, timeout=20):
        """Sends a command and returns what it printed (without the echo or the prompt)."""
        self.proc.stdin.write(command.encode() + b"\r")
        self.proc.stdin.flush()
        out = self.wait_prompt(timeout)
        lines = out.replace("\r", "").split("\n")
        # primera linea: eco de la orden; ultima: el prompt (puede venir con el nombre de usuario)
        return "\n".join(lines[1:-1])

    def close(self):
        try:
            self.proc.kill()
        except OSError:
            pass


class Host:
    """El otro extremo: un socket UDP que habla en tramas."""

    def __init__(self, rx_port, qemu_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", rx_port))
        self.qemu = ("127.0.0.1", qemu_port)
        self.rx = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            try:
                self.rx.put(self.sock.recvfrom(4096)[0])
            except OSError:
                return

    def send(self, frame):
        self.sock.sendto(frame, self.qemu)

    def drain(self):
        while not self.rx.empty():
            self.rx.get_nowait()

    def frames(self, seconds):
        """Tramas Trunomy validas recibidas durante `seconds` (el resto se ignora: ARP, ruido)."""
        got, end = [], time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                f = self.rx.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                got.append((f, parse_frame(f)))
            except ValueError:
                pass
        return got

    def during(self, frames, seconds, period=0.05, stop=None):
        """Reenvia `frames` cada `period` s hasta `seconds` o hasta que `stop` se active (el invitado no
        avisa cuando escucha)."""
        end = time.monotonic() + seconds
        while time.monotonic() < end and not (stop and stop.is_set()):
            for f in frames:
                self.send(f)
            time.sleep(period)


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def listen(g, h, frames, seconds=1.6, period=0.05, port=40001):
    """Un `net listen` con el host reenviando `frames` MIENTRAS dura. Devuelve lo que imprimio.

    El comando vuelve con la primera trama, pero las que el host siga enviando hasta entonces quedan
    en el anillo de recepcion sin atender y las recibiria el siguiente `net listen`: por eso el emisor
    se detiene al volver el comando y despues se vacia el backlog (cada escenario parte de cero).
    """
    stop = threading.Event()
    t = threading.Thread(target=h.during, args=(frames, seconds, period, stop))
    t.start()
    try:
        out = g.run("net listen %d" % port)
    finally:
        stop.set()
        t.join()
    time.sleep(0.2)  # tramas ya en vuelo por el socket
    for _ in range(12):
        if "nothing arrived" in g.run("net listen %d" % port):
            break
    return out


def stat(text, label):
    """Numero que sigue a `label` en una linea de `net stats`."""
    i = text.index(label) + len(label)
    return int(text[i:].split()[0])


def scenarios(g, h, guest_mac_text):
    results = []

    def check(name, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else "  -> " + detail))
        results.append(cond)

    # --- preparacion: root enciende la red y crea un tenant y un usuario con permiso de red
    g.wait_prompt(120)
    out = g.run("net up", 30)
    check("net up activates the network", "ACTIVE" in g.run("net info") or "activo" in out.lower() or "active" in out.lower(), out)
    g.run("tenant create lab")
    g.run("user create nora lab net")
    g.run("user create omar lab")

    # --- invitado -> host
    g.run("su nora")
    h.drain()
    out = g.run("net send 40001 bcast 7 hola desde el invitado")
    check("net send answers ok", "net send: ok" in out, out)
    got = h.frames(1.5)
    check("the host receives a Trunomy frame", len(got) >= 1, "nothing received")
    if got:
        raw, (dst, src, sport, dport, payload) = got[0]
        check("the frame goes out to broadcast", dst == BROADCAST)
        check("source MAC = the device's", src == bytes.fromhex(guest_mac_text.replace(":", "")), src.hex())
        check("ports 40001 -> 7", (sport, dport) == (40001, 7), (sport, dport))
        check("payload intact", payload == b"hola desde el invitado", payload)
        check("padding up to the Ethernet minimum", len(raw) == max(MIN_FRAME, HEADER_LEN + len(payload)), len(raw))

    # el invitado no puede fingir un puerto de origen ajeno: el dueno lo fija el kernel, no el mensaje
    g.run("su omar")
    out = g.run("net send 40001 bcast 7 intruso")
    check("without the net.send capability the user is denied", "denied" in out, out)
    h.drain()
    check("and nothing goes out to the network", not h.frames(0.5))

    # --- host -> invitado
    g.run("su nora")
    msg = build_frame(bytes.fromhex(guest_mac_text.replace(":", "")), HOST_MAC, 4242, 40001, b"ping del host")
    out = listen(g, h, [msg], 1.6)
    check("net listen receives the host frame", "port 4242: ping del host" in out, out)
    check("and shows the peer MAC only as data", "from 52:54:00:12:34:57" in out, out)

    # broadcast tambien llega
    bmsg = build_frame(BROADCAST, HOST_MAC, 4243, 40001, b"difusion")
    out = listen(g, h, [bmsg], 1.6)
    check("a broadcast frame also arrives", "port 4243: difusion" in out, out)

    # --- tramas hostiles: ninguna produce efecto; la valida que va detras si llega
    g.run("su root")
    before = stat(g.run("net stats"), "protocol drops ")
    g.run("su nora")
    mac = bytes.fromhex(guest_mac_text.replace(":", ""))
    hostile = hostile_frames(mac, 40001)
    good = build_frame(mac, HOST_MAC, 4244, 40001, b"tras las hostiles")
    out = listen(g, h, hostile + [good], 1.6)
    check("hostile frames are not delivered; the valid one is", "port 4244: tras las hostiles" in out and sum(1 for l in out.split("\n") if l.startswith("from ")) == 1, out)
    g.run("su root")
    after = stat(g.run("net stats"), "protocol drops ")
    check("the drops are counted", after > before, "%d -> %d" % (before, after))

    # --- tramas a un puerto sin dueno: se descartan y se cuentan
    before = after
    g.run("su nora")
    orphan = build_frame(mac, HOST_MAC, 4245, 40009, b"a nadie")
    listen(g, h, [orphan, good], 1.6)
    g.run("su root")
    check("a port with no owner counts as a drop", stat(g.run("net stats"), "protocol drops ") > before)

    # --- inundacion: el kernel sigue vivo, las colas siguen sanas, y aun se recibe despues
    flood = [build_frame(mac, HOST_MAC, 5000 + (i % 100), 40001, b"inundacion %d" % i) for i in range(64)]
    g.run("su nora")
    listen(g, h, flood, 1.0, 0.01)
    g.run("su root")
    out = g.run("net stats")
    check("after the flood the queues stay healthy", "queues ok" in out, out)
    g.run("su nora")
    out = listen(g, h, [good], 1.6)
    check("and receiving still works", "port 4244: tras las hostiles" in out, out)

    # --- cierre ordenado
    g.run("su root")
    out = g.run("net down")
    check("net down", "net" in out.lower(), out)
    return all(results)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true", help="only this script's frame codec")
    ap.add_argument("--mac", default="52:54:00:12:34:56", help="MAC of the guest device")
    ap.add_argument("--transcript", help="save everything the VM printed here")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1
    if not selftest():
        return 1
    rx, qemu = free_udp_port(), free_udp_port()
    host = Host(rx, qemu)
    guest = Guest(rx, qemu)
    ok = False
    try:
        ok = scenarios(guest, host, args.mac)
    except (TimeoutError, RuntimeError) as e:
        print("  FAIL the guest did not respond: %s" % e)
    finally:
        if args.transcript:
            with open(args.transcript, "wb") as f:
                f.write(bytes(guest.transcript))
        guest.close()
    print("nettest: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
