// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Comandos de seguridad del shell: tenants, usuarios, objetos, capabilities y auditoria.
//! El shell NO decide nada: cada comando es una syscall y el veredicto es del kernel.
//! Los nombres son una comodidad del shell; el kernel solo ve handles e identidades.

use alloc::vec::Vec;
use libtrunomy::process;
use libtrunomy::session::audit_read;
use libtrunomy::table::Table;
use libtrunomy::worker::{self, Request, MAX_REQUEST};
use libtrunomy::text::{format_hex, parse_rights, parse_u64};
use libtrunomy::{Errno, Handle};
use libtrunomy::abi_audit::{op_name, Record};
use libtrunomy::abi_sysinfo;

use super::{print_bytes, print_raw};

struct Named {
    name: Vec<u8>,
    id: u64,
}

struct HandleEntry {
    owner: u64,
    name: Vec<u8>,
    handle: Handle,
}

struct State {
    tenants: Vec<Named>,
    users: Vec<Named>,
    handles: Vec<HandleEntry>,
    current: u64,
    last_audit_seq: u64,
}

static mut STATE: State = State { tenants: Vec::new(), users: Vec::new(), handles: Vec::new(), current: 1, last_audit_seq: 0 };

fn st() -> &'static mut State {
    // Un solo hilo de ejecucion en el shell.
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

const MAX_NAME: usize = 16;

fn num(v: u64) { let mut b = [0u8; 20]; print_bytes(libtrunomy::text::format_u64(v, &mut b)); }

fn fail(e: Errno) { print_raw("denied: "); print_raw(e.name()); print_raw("\n"); }

/// Por que no se pudo ejecutar una orden.
enum RunErr {
    /// La orden no cabe en la pagina de argumentos de un worker.
    TooLong,
    Kernel(Errno),
    /// El kernel termino al worker (fallo de CPU, kill o plazo vencido); trae el codigo `abi_exit`.
    Terminated(u64),
}

/// Plazo maximo de un worker: 10 s (100 ticks por segundo). Si no termina, el kernel lo mata.
const WORKER_TIMEOUT_TICKS: u64 = 1000;

fn fail_run(e: RunErr) {
    match e {
        RunErr::TooLong => { print_raw("too long for a worker (max "); num((MAX_REQUEST - 9) as u64); print_raw(" bytes of text)\n"); }
        RunErr::Kernel(e) => fail(e),
        RunErr::Terminated(code) => {
            print_raw("worker terminated by the kernel: ");
            match libtrunomy::abi_exit::fault_vector(code) {
                Some(v) => print_raw(libtrunomy::abi_exit::exception_name(v)),
                None if code == libtrunomy::abi_exit::TIMEOUT => print_raw("timed out"),
                None if code == libtrunomy::abi_exit::KILLED => print_raw("killed"),
                None if code == libtrunomy::abi_exit::CPU_QUOTA => print_raw("cpu quota exceeded"),
                None => print_raw("unknown"),
            }
            print_raw("\n");
        }
    }
}

/// Muestra salida que escribio otro proceso o que viene de un objeto: solo ASCII imprimible, para
/// que no pueda mover el cursor ni falsificar lineas en la consola del operador (I-35).
fn show_untrusted(b: &[u8]) {
    for &c in b { print_bytes(&[worker::printable(c)]); }
    print_raw("\n");
}

/// Ejecuta `req` como la identidad `me`. La raiz (pid 1) lo hace en este mismo proceso; un
/// usuario, en un PROCESO nuevo lanzado con su identidad (`ProcessSpawn`), que termina con el
/// resultado de la syscall. El kernel decide en ambos casos: este shell solo hace de
/// intermediario con nombres.
fn run_as(me: u64, req: &Request) -> Result<u64, RunErr> {
    if me == 1 {
        let code = worker::execute(req, &mut |b| show_untrusted(b));
        return worker::result_of(code).map_err(RunErr::Kernel);
    }
    let mut buf = [0u8; MAX_REQUEST];
    let n = req.encode(&mut buf).ok_or(RunErr::TooLong)?;
    let pid = process::spawn(me, &buf[..n]).map_err(RunErr::Kernel)?;
    let waited = process::wait_output(pid, WORKER_TIMEOUT_TICKS).map_err(RunErr::Kernel)?;
    let code = waited.code;
    // Un codigo del rango del kernel NO es un resultado de syscall: se mira antes de interpretarlo.
    if libtrunomy::abi_exit::is_kernel_terminated(code) {
        return Err(RunErr::Terminated(code));
    }
    if !waited.output().is_empty() { show_untrusted(waited.output()); }
    worker::result_of(code).map_err(RunErr::Kernel)
}

fn words(args: &[u8]) -> Vec<&[u8]> {
    args.split(|b| *b == b' ' || *b == b'\t').filter(|w| !w.is_empty()).collect()
}

fn valid_name(n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= MAX_NAME && n.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

fn find<'a>(list: &'a [Named], name: &[u8]) -> Option<&'a Named> { list.iter().find(|n| n.name == name) }

/// Prompt: "root" (pid 1) o el nombre del usuario actual.
pub fn current_user_name() -> Option<Vec<u8>> {
    let s = st();
    s.users.iter().find(|u| u.id == s.current).map(|u| u.name.clone())
}

fn handle_of(owner: u64, name: &[u8]) -> Option<Handle> {
    st().handles.iter().find(|h| h.owner == owner && h.name == name).map(|h| h.handle)
}

fn put_handle(owner: u64, name: &[u8], handle: Handle) {
    let s = st();
    if let Some(e) = s.handles.iter_mut().find(|h| h.owner == owner && h.name == name) {
        e.handle = handle;
    } else {
        s.handles.push(HandleEntry { owner, name: name.to_vec(), handle });
    }
}

/// selftest fault|ud|hang|stack|console (console: el worker intenta escribir en la consola y detener la maquina; debe ser denegado y quedar en `audit`): un worker (con la identidad del usuario actual) provoca un #PF, un #UD
/// o se cuelga a proposito. El kernel debe terminar SOLO a ese proceso y la shell sigue viva.
pub fn cmd_selftest(args: &[u8]) {
    let kind = match words(args).as_slice() {
        [b"fault"] => b'f',
        [b"ud"] => b'u',
        [b"hang"] => b'h',
        [b"stack"] => b's',
        [b"console"] => b'c',
        _ => { print_raw("usage: selftest fault|ud|hang|stack|console (as a user, not root)\n"); return; }
    };
    let me = st().current;
    if me == 1 {
        // La raiz ejecuta en este mismo proceso: un fallo suyo detendria la sesion.
        print_raw("selftest runs in a worker: use su <user> first\n");
        return;
    }
    match run_as(me, &Request::SelfTest { kind }) {
        Err(e @ RunErr::Terminated(_)) => { fail_run(e); print_raw("contained: the shell is still alive\n"); }
        Err(e) => fail_run(e),
        Ok(_) => print_raw("unexpected: the worker returned\n"),
    }
}

pub fn cmd_tenant(args: &[u8]) {
    let w = words(args);
    if w.len() == 1 && w[0] == b"list" {
        cmd_tenant_list();
        return;
    }
    if (w.len() == 2 || w.len() == 3) && w[0] == b"panic" {
        cmd_tenant_panic(&w);
        return;
    }
    if w.len() == 2 && w[0] == b"thaw" {
        cmd_tenant_thaw(w[1]);
        return;
    }
    if w.len() != 2 || w[0] != b"create" || !valid_name(w[1]) {
        print_raw("usage: tenant create <name> | tenant list | tenant panic <name> [wipe] | tenant thaw <name>\n");
        return;
    }
    if find(&st().tenants, w[1]).is_some() { print_raw("tenant exists\n"); return; }
    match run_as(st().current, &Request::TenantCreate) {
        Ok(id) => { st().tenants.push(Named { name: w[1].to_vec(), id }); print_raw("tenant "); print_bytes(w[1]); print_raw(" id="); num(id); print_raw("\n"); }
        Err(e) => fail_run(e),
    }
}

pub fn cmd_user(args: &[u8]) {
    let w = words(args);
    // `ipc` y/o `net` al final dan al usuario la autoridad de IPC y/o de red (si no, ninguna).
    let (mut ipc, mut net) = (false, false);
    for flag in w.iter().skip(3) {
        match *flag {
            b"ipc" => ipc = true,
            b"net" => net = true,
            _ => { print_raw("usage: user create <name> <tenant> [ipc] [net]\n"); return; }
        }
    }
    if w.len() < 3 || w.len() > 5 || w[0] != b"create" || !valid_name(w[1]) {
        print_raw("usage: user create <name> <tenant> [ipc] [net]\n");
        return;
    }
    if find(&st().users, w[1]).is_some() { print_raw("user exists\n"); return; }
    let Some(t) = find(&st().tenants, w[2]).map(|t| t.id) else { print_raw("unknown tenant\n"); return; };
    match run_as(st().current, &Request::ActorCreate { tenant: t, ipc, net }) {
        Ok(pid) => { st().users.push(Named { name: w[1].to_vec(), id: pid }); print_raw("user "); print_bytes(w[1]); print_raw(" pid="); num(pid); print_raw(" tenant="); print_bytes(w[2]); if ipc { print_raw(" ipc"); } if net { print_raw(" net"); } print_raw("\n"); }
        Err(e) => fail_run(e),
    }
}

/// su <user>|root
pub fn cmd_su(args: &[u8]) {
    let w = words(args);
    if w.len() != 1 { print_raw("usage: su <user>|root\n"); return; }
    let target = if w[0] == b"root" { 1 } else {
        match find(&st().users, w[0]) { Some(u) => u.id, None => { print_raw("unknown user\n"); return; } }
    };
    // No hay syscall: `su` solo elige en nombre de quien se lanzan los procesos siguientes.
    // Cada lanzamiento lo autoriza y audita el kernel (solo el lider de la sesion puede).
    st().current = target;
}

pub fn cmd_object(args: &[u8]) {
    let w = words(args);
    let me = st().current;
    match (w.first().copied(), w.len()) {
        (Some(b"create"), n) if n >= 2 && valid_name(w[1]) => {
            // El contenido es el resto de la linea tras el nombre.
            let rest = rest_after(args, 2);
            match run_as(me, &Request::ObjectCreate { data: rest }) {
                Ok(code) => { let h = Handle(code); put_handle(me, w[1], h); print_raw("ok handle="); let mut b = [0u8; 16]; print_bytes(format_hex(h.0, &mut b)); print_raw("\n"); }
                Err(e) => fail_run(e),
            }
        }
        (Some(b"read"), 2) => match handle_of(me, w[1]) {
            None => print_raw("no handle for that name (try: cap forge <user> <name>)\n"),
            Some(h) => {
                // El contenido lo imprime quien lo lee (la raiz o el worker); aqui solo el veredicto.
                if let Err(e) = run_as(me, &Request::ObjectRead { handle: h.0 }) { fail_run(e); }
            }
        },
        (Some(b"write"), n) if n >= 3 => match handle_of(me, w[1]) {
            None => print_raw("no handle for that name\n"),
            Some(h) => match run_as(me, &Request::ObjectWrite { handle: h.0, data: rest_after(args, 2) }) { Ok(_) => print_raw("ok\n"), Err(e) => fail_run(e) },
        },
        (Some(b"delete"), 2) => match handle_of(me, w[1]) {
            None => print_raw("no handle for that name\n"),
            Some(h) => match run_as(me, &Request::ObjectDelete { handle: h.0 }) { Ok(_) => print_raw("ok\n"), Err(e) => fail_run(e) },
        },
        _ => print_raw("usage: object create <name> <text> | read <name> | write <name> <text> | delete <name>\n"),
    }
}

/// Devuelve lo que queda de `args` despues de saltar `n` palabras.
fn rest_after(args: &[u8], n: usize) -> &[u8] {
    let mut rest = args;
    for _ in 0..n {
        while let Some((&c, tail)) = rest.split_first() { if c == b' ' || c == b'\t' { rest = tail; } else { break; } }
        match rest.iter().position(|b| *b == b' ' || *b == b'\t') { Some(i) => rest = &rest[i..], None => return &[] }
    }
    while let Some((&c, tail)) = rest.split_first() { if c == b' ' || c == b'\t' { rest = tail; } else { break; } }
    rest
}

/// cap grant <user> <name> <RIGHTS> [max_uses]  |  cap revoke <name>  |  cap forge <user> <name>
pub fn cmd_cap(args: &[u8]) {
    let w = words(args);
    let me = st().current;
    match (w.first().copied(), w.len()) {
        (Some(b"grant"), 4) | (Some(b"grant"), 5) => {
            let Some(target) = find(&st().users, w[1]).map(|u| u.id) else { print_raw("unknown user\n"); return; };
            let Some(h) = handle_of(me, w[2]) else { print_raw("no handle for that name\n"); return; };
            let Some(mask) = parse_rights(w[3]) else { print_raw("rights: read,write,delegate (comma separated)\n"); return; };
            let uses = if w.len() == 5 { match parse_u64(w[4]) { Some(u) if u <= u32::MAX as u64 => u as u32, _ => { print_raw("bad max_uses\n"); return; } } } else { 0 };
            match run_as(me, &Request::CapDerive { handle: h.0, target, rights: mask, uses: uses as u64 }) {
                Ok(code) => { put_handle(target, w[2], Handle(code)); print_raw("ok granted\n"); }
                Err(e) => fail_run(e),
            }
        }
        (Some(b"revoke"), 2) => match handle_of(me, w[1]) {
            None => print_raw("no handle for that name\n"),
            Some(h) => match run_as(me, &Request::CapRevoke { handle: h.0 }) { Ok(_) => print_raw("ok revoked\n"), Err(e) => fail_run(e) },
        },
        // Ataque simulado: usar el handle crudo de otro usuario. El kernel lo rechaza.
        (Some(b"forge"), 3) => {
            let Some(victim) = find(&st().users, w[1]).map(|u| u.id) else { print_raw("unknown user\n"); return; };
            match handle_of(victim, w[2]) { Some(h) => { put_handle(me, w[2], h); print_raw("copied raw handle (the kernel decides)\n"); } None => print_raw("nothing to copy\n") }
        }
        _ => print_raw("usage: cap grant <user> <name> <rights> [max_uses] | revoke <name> | forge <user> <name>\n"),
    }
}

pub fn cmd_audit(_args: &[u8]) {
    let s = st();
    if s.current != 1 {
        // Un usuario lo intenta como proceso propio: solo el lider de la sesion lee la auditoria.
        match run_as(s.current, &Request::AuditProbe) {
            Err(e) => fail_run(e),
            Ok(_) => print_raw("(audit is read by the session leader: su root)\n"),
        }
        return;
    }
    let mut recs = [Record { seq: 0, subject: 0, tenant: 0, resource: 0, handle: 0, op: 0, outcome: 0 }; 16];
    let mut any = false;
    loop {
        match audit_read(&mut recs, s.last_audit_seq) {
            Err(e) => { fail(e); return; }
            Ok(0) => break,
            Ok(n) => {
                any = true;
                for r in &recs[..n] {
                    print_raw("#"); num(r.seq); print_raw(" subject="); num(r.subject); print_raw(" tenant="); num(r.tenant);
                    if r.resource != 0 { print_raw(" resource="); num(r.resource); }
                    print_raw(" "); print_raw(op_name(r.op)); print_raw(" -> ");
                    if r.outcome == 0 { print_raw("allowed"); } else {
                        match Errno::from_code(libtrunomy::ERROR_BASE + r.outcome as u64) { Some(e) => { print_raw("DENIED "); print_raw(e.name()); } None => print_raw("DENIED ?") }
                    }
                    print_raw("\n");
                }
                s.last_audit_seq = recs[n - 1].seq;
            }
        }
    }
    if !any { print_raw("(no new records)\n"); }
}

/// Ejecuta la secuencia del plan de demo, mostrando cada comando.
pub fn cmd_demo(run: fn(&[u8])) {
    let script: [&[u8]; 18] = [
        b"tenant create acme", b"tenant create evil",
        b"user create alice acme", b"user create bob acme", b"user create mallory evil",
        b"su alice", b"object create secret hello-world",
        b"cap grant bob secret read", b"su bob", b"object read secret", b"object write secret hacked",
        b"su mallory", b"cap forge alice secret", b"object read secret",
        b"su alice", b"cap revoke secret", b"su bob", b"object read secret",
    ];
    for line in script {
        print_raw("> "); print_bytes(line); print_raw("\n");
        run(line);
    }
    print_raw("> su root\n"); run(b"su root");
    print_raw("> audit\n"); run(b"audit");
}

/// `net demo`: recorrido narrado de la red, todo dentro del shell. Solo la raiz (crea un tenant y
/// dos usuarios). Cada paso es el comando real: el veredicto lo da el kernel, no el demo.
pub fn cmd_net_demo(run: fn(&[u8])) {
    use libtrunomy::abi_netctl as nc;
    if st().current != 1 {
        print_raw("net demo: run it as root (su root); it creates a tenant and two users\n");
        return;
    }
    let say = |t: &str| { print_raw("\n# "); print_raw(t); print_raw("\n"); };
    let step = |l: &[u8]| { print_raw("> "); print_bytes(l); print_raw("\n"); run(l); };

    say("1. Only root turns the NIC on. The kernel validates the device, then enables DMA (I-44).");
    print_raw("> net up\n");
    if let Err(e) = run_as(1, &Request::NetControl { op: nc::UP as u8 }) {
        fail_run(e);
        print_raw("net demo: no usable network device (the QEMU command in run_os.sh adds a virtio-net NIC)\n");
        return;
    }
    print_raw("net up: ok\n");
    step(b"net info");

    say("2. Real traffic: an ARP request to the QEMU gateway 10.0.2.2 and its reply, through the queues.");
    step(b"net selftest");

    say("3. Authority is per user. nora was created WITH `net`; omar was created without it.");
    if find(&st().tenants, b"netlab").is_none() { step(b"tenant create netlab"); }
    if find(&st().users, b"nora").is_none() { step(b"user create nora netlab net"); }
    if find(&st().users, b"omar").is_none() { step(b"user create omar netlab"); }
    step(b"tenant list");

    say("4. nora has net.send and net.recv: a message to this same machine goes through the kernel and comes back.");
    step(b"su nora");
    step(b"net loopback hello-from-nora");

    say("5. nora sends a real frame to the wire (broadcast). `ok` means the NIC accepted it; nobody confirms delivery (no TCP/IP).");
    step(b"net send 40001 bcast 7 hello-network");

    say("6. omar has no network authority. The kernel denies both directions, even for his own tenant.");
    step(b"su omar");
    step(b"net send 40001 bcast 7 intruder");
    step(b"net listen 7");

    say("7. Back to root: queue health and the audit trail. The denials are there, with who and what.");
    step(b"su root");
    step(b"net stats");
    step(b"audit");

    say("Done. Try it yourself: su nora, then `net loopback <text>`. `net down` turns the NIC off again.");
}

/// uptime: ticks del reloj del kernel (PIT) convertidos a segundos.
pub fn cmd_uptime() {
    match libtrunomy::session::clock_ticks() {
        Ok(t) => {
            print_raw("up "); num(t / libtrunomy::TICK_HZ); print_raw(".");
            let centi = (t % libtrunomy::TICK_HZ) * 100 / libtrunomy::TICK_HZ;
            if centi < 10 { print_raw("0"); }
            num(centi); print_raw(" s ("); num(t); print_raw(" ticks)\n");
        }
        Err(e) => fail(e),
    }
}

/// Estado real del kernel (`SystemInfo`): `what` es `b'w'` whoami, `b'i'` id, `b'f'` free,
/// `b'p'` ps, `b'c'` caps. Corre como la identidad actual (un usuario, en un worker): el kernel
/// decide que ve cada uno.
pub fn cmd_info(what: u8) {
    let me = st().current;
    if what == b'w' {
        // El nombre es del shell (comodidad); pid, tenant y sujeto los dice el kernel. Va en su
        // propia linea: el log del kernel de un worker se intercala antes de su salida.
        print_raw("name: ");
        match current_user_name() { Some(n) => print_bytes(&n), None => print_raw("root") }
        print_raw("\n");
    }
    if let Err(e) = run_as(me, &Request::Info { what }) { fail_run(e); }
}

/// `net info|stats|up|down|selftest`: el dispositivo de red. Solo la raiz; a un usuario el kernel
/// le deniega y lo audita (I-44).
pub fn cmd_net(args: &[u8]) {
    use libtrunomy::abi_netctl as nc;
    let me = st().current;
    match words(args).first().copied() {
        Some(b"info") => cmd_info(b'n'),
        Some(b"stats") => cmd_info(b's'),
        Some(b"up") => match run_as(me, &Request::NetControl { op: nc::UP as u8 }) {
            Ok(_) => print_raw("net up: queues registered, bus master on (net selftest checks it end to end)\n"),
            Err(e) => fail_run(e),
        },
        Some(b"down") => match run_as(me, &Request::NetControl { op: nc::DOWN as u8 }) {
            Ok(0) => print_raw("net down: bus master off, device reset, queue memory wiped and returned\n"),
            Ok(_) => print_raw("net down: device did not confirm reset; its queue memory is withheld, not reused\n"),
            Err(e) => fail_run(e),
        },
        Some(b"selftest") => match run_as(me, &Request::NetControl { op: nc::SELFTEST as u8 }) {
            Ok(0) => print_raw("net selftest: FAILED (no ARP reply from 10.0.2.2; is QEMU running with -netdev user?)\n"),
            Ok(_) => print_raw("net selftest: OK (ARP reply from the gateway 10.0.2.2: send and receive work)\n"),
            Err(e) => fail_run(e),
        },
        Some(b"loopback") if words(args).len() >= 2 => {
            let text = rest_after(args, 1);
            if text.len() > worker::NET_TEXT_MAX { print_raw("message too long (max 128 bytes)\n"); return; }
            match run_as(me, &Request::NetLoopback { text }) {
                Ok(_) => print_raw("net loopback: OK (sent to this machine and received through the kernel)\n"),
                Err(e) => fail_run(e),
            }
        }
        Some(b"listen") if matches!(words(args).len(), 2 | 3) => {
            let w = words(args);
            let Some(port) = parse_port(w[1]) else { print_raw("port must be 1..65535\n"); return; };
            let secs = match w.get(2) { None => 1, Some(s) => match parse_num(s) { Some(v) if (1..=1).contains(&v) => v, _ => { print_raw("seconds: 1 (the worker's CPU quota caps the wait)\n"); return; } } };
            match run_as(me, &Request::NetListen { port, ticks: (secs * 100) as u16 }) {
                Ok(0) => print_raw("net listen: nothing arrived\n"),
                Ok(_) => {}
                Err(e) => fail_run(e),
            }
        }
        Some(b"send") if words(args).len() >= 5 => {
            let w = words(args);
            let (Some(src), Some(dst)) = (parse_port(w[1]), parse_port(w[3])) else { print_raw("ports must be 1..65535\n"); return; };
            let Some(mac) = parse_mac(w[2]) else { print_raw("mac: aa:bb:cc:dd:ee:ff | self | bcast\n"); return; };
            let text = rest_after(args, 4);
            if text.len() > worker::NET_TEXT_MAX { print_raw("message too long (max 128 bytes)\n"); return; }
            match run_as(me, &Request::NetSend { src, dst, mac, text }) {
                Ok(_) => print_raw("net send: ok\n"),
                Err(e) => fail_run(e),
            }
        }
        _ => print_raw("usage: net info | stats | up | down | selftest | demo | loopback <text> | listen <port> [secs] | send <src> <mac|self|bcast> <dst> <text>\n"),
    }
}

fn parse_num(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 5 || !s.iter().all(|b| b.is_ascii_digit()) { return None; }
    Some(s.iter().fold(0u64, |v, b| v * 10 + (*b - b'0') as u64))
}

fn parse_port(s: &[u8]) -> Option<u16> {
    parse_num(s).filter(|v| (1..=65535).contains(v)).map(|v| v as u16)
}

/// `aa:bb:cc:dd:ee:ff`, `self` (esta maquina) o `bcast` (difusion).
fn parse_mac(s: &[u8]) -> Option<[u8; 6]> {
    if s == b"self" { return Some(libtrunomy::abi_netio::SELF_MAC); }
    if s == b"bcast" { return Some([0xFF; 6]); }
    let mut mac = [0u8; 6];
    let mut parts = s.split(|b| *b == b':');
    for m in mac.iter_mut() {
        let p = parts.next()?;
        if p.len() != 2 { return None; }
        let hex = |c: u8| (c as char).to_digit(16);
        *m = (hex(p[0])? * 16 + hex(p[1])?) as u8;
    }
    if parts.next().is_some() { return None; }
    Some(mac)
}

/// halt: lo pide la identidad actual. La raiz detiene la maquina; un usuario recibe la denegacion
/// del kernel, que queda en `audit` (I-41).
pub fn cmd_halt() {
    let me = st().current;
    if me == 1 { print_raw("Halting Trunomy OS...\n"); }
    if let Err(e) = run_as(me, &Request::Halt) { fail_run(e); }
}

fn user_name_of(pid: u64) -> Option<Vec<u8>> {
    st().users.iter().find(|u| u.id == pid).map(|u| u.name.clone())
}

/// `tenant panic <name> [wipe]`: corte de emergencia (I-45). Lo pide la identidad actual; solo el
/// lider puede, a un usuario el kernel se lo deniega y lo audita.
fn cmd_tenant_panic(w: &[&[u8]]) {
    let wipe = match w.get(2) {
        None => false,
        Some(f) if *f == b"wipe" => true,
        Some(_) => { print_raw("usage: tenant panic <name> [wipe]\n"); return; }
    };
    let Some(t) = find(&st().tenants, w[1]).map(|t| t.id) else { print_raw("unknown tenant\n"); return; };
    match run_as(st().current, &Request::TenantPanic { tenant: t, wipe }) {
        Ok(packed) => {
            let (killed, revoked, wiped) = libtrunomy::abi_panic::unpack(packed);
            print_raw("tenant "); print_bytes(w[1]); print_raw(" PANIC: ");
            num(killed); print_raw(" processes killed, ");
            num(revoked); print_raw(" capabilities revoked, ");
            num(wiped); print_raw(" objects wiped\n");
            print_raw("tenant frozen; its users are retired (tenant thaw allows NEW users)\n");
        }
        Err(e) => fail_run(e),
    }
}

/// `tenant thaw <name>`: reabre el tenant para usuarios NUEVOS; los retirados no vuelven.
fn cmd_tenant_thaw(name: &[u8]) {
    let Some(t) = find(&st().tenants, name).map(|t| t.id) else { print_raw("unknown tenant\n"); return; };
    match run_as(st().current, &Request::TenantThaw { tenant: t }) {
        Ok(_) => { print_raw("tenant "); print_bytes(name); print_raw(" thawed (existing users stay retired)\n"); }
        Err(e) => fail_run(e),
    }
}

/// Las capabilities de `subject` como lineas de texto, tal como las cuenta el kernel. Si no hay
/// ninguna o el kernel lo niega, una unica linea que lo dice (nunca queda una celda vacia).
fn caps_lines(subject: u64) -> Vec<Vec<u8>> {
    use libtrunomy::sysinfo::{cap_text, Line};
    let mut recs = [0u64; 4 * 16];
    match libtrunomy::sysinfo::query(abi_sysinfo::CAPS, subject, &mut recs) {
        Err(e) => alloc::vec![[b"denied: ".as_slice(), e.name().as_bytes()].concat()],
        Ok(0) => alloc::vec![b"(no capabilities)".to_vec()],
        Ok(n) => recs.chunks_exact(4).take(n).map(|r| { let mut l = Line::new(); cap_text(r, &mut l); l.finish().to_vec() }).collect(),
    }
}

/// Texto de un numero decimal.
fn digits(v: u64) -> Vec<u8> { let mut b = [0u8; 20]; libtrunomy::text::format_u64(v, &mut b).to_vec() }

/// Una entidad en la tabla: sus datos en la primera linea y una capability por linea.
fn entity_rows(t: &mut Table<4>, tenant: &[u8], entity: &[u8], pid: &[u8], caps: &[Vec<u8>]) {
    for (i, cap) in caps.iter().enumerate() {
        if i == 0 { t.row([tenant, entity, pid, cap]); } else { t.row([b"", b"", b"", cap]); }
    }
}

/// tenant list: tabla ASCII tenants -> usuarios -> permisos, todo leido del kernel (solo la raiz).
/// Los nombres son del shell; pertenencia y permisos son los del kernel.
fn cmd_tenant_list() {
    let me = st().current;
    if me != 1 {
        // El kernel es quien niega: `ps` (procesos) es solo del lider.
        if let Err(e) = run_as(me, &Request::Info { what: b'p' }) { fail_run(e); }
        return;
    }
    let mut actors = [0u64; 3 * 16];
    let n = match libtrunomy::sysinfo::query(abi_sysinfo::ACTORS, 0, &mut actors) {
        Ok(n) => n,
        Err(e) => { fail(e); return; }
    };
    let actors = &actors[..n * 3];
    let mut t = Table::new(["Tenant ID", "Entity (Role / User)", "PID", "Permissions / Capabilities"]);
    // La raiz es la unica entidad del tenant 1 (el del lider de la sesion).
    entity_rows(&mut t, b"1", b"root (session leader)", b"1", &caps_lines(1));
    // Tenants que el shell nombro, mas los que el kernel conoce por sus actores.
    let mut ids: Vec<u64> = st().tenants.iter().map(|t| t.id).collect();
    for r in actors.chunks_exact(3) { if !ids.contains(&r[1]) { ids.push(r[1]); } }
    for id in ids {
        let mut tenant = digits(id);
        tenant.push(b' ');
        match st().tenants.iter().find(|x| x.id == id) { Some(x) => tenant.extend_from_slice(&x.name), None => tenant.extend_from_slice(b"(unnamed)") }
        if actors.chunks_exact(3).any(|r| r[1] == id && r[2] & abi_sysinfo::ACTOR_TENANT_FROZEN != 0) { tenant.extend_from_slice(b" [FROZEN]"); }
        let mut any = false;
        for r in actors.chunks_exact(3).filter(|r| r[1] == id) {
            any = true;
            t.rule();
            let mut entity = user_name_of(r[0]).unwrap_or_else(|| b"(unnamed)".to_vec());
            if r[2] & abi_sysinfo::ACTOR_RETIRED != 0 { entity.extend_from_slice(b" [retired]"); }
            entity_rows(&mut t, &tenant, &entity, &digits(r[0]), &caps_lines(r[0]));
        }
        if !any { t.rule(); t.row([&tenant, b"(no users)", b"-", b"-"]); }
    }
    t.render(&mut |b| print_bytes(b));
}

/// ls: no hay sistema de archivos. Lo unico que el shell puede listar con verdad son los nombres de
/// objetos cuyo handle tiene la identidad actual (el kernel decide si aun valen al usarlos).
pub fn cmd_ls() {
    let s = st();
    print_raw("no filesystem: objects are capabilities. Handles named by this identity:\n");
    let mut any = false;
    for h in s.handles.iter().filter(|h| h.owner == s.current) {
        any = true;
        print_raw("  "); print_bytes(&h.name); print_raw("\n");
    }
    if !any { print_raw("  (none: object create <name> <text>)\n"); }
}

/// ipc send <user> <texto (hasta 32 bytes)> | ipc recv
/// Lo ejecuta la identidad actual en su propio proceso: el kernel exige CAP_IPC_SEND/RECV, el mismo
/// tenant y que el destino pueda recibir. Una denegacion queda en `audit` (I-43).
pub fn cmd_ipc(args: &[u8]) {
    let w = words(args);
    let me = st().current;
    match (w.first().copied(), w.len()) {
        (Some(b"send"), n) if n >= 3 => {
            let Some(target) = find(&st().users, w[1]).map(|u| u.id) else { print_raw("unknown user\n"); return; };
            let text = rest_after(args, 2);
            if text.len() > worker::IPC_TEXT_MAX { print_raw("message too long (max 32 bytes)\n"); return; }
            match run_as(me, &Request::IpcSend { target, data: text }) {
                Ok(_) => print_raw("ok sent\n"),
                Err(e) => fail_run(e),
            }
        }
        (Some(b"recv"), 1) => match run_as(me, &Request::IpcRecv) {
            Ok(_) => {}
            Err(RunErr::Kernel(Errno::ObjectNotFound)) => print_raw("(no messages)\n"),
            Err(e) => fail_run(e),
        },
        _ => print_raw("usage: ipc send <user> <text> | ipc recv\n"),
    }
}
