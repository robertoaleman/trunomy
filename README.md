<h1 align="center">Trunomy OS</h1>
<p align="center">
  <b>Author : Roberto C. Alemán F.</b><br/><b>Zulia, Venezuela</b><br/><img src="https://flagcdn.com/ve.svg" alt="Bandera de Venezuela" width="48">
<p align="center">
  <a href="https://trunomy.com">Website</a><br/><br/>
   <b>License: GNU Affero General Public License (AGPL) </b></br>
   <b>Current version available: v0.1.0</b></br>
</p>
<p align="center">
  <b>A microkernel designed from the ground up with a focus on a "Zero Trust" architecture and the isolation of AI agents by controlling their assigned capabilities.</b><br/>
  <b>The kernel is the sole source of truth!<br/> An AI agent may attempt to do something, but the kernel decides!</b>
<br/><b>Intention ≠ Authority</b><br/></p>
<h2>Introduction</h2> 
<h2> What Trunomy OS is and where the name comes from</h2>

<p>The name <strong>Trunomy</strong> combines the English word <em>True</em> with the Greek suffix <em>-nomy</em> (derived from <em>nomos</em>, meaning law, rule, or system of governance). Within the context of the operating system, this etymology defines the core philosophy of the architecture: a system governed by true and absolute laws, completely free from implicit trust or legacy software conventions.</p>

<ul>
  <li><strong>True (Uncompromising / Verifiable):</strong> Represents strict cryptographic boot verification via Ed25519 signatures, geometric validation of memory segments under W XOR X policies, and real hardware-level isolation. It ensures that every component running on the bare metal is precisely what was signed and authorized, with zero shortcuts or permissive development modes.</li>
  <li><strong>-nomy (Law / Government / Systematic Order):</strong> Refers to the microkernel's internal governance system. Capabilities, strict CPU and memory resource limits, tenant boundaries, and the immutable audit log do not rely on the good faith of applications, but rather on deterministic laws enforced relentlessly at Layer 0.</li>
</ul>

<p>Conceptually, Trunomy OS translates to <strong>"the system of true laws"</strong> an operating environment where the security, isolation, and control of AI agents or critical processes are governed by unbreakable rules rooted directly in the kernel, rather than simulated through superficial software layers.</p>

Trunomy OS is an experimental `no_std` Rust operating-system research project focused on secure data access, strong tenant isolation, and kernel-enforced immutable capabilities.

Its central security thesis is:

> An attacker may know the source code, syscall ABI, object identifiers, and communication protocols, but that knowledge alone must not become effective authority over another tenant's data or resources.

The project does not claim perfect security. It aims to make privilege escalation and useful lateral movement sufficiently expensive in a hostile environment that an attacker is discouraged from continuing.


## Project status

**Initial research prototype; it is not ready for production and has not been independently audited. The current focus is to demonstrate that the proposed design serves as an alternative for achieving true isolation for AI agents and other processes by controlling their capabilities at the kernel level..**

The current implementation contains a UEFI bootloader, a bare-metal Rust kernel, userland components, an experimental shell, and early IPC/capability concepts. The security model and capability-book design are being developed alongside the implementation.

Do not use Trunomy to protect real or production data.

Trunomy is a direction, not a finished product: it is meant to show an alternative way of building systems for sensitive data, not to be a ready-to-use general-purpose system. See [Scope](docs/scope.md).

## Architecture

```text
+---------------------------------------------------------------+
|                         Userland                              |
|  Shell | Core utilities | Data services | Network client     |
+-----------------------------+---------------------------------+
                              | IPC / syscalls
+-----------------------------v---------------------------------+
|                         Kernel                                |
|  Capability book | Tenant isolation | Memory | IPC | Scheduler|
+-----------------------------+---------------------------------+
                              |
+-----------------------------v---------------------------------+
|                    Boot and platform                          |
|                 UEFI bootloader | x86_64                      |
+---------------------------------------------------------------+
```

The kernel is the authority boundary. Userland components are treated as potentially compromised and must not be trusted to enforce authorization.

## Repository layout

- `boot/` — UEFI bootloader.
- `kernel/` — bare-metal kernel and security-critical mechanisms.
- `userland/shell/` — experimental Ring 3 shell.
- `userland/libtrunomy/` — userland SDK and IPC abstractions.
- `userland/coreutils/` — early userland utilities.
- `config/` — system configuration manifests.
- `docs/threat-model.md` — attacker model, assumptions, and security goals.
- `docs/security-model.md` — authorization and capability semantics.
- `docs/invariants.md` — security invariants to preserve and test.
- `docs/scope.md` — what this project is and is not.

## Security model in one paragraph

A tenant receives opaque, kernel-managed handles rather than authority encoded in user-controlled structures. Every operation resolves the handle in the caller's capability table and checks subject identity, tenant, object lifetime, generation, revocation state, rights, memory safety, and quotas. Object identifiers are not credentials. IPC and network transport authority; they do not create authority.

## Intended first demonstration

The first meaningful milestone is a reproducible end-to-end demonstration:

1. Tenant A owns or receives access to a protected object.
2. Tenant A reads it with a valid `READ` capability.
3. Tenant B knows the object's identifier but is denied access.
4. Tenant A cannot turn `READ` into `WRITE`.
5. Revoking A's capability invalidates subsequent access.
6. Forged, modified, stale, and cross-subject handles fail.
7. The same authorization decision is preserved over IPC and a minimal network interface.

## Building

The current build flow targets x86_64 UEFI and a bare-metal x86_64 kernel:

```bash
./trunomy up          # checks the machine, builds, signs and boots in QEMU
```

`./trunomy` is the single entry point (`./trunomy help` lists everything): `check` (what is missing on this machine), `build`, `run`, `test`, `verify` (reproducibility). The build prints what each stage does and why, keeps cargo's output in `target/build-logs/`, and shows it only if something fails (`--verbose` streams it).

Trunomy only runs signed code, and the repository does not contain anyone's private key. On a fresh clone the build offers to generate your own keys (`./build_os.sh --own-keys` does it without asking); the result is a chain of trust that is yours alone. Inside QEMU: `help`, then `demo`; exit with Ctrl-A, then X. Step-by-step guide with commands and expected output: [docs/quickstart.en.md](docs/quickstart.en.md). or  [docs/quickstart.md](docs/quickstart.md) in spanish.

Requirements: `rustup` (the toolchain is pinned in `rust-toolchain.toml`), `openssl` with Ed25519, `objcopy`/`readelf`, `dosfstools` + `mtools`, and QEMU + OVMF to boot (`./trunomy check` tells you which are missing). The compiler is expected to emit no warnings; `./scripts/ci.sh` fails if it does.

# Quick guide to commands for booting the OS

./trunomy help

Trunomy OS entry point: one command per task—no need to memorize scripts.
./trunomy up

check, build, sign, and boot in QEMU (the go-to command for first-time use)
 
./trunomy build

build, sign, and create trunomy.img (supports --own-keys, --verbose)

./trunomy run

boot trunomy.img in QEMU

./trunomy check

identify missing requirements on your machine (tools, toolchain, keys, QEMU)

./trunomy test

run unit tests on the host

./trunomy verify

verify that the build is reproducible (two clean clones, identical hash)

## Design documents

Read these documents before treating any security property as implemented:

- [Threat model](docs/threat-model.md)
- [Security model](docs/security-model.md)
- [Formal invariants](docs/invariants.md)
- [Capability-book architecture](docs/capability-book-architecture.md)
- [Scope: a direction, not a product](docs/scope.md)

## Contributing and research scope

The most valuable contributions are small, testable improvements to:

- Capability validation;
- Tenant separation;
- Revocation and generation handling;
- User/kernel memory validation;
- IPC authorization;
- Negative security tests;
- Documentation and threat-model clarity.

Avoid treating comments, naming, or hidden identifiers as security controls. Security decisions must be enforced by the kernel and backed by tests.

## License

- **Code** (The kernel and its security-critical components, bootloader, userland and scripts): [GNU AGPL-3.0-only](LICENSE).
- **Documentation** (`docs/` and this README): [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). You may share and adapt it with attribution, under the same license.
- **The Trunomy name and logo are not covered by these licenses.**
Copyright (C) 2026 Roberto C. Aleman F.
## Blockchain Integrity Verification

The content of this repository and its release files are **verified on the Bitcoin blockchain** using the **OpenTimestamps** protocol.
The having been permanently anchored under the following transaction and confirmed blocks of the Bitcoin mainnet:

* **Bitcoin Transaction ID (TXID):** `c0960baac337cb6fe8ee650418bfd41ddd8f08df821d07a526be48d908729066`
* **Backup Bitcoin Blocks:** 972749, 972686, 972728


## Disclaimer

Trunomy is an experimental research project. It has not received an independent security audit and provides no warranty that its current implementation is secure, reliable, or suitable for production use.

## Contact 
If you would like to contact me, you can write to roberto@trunomy.com

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S2Y6296BZ2)

## Important
I am currently not accepting pull requests (PRs); 
if you would like to make a suggestion, please post it in the issues section or you can write to roberto@trunomy.com

<p align="center">
  <b>Author : Roberto C. Alemán F., Zulia, Venezuela.</b><br/><img src="https://flagcdn.com/ve.svg" alt="Bandera de Venezuela" width="32">
  </br>
  
<p align="center">
  <a href="https://trunomy.com" title="Official website of trunomy os">Website</a> </br>
   <b>License: GNU Affero General Public License (AGPL) </b></br>
   <b>Current version available: v0.1.0</b></br>
</p>
