<h1 align="center">Trunomy OS</h1>
<p align="center">
  <b>Author : Roberto C. Alemán F.</b><br/><b>Zulia, Venezuela</b><br/><img src="https://flagcdn.com/ve.svg" alt="Bandera de Venezuela" width="48">
<p align="center">
  <a href="https://trunomy.com">Website</a><br/><br/>
   <b>License: GNU Affero General Public License (AGPL-3.0-only) </b></br>
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

## Trunomy OS does not rely on trusting the intentions of an agent. Instead, it explores how to build a system that limits an agent's authority ensuring that such authority is explicit, constrained, and enforced by the kernel, even when the process requesting an operation is hostile.


## Project status

**Experimental research prototype (v0.1.0). Not for production, not independently audited, QEMU only.** Do not use Trunomy to protect real data.

Trunomy's goal is to show that isolating AI agents and other processes with kernel-enforced capabilities is a viable alternative to stacking sandboxes on top of a general-purpose OS.

**What exists today**

- **Boot integrity:** Ed25519-signed kernel and shell (separate keys), anti-rollback through a UEFI NVRAM counter, and reproducible builds (`./trunomy verify`).
- **Capabilities owned by the kernel:** opaque handles, monotonic delegation, cascading revocation, per-subject quotas, tenant checks and a bounded audit log.
- **Isolation:** per-process address spaces, W^X/NX, guard pages, zero-on-free, validated copies of user memory and fault containment.
- **Operations:** `tenant panic` cuts off a tenant, IPC is scoped to a tenant, and a minimal virtio-net datagram protocol has per-port ownership.
- **Evidence:** 50 documented invariants, 465 host tests and six end-to-end QEMU scripts.

**What it is not (yet)**

- Not run on real hardware; no IOMMU/DMA protection.
- No peer authentication on the network, no TCP/IP, no filesystem or persistence.
- No KASLR and no mitigations against speculative-execution side channels; single CPU.
- Not formally verified. Some drivers (virtio-net) still run inside the kernel; keeping the kernel small is a design goal.

Known limitations are listed in the [release notes](docs/release-notes-v0.1.0.md#known-limitations). Trunomy is a direction, not a finished product: see [Scope](docs/scope.md).
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

./trunomy help : Trunomy OS entry point: one command per task—no need to memorize scripts.

./trunomy up : check, build, sign, and boot in QEMU (the go-to command for first-time use)

./trunomy build : build, sign, and create trunomy.img (supports --own-keys, --verbose)

./trunomy run : boot trunomy.img in QEMU

./trunomy check : identify missing requirements on your machine (tools, toolchain, keys, QEMU)

./trunomy test : run unit tests on the host

./trunomy verify : verify that the build is reproducible (two clean clones, identical hash)

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
- Documentation and threat-model.

Avoid treating comments, naming, or hidden identifiers as security controls. Security decisions must be enforced by the kernel and backed by tests.

## License

- **Code** (The kernel and its security-critical components, bootloader, userland and scripts): [GNU AGPL-3.0-only](LICENSE).
- **Documentation** (`docs/` and this README): [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). You may share and adapt it with attribution, under the same license.
- **The Trunomy name and logo are not covered by these licenses.**
Copyright (C) 2026 Roberto C. Alemán F.

## Disclaimer

Trunomy is an experimental research project. It has not received an independent security audit and provides no warranty that its current implementation is secure, reliable, or suitable for production use.

## Clarifications 

It is important to clarify that this project much like many others today received support from specialized artificial intelligence during its coding phase. This technology helped accelerate development by reviewing code and detecting errors, in line with current trends in AI-assisted software development. Nevertheless, the results generated by the AI ​​were supervised, evaluated, and audited throughout the entire process, as a project of this nature can only be conceptualized, designed, and executed by a human being.

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
   <b>License: GNU Affero General Public License (AGPL-3.0-only) </b></br>
</p>
