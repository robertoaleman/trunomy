# Trunomy OS v0.1.0, release notes

First tagged release of the research prototype: a UEFI bootloader, an `x86_64` Rust capability microkernel, an experimental Ring 3 shell and a reproducible demonstration that runs in QEMU.

> **Research prototype, not production software, not independently audited.** Do not put real data on it. See [`scope.md`](scope.md) for what 0.1.0 does and does not mean.

## What is in 0.1.0

**Authority model**
- Capabilities are owned by the kernel: opaque handles (slot + generation), monotonic delegation, cascading revocation, quotas per subject, symmetric tenant check. Knowing an object id or a raw handle gives no authority (I-01 … I-15).
- A data capability can never satisfy a system capability; revoked slots are reused without ABA; a delegatee cannot revoke its delegator or siblings; `CapDerive` enforces the delegated-slot quota.
- Every kernel decision is audited in a bounded ring; only the session leader reads it.

**Isolation and memory**
- Per-process address spaces (own PML4), W^X for the kernel image and shell, NX, CR0.WP, guard pages, SMEP/SMAP when the CPU reports them.
- Zero-on-free for physical frames and object payloads; double-free detection; validated copy in/out of user memory in a single step.
- Fault containment: a faulting, hanging or stack-overflowing worker is terminated and the shell stays alive; no frame leaks.
- Tenant emergency cut (`tenant panic`): revokes every capability of a tenant group-wide, optionally wipes its objects, and leaves other tenants running.

**Boot integrity**
- Ed25519-signed kernel and shell with **separate keys**; no development mode; ELF segment ranges validated.
- Anti-rollback: signed security version, minimum stored in a UEFI NVRAM variable (`ROLLBACK REJECTED`).
- Bring your own chain of trust: the repository ships only public keys; `./trunomy build --own-keys` generates yours.

**IPC and network (QEMU)**
- Capability-checked IPC within a tenant; bounded queues; IPC authority only on request.
- virtio-net (legacy) negotiated inactive; the leader turns it on after validation (`net up`). A small Trunomy datagram protocol with per-port ownership; hostile frames are dropped and counted. Verified end to end against an independent implementation of the protocol (`nettest.py`) and between two VMs (`nettest2.py`).

**Userland**
- Shell with `tenant`, `user`, `su`, `object`, `cap`, `ipc`, `net`, `audit`, `demo`, `net demo`, `selftest`, a minimal line editor with history (I-50).
- All on-screen output is US English.

**Tooling**
- `./trunomy check | build | run | up | test | verify`, six QEMU test scripts, `ci.sh all`.
- Reproducible build: two clean clones in different paths give bit-identical kernel, shell, `shell.bin` and bootloader.
- 465 host tests (kernel 384, abi 32, libtrunomy 25, bootcore 22 + 2 openssl interop), zero compiler warnings, 50 invariants with traceable evidence ([`invariants.md`](invariants.md)).

## Changes since the external review (2026-10-20)

- `has_capability_for` now checks resource type, rights and state; data capabilities cannot be used as system authority.
- Revocation cuts the whole derived subtree across subjects; delegated-slot quota enforced in `CapDerive`.
- Dead boot-time debug harness, `config/system.toml` and the vendored `OVMF_CODE.fd` removed; the firmware now comes from the system (`edk2-ovmf` / `ovmf`) or `OVMF_CODE=/path`.
- All crates are `0.1.0`; `version`, `status`, the shell banner and the bootloader banner share one source (`CARGO_PKG_VERSION`).

## Verification

Recorded on the maintainer's clean machine, rustc 1.98.1 (pinned in `rust-toolchain.toml`), commit `e174f7a` (later docs-only commits do not change the binaries):

| Artifact | sha256 |
|---|---|
| `target/x86_64-unknown-none/release/trunomy-kernel` | `93c9533c88e7b9b679e670fb01adf976dda431779a78acbe5ff8e1327d8766df` |
| `target/x86_64-unknown-none/release/trunomy-shell` | `ea7edba14771ebe48be9059ece25c8f0437ddcfa8933b93d1b8ee1f77ff5d4af` |
| `target/x86_64-unknown-none/release/shell.bin` | `695483dd754a42d9bded651f29072f3c0c66aded4a538e8e00a87cdd8921cf54` |
| `target/x86_64-unknown-uefi/release/trunomy-bootloader.efi` | `0bf39eb8f2f31f4c9f3a2e6a75a66d6136b41efbb4e85078e0a14576faebaaec` |

The signing public keys are compiled into the binaries, so these hashes hold for the release keys in `abi/src/lib.rs`. Fingerprints (sha256 of the public PEM files):

| Key | sha256 |
|---|---|
| kernel signing key (`kernel-ed25519-public.pem`) | `4846ff4d7bae7ed1c3aad4318dffd9a5757dce1995c042b2681dabcf7350cad8` |
| shell signing key (`shell-ed25519-public.pem`) | `9cb81c972c679971dd1b772243b564e071b0933fd8e23ea665306f6b6ea6c51b` |
 A build with `--own-keys` produces different hashes by design; `./trunomy verify` still checks that your two clean builds agree with each other.

To reproduce them from a fresh clone: `git checkout v0.1.0 && ./trunomy verify` (if the build offered to generate your own keys, discard that change first with `git checkout -- abi/src/lib.rs`; your own keys give different hashes by design).

Also verified: `ci.sh all`, the GitHub workflow (including `cargo audit`), a clean-machine install, and the six QEMU scripts (`audittest`, `linetest`, `netdemotest`, `rollbacktest`, `nettest`, `nettest2`).

## Known limitations

- **QEMU only.** Not run on real hardware; DMA protection (IOMMU) and real device timing are untested (I-44).
- **No peer authentication on the network.** Capabilities are authorized by the kernel locally; the Trunomy datagram protocol has no TCP/IP and no per-tenant authentication. The remote-server design is documented, not implemented ([`design-remote-server.md`](design-remote-server.md)).
- **Rollback protection depends on NVRAM.** With the UEFI variable store erased, an older signed kernel boots (documented in I-49).
- **No KASLR.** Memory hardening covers the first 4 GiB; the firmware's page tables stay in place (I-38).
- **SMEP/SMAP** are enabled when the CPU reports them and skipped with a warning otherwise (`REQUIRE_SMEP_SMAP` is `false`).
- **Audit ring:** allowed operations can still rotate the 256-event ring; there is no counter of lost events yet.
- **Zombie processes** stay until reaped, bounded by `MAX_PROCS`.
- **Supply chain:** crates come from crates.io pinned by `Cargo.lock`; they are not vendored.
- State (users, tenants, objects) lives in RAM; there is no filesystem or persistence.

## After 0.1.0

KASLR, real-hardware boot, an authenticated network/server responder, and an audit counter for lost events.

## Upgrading and building

```bash
git clone https://github.com/robertoaleman/trunomy.git
cd trunomy
./trunomy check
./trunomy up            # offers to generate your own keys on a fresh clone
```

Full walkthrough: [`quickstart.en.md`](quickstart.en.md). License: see `LICENSE`.
