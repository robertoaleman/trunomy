# Security policy

Trunomy OS is an **experimental research prototype**, not production software and not independently audited. Do not use it to protect real data. Even so, reports of weaknesses are welcome: finding them is the point of publishing it.

## Supported versions

| Version | Supported |
|---|---|
| `main` and the latest `v0.1.x` | yes, best effort |
| anything older | no |

## What to report

Anything that breaks a documented guarantee, in particular:

- A way to obtain authority without a capability: forged, guessed, replayed or stale handles; a data capability acting as a system capability; crossing a tenant boundary; READ turning into WRITE; surviving a revocation.
- A way to run unsigned code or to bypass boot integrity, including rollback protection (I-18, I-19, I-39, I-49).
- Memory-safety or isolation failures in the kernel: validated copies, W^X, page tables, guard pages, zero-on-free.
- A hostile or malformed network frame, virtio device or syscall argument that is accepted when it should be dropped, or that crashes or hangs the kernel.
- A reproducibility failure: `./trunomy verify` reporting `DIFFERENT` on a clean clone.

The guarantees and their limits are listed in [`docs/invariants.md`](docs/invariants.md) and [`docs/threat-model.md`](docs/threat-model.md). **Known limitations are not vulnerabilities**: see "Known limitations" in [`docs/release-notes-v0.1.0.md`](docs/release-notes-v0.1.0.md) (QEMU only, no peer authentication on the network, NVRAM-dependent rollback protection, no KASLR, and so on). A failing negative test that shows an invariant does not hold is the most useful report.

## How to report

Please **do not open a public issue** for a vulnerability.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository
(<https://github.com/robertoaleman/trunomy/security/advisories/new>).

Include, if you can: the commit or tag, how you built it (`./trunomy verify` hashes help), the steps or the test that reproduces it, and which invariant you think is violated.

## What to expect

This is a one-person project, so these are goals, not guarantees:

- acknowledgement within 7 days;
- an assessment (accepted, known limitation, or not reproducible) within 30 days;
- for accepted reports, a fix on `main` with a regression test and a mention in the release notes, crediting you unless you prefer otherwise.

Please allow a reasonable time to fix before disclosing details publicly. Good-faith research that follows this policy will not be met with any legal action.

## Scope

In scope: the code in this repository (bootloader, kernel, shell, libraries, build and verification scripts). Out of scope: vulnerabilities in QEMU, OVMF/EDK II, the Rust toolchain or third-party crates (report those upstream; if one affects Trunomy, tell us too), attacks that need physical access or a compromised build machine, and social engineering.

## Signing keys

The repository ships only **public** keys (`abi/src/lib.rs`). The private keys live in the maintainer's `.keys/` directory and are never committed. If you ever find a private key in this repository or its history, treat it as a vulnerability and report it as above. The release key fingerprints are in [`docs/release-notes-v0.1.0.md`](docs/release-notes-v0.1.0.md).
