# Scope: a direction, not a product

Trunomy OS is not trying to be the operating system you install tomorrow. It is an argument, written as working code, about **which way operating systems for sensitive data could go**, and a reference you can read, run, and attack to see whether the argument holds, At least for now and until there is a stable major version that has been tested on actual physical hardware rather than just in QEMU (which would imply readiness for production use) the project remains in development. When that point is reached, it will be announced; for the time being, the project is focused on how the proposed authority model can serve as an alternative for the era of agentic AI.

If you arrive expecting a ready-to-use system, this page is here to save you time and to explain why that is not the goal.

## The argument

Today's general-purpose systems grant authority to whoever runs as the right user, inside a very large kernel, and then try to contain mistakes with layers added afterwards. For data that must not leak between tenants, or for software agents that must not exceed their remit, that default is the wrong way round.

Trunomy tests the opposite default:

- **Authority is a kernel-owned capability**, never a name, a path, an identifier, or a field in a message. Knowing how something is called gives no right to use it (see [threat model](threat-model.md), [invariants](invariants.md)).
- **Nothing is trusted because it is local.** Userland, the network, and other tenants are all treated as potentially hostile; the kernel decides, and every decision is audited.
- **Small enough to read.** The security-critical mechanisms are few and each has a statement of what must stay true and at least one test that would fail if it did not.
- **Honest about limits.** Every invariant lists what it does *not* cover.

The project does not claim perfect security. It claims that a design built on these defaults can make privilege escalation and useful lateral movement expensive enough to discourage an attacker, and it keeps the evidence in the open so that the claim can be checked.

## What this repository is

- A research prototype: a UEFI bootloader, an `x86_64` Rust kernel, a shell, and a reproducible demonstration that runs in QEMU.
- A set of **invariants with traceable evidence**: which test, which QEMU script, and what is still unproven.
- A **starting point to build on**, the way a distribution builds on a kernel: Trunomy supplies the kernel and its guarantees; others may assemble what they need on top.
- A record of design decisions.

## What it is not

- **Not production software**, and not independently audited. Do not put real data on it.
- **Not general purpose.** There is no POSIX layer, no package ecosystem, and no promise of running existing software.
- **Not a TCP/IP system.** The network layer carries a small datagram protocol of its own; a conventional stack is a decision for later, not an omission by accident.
- **Not broad on hardware.** It is developed and verified under QEMU. Real hardware, DMA protection (IOMMU), and timing behaviour are explicitly future work.
- **Not a replacement for Linux.** It is an alternative to examine, not a migration path.

## Why things are missing on purpose

Features are added when they sharpen the argument, not to widen the audience. A missing driver, filesystem, or protocol is usually a deliberate absence: every addition to a kernel is more code that must be reasoned about, and the point is to see how little is needed.

Equally, the work is staged so that each step is verified before the next is built on it. A design that is written down but not implemented (such as authenticated network messages) is labelled as a design, and the invariants file only contains properties that have code and tests behind them.

## How to read the progress figures

Percentages in [`demo-progress.md`](demo-progress.md) are the maintainer's estimates, not measurements, and the method is shown next to the number. "Verified in QEMU" means the maintainer ran it in the emulator; "verified (host)" means unit tests with simulated hardware.

**Version 0.1.0** means: everything compiles without warnings, the unit tests pass, it installs on a clean machine, the demonstration is reproducible, and the limitations are documented. It does **not** mean "complete", "hardened for production", or "ready for every use". After 0.1.0 the project keeps hardening the kernel, and anyone may add to their own builds whatever they need.

## If you want to use it anyway

- Run the demonstration: `./trunomy up`, then `demo` and `net demo` in the shell.
- Read [`quickstart.md`](quickstart.md) for what to type and what you should see.
- Try to break an invariant and report it: a failing negative test is the most useful contribution (see *Contributing and research scope* in the README).
- Treat anything not covered by an invariant, a test, or a QEMU script as unverified.
