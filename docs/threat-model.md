# Threat Model for Trunomy OS

## Document status

- **Status:** design draft for an experimental research prototype
- **Scope:** tenant isolation, data access, and communication between components
- **Not a:** security audit, certification, or production security guarantee

## 1. Security thesis

Trunomy does not attempt to hide its implementation. Its thesis is that public knowledge of the source code, ABI, and interfaces must not become effective authority over another tenant's data or resources by itself.

The intended property is:

> A subject without a valid capability cannot obtain useful access to a protected object merely by knowing its identifier, the source code, the syscall surface, or the communication protocol.

The kernel is the source of truth for authorization. Userland, the shell, services, and network clients are untrusted components.

## 2. Protected assets

1. Tenant data, contents, metadata, and versions.
2. Authority: capabilities, rights, delegation, and revocation state.
3. Isolation: address spaces, IPC, handles, and tenant resources.
4. Kernel integrity: capability tables, memory, schedulers, validators, and entry points.
5. Bounded availability: tenant memory, objects, messages, pipes, and capability quotas.

Confidentiality and integrity are the first demonstration priorities. Availability is addressed through limits and controlled failures, not a promise to resist every denial-of-service attack.

## 3. Adversaries

### 3.1 Compromised userland process

A process may read public source and binaries, know syscall numbers and formats, send malformed arguments, forge or reuse handles, access invalid memory ranges, abuse IPC, retain a capability after revocation, and cooperate with another compromised process in the same tenant.

### 3.2 Autonomous or hostile AI agent

An AI agent is modeled as a process that can execute code, repeat attempts, analyze observable responses, and adapt. It receives no special authority: its limits are exactly those of the process and tenant hosting it.

### 3.3 Untrusted remote client

A remote client may know the protocol, replay messages, alter fields, send extreme sizes, and present a capability belonging to another tenant.

### 3.4 Out of scope for the initial model

- physical control of the machine;
- compromised firmware, UEFI, or hypervisor;
- malicious DMA devices;
- hardware or CPU vulnerabilities;
- compromised compiler or supply chain;
- unmanaged production secrets;
- host-level denial of service;
- design errors not yet implemented or tested.

These exclusions must remain visible. They are not evidence of security.

## 4. Assumptions

1. Verified boot, firmware, and the hypervisor are initially outside scope.
2. The kernel contains `unsafe` code, but each unsafe boundary must be documented and tested.
3. Userland may be fully compromised.
4. IDs, syscall numbers, and public formats are not secrets.
5. An object is not protected merely because its ID is hard to guess.
6. Privileged services are part of the attack surface.
7. Cryptography, when added, will use reviewed primitives and libraries rather than custom primitives.

## 5. Security objectives

- Prevent capability forgery and rights amplification.
- Preserve tenant separation even when object IDs are known.
- Invalidate revoked and stale handles.
- Validate pointers, lengths, overflow, and permissions in the kernel.
- Prevent IPC from becoming unauthorized lateral movement.
- Fail closed on authorization errors.
- Keep the security-critical surface small and auditable.
- Provide reproducible positive and negative tests.

## 6. Non-goals

- perfect security;
- replacing independent review;
- a general-purpose operating system;
- guaranteed availability under host control;
- solving hardware or firmware trust;
- treating obfuscation as access control.

## 7. Success criteria

The first version is technically defensible when a reproducible demo shows that:

1. Tenant A receives access to an object.
2. Tenant A performs an allowed operation.
3. Tenant B knows the same object identifier and is denied.
4. A cannot turn `READ` into `WRITE`.
5. Revocation invalidates later use.
6. Forged, modified, stale, and cross-subject handles fail.
7. The same authorization remains in force through IPC and a minimal network interface.

## 8. Disclosure posture

Until independent review and substantially broader testing exist, Trunomy must be described as an **experimental research prototype**. It must not be recommended for real or production data.
