# Security Model for Trunomy OS

## 1. Purpose

This document defines the minimum authorization model for demonstrating tenant isolation through an immutable, kernel-owned capability book.

Authority is not represented by a serialized object that userland can edit. Userland receives opaque references; the kernel retains the meaning and decides every operation.

## 2. Entities

- **Tenant:** logical isolation and responsibility domain.
- **Subject:** process, service, or endpoint making a request. The kernel determines its identity and tenant.
- **Object:** protected resource, initially a data object.
- **Capability:** bounded authority over an object or endpoint.
- **Handle:** subject-local opaque reference to a capability-book entry.
- **Capability book:** kernel tables relating handles, subjects, objects, rights, generations, and state.

## 3. Authorization flow

```text
subject request
      |
      v
validate ABI, pointers, lengths, and overflow
      |
      v
resolve handle in the subject's table
      |
      v
check generation, lifecycle, tenant, object, and rights
      |
      v
check revocation and quotas
      |
      v
perform the minimum operation or return an error
```

No service may bypass this flow merely by knowing an object ID.

## 4. Capability representation

The exact representation may evolve, but the kernel should maintain the equivalent of:

```text
CapabilityEntry {
    object_ref: KernelObjectRef,
    rights: Rights,
    owner_tenant: TenantId,
    generation: Generation,
    state: Active | Revoked,
    delegation: DelegationPolicy,
}

CapabilityHandle {
    slot: u32,
    generation: u32,
}
```

The internal layout is not a userland contract. A handle must not contain trusted rights by itself.

## 5. Creation

A capability is created only by the kernel or a service explicitly authorized by the kernel. Creating an integer with a similar format does not create authority.

Creation must establish the target object, tenant relationship, initial rights, delegation policy, revocation policy, and quota usage.

## 6. Use

Every use must revalidate authority. A check performed when an object is opened must not be assumed valid forever.

Conceptually:

```text
valid(handle, subject, operation) =
    slot exists
    AND generation matches
    AND entry is active
    AND entry belongs to subject or was validly delegated
    AND subject tenant is authorized
    AND operation is in entry rights
    AND object is alive
    AND quotas allow the operation
```

Revocation must take effect on the next operation without requiring voluntary cooperation from userland.

## 7. Rights and delegation

Delegated rights must be a subset of the parent's rights:

```text
rights_delegated ⊆ rights_parent
```

A subject may delegate only with `DELEGATE`, and must not add rights, change the object, change the tenant boundary, bypass revocation, or create an untracked child capability.

## 8. Revocation and reuse

On revocation or slot reuse, the kernel must mark the entry inactive, advance its generation, invalidate dependent delegations according to policy, and reject old handles. This prevents stale handles and the ABA problem.

## 9. IPC and network

IPC and network are transports, not authorization mechanisms. Messages may carry references or requests, but each reference must be resolved against kernel-owned subject context.

This is not sufficient authorization:

```text
{ tenant_id, object_id, rights }
```

Those fields may be attacker-controlled. Authentication, tenant resolution, authorization, and object access must remain separate steps.

## 10. Memory and ABI

Before copying data between userland and kernel, validate ownership of the address range, overflow, mapping, permissions, maximum sizes, and the safety of copying mutable memory. Invalid user memory must never become privileged access.

## 11. Errors

The ABI should distinguish at least `InvalidArgument`, `InvalidPointer`, `InvalidCapability`, `RevokedCapability`, `PermissionDenied`, `ObjectNotFound`, `TenantMismatch`, `BufferTooSmall`, `QuotaExceeded`, and `ResourceUnavailable`.

Ambiguous values must not represent both success and failure.

## 12. Properties to demonstrate

- knowing an object ID does not grant access;
- knowing the implementation does not create authority;
- rights cannot be amplified;
- delegation preserves limits;
- revocation invalidates old handles;
- subjects cannot use another subject's handles;
- services cannot confuse tenants;
- IPC does not enable lateral movement without explicit authority.

## 13. Status

This document describes the target design. It does not claim that every property is implemented in the current revision. Each property must eventually link to code, tests, and reproducible evidence.
