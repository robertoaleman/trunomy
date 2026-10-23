# Capability Book Architecture

## 1. Purpose

The capability book is the kernel-owned authority registry for Trunomy. It maps opaque, subject-local handles to restricted authority over objects, IPC endpoints, or other kernel resources.

The design goal is to make authority explicit, non-forgeable, bounded, revocable, and independent of userland knowledge of object identifiers.

## 2. Core rule

A userland value is never authoritative by itself.

An object ID, tenant ID, rights bitmask, serialized capability, or network field can identify a request, but only an active kernel entry can authorize it.

```text
user request
    -> validate ABI and memory
    -> resolve subject-local handle
    -> validate generation and lifecycle
    -> validate tenant and object relationship
    -> validate requested rights
    -> validate revocation and quotas
    -> perform the smallest permitted operation
```

## 3. Logical data model

The first implementation should use a table per subject or security domain.

```text
CapabilityTable(subject)
    slot 0 -> object 17 / READ / generation 4
    slot 1 -> pipe  3 / SEND / generation 2
    slot 2 -> object 21 / READ + DELEGATE / generation 1
```

A conceptual kernel entry is:

```rust
struct CapabilityEntry {
    resource: KernelResourceRef,
    owner_tenant: TenantId,
    rights: Rights,
    generation: Generation,
    state: CapabilityState,
    delegation: DelegationPolicy,
}
```

The exact internal representation is not a userland ABI. Userland receives only an opaque handle:

```rust
struct CapabilityHandle {
    slot: u32,
    generation: u32,
}
```

The handle must be local to its subject. Copying its bytes to another subject must not make it valid there.

## 4. Resource references

`KernelResourceRef` must not be a raw userland pointer. It should be a kernel-owned reference to a typed resource, such as:

- data object;
- IPC endpoint;
- pipe;
- process or task resource;
- memory object.

A resource reference should include enough type information for the kernel to reject using a data-object capability as a pipe or task capability.

## 5. Rights

Rights should be explicit and operation-specific:

- `READ` — read object contents or metadata allowed by policy;
- `WRITE` — modify permitted object contents;
- `SEND` — send through an endpoint;
- `RECEIVE` — receive from an endpoint;
- `DELEGATE` — delegate a subset of current authority;
- `REVOKE` — request revocation when policy permits;
- `INSPECT` — inspect non-sensitive metadata.

The first version should implement the smallest useful set: `READ`, `WRITE`, `SEND`, `RECEIVE`, and `DELEGATE`.

## 6. Authorization algorithm

For a request `(subject, handle, operation, arguments)`, the kernel should:

1. Validate the syscall ABI.
2. Validate all user pointers, lengths, alignment requirements, and overflow conditions.
3. Resolve `handle.slot` in the subject's table.
4. Require the handle generation to equal the entry generation.
5. Require the entry to be active.
6. Require the resource to be alive and of the expected type.
7. Derive subject and tenant identity from kernel state.
8. Check tenant policy and any explicit cross-tenant relationship.
9. Check that `operation` is contained in the entry's rights.
10. Check quotas and resource limits.
11. Perform only the authorized operation.
12. Return an explicit result or error.

A failed check must not perform a partial privileged operation.

## 7. Delegation

Delegation must be capability-based and monotonic:

```text
rights(child) ⊆ rights(parent)
```

A subject may delegate only if it has `DELEGATE`. It must not be able to:

- add rights;
- change the target resource;
- change the tenant boundary;
- bypass revocation;
- create an untracked child capability.

The kernel should retain a parent/child relation or revocation group so that policy can invalidate delegated authority predictably.

## 8. Revocation and generation safety

Each slot must use a generation or epoch. When an entry is revoked or recycled:

1. mark it inactive;
2. increment its generation;
3. invalidate dependent delegation records according to policy;
4. release or quarantine the resource reference;
5. reject all handles carrying the old generation.

This prevents stale handles and the ABA problem, where a slot is reused for a different resource and an old handle accidentally becomes valid again.

A simple first policy is eager revocation of descendants. More scalable policies can later introduce revocation groups or epochs.

## 9. Tenant model

Tenant identity belongs to kernel-managed subject state. It must not be trusted from a syscall argument, IPC message, or network payload.

Cross-tenant access should be denied by default. If the design later allows a broker or shared service to access multiple tenants, that relationship must be represented by explicit capabilities and documented policy.

Knowing an object ID is never sufficient:

```text
known(object_id) + no valid capability => PermissionDenied
```

## 10. IPC and network integration

IPC and network services should receive a subject context from the kernel and resolve handles through the same authorization path as local syscalls.

Do not treat this as authorization:

```json
{"tenant_id":"A", "object_id":17, "rights":["READ"]}
```

Those fields are attacker-controlled unless bound to authenticated kernel state. A network service may authenticate a client and request a capability operation, but the final object authorization must still be checked against kernel-owned authority.

## 11. Resource limits

The capability book must have bounded behavior. Track limits per tenant and subject for:

- capability slots;
- live resources;
- delegated capabilities;
- IPC endpoints;
- outstanding messages;
- message sizes;
- memory usage;
- syscall rate where needed.

Exhaustion must produce a controlled error or backpressure, not an authority bypass.

## 12. Suggested implementation sequence

1. Define shared types: `TenantId`, `ObjectId`, `Rights`, `CapabilityHandle`, and error codes.
2. Implement a kernel-owned table with slot and generation validation.
3. Add `READ` and `WRITE` against an in-memory object store.
4. Add revocation and stale-handle tests.
5. Add delegation with rights-subset enforcement.
6. Integrate IPC endpoints through the same resolver.
7. Add a minimal network-facing service outside the kernel.
8. Add fuzz/property tests for handles, rights, lengths, and tenant fields.

## 13. Security boundary

The capability book is not a replacement for memory isolation, safe syscall handling, or a correct boot chain. It is one authority mechanism within the kernel. The system is only as strong as the weakest path that can access the protected object.

Every new object access path must use the same resolver and must add a negative test demonstrating denial without authority.
