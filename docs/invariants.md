# Formal Security Invariants

## 1. Purpose

These invariants are statements that must remain true in every relevant kernel state. They are not aspirational comments: each requires an implementation owner and at least one positive or negative test.

Notation:

- `s`: subject or process;
- `t`: tenant;
- `o`: object;
- `h`: handle;
- `c`: capability;
- `r`: right;
- `active(x)`: entity is active;
- `valid(h, s)`: handle is valid for subject;
- `authorize(s, o, r)`: kernel authorizes the operation.

## 2. Fundamental invariants

### I-01 — Kernel-owned authority

Every access decision for a protected object is made by the kernel or by a component whose authority is validated by the kernel.

```text
authorize(s, o, r) => kernel_validated(s, o, r)
```

### I-02 — No authorization by bare identifier

Knowing an object ID does not imply possession of a capability.

```text
known(s, object_id(o)) AND NOT holds(s, capability(o, r))
    => NOT authorize(s, o, r)
```

### I-03 — No capability forgery

A value created or modified by userland gains no authority unless it resolves to an active kernel-created entry.

```text
forged(h) => NOT valid(h, s)
```

### I-04 — No rights amplification

An authorized operation cannot produce authority greater than allowed by policy.

```text
rights(child) ⊆ rights(parent)
```

### I-05 — Tenant separation

A subject cannot access another tenant's object without an explicit cross-tenant capability.

```text
tenant(s) != tenant(o) AND NOT cross_tenant_capability(s, o, r)
    => NOT authorize(s, o, r)
```

### I-06 — Effective revocation

A revoked capability does not authorize later operations.

```text
revoked(c) AND use_after_revoke(c, r)
    => NOT authorize(s, object(c), r)
```

### I-07 — No validity through slot reuse

Reusing a slot does not make a handle from an older generation valid.

```text
generation(h) != generation(entry(slot(h))) => NOT valid(h, s)
```

### I-08 — Handle scope

A handle valid for one subject is not automatically valid for another subject.

```text
valid(h, s1) AND s1 != s2 => NOT valid(h, s2)
```

### I-09 — Subject identity is not message-controlled

Effective identity and tenant context come from kernel state, not from userland or network fields.

```text
claimed_tenant(message) != kernel_tenant(s)
    => claimed_tenant does not change authorization(s, ...)
```

### I-10 — Complete memory validation

The kernel does not read or write userland memory without validating range, overflow, mapping, and permissions.

```text
invalid_range(ptr, len) => no_kernel_access(ptr, len)
```

### I-11 — Fail closed

An ambiguous condition, validation error, missing object, or inconsistent state denies the operation and grants no partial authority.

```text
validation_error => deny
```

### I-12 — IPC is not implicit authority

The ability to send or receive a message does not grant access to objects named in that message.

```text
ipc_access(s, endpoint) AND NOT capability(s, o, r)
    => NOT authorize(s, o, r)
```

### I-13 — Exact operation rights

`READ` does not permit `WRITE`; `SEND` does not permit `RECEIVE`; and authority over one object does not grant authority over another.

```text
r_requested NOT IN rights(c) => deny
```

### I-14 — Object lifetime

A capability does not keep a destroyed object valid unless an explicit persistence policy says so.

```text
NOT active(o) => NOT authorize(s, o, r)
```

### I-15 — Quotas and limits

A valid request cannot bypass tenant limits for memory, objects, capabilities, messages, or pipes.

```text
usage(t) > quota(t) => deny_or_backpressure
```

## 3. Evidence requirements

Every release should execute at least:

1. A reads its object with `READ`.
2. B knows A's ID and receives `PermissionDenied`.
3. A attempts `WRITE` with `READ` and fails.
4. A modifies a handle and fails.
5. A uses a revoked handle and fails.
6. B attempts to use A's handle and fails.
7. A recycled slot does not validate an old handle.
8. An out-of-range pointer cannot cause kernel access.
9. An IPC message naming another object does not grant access.
10. Network fields cannot elevate tenant or rights.
11. Delegation with rights above the parent is rejected.
12. Quotas remain enforced under repeated requests.

## 4. Traceability

Maintain this table as implementation progresses:

```text
ID | Responsible code | Test | Result | Known limitation
```

An invariant without code and a test is a design hypothesis, not a security guarantee.

## 5. Limitations

These invariants do not eliminate kernel bugs, hardware failures, dependency vulnerabilities, or attacks against the boot chain. They make authority explicit and define what must be tested.

## 6. Invariant amendments and additions

The following amendments and additions extend the invariants above. They are recorded as an addendum so the original invariant text remains unchanged while the agreed implementation and evidence requirements are preserved.

### I-04 / I-13 — System capability validation

System capabilities (`CAP_OBJECT_CREATE` 4, `CAP_ADMIN`/`CAP_HALT` 5, `CAP_CONSOLE` 6, `CAP_IPC_SEND`/`RECV` 0x10/0x11, `CAP_NET_SEND`/`RECV` 0x12/0x13) are `Task` capabilities identified by a number, while data capabilities carry an `ObjectId` in the same field. `has_capability_for` used to compare only tenant, number and state, so a tenant without privileges that was handed the object with a matching number (object ids are consecutive from boot) satisfied `CAP_ADMIN`, the console or the network checks (reproduced with a host test; found by an external review). Status: fixed. The check now requires an ACTIVE capability of type `Task`, the `READ` right (the one granted when they are seeded) and the same tenant; a data capability never satisfies it.

Not covered: the check does not consume uses or verify expiry, because system capabilities are seeded without limits; if a system capability is ever granted with limits, `has_capability_for` must be replaced by the full resolver (`lookup`). The two id spaces still share one numeric field; a distinct `System` resource type would remove the possibility by construction.

### I-06 / I-07 — Revocation scope and slot reuse

Revoking a handle revokes that capability and everything derived from it, transitively, and nothing else: not the capability it was derived from, not its siblings. A holder can always drop its own capability (and what it delegated), but cannot take authority away from whoever delegated to it. The tenant cut of I-45 (`revoke_subject`) is deliberately wider and works by revocation group. Revoked slots are reused: a new capability takes the generation that the revocation already incremented (no issued handle ever had it), so an old handle on a reused slot never becomes valid again (I-07); a slot whose generation is at the maximum is not reused. A process cannot fill another subject's slots: `CapDerive` refuses a target that already holds 8 delegated capabilities (`MAX_DELEGATED_PER_SUBJECT`), so the rest of its 16 stays available for its own objects and system capabilities. The capability book itself does not impose that cap (kernel-side delegation, such as the agent-support scenario holding one capability per customer, may use all 16 slots).

Not covered: a delegation still does not need the target's consent (it only costs the target up to 8 slots); the delegatee learns of a delegation only if the delegator tells it, and has no syscall to list its own capabilities; `revoke_subject` can revoke a capability of the same group held by another subject (all in the same tenant, because delegation across tenants is refused).

### I-05 — Tenant separation (Amplification (WIP))

Tenant separation must be symmetric across every access path: `read`, `write`, and `delete`. The write path explicitly validates tenant membership, while `read_object_via_capability` currently lacks an explicit tenant check. The read path must perform the same tenant resolution and rejection as write and delete so that asymmetric access paths cannot create an authority leak.

### I-10 — Complete memory validation (Amplification (WIP))

Validation must be atomic with respect to subsequent access to close TOCTOU windows: interrupts must be disabled or equivalent CPU-level protection applied, or the relevant pages must be pinned for the duration between validation and access. This requirement applies to the user-memory accessors in `kernel/src/user_access.rs` (the unused `copy_from_user` and `copy_to_user` of `memory_validation.rs` were removed) and must also cover ELF segment loading during boot.

### I-12 — IPC is not implicit authority (Amplification (WIP))

Sending an IPC message requires the sender to hold `CAP_IPC_SEND`, validated with the same rigor as an object capability, including state, rights, generation, and revocation checks. Runtime dispatch must verify the sender capability at the same security boundary where receiver capabilities are checked. Status: wired at runtime. `syscall_dispatch` checks the global capability each call needs before anything else (`SendIpc` needs `CAP_IPC_SEND`, `ReceiveIpc` needs `CAP_IPC_RECV`; the two are independent, so sending does not imply receiving: I-13), then `validate_ipc_dispatch_args` requires a valid target, the same tenant as the sender, and `CAP_IPC_RECV` on the target; `ReceiveIpc` only delivers to the caller's own pid. A message is four plain words: it carries no handle and no authority, so naming an object in a message grants nothing (I-12). Not covered: the kernel queue (`IpcManager`) has no bound per target or in total, so a sender with `CAP_IPC_SEND` can grow kernel memory until its target (or nobody) reads; `IpcManager::sender_has_send_capability` and `target_has_recv_capability` are dead stubs that return `true` (the real checks are in the dispatcher; the stubs should be deleted so nobody trusts them); there is no end-to-end test of two real processes exchanging a message in QEMU (`pipe-demo` exercises the path from the root shell only); IPC denials are not audited.

### I-16 — No memory residue (zero-on-free)

Freed physical frames or object payload buffers must not reveal previous data to a later use.

```text
freed(frame|payload) => content == 0 before reuse
```

Implementation: `deallocate_frame_with` scrubs the frame (volatile writes) under the allocator lock before clearing the bit (`kernel/src/memory/frame_allocator.rs`). The kernel heap is a `ZeroOnFree` allocator (`kernel/src/zero_alloc.rs`): every freed block, including replaced or deleted object payloads and temporary copies of user data, is zeroed before it is returned to the inner allocator.

Not covered: frames that were never allocated by this allocator (firmware/boot data), DMA buffers, device-mapped regions, cold-boot and cache remnants, and bytes that never reach `dealloc` (e.g. a leaked buffer or stack copies).

### I-17 — Single owner of a physical frame (no double-free / no aliasing)

A physical frame belongs to at most one active context; freeing twice or freeing an unallocated frame is rejected.

```text
owners(frame) <= 1 AND double_free(frame) => deny
```

Implementation: a second bitmap (`owned`) marks frames handed out by `allocate_frame`; `deallocate_frame_with` rejects unaligned, out-of-range and not-owned frames (double free, never allocated, or reserved for kernel/firmware) without scrubbing or changing state. Allocated frames are unique. Not covered: sharing frames between contexts (no refcounts yet) and who the owner is (it is a single allocator-level owner bit, not a per-process record).

### I-18 — Verified and range-bounded code loading

No binary (kernel or userland) executes without a valid signature, and its segments only write within the reserved region.

```text
load(image) => verified_signature(image) AND all_segments_within_region(image)
```

Implementation: `trunomy-bootcore` (`bootcore/src/sig.rs`, `elf.rs`), shared by the bootloader and the kernel loader. Signatures use `verify_strict` (non-canonical signatures and weak keys are rejected). `plan_load` validates the whole ELF before a byte is copied: x86_64 `ET_EXEC`, `file_size <= mem_size`, checked arithmetic, source inside the file, destination inside `[0x200000, 0x200000 + 16 MiB)`, no overlapping segments, no segment both writable and executable, base equals the link address, and the entry point inside an executable segment. `load_into` zeroes the whole region and copies with bounded slices. A kernel found without its `.sig` is refused with an explicit message. Not covered: the firmware/kernel identity map is still not W^X; a compromise of the kernel key (I-39 separates the roles, it does not protect that key); rollback of an older signed kernel is handled by I-49 (with its limits); there is no measured boot or TPM.

### I-19 — Trust is not inferred from data

Trust mode (dev/prod, signed/unsigned) comes from explicit build configuration, never from the content of a key or datum.

```text
trust_mode = build_config, NOT inferred(key_bytes)
```

Implementation: there is no dev mode at all. Verification is unconditional; an all-zero or small-order key is an error (`BadKey`), never a switch. There are two role-specific trust constants (I-39), `KERNEL_SIGNING_PUBLIC_KEY` and `SHELL_SIGNING_PUBLIC_KEY` in `trunomy_abi::trust`; `build_os.sh` aborts if either differs from its PEM in `.keys/`. If a dev/prod distinction is ever added it must be a compile-time feature of the build, not derived from data.

### I-20 — Atomic validate-then-access

Between validating a user range and accessing it there must be no observable mapping change.

```text
validated(ptr,len) AND access(ptr,len) => no_remap_between(validate, access)
```

Implementation: validation and access are one step. `ActiveUserSpace::read`/`write` check the range (canonical, lower half, no overflow) and the page permissions (present, user, writable) and perform the copy inside the same call, in the SMAP window (I-37); `UserSlice` keeps only `(ptr, len)`, it is a descriptor and not a proof of validity, so a mapping or permission that changes between building the slice and using it is caught at the access (`a_slice_is_not_a_proof_of_validity_*`, `a_permission_that_changes_*`). A rejected access modifies nothing (`a_rejected_write_leaves_the_user_memory_untouched`). Reads are a single copy into kernel memory, and only the copy is used afterwards (no double fetch). Why no remap can happen between the check and the copy: syscalls enter with IF=0 and run on one CPU, a process has exactly one task, there is no `mmap`/`munmap`/shared-memory syscall, and the kernel is the only writer of page tables (`ConsoleRead` composes the line in a kernel buffer and copies out once, so its interrupt windows never separate a check from its access).

Not covered: SMP (a second CPU could change another task's mappings; there is none), any future syscall that maps or unmaps memory or shares it between processes (it would need its own argument), and memory the kernel itself may unmap or reclaim while a syscall holds a range. The page-permission check only runs when a user PML4 is registered; the range check always runs. The hardware path (SMAP window, real page tables) is exercised by every syscall in QEMU but has no dedicated fault-injection test.

### I-21 — Every authorization decision is recorded, boundedly and without content

Every allow/deny decision on the capability and object path (read, write, delete, grant, delegate, revoke) leaves an audit event with subject, operation, handle, outcome and, when the handle resolves, tenant and resource. The log is bounded; losing old events is counted, never silent. Events never contain object payloads.

```text
decision(subject, op, handle) => exists audit_event(subject, op, handle, outcome)
len(audit_log) <= AUDIT_CAPACITY  AND  overwritten counts every dropped event
audit_event contains no payload bytes
```

Context: `kernel/src/audit.rs`. Not yet covered: IPC denials and pointer-validation denials, and reading the log from Ring 3 through a capability-protected syscall.

### I-22 — Time and use limits only narrow

A delegated capability never outlives its parent and never carries more uses than its parent has left; the child's uses are charged to the parent. An expired or exhausted capability is denied, and an expired or exhausted parent cannot delegate.

```text
child.expires_at <= parent.expires_at   (when the parent has a deadline)
child.max_uses   <= parent.remaining_uses; parent.remaining_uses -= child.max_uses
now >= expires_at  OR  remaining_uses == 0  =>  deny
```

Context: `kernel/src/capabilities.rs` (`delegate_limited`, `authorize_at`). Uses are consumed when authorization succeeds, even if the operation later fails. Expiry depends on `clock::advance`, which no timer drives yet.

### I-23 — Kernel access to user memory is single-copy and length-bounded

The kernel touches user memory only through `user_access` (`UserSlice` + `UserSpace`). Reads copy once into kernel memory and the copy is the only thing used afterwards; the requested length is capped by a kernel maximum before any allocation; writes never exceed the data being delivered nor the buffer the user offered (`BufferTooSmall` otherwise). Range is always checked; page permissions are checked when a user PML4 is active.

### I-24 — Object syscalls act only as the calling process

`ObjectCreate/Read/Write/Delete` and `CapDerive/CapRevoke` take the identity (subject, tenant) from the process table, never from an argument. Authority is the presented handle (creation additionally needs the global `CAP_OBJECT_CREATE`). Delegation across tenants is refused, derived rights only narrow, creation is atomic with its capability (no orphan object when the capability quota is hit), and every decision is audited, including `Create`.

### I-25 — Session identities are administered, bounded and audited

Until a scheduler exists, the session leader (pid 1) may create tenants and actors and act as one of them (`SwitchIdentity`), but only while it holds the global `CAP_ADMIN`; only session members may do so; tenants (8) and actors (16) are bounded; every identity change is audited; the audit log is readable (`AuditRead`) only by session members. Actor ids start at 1000, away from the pids and subjects of the root shell, so a new actor never inherits another subject's capability book. This is a transitional mechanism: with real processes `SwitchIdentity` is removed.

### I-26 — Physical memory is handed out only from firmware-declared usable memory

The frame allocator starts with every frame reserved and frees only what the firmware memory map declares usable (`EfiConventionalMemory` after `ExitBootServices`), below 4 GiB and above the first MiB, minus the kernel image, the shell image, the `BootInfo` page and the region table. Reserved wins over usable on overlap; malformed, misaligned or overflowing regions are ignored. The kernel validates the `BootInfo` pointer, magic, descriptor size and table bounds before use and, if anything is wrong, falls back to the conservative defaults (4 GiB assumed, first 32 MiB reserved) and says so on the serial port. Bootloader and kernel share one definition of the contract (`trunomy-abi::boot`).

### I-27 — Kernel time is monotonic and comes only from the timer

The kernel clock advances only from the timer interrupt (PIT channel 0 at `TICK_HZ` = 100 Hz through the remapped 8259 PIC, IRQ0 only; every other line stays masked) and never goes backwards. The handler takes no lock (one atomic), so it cannot deadlock against interrupted code. Interrupt entry from Ring 3 uses a dedicated `TSS.rsp0` stack and #DF uses IST1; syscalls run with IF=0 and only `ConsoleRead` opens short interrupt windows while it waits for input. Capability expiry (I-22) therefore compares against a clock that actually moves. Userland can read the clock (`ClockNow`) but not set it. Bisect switch: `interrupts::TIMER_ENABLED`.

Not covered: LAPIC/APIC and SMP, timer calibration against another source, clock drift, and preemption (the tick does not yet reschedule anything).

### I-28 — Scheduling is fair, bounded and never runs a task that cannot run

The scheduler is round-robin with a fixed quantum. A task is queued at most once and only while `Ready`; at most one task is `Running` and it is the current one; `Blocked` and `Exited` tasks are never chosen; sleepers wake when the kernel clock reaches their deadline; with N ready tasks each one runs within N x quantum ticks; the task table is bounded (`MAX_TASKS`) and a pid is not reused while it exists. `Scheduler::check_invariants` states these and a 5000-step randomized storm checks them after every operation.

Not covered yet: priorities, per-task CPU quotas, and revoking a task's capabilities on exit. The real context switch is I-29.

### I-29 — A context switch never mixes tasks' stacks, address spaces, identities or registers

Each task owns a kernel stack; `TSS.rsp0` and the syscall stack always point at the running task's stack. The user `rsp` of a syscall is saved on that stack, not in a global, so a task can be suspended inside a syscall (keyboard wait) while another one makes its own. On every switch the kernel restores the incoming task's CR3, active-user-PML4 and `ProcessContext`, so `current_process()` and user-pointer validation always describe the task that runs. A new task enters Ring 3 through `iretq` with all caller-saved registers zeroed and callee-saved ones zero (nothing from the kernel leaks). The timer path takes the scheduler with `try_lock` and acknowledges the PIC before switching. Interrupts are open only in Ring 3 and in `irq_window()`, where no kernel lock is held. The test task has no capabilities and runs from a read-only, executable user page.

Not covered yet: FPU/SSE state (the target is soft-float, so there is none), SMP, freeing a task's kernel stack and address space on exit, per-process identity replacing `SwitchIdentity`.

### I-30 — Console input is interrupt-driven, bounded and never loses a wake-up

COM1 IRQ4 drains the UART FIFO into a fixed lock-free ring buffer (single producer in the interrupt, single consumer in `ConsoleRead`). A full buffer drops the new byte and counts it; unread bytes are never overwritten. A reader with nothing to read sleeps in the scheduler (`block_current`) when another task can run, otherwise the CPU halts with `sti; hlt`; it does not poll. Between the empty-buffer check and the block interrupts are closed, so IRQ4 cannot slip in unseen. Only one task may sleep as input waiter; the wake-up is delivered once (`take_waiter`), by IRQ4 with `try_lock` and again by the timer tick if input is still pending, so a busy scheduler delays a wake-up but never loses it.

Not covered yet: console ownership (any task can call `ConsoleRead` and take keystrokes: it needs a console capability), input line discipline in the kernel, multiple waiters, and keyboard (PS/2) input.

### I-31 — A process acts only with the identity it was born with, and only the session leader can create one

`SwitchIdentity` no longer exists. An actor acts as a real process: `ProcessSpawn(actor, args)` creates a process with its own address space (built from the firmware base PML4, never from the caller's), its own kernel stack and the identity of that actor, running only the image that passed Ed25519 verification at boot (the caller cannot supply code). Only the session leader holding `CAP_ADMIN` can spawn, only for actors of its session, and every spawn is audited. Actors cannot create tenants or actors, read the audit log or spawn. A live pid cannot be spawned twice; `ProcessWait` is allowed only to the parent, delivers the exit code once and reaps the child (kernel stack and address space returned, frames zeroed on free: I-16/I-17). Only a spawned process can exit; the process table and kernel stack pool are fixed-size, so a spawner cannot exhaust kernel memory. Arguments (1..=256 bytes) reach the child on a read-only page.

Not covered yet: orphan handling when a parent dies, killing a running child, capability inheritance beyond what `cap derive` already delegates, `destroy` assumes firmware page-table leaves are not user-accessible.

### I-32 — No user page is writable and executable at the same time

Every user mapping is created through `map_user_page`, which refuses `writable && executable` (`wx_allowed`). The user image is loaded by region: `text` R-X, `rodata` R-- (no execute), `data`+`bss` RW- (no execute); stack, arguments page and VGA are never executable. The region boundaries come from a 64-byte descriptor at the end of the image (`abi/src/image.rs`, written by `userland/shell/linker.ld`), read from the payload only after its Ed25519 signature has been verified. A missing, misaligned, inconsistent descriptor or an entry point outside `text` makes the loader refuse the image (fail closed). The kernel sets `EFER.NXE` explicitly so the NX bit is honoured.

Not covered yet: the kernel's own pages (identity map from the firmware) are not W^X; the spinner and shell share the layout policy but there is no per-process W^X audit at runtime; guard pages below the user stack; SMEP/SMAP.

### I-33 — A CPU fault in Ring 3 terminates the faulting process, never the system

Every CPU exception a user process can provoke (#DE, #DB, #BP, #OF, #BR, #UD, #NM, #TS, #NP, #SS, #GP, #PF, #MF, #AC, #XM) enters through a stub (`kernel/src/faults.rs`) that records `(vector, error code)` and calls `exception_entry`. If the interrupted code was Ring 3 (`CS.RPL == 3`), only that process is terminated with exit code `abi::exit::fault(vector)`, the event is audited (`AuditOp::ProcessFault`) and a parent sleeping in `ProcessWait` is woken. The exit-code range `0xFFFE…` is kernel-only: `ProcessExit` rejects it, so a parent that sees it knows the kernel terminated the child and the code cannot be forged by the child. A fault in Ring 0 (a kernel bug) or in the root shell (the session leader, which is not in the process table) still halts the machine.

```text
fault(user process P) => terminated(P) AND other processes unaffected AND audited
fault(kernel) OR fault(root shell) => halt
```

Not covered: the stubs and the real fault-to-switch path only run on hardware (needs QEMU: `selftest fault` as a user); #DF, NMI and #MC still halt; a fault inside a syscall (Ring 0 touching user memory) still halts (I-20); a handle with generation >= 0xFFFE0000 (4.29e9 revocations of one slot) would be rejected by `ProcessExit` instead of returned.

### I-34 — Only a parent can kill its child, every attempt is audited, and a hung child is bounded

`ProcessKill(pid)` succeeds only for the caller's own live child (`ProcTable::kill` checks parent and state); the child is removed from the scheduler and the console waiter slot, exits with `abi::exit::KILLED`, and is freed when the parent reaps it. Permitted and denied attempts are audited (`AuditOp::ProcessKill`, subject = caller, resource = target). `ProcessWait(child, out, timeout_ticks)` kills a child still alive at the deadline (exit code `abi::exit::TIMEOUT`) and reaps it; the deadline is mandatory since I-40; the shell uses a 10 s deadline for every worker it launches.

Not covered: a child that is never waited for stays a zombie holding its stack and address space (the table is bounded to `MAX_PROCS`); CPU and memory quotas are I-40.

### I-35 — The operator console and halting the machine are authority, not ambient rights

`ConsoleWrite` and `ConsoleRead` require the global capability `CAP_CONSOLE` (0x0006) and `Halt` requires `CAP_ADMIN` (0x0005); `seed_root_capabilities` grants them only to the root shell (pid 1). Actors, and therefore workers, receive only `CAP_OBJECT_CREATE`, so a worker can neither write to the operator's console (spoofing the operator) nor stop the machine. A worker reports through `ProcessOutput(ptr, len)`: at most `MAX_OUTPUT` (256) bytes per process, all-or-nothing, only while the process is alive and in the process table; the parent receives them in the `ProcessWait` buffer (`[code: u64][len: u64][bytes; 256]`, written in one copy-out) and nobody else can. The shell prints that output (and object contents shown by the root) as printable ASCII only, so it cannot carry terminal controls. A worker panic ends that worker (`ProcessExit`); only the root shell halts. `audit` shows `resource`; the exception dump prints CR2 only for #PF (other vectors would leak the last page-fault address, possibly another process's).

Not covered: (console and `Halt` denials are audited since I-41); `ConsoleRead` still writes through a raw pointer instead of the `user_access` layer; output beyond 256 bytes is rejected, not streamed; a worker's own exit code is not authenticated beyond what the kernel records.

### I-36 — A stack overflow faults instead of corrupting the memory next to it

Every kernel stack (one per task, the interrupt stack, the #DF stack and the initial syscall stack) is a `GuardedStack<N>`: a 4 KiB guard page sits directly below the usable stack. At boot, before any address space is created, `guard::install_base` removes those pages from the base page tables (the bootloader's 2 MiB identity map is split into 4 KiB pages with identical permissions, only the guard leaf is cleared; the new tables are not `OWNED`, so `destroy` never frees them). Address spaces copy the base PML4 entries and share its lower tables, so they inherit the guards, and `create_task` additionally runs `guard::verify_space(cr3)` and refuses to create a task whose address space maps any guard (fail closed, no ordering assumption). If the guards cannot be installed the kernel halts at boot. The base tables belong to the firmware and may be mapped read-only (a write with CR0.WP set faults with P=1, W=1), so the edit runs inside `without_write_protect` (WP cleared, interrupts closed, both restored afterwards). The user stack is separated from the read-only args page by an unmapped page (`USER_STACK_BASE` = `ARGS_VADDR + 0x2000`); `selftest stack` makes a worker overflow its stack and the fault is contained like any Ring 3 fault (I-33).

Not covered: a kernel stack overflow is detected, not survived: the fault is taken on the overflowing stack, escalates to #DF and halts the machine (fail-stop instead of silent corruption); the very first boot stack (set by the bootloader) has no guard; stack size is fixed at 16 KiB (no probing of large frames, so a single frame larger than the guard page can jump over it); the guard is a page-table property: it relies on the base tables not being remapped later (patch 22 touches the same tables and must keep `verify_space` green).

### I-37 — The kernel does not execute data, write its own code, or touch user memory outside one window

At boot, before any address space is created, `cpu::harden` enables EFER.NXE (mandatory: without NX the kernel halts), CR0.WP and, when the CPU reports them, SMEP and SMAP; `kmap::apply_base` (inside `guard::without_write_protect`, because the firmware's tables may be read-only) then sets the kernel image permissions in the base tables from linker symbols: header and `.rodata` read-only and non-executable, `.text` read-execute and never writable, `.data`/`.bss` read-write and non-executable, and every other page of the 4 GiB identity map non-executable. The image is updated first and the rest of RAM afterwards, so `.text` never carries NX in the tables while it runs; 2 MiB pages that straddle a boundary are split into 4 KiB pages with identical flags, the pointer entry of a split is permissive (effective permission comes from the leaves) and guard pages (I-36) stay unmapped. With SMAP active the only code that reads or writes user memory is `cpu::user_window` (`stac`/`clac`), called from `ActiveUserSpace::{read, write}` and the legacy `copy_*_user`; `ConsoleRead` composes the line in kernel memory and copies it once through `ActiveUserSpace` (the previous raw pointer write is gone). `create_task` runs `kmap::verify_space` (every image page has its region's permissions, none is writable and executable, sampled RAM is non-executable) and refuses the address space otherwise.

Not covered: SMEP/SMAP are skipped with a warning on CPUs without them (`REQUIRE_SMEP_SMAP` makes it fatal) and need `-cpu max`/`host` in QEMU; only `0..4 GiB` is hardened (memory the firmware maps above it is untouched); a linker orphan section placed after `__kernel_end` would be data, not code; the `stac`/`clac` window is not saved per task, so it must stay short and never yield; the user-mapped VGA page and the page tables themselves are RW-NX but not otherwise isolated; no KASLR, so the kernel layout is fixed.

### I-38 — The kernel runs on page tables it built, not on the firmware's

`memory::ident::install` builds, in frames reserved through the frame allocator, a PML4 -> PDPT -> 4 PD hierarchy that identity-maps `0..4 GiB` (the range the frame allocator manages) with 2 MiB pages, present and writable, without USER or NX (`kmap` hardens them afterwards, I-37), and loads it into CR3 before any address space is created (so every process copies these tables, not the firmware's). Before switching it checks that what the kernel is using right now (the running code, the stack, the new table itself, the `BootInfo` and the VGA page) is identity-mapped in the new tables; if anything is missing or no frame is available, CR3 is not touched and the kernel continues on the firmware tables with a warning (`OWN_PAGE_TABLES = false` forces that path). This removes the dependence on tables that may be read-only, that carry global or differently sized pages, or that sit in memory the firmware memory map reports as usable and the allocator could hand out.

Not covered: the old firmware tables are left in place (not freed, not scrubbed); MMIO and anything above 4 GiB is unmapped (the kernel uses port I/O only, so nothing needs it today); every mapping is write-back (the VGA page and any MMIO would need PCD/PAT attributes if cached access ever matters); a failed switch falls back to the firmware tables instead of halting.

### I-39 — Signing keys are separated by role

The key that signs the shell image cannot sign a kernel, and vice versa.

```text
verify(kernel ELF)  uses KERNEL_SIGNING_PUBLIC_KEY   (bootloader)
verify(shell image) uses SHELL_SIGNING_PUBLIC_KEY    (bootloader with LOAD_SHELL, kernel loader)
KERNEL_SIGNING_PUBLIC_KEY != SHELL_SIGNING_PUBLIC_KEY, neither all-zero
```

Implementation: `trunomy_abi::trust` holds two constants. The bootloader checks the kernel `.sig` with the first; the shell image (payload || 64-byte signature) is checked with the second, both by the bootloader (when `LOAD_SHELL` is on) and by the kernel before spawning the first process. `build_os.sh` signs the shell with `.keys/shell-ed25519-private.pem` and the kernel with `.keys/kernel-ed25519-private.pem`, and aborts unless each constant equals the public key of its PEM and the two differ. `scripts/provision-keys.sh` creates the shell key pair if missing (the private key never enters the repository) and rewrites the shell constant; until it is run the constant is all-zero, which bootcore rejects (`BadKey`), so an unprovisioned tree fails closed instead of trusting anything. `scripts/ci.sh keys` checks the public constants (non-zero, distinct).

Not covered: the embedded shell is part of the kernel ELF (`include_bytes!`), so it is ALSO covered by the kernel signature; separation only means a leaked shell key cannot produce a bootable kernel, and it cannot defend against a leaked kernel key (which signs a kernel that embeds any shell and any key constants). The keys are plain PEM files on the build machine (no HSM, no passphrase, no rotation or revocation: changing a key means rebuilding and re-signing everything); rollback protection is I-49.

### I-40 — Every wait is bounded and every spawned process has CPU and memory quotas

A parent cannot sleep forever on a child, and a worker cannot consume unbounded CPU or memory.

```text
ProcessWait: 1 <= timeout_ticks <= MAX_WAIT_TICKS (6000 = 60 s), else InvalidArgument with no effects
cpu_ticks(worker) <= WORKER_CPU_TICKS (200 = 2 s); over -> stopped, parent kills it with exit::CPU_QUOTA
spawn allowed only if frames_needed(image) <= MAX_PROCESS_FRAMES and free - needed >= KERNEL_RESERVE_FRAMES
```

Implementation: `wait_with` rejects `timeout_ticks == 0` or `> MAX_WAIT_TICKS` before touching the child (`timeout_ticks = 0` used to wait forever). `sched::Scheduler::on_tick` counts the CPU ticks the current task actually runs (`ticks_run`); at its `cpu_limit` the task is flagged `over_quota`, wakes the parent registered with `watch`, and, if anyone else is ready, is stopped (Blocked, never made ready again: `make_ready` refuses it, so neither a wake-up nor a deadline revives it). The scheduler never kills anything from the timer interrupt (no process-table lock in IRQ context): the parent, in `wait_with`, sees `cpu_quota_exceeded(child)`, kills it (audited like any `ProcessKill`) and reaps it with `abi::exit::CPU_QUOTA`. `quota::admit` is checked in `spawn_with` before any state is reserved (`QuotaExceeded`); `frames_needed` is an upper bound from the verified image size (code, 4 stack pages, args page, page tables). A process allocates nothing after it is born (no `brk`/`mmap`), so its cost is fixed at spawn and, with `MAX_PROCS` live processes, total worker memory is bounded.

Not covered: the CPU quota counts timer ticks (10 ms granularity; a task that runs less than a tick between interrupts is under-counted); only workers have a CPU quota (the root shell and kernel tasks have none); if nothing else is ready, an over-quota task keeps the CPU (flagged) until someone else becomes ready or its parent kills it; a stopped worker holds its memory until its parent waits for it; there is no per-tenant or per-actor aggregate quota (each process is limited, the set of processes only by `MAX_PROCS`); the memory limits are policy constants (`MAX_PROCESS_FRAMES`, `KERNEL_RESERVE_FRAMES`) not tuned against measurements; a denied spawn is not audited as a quota denial; I/O and IPC bandwidth have no quota.

### I-41 — Denied console use and every halt are audited, without letting the log be flooded

A process that tries the operator console or `Halt` without the capability leaves a record, and nobody can use those denials to erase the audit history.

```text
denied ConsoleWrite/ConsoleRead -> AuditOp::Console (resource = syscall number), at most DENIAL_BURST (4) per (subject, syscall)
Halt denied  -> AuditOp::Halt, Denied, with a bigger budget (HALT_BURST 16 per key) but still bounded (I-48)
Halt allowed -> AuditOp::Halt, Allowed, recorded, and printed on the serial line before the machine stops
denied_total counts every denial, stored or not; suppressed counts those not stored
```

Implementation: `validate_required_capability_for` (in `syscalls.rs`) calls `syscall::audit_privileged_denial` when the global capability check fails (the capability-book lock is already released; the audit lock is taken last, as everywhere). Allowed `ConsoleWrite` is not audited (one syscall per character: it would evict everything useful). Console denials go through `AuditLog::record_throttled_denial`, which remembers up to `THROTTLE_KEYS` (32) `(subject, operation, resource)` keys and stores only the first `DENIAL_BURST` of each; a process that repeats the denial a million times adds four events and a counter, and the existing events stay (`overwritten` stays 0). `Halt` attempts get a bigger budget than other denials (`HALT_BURST` 16 per key, `HALT_OP_CAP` 32 per subject) and are all counted; before I-48 they had no limit at all, so a user looping `halt` could fill the ring. The record carries subject, tenant and the syscall number, never data. The audit ring lives in memory, so an allowed `Halt` also prints `[KERNEL] Halt solicitado por el proceso ...` on the serial line. `selftest console` (as a user) makes a worker try both and shows the verdict; the denials then appear in `audit` as `console -> denied` and `halt -> denied`.

Not covered: the throttle is per key for the life of the key (no refill over time): after four denials a persistent attacker's further attempts are only counted, and forgetting a key after 32 other keys means a very long run of distinct subjects could re-open its budget; the flood gaps this section used to list (older denied object/capability events going straight into the ring, a fresh key per varied resource) are closed by I-48; the ring is in RAM (256 events) and is lost on halt or reset; denied attempts at other privileged calls (spawn, tenant/actor creation) are audited by their own paths, not by this one.

### I-42 — What the shell prints about the machine is what the kernel says, authorized per query

`free`, `ps`, `whoami`, `id`, `caps` and `tenant list` no longer print fixed text. They call `SystemInfo` (0x58) and show the kernel's answer; the kernel decides who may ask what.

```text
Identity     (pid, tenant, subject)                      any caller, about itself
TenantUsage  (objects, max, bytes, max per object)       any caller, ITS tenant only
Caps         (active capabilities of a subject)          own: any caller; another subject: session leader, session members only
Memory       (frames total/free, kernel heap total/used) session leader (CAP_ADMIN) only
Processes    (leader + child table)                      session leader only
Actors       (pid, tenant of each session actor)         session leader only
```

Implementation: `kernel/src/syscall/info.rs` (authorization inside the handler, `required_capability` is `None`), `CapabilityBook::entries_of` (active entries only, read-only: it consumes no uses and writes no audit), `ObjectStore::bytes_for_tenant`, `allocator::heap_stats`, `ProcTable::entries`. Formatting is pure code in `libtrunomy/src/sysinfo.rs`. `free` runs as the current identity: root sees real frames and heap; a user sees only its own tenant's quota (a user must not learn the machine's memory). `tenant list` prints tenant -> users -> capabilities; the names are the shell's convenience, membership and permissions are the kernel's. `halt` now goes through the worker path, so a user is denied by the kernel and the denial is audited (I-41). `pipe-demo`, pipelines and `reboot` say plainly they are not implemented instead of narrating a fake run; `ls` lists only the handle names the current identity holds.

Not covered: the shell's names are not authenticated (a rename is a shell lie; pids, tenants and rights are not); `ps` shows only pids and states, no names or CPU use; `Caps` lists at most 16 entries (the per-subject cap), and a worker's one-line output truncates with `...` after 256 bytes; the memory figures are a snapshot and the frame count includes frames the kernel itself holds; there is still no filesystem.

### I-43 — The IPC queue is bounded, authority is explicit, and every denial is audited

A sender cannot grow kernel memory without limit or crowd out another process's queue, nobody receives IPC authority by default, and a refused send leaves a record.

```text
pending(target) <= MAX_QUEUED_PER_TARGET (8)      pending(all) <= MAX_QUEUED_TOTAL (32)
actor_create(tenant, flags): CAP_IPC_SEND and CAP_IPC_RECV only if FLAG_IPC; unknown flag => InvalidArgument, nothing created
send denied (other tenant | target without CAP_IPC_RECV | full queue | caller without CAP_IPC_SEND) => AuditOp::Ipc, resource = target pid (or the syscall number)
```

Implementation: `ipc/manager.rs` (`enqueue_message` returns `IpcError::{Invalid, TargetFull, QueueFull}`; the dead `sender_has_send_capability` / `target_has_recv_capability` stubs that returned `true` and the unreferenced `ipc_handlers.rs` are deleted), `syscalls.rs` (`audit_ipc_denial`, `enqueue_checked`: a full queue is `QuotaExceeded`), `syscall/mod.rs` (`audited_op`: `SendIpc`/`ReceiveIpc` -> `AuditOp::Ipc`; only `Halt` skips the throttle), `syscall/identity.rs` (`actor_create_with`; granting IPC is audited as `AuditOp::Grant`, resource = the actor's pid). IPC denials use the same per-(subject, operation, resource) burst limit as the console (I-41), so repeating one cannot evict other events. Allowed sends are not audited (they would flood the ring). In the shell: `user create <name> <tenant> ipc` and `ipc send <user> <text>` / `ipc recv`; each runs in the identity's own worker. The queue outlives the sending worker, so a message from one worker is received by a later worker of the target actor.

Not covered: messages carry no authority and no sender identity (the receiver gets the payload only); a message to an actor that never receives stays queued until the per-target limit; there is no per-tenant queue quota (only per target and global); an actor with `ipc` can fill another same-tenant actor's queue (8 messages) and so deny it more messages: availability inside a tenant is not protected; the end-to-end path between two worker processes runs only in QEMU.

### I-44 — The network device is discovered within bounds and left inactive until it is validated

PCI is scanned within fixed limits (buses 0..8, at most 64 functions, bridges are not followed). The only device the kernel touches is a legacy virtio-net (`1af4:1000`) whose BAR0 is I/O space. Bring-up resets the device with a bounded wait, acknowledges it, accepts only the `MAC` and `STATUS` features, reads the MAC and the link, and stops there: it enables only the I/O-space bit of the PCI command register (16-bit write, so RW1C status bits are never touched), never enables bus mastering, never sets `DRIVER_OK` and creates no queues. Activation is a separate, explicit step: `NetControl(UP)` (leader only, audited, never automatic) re-negotiates the device, builds BOTH queues first (size read from the device and checked, queue must be unused, contiguous frames for ring + 16 buffers of 2 KiB, ring zeroed, receive buffers posted), registers them, and only then enables bus mastering and sets `DRIVER_OK`, reading the status back: a device that refuses is reset. Any failure leaves bus mastering off and the device reset, and queue memory is returned (wiped) only if the reset was confirmed; otherwise it is withheld on purpose, because the device might still write it. `NetControl(DOWN)` does the same on demand. A device that fails any step is marked failed and reported with its reason; a modern-only device is reported as unusable. The hardware inventory (`SystemInfo(NET)`, `net info`) is leader-only.

Implementation: `net/pci.rs` (`scan`, `enable_io_space`, `enable_bus_master`), `net/virtio.rs` (`init`, `InitError`), `net/nic.rs` (`activate`, `Nic::{send, recv, shutdown}`, `DmaHost`), `net/arp.rs` (`selftest`), `net/mod.rs` (`probe`, `control`, `info_words`, `stats_words`), `memory/frame_allocator.rs` (`allocate_contiguous`), `syscall/netctl.rs`, `syscall/info.rs` (`NET`, `NET_STATS`), shell `net info|stats|up|down|selftest`. All hardware access goes through the `Io` trait, so the logic is tested on the host against simulated devices (including a device that never finishes the reset).

Not covered: frames are not yet tied to any tenant (no network capabilities or endpoints: that comes next), so only the leader can drive the device; everything is polled (no interrupts; a long `net selftest` blocks the caller); DMA, IOMMU and real device timing are NOT validated by QEMU, which emulates them permissively, so isolation of device memory access is unproven until real hardware; only the first virtio-net is used; modern virtio (MMIO/PCI capabilities) is not supported.

### I-45 — A tenant can be cut off in one operation, and nothing of it survives the cut

`Halt` stops the whole machine; a compromised tenant needs a cut that leaves the others running. `TenantPanic(tenant, flags)` (session leader with `CAP_ADMIN` only) does, in order: (1) freezes the tenant and retires every actor of it, so it admits no new actors and none of its identities can be spawned again (a refused spawn is audited); (2) kills the live processes of those actors and reaps them and any unreaped zombie (each kill audited); (3) revokes every capability of those actors and the ones derived from them, so handles they already knew stop working; (4) drops every pending IPC message sent by or to them; (5) with `FLAG_WIPE`, deletes the tenant's objects (their payloads are zeroed on free, I-16); (6) records `AuditOp::Panic`. An invalid tenant or flag changes nothing. Repeating it is harmless. A non-leader attempt is denied, audited and throttled (I-43). `TenantThaw(tenant)` reopens the tenant for NEW actors only: retired identities stay retired and without capabilities.

Implementation: `syscall/lockdown.rs` (`tenant_panic_with`, `tenant_thaw_with`), `syscall/identity.rs` (`Session::{quarantine, thaw, actor_state}`, checks in `authorize_spawn` and `actor_create_with`), `capabilities.rs` (`revoke_subject`, `purge_tenant`), `ipc/manager.rs` (`purge_pids`), `SystemInfo(ACTORS)` third word (`ACTOR_RETIRED`, `ACTOR_TENANT_FROZEN`), shell `tenant panic <name> [wipe]`, `tenant thaw <name>`. Each phase takes its locks separately (never nested).

Not covered: only the leader can trigger it (there is no tenant administrator, and no automatic trigger such as a quota or audit threshold); without `wipe` the tenant's objects remain in memory, unreachable but not destroyed, and keep counting against its quota; retired names stay used until reboot; a tenant with no actors has no record to show `[FROZEN]` in `tenant list`; objects shared outside the tenant do not exist (I-05), so there is nothing to cut beyond it; once a network layer exists its tenant-bound endpoints must be closed by this same operation (there are none today); the end-to-end behaviour with a live worker only runs in QEMU.

### I-46 — The kernel never believes what the network device reports about its queues

A virtqueue is memory shared with a device the kernel does not trust. `net/vring.rs` keeps the truth in kernel memory: what was published (address, length, direction of each buffer) is a shadow copy and the shared descriptor table is never read back, so rewriting it changes nothing. The kernel only programs addresses inside a fixed DMA window (checked arithmetic, non-zero length). Everything the device reports is validated: `used.idx` cannot run ahead of what was published, the returned id must be a descriptor in flight and cannot be completed twice, and the length cannot exceed the buffer. Any violation poisons the queue for good: nothing more is read or published (fail closed). The queue memory starts zeroed and indices wrap at 16 bits. `DmaPool` hands out fixed slots and takes back only its own, once.

Status: verified on the host against a simulated device that lies, and connected to the device in `net/nic.rs` (I-44): queue memory, registration, bus mastering and notification exist, and `net up` + `net selftest` exercise them in QEMU.

Not covered: without an IOMMU the window limits what the kernel ASKS the device to touch, not what a malicious or buggy device could DMA on its own; QEMU does not model that, so only real hardware with an IOMMU can show it. Interrupt-driven completion and notification suppression are not handled (polling only). Legacy virtio only.

### I-47 — Network authority is a capability, the owner of a port is set by the kernel, and nothing from the wire is believed

A process can use the network only through a global capability (`net.send` to send; `net.recv` to bind, unbind and receive), granted only when the leader creates the user with `net`; without it the dispatcher answers `InvalidCapability` and audits the refusal (throttled, like I-43). The capability is only the door. A **port** is a numeric endpoint bound by one process: the kernel records its owner (pid, tenant, subject) from the caller at bind time, and nothing a frame says changes that. Only the owner receives, unbinds or sends from a port; another process's port is indistinguishable from a nonexistent one (`ObjectNotFound`) and the attempt is audited (resource = port), so a process cannot spoof a source port or read another tenant's messages. Quotas: 16 endpoints in total, 4 per tenant, 8 queued messages of at most 256 bytes per endpoint, and at most 16 frames taken from the device per `NetRecv`; what does not fit is dropped and counted (`net stats`, "protocol drops"), so the network cannot grow kernel memory or monopolise the CPU. Everything that arrives is hostile: `abi::netproto::parse` is total and strict (known magic and version, non-zero ports, length within the frame and within 256 bytes, zero padding), frames not addressed to this machine are dropped, and the peer's MAC and port are handed to the receiver only as unauthenticated data, never as identity (I-09). Endpoints are closed (and their queues discarded) when the owner exits or is killed and when its tenant is cut off with `tenant panic` (I-45). A destination MAC of all zeros, or our own, delivers inside the kernel under the same rules (`net loopback`).

Implementation: `abi/src/netproto.rs` (`parse`, `build`), `net/endpoint.rs` (`Table`: `bind`, `unbind`, `deliver_frame`, `recv`, `close_pid`, `close_tenant`), `syscall/netio.rs` (`net_bind_with`, `net_unbind_with`, `net_send_with`, `net_recv_with`, `NetPort`), `syscall/mod.rs` (required capabilities, audited denials), `syscall/identity.rs` (`FLAG_NET`), `syscall/lockdown.rs` (closes the tenant's endpoints), `dispatch.rs` (closes a process's endpoints on exit, kill and reap), libtrunomy (`net`, worker requests), shell (`net loopback|listen|send`, `user create ... net`).

Not covered: there is no authentication or encryption of peers (a MAC is not an identity), so what arrives is data for the receiver to judge; reception is polled and only happens while some actor calls `NetRecv` (frames wait in the device's queue meanwhile and the excess is dropped by the device or the kernel); endpoints belong to a process, and user commands run in short-lived workers, so a listener lives only for the length of one command (`net listen` waits at most about a second); only the first virtio-net is used; QEMU does not validate DMA, IOMMU or real timing.

### I-48 — No flood of denials can erase the audit history

Every denial is audited, but a process that repeats denials cannot use them to push other events out of the ring, however it varies them.

```text
every Denied outcome (object, capability, console, Halt, IPC, net, spawn, panic...) goes through one limiter in AuditLog:
  stored only if the key (subject, operation, resource) has used < DENIAL_BURST (4; Halt: 16)
            AND the pair (subject, operation) has stored < DENIAL_OP_CAP (16; Halt: HALT_OP_CAP 32)
  otherwise: denied_total and suppressed go up, nothing is stored
a stored Denied into a full ring evicts the OLDEST DENIED event; it evicts the oldest event of any kind only when the ring holds no denial
Allowed events are never evicted by denials
```

The per-key burst (I-41) was not enough: a process that varies the resource each time (handles, port numbers) opens a new key per attempt and never exhausts a burst, and the older object/capability denials did not use the limiter at all. The per-(subject, operation) cap closes the first; routing `record` itself through the limiter closes the second (callers keep the same API). The eviction rule closes the third: many distinct subjects each get their own budget, but they can only rotate among themselves, so grants, revokes, tenant panics and every other allowed event stay.

Implementation: `kernel/src/audit.rs` (`record`, `record_denial`, `push`, `denial_limits`, `DENIAL_OP_CAP`, `HALT_BURST`, `HALT_OP_CAP`, `OP_BUDGET_KEYS`); `syscall/mod.rs` (`audit_privileged_denial` no longer special-cases `Halt`). `record` now returns 0 when the denial was only counted (sequences start at 1); `AuditRead` pages by sequence number, so events removed from the middle of the ring do not disturb it.

Not covered: the limits do not refill over time (a persistent hostile subject is silenced after its budget; its later attempts only count); both tables are bounded (32 keys, 64 pairs) and forget the oldest, so many distinct subjects (each costs a process, which the quotas bound) can re-open budgets; allowed events are not limited here (they are bounded by the quotas of the operations that produce them) and when the ring has no denials they rotate normally; the ring is 256 events in RAM and is lost on reset; `suppressed` is a global counter, not per subject.

### I-49 — A validly signed but older kernel does not boot

A signature proves who built a kernel, not that it is the latest: an old kernel with a fixed vulnerability still carries a valid signature. Each kernel therefore carries a security version inside what is signed, and the bootloader refuses any version lower than the highest it has already accepted.

```text
signature = Ed25519( "TRUNOMY-KERNEL-IMAGE-v2\0" || version (u64 little endian) || kernel ELF )
kernel_x86_64.elf.ver = version (8 bytes);   kernel_x86_64.elf.sig = signature (64 bytes)
version comes from config/security-version (an integer raised on purpose when a fix is released, not a build number)
UEFI variable TrunomyMinKernelVersion (non-volatile, boot-services only) = highest accepted version
boot: read .ver -> VERIFY the signature -> only then compare with the variable:
      version <  minimum  -> refuse ("ROLLBACK REJECTED")
      version == minimum  -> boot
      version >  minimum  -> boot and store the new minimum
no variable yet = first boot (accepted and recorded); a variable that is not 8 bytes, or any read error other than "not found" -> refuse to boot
```

Order matters: the version is untrusted until the signature verifies, so an unsigned `.ver` can neither pass nor move the counter (otherwise writing a huge number to the disk would leave the machine unbootable). Editing the `.ver` of a good kernel, up or down, breaks the signature because the version is part of the signed message. A signature over the bare ELF (the old format) no longer verifies; there is no unversioned path. The variable has no runtime access attribute, so the running kernel and userland cannot reach it.

Implementation: `bootcore/src/rollback.rs` (`signed_message`, `verify_kernel`, `decide`, `check_kernel`, `parse_version`, `encode_counter`/`decode_counter`; pure logic, tested on the host), `boot/src/main.rs` (`read_rollback_counter`, `store_rollback_counter`, the `.ver` read and `check_kernel` call before anything is loaded), `scripts/kernel-message.sh` (builds the `.ver` and the signed message; used by `build_os.sh` and executed as-is by a bootcore test, so the script and the Rust code cannot drift), `build_os.sh`, `config/security-version`, `scripts/ci.sh security-version` (the number is a positive integer and does not go down from the previous commit). `run_os.sh` takes `OVMF_VARS` (a writable copy of the matching `OVMF_VARS.fd`) and `IMG`.

Not covered: the counter lives in firmware NVRAM with no dedicated hardware (no TPM NV counter, no RPMB), so whoever can write the NVRAM (physical access, a flash tool, resetting the variable store) can reset it, and then an old kernel boots; this protects against putting an old kernel on the DISK, not against control of the firmware. QEMU keeps variables only in RAM unless `OVMF_VARS` is given, so the protection is inactive in the default `./trunomy run` (the bootloader says so when it cannot store the value) and active on real hardware. If the firmware refuses the write, the verified kernel still boots with a warning (availability over a counter that cannot be kept). The shell is embedded in the kernel ELF, so it is covered by the same version; the security version is bumped by hand, and forgetting to bump it after a fix leaves the old kernel acceptable.

### I-50 — The console keyboard cannot move the cursor out of the input line, and a command history never keeps a stale secret

`ConsoleRead` used to store and echo every byte. An arrow key (`ESC [ D`) therefore reached the terminal as a cursor-movement command, so the operator could leave the input line and write over the prompt. The line editor is now a pure state machine in the kernel (`kernel/src/lineedit.rs`), tested on the host.

```text
accepted(byte) <=> 0x20 <= byte <= 0x7e            every other control and every 8-bit byte is ignored, with no echo
ESC [ ... final | ESC O final                        consumed whole: neither stored nor echoed; a control byte (Enter) ends an unfinished sequence
echo ⊆ { typed printable bytes, "\b \b" per typed byte erased, "\n", "^C\n", a recalled line }
erased_so_far <= typed_so_far                        backspace on an empty line does nothing: the prompt is never touched
len(line) <= min(caller buffer, 512)
history = last 16 lines: no empty lines, no repeats in a row, nothing over 256 bytes, every stored line printable ASCII
reuse(slot) => slot is overwritten with zeros (volatile writes) before the new line is copied in
delivered(line) => the editor buffer is zeroed
```

Keys: `↑`/`↓` walk the history (a recalled line can be edited), `Ctrl-U` clears the line, `Ctrl-C` cancels it (an empty line is returned and the shell prints a new prompt).

Implementation: `kernel/src/lineedit.rs` (`LineEditor::feed`, `History`), `kernel/src/syscalls.rs` (`serial_read_line`, `HISTORY`: the history lock is held only while one byte is processed, with no other lock held). The single copy of the finished line to user memory through `user_access` (I-37) is unchanged.

Not covered: the history belongs to the console, not to an identity, so after `su bob` the up arrow shows what root typed (there is one operator console); it lives in kernel RAM, so a kernel memory disclosure would expose the last 16 commands (and the slot of a command that was just run keeps its text until it is reused); there is no editing in the middle of a line, no history search and no tab completion; input is ASCII only (no UTF-8 typing); a serial terminal that sends a malformed escape sequence loses at most the keys of that sequence. Keystrokes are not authenticated: whoever holds the console is the operator.

## 7. Additional evidence requirements

13. A freed frame reads back as all zeros before reuse (I-16).
14. A freed object payload is zeroed before the buffer is released or replaced (I-16).
15. Double-freeing a frame, or freeing an unallocated frame, is rejected (I-17).
16. An image with an invalid signature is not loaded (I-18).
17. An ELF segment whose destination falls outside the reserved region is rejected (I-18).
18. Trust mode is determined by build configuration, not by key contents (I-19).
19. A sender without `CAP_IPC_SEND` is denied when sending IPC (I-12 amplification).
20. A cross-tenant read is denied symmetrically like a write (I-05 amplification).
21. The full sequence of an agent session (reads, attacks, revocation) appears in the audit log in order (I-21).
22. Delegated expiry and use limits can be narrowed but never widened, and an exhausted capability is denied (I-22).
23. User memory is accessed only through the single-copy, length-bounded layer (I-23).
24. Object and capability syscalls run as the calling process, narrow-only, atomic and audited (I-24).
25. Session identities are administered, bounded and audited (I-25).
26. Frames are allocated only from firmware-declared usable memory, minus the kernel, shell and boot structures (I-26).
27. Kernel time is monotonic and comes only from the timer interrupt (I-27).
28. Scheduling is fair, bounded and never runs a task that cannot run (I-28).
29. A context switch never mixes tasks' stacks, address spaces, identities or registers (I-29).
30. Console input is interrupt-driven, bounded and never loses a wake-up (I-30).
31. A process acts only with the identity it was born with; only the session leader creates processes (I-31).
32. No user page is writable and executable at the same time (I-32).
33. A kernel ELF with a bad signature, malformed headers, out-of-range, overlapping or W+X segments, or an entry outside executable code is rejected before anything is copied (I-18); the trust root is a single constant and no key value enables a bypass (I-19).
34. A Ring 3 exception terminates only that process, with a kernel-only exit code that no process can produce itself, and is audited; a fault of the root shell or of the kernel halts (I-33).
35. Only the parent can kill a live child, denied attempts are audited, and `ProcessWait` with a deadline kills and reaps a hung child (I-34).
36. A worker has no console and cannot halt the machine; its output reaches only its parent, bounded, and is shown sanitized (I-35).
37. A kernel or user stack overflow hits an unmapped guard page; no address space can be created that maps one (I-36).
38. The kernel image has no writable-and-executable page, the rest of RAM is not executable, and kernel access to user memory happens only inside the SMAP window (I-37).
39. The kernel's base page tables are its own: identity `0..4 GiB`, every address the kernel uses at the switch is mapped, and processes inherit them (I-38).
40. A shell image is verified only with the shell key and a kernel only with the kernel key; the two keys differ and an unprovisioned (all-zero) key is rejected (I-39).
41. `ProcessWait` without a bounded deadline is rejected; a worker that exhausts its CPU quota is stopped and killed with `exit::CPU_QUOTA`; a spawn that does not fit the memory quota creates nothing (I-40).
42. A denied console or `Halt` is audited, an allowed `Halt` is audited and printed, and repeating a denial cannot evict other events from the audit log (I-41).
43. Validation and access to a user range are one step: validity is never cached between building a `UserSlice` and using it, and a rejected access changes nothing (I-20).
44. `SystemInfo` answers come from the kernel and each kind is authorized in the kernel: machine-wide kinds are leader-only, a user sees only itself and its tenant, and nothing prints a constant (I-42).
45. The IPC queue is bounded per target and globally, IPC authority is granted only on request and audited, and refused sends are audited and throttled (I-43).
46. The PCI scan is bounded, the virtio-net bring-up enables only I/O space, and bus mastering and `DRIVER_OK` come only from the leader's `NetControl(UP)` after both queues are built and registered (a failed activation resets the device and withholds queue memory it cannot prove idle), accepts only `MAC` and `STATUS`, fails closed with a reason, and its inventory is leader-only (I-44).
47. A tenant can be cut off by the leader alone: its actors are retired, its processes killed, every capability and pending message removed, optionally its objects wiped, and the cut is audited; other tenants are untouched (I-45).
48. The kernel keeps a shadow of every buffer it publishes to the network device, programs only addresses inside its DMA window, validates every index, id and length the device reports, and poisons the queue on the first lie (I-46).
49. Network use needs a global capability granted only with `net`; a port's owner is fixed by the kernel, a foreign port looks nonexistent and the attempt is audited, every queue and table is bounded, every frame from the wire is parsed strictly and filtered, and endpoints die with their owner or their tenant (I-47).
50. Repeating or varying denials cannot fill the audit ring or evict an allowed event: every denial passes one limiter (per key and per subject-operation), a stored denial only evicts the oldest denial, and all of them are counted (I-48).
51. A kernel with a valid signature but a security version below the highest accepted does not boot, an edited `.ver` invalidates the signature, an unsigned version never moves the counter, and the signature format has no unversioned path (I-49).
52. Cursor keys and other escape sequences neither enter the line nor reach the terminal, backspace never erases more than was typed, only printable ASCII is accepted, the history keeps at most 16 printable lines and overwrites a reused slot with zeros (I-50).

## 8. Additional traceability

The current status of the newly added invariants is intentionally recorded as pending until responsible code and tests exist.

```text
ID   | Responsible code | Test   | Result           | Known limitation
-----+------------------+--------+------------------+-----------------------------------------------
I-12 | syscalls.rs (`validate_required_capability_for`, `validate_ipc_dispatch_args`, `syscall_dispatch`), ipc/ | syscalls::tests::{ipc_send_and_receive_each_need_their_own_global_capability, runtime_ipc_rejects_*, ipc_manager_enqueues_for_target} | verified (host) | the kernel queue is bounded and denials are audited since I-43; the end-to-end test between two worker processes needs QEMU (see I-43)
I-16 | memory/frame_allocator.rs, zero_alloc.rs | frame_allocator::tests::free_scrubs_*; zero_alloc::tests::* | verified (host) | heap wipe tested on a host allocator, real bare-metal path needs QEMU; no frame is freed at runtime yet
I-17 | memory/frame_allocator.rs | frame_allocator::tests::{allocated_frames_are_unique_*, double_free_*, reserved_*, unaligned_*} | verified (host) | no refcounts; nothing frees frames at runtime yet
I-18 | bootcore/src/sig.rs, bootcore/src/elf.rs, boot/src/main.rs, kernel/src/loader.rs, build_os.sh | bootcore sig::tests::* (bit-flip on every signature bit, wrong key, length, tamper), elf::tests::* (range, overflow, overlap, W^X, entry, truncated input never panics), tests/openssl_interop.rs (real `openssl pkeyutl -rawin` signatures), loader::tests::* | verified (host) for the logic | the UEFI bootloader build and the real kernel ELF through `plan_load` only run with `build_os.sh` + QEMU (first boot after this patch must still print "Firma Ed25519 válida"); rollback: see I-49; one key signs kernel and shell
I-19 | abi/src/lib.rs (`trust`), bootcore/src/sig.rs, kernel/src/loader.rs, build_os.sh | sig::tests::{all_zero_key_is_not_a_bypass, small_order_keys_are_rejected}; loader::tests::{zero_key_is_not_a_dev_mode, embedded_trust_root_is_a_valid_strong_key}; build_os.sh key-consistency check | verified (host) | the pem-vs-code check runs only in `build_os.sh`; no dev/prod build modes exist yet
I-20 | user_access.rs (`ActiveUserSpace`, `UserSlice`), cpu.rs (`user_window`) | user_access::tests::{a_slice_is_not_a_proof_of_validity_*, a_permission_that_changes_*, a_rejected_write_leaves_*, read_copies_exactly_once_*} | verified (host) on a simulated user space; the argument against remapping is structural (one CPU, IF=0, no mapping syscalls) | no fault-injection test on hardware; breaks if SMP or a mapping/shared-memory syscall is added
I-21 | audit.rs         | audit::tests::*; scenario_agent_support::agent_reads_only_its_customer_and_injection_is_just_data | scenario disabled | IPC and pointer-validation denials not yet audited; no Ring 3 reader
I-22 | capabilities.rs  | capabilities::tests::{capability_expires_*, delegated_expiry_*, uses_are_*, child_uses_*}; scenario_agent_support::session_limits_* |scenario disabled | no timer advances the clock yet; limits only on delegation
I-23 | user_access.rs   | user_access::tests::*; syscalls IPC paths use it | verified (host, mock memory) | real page-table path and ConsoleRead still need QEMU; no page check without active user PML4
I-24 | syscall/objects.rs | syscall::objects::tests::* | verified (host, mock memory) | dispatch + asm entry untested here (needs QEMU); caller identity still comes from CURRENT_PROCESS (no scheduler yet); no shell command uses it yet
I-25 | syscall/identity.rs | syscall::identity::tests::* (incl. full_demo_flow_*) | verified (host, mock memory) | transitional limitation closed by I-31 (actors no longer administer the session)
I-26 | memory/boot_map.rs, memory/frame_allocator.rs, boot/src/main.rs | boot_map::tests::*; frame_allocator::tests::{only_usable_*, reserved_wins_*, malformed_*, allocation_only_*} | verified (host) for kernel side | bootloader side (ExitBootServices map -> table) not compiled or run here: needs build_os.sh + QEMU; only memory < 4 GiB is managed
I-27 | interrupts.rs, pic.rs, pit.rs, clock.rs | pic::tests::*; pit::tests::*; clock::tests::*; syscalls::tests::clock_now_*; idt::entries::tests::* | verified (host) for sequences/encoding | naked IRQ stub, TSS stacks and sti windows only run on hardware: needs QEMU (`uptime` must advance)
I-28 | sched.rs | sched::tests::* (incl. no_starvation_*, random_operation_storm_*) | verified (host), policy only | wired by dispatch.rs (I-29)
I-29 | dispatch.rs, spinner.rs, syscalls.rs (entry asm), interrupts.rs, sched.rs (`start`) | dispatch::tests::*; sched::tests::start_* | verified (host) for frame layout, selectors, table bounds | the asm switch, `iretq` entry and nested IRQ-in-syscall only run on hardware: needs QEMU (see docs/demo-shell.md, multitasking)
I-30 | console.rs, interrupts.rs (IRQ4 stub), dispatch.rs (wait/wake), syscalls.rs | console::tests::* (incl. concurrent producer/consumer, single waiter) | verified (host) for buffer and waiter logic | IRQ4 stub, UART programming and the block/wake path only run on hardware: needs QEMU (typing must work, CPU idle while waiting)
I-31 | syscall/spawn.rs, proctab.rs, image.rs, syscall/identity.rs, memory/process_paging.rs (`destroy`), dispatch.rs (`HwPlatform`), libtrunomy worker/process | spawn::tests::*; proctab::tests::*; identity::tests::{actors_do_not_administer_the_session, spawn_is_audited_*}; image::tests::*; dispatch::tests::{stack_pool_*, ktable_remove_*}; worker::tests::* | verified (host, fake platform) | page-table build/destroy, process exit/switch and the shell's spawn+wait path only run on hardware: needs QEMU (`demo` must give the same result; boot log shows "proceso N creado/recogido" with frames returned)
I-32 | abi/src/image.rs, userland/shell/linker.ld, loader.rs, memory/process_paging.rs (`wx_allowed`), syscalls.rs (NXE) | image::tests::* (layout parse, fail-closed, entry in text); wx_tests::no_user_page_is_writable_and_executable; linker script checked with `ld`+`objcopy` and the Rust parser | verified (host) for the layout format and policy | the real shell image (needs `build_os.sh` with the new linker.ld) and the page faults on a write to text / execute from data only show on hardware: needs QEMU (boot log prints "Imagen W^X: paginas text R-X=... rodata R--=... data RW-=...")
I-33 | kernel/src/faults.rs, syscall/spawn.rs (`fault_with`, `exit_with`), proctab.rs, abi/src/lib.rs (`exit`), idt/mod.rs | faults::tests::*; spawn::tests::{a_cpu_fault_terminates_only_*, a_fault_in_the_root_shell_is_not_contained, a_fault_cannot_be_reported_twice, a_user_cannot_exit_with_a_kernel_only_code}; proctab::tests::*; abi exit::tests::*; naked stubs inspected with `objdump` (push vector / jmp exc_common / call exception_entry, relocations resolve) | verified (host) for the policy and bookkeeping | the stubs and the switch away from a faulting task only run on hardware: needs QEMU (`su <user>`, then `selftest fault` and `selftest ud` must print the worker was terminated and the shell stays alive)
I-34 | syscall/spawn.rs (`kill_with`, `kill_child`, `wait_with`), proctab.rs, dispatch.rs (`hw::terminate`, `block_for_child`) | spawn::tests::{only_the_parent_can_kill_*, wait_with_a_timeout_kills_*, wait_with_a_timeout_does_not_kill_*, wait_requires_a_deadline_and_bounds_it_before_any_effect}; proctab::tests::{only_the_parent_can_kill_*, kill_and_terminate_wake_*} | verified (host) with a fake platform | the real removal of a Blocked/Ready task from the scheduler and the deadline wake-up need QEMU (`selftest hang` must return with "timed out" (before I-40; since I-40 it ends earlier with "cpu quota exceeded") and the console must still accept input)
I-35 | syscall/mod.rs (`required_capability`), capabilities.rs (`seed_root_into`), syscall/spawn.rs (`output_with`, `wait_with`), proctab.rs (`append_output`, `wait_output`), faults.rs (`shows_cr2`), libtrunomy `worker::printable` | syscall::tests::console_and_halt_require_authority; capabilities::tests::only_the_root_shell_gets_console_and_admin; spawn::tests::{a_workers_output_reaches_only_its_parent_through_wait, wait_needs_room_for_the_whole_result}; proctab::tests::output_is_bounded_*; faults::tests::cr2_is_shown_only_for_page_faults; libtrunomy worker::tests::untrusted_output_cannot_carry_terminal_controls | verified (host) | the end-to-end path needs QEMU: as a user, `read` must still print the object and `selftest fault` must still be contained; the root shell must still print and read the keyboard
I-36 | guard.rs (`GuardedStack`, `slot`, `unmap_page`, `is_mapped`, `install`, `verify`), dispatch.rs (`create_task`, `kstack_slot`), interrupts.rs, syscalls.rs, image.rs (`USER_STACK_BASE`), main.rs | guard::tests::{slot_geometry_*, unmapping_one_page_splits_*, the_new_tables_are_not_owned_*, splitting_a_1g_page_*, bad_addresses_*, install_unmaps_every_guard_*, a_process_that_copies_the_base_pml4_inherits_*}; image::tests::layout_regions_do_not_overlap_* | verified (host) on a simulated page-table memory | the real tables need QEMU: boot must print `Paginas de guarda activas: 0x0B`, the shell must reach the prompt, and `selftest stack` as a user must report a contained #PF; free frames drop by the 1-2 tables of the split
I-37 | cpu.rs (`decode`, `cr4_with`, `user_window`, `harden`), kmap.rs (`Layout`, `update`, `apply`, `effective`, `verify`), guard.rs (`split`), user_access.rs, syscalls.rs (`serial_read_line`), linker.ld, dispatch.rs (`create_task`), main.rs | cpu::tests::*; kmap::tests::{apply_gives_every_region_its_permissions, the_rest_of_ram_*, the_running_text_is_never_nx_*, guard_pages_stay_unmapped_*, verify_catches_*, an_address_space_built_before_the_policy_is_detected, split_pages_keep_*}; guard::tests::a_split_keeps_the_leaf_flags_* | verified (host) on simulated page tables; linker symbols checked with GNU ld on a toy object | the real CPU needs QEMU with `-cpu max`: boot must print `CPU: NX=si SMEP=si SMAP=si` and `W^X del kernel activo`, the shell must reach the prompt, and every earlier command (`read`, `selftest *`, `audit`, typing a line) must still work
I-38 | memory/ident.rs (`build`, `check_identity`, `install`), memory/mod.rs (`init_memory_system`), kmap.rs (`IDENTITY_LIMIT`) | ident::tests::{the_table_maps_exactly_the_first_4_gib_*, running_out_of_frames_*, the_identity_check_catches_*, guards_and_wx_compose_on_top_of_the_new_tables, identity_limit_matches_*} | verified (host) on simulated page tables | the CR3 switch needs QEMU: the log must print `Tablas de paginacion propias activas` before the guard-page line, and every earlier check must still pass (prompt, spinner, `demo`, `selftest *`); free frames drop by 6 more than before (the new tables)
I-39 | abi/src/lib.rs (`trust`), boot/src/main.rs, kernel/src/main.rs, build_os.sh, scripts/{keys-lib,provision-keys,ci}.sh | abi::tests::kernel_and_shell_signing_keys_are_distinct_roles; loader::tests::{embedded_signing_keys_are_real_keys_or_fail_closed, image_signed_with_the_kernel_role_key_is_not_a_shell_image, zero_key_is_not_a_dev_mode}; `ci.sh keys` | verified (host) on the verification logic and the scripts | no QEMU/build run of the full signing flow by me: after `provision-keys.sh`, `build_os.sh` must print both key checks and boot as before; the kernel key is not protected by this (see I-39)
I-40 | syscall/spawn.rs (`wait_with`, `spawn_with`, `Platform::{admit_memory,cpu_quota_exceeded}`), sched.rs (`on_tick`, `watch`, `over_quota`, `spawn_limited`), quota.rs, dispatch.rs (`admit_memory`, `block_for_child`, `create_task_limited`) | spawn::tests::{wait_requires_a_deadline_*, a_child_that_exhausts_its_cpu_*, the_quota_kill_is_audited_*, only_the_parent_can_trigger_the_quota_kill, spawn_over_the_memory_quota_*}; sched::tests::{a_task_over_its_cpu_quota_*, quota_is_per_task_*, a_task_without_a_limit_*, the_parent_is_woken_*, with_nobody_else_ready_*}; quota::tests::*; abi::tests::wait_deadlines_are_consistent | verified (host) with a fake platform and the pure scheduler | the real timer-IRQ path and the stop/kill need QEMU: `selftest hang` as a user must end in ~2-4 s with "cpu quota exceeded", the console must still answer and `free` must be unchanged afterwards; the memory constants must be checked against the `marcos liberados` line of a real spawn
I-41 | audit.rs (`record_throttled_denial`, `DENIAL_BURST`, `THROTTLE_KEYS`), syscall/mod.rs (`audit_privileged_denial`, `audit_halt_allowed`, `audited_op`), syscalls.rs (`validate_required_capability_for`, Halt arm), syscall/identity.rs (`record_of`), abi (`OP_CONSOLE`, `OP_HALT`) | audit::tests::{a_repeated_denial_cannot_wipe_the_history, the_burst_is_per_subject_*, the_throttle_table_is_bounded_*}; syscalls::tests::{a_denied_console_or_halt_is_audited_*, a_process_with_the_capability_is_allowed_*, a_console_flood_is_bounded_*, halt_denials_have_a_bigger_but_bounded_budget, halt_allowed_is_audited_*, only_console_and_halt_*}; abi::tests::audit_op_codes_are_unique_and_named | verified (host) | the real dispatch path needs QEMU: as a user run `selftest console` (must print `denied: InvalidCapability`, the machine must NOT halt), then `su root` and `audit` must list `console -> denied` and `halt -> denied`
I-42 | syscall/info.rs (`system_info`, `info`), capabilities.rs (`entries_of`, `bytes_for_tenant`, `Rights::bits`), allocator.rs (`heap_stats`), proctab.rs (`entries`), syscall/identity.rs (`is_admin`, `actor_pids`), libtrunomy (`sysinfo.rs`, `worker.rs` Info/Halt), shell (`cmd_info`, `cmd_halt`, `cmd_ls`, `tenant list`), abi (`sysinfo`, `Syscall::SystemInfo`) | info::tests::{identity_reports_*, machine_wide_kinds_are_admin_only, actors_listing_matches_the_session, caps_are_own_by_default_*, revoked_capabilities_are_not_listed_*, tenant_usage_counts_only_*, processes_listing_starts_with_the_leader, unknown_kind_is_rejected}; libtrunomy sysinfo::tests::*; worker::tests::info_and_halt_requests_are_strict; abi::tests::sysinfo_kinds_are_unique_* | verified (host) | needs QEMU: `free` as root must change after `object create` / `user create`; `su bob` then `free` shows bob's tenant quota; `whoami`/`id` follow `su`; `ps` as bob prints `denied: PermissionDenied`; `tenant list` as root shows tenants, users and their capabilities; `su bob`, `halt` must be denied and appear in `audit`
I-43 | ipc/manager.rs (`IpcError`, `MAX_QUEUED_*`), syscalls.rs (`audit_ipc_denial`, `enqueue_checked`, `validate_ipc_dispatch_args`), syscall/mod.rs (`audited_op`, `audit_privileged_denial`), syscall/identity.rs (`actor_create_with`), audit.rs (`AuditOp::Ipc`), abi (`actor`, `OP_IPC`), libtrunomy (`worker.rs` IpcSend/IpcRecv), shell (`cmd_ipc`) | ipc::manager::tests::{one_target_cannot_hold_more_than_its_share, the_whole_queue_is_bounded, invalid_messages_are_rejected, the_global_limits_fit_the_kernel_heap}; syscalls::tests::{a_denied_send_is_audited_*, a_missing_ipc_capability_is_audited_and_throttled, a_full_queue_is_a_quota_error_and_is_audited}; identity::tests::{actors_get_ipc_only_when_asked_*, unknown_actor_flags_create_nothing_*}; worker::tests::ipc_requests_are_strict; abi::tests::audit_op_codes_* | verified (host) | needs QEMU: `user create alice acme ipc`, `user create bob acme ipc`, `user create mallory evil ipc`; `su alice`, `ipc send bob hola` -> `ok sent`; `su bob`, `ipc recv` -> `hola`, again -> `(no messages)`; `su mallory`, `ipc send alice x` -> `denied: PermissionDenied`; `su root`, `audit` shows `ipc -> DENIED`; a user created without `ipc` gets `denied: InvalidCapability`
I-44 | net/pci.rs (`scan`, `enable_io_space`), net/virtio.rs (`init`, `InitError`), net/mod.rs (`probe`, `info_words`, `boot_line`), syscall/info.rs (`NET`), abi (`sysinfo::NET`), libtrunomy (`net_line`, worker `b'n'`), shell (`cmd_net`), run_os.sh, net/nic.rs (`activate`, `Nic`), net/arp.rs, syscall/netctl.rs (`net_control_with`), memory/frame_allocator.rs (`allocate_contiguous`), abi (`netctl`, `sysinfo::NET_STATS`) | net::pci::tests::*; net::virtio::tests::{the_handshake_stops_before_driver_ok_and_bus_master, only_the_features_the_kernel_can_use_are_accepted, a_device_that_never_finishes_the_reset_times_out_instead_of_hanging, a_memory_bar_or_an_unassigned_bar_is_rejected_before_touching_the_device, a_missing_mac_feature_or_a_bad_mac_fails_closed_and_marks_failed}; net::tests::*; info::tests::machine_wide_kinds_are_admin_only; sysinfo::tests::net_info_shows_what_the_kernel_found; net::nic::tests::*; netctl::tests::*; frame_allocator::tests::{contiguous_runs_are_consecutive_owned_and_skip_holes_that_are_too_small, a_failed_contiguous_request_changes_nothing} | verified (host) | needs QEMU: `./trunomy up`, boot log shows `Red: virtio-net en PCI 00:02.0 MAC 52:54:00:12:34:56 ... inactivo`; as root `net info` shows the same MAC and `link up`; `su` a user and `net info` -> `denied: PermissionDenied`; `NET=0 ./trunomy run` -> `net: no device`; DMA/IOMMU not validated in QEMU; QEMU: as root `net up` (boot-log line `activo`), `net selftest` prints OK (ARP reply from 10.0.2.2), `net stats` shows tx/rx counters and `queues ok`, `net down` returns the memory (`free` unchanged); as a user `net up` is `denied: PermissionDenied` and is audited
I-45 | syscall/lockdown.rs (`tenant_panic_with`, `tenant_thaw_with`), syscall/identity.rs (`Session::quarantine`, `thaw`, `actor_state`), capabilities.rs (`revoke_subject`, `purge_tenant`), ipc/manager.rs (`purge_pids`), syscall/info.rs (`ACTORS`), abi (`panic`, `OP_PANIC`, `OP_THAW`), libtrunomy (`session::tenant_panic`, worker `TenantPanic`), shell (`cmd_tenant_panic`) | lockdown::tests::{a_panicked_tenant_cannot_spawn_and_cannot_get_new_actors, a_refused_spawn_is_audited, live_workers_are_killed_and_reaped_and_zombies_do_not_leak_slots, every_capability_is_revoked_and_known_handles_stop_working, derived_capabilities_die_with_their_parent, ipc_messages_from_or_to_the_tenant_are_dropped_and_others_stay, wipe_deletes_only_that_tenants_objects_and_only_when_asked, only_the_session_leader_can_panic_and_a_refusal_changes_nothing, a_hostile_actor_cannot_flood_the_audit_log_with_panic_attempts, unknown_tenant_or_flags_do_nothing, panic_is_idempotent, thaw_reopens_the_tenant_for_new_actors_but_never_for_retired_ones}; info::tests::actors_listing_reports_a_panicked_tenant_and_its_retired_actors; worker::tests::tenant_panic_requests_are_strict; abi::tests::panic_counters_pack_and_saturate_* | verified (host) | needs QEMU: create `acme` and `evil` with users (`user create eve evil ipc`), `tenant panic evil` -> `tenant evil PANIC: 0 processes killed, N capabilities revoked, 0 objects wiped`; `tenant list` shows `evil ... [FROZEN]` and `eve ... [retired]` with `(no capabilities)`; `su eve`, `whoami` -> `denied: PermissionDenied`; `su root`, `audit` shows `panic -> allowed` and `identity -> DENIED PermissionDenied`; acme's users keep working; `su` a user of acme, `tenant panic evil` -> `denied: PermissionDenied`, `audit` shows `panic -> DENIED`
I-46 | net/vring.rs (`Vring::{new, post, poll}`, `Layout`, `DmaPool`) | vring::tests::{only_addresses_inside_the_dma_window_are_ever_programmed, a_device_that_claims_more_completions_than_were_posted_poisons_the_queue, an_id_that_is_out_of_range_or_not_in_flight_is_rejected, completing_the_same_buffer_twice_is_a_lie, a_length_larger_than_the_buffer_is_rejected, what_the_device_does_to_the_descriptor_table_is_never_believed, a_poisoned_queue_stays_silent_even_if_the_device_recovers, sixteen_bit_indices_wrap_without_losing_buffers, the_pool_hands_out_distinct_slots_and_takes_back_only_its_own, construction_zeroes_the_memory_and_checks_its_arguments} | verified (host); connected to the device in `net/nic.rs` | the QEMU check is `net up` + `net selftest`; IOMMU/DMA behaviour of a real device is not validated
I-47 | abi/src/netproto.rs, net/endpoint.rs (`Table`), syscall/netio.rs, syscall/mod.rs (`CAP_NET_*`, `audited_op`), syscall/identity.rs (`FLAG_NET`), syscall/lockdown.rs, dispatch.rs, libtrunomy (`net`, worker), shell | netproto::tests::*; endpoint::tests::*; netio::tests::*; identity::tests::the_net_flag_grants_the_network_capabilities_and_nothing_else; syscalls::tests::network_syscalls_need_their_global_capability_and_a_denial_is_audited_with_limit; lockdown::tests::{network_endpoints_of_the_tenant_are_closed_and_other_tenants_keep_theirs, a_refused_panic_does_not_touch_the_network}; worker::tests::* | verified (host) | needs QEMU: `user create ana acme net`, `su ana`, `net loopback hola` prints `from … port 40001: hola`; a user created without `net` gets `denied: InvalidCapability` and `audit` shows `net DENIED`; `tenant panic acme` closes the tenant's ports; `python3 scripts/nettest.py` (frames from a host script over `-netdev socket,udp`) checks inbound delivery, the hostile-frame drops and a flood; `python3 scripts/nettest2.py` links two VMs and checks delivery between tenants of different machines
I-48 | audit.rs (`record`, `record_denial`, `push`, `denial_limits`, `DENIAL_OP_CAP`, `HALT_BURST`, `HALT_OP_CAP`, `OP_BUDGET_KEYS`), syscall/mod.rs (`audit_privileged_denial`) | audit::tests::{varying_the_resource_does_not_open_a_fresh_budget_each_time, the_cap_is_per_operation_and_per_subject, denials_never_displace_allowed_events_from_a_full_ring, allowed_events_still_rotate_when_there_is_no_denial_to_evict, a_denial_into_a_ring_without_denials_evicts_the_oldest_event, the_budget_table_is_bounded}; syscalls::tests::{halt_denials_have_a_bigger_but_bounded_budget, a_console_flood_is_bounded_in_the_log_but_counted} | verified (host) | needs QEMU: `python3 scripts/audittest.py` (a user repeats `halt` 40 times and `selftest console` 10 times; as root `audit` shows at most 16 `halt` and 8 `console` denials and the earlier grant is still there)
I-49 | bootcore/src/rollback.rs, boot/src/main.rs, scripts/kernel-message.sh, build_os.sh, config/security-version, scripts/ci.sh (`security-version`) | bootcore rollback::tests::* (layout of the signed message, first boot, same/newer/older version, edited `.ver` up and down, unsigned version never moves the counter, bare-ELF signature refused, `.ver` and counter sizes, monotonic `decide`, upgrade-then-downgrade story); tests/openssl_interop.rs::the_real_build_script_message_verifies_with_the_bootloader_logic (the real `kernel-message.sh` + openssl signature through `check_kernel`) | verified (host) for the logic; the UEFI calls type-check on the host | needs QEMU with a persistent NVRAM: `./trunomy build`, then `python3 scripts/rollbacktest.py` (N+1 boots and is recorded; N is refused; an edited `.ver` is refused and does not move the counter; N+1 still boots; with the NVRAM reset N boots: the documented limit)
I-50 | kernel/src/lineedit.rs (`LineEditor`, `History`), kernel/src/syscalls.rs (`serial_read_line`, `HISTORY`) | lineedit::tests::{cursor_keys_are_swallowed_whole_and_never_echoed, the_cursor_can_never_leave_the_input_line, backspace_on_an_empty_line_does_nothing, only_printable_ascii_enters_the_line, an_incomplete_sequence_does_not_swallow_enter, the_line_never_exceeds_the_callers_buffer, ctrl_u_clears_the_line_and_ctrl_c_cancels_it, history_recalls_newest_first_and_stops_at_the_ends, a_recalled_line_replaces_what_was_typed_and_can_be_edited_and_run, empty_repeated_and_long_lines_are_not_remembered, only_the_last_sixteen_are_kept, a_reused_slot_leaves_no_trace_of_the_older_secret, a_delivered_line_can_be_wiped_from_the_editor, every_stored_line_is_printable_ascii} | verified (host) for the editor | needs QEMU: `./trunomy build`, then `python3 scripts/linetest.py` (arrow keys do not move the cursor, no ESC reaches the terminal, Ctrl-C/Ctrl-U, the up and down arrows recall and run commands)
I-04 / I-13 (system capabilities) | capabilities.rs (`has_capability_for`), process.rs (`validate_process_capability`) | capabilities::tests::{a_data_capability_never_satisfies_a_system_capability, creating_objects_never_yields_system_authority, only_the_root_shell_gets_console_and_admin} | verified (host) | the PoC that reproduced the escalation is now a regression test
I-06 / I-07 (revocation scope, slot reuse) | capabilities.rs (`revoke_inner`, `try_insert`, `delegated_count`, `MAX_DELEGATED_PER_SUBJECT`), syscall/objects.rs (`cap_derive`) | capabilities::tests::{a_delegatee_cannot_revoke_its_delegator_or_its_siblings, revoking_cuts_the_whole_subtree_and_nothing_else, revoked_slots_are_reused_without_aba, the_book_delegates_up_to_the_total_quota_and_counts_what_was_delegated, objects::tests::cap_derive_cannot_fill_the_targets_slots} | verified (host) | the debug harness no longer runs at boot (`mod debug` is `cfg(test)`)
```

## 9. Updated limitations

Status at 2026-10-14. Verified in QEMU by the author through patch 28 (patches 23 and 24 are host-verified only: the `baremetal` CI job and the GitHub workflow have never run). Everything else in this file is verified on the host with simulated hardware. Open items:

- Network: since I-44 and I-47 the leader can bring a virtio-net up in QEMU and actors created with `net` can exchange frames of the Trunomy protocol through ports they own, but there is no authentication of peers, no TCP/IP, and DMA/IOMMU/real timing are not validated in QEMU. The network only carries messages between endpoints (no object access over the wire), so point 7 of threat model §7 (the same authorization through a network interface) is met for message delivery between actors in QEMU, not yet verified between two VMs, and not for object access. IPC is wired (I-12) but has the gaps listed there.
- Boot trust: rollback of an older signed kernel is refused only while the NVRAM counter survives (I-49: no TPM/RPMB, and QEMU's default NVRAM is volatile); the kernel signing key is a plain PEM on the build machine with no passphrase, rotation or revocation (I-39 only separates it from the shell key); no measured boot or TPM.
- Console: the line editor accepts ASCII only, edits only at the end of the line (no cursor movement, no tab completion, no history search) and keeps the last 16 commands in kernel RAM for the whole console, not per identity (I-50).
- Memory hardening covers the first 4 GiB only; no KASLR; SMEP/SMAP are skipped with a warning on CPUs without them; the old firmware page tables are left in place (I-38).
- Resource control: quotas are per process (I-40), not per tenant; the CPU quota counts timer ticks and only applies to workers; the audit ring is 256 events in RAM; every denial is rate-limited per key and per (subject, operation) and a denial never evicts an allowed event (I-48), but allowed events are not limited (they are bounded by the quotas that bound the operations) and the limits do not refill over time.
- External review (2026-10-20): the first four findings are fixed (I-04/I-13, I-06/I-07 above). Closed: `config/system.toml` (copied into the image but read by nothing) was removed. Open by decision: `OVMF_CODE.fd` at the repository root is a vendored firmware binary without recorded origin or hash (only a last resort for `run_os.sh`); `REQUIRE_SMEP_SMAP` stays `false` until verified in QEMU with `-cpu max`; allowed operations can still rotate the 256-event audit ring.
- Process lifecycle: a child that is never waited for stays a zombie until reaped (bounded by `MAX_PROCS`).
- Reproducibility: CI (`scripts/ci.sh`, GitHub Actions) exists but `baremetal` and the workflow are unrun; there is no recorded install on a clean machine, and the current hardening (own page tables, SMEP/SMAP) has not been recorded on real hardware.
- Hardware failures, kernel bugs, and vulnerabilities in third-party dependencies remain outside the scope of these invariants.

Reminder: every invariant requires responsible code and automated tests to become a security guarantee. Until both are present, the invariant is a design hypothesis, not a guarantee.
