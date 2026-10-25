# Quick start guide

From a clean clone to a Trunomy OS session in QEMU, with every command and what you should see. If something differs, `./trunomy check` (or the "If something fails" section) tells you why.

> Trunomy is a research prototype with no independent audit. Do not use it with real data.

Conventions: `$` is your terminal; `λ [Trunomy] >` is the shell prompt inside QEMU. Numbers marked with `…` (pids, tenant ids, handles, free frames) change from run to run; what matters is the shape of the result.

## 1. Install

You need `rustup` (the toolchain is pinned in `rust-toolchain.toml`), `openssl` with Ed25519, `objcopy`/`readelf` (binutils), `dosfstools` + `mtools`, and QEMU + OVMF to boot.

```bash
# AlmaLinux / Fedora
sudo dnf install -y binutils openssl dosfstools mtools qemu-kvm edk2-ovmf git
# Debian / Ubuntu
sudo apt install -y binutils openssl dosfstools mtools qemu-system-x86 ovmf git
# Rust (if you do not have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

```bash
git clone https://github.com/robertoaleman/trunomy-experimental.git
cd trunomy-experimental
./trunomy check
```

`check` lists every tool, the toolchain, the keys and QEMU with `[OK]`, `[WARN]` or `[MISSING]`. Do not continue until no `[MISSING]` is left for tools and toolchain (QEMU and OVMF are only needed to boot). On a fresh copy the signing keys show up as `[WARN]`: `./trunomy build` offers to generate yours in its first stage.

## 2. Build and boot

```bash
./trunomy up
```

It does, in this order: check the machine, build and sign the bootloader, the shell and the kernel, write `trunomy.img` and boot it in QEMU. Each stage says what it does and why; cargo's output goes to `target/build-logs/` and is only shown if something fails (`--verbose` always shows it). The build must finish **with no warnings**.

Trunomy only runs signed code and the repository does not ship private keys. On a new clone the build offers to generate yours; `./build_os.sh --own-keys` does it without asking. Those keys are yours: nobody else shares the resulting chain of trust.

At boot, the end of the log should look like this (PCI addresses and numbers may vary):

```text
[KERNEL] W^X image: text pages R-X=0x… rodata R--=0x… data RW-=0x…
[KERNEL] Timer: PIT divisor 0x… (100 Hz), PIC remapped to 0x20, only IRQ0 enabled
[KERNEL] Console: COM1 via IRQ4 (1-byte FIFO), blocking reads
[KERNEL] Network: virtio-net at PCI 00:02.0 MAC 52:54:00:12:34:56 link up (negotiated: inactive until `net up`)
[KERNEL] Scheduler: 0x…02 tasks, quantum 5 ticks; entering Ring 3...
Welcome to Trunomy OS - True Zero Trust CLI v0.1.0
λ [Trunomy] >
```

After the prompt, dots (`.`) appear (one per second): that is the scheduler's second task and confirms multitasking is running.

**Leave QEMU:** `Ctrl-A` then `X`. To boot again without rebuilding: `./trunomy run`.

`run` variables: `QEMU=/path/qemu`, `OVMF_CODE=/path/OVMF_CODE.fd` if it does not detect them, and `NET=0` to boot without a network card.

### Kernel security version (rollback)

Every kernel carries a security version signed together with it (`config/security-version`, an integer; `./trunomy build` signs it and writes `kernel_x86_64.elf.ver` into the image). The bootloader stores the highest accepted version in a non-volatile UEFI variable and refuses to boot a signed but **older** kernel (`ROLLBACK REJECTED`). Raise the number on purpose (`echo 2 > config/security-version`) when you ship a fix: `ci.sh security-version` fails if it goes down compared with the previous commit.

In QEMU the variable only persists if you give it a real NVRAM (`OVMF_VARS=copy-of-OVMF_VARS.fd ./trunomy run`); without it, `./trunomy run` boots anyway and the bootloader warns that it could not store the minimum. `python3 scripts/rollbacktest.py` runs the whole walkthrough (boots N+1, rejects N, rejects an edited `.ver`, boots N+1 again and shows that with the NVRAM erased the old kernel boots: the limit documented in I-49). It works on copies and needs `mtools`, `openssl` and `.keys/`.

## 3. First walkthrough (as root)

Type `help` to see all commands. The status commands read the kernel, not a fixed text:

| Command | What you should see |
|---|---|
| `whoami` | `name: root` and a line `pid=1 tenant=… subject=1` |
| `id` | `pid=1 tenant=… subject=1` |
| `caps` | root's capabilities, separated by `;` (for example `object.create; …`) |
| `free` | `frames: … KiB free of … KiB \| kernel heap: … KiB used of … KiB` |
| `ps` | one line `pid=… parent=… running` per process; the first is the leader (`pid=1`) |
| `uptime` | `up N.NN s (… ticks)` |
| `net info` | `net: virtio-net 1af4:1000 pci 00:02.0 mac 52:54:00:12:34:56 link up \| negotiated: inactive (net up)` |
| `status` / `version` | `Trunomy OS v0.1.0` and the module status |

Run `free` twice in a row: the free frames must not go down (no memory leaks).

### Line editing and history

The console has a minimal line editor (I-50). You always type at the end of the line: **the left/right arrows, Home, End and Del move nothing** (you cannot leave the line or overwrite the prompt), and only printable ASCII characters are accepted.

| Key | What it does |
|---|---|
| `↑` / `↓` | walks through the last 16 commands (↓ past the most recent leaves the line empty) |
| Backspace | deletes the last typed character (does nothing on an empty line) |
| `Ctrl-U` | clears the whole line |
| `Ctrl-C` | cancels the line and returns to the prompt |

A command recalled with `↑` can be edited (backspace and keep typing) before pressing Enter. The history does not store empty lines or the same command twice in a row, lives only in kernel RAM (lost on power-off) and belongs to the console, not to an identity: after `su bob`, `↑` also shows what root typed. Each entry is zeroed before it is reused, because a command may carry a secret (`object create key …`). `python3 scripts/linetest.py` checks it in QEMU (`linetest: OK`).

## 4. The security demo

```text
λ [Trunomy] > demo
```

It runs 18 commands and ends with `audit`. Two tenants (`acme`, `evil`); `alice` and `bob` in `acme`, `mallory` in `evil`. What you should see, in order:

1. alice creates `secret` (`ok handle=…`) and gives bob `read` (`ok granted`).
2. bob reads `secret`: **allowed**, shows `hello-world`.
3. bob tries to write: `denied: PermissionDenied` (READ does not turn into WRITE).
4. mallory copies alice's raw handle (`copied raw handle (the kernel decides)`) and uses it: **denied** (knowing the handle is not having authority).
5. alice revokes (`ok revoked`).
6. bob reads again: `denied: RevokedCapability`.
7. `audit` prints the kernel's decisions: lines `#N subject=… tenant=… … -> allowed` and `-> DENIED <error>`.

## 5. Try it by hand

> **Before you start:** the state lives in RAM and users cannot be modified after they are created (nor given `ipc` afterwards). If you already ran `demo` or tried other names, restart QEMU (`Ctrl-A`, `X`, then `./trunomy run`) to start from scratch, or use new names; `user exists` / `tenant exists` mean that name is already taken.

Names are a shell convenience; the kernel only sees handles and identities. Each user operation runs in a new process with that user's identity (`su <user>` only chooses on whose behalf the next thing runs).

**Tenants and users**

```text
λ [Trunomy] > tenant create acme
tenant acme id=…
λ [Trunomy] > user create alice acme
user alice pid=… tenant=acme
λ [Trunomy] > tenant list
```

`tenant list` (root only) prints an ASCII table read from the kernel: one row per capability, with the entity's data on its first line and a separator line between entities.

```text
+-------------+-------------------------+------+------------------------+
| Tenant ID   | Entity (Role / User)    | PID  | Permissions / Capabilities |
+-------------+-------------------------+------+------------------------+
| 1           | root (session leader)   | 1    | pipe.create            |
|             |                         |      | metadata.read          |
|             |                         |      | …                      |
+-------------+-------------------------+------+------------------------+
| 1000 acme   | alice                   | 1000 | object.create          |
+-------------+-------------------------+------+------------------------+
```

The Tenant ID column carries the id and the name the shell gave it; the markers `[FROZEN]` (frozen tenant) and `[retired]` (retired user) appear in its cell.

**Objects and capabilities**

```text
λ [Trunomy] > su alice
λ [Trunomy] > object create note hello
ok handle=…
λ [Trunomy] > ls
no filesystem: objects are capabilities. Handles named by this identity:
  note
λ [Trunomy] > cap grant bob note read 2
ok granted
```

`cap grant <user> <name> <rights> [uses]`: rights `read`, `write`, `delegate` separated by commas; `uses` limits how many times it can be used. `object read|write|delete <name>` and `cap revoke <name>` complete the cycle. A name without a handle gives `no handle for that name`.

**Expected denials**

| Attempt | Result |
|---|---|
| a user runs `ps`, `tenant list` or `net info` | `denied: PermissionDenied` |
| a user runs `halt` | `denied: PermissionDenied` (recorded in `audit`) |
| a user runs `audit` | `denied: PermissionDenied` (only the leader reads the audit log: `su root`) |
| `su root` and `audit` | the new records since the last read, or `(no new records)` |

**IPC between users.** IPC authority (`ipc.send` / `ipc.recv`) only exists if it is requested **when the user is created**, and only works inside the same tenant. That is why this example creates new users (`ana`, `beto`, `eve`) with `ipc`; `alice` and `bob` will not do if you created them without it. Root does not have `ipc.send` either: an `ipc send` as root gives `denied: InvalidCapability`, and that is correct.

```text
λ [Trunomy] > user create ana acme ipc
user ana pid=… tenant=acme ipc
λ [Trunomy] > user create beto acme ipc
user beto pid=… tenant=acme ipc
λ [Trunomy] > tenant create evil
λ [Trunomy] > user create eve evil ipc
λ [Trunomy] > su ana
λ [ana] > ipc send beto hello
ok sent
λ [ana] > su beto
λ [beto] > ipc recv
hello
λ [beto] > ipc recv
(no messages)
λ [beto] > su eve
λ [eve] > ipc send ana x
denied: PermissionDenied
λ [eve] > su root
λ [Trunomy] > audit
```

`audit` must show an `ipc -> DENIED …` line for eve. To check what authority each one has, `tenant list` (as root) shows `ipc.send` and `ipc.recv` only under users created with `ipc`.

| Attempt | Result |
|---|---|
| sending from a user created **without** `ipc` | `denied: InvalidCapability` |
| sending from root | `denied: InvalidCapability` |
| sending to a user in another tenant | `denied: PermissionDenied` (and it is recorded in `audit`) |
| message longer than 32 bytes | `message too long (max 32 bytes)` |

**Emergency cut of a tenant (`tenant panic`).** `halt` shuts down the whole machine; this cuts only a compromised tenant and lets the others keep working. Only root can. With the users from the IPC example (`eve` in `evil`, `ana` and `beto` in `acme`):

```text
λ [Trunomy] > tenant panic evil
tenant evil PANIC: 0 processes killed, 3 capabilities revoked, 0 objects wiped
tenant frozen; its users are retired (tenant thaw allows NEW users)
λ [Trunomy] > tenant list
…
| 1001 evil [FROZEN] | eve [retired]           | 1002 | (no capabilities)      |
…
λ [Trunomy] > su eve
λ [eve] > whoami
denied: PermissionDenied
λ [eve] > su ana
λ [ana] > ipc send beto hello
ok sent
λ [ana] > tenant panic acme
denied: PermissionDenied
λ [ana] > su root
λ [Trunomy] > audit
```

What each step checks: **all** of `eve`'s capabilities are revoked (the number depends on what she did; here `object.create`, `ipc.send` and `ipc.recv`); `eve` can no longer launch anything; `acme` keeps working normally; a user cannot cut anyone. `audit` must show `panic -> allowed` (the cut), `identity -> DENIED PermissionDenied` (the attempt to launch `eve`) and `panic -> DENIED PermissionDenied` (`ana`'s attempt).

- `tenant panic <name> wipe` also erases the tenant's objects (zeroing them); without `wipe` they become unreachable but not destroyed.
- `tenant thaw evil` reopens the tenant for **new** users only (`user create eve2 evil` works); `eve` stays retired and without capabilities.
- The names of retired users stay taken until QEMU is restarted.

## 6. Fault containment

The `selftest` tests run in a worker with a user identity (not as root) and check that the kernel contains the fault and the shell stays alive:

```text
λ [Trunomy] > su bob
λ [Trunomy] > selftest fault
worker terminated by the kernel: <exception>
contained: the shell is still alive
```

| Test | What it simulates | Expected result |
|---|---|---|
| `selftest fault` | invalid memory access | terminated by the kernel (page fault), shell alive |
| `selftest ud` | invalid instruction | terminated (#UD), shell alive |
| `selftest hang` | infinite loop | `cpu quota exceeded` (or `timed out`), shell alive |
| `selftest stack` | stack overflow | terminated by the kernel, shell alive |
| `selftest console` | using the console without a capability | `denied: InvalidCapability`, recorded in `audit` |

After each one, `free` as root must show the same free frames as before: the kernel recovers the worker's memory.

## 7. Network (QEMU only)

The kernel discovers a legacy virtio-net device and negotiates it, but leaves it **inactive**: no DMA until the leader asks for it.

```text
λ [Trunomy] > net info                 (root)
net: virtio-net 1af4:1000 pci 00:02.0 mac 52:54:00:12:34:56 link up | negotiated: inactive (net up)
λ [Trunomy] > net up
net up: queues registered, bus master on (net selftest checks it end to end)
λ [Trunomy] > net selftest
net selftest: OK (ARP reply from the gateway 10.0.2.2: send and receive work)
λ [Trunomy] > net stats
net stats: tx 1 rx 1 | tx full 0 rx dropped 0 | queues ok
λ [Trunomy] > net down
net down: bus master off, device reset, queue memory wiped and returned
```

`net up` does, in the kernel and in this order: build and validate the two queues, register them, and only then turn on bus master and `DRIVER_OK`. `net selftest` sends a real ARP to the QEMU gateway and waits for its reply: it is the end-to-end test (it needs `-netdev user`, which `run_os.sh` already includes; with `NET=0` it fails). After `net down`, `free` must show the same free frames as before `net up`. With the network running, `net info` ends in `ACTIVE (queues registered, bus master on)`.

A user cannot do any of this:

```text
λ [Trunomy] > su bob
λ [bob] > net up
denied: PermissionDenied
```

The denial is recorded in `audit` (operation `net`). If `net selftest` fails, look at `net stats`: `QUEUE POISONED` means the device lied about its queues and the kernel stopped using them.

### Network between actors

Network access for actors requires a global capability: it is granted when the user is created with `net`. Each port is owned by the process that binds it; the others cannot use it.

```text
λ [Trunomy] > net up                              (root; without this there is no MAC or device)
λ [Trunomy] > tenant create lab
λ [Trunomy] > user create nora lab net
user nora pid=… tenant=lab net
λ [Trunomy] > user create omar lab
λ [Trunomy] > su nora
λ [nora] > net loopback hello
from 52:54:00:12:34:56 port 40001: hello
net loopback: OK (sent to this machine and received through the kernel)
λ [nora] > su omar
λ [omar] > net loopback hello
denied: InvalidCapability
λ [omar] > su root
λ [Trunomy] > audit
```

`net loopback` binds two of `nora`'s ports, sends to itself (MAC `self`) and receives through the kernel: it tests syntax, capabilities, port ownership and queues without another endpoint. `audit` must show `net DENIED` for `omar`. `net stats` adds up the protocol's drops (malformed frames, frames for another MAC or with no owner); in QEMU `-netdev user` you will see that number rise with foreign traffic (ARP, DHCP) that Trunomy's protocol drops on purpose.

Other user commands with `net`: `net listen <port> [1]` waits at most ~1 s for a message on that port and shows it, and `net send <source> <mac|self|bcast> <destination> <text>` sends a frame (`mac` = `aa:bb:cc:dd:ee:ff`). A port lives as long as the command: the user runs in a short process that dies when it ends, and then the kernel closes its ports. `tenant panic lab` closes them too.

#### Guided demo: `net demo`

If you only want to see what the network does, you do not have to type any of the above: as root, `net demo` walks through all of it inside the shell, with a `# …` line explaining each step before the real command (`> …`).

```text
λ [Trunomy] > net demo
# 1. Only root turns the NIC on. The kernel validates the device, then enables DMA (I-44).
> net up
…
# 2. Real traffic: an ARP request to the QEMU gateway 10.0.2.2 and its reply, through the queues.
> net selftest
net selftest: OK (ARP reply from the gateway 10.0.2.2: send and receive work)
…
# 6. omar has no network authority. The kernel denies both directions, even for his own tenant.
> su omar
> net send 40001 bcast 7 intruder
denied: InvalidCapability
> net listen 7
denied: InvalidCapability
```

The steps: network on, real ARP against the gateway, `nora` (with `net`) and `omar` (without `net`) in the `netlab` tenant, `nora`'s local loopback through the kernel, a real frame to the network (`ok` = the NIC accepted it; nobody confirms delivery: there is no TCP/IP), `omar` denied on send and on listen, and finally `net stats` and `audit` with the denials. It can be repeated (it reuses `netlab`, `nora` and `omar`). The demo decides nothing: each step is the normal command and the verdict is the kernel's. It leaves the network on; `net down` turns it off. Without a NIC (`NET=0`) it says so and stops. `python3 scripts/netdemotest.py` runs it in QEMU and checks the output (`netdemotest: OK`).

#### Real frames from the host

`scripts/nettest.py` boots the system with a `-netdev socket,udp=…` backend (`NETDEV` variable of `run_os.sh`): each guest frame reaches the script as a UDP datagram and each datagram from the script reaches the guest as a frame. The script is a second implementation of the protocol, written from the specification, so it checks the kernel against something that is not its own code.

```text
$ ./trunomy build            (trunomy.img is required)
$ python3 scripts/nettest.py --transcript /tmp/nettest.log
  ok   net send answers ok
  ok   the host receives a Trunomy frame
  ...
nettest: OK
```

It checks: what the guest emits (MAC, ports, payload, padding), that a user without `net.send` emits nothing, that `net listen` receives unicast and broadcast from the host, that eleven hostile frames (one broken rule each) are not delivered and are counted, that a port with no owner counts as a drop, and that after a flood the queues stay healthy and receiving continues. The guest does not announce when it starts listening, so the host resends the frame during the `net listen` window. `python3 scripts/nettest.py --selftest` tests only the codec, without QEMU. If something fails, `--transcript` saves everything the guest printed.

#### Two linked VMs

`scripts/nettest2.py` boots two VMs at once with their `-netdev socket,udp` backends pointed at each other (each with its own MAC, `NETMAC`, and in `SNAPSHOT=1` mode to share `trunomy.img` without writing it), creates a `lab` tenant with `nora` (with `net`) and `omar` (without `net`) in each, and checks: A→B and B→A with the other end's MAC shown only as data, 128 bytes intact, a frame for a third MAC that does not arrive, denial without `net.recv`/`net.send`, 10 messages in a row and healthy queues. It ends with `nettest2: OK`; `--transcript-dir DIR` saves what each VM printed. Since the receiver does not announce when it starts listening, the script retries the `net listen`/`net send` pair.

To do it by hand: two terminals with `NETMAC=52:54:00:12:34:56 SNAPSHOT=1 NETDEV="socket,udp=127.0.0.1:5001,localaddr=127.0.0.1:5000" ./run_os.sh` and `NETMAC=52:54:00:12:34:58 SNAPSHOT=1 NETDEV="socket,udp=127.0.0.1:5000,localaddr=127.0.0.1:5001" ./run_os.sh`; in each one `net up`, and in B `net listen 7` while in A `net send 40001 52:54:00:12:34:58 7 hello`.

Without a card: `NET=0 ./trunomy run` and `net info` gives `net: no device`. If you see `no usable … disable-modern=on`, QEMU presented a modern virtio: `run_os.sh` already passes `disable-modern=on`; if you use your own QEMU command line, add it.

There is no network authority for tenants yet: only the leader drives the device. What QEMU does not validate: DMA, IOMMU and real device timing. Those guarantees wait for real hardware (see `docs/invariants.md`, I-44).

## 8. Host tests

They boot nothing; they are fast and do not need QEMU.

```bash
./trunomy test            # unit tests of all crates
./scripts/ci.sh docs      # every invariant I-16+ has its traceability row
./scripts/ci.sh keys      # kernel and shell keys provisioned, non-zero and distinct
./scripts/ci.sh baremetal # builds bootloader, shell and kernel for their real targets
./scripts/ci.sh all       # all of the above (+ toolchain and lock)
```

`ci.sh all` ends with `[OK] all green`; any compiler warning counts as a failure. The individual targets are `lock`, `toolchain`, `host`, `baremetal`, `docs` and `keys`.

Reproducibility: builds two clean clones and compares the hashes.

```bash
./trunomy verify
```

It must end with `[OK] reproducible build` and the four artifacts (`kernel`, `shell`, `shell.bin`, `.efi`) as `SAME`. It also works on a tree without `.git` (an unzipped `.zip`): it builds two copies of the directory, without `.git`, `target/` or `.keys/`. Details in `docs/reproducible-demo.md`.

## 9. Checklist

| Step | Command | Result |
|---|---|---|
| Machine ready | `./trunomy check` | no `[MISSING]` |
| Builds without warnings | `./trunomy build` | finishes with no warnings |
| Boots | `./trunomy run` | prompt `λ [Trunomy] >` and dots `.` |
| Network | boot log / `net info` | virtio-net negotiated, inactive |
| Authority | `demo` | allowed / `PermissionDenied` / denied / `RevokedCapability` / `audit` |
| IPC | section 5 | `ok sent`, `hello`, `(no messages)`, eve's denial |
| Containment | `selftest …` as a user | worker terminated, shell alive, no leaks |
| Network between actors | `net loopback hello` as a user with `net` | `from …: hello`; without `net`: `denied: InvalidCapability` |
| Tenant cut | `tenant panic evil` | `PANIC: … revoked`, `[FROZEN]`/`[retired]`, `acme` intact |
| Network from the host | `python3 scripts/nettest.py` | `nettest: OK` |
| Network between two VMs | `python3 scripts/nettest2.py` | `nettest2: OK` |
| Guided network demo | `net demo` in the shell, or `python3 scripts/netdemotest.py` | 7-step walkthrough; `netdemotest: OK` |
| Line editor | `python3 scripts/linetest.py` (or `↑`/`←` by hand at the prompt) | `linetest: OK`; the side arrows do not move the cursor, `↑` recalls commands |
| Bounded audit | `python3 scripts/audittest.py` | `audittest: OK` |
| Rollback | `python3 scripts/rollbacktest.py` | `rollbacktest: OK` |
| Tests | `./scripts/ci.sh all` | `[OK] all green` |
| Reproducible | `./trunomy verify` | `[OK] reproducible build` |

## If something fails

| Symptom | Cause and fix |
|---|---|
| `[ERROR] cannot find QEMU` / `OVMF_CODE.fd` | install `qemu-kvm`/`qemu-system-x86` and `edk2-ovmf`/`ovmf`, or `QEMU=… OVMF_CODE=… ./trunomy run` |
| `the compiler emitted N warning(s)` | fix them or justify an `#[allow]` with a comment; CI requires zero warnings |
| `kernel_x86_64.elf.sig is missing: not loading (I-18)` | the bootloader rejects an unsigned kernel: run `./trunomy build` again |
| `image without a W^X layout descriptor` | the shell was built with an old linker script: `./trunomy build` |
| `kernel_x86_64.elf.ver is missing: not loading (I-49)` | the image predates kernel versioning: `./trunomy build` |
| `ROLLBACK REJECTED: … < minimum accepted …` | the NVRAM remembers a newer kernel than the one in the image: rebuild with the current version or, only if intended, restore the NVRAM (fresh `OVMF_VARS`) |
| `net: … found, not usable (modern virtio …)` | use `disable-modern=on` (`run_os.sh` already does) |
| `denied: InvalidCapability` on `ipc send` | the sender was created without `ipc` (or is root): create new users with `user create <n> <tenant> ipc` |
| `user exists` / `tenant exists` | that name is already used in this session: restart QEMU or use another |
| QEMU is slow | without `/dev/kvm` it uses emulation; it works, but takes longer |
| `cargo audit` red in the workflow | it is informational; check the notice in `docs/ci.md` |
