# Zephyr threat model — security properties, attacker classes, scope rulings

<!--
DRAFT, written for security-dive (2026-11-14). Zephyr has no project-wide
threat model: doc/security/security-overview.rst asks for one, and the only
written models are user mode's (doc/kernel/usermode/overview.rst, "Threat
Model") and the narrower doc/security/sensor-threat.rst. This draft builds on
both, plus the general rules zepsec's Zephyr analyst applies (privilege
differential, attack-vector mapping, reportability), written down here so
they are explicit.

Analysis agents read this file, so it must not hint at known bugs (blind
benchmarking depends on it): no finding IDs, no advisory references, rules in
general form only. Rulings marked **Open** are proposals to settle with the
Zephyr security team; until they are settled, agents apply the proposal and
say in their verdict that they relied on an open ruling.
-->

Every verdict must **name the security property violated and the attacker
class required**. A defect that violates no property below, or that needs an
attacker more capable than the one that can reach it, is not a
vulnerability. Zephyr is a toolkit: the same code ships in very different
products, so every verdict also states **which configuration** it needs (see
"Configuration and reachability").

## Security properties (the assets we defend)

- **P1 Kernel integrity** — input from an attacker cannot corrupt memory,
  hijack control flow or run code in supervisor context. In most Zephyr
  builds there is no user mode, so everything — kernel, drivers, stacks and
  the application — runs in supervisor context, and any attacker-driven
  memory corruption violates P1.
- **P2 User-mode isolation** (`CONFIG_USERSPACE`) — as Zephyr's user-mode
  design states: a user thread cannot read or write memory it was not
  granted, use kernel objects or driver instances it was not granted, raise
  its own privilege, or interfere with the kernel or with threads in other
  memory domains.
- **P3 Secure-world isolation** (TrustZone-M) — non-secure code cannot read
  secure-only state or corrupt the secure side through the calls Zephyr
  exposes across the boundary. The secure firmware itself (TF-M) is an
  external module; Zephyr's side is the non-secure glue and the
  secure-entry code in `arch/`.
- **P4 Confidentiality** — secrets (long-term keys, Bluetooth pairing keys,
  TLS credentials, secure-storage contents, application data handed to the
  stack) and uninitialised or stale memory are not disclosed to an attacker
  (over a protocol, through a syscall, or across a domain). *A property in
  its own right: a leak is reportable without proof that the leaked bytes
  are sensitive in a particular product.*
- **P5 Protocol security** — the authentication, integrity, confidentiality
  and anti-spoofing guarantees each protocol promises hold as specified:
  Bluetooth pairing, bonding, encryption and privacy; mesh provisioning and
  network/app keys; TLS/DTLS peer verification through Zephyr's socket and
  credential layers; unpredictable values where the protocol relies on them
  (TCP initial sequence numbers, DNS transaction IDs and ports, nonces).
  Cryptographic primitives come from external modules (Mbed TLS / PSA
  Crypto); their internal defects are upstream notes, while misuse of them
  from Zephyr code is in scope.
- **P6 Availability** — an attacker cannot crash, hang, deadlock or
  permanently disable the device or a subsystem with crafted input: one
  malformed packet that faults, asserts or wedges a thread, a per-message
  leak that eventually exhausts a buffer pool, unbounded recursion or loops.
  Plain volume (flooding a link) is not a finding.

## Attacker classes (capabilities)

Pre-authentication capability is the default for each class; a finding that
needs an authenticated or paired peer says so, and scores `PR:L` (or
higher) accordingly.

- **A1 Remote network** — sends arbitrary IP traffic to the device:
  datagrams and segments to any reachable port, and **forged or hostile
  responses** to the device's own requests (DNS, DHCP, SNTP, and server
  replies to HTTP, MQTT, CoAP and LwM2M clients) unless the exchange is
  authenticated by TLS/DTLS with peer verification on. An authenticated
  server is still an attacker for P1/P4/P6 (it can send malformed data), at
  `PR:L`/`PR:H`. Scored `AV:N`.
- **A2 Adjacent** — shares a link or radio with the device: Bluetooth LE and
  Classic (advertisers, scanners, unpaired and paired peers), IEEE 802.15.4 /
  Thread, Wi-Fi, Ethernet on the same segment (L2 frames, ARP, neighbour
  discovery, gPTP), CAN, LoRa. Scored `AV:A`.
- **A3 Bus peer** — a device on an external bus the product exposes: a USB
  host talking to Zephyr's device stack, a USB device plugged into Zephyr's
  host stack, removable storage, a modem or co-processor on UART/SPI, a
  peripheral answering on I2C/SPI/I3C. Scored `AV:P` for something plugged in
  by hand, `AV:L` for a component inside the product. *Scope is Open — see
  "Bus peers".*
- **A4 Unprivileged user thread** (`CONFIG_USERSPACE` only) — calls any
  syscall it is permitted to with arbitrary arguments, and runs other user
  threads in its domain that change its memory concurrently (user memory
  can change between a kernel check and a kernel use). Scored `AV:L`,
  `PR:L`.
- **A5 Non-secure world** (TrustZone-M) — non-secure code calling into the
  secure side through the exposed entry points. Scored `AV:L`, `PR:L`.
- **A6 Physical** — debug ports, flash readout, fault injection, probing.
  Resistance is defence in depth, not a guaranteed property; findings that
  need A6 are out of scope unless they defeat a mechanism that exists
  specifically to resist it.

**Trusted (not attackers):** the product developer and everything they
control — application code running in supervisor mode, Kconfig, devicetree,
board files, linker scripts, build options, the bootloader, factory
provisioning. A defect that only such a party can trigger is not a
vulnerability.

## The load-bearing rules

### Untrusted relative to whom — the privilege differential

A memory-safety bug matters only if exploiting it gives the attacker a
capability they did not already have. Before calling a parser or loader bug
a vulnerability, ask: **does the code that processes the input run at a
higher privilege than whoever supplies it?**

- Network, radio and bus input is processed in supervisor context by code
  that outranks the sender: a differential always exists (A1–A3 → P1).
- If processing a *well-formed* input already hands the supplier equal
  capability by design, a bug in that processing grants nothing. Example
  of the reasoning: a loader whose loaded code runs in kernel mode already
  gives whoever can get code loaded kernel execution, so a bounds bug in
  that loader adds nothing in that configuration. It matters again where
  a real differential exists — a syscall that lets a user thread drive
  kernel-side parsing, or a loader that sandboxes the loaded code in user
  mode while itself running in the kernel. Check the actual privilege (is
  there a `__syscall` entry? what mode does the result run in?), don't
  assume it.

### No user mode, no syscall boundary

Without `CONFIG_USERSPACE`, application code is trusted. A kernel, driver or
library API that misbehaves when its *caller* passes a bad pointer, size or
handle is **API misuse, not a vulnerability** — unless the bad value
originates from an attacker (A1–A3) and the API is the place that is meant
to validate it. Most Zephyr APIs document their preconditions and check them
only with `__ASSERT`.

### The syscall boundary (`CONFIG_USERSPACE`)

`z_impl_*` functions trust their arguments; the generated marshalling and
the `z_vrfy_*` handlers are the boundary, and must:

- validate every pointer and length against the caller's memory
  (`K_SYSCALL_MEMORY_READ/WRITE` and friends) with arithmetic that cannot
  overflow;
- validate every kernel object and driver instance (type, initialised state
  and the caller's permission on it), and the driver API being invoked;
- **copy user data into kernel memory before checking and using it** when
  it is read more than once — a check-then-use on user memory is a
  TOCTOU that A4 wins with a second thread;
- never write kernel data to user memory the caller did not supply, and
  never leave uninitialised kernel bytes in data copied out (P4).

A defect at the boundary violates P2; one that also corrupts kernel memory
violates P1 as well.

### Assertions are not checks

`__ASSERT` compiles to nothing unless `CONFIG_ASSERT=y`, which shipped
products usually leave off. A bounds or state check that exists only as an
assertion is **missing** in production (P1 and friends); an assertion that
an attacker can trigger when `CONFIG_ASSERT=y` is a P6 crash. State which
build the finding concerns.

### Who checked the length

Lengths, offsets, counts and indices read from a packet, PDU, descriptor or
register value are attacker data until checked against what the buffer
actually holds. A check made by an earlier layer counts only if the value
cannot change after it (same buffer, no re-read, no fragment or
reassembly path that skips it); say where the check is.

## Configuration and reachability

- Name the Kconfig options a finding needs, their defaults, and whether the
  path is selected implicitly by something common (`default y`,
  `select`ed by a popular option, used by in-tree samples).
- **Default-off and experimental features are in scope.** Zephyr publishes
  advisories for them; reachability affects severity, not reportability.
- Devicetree decides which drivers are built; a driver finding names the
  compatible and whether any in-tree board enables it.
- **Out of scope:** code only built for tests (`CONFIG_ZTEST`, test-only
  options, `tests/`), samples (`samples/` — example code, not shipped
  product code; *Open*: a sample that products commonly copy verbatim), host
  tools under `scripts/` (a separate threat model), and options that exist
  only for debugging (verbose logging, debug shells, tracing back-ends)
  unless they are on by default.
- External west modules (`modules/` projects, HALs, Mbed TLS, TF-M,
  OpenThread, …) are not Zephyr's code: their defects are upstream notes.
  Zephyr's own glue to them (in-tree `modules/` directory, `subsys/*` shims)
  is in scope.

## Scope rulings

- **DoS** (P6) — crafted input that crashes, asserts, deadlocks or leaks
  per message is in scope at the reaching class's attack vector. Flooding,
  and exhaustion that recovers when the traffic stops, is not. A reachable
  NULL dereference is a P6 crash (and P1 where address 0 is mapped and
  writable).
- **Defence in depth** — a missing hardening feature (stack canaries, MPU
  guard placement, CFI) is not a vulnerability by itself. A *mitigation that
  claims to work and doesn't* (a stack guard that can be skipped, a
  memory-domain partition that maps more than intended) is.
- **Fails closed ≠ bypass** — a path that ends in a rejected connection, a
  dropped packet or a returned error is not a finding, provided nothing
  leaks or is left half-updated on the way out (resources, references,
  connection state).
- **Peer lifetime** — the remote side controls when a connection, channel or
  session ends. Use of per-connection state after the peer has torn it down
  (disconnect during a pending operation, reuse of a freed context or
  buffer) is attacker-triggerable, and counts as P1 (or P6 when only a
  crash is reachable).
- **Bus peers** — **Open.** Proposal: a peer on a bus the user can reach
  from outside (USB, removable media, external connectors) is an attacker
  (A3, `AV:P`), in scope at normal priority. A component soldered inside the
  product (sensor, PMIC, on-board co-processor) is trusted for
  confidentiality and logic, but a memory-safety defect driven by its
  replies is reportable at low severity (`AV:L`, `AC:H`): a compromised or
  counterfeit part is a realistic stepping stone, and these fixes are
  cheap.
- **Bluetooth host and controller** — **Open.** Proposal: for host analysis
  an HCI controller on a separate chip is an A3 bus peer, but over-the-air
  data it relays is A2 and keeps `AV:A`. The in-tree controller is analysed
  as receiving A2 input directly.
- **Shell** — **Open.** Proposal: the shell is a trusted administrative
  interface; a command that misbehaves on bad arguments needs an attacker
  who already has the shell, so it is not a finding. In scope: bypassing
  shell authentication or obscured input where configured, and reaching the
  shell over a remote back-end without the configured access control.
- **Device management (mcumgr / SMP)** — like serial recovery in MCUboot,
  SMP is unauthenticated unless the transport or an application hook adds
  authentication: "can upload an image" or "can run a permitted command" is
  granted. The findings are memory corruption, escaping the area a command
  may touch, and bypassing the access-control hooks the product configured.
- **Filesystems** — an image on removable media is attacker data (A3); a
  filesystem in internal flash written only by the device is trusted absent
  A6 or prior code execution.
- **Configuration matters** — state the options, boards or compatibles a
  finding needs and whether those are realistic for shipped products.
