# Writer guidance: Zephyr

Project-specific guidance for the `sdive-writer` agent. The export carries
zepsec's `zepsec-deep-analyst` field set plus `property_violated` and
`attacker_class` (P1–P6, A1–A6 from `projects/zephyr/threat-model.md`).
Zephyr is a toolkit: the same code ships in very different products, so the
configuration a finding needs is part of the advisory, not a footnote.

## CVSS attack vector and privileges

Map the attacker class to the vector as the threat model does:

- A1 remote network → `AV:N`. A forged response to the device's own request
  (DNS, DHCP, SNTP, an HTTP/MQTT/CoAP/LwM2M server reply) is still `AV:N`;
  if it needs a position on the path or winning a race, raise `AC`.
  An authenticated server (TLS/DTLS with peer verification) sending malformed
  data → `PR:L` or `PR:H`.
- A2 adjacent → `AV:A`: Bluetooth (advertisers, scanners, unpaired and paired
  peers), IEEE 802.15.4/Thread, Wi-Fi, Ethernet on the segment, CAN, LoRa. A
  paired or bonded peer → `PR:L`; anything before pairing → `PR:N`.
- A3 bus peer → `AV:P` for something plugged in by hand (USB host or device,
  removable media), `AV:L` with `AC:H` for a component inside the product
  (the threat model's proposed bus-peer ruling, still Open: say so).
- A4 unprivileged user thread (`CONFIG_USERSPACE`) → `AV:L`, `PR:L`. Kernel
  memory corruption or escaping the memory domain changes scope (`S:C`).
- A5 non-secure world (TrustZone-M) → `AV:L`, `PR:L`, usually `S:C`.
- A6 physical → `AV:P`; normally out of scope (see the threat model).

Impact: memory corruption in supervisor context (P1) is normally
`C:H/I:H/A:H` when a write is attacker-shaped, `A:H` alone when only a crash
is reachable (P6); an out-of-bounds read that leaks bytes back to the
attacker is `C:L` or `C:H` by how much and what (P4).

## reachable_surface vocabulary

`network`, `bluetooth`, `radio`, `usb`, `parser`, `ota-dfu`, `filesystem`,
`ipc`, `syscall`, `shell`, `local-config`, `local-only`.

## Configurations

`affected_configurations` names the Kconfig options the path needs
(`CONFIG_NET_TCP`, `CONFIG_BT_SMP`, `CONFIG_LWM2M_RW_SENML_CBOR_SUPPORT`),
and for drivers the devicetree compatible (`nordic,nrf-usbd`) and whether an
in-tree board enables it. Use the brief's `enabled_by` as the starting point
and confirm in Kconfig: say whether each option is `default y`, selected by a
common option, or used by in-tree samples. Default-off and experimental
features are still reportable; reachability lowers severity, not
reportability. Name the build only when it matters (`CONFIG_ASSERT=n`, the
production default, for an assertion-only check).

## Versions

Zephyr release tags (`v4.2.0`). Zephyr maintains LTS and recent release
branches: when the blamed code is old, say "present since at least vX.Y.Z"
rather than guessing a floor, and note in `open_questions` if a supported
branch (`v3.7-branch` LTS) may need a backport.

## Advisory text

Name the subsystem as Zephyr's documentation does ("the Bluetooth host's
L2CAP layer", "the IPv6 fragment reassembly code", "the USB device stack's
MSC class"). Never mention samples or tests as the affected code: if the
defect is reachable only through a sample, it is not a Zephyr vulnerability
(threat model: samples, Open).
