# Writer guidance: MCUboot

Project-specific guidance for the `sdive-writer` agent. The export carries
zepsec's `mcuboot-deep-analyst` field set, including `property_violated` and
`attacker_class` (P1–P6, A1–A3 from `projects/mcuboot/threat-model.md`).

## CVSS attack vector and privileges

- `AV:P`: physical access, JTAG, external flash or a bus interposer.
- `AV:L`: serial recovery over a wired UART, or a local console.
- `AV:A`: adjacent radio (BLE SMP).
- `AV:N`: network-delivered images (an OTA update an A1 attacker supplies).
- `PR:N` for the unauthenticated recovery interface.

## reachable_surface vocabulary

`serial-recovery`, `smp-dfu`, `ota-dfu`, `image-parser`, `tlv`, `swap`,
`flash-backend`, `usb`, `crypto`, `local-config`, `physical`.

## Configurations

Name build options and ports as MCUboot does: `MCUBOOT_SERIAL`,
`MCUBOOT_ENC_IMAGES`, `MCUBOOT_SWAP_USING_MOVE`, Zephyr's
`CONFIG_BOOT_SERIAL_UART`, `CONFIG_BOOT_SWAP_USING_OFFSET`, and the port
("Zephyr port", "Espressif port") when only one is affected.

## Versions

MCUboot release tags (`v2.1.0`).
