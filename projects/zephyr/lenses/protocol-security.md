---
applies:
  areas: ["bt-smp", "bt-gap", "bt-hci-host", "bt-l2cap", "bt-att-gatt", "bt-classic-l2cap",
          "bt-classic-rfcomm-sdp", "bt-ll-llcp", "bt-ll-iso", "bt-mesh-*", "bt-audio-*",
          "bluetooth-*", "networking-bsd-sockets", "net-tcp", "net-ipv6", "net-ipv4",
          "net-dns", "net-ssh", "net-quic", "net-wireguard", "net-dhcpv6",
          "networking-dhcpv4", "networking-wi-fi", "networking-coap", "networking-mqtt",
          "networking-http", "lwm2m-engine", "mcu-manager", "hawkbit", "mgmt-*",
          "osdp", "authentication*", "json-web-token", "secure-storage", "random",
          "drivers-entropy", "drivers-crypto", "west-project-mbedtls",
          "west-project-tf-psa-crypto*", "west-project-hostap",
          "west-project-uoscore-uedhoc", "west-project-openthread",
          "west-project-trusted-firmware-m", "settings"]
---
# Lens: protocol security (P5) and secrets (P4)

Find where an authentication, integrity, confidentiality or anti-spoofing
guarantee that a protocol promises does not hold, and where keys and
credentials leak. The primitives come from external modules; the question is
whether Zephyr uses them correctly and enforces what the protocol requires.

## Questions

- **Pairing and key agreement.** Bluetooth SMP (legacy and LE Secure
  Connections), BR/EDR SSP, mesh provisioning, OSDP secure channel,
  EDHOC/OSCORE, WPA via the supplicant glue: are the peer's public key,
  confirm and random values checked as the specification requires (point
  validation, confirm value compared before keys are used, reflection of
  our own values rejected)? Can the peer force a weaker method, key size or
  association model than the configuration allows (downgrade)?
- **Keys and their use.** Correct key, nonce and IV for each direction and
  session; nonces and counters never reused; replay protection (sequence
  numbers, IV index, replay lists) enforced before acting on a message;
  authentication tag verified *before* the payload is used, and compared in
  constant time where it matters.
- **Security-level enforcement.** Is the required security level (encrypted,
  authenticated, bonded, LESC) checked on every path to the protected
  operation, including after a re-pairing, key refresh or reconnection, and
  for every attribute, channel or object with permissions?
- **TLS/DTLS through Zephyr's layers.** Socket options and credential
  handling (`TLS_PEER_VERIFY`, hostname, session cache, credential tags):
  can verification end up disabled or the wrong credential used without the
  application asking? Is a failed handshake treated as failure?
- **Randomness where protocols rely on it.** TCP initial sequence numbers,
  DNS transaction IDs and source ports, RPAs, nonces and keys: drawn from a
  CSPRNG (`sys_csrand_get`), not `sys_rand*` or a predictable source, and
  errors from the RNG not ignored.
- **Secrets at rest and in transit.** Keys, LTKs, credentials and session
  state: zeroised when done, not logged, not copied into buffers that are
  sent or reused, not readable through settings, shell-independent APIs or
  syscalls by parties that should not have them.
- **Privacy and spoofing.** Identity resolution, address rotation, and
  anything that lets a peer impersonate another (bond overwritten by an
  unauthenticated pairing, identity address confusion).

## Not findings

- Defects inside Mbed TLS / TF-PSA-Crypto / TF-M themselves (upstream notes).
- Weaknesses the specification itself mandates, unless Zephyr's
  configuration claims to avoid them.
- Options the application deliberately set to weaken security.
