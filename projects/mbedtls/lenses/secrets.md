---
applies:
  areas: ["tls-record", "tls13-handshake", "tls12-handshake", "tls-core",
          "tls13-keys", "tls-session-store", "pkcs7", "x509-*"]
---
# Lens: secret handling (P4)

Find where key material and session secrets outlive their use, reach places
they should not, or are derived or separated wrongly. Secrets: private keys
and their PSA key IDs, PSKs, the pre-master and master secrets, TLS 1.3
early, handshake, application and resumption secrets, traffic keys and IVs,
ticket keys, exporter secrets, DTLS cookie keys.

## Questions

- **Zeroization.** Every stack and heap buffer that holds a secret wiped
  with `mbedtls_platform_zeroize` (or freed through a function that does)
  on every exit, including error paths and early returns; structures
  holding secrets wiped on free and on reset (`mbedtls_ssl_session_reset`,
  renegotiation, handshake free); PSA keys destroyed when the session or
  handshake no longer needs them.
- **Disclosure.** Secrets copied into buffers that are sent, logged
  (outside debug, see the threat model's debug ruling), serialized
  (`mbedtls_ssl_session_save`, `mbedtls_ssl_context_save`) or returned to
  the application when the API does not promise them; output buffers that
  include uninitialised bytes next to secrets.
- **Derivation and separation.** Correct labels, contexts and lengths in
  the TLS 1.2 PRF and TLS 1.3 HKDF-Expand-Label calls; keys for the two
  directions, epochs and sessions never shared; IV and nonce construction
  never repeating under one key (sequence number XOR, explicit nonces);
  key update replacing both key and IV.
- **Tickets and caches.** Ticket encryption key rotation and lifetime;
  ticket contents authenticated before use; the cache not handing a
  session to a different peer or context; serialized contexts integrity
  protected or documented as trusted.
- **Randomness.** Client and server random, session IDs, ticket nonces,
  cookies, explicit IVs and padding drawn from the configured RNG, with
  its errors honoured.

## Not findings

- Secrets the application keeps or exports by API design
  (`mbedtls_ssl_export_keys` callbacks, exporters).
- Physical and non-timing side channels.
- Zeroization inside TF-PSA-Crypto's own state (upstream notes).
