---
applies:
  areas: ["tls-record", "tls13-handshake", "tls12-handshake", "tls-core",
          "tls13-keys", "tls-session-store"]
---
# Lens: timing side channels on secrets (P4, P3)

Find secret-dependent timing an in-scope attacker can measure: A1 over the
network (fully in scope) or A3 through shared hardware (cache, branch
predictor, memory bus; in scope for publicly documented techniques). Name
the technique and the secret: plaintext, padding validity, MAC or tag
correctness, key material, PSK identity validity, ticket contents.

## Questions

- **Record decryption.** CBC with MAC-then-encrypt: is the padding check
  and the MAC computation constant-time in the padding length (no early
  return, the MAC computed over a constant amount of data, Lucky
  Thirteen-style)? Does the error path, the alert sent, or the time before
  it differ between bad padding and bad MAC? AEAD and TLS 1.3: tag checked
  before anything plaintext-dependent; TLS 1.3 padding removal (scanning
  for the content type) not leaking the plaintext length beyond what the
  protocol reveals.
- **Comparisons.** MACs, tags, Finished `verify_data`, binders, cookies,
  ticket MACs and PSK identities compared with `mbedtls_ct_memcmp` or
  equivalent, not `memcmp` or an early-exit loop, when the attacker can
  submit guesses.
- **Secret-dependent branches and indices.** Branches, table lookups and
  array indices keyed by secret bytes (key material, pre-master secret,
  decrypted plaintext before authentication), including in the handling of
  RSA decryption results in TLS 1.2 key exchange (the Bleichenbacher class:
  does any observable behaviour depend on the PKCS#1 v1.5 padding being
  valid?).
- **Lengths and errors.** Variable-time work proportional to a secret length;
  different error codes or alerts for conditions an oracle could
  distinguish; debug or logging calls on secret-dependent paths.
- **Use of the constant-time helpers.** `mbedtls_ct_*` used with the right
  lengths and masks; results not re-branched on afterwards; compiler-visible
  patterns that common compilers at `-O2`/`-Os` turn into branches.

## Not findings

- Table-based software AES/ARIA/Camellia/DES and GCM GHASH timing, and
  Everest X25519 against local timing (documented caveats in the threat
  model).
- Non-timing side channels (power, EM), fault injection, physical attacks.
- Timing differences that depend only on public data (lengths the protocol
  reveals, message types, configuration).
- Variable-time code inside TF-PSA-Crypto primitives (upstream notes);
  variable-time *use* of their results in Mbed TLS is in scope.
