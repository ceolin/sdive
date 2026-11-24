---
applies:
  areas: ["tls13-handshake", "tls12-handshake", "tls-core", "x509-*", "pkcs7",
          "tls-session-store", "tls13-keys"]
---
# Lens: peer authentication (P2)

Find where a handshake can succeed, or a certificate or signed object be
accepted, without the proof the configuration requires. The primitives are
TF-PSA-Crypto's; the question is whether Mbed TLS asks the right question
and honours the answer.

## Questions

- **Chain building and verification.** Trust anchor matching (by name *and*
  key), path length and `basicConstraints` CA flag on every intermediate,
  signature verified with the issuer's key over the exact TBS bytes,
  signature algorithm allowed by the profile (`mbedtls_x509_crt_profile`:
  hashes, key types, curves, minimum RSA size), validity times, self-signed
  and self-issued certificates, loops, the maximum chain depth. Does every
  failure set the right `MBEDTLS_X509_BADCERT_*` flag, and can a later step
  clear or overwrite a flag an earlier step set?
- **Extensions that restrict.** Key usage and extended key usage for the
  role (server, client, signing), name constraints (permitted and excluded,
  every name type the code matches, case and encoding), critical extensions
  the code does not understand.
- **Revocation.** CRLs matched to the right issuer, CRL signature and
  validity checked, serial comparison exact (leading zeros, length), the CA
  allowed to sign CRLs.
- **Hostname.** Matching against SAN DNS names (and CN only when the
  standard allows), wildcard rules, IP addresses, embedded NULs, case,
  trailing dots; what happens when the application set no hostname for a
  client handshake that verifies certificates.
- **Handshake binding.** CertificateVerify (TLS 1.3) or ServerKeyExchange /
  CertificateVerify (TLS 1.2) checked with the leaf's key over the right
  transcript or parameters, with the negotiated and permitted signature
  algorithm; the peer's key type matching the ciphersuite; Finished verified
  before application data is accepted; a missing or empty Certificate
  message treated per authmode (`REQUIRED`, `OPTIONAL` reporting failure,
  client certificates on the server).
- **Results honoured.** `verify_result` and callback return values reach
  the handshake outcome on every path, TLS 1.2 and 1.3, client and server,
  renegotiation and resumption; `MBEDTLS_SSL_VERIFY_OPTIONAL` reports a
  failure truthfully; a callback error is not converted into success.
- **Resumption and PSK.** Tickets and cached sessions bind the peer identity
  and authentication result they were issued for; a resumed session cannot
  claim a certificate it never verified; PSK binders verified before the PSK
  is used; external and resumption PSKs not confused; ticket age and
  lifetime enforced as configured.
- **PKCS#7.** Signer matched to the right certificate, signature over the
  right content (detached or not), digest algorithm checked, and the
  certificate validated as the caller expects.

## Not findings

- Leniency in parsing a correctly signed object (threat model: X.509
  formatting) unless it changes one of the decisions above.
- Weak choices the application configured (a permissive profile, authmode
  `NONE`, its own trust anchors).
- Defects inside TF-PSA-Crypto's signature verification (upstream notes).
