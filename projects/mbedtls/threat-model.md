# Mbed TLS threat model — security properties, attacker classes, scope rulings

<!--
Derived from the public threat models in Mbed TLS's and TF-PSA-Crypto's
SECURITY.md (development branches, 2026-11), restated as the numbered
properties and attacker classes every security-dive verdict names. Rulings
marked **Open** are this project's proposals where SECURITY.md is silent;
agents apply them until the Mbed TLS security team rules. Analysis agents
read this file, so it must never name or hint at specific findings (blind
benchmarking depends on it); add rules only in general form.
-->

Every verdict must **name the security property violated and the attacker
class required**. A defect that violates no property below, or that needs an
attacker more capable than the one that can reach it, is not a vulnerability.

Mbed TLS 4.x is the TLS/DTLS stack, X.509 and PKCS#7. Its cryptography is
TF-PSA-Crypto's (a reference tree in the snapshot): TF-PSA-Crypto's threat
model applies to every cryptographic operation Mbed TLS performs, and a
defect inside TF-PSA-Crypto is an upstream note, not a finding here. What is
in scope is how Mbed TLS *uses* it: which keys, inputs, lengths and results
it passes and trusts.

## Security properties (the assets we defend)

- **P1 Memory safety** — no attacker-supplied input (TLS/DTLS records and
  handshake messages, certificates, CRLs, CSRs, PKCS#7 objects, session
  tickets, cookies) causes memory corruption, an out-of-bounds read or other
  undefined behaviour. SECURITY.md states this explicitly for X.509 parsing:
  undefined behaviour while parsing a certificate, CSR or CRL is a
  vulnerability even though Mbed TLS does not enforce strict X.509
  compliance.
- **P2 Peer authentication** — a handshake succeeds only with a peer that
  proved possession of a credential the configuration accepts: a certificate
  chaining to the configured trust anchors that passes the configured
  checks (signature, validity, key usage and extended key usage, name
  constraints, revocation through the supplied CRLs, the expected hostname,
  the allowed signature algorithms and key sizes), or a configured PSK. A
  verification failure must not be ignorable unless the application chose
  `MBEDTLS_SSL_VERIFY_OPTIONAL`/`NONE`, and then the result must still be
  reported truthfully.
- **P3 Channel security** — the security guarantees the TLS/DTLS protocol
  itself offers: confidentiality and integrity of application data and of the
  handshake transcript (no forged, replayed (DTLS with replay protection on),
  reordered or truncated data accepted as genuine, no plaintext leaked),
  downgrade protection for version, ciphersuite, group and signature
  algorithm, binding of resumption, renegotiation and early data to the right
  session, and key separation between directions, epochs and sessions. Mbed
  TLS does not promise more than the protocol does (it cannot guarantee
  delivery or timeliness).
- **P4 Secret confidentiality** — private keys, PSKs, master and traffic
  secrets, ticket keys and other session secrets do not leak: not through
  memory disclosure, not left unzeroized where Mbed TLS owns the buffer, not
  through timing observable by an in-scope attacker (see A1, A3).
- **P5 Availability** — an unauthenticated peer cannot crash the process,
  make it loop without bound, or exhaust memory or CPU out of proportion to
  its own effort (a handful of messages driving unbounded allocation, a
  quadratic parse). Typically low severity on its own.

## Attacker classes (capabilities)

- **A1 Remote network attacker** — observes and modifies data sent over the
  network: sees content and timing of individual packets, suppresses, delays,
  injects and reorders messages. Can act as the peer: a malicious server to
  a client, a malicious client to a server, before any authentication. Can
  present any certificate chain it can construct; one the local trust
  anchors accept makes it A2. Remote (network-observable) timing is part of
  A1. Mbed TLS **aims to fully protect**
  against A1.
- **A2 Authenticated peer** — a peer that completes authentication: holds a
  certificate the local trust anchors accept, or a configured PSK, then
  misbehaves (malformed post-handshake messages, renegotiation, key updates,
  tickets, records). Findings that need A2 are real but lower severity; a
  P2 finding cannot require A2 by definition.
- **A3 Local timing attacker** — unprivileged software on the same machine
  that observes Mbed TLS's timing through shared hardware (cache timing,
  memory-bus contention, branch prediction); cannot read Mbed TLS's memory or
  files directly. Protection is **limited to publicly documented attack
  techniques**: a finding names the technique (e.g. a secret-dependent
  branch, memory access or variable-time operation reachable with a secret
  that the documented techniques recover).
- **A4 Object supplier** — supplies an encoded object the application parses
  outside a handshake: a certificate, chain, CRL, CSR or PKCS#7 object (for
  example an uploaded certificate or a signed firmware manifest). Gets P1
  (undefined behaviour) and P5; does **not** get "accepted non-compliant
  encoding" findings (see the X.509 ruling).

Not in scope (SECURITY.md: no security guarantees): **local non-timing side
channels** (power, EM, ADC noise), **local fault injection** and **physical
attacks** (power analysis, emissions, glitching). Countermeasures against
these exist in places; their failure is not a vulnerability.

## Trusted parties

- **The application** and its configuration (`mbedtls_config.h`, the
  `mbedtls_ssl_config` it builds, callbacks, BIO functions, the keys,
  certificates and CRLs it installs as trust anchors or own credentials).
  Misuse of the API with invalid arguments the documentation forbids is a
  bug in the application, not in Mbed TLS — unless the documentation says
  Mbed TLS validates that argument, or the "invalid" value is something a
  remote peer can drive.
- **Signing parties**: a certificate or CRL whose signature verifies is
  trusted to be correctly formed (SECURITY.md); CSRs are trusted to be
  standards-compliant.

## Scope rulings

- **Undefined behaviour is always in scope for attacker-reachable input.**
  Any input A1, A2 or A4 controls that reaches an out-of-bounds access,
  integer overflow feeding a size, use of uninitialised memory, use after
  free or double free is a P1 finding, whatever its practical impact (that
  sets severity, not reportability).
- **X.509 formatting.** Accepting a certificate, CRL or CSR that is not
  strictly X.509-compliant is **not** a finding by itself (SECURITY.md:
  Mbed TLS is not suitable as a CA without extra validation). It *is* a
  finding when the leniency changes a security decision: a chain, name
  constraint, key usage, hostname or revocation check that passes when it
  must fail (P2), or undefined behaviour (P1).
- **Timing.** Remote timing is A1 and fully in scope. Local timing (A3) is
  in scope only for publicly documented techniques. Two documented caveats
  are **not** findings: the table-based software AES, ARIA, Camellia, DES
  and GCM GHASH implementations (TF-PSA-Crypto's block-cipher caveat), and
  Everest's X25519 against local timing. Compiler-introduced timing
  differences count only at common optimisation levels (`-O2`, `-Os`) with
  common compilers.
- **Out-of-scope countermeasures.** Hardening against attacks outside this
  model (fault injection, physical side channels) may exist; weakening or
  bypassing it is not a vulnerability.
- **Fails closed is not a bypass.** A path that ends in a failed handshake,
  a fatal alert or a rejected certificate is not a P2/P3 violation (it may
  be P5 if an unauthenticated peer can drive it at disproportionate cost).
- **Configuration.** Name the configuration a finding needs. Code compiled
  only under non-default options (`MBEDTLS_SSL_RENEGOTIATION`,
  `MBEDTLS_SSL_DTLS_*`, `MBEDTLS_SSL_EARLY_DATA`, ECJPAKE, a given key
  exchange) is still in scope; reachability under the default
  `mbedtls_config.h` raises severity, it does not decide reportability.
  Options documented as insecure or for testing only (`MBEDTLS_TEST_HOOKS`),
  and weakening the application asked for (authmode
  `MBEDTLS_SSL_VERIFY_NONE`), are not findings.
- **Assertions are not checks.** `assert()`-style or debug-only checks that
  compile out in release builds do not count as validation.
- **Sample and test programs** (`programs/`, `tests/`, the framework
  submodule) are out of scope, as is the BIO glue in `net_sockets.c` beyond
  its own memory safety.
- **Debug output (Open).** `MBEDTLS_DEBUG_C` output is a development aid the
  application enables and routes. Proposed: secrets appearing in debug
  output at the verbose levels are not findings; memory-safety defects in
  debug code reachable with attacker data are P1 at low severity.
- **Non-default DoS (Open).** Proposed: P5 findings need an unauthenticated
  peer (A1) and disproportionate cost; resource use an authenticated peer
  (A2) or the application's own limits can bound is hardening, not a
  vulnerability.
