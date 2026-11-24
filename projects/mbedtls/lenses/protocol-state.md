---
applies:
  areas: ["tls-record", "tls13-handshake", "tls12-handshake", "tls-core",
          "tls13-keys", "tls-session-store"]
---
# Lens: protocol state and channel security (P3, P5)

Find where the TLS/DTLS state machines accept a message, parameter or
transition the protocol forbids, in a way that breaks a guarantee the
protocol offers: confidentiality or integrity of data and transcript,
downgrade protection, binding of resumption, renegotiation and early data,
or availability against an unauthenticated peer.

## Questions

- **Message in the wrong state.** Every handshake message type checked
  against the current state; unexpected messages rejected, including
  ChangeCipherSpec, alerts, post-handshake messages (NewSessionTicket,
  KeyUpdate, CertificateRequest, HelloRequest) and application data during
  the handshake. Can a message skip a step (no CertificateVerify, no
  Finished) and still complete?
- **Negotiation.** Version negotiation and the downgrade sentinel in the
  server random; the selected ciphersuite, group, signature algorithm and
  extensions actually ones we offered and allow; HelloRetryRequest
  constraints (one HRR, the second ClientHello consistent with the first,
  the selected group offered and not already shared); extensions that must
  not appear in a given message rejected.
- **Transcript and keys.** Every handshake byte enters the transcript hash
  exactly once, in order, including HRR's synthetic message and DTLS
  fragments; keys switched at the right point for each direction; epochs and
  sequence numbers advance correctly and never wrap or repeat; records
  protected under the wrong epoch rejected.
- **Record integrity.** MAC or tag verified before any plaintext is used;
  padding checked; DTLS replay window updated only after authentication;
  records with an unexpected content type, empty fragments or excessive
  padding (TLS 1.3) handled as the protocol requires; truncation attacks
  (close_notify) reported to the application.
- **Renegotiation and resumption.** Secure renegotiation (RFC 5746)
  enforced as configured; session ID and ticket resumption checks that the
  ciphersuite, version, extended master secret and ALPN match; early data
  accepted only when allowed, within its limits, and rejected cleanly
  otherwise.
- **DTLS.** Cookie exchange before state is allocated, retransmission and
  flight handling, client port reuse (`MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE`),
  connection IDs.
- **Availability.** Loops driven by peer counts or lengths, allocations sized
  by peer claims, messages that can be repeated without limit before
  authentication (empty records, KeyUpdate, renegotiation requests, HRR),
  work done before the cookie or binder check.

## Not findings

- Behaviour the protocol specification itself mandates or allows.
- Options the application deliberately enabled with documented risks
  (legacy renegotiation, disabled replay protection).
- A path that ends in a fatal alert at reasonable cost (fails closed).
