---
applies:
  min_priority: 3
---
# Lens: memory safety on attacker-controlled data

Find out-of-bounds reads and writes, integer errors, uninitialised memory,
use-after-free and double free that an attacker can drive (P1). In Mbed TLS
the data arrives as TLS/DTLS records and handshake messages from the peer
(A1, or A2 after authentication), DER/PEM objects handed to the X.509 and
PKCS#7 parsers (A4, and A1 when they arrive in a Certificate message),
session tickets and DTLS cookies presented by clients.

## Questions

- **Every read is preceded by a length check against the real end.** Parsers
  walk `p` towards `end`: is `end - p` checked before each read of a fixed
  field, each length prefix, and each body that length announces? Is a nested
  length checked against its *parent's* end, not the message's? Watch
  `MBEDTLS_SSL_CHK_BUF_READ_PTR` being skipped, checks done once and then
  `p` advanced further, and `p` compared with `end` after it already moved
  past it (pointer overflow is undefined behaviour too).
- **Extensions and lists.** Extension blocks, cipher suite lists, groups,
  signature algorithms, PSK identities and binders, ALPN names, SNI host
  names, certificate lists and per-certificate extensions (TLS 1.3): is each
  element's length bounded by the enclosing list, the list by the message,
  and zero-length and odd lengths handled? Are duplicates rejected where a
  later copy would overwrite an earlier allocation or pointer?
- **Integer arithmetic.** Sums of attacker lengths (`hdr + len`,
  `ext_len + 4`), 24-bit handshake lengths, record lengths minus MAC, IV,
  padding or tag sizes going negative, `size_t` to `int`/`uint16_t`
  truncation, signed returns used as lengths.
- **Record layer.** Decryption of CBC (IV, MAC, padding lengths), AEAD
  (explicit nonce, tag) and the null cipher: can a short record underflow
  the plaintext length? DTLS handshake reassembly: fragment offset plus
  length against the message length, the reassembly bitmap, the buffer for
  a message larger than the configured maximum; record and message buffering
  for future epochs.
- **Fixed-size destinations.** Copies into `session->id`, `randbytes`,
  `peer_verify_data`, ticket and cookie buffers, hostname and ALPN storage,
  key buffers, the output record: bounded by the destination or by the
  sender's claim? Writing paths: is space checked before each write
  (`MBEDTLS_SSL_CHK_BUF_PTR`)?
- **X.509, CRL, CSR, PKCS#7.** Names and multi-valued RDNs, SAN entries of
  each type, `otherName`, extensions with unexpected tags or lengths,
  serial numbers, times, signature parameters, PKCS#7 signer infos and
  certificate sets; recursion or chained structures (linked `next` lists)
  and their cleanup on a parse error halfway through. Functions that turn
  parsed fields into strings (`mbedtls_x509_dn_gets`, `*_info`): output
  bounded on every branch, `snprintf` returns handled?
- **Lifetime.** Peer certificate kept or freed (`KEEP_PEER_CERTIFICATE`),
  session copies, handshake structure freed and reused across
  renegotiation, HRR and resumption, buffers resized
  (`MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH`) while pointers into them survive.
- **Uninitialised data** sent to the peer or compared as if set.

## Not findings

- Bounds enforced earlier on every path, with the value unchanged since (cite
  the check and say why it still holds).
- Values only the application controls (configuration, buffer sizes it
  passes, its own certificates and keys), unless the documentation says
  Mbed TLS validates them.
- Code in `programs/` and `tests/`.
