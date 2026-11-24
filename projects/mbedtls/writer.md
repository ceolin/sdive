# Writer guidance: Mbed TLS

Project-specific guidance for the `sdive-writer` agent. The export carries
zepsec's verdict field set plus `property_violated` and `attacker_class`
(P1–P5, A1–A4 from `projects/mbedtls/threat-model.md`). Mbed TLS does not
file GHSAs: its advisories are published with the release that fixes them,
and the CVE comes from MITRE. The hand-off for Mbed TLS (zepsec or its own
tooling) is not built yet, so write the advisory text as Mbed TLS publishes
it; the fields stay the same.

## CVSS attack vector and privileges

- A1 remote network attacker or malicious unauthenticated peer → `AV:N`,
  `PR:N`. A man-in-the-middle position or a race raises `AC`. A
  malicious server attacking a client is still `AV:N` (`UI:R` only if a user
  must be lured to connect; a device's own connection needs none).
- A2 authenticated peer → `AV:N`, `PR:L` (a certificate the victim trusts or
  a configured PSK).
- A3 local timing attacker → `AV:L`, `PR:L`, usually `AC:H`; a remote timing
  attack (A1) is `AV:N` with `AC:H`.
- A4 object supplier → `AV:N` when the application accepts objects from the
  network (uploaded certificates, signed manifests), else `AV:L`; say which
  in `open_questions` if unclear.

Impact: memory corruption with an attacker-shaped write is normally
`C:H/I:H/A:H`; a crash only, `A:H` (P5 alone is usually Low); an
out-of-bounds read returned to the attacker `C:L`/`C:H` by how much and
what; a P2 bypass (impersonation) `C:H/I:H`; key or plaintext recovery
through timing `C:H`.

## Severity

Mbed TLS rates advisories High, Medium or Low by impact and reach: High for
the worst cases in common configurations (remote key recovery,
authentication bypass, remotely triggered memory corruption with a plausible
exploit), Low for defects unlikely to be exploitable (a small over-read with
no clear use, most DoS). The `severity` field must still be the CVSS band;
if the Mbed TLS rating would differ, say so in `open_questions`.

## reachable_surface vocabulary

`tls-handshake`, `tls-record`, `dtls`, `x509-parse`, `x509-verify`,
`pkcs7`, `session-resumption`, `timing`, `local-config`.

## Configurations

`affected_configurations` names the compile-time options the path needs
(`MBEDTLS_SSL_PROTO_TLS1_3`, `MBEDTLS_SSL_PROTO_DTLS`,
`MBEDTLS_SSL_RENEGOTIATION`, `MBEDTLS_SSL_EARLY_DATA`,
`MBEDTLS_SSL_SESSION_TICKETS`, `MBEDTLS_X509_CRL_PARSE_C`, a key exchange
such as `MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED`), the role (client,
server, both) and the runtime settings (authmode, `mbedtls_ssl_conf_*`
choices). Say whether each option is on in the default `mbedtls_config.h`:
reachability in the default configuration raises severity, it does not
decide reportability.

## Versions

Mbed TLS release tags (`v4.3.0`). Maintained branches are the development
line (4.x) and the LTS branches named in `BRANCHES.md` (currently 3.6 and
4.1). Write affected versions as Mbed TLS does ("Mbed TLS 4.0.0 to 4.3.0;
Mbed TLS 3.6.0 to 3.6.8"). The analysis runs on the 4.x development line
only: when the blamed code predates 4.0, name the 3.6 LTS as possibly
affected in `open_questions` (in 3.6 the crypto is in the same tree, so
the code may sit in a different file), rather than asserting it.

## Advisory text

Follow Mbed TLS's advisory layout in `advisory_description`: **Impact**
(who is affected and what an attacker gains), **Vulnerability** (the defect,
without exploit detail), **Resolution** (upgrade to the fixed release) and
**Work-around** (configuration changes that avoid the path, or "none").
Name components as Mbed TLS's documentation does ("the TLS 1.3 server's
ClientHello parsing", "X.509 certificate chain verification", "the DTLS
record layer"). Defects in TF-PSA-Crypto are not Mbed TLS advisories: if
the root cause is there, say so and stop.
