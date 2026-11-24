# Lens: holistic (deep dive)

The default lens for **dives**: a careful, function-by-function examination of
the target functions against the *whole* threat model. You have time; depth
beats breadth.

## For each target function

1. **Inputs and their trust.** List every input: parameters, fields of
   `mbedtls_ssl_context`/`mbedtls_ssl_session`/`mbedtls_ssl_handshake_params`,
   bytes of the record or handshake message being parsed, parsed certificate
   fields, ticket contents, callback results, configuration. For each, decide
   who controls it: A1 (any peer, before authentication), A2 (an
   authenticated peer), A4 (an object handed to a parser), or the trusted
   application. Follow callers (the handshake state machine, the record
   layer, `mbedtls_ssl_handle_message_type`, parse entry points) far enough
   to know what was validated before this function runs. Do not assume a
   check exists without reading it.
2. **What the function is responsible for.** Which property does correct
   behaviour protect (P1-P5)? What would an attacker gain if it misbehaved?
3. **Look for the defect.** At minimum:
   - length, offset and count arithmetic on peer data: overflow, underflow,
     truncation to a narrower type, signedness, off-by-one; reads past the
     end of the message (`end - p` checks before every read, including
     nested length fields that must fit inside their parent); writes past
     the output buffer (`MBEDTLS_SSL_OUT_CONTENT_LEN`, `buf + len`);
   - ASN.1/DER walking: tag and length checks via the TF-PSA-Crypto ASN.1
     helpers, their return values, and `end` pointers passed to nested
     calls;
   - state: a message accepted in a state where it makes no sense, a field
     from an earlier message (hello, HRR, ticket, extension list) trusted
     later without re-checking, a renegotiation or key update mixing old and
     new state;
   - authentication: every check P2 lists happens and its failure is
     honoured on every path (`verify_result`, authmode, callbacks returning
     errors, the TLS 1.2 and TLS 1.3 paths separately);
   - secrets: secret-dependent branches, memory accesses or early exits
     reachable with an A1 timing view (record decryption, padding, MAC and
     tag checks); buffers holding keys and secrets zeroized on every exit;
   - error paths: return values ignored, partially initialised structures
     freed or reused, fail-open defaults;
   - configuration variants: every `#if` branch (TLS 1.2 only, TLS 1.3
     only, both, DTLS, `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` off, PSK only,
     early data, renegotiation); name the options a defect needs.
4. **Decide.** If you have a concrete defect with an attacker path, raise a
   hypothesis. If the function is safe, say why in one line in the unit note,
   and record any invariant worth reusing in the dossier.

## Calibration

- Recall matters more than precision at this stage (an independent verifier
  checks every hypothesis), but every hypothesis must name a concrete defect,
  a concrete path from an attacker-controlled input, the attacker class, the
  property and the configuration. "Could be risky" is not a hypothesis.
- Apply the threat model's rulings: X.509 leniency is not a finding unless
  it changes a decision or causes undefined behaviour, block-cipher table
  timing is a documented caveat, fails closed is not a bypass, sample
  programs are out of scope. Say when you rely on a ruling marked Open.
- A defect inside TF-PSA-Crypto is an upstream note; its *misuse* by Mbed
  TLS (wrong length, unchecked status, wrong key or algorithm) is a finding.
- Mark a unit `partial` when you could not examine it thoroughly. Honest
  coverage is worth more than complete-looking coverage.
