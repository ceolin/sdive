# Lens: holistic (deep dive)

The default lens for **dives**: a careful, function-by-function examination of
the target functions against the *whole* threat model. You have time; depth
beats breadth.

## For each target function

1. **Inputs and their trust.** List every input: parameters, globals, packet
   and buffer contents, descriptor and register values, syscall arguments,
   Kconfig and devicetree values. For each, decide who controls it using the
   attacker classes (A1 network, A2 adjacent/radio, A3 bus peer, A4 user
   thread, A5 non-secure world) and the trusted parties. Follow callers
   (search for call sites, callback registrations and handler tables) far
   enough to know what was validated before this function is reached, and
   from which context it runs (ISR, work queue, stack thread, syscall). Do
   not assume a check exists without reading it.
2. **What the function is responsible for.** Which property does correct
   behaviour protect (P1-P6)? What would an attacker gain if it misbehaved?
   Is there a privilege differential between the data's source and this code?
3. **Look for the defect.** At minimum:
   - length/offset/index arithmetic on controlled values: overflow,
     underflow, truncation, signedness, off-by-one; reads past the data a
     `net_buf`/`net_pkt` actually holds; checks that exist only as
     `__ASSERT`;
   - copies into fixed-size buffers bounded by the sender's claim; tables
     indexed by peer-supplied IDs;
   - object lifetime: references, teardown while an operation is pending,
     slot reuse, ISR/thread races, leaks per message;
   - protocol state: the message accepted in a state where it makes no sense;
     negotiated parameters trusted later;
   - security enforcement: required security level, key and nonce handling,
     replay protection, randomness;
   - error paths: return values ignored, cleanup on uninitialised state,
     fail-open defaults;
   - configuration variants: every `#if` branch, not just the default build;
     name the Kconfig options a defect needs.
4. **Decide.** If you have a concrete defect with an attacker path, raise a
   hypothesis. If the function is safe, say why in one line in the unit note,
   and record any invariant worth reusing in the dossier.

## Calibration

- Recall matters more than precision at this stage (an independent verifier
  checks every hypothesis), but every hypothesis must name a concrete defect,
  a concrete path from an attacker-controlled input, the attacker class, the
  property and the configuration. "Could be risky" is not a hypothesis.
- Apply the threat model's rules: privilege differential, no syscall boundary
  without `CONFIG_USERSPACE`, assertions are not checks, fails closed is not
  a bypass, shell and samples out of scope. Say when you rely on a ruling
  marked Open.
- Mark a unit `partial` when you could not examine it thoroughly. Honest
  coverage is worth more than complete-looking coverage.
