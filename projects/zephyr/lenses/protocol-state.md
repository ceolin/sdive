---
applies:
  areas: ["net-tcp", "net-ipv6", "net-ipv4", "net-core", "net-ppp", "net-dhcpv6", "net-dns",
          "net-ssh", "net-quic", "net-wireguard", "net-lib", "networking*",
          "bt-l2cap", "bt-att-gatt", "bt-smp", "bt-hci-host", "bt-gap", "bt-services",
          "bt-classic-*", "bt-ll-*", "bt-audio-*", "bt-mesh-*", "bluetooth-*",
          "lwm2m-engine", "lwm2m-formats", "usb-device-*", "usb-host", "usb-c",
          "mcu-manager", "osdp", "hawkbit", "mgmt-*", "authentication-fido2",
          "drivers-can", "modbus", "lora*", "drivers-modem", "modem",
          "west-project-hostap", "west-project-uoscore-uedhoc"]
---
# Lens: protocol state machines

Find what goes wrong when a peer sends a valid-looking message at the wrong
time, in the wrong state, or out of order. Protocol code is written for the
expected sequence; the attacker (A1/A2/A3) chooses the sequence.

## Questions

- **Wrong state.** For each received PDU, request or response type: is the
  current state checked before acting on it? What happens on a response with
  no request outstanding, a second request while one is pending, a
  confirmation for a procedure never started, data before setup completes,
  or a message after teardown began (TCP segments in TIME_WAIT/CLOSED, L2CAP
  responses with an unknown identifier, ATT responses without a request, an
  SMP command out of the pairing sequence, LL control PDUs during another
  procedure, USB requests before SET_CONFIGURATION, LwM2M or CoAP replies to
  stale tokens)?
- **Identifiers.** Transaction IDs, sequence numbers, tokens, channel IDs and
  handles from the peer: matched to the right outstanding operation and
  connection, or can a reply for one context be applied to another?
- **Transitions that skip steps.** Can the peer drive the machine into a state
  that assumes earlier steps (keys derived, parameters negotiated, buffers
  allocated) which did not happen? Is partially built state cleaned up when
  a procedure is abandoned or times out?
- **Negotiated parameters.** MTU, MPS, window, credits, segment sizes, PHY and
  timing: validated against both the specification and local limits, and
  re-validated when renegotiated mid-connection? Does a later use assume the
  value from an earlier negotiation?
- **Counters and timers.** Credits, windows, retransmission counts, sequence
  arithmetic (wraparound comparisons), timers restarted or left running in
  the wrong state.
- **Error and reset paths.** Does a reject, reset or error from the peer leave
  the state consistent, or half-updated (resources held, callbacks pending,
  flags set)?

## Not findings

- A rejected or dropped message with nothing left inconsistent (fails closed).
- Deviations from the specification with no security effect; report them only
  when they break a property (P1, P4, P5, P6).
