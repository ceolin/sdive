---
# Attacker-facing code: priority 4-5 areas (network, radio, bus, syscall,
# storage and management surfaces). Shell commands and platform glue are out.
applies:
  min_priority: 4
---
# Lens: memory safety on attacker-controlled data

Find out-of-bounds reads and writes, integer errors and uninitialised memory
that an attacker can drive. In Zephyr the data arrives in `net_pkt` and
`net_buf` chains (IP, Bluetooth, IEEE 802.15.4, CAN), USB setup packets and
descriptors, CBOR/JSON/TLV payloads, filesystem images and syscall
arguments. The attacker class follows from the source (threat model, A1-A4).

## Questions

- **Where does each length, offset, count or index come from**, and is it
  checked against what the buffer *actually holds* (`net_buf.len`,
  `net_pkt_remaining_data()`, `net_buf_tailroom()`, the descriptor's real
  size) before use, on every path and in every `#if` branch?
- **Pull and read helpers.** `net_buf_pull*()`, `net_buf_pull_mem()`,
  `net_buf_simple_pull*()`, `net_pkt_read*()`, `net_pkt_skip()`,
  `net_pkt_get_data()` / `NET_PKT_DATA_ACCESS_DEFINE`: which of them check the
  remaining length and which only `__ASSERT` it? A pull of more than `len`
  with assertions off reads past the data. Is a NULL return from
  `net_pkt_get_data()` or `net_buf_pull_mem()` handled?
- **Fragments and chains.** Data split across `net_buf` fragments: does the
  code assume a header is contiguous in the first fragment
  (`net_buf_frags_len()` vs `buf->len`)? Does reassembly (IPv4/IPv6
  fragments, L2CAP SDUs, ISO SDUs, mesh SAR, 6LoWPAN, USB transfers) bound
  the total and each piece, and handle overlaps, duplicates and missing
  pieces?
- **Integer arithmetic.** Can `a + b` wrap, `a - b` underflow (header length
  greater than packet length), a `uint16_t` or `uint8_t` truncate a larger
  value, a signed length go negative and pass an unsigned check? Watch
  options and TLVs where `len` includes or excludes its own header.
- **Fixed-size destinations.** Stack buffers, struct arrays, per-connection
  tables, static pools: is each copy bounded by the destination, or by the
  sender's claim? `memcpy`, `strcpy`/`strncpy` (termination), `snprintk`
  return values used as lengths, `net_buf_add_mem()` without a tailroom
  check.
- **Index into tables.** Handles, channel IDs, endpoint numbers, attribute
  handles, object IDs, opcodes used to index arrays or callback tables:
  checked against the table size before use, including zero and the maximum?
- **Uninitialised data.** Structures or buffers sent back to a peer, or copied
  to user mode, before every byte is written (padding included): P4.
- **Recursion and loops** driven by attacker nesting or counts (CBOR, JSON,
  DNS name compression pointers, option lists): bounded?

## Not findings

- Bounds enforced earlier on every path, with the value unchanged since (cite
  the check and say why it still holds).
- Values only a trusted party (the application, Kconfig, devicetree)
  controls, without `CONFIG_USERSPACE` exposure: API misuse, not a
  vulnerability.
- Code reachable only from shell commands, tests or samples.
