---
applies:
  areas: ["net-*", "networking*", "bt-*", "bluetooth*", "usb*", "lwm2m-*", "mcu-manager",
          "kernel", "userspace", "modem", "drivers-modem", "drivers-ethernet",
          "drivers-wi-fi*", "drivers-ieee-802-15-4", "drivers-can", "ipc", "open-amp",
          "osdp", "hawkbit", "mgmt-*", "west-project-hostap", "west-project-openthread",
          "shell", "logging", "zbus", "rtio", "filesystems", "little-fs", "vfs"]
---
# Lens: object lifetime, reference counting and concurrency

Find use-after-free, double free, leaks and races on objects whose lifetime
an attacker influences. In Zephyr the remote peer decides when a connection,
channel or session ends (threat model, "Peer lifetime"), and work runs
concurrently in ISRs, the system work queue, stack threads (RX/TX, BT RX)
and application threads.

## Questions

- **Reference counts.** `net_pkt_ref/unref`, `net_buf_ref/unref`,
  `bt_conn_ref/unref`, `net_context_ref/unref`, `k_object` permissions: on
  every path (errors included), does each reference taken get released
  exactly once? Is a buffer used after it was handed to a function that
  consumes it (queued, sent, unref'd)? Is a pointer into a buffer's data kept
  after the buffer is freed or its data moved (pull/push on a shared buffer,
  `net_buf_clone` sharing data)?
- **Teardown during a pending operation.** Disconnect, close, reset or
  unregister while a request, timer, work item or callback still holds the
  object: does the callback re-check state, or touch freed memory?
  `k_work_cancel*()` and `k_timer_stop()` do not wait for a running handler
  unless the `_sync` variant is used, and cannot be called from every context.
- **Slot and pool reuse.** Fixed arrays of contexts, connections, channels or
  sessions: after release, can a stale index, handle or pointer still reach
  the slot now owned by a new peer? Are IDs reused before every holder is
  gone?
- **Races.** State read in one context and modified in another without a lock
  or atomic (ISR vs thread, two stack threads, work queue vs caller): check
  then use on shared state, lists modified while iterated (`SYS_SLIST_FOR_EACH`
  vs the `_SAFE` variants), flags tested and set non-atomically.
- **Leaks per message.** An error path that drops a packet but not its buffer,
  context or fragment chain: a remote sender exhausts the pool (P6).
- **Locks.** Lock held across a call that can block on the peer, re-entered
  from a callback, or released on one path only: deadlock or wedge (P6).

## Not findings

- Lifetime managed entirely by the trusted application (it opens and closes
  its own objects), with no peer-driven trigger.
- Exhaustion that ends when the traffic stops (flooding).
