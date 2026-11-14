---
# The user-mode boundary (CONFIG_USERSPACE): verification handlers, the
# kernel objects and memory domains they guard, and arch syscall entry.
applies:
  areas: ["userspace", "syscall-handlers", "kernel", "memory-management", "demand-paging",
          "rtio", "device-driver-model"]
  paths: ["arch/*/core/**/userspace*", "arch/*/core/**/syscall*", "arch/*/core/**/mpu/**",
          "arch/*/core/**/mmu*", "arch/*/core/**/pmp*", "arch/*/core/**/swap*",
          "arch/*/core/**/fatal*", "arch/*/core/**/fault*", "arch/*/core/**/thread*",
          "kernel/userspace*", "kernel/mem_domain.c", "kernel/dynamic.c"]
  symbols: ["z_vrfy_*", "z_mrsh_*", "arch_buffer_validate", "arch_mem_domain_*",
            "z_object_*", "k_object_*", "z_user_*", "k_usermode_*"]
---
# Lens: the syscall boundary (user mode)

With `CONFIG_USERSPACE`, an unprivileged user thread (A4) calls syscalls with
arbitrary arguments and can change its own memory from another thread while
the kernel runs. The `z_vrfy_*` handlers and the arch entry code are the
boundary (threat model, "The syscall boundary"); `z_impl_*` trusts its
arguments. Without `CONFIG_USERSPACE` none of this applies: say so and move
on.

## Questions

- **Memory arguments.** Is every user pointer checked with
  `K_SYSCALL_MEMORY_READ/WRITE` (or `K_SYSCALL_MEMORY_ARRAY_*`) for the size
  actually accessed, including nested pointers inside a user-supplied struct?
  Can the size computation (`count * size`, `offset + len`) overflow before
  the check? Is the check against the right access mode (written memory
  checked only for read)?
- **Copy before use (TOCTOU).** Is a user struct or buffer copied into
  kernel memory (`k_usermode_from_copy`, `K_SYSCALL_MEMORY_*` followed by
  a copy) before its fields are validated, or are fields re-read from user
  memory after the check? Strings: `k_usermode_string_copy` with a bound?
- **Kernel objects.** Is every object argument checked with
  `K_SYSCALL_OBJ` / `K_SYSCALL_OBJ_INIT` / `K_SYSCALL_OBJ_NEVER_INIT` for
  type, initialisation state and the caller's permission? Driver instances:
  `K_SYSCALL_DRIVER_<subsys>` checks that the API function exists, so a NULL
  API pointer is not called? Objects freed (`k_object_free`, dynamic
  threads/stacks) while another user thread still uses them?
- **Handler coverage.** Does every `__syscall` have a handler that validates
  each argument, or does a handler pass an unchecked value (an index, a
  channel number, a size) through to an implementation that trusts it?
- **Data back to user mode.** Results written only to memory the caller
  supplied and was checked for write; no uninitialised kernel bytes or
  kernel pointers in what is copied out (P4).
- **Arch and domains.** Syscall entry and exit (stack switch, privilege
  drop, register clearing), fault handling for user threads, MPU/MMU/PMP
  programming of memory domains and partitions (alignment, overlaps, a
  partition granting more than requested), thread stack guards and the
  privileged stack: can user mode end up with access it was not granted?

## Not findings

- `z_impl_*` functions trusting their arguments when every handler that
  reaches them validates first (cite the handler).
- Supervisor-mode callers passing bad values (trusted, no differential).
- Missing hardening with no access gained (defence in depth).
