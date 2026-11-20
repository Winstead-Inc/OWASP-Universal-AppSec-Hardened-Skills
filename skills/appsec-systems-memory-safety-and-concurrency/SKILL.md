---
name: appsec-systems-memory-safety-and-concurrency
description: Enforces systems-level memory safety, integer overflow defense, concurrency invariants, and algorithmic DoS limits. Use when writing low-level code, systems services, FFI bindings, C/C++ or Rust applications, multi-threaded algorithms, or handling high-throughput concurrency.
---

# Systems-Level Memory Safety & Concurrency Engineering Runbook

## Overview

Memory corruption and uncontrolled concurrency represent the most destructive class of software vulnerabilities, consistently accounting for over 70% of high-severity CVEs across the industry. Exploits ranging from arbitrary code execution via buffer overflows to state corruption via race conditions stem from inadequate memory validation, incorrect synchronization, and missing resource limits. This runbook codifies mandatory engineering invariants for systems software, native binaries, FFI bindings, and concurrent pipelines across Rust, C/C++, Go, and multi-threaded runtimes.

---

## 1. Memory Safety & Integer Arithmetic Invariants

### 1.1 Checked Arithmetic & Overflow Defense
Integer overflows and underflows can bypass allocation checks, resulting in undersized heap allocations followed by catastrophic heap buffer overflows.

1. **Rule 1 (Checked Arithmetic for Bounds & Allocations)**: Every arithmetic calculation involving buffer sizes, offsets, loop bounds, or memory allocation sizes must use checked, saturating, or overflowing arithmetic operations (`checked_add`, `saturating_mul` in Rust; SafeInt or compiler built-ins `__builtin_add_overflow` in C/C++).
2. **Rule 2 (Explicit Bounds Verification)**: Arrays, slices, and buffers must never be accessed via unchecked pointer arithmetic without prior verification against slice lengths. Never use `get_unchecked` in Rust unless mathematically proven and reviewed under safety audit.
3. **Rule 3 (Truncation and Sign Mismatch Prevention)**: Explicitly prevent signed-to-unsigned conversions and size downcasting (e.g., casting `size_t` or `u64` to `u32` or `int32`), which can turn large numbers into small positive values or negative indices.

### 1.2 Binary Hardening & Compiler Sanitizers
All native C/C++ and Rust binaries must be compiled with battle-hardened compiler flags and analyzed under sanitizers during CI:

```bash
# Clang / GCC Hardened Production Flags
-fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wformat -Wformat-security
-fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -fcf-protection=full

# CI Sanitizer Builds (Address, Undefined Behavior, Thread Sanitizers)
-fsanitize=address,undefined -fno-omit-frame-pointer
```

- **ASLR (Address Space Layout Randomization)**: Compile all binaries as Position Independent Executables (`-fPIE -pie` / `/DYNAMICBASE` on Windows).
- **DEP/NX (Data Execution Prevention)**: Enforce non-executable stacks and heaps (`-Wl,-z,noexecstack` / `/NXCOMPAT` on Windows).
- **RELRO (Relocation Read-Only)**: Enforce full RELRO (`-z,relro,-z,now`) to prevent Global Offset Table (GOT) overwrite attacks.

---

## 2. Rust Unsafe Discipline & FFI Boundaries

In Rust, the `unsafe` keyword does not disable type rules; it asserts that the engineer has manually guaranteed the invariant that the compiler cannot verify.

### 2.1 The Invariant Safety Documentation Standard
Every `unsafe` block must be immediately preceded by a `// SAFETY:` comment proving:
1. Pointer validity: The pointer is non-null, properly aligned, and points to initialized memory of sufficient size.
2. Lifetime integrity: The pointee lives for the duration of the reference and is not freed concurrently.
3. Aliasing discipline: No mutable reference coexists with any other reference (`&mut` exclusivity).

```rust
// LAFS Compliant Rust FFI Pattern
pub struct Native_Buffer_Handle
{
    Raw_Pointer: *mut u8,
    Capacity: usize,
    Length: usize,
}

impl Native_Buffer_Handle
{
    pub fn From_Raw_Parts
    (
        Pointer: *mut u8,
        Length: usize,
    ) -> Result<Self, String>
    {
        if Pointer.is_null()
        {
            return Err("Encountered null pointer in buffer initialization".to_string());
        }

        if Length == 0 || Length > (isize::MAX as usize)
        {
            return Err("Buffer length exceeds valid memory bounds".to_string());
        }

        Ok
        (
            Self
            {
                Raw_Pointer: Pointer,
                Capacity: Length,
                Length,
            }
        )
    }

    pub fn As_Slice(&self) -> &[u8]
    {
        // SAFETY: Pointer is verified non-null, aligned for u8, points to Length valid bytes,
        // and immutable borrow of self guarantees no concurrent mutable access.
        unsafe
        {
            std::slice::from_raw_parts(self.Raw_Pointer, self.Length)
        }
    }
}

impl Drop for Native_Buffer_Handle
{
    fn drop(&mut self)
    {
        if !self.Raw_Pointer.is_null()
        {
            // SAFETY: Memory was allocated via libc::malloc with Capacity bytes.
            unsafe
            {
                libc::free(self.Raw_Pointer as *mut libc::c_void);
            }
            self.Raw_Pointer = std::ptr::null_mut();
        }
    }
}
```

---

## 3. Concurrency, Race Condition & TOCTOU Defense

### 3.1 Data Races vs. Race Conditions
- **Data Race**: Two threads concurrently access the same memory location, at least one is a write, without synchronization. Mitigated by Rust's `Send`/`Sync` type system and runtime sanitizers (`TSan`).
- **Race Condition / TOCTOU (Time-of-Check to Time-of-Use)**: A logical flaw where external state changes between the check and the action.
  - *Filesystem TOCTOU*: Never check `path.exists()` and then open the file. Open the file directly using atomic flags (`O_CREAT | O_EXCL` in POSIX, `CREATE_NEW` in Windows) and inspect the file descriptor.
  - *Atomic State Updates*: Always perform check-and-update operations within a single lock critical section or atomic compare-and-swap (`compare_exchange`).

### 3.2 Deadlock Prevention Architecture
- Establish a global **Lock Hierarchy**: When acquiring multiple locks (e.g., `Lock_A` and `Lock_B`), all threads must acquire them in the exact same deterministic order.
- Prefer message passing via bounded, non-blocking channels over shared mutable memory.
- Always apply timeouts on lock acquisition in high-availability services.

---

## 4. Algorithmic Complexity Attacks (DoS Defense)

1. **ReDoS Defense**: Reject untrusted regular expressions with catastrophic backtracking. Use linear-time regex engines (`regex` crate in Rust, RE2 in C++/Go).
2. **HashDoS Defense**: Use cryptographically secure hash functions (SipHash-1-3 or AHash) for hash tables storing untrusted keys to prevent collision denial-of-service.
3. **Unbounded Recursion**: Enforce a maximum recursion depth or replace deep recursive traversals with iterative stack-bounded loops.
4. **Channel Capacity**: Never create unbounded channels in multi-threaded task queues; always set explicit capacity limits and backpressure strategies.

---

## 5. Security Verification Checklist

- [ ] All integer calculations governing buffer sizing and indices use checked or saturating arithmetic.
- [ ] Native code is compiled with stack canaries, full RELRO, PIE, and ASLR flags.
- [ ] Every `unsafe` block in Rust contains an explicit `// SAFETY:` rationale.
- [ ] Filesystem operations avoid TOCTOU races by operating on open file descriptors / atomic creation flags.
- [ ] Regex engines are linear-time (RE2, Rust regex) with compile-time complexity guarantees.
- [ ] Concurrency synchronization adheres to a strict deterministic lock ordering hierarchy.
- [ ] CI pipeline runs AddressSanitizer and UndefinedBehaviorSanitizer regression suites.
