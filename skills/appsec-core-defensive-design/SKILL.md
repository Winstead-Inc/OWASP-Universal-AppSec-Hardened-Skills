---
name: appsec-core-defensive-design
description: >-
  Universal architectural standard for building battle-hardened, impossibly high-security applications across general software development (OWASP ASVS Level 3). Use when designing software architecture, implementing core business logic, validating system boundaries, and establishing defense-in-depth principles in Rust, Python, Go, TypeScript/JavaScript, C++, Java, and C#.
---

# Universal Application Security & Core Defensive Design Standard

This skill establishes the universal engineering baseline for building software to the highest possible security standard (aligning with **OWASP ASVS Level 3** - Defense in Depth). It applies to all application archetypes: cloud APIs, microservices, native systems, CLI tools, desktop shells, and distributed networks.

---

## 1. Invariant Architecture Principles

### 1.1 Complete Mediation (Zero Trust at Every Layer)
- Never rely on upstream callers or client-side checks for security guarantees. Every function, service boundary, and internal component must validate its own inputs, enforce its own permissions, and assert its own invariants.
- If Component A calls Component B in the same process, Component B must still enforce parameter bounds, type constraints, and structural sanity.

### 1.2 Fail-Closed & Safe Defaults
- All security decisions must default to **DENY**. Access is granted only when an explicit, affirmative authorization check succeeds.
- If an unexpected error, exception, or timeout occurs during authorization or data processing, the transaction must immediately abort, release all locked resources, and return a generic error.
- Never write fallback logic that degrades to an unauthenticated or permissive state.

### 1.3 Economy of Mechanism & Least Surprise
- Security controls must be simple, standardized, and auditable. Complex, home-grown cryptographic schemes, custom parsers, or esoteric authorization logic invite critical vulnerabilities.
- Standardize on well-vetted libraries (e.g. `argon2`, `ring`, `sodium`, `serde`, `zod`, `pydantic`) rather than implementing ad-hoc primitives.

---

## 2. Universal Defensive Coding Patterns

### 2.1 Input Validation & Strict Allowlisting
- **Syntactic Validation**: Enforce strict data type, maximum length, allowable character ranges (using strict regex), and exact numeric boundaries on all incoming data.
- **Semantic Validation**: Validate business logic constraints (e.g. start date must precede end date; transaction amount must be strictly greater than zero and less than account balance).
- **Canonicalization Before Validation**: Always decode and canonicalize inputs (strip URL encoding, resolve Unicode normalization NFKC, resolve relative path traversal tokens) *before* applying allowlist or validation checks.

### 2.2 Error Handling & Information Leakage Prevention
- **Generic External Responses**: Never return database errors, stack traces, internal IP addresses, file paths, or framework version headers to external callers or UI elements.
- **Structured Internal Logging**: Log the full technical diagnostic details internally with structured, privacy-safe telemetry (excluding passwords, API keys, and PII).
- **Graceful Resource Release**: Wrap critical transactions in RAII guards, `try...finally`, or deferred cleanup blocks to prevent resource leaks (dangling file descriptors, leaked database connections, orphaned mutexes).

### 2.3 Safe Component Boundaries & Type-Driven Security
- **Make Illegal States Unrepresentable**: Leverage strong type systems (Rust, TypeScript, modern Go/Python) to encode security invariants into types. For example, represent an authenticated user session as a distinct type `AuthenticatedSession` that can only be instantiated by the authenticator module, preventing unauthenticated calls to privileged methods.
- **Smart Constructors & Value Objects**: Instead of passing raw strings for email addresses, user IDs, or URLs, wrap them in validated Value Objects that enforce invariants at instantiation.

---

## 3. General Development Security Checklist

- [ ] Does every public and internal interface enforce positive allowlisting on all parameters?
- [ ] Are all authorization decisions fail-closed by default?
- [ ] Are all inputs fully canonicalized before validation checks occur?
- [ ] Are error messages returned to clients generic, with detailed stack traces isolated strictly to internal logs?
- [ ] Are illegal application states made unrepresentable via strong typing and validated value objects?
