---
name: appsec-auth-session-and-access-control
description: >-
  Implement zero-trust authentication, robust session management, rate limiting, and object-level access control (BOLA/IDOR/RBAC) across general software development. Use when building login systems, API endpoints, user sessions, role-based permissions, or multi-tenant architectures.
---

# Zero-Trust Authentication, Session Security & Access Control

This skill provides an uncompromising runbook for designing, implementing, and auditing authentication, authorization, session lifecycles, and access control across web, API, microservice, and distributed architectures.

---

## 1. Authentication & Credential Architecture

### 1.1 Password Storage & Verification
- Use exclusively modern, memory-hard key derivation algorithms. Standardize on **Argon2id** with calibrated parameters:
  - Algorithm: `Argon2id`
  - Memory: $\ge 64 \text{ MB}$ (65536 KiB)
  - Iterations: $\ge 3$ passes
  - Parallelism: 2–4 lanes
- Never use plain SHA-256, SHA-512, MD5, SHA-1, or basic PBKDF2 with low iterations for password storage.

### 1.2 Constant-Time Comparisons (Timing Attack Defense)
Whenever verifying passwords, tokens, API keys, or signatures, always use constant-time byte comparisons to prevent timing side-channel attacks:
```rust
// Rust: Constant-time comparison via subtle
use subtle::ConstantTimeEq;
pub fn VerifyToken(Provided: &[u8], Stored: &[u8]) -> bool
{
    Provided.ct_eq(Stored).into()
}
```
In Node.js:
```javascript
const Crypto = require("node:crypto");

function VerifyToken(Provided, Stored)
{
    if (Provided.length !== Stored.length)
    {
        return false;
    }

    return Crypto.timingSafeEqual(Buffer.from(Provided), Buffer.from(Stored));
}
```

### 1.3 Brute Force & Credential Stuffing Defense
- Implement multi-tiered rate limiting:
  - Per IP address (e.g. max 10 failed login attempts per minute).
  - Per account username/email (e.g. progressive delays or temporary lockout after 5 consecutive failures).
- Enforce Multi-Factor Authentication (MFA) via TOTP (RFC 6238) or FIDO2/WebAuthn hardware keys.

---

## 2. Session Management & Token Lifecycles

### 2.1 Cryptographic Session Tokens
- Generate session IDs using a cryptographically secure pseudorandom number generator (CSPRNG) with at least **256 bits of entropy** (32 random bytes).
- Session cookies must enforce defensive flags:
  - `HttpOnly`: Prevents client-side scripts from reading the cookie via DOM XSS.
  - `Secure`: Enforces transmission strictly over HTTPS.
  - `SameSite=Strict` (or `Lax`): Defends against Cross-Site Request Forgery (CSRF).
  - `Path=/; Partitioned`: Defends against cross-site tracking and cookie leakage.

### 2.2 JWT & Stateless Token Security
- **Asymmetric Signing**: Sign tokens using asymmetric keys (Ed25519 or ECDSA P-256) rather than symmetric HMAC secrets. This prevents microservices verifying tokens from being able to forge them.
- **Strict Algorithm Whitelisting**: Explicitly reject tokens specifying `"alg": "none"` or unapproved algorithms.
- **Short Lifespan with Sliding Refresh**: Access tokens must have short lifespans (5–15 minutes). Refresh tokens must be single-use with automatic token family invalidation upon replay detection.

---

## 3. Access Control & Authorization (BOLA / IDOR Defense)

### 3.1 Broken Object-Level Authorization (BOLA / IDOR) Defense
- Never trust client-provided object IDs without verifying ownership against the authenticated context:
  ```rust
  // WRONG - Insecure Direct Object Reference
  let Doc = GetDocumentById(RequestedDocId).await?;

  // CORRECT - Ownership Verified Query
  let Doc = db::GetDocumentForUser(RequestedDocId, CurrentSession.UserId).await?;
  if Doc.is_none()
  {
      return Err(SecurityError::NotFoundOrForbidden);
  }
  ```
- Return uniform `404 Not Found` (rather than `403 Forbidden`) when accessing objects belonging to other users to prevent resource enumeration.

### 3.2 Role-Based & Attribute-Based Access Control (RBAC / ABAC)
- Enforce authorization checks at the service/business logic layer, not merely in UI view routing.
- Implement explicit permission gates (e.g. `CanEditDocument(User, Document) -> bool`) evaluated on every state-modifying mutation.

---

## 4. Auth & Access Control Checklist

- [ ] Are passwords hashed using Argon2id with $\ge 64 \text{ MB}$ memory cost?
- [ ] Are tokens and secrets verified using constant-time comparison functions?
- [ ] Do session cookies enforce `HttpOnly`, `Secure`, and `SameSite=Strict`?
- [ ] Are JWTs signed with asymmetric keys with short expiration times ($\le 15\text{ min}$)?
- [ ] Does every object query enforce user/tenant ownership checking (zero IDOR)?
- [ ] Are failed login attempts bounded by progressive rate limiting?
