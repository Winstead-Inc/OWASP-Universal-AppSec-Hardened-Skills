---
name: appsec-cryptography-and-secrets-hygiene
description: Implements modern cryptographic primitives, zero-trust secrets lifecycle management, memory zeroization, and OS keychain integration. Use whenever handling encryption, password hashing, API tokens, cryptographic key derivation, or memory-sensitive state.
---

# Universal Cryptography & Secrets Hygiene Runbook

## Overview

Flawed cryptographic implementations and improper secrets handling represent catastrophic security risks across all software tiers. Cryptographic systems must never rely on bespoke algorithms, obsolete ciphers, unauthenticated encryption modes, or deterministic nonces. Secrets must never reside in plaintext repositories, environment variable dumps, or unzeroized runtime memory. This runbook codifies the non-negotiable cryptographic standards and operational procedures for battle-hardened applications across Rust, TypeScript/JavaScript, Python, Go, and C/C++.

---

## 1. Algorithm Selection Matrix & Banned Primitives

### 1.1 Mandatory Modern Primitives

| Purpose | Approved Algorithms | Banned / Deprecated Primitives |
| :--- | :--- | :--- |
| **Symmetric Encryption (AEAD)** | AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM | AES-ECB, AES-CBC (without HMAC), 3DES, DES, RC4, Blowfish |
| **Password Hashing** | Argon2id (m=65536 KiB, t=3, p=4), scrypt | MD5, SHA-1, SHA-256/512 (raw), NTLM, PBKDF2 (< 600,000 iterations) |
| **Key Derivation (KDF)** | HKDF-SHA256, Argon2id, scrypt | Raw string hashing, truncated hashes |
| **Digital Signatures** | Ed25519 (EdDSA), ECDSA (P-256 / P-384 with RFC 6979), RSA-PSS (>= 3072-bit) | RSA PKCS#1 v1.5, DSA, ECDSA with non-deterministic random nonces |
| **Public Key Encryption** | X25519 (ECDH), RSA-OAEP with SHA-256 (>= 3072-bit) | RSA PKCS#1 v1.5 encryption, ElGamal |
| **Cryptographic Hashing** | SHA-256, SHA-384, SHA-512, SHA-3, BLAKE3 | MD4, MD5, SHA-1, RIPEMD |
| **Random Number Generation** | OS-backed CSPRNG (`/dev/urandom`, `BCryptGenRandom`, `getrandom`) | `rand()`, `Math.random()`, `random.random()`, `mt19937` |

### 1.2 Invariant Cryptographic Axioms

1. **Rule 1 (AEAD Only)**: Every symmetric encryption operation must provide Authenticated Encryption with Associated Data (AEAD). Unauthenticated modes (such as CBC without Encrypt-then-MAC) allow padding oracle attacks and bit-flipping malleability.
2. **Rule 2 (Unique Nonces/IVs)**: Nonces in AES-GCM and ChaCha20-Poly1305 must never be reused under the same key. A single nonce collision in AES-GCM destroys the authenticity key and allows message forgery. Use a 96-bit CSPRNG-generated nonce per encryption, or XChaCha20-Poly1305 (192-bit nonce) when nonces are randomly generated without a sequential counter.
3. **Rule 3 (Constant-Time Verification)**: All comparisons of cryptographic tokens, HMAC tags, signatures, and passwords must execute in constant time to defeat timing side-channel attacks (`subtle.ConstantTimeCompare` in Go, `constant_time_eq` in Rust, `crypto.timingSafeEqual` in Node.js, `hmac.compare_digest` in Python).
4. **Rule 4 (Never Invent Crypto)**: Never implement cryptographic primitives from scratch. Utilize peer-reviewed, audited standard libraries (`ring`, `sodiumoxide`/`libsodium`, `cryptography` in Python, `@noble/hashes` or Web Crypto API in Node.js/Browser, `crypto/subtle` in Go).

---

## 2. Secrets Lifecycle & Zeroization Architecture

### 2.1 The In-Memory Secrets Defense
Compromised process memory, core dumps, and swap files frequently expose plaintext keys long after they are used. All in-memory sensitive tokens (passwords, private keys, symmetric keys, API tokens) must be cleared immediately upon exit or drop.

```text
    ┌────────────────────────────────────────────────────────┐
    │              SECRETS LIFECYCLE DEFENSE                 │
    └───────────────────────────┬────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  [ AT-REST ]             [ IN-TRANSIT ]          [ IN-MEMORY ]
  OS Keystore / DPAPI     TLS 1.3 Strict          Zeroize on Drop
  No Plaintext Files      mTLS Service Mesh       Lock Pages in RAM
  No Git .env Commits     No Query Param Tokens   Zero Core Dumps
```

### 2.2 Memory Zeroization Standards
- Compilers routinely optimize away standard `memset()` calls when variables go out of scope. Use compiler-resistant volatile clearing routines (`SecureZeroMemory` on Windows, `explicit_bzero` on Linux, `zeroize::ZeroizeOnDrop` in Rust).
- Prevent secrets from swapping to disk: in native C/Rust, use `mlock` / `VirtualLock` to pin sensitive memory buffers in physical RAM.

---

## 3. Implementation Blueprints across Environments

### 3.1 Rust: Authenticated Encryption with Memory Zeroization (LAFS Compliant)

```rust
use aes_gcm::
{
    aead::
    {
        Aead,
        KeyInit,
        OsRng,
    },
    Aes256Gcm,
    Nonce,
};
use zeroize::
{
    Zeroize,
    ZeroizeOnDrop,
};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret_Buffer
{
    Payload: Vec<u8>,
}

impl Secret_Buffer
{
    pub fn New(Data: Vec<u8>) -> Self
    {
        Self
        {
            Payload: Data,
        }
    }

    pub fn As_Slice(&self) -> &[u8]
    {
        &self.Payload
    }
}

pub struct Secure_Cipher_Service;

impl Secure_Cipher_Service
{
    pub fn Encrypt_Payload
    (
        Key: &Secret_Buffer,
        Plaintext: &[u8],
    ) -> Result<Vec<u8>, String>
    {
        use aes_gcm::aead::rand_core::RngCore;

        let Cipher = Aes256Gcm::new_from_slice(Key.As_Slice())
            .map_err(|Error| format!("Invalid key length: {Error}"))?;

        let mut Nonce_Bytes = [0u8; 12];
        OsRng.fill_bytes(&mut Nonce_Bytes);
        let Nonce_Tag = Nonce::from_slice(&Nonce_Bytes);

        let Ciphertext = Cipher.encrypt(Nonce_Tag, Plaintext)
            .map_err(|Error| format!("Encryption failure: {Error}"))?;

        let mut Combined = Vec::with_capacity(12 + Ciphertext.len());
        Combined.extend_from_slice(&Nonce_Bytes);
        Combined.extend_from_slice(&Ciphertext);

        Ok(Combined)
    }

    pub fn Decrypt_Payload
    (
        Key: &Secret_Buffer,
        Encrypted_Blob: &[u8],
    ) -> Result<Vec<u8>, String>
    {
        if Encrypted_Blob.len() < 28
        {
            return Err("Encrypted blob is too short to contain nonce and tag".to_string());
        }

        let Cipher = Aes256Gcm::new_from_slice(Key.As_Slice())
            .map_err(|Error| format!("Invalid key length: {Error}"))?;

        let (Nonce_Part, Ciphertext_Part) = Encrypted_Blob.split_at(12);
        let Nonce_Tag = Nonce::from_slice(Nonce_Part);

        let Plaintext = Cipher.decrypt(Nonce_Tag, Ciphertext_Part)
            .map_err(|Error| format!("Decryption authentication failure: {Error}"))?;

        Ok(Plaintext)
    }
}
```

### 3.2 TypeScript / Node.js: Safe Constant-Time Token Verification

```typescript
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";

export class Authentication_Token_Verifier
{
    public static Generate_Secure_Token(Byte_Length: number = 32): string
    {
        return randomBytes(Byte_Length).toString("hex");
    }

    public static Compute_HMAC_Signature(Secret_Key: string, Payload: string): Buffer
    {
        return createHmac("sha256", Secret_Key)
            .update(Payload)
            .digest();
    }

    public static Verify_HMAC_Signature
    (
        Secret_Key: string,
        Payload: string,
        Expected_Hex_Signature: string,
    ): boolean
    {
        const Computed_Buffer = this.Compute_HMAC_Signature(Secret_Key, Payload);
        const Expected_Buffer = Buffer.from(Expected_Hex_Signature, "hex");

        if (Computed_Buffer.length !== Expected_Buffer.length)
        {
            return false;
        }

        return timingSafeEqual(Computed_Buffer, Expected_Buffer);
    }
}
```

### 3.3 Python: Production Argon2id Password Hashing

```python
import argon2
from typing import Tuple

Password_Hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID,
)

def Hash_User_Password(Plaintext_Password: str) -> str:
    return Password_Hasher.hash(Plaintext_Password)

def Verify_User_Password(Plaintext_Password: str, Stored_Hash: str) -> Tuple[bool, bool]:
    """
    Returns (Is_Valid, Needs_Rehash) tuple to support transparent credential upgrade.
    """
    try:
        Password_Hasher.verify(Stored_Hash, Plaintext_Password)
        Needs_Rehash = Password_Hasher.check_needs_rehash(Stored_Hash)
        return True, Needs_Rehash
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
        return False, False
```

---

## 4. Hardware and Operating System Keystore Integration

Never store master keys, encryption keys, or service tokens in flat files, `.env` configs, or git repositories.

### 4.1 Native OS Keystore Standards
1. **Windows**: Use DPAPI (`CryptProtectData` / `CryptUnprotectData`) with user- or machine-level credential isolation, or the Windows Credential Manager API (`CredWriteW` / `CredReadW`).
2. **macOS**: Use the macOS Keychain Services API (`SecItemAdd`, `SecItemCopyMatching`) with secure access groups and biometric (TouchID) entitlements.
3. **Linux**: Use the freedesktop.org Secret Service API over D-Bus with Libsecret, or kernel keyrings (`keyctl`) for ephemeral session keys.
4. **Cloud / Infrastructure**: Use managed Key Management Services (AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault) using Envelope Encryption: data is encrypted with a local ephemeral Data Encryption Key (DEK), and the DEK is encrypted under the KMS Key Encryption Key (KEK).

---

## 5. Security Verification Checklist

- [ ] All symmetric encryption uses AEAD modes (AES-256-GCM, ChaCha20-Poly1305) with unique nonces.
- [ ] No static, hardcoded, or sequentially repeating IVs or nonces are ever used.
- [ ] Passwords are exclusively hashed using Argon2id with memory-hard parameters.
- [ ] Random bytes, UUIDs, and tokens are generated exclusively via OS CSPRNG.
- [ ] All message and token comparisons use constant-time algorithms.
- [ ] In-memory secrets are zeroized on drop or process termination.
- [ ] Long-term secrets are stored exclusively in OS credential vaults or hardware-backed KMS.
- [ ] Automated git hooks (e.g. Gitleaks, TruffleHog) block any plaintext secret commit.
