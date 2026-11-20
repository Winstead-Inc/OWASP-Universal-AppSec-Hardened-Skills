# OWASP-Universal-AppSec-Hardened-Skills

A comprehensive security engineering suite of 20 defensive development skills, architectural guidelines, and security rules for general software development and autonomous agent ecosystems.

---

> [!CAUTION]
> ### Mandatory Code Formatting & K&R Disclaimer
> 
> All code snippets, configuration files, schemas, and contributions in this repository are strictly governed by the **Language-Agnostic Formatting Style (LAFS)**.
> 
> Kernighan & Ritchie (K&R) formatting (trailing opening delimiters, offset anchors, Egyptian brackets, and clumped closures) is strictly prohibited.
> 
> **DISCLAIMER:** Any code containing K&R slop—if found anywhere in this repository or submitted via contributions—will be reformatted into clean LAFS geometry without the user's consent. The official formatting tool `LAFS.exe` is provided in the repository to format source files.

---

## Security Skills Catalog

The repository organizes defensive capabilities into two complementary frameworks: the Universal Application Security Spectrum (general software engineering) and the OWASP Agentic Skills Top 10 (AI agent and tool execution safety).

### Universal Application Security Spectrum

* [appsec-core-defensive-design](skills/appsec-core-defensive-design/SKILL.md) — Universal architectural baseline, Zero Trust boundaries, fail-closed defaults, and complete mediation.
* [appsec-injection-and-input-validation](skills/appsec-injection-and-input-validation/SKILL.md) — Elimination of SQL, NoSQL, OS command, template, and regular expression injection flaws.
* [appsec-auth-session-and-access-control](skills/appsec-auth-session-and-access-control/SKILL.md) — Zero-trust authentication, robust session management, rate limiting, and object-level authorization (IDOR defense).
* [appsec-cryptography-and-secrets-hygiene](skills/appsec-cryptography-and-secrets-hygiene/SKILL.md) — Authenticated symmetric encryption (AEAD), memory zeroization, Argon2id password hashing, and OS keystore integration.
* [appsec-systems-memory-safety-and-concurrency](skills/appsec-systems-memory-safety-and-concurrency/SKILL.md) — Integer overflow defenses, binary compiler hardening, safe concurrency invariants, and ReDoS protection.
* [appsec-network-transport-and-ssrf-defense](skills/appsec-network-transport-and-ssrf-defense/SKILL.md) — Transport layer hardening (TLS 1.3/1.2), HTTP security headers, and multi-stage SSRF protection with socket pinning.
* [appsec-client-shell-and-ui-containment](skills/appsec-client-shell-and-ui-containment/SKILL.md) — Desktop shell hardening (Tauri, Electron), strict nonced Content Security Policy, and DOMPurify SVG/HTML sanitization.
* [appsec-supply-chain-ci-cd-and-slsa](skills/appsec-supply-chain-ci-cd-and-slsa/SKILL.md) — SLSA Level 3 compliance, immutable dependency hash pinning, lockfile enforcement, and automated CycloneDX SBOM generation.
* [appsec-observability-audit-logging-and-incident-response](skills/appsec-observability-audit-logging-and-incident-response/SKILL.md) — Structured JSON audit logging, forward hash chaining for tamper evidence, CRLF log sanitization, and emergency kill switches.

### OWASP Agentic Skills Top 10 (AST10)

* [owasp-ast-appsec-hardened](skills/owasp-ast-appsec-hardened/SKILL.md) — Master runbook for securing AI agent workflows across the B1-B4 trust boundary pipeline.
* [owasp-ast01-malicious-code-defense](skills/owasp-ast01-malicious-code-defense/SKILL.md) — Detection and prevention of unauthorized persistence mechanisms, malicious instructions, and identity tampering.
* [owasp-ast02-supply-chain-integrity](skills/owasp-ast02-supply-chain-integrity/SKILL.md) — Supply chain validation, pre-mutation installation receipts, and dependency hash pinning.
* [owasp-ast03-least-privilege-enforcement](skills/owasp-ast03-least-privilege-enforcement/SKILL.md) — Principle of least privilege, strict canonical path allowlisting, and credential store isolation.
* [owasp-ast04-secure-metadata-deserialization](skills/owasp-ast04-secure-metadata-deserialization/SKILL.md) — Hardened parsing of structured metadata, safe YAML loading, and prompt steganography defenses.
* [owasp-ast05-untrusted-instruction-defense](skills/owasp-ast05-untrusted-instruction-defense/SKILL.md) — Defense against indirect prompt injection and unverified remote instruction fetching via cryptographic pinning.
* [owasp-ast06-sandboxing-runtime-isolation](skills/owasp-ast06-sandboxing-runtime-isolation/SKILL.md) — Sandboxed runtime environments, loopback interface protection, and DNS rebinding mitigation.
* [owasp-ast07-update-drift-management](skills/owasp-ast07-update-drift-management/SKILL.md) — Prevention of silent code modifications, unpinned runtime updates, and unverified auto-updating.
* [owasp-ast08-multi-layer-security-scanning](skills/owasp-ast08-multi-layer-security-scanning/SKILL.md) — Multi-tier static security analysis, automated secret detection, and AST pattern scanning.
* [owasp-ast09-governance-audit-logging](skills/owasp-ast09-governance-audit-logging/SKILL.md) — Security governance, risk tier classification (L0-L3), and Non-Human Identity management.
* [owasp-ast10-cross-platform-security](skills/owasp-ast10-cross-platform-security/SKILL.md) — Preservation of security invariants across heterogeneous operating systems and execution platforms.

---

## Bundled Formatter: `LAFS.exe`

The repository includes the official native binary `LAFS.exe` (located at root and inside `tools/`) for enforcing the Language-Agnostic Formatting Style.

### Basic Commands

```powershell
# Check compliance across all files
.\LAFS.exe --check -a

# Format all files in-place
.\LAFS.exe -a -w

# Format a specific folder
.\LAFS.exe -d skills -w
```

---

## Universal Security Rules

See [rules/AGENTS.md](rules/AGENTS.md) for 31 global security rules designed for integration into AI agents and developer toolchains.
