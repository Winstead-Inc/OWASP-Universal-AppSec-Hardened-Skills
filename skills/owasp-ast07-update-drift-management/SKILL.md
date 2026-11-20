---
name: owasp-ast07-update-drift-management
description: >-
  Mitigate update drift, silent code modifications, unverified automatic updates, and production hot-reloading risks (OWASP AST07). Use when configuring package update policies, designing auto-update mechanisms, or auditing runtime immutability.
---

# OWASP AST07: Update Drift & Immutability Management

AST07 addresses risks where a skill or application component that was initially vetted and approved changes over time via silent updates, mutable tags, or hot-reload mechanisms, introducing backdoors or vulnerabilities into an otherwise secure environment.

---

## 1. Threat Mechanics & Attack Vectors

1. **Silent Upstream Hijack**: A trusted developer account on GitHub or npm is compromised, and an attacker publishes a malicious patch version (`v1.0.1`) that gets auto-installed.
2. **Hot-Reload Exploitation**: Development hot-reloading features (such as `SkillsWatcher`) left enabled in production environments, allowing on-disk edits or staged file changes to execute immediately without re-approval.
3. **Patch-Lag Window Exploitation**: Vulnerable skills remaining unpatched in production due to lack of security advisory subscriptions.
4. **Unsigned Auto-Updates**: Applications downloading updates over insecure channels or without cryptographic signature verification.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 Immutable Content Hashing
Record the exact SHA-256 hash of all approved skills, packages, and scripts in an immutable inventory. Reject execution if the on-disk hash differs:

```python
import hashlib
import os

def assert_skill_integrity(skill_dir: str, expected_manifest_hash: str):
    manifest_path = os.path.join(skill_dir, "SKILL.md")
    with open(manifest_path, "rb") as f:
        actual_hash = f"sha256:{hashlib.sha256(f.read()).hexdigest()}"
    
    if actual_hash != expected_manifest_hash:
        raise SecurityError(
            f"Integrity Alert: Skill at '{skill_dir}' has drifted! "
            f"Expected {expected_manifest_hash}, found {actual_hash}. Execution blocked."
        )
```

### 2.2 Disable Hot-Reload in Production
- Ensure file watchers (`SkillsWatcher`, live file reloaders) are strictly gated to development builds.
- In production, any change to a skill file requires an explicit restart and formal security re-scan.

### 2.3 Cryptographic Update Signatures
- Enforce public key signature verification on every update archive before extraction.
- Refuse updates that are unsigned or signed with an unrecognized key.

### 2.4 Automated Security Advisory Monitoring
- Maintain an active inventory of installed packages and skills.
- Query OSV.dev or GitHub Advisory Database regularly to detect disclosed CVEs in installed dependencies.

---

## 3. AST07 Review Checklist

- [ ] Are all skills and critical dependencies pinned to immutable `sha256:` content hashes?
- [ ] Is automatic updating disabled or gated behind explicit human re-approval?
- [ ] Are all updates cryptographically signed by the original verified publisher?
- [ ] Is dynamic hot-reloading disabled in production environments?
- [ ] Is an automated vulnerability monitoring pipeline active for all installed components?
