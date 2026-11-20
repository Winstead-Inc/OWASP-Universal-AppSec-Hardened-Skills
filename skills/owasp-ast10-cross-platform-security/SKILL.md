---
name: owasp-ast10-cross-platform-security
description: >-
  Ensure security property preservation, cross-runtime parity, and Universal Skill Format (USF v1.0) compliance across agent ecosystems (OWASP AST10). Use when porting skills or applications across Claude Code, Cursor, OpenClaw, VS Code, and Antigravity.
---

# OWASP AST10: Cross-Platform Security Parity & Universal Format

AST10 addresses security degradation that occurs when skills, tools, or extensions are ported across different agent runtimes (OpenClaw, Claude Code, Cursor, VS Code, Antigravity). Security properties declared in one format (such as sandboxing or path restrictions) are frequently dropped or misinterpreted when translated to another, creating unexpected vulnerabilities.

---

## 1. Threat Mechanics & Attack Vectors

1. **Silent Permission Loss**: A skill with restricted permissions in one platform becomes unconstrained (`shell: true`, full filesystem access) when ported to a platform with looser defaults.
2. **Multi-Registry Poisoning**: Attackers publish the same malicious skill simultaneously across multiple package ecosystems (e.g. ClawHub and skills.sh).
3. **Execution Model Mismatches**: A skill designed for a containerized runtime running in host-mode on another platform without developer awareness.
4. **Credential Handling Inconsistencies**: Storing tokens in native OS keychains on one platform but falling back to unencrypted plaintext `.json` on another.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 The Universal Skill Format (USF v1.0)
Adopt the canonical, platform-agnostic manifest specification to guarantee that security metadata is preserved across all targets:

```yaml
---
# Universal Agentic Skill Format v1.0
name: secure-code-auditor
version: 1.0.0
platforms: [openclaw, claude, cursor, vscode, antigravity]

description: "Automated application security review and vulnerability detection"
author:
  name: "Security Engineering Team"
  identity: "did:web:security.example.com"
  signing_key: "ed25519:abcdef0123456789..."

permissions:
  files:
    read:
      - ./src/**
      - ./package.json
    write:
      - ./security-reports/**
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
      - "**/.env*"
  network:
    allow:
      - osv.dev
    deny: "*"
  shell: false
  tools:
    - read_file
    - write_file

risk_tier: L1
scan_status:
  scanner: "skill-spector@1.2.0"
  last_scanned: "2026-11-20"
  result: "pass"

signature: "ed25519:4a7b9c1d..."
content_hash: "sha256:d8e9f0a1..."
---
```

### 2.2 Cross-Platform Security Gap Assessment
When deploying across platforms, evaluate differences in runtime isolation:

| Platform | Sandbox Model | Permission Enforcement | Default Posture |
|---|---|---|---|
| **Antigravity / Gemini** | Capability-based plugin model; tool allowlists | Manifest & Schema-enforced | Sandboxed |
| **Claude Code** | Tool approval prompts; workspace scoping | Interactive user prompt | Interactive Gate |
| **OpenClaw** | Container / Host runtime options | Manifest-declared | Must configure sandbox |
| **Cursor / VS Code** | Extension host process; workspace trust | Workspace trust API | User trust prompt |

### 2.3 Independent Validation per Target
Never assume that passing security checks on one platform guarantees safety on another:
- Run automated security tests in each target platform's runtime environment.
- Confirm that credential storage uses the target platform's secure enclave / secret store, never plaintext configuration.

---

## 3. AST10 Review Checklist

- [ ] Does the skill or component declare a Universal Skill Format (USF v1.0) or normalized manifest?
- [ ] Are all security properties (`permissions`, `risk_tier`, `deny_write`, `content_hash`) maintained across all platform targets?
- [ ] Has an independent security audit been conducted in each target runtime?
- [ ] Is credential storage verified as secure (encrypted at rest) on every supported operating system and platform?
