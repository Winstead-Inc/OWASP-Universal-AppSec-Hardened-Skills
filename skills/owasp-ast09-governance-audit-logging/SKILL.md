---
name: owasp-ast09-governance-audit-logging
description: >-
  Establish security governance, risk tier classification (L0-L3), tamper-evident audit logging, and Non-Human Identity (NHI) lifecycle management (OWASP AST09). Use when defining enterprise policies, setting up audit logging pipelines, or managing agent access credentials.
---

# OWASP AST09: Governance, Risk Tiering & Audit Logging

AST09 addresses the critical gap where autonomous agent skills, tools, and applications operate without centralized inventory, clear risk classification, cryptographic audit logging, or non-human identity (NHI) credential governance.

---

## 1. Threat Mechanics & Attack Vectors

1. **Shadow Agent & Tool Proliferation**: Developers installing third-party skills and plugins locally with no enterprise inventory or security visibility.
2. **Missing Forensic Audit Trails**: When an incident occurs, system logs fail to capture which skill executed which tool, what arguments were passed, or what files were accessed.
3. **Mislabeled Risk Tiers**: High-risk skills with network and disk write access classified as "low risk" to bypass review pipelines.
4. **Orphaned Non-Human Credentials**: Agent API tokens remaining active long after an employee or project has been deprovisioned.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 Four-Tier Risk Classification Framework (L0–L3)
Classify every tool, skill, and application module by its inherent capability risk:

| Risk Tier | Capabilities & Scope | Review & Deployment Policy |
|---|---|---|
| **L0 (Minimal)** | Pure read-only in-memory computation; no disk, network, or shell | Automated scan approval |
| **L1 (Low)** | Scoped reads within project directory; approved external API reads | Automated scan + single reviewer sign-off |
| **L2 (Elevated)** | Local project file writes; network egress; scoped CLI execution | Full checklist + manual security review + canary testing |
| **L3 (Critical)** | System configuration changes; credential access; arbitrary code execution | Architectural review board + dynamic behavioral analysis |

### 2.2 Tamper-Evident Action Logging (Execution Receipts)
Log every security-sensitive action (file write, network request, subprocess spawn) with an immutable execution receipt:

```json
{
  "timestamp": "2026-11-20T14:00:00Z",
  "event_id": "evt_98f7e6d5c4b3",
  "skill_name": "typst-compiler-guard",
  "user_context": "dev-user-01",
  "action": "execute_subprocess",
  "command": "typst",
  "arguments": ["compile", "--root", "E:\\Typst\\projects", "document.typ"],
  "working_directory": "E:\\Typst\\projects",
  "duration_ms": 142,
  "exit_code": 0,
  "sha256_output_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### 2.3 Non-Human Identity (NHI) Lifecycle Management
- Register all AI agents and automated tools as formal Non-Human Identities within your IAM system.
- Issue short-lived, rotation-enforced tokens (max lifespan 1–24 hours).
- Immediately revoke agent credentials upon task completion or suspicious activity alert.

---

## 3. AST09 Review Checklist

- [ ] Is every installed skill and tool recorded in a centralized, searchable inventory?
- [ ] Has each component been assigned an explicit Risk Tier (L0–L3) matching its actual permissions?
- [ ] Are all security-sensitive actions logged with structured, privacy-safe execution receipts?
- [ ] Is agent credential access managed through short-lived Non-Human Identities with automated rotation?
- [ ] Is there a formal revocation procedure to immediately disable compromised skills across the organization?
