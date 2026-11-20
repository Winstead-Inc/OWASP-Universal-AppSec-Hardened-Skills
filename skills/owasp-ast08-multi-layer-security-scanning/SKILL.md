---
name: owasp-ast08-multi-layer-security-scanning
description: >-
  Deploy multi-layer security scanning across code, metadata, and natural language instructions using Semgrep, Gitleaks, and AST-aware analyzers (OWASP AST08). Use when configuring CI/CD security pipelines, conducting pre-deployment code audits, or scanning for secrets.
---

# OWASP AST08: Multi-Layer Security Scanning Pipeline

AST08 addresses the critical failure of relying on a single scanning tool or shallow regex pattern matching to detect security flaws in modern agentic applications. Up to 13.4% of critical vulnerabilities in agent skills are completely missed by simple pattern matching, requiring a defense-in-depth scanning strategy covering both the code layer and natural language instruction layer.

---

## 1. Threat Mechanics & Attack Vectors

1. **False Sense of Security**: Relying solely on basic keyword search (e.g. checking for `rm -rf`) while attackers use base64 encoding, obfuscated imports, or polyglot files.
2. **Instruction-Layer Blindness**: Traditional SAST tools (SonarQube, Bandit) scan only Python or JavaScript, completely ignoring malicious prompts inside `SKILL.md` or system instructions.
3. **Compromised Scanners**: Relying on untrusted third-party scanners that may be malicious themselves.
4. **Hardcoded Secrets**: Leaking API tokens, private keys, or credentials into repository files or tool configurations.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 Multi-Tool Scanning Architecture
Deploy a multi-layer scanning pipeline where each tool targets a distinct threat angle:

| Layer | Focus Area | Recommended Tooling |
|---|---|---|
| **Static Code Analysis (SAST)** | AST pattern matching, dangerous functions | **Semgrep**, **Bandit**, **Clippy** |
| **Secret Detection** | API keys, SSH keys, private tokens | **Gitleaks**, **TruffleHog** |
| **Agentic Skill Analyzer** | Manifest schemas, prompt injection, permissions | **NVIDIA SkillSpector**, **Caterpillar** |
| **Dependency & Supply Chain** | Known CVEs in transitive dependencies | **Snyk**, **OSV-Scanner** |

### 2.2 Dual-Layer Auditing (Code + Instructions)
Every security evaluation must scan both:
1. **The Code Layer**: Scripts (`.py`, `.js`, `.rs`, `.sh`) evaluated for command injection, path traversal, and unsafe deserialization.
2. **The Instruction Layer**: Natural language instructions (`SKILL.md`, `AGENTS.md`) evaluated for hidden instructions, brand impersonation, and prompt overrides.

### 2.3 Semgrep Rules for Agentic & Application Security
Incorporate custom Semgrep rules into your CI pipeline:

```yaml
rules:
  - id: dangerous-shell-execution
    patterns:
      - pattern-either:
          - pattern: child_process.exec($CMD, ...)
          - pattern: subprocess.Popen($CMD, shell=True, ...)
          - pattern: os.system($CMD)
    message: "High Risk: Dynamic shell execution detected. Use argument arrays and shell=False."
    languages: [javascript, typescript, python]
    severity: ERROR

  - id: path-containment-prefix-bug
    patterns:
      - pattern: $PATH.starts_with($ROOT)
    message: "Critical: Path containment check using string prefix is vulnerable on Windows. Use component-wise checking."
    languages: [rust]
    severity: ERROR

  - id: unsafe-yaml-deserialization
    patterns:
      - pattern: yaml.load($STREAM)
    message: "Critical: Unsafe YAML loader detected. Replace with yaml.safe_load."
    languages: [python]
    severity: ERROR
```

### 2.4 Pre-Commit Gitleaks Secret Scanning
Enforce secret scanning on every commit and pull request:
```bash
# Run Gitleaks across staged files
gitleaks protect --verbose --staged
```

---

## 3. AST08 Review Checklist

- [ ] Does the security pipeline combine static code analysis, secret scanning, and agentic manifest scanning?
- [ ] Are both executable code files AND natural language instruction files scanned independently?
- [ ] Are custom AST rules (e.g. Semgrep) active to catch path traversal, command injection, and unsafe YAML loading?
- [ ] Has secret scanning (Gitleaks / TruffleHog) passed with zero unencrypted credentials found?
- [ ] Are dynamic behavioral logs evaluated in an isolated sandbox before production approval?
