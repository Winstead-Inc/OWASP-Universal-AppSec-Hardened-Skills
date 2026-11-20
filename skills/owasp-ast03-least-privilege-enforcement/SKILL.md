---
name: owasp-ast03-least-privilege-enforcement
description: >-
  Enforce least privilege, strict file path allowlisting, shell command restrictions, and credential store isolation (OWASP AST03). Use when defining permissions, designing file system boundaries, sandboxing shell access, or handling non-human credentials.
---

# OWASP AST03: Least Privilege & Scope Minimization

AST03 addresses over-privileged tools, skills, or applications that request broad system, file, network, or credential access beyond their legitimate function (motivated by audits revealing over 280 skills snooping on `.env` files, SSH keys, browser passwords, and crypto wallets).

---

## 1. Threat Mechanics & Attack Vectors

1. **Broad Filesystem Wildcards**: Requesting `**/*` or root drive access (`C:\`, `/`) when only a specific project subfolder is required.
2. **Unrestricted Shell Execution**: Exposing raw shell execution (`shell: true` or `powershell.exe`) allowing arbitrary script execution.
3. **Credential Store Snooping**: Scanning user home directories for `.ssh/id_rsa`, `.aws/credentials`, `.env`, browser profile databases, or keychain stores.
4. **Shared High-Privilege Agent Context**: Multiple distinct tasks sharing a single god-tier API key or elevated administrative token.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 Explicit Path Scoping & Negative Globs
Declare permissions with minimal, explicit path sets:

```yaml
# Compliant Universal Skill Manifest Scope
permissions:
  files:
    read:
      - ./documents/*.typ
      - ./assets/*.png
    write:
      - ./documents/*.typ
    deny:
      - "**/.env*"
      - "~/.ssh/**"
      - "~/.aws/**"
      - "**/id_rsa"
      - "**/id_ed25519"
      - "SOUL.md"
      - "MEMORY.md"
      - "AGENTS.md"
  network:
    allow:
      - api.typst.org
    deny: "*"
  shell: false
```

### 2.2 Component-Wise Path Boundary Validator (Rust / Node / Python)
Never compare string prefixes. Use component-wise path checking:

```rust
// Rust implementation: Strict path containment
pub fn EnsureWithinAllowedDirectory(Target: &std::path::Path, Root: &std::path::Path) -> Result<std::path::PathBuf, String>
{
    let CanonTarget = Target.canonicalize().map_err(|E| format!("Invalid target path: {}", E))?;
    let CanonRoot = Root.canonicalize().map_err(|E| format!("Invalid root path: {}", E))?;

    if !CanonTarget.strip_prefix(&CanonRoot).is_ok()
    {
        return Err(format!("Security Violation: Path '{}' is outside authorized workspace root.", Target.display()));
    }
    Ok(CanonTarget)
}
```

### 2.3 Shell Access Minimization
- Default `shell: false` for all skills.
- If command execution is necessary, scope permissions to specific binaries with fixed, parameter-validated argument lists (e.g. `["typst", "compile", "--format", "svg"]`).
- Disallow command chaining (`&&`, `||`, `;`, `|`), redirection (`>`, `<`), and command substitution (`$()`, `` ` ``).

### 2.4 Non-Human Identity (NHI) Scoped Credentials
- Provide ephemeral, task-scoped tokens rather than long-lived master keys.
- Rotate credentials automatically upon session completion.
- Block skills from reading parent process environment variables or memory dumps.

---

## 3. AST03 Review Checklist

- [ ] Are permissions minimized strictly to the documented feature scope?
- [ ] Is unrestricted shell access (`shell: true`) completely disabled?
- [ ] Are file permissions scoped to specific relative paths rather than broad wildcards?
- [ ] Are credential directories (`~/.ssh`, `~/.aws`, `.env`, wallet files) protected by explicit deny rules?
- [ ] Are network permissions declared as domain allowlists with default-deny (`deny: "*"`), rather than unrestricted egress?
