---
name: owasp-ast02-supply-chain-integrity
description: >-
  Enforce supply chain integrity, immutable dependency hash pinning, SBOM generation, and pre-mutation installation receipts (OWASP AST02). Use when installing packages, managing dependencies, configuring build pipelines, or writing installer scripts.
---

# OWASP AST02: Supply Chain Security & Dependency Integrity

AST02 addresses compromised dependencies, typosquatting, unpinned dependency trees, and untrusted repository configurations that execute code upon cloning or project initialization (motivated by incidents such as *Claude Code CVE-2025-59536* where repository configuration files triggered RCE upon opening).

---

## 1. Threat Mechanics & Attack Vectors

1. **Slopsquatting & Dependency Confusion**: Attackers register hallucinated package names or public packages with higher version numbers to hijack private packages.
2. **Mutable Version Drift**: Using floating ranges (`^1.2.0`, `~2.0`, `latest`) allows compromised upstream releases to infiltrate builds automatically.
3. **Implicit Execution on Clone**: Hidden configuration files (`.claude/settings.json`, git hooks, vscode tasks) executing shell scripts automatically when a project directory is opened.
4. **Opaque Installer Mutations**: Installers altering environment variables, MCP configs, hooks, and instruction files without audit visibility.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 Immutable Content Hash Pinning
Every dependency, base container image, and external asset must be pinned to an immutable cryptographic hash:
```text
# Python (requirements.txt with hash verification)
requests==2.31.0 --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2f0b7f530f314d7d49d17e5d6d630

# Node.js (package-lock.json / npm strict verification)
npm install --package-lock-only --ignore-scripts

# Container base images
FROM node:20.11.1-alpine@sha256:d6fa92fad9...
```

### 2.2 Pre-Mutation Installation Receipts
Skill and tool installers must never mutate settings files, hooks, or commands blindly. Installers must emit a reviewable, privacy-safe **Pre-Mutation Receipt** with `--plan` mode before the first disk write occurs:

```json
{
    "schema": "agent.install.plan.v1",
    "installer": "typst-studio-security-pack",
    "resources_planned":
    {
        "skills":
        [
            "security-audit"
        ],
        "hooks":
        [
            "PreToolUse: path-sanitizer"
        ],
        "mcp_servers": [],
        "instruction_files":
        [
            "AGENTS.md"
        ],
        "settings_files":
        [
            ".gemini/config/config.json"
        ]
    },
    "external_commands_planned": [],
    "network_after_install":
    [
        "127.0.0.1:3000"
    ],
    "backups_planned":
    [
        ".gemini/config/config.json.bak"
    ],
    "writes_started": false,
    "next_safe_action": "review receipt, then re-run with --apply"
}
```

### 2.3 Software Bill of Materials (SBOM) Generation
Generate and audit CycloneDX or SPDX SBOMs during every build and publication step:
```bash
# Generate CycloneDX SBOM for Node.js
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Generate CycloneDX SBOM for Rust
cargo cyclonedx --format json -f sbom.json
```

### 2.4 Untrusted Repository Config Sandboxing
Never auto-execute repository-provided hooks or configuration scripts on clone:
- Disable automatic task execution in IDE configurations (`git config core.hooksPath /dev/null` for untrusted clones).
- Require explicit user confirmation before registering local repository hooks or workspace settings.

---

## 3. AST02 Review Checklist

- [ ] Are all dependencies, sub-dependencies, and container images pinned to immutable `sha256:` hashes?
- [ ] Are dependency install commands run with script execution disabled (`--ignore-scripts`)?
- [ ] Does the installer produce a reviewable pre-mutation receipt before altering any settings or files?
- [ ] Are repository configuration files reviewed as executable code before opening projects?
- [ ] Has an SBOM been generated and verified against known vulnerability registries (OSV, NVD)?
