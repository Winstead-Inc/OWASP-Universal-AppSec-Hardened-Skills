---
name: appsec-supply-chain-ci-cd-and-slsa
description: Hardens CI/CD pipelines, enforces SLSA provenance, immutable dependency hash pinning, SBOM generation, and mitigates dependency confusion, typosquatting, and slopsquatting. Use whenever managing dependencies, package manifests, build scripts, GitHub Actions, or release engineering workflows.
---

# Universal Supply Chain, CI/CD Hardening & SLSA Runbook

## Overview

Software supply chain attacks have increased exponentially, targeting build pipelines, third-party packages, developer workstations, and deployment automation. Breaches compromising dependencies (such as SolarWinds, EventStream, or XZ Utils) bypass traditional perimeter defenses by poisoning software before it reaches production. This runbook establishes mandatory standards for Supply-chain Levels for Software Artifacts (SLSA v1.0), immutable lockfile integrity, Software Bill of Materials (SBOM) generation, and zero-trust CI/CD execution across all development ecosystems.

---

## 1. Dependency Integrity & Cryptographic Lockfile Pinning

### 1.1 Invariant Dependency Rules
1. **Rule 1 (Immutable Checksum Pinning)**: All dependencies, build tools, transitive packages, and base container images must be pinned to immutable cryptographic hashes (`sha256:`), never floating version ranges (`^`, `~`, `*`, `>=`), semantic tags (`latest`), or mutable git branches.
2. **Rule 2 (Mandatory Lockfile Commit)**: Project lockfiles (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `go.sum`, `requirements.txt` with `--require-hashes`, `poetry.lock`, `uv.lock`) must be committed to version control and validated during CI via frozen/immutable installation flags:
   - Rust: `cargo build --locked`
   - Node.js: `npm ci` or `pnpm install --frozen-lockfile`
   - Python: `pip install --require-hashes -r requirements.txt` or `uv sync --frozen`
   - Go: `go build -mod=readonly`
3. **Rule 3 (Dependency Namespace Scoping)**: Internal packages must use scoped namespaces (`@organization/package-name`) and dedicated private registries configured in `.npmrc`, `pip.conf`, or `config.toml`. Explicitly block public fallback lookups to prevent **Dependency Confusion** attacks.
4. **Rule 4 (Pre-Mutation Verification Receipts)**: Any automated change to project dependencies or build configurations must generate an immutable pre-mutation receipt with SHA-256 hashes before and after modification.

---

## 2. Supply-chain Levels for Software Artifacts (SLSA v1.0) Architecture

### 2.1 SLSA Build Track Levels

```text
    ┌────────────────────────────────────────────────────────┐
    │           SLSA v1.0 BUILD LEVEL HIERARCHY              │
    └───────────────────────────┬────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   [ SLSA BUILD L1 ]       [ SLSA BUILD L2 ]       [ SLSA BUILD L3 ]
   Automated Build Script  Hosted Build Platform   Hardened Ephemeral Runner
   Provenance Generated    Signed Provenance       Hermetic Build Isolation
   SHA-256 Checksum List   Sigstore / Cosign Keys  Zero Host Parameterization
```

### 2.2 SLSA Level 3 Requirements
- **Hosted Build Platform**: Builds must run on dedicated, managed infrastructure (GitHub Actions hosted runners, Google Cloud Build) rather than developer laptops or persistent unmanaged servers.
- **Ephemeral Environments**: Every build step must execute in a freshly initialized, isolated virtual environment or container that is destroyed upon job completion.
- **Hermetic Isolation**: Dependencies must be pre-fetched and cryptographically verified. Network access during the actual compilation/packaging phase must be restricted or disabled.
- **Non-Falsifiable Provenance**: Build provenance must be signed using cryptographic keys protected by hardware security modules (HSM) or identity-bound OIDC tokens via Sigstore / Cosign (`cosign sign-blob --bundle ...`).

---

## 3. GitHub Actions & CI/CD Pipeline Hardening

### 3.1 Immutable Action Commit SHA Pinning
GitHub Actions referenced by release tags (e.g. `actions/checkout@v4`) can be mutated if a maintainer account is compromised. All actions must be pinned to full 40-character commit hashes:

```yaml
# LAFS Compliant GitHub Actions CI Workflow
name: Secure_CI_Pipeline

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

permissions: read-all

jobs:
  Build_And_Verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout Source Repository
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
        with:
          persist-credentials: false

      - name: Setup Toolchain
        uses: dtolnay/rust-toolchain@7b7640ecc771b841795e1e8f2414777a4a16d8a9 # stable
        with:
          toolchain: stable
          components: clippy, rustfmt

      - name: Verify Build Lockfile
        run: cargo build --locked --release

      - name: Audit Dependencies for Known CVEs
        uses: rustsec/audit-check@2e8b090623e1da18073b64cf63b9f4939b4b0051 # v2.0.0
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

### 3.2 CI/CD Invariant Rules
1. **Minimal Default Permissions**: Always declare `permissions: read-all` at the top level of the workflow. Grant granular write permissions (`contents: write`, `issues: write`) only to the specific jobs that require them.
2. **Prevent `pull_request_target` Token Poisoning**: Never check out and build untrusted code from pull requests within a `pull_request_target` workflow. Untrusted PRs can extract CI secrets or push poisoned artifacts.
3. **Runner Token Hygiene**: Never persist git credentials on runners (`persist-credentials: false`).
4. **Secret Masking & Zero Leaks**: Ensure all API keys and deployment credentials are piped via GitHub Secrets with automatic masking; never output raw environment blocks (`env`) to job logs.

---

## 4. Software Bill of Materials (SBOM) Generation

Automated SBOMs provide real-time vulnerability tracking and inventory governance across the software lifecycle.

### 4.1 Industry Standard Formats
- **CycloneDX (JSON)**: The preferred format for application security, license compliance, and dependency vulnerability mapping.
- **SPDX (Software Package Data Exchange)**: ISO/IEC 5962:2021 standard for open-source licensing compliance and software component attribution.

### 4.2 Automated SBOM Pipeline Generation
Incorporate automated SBOM generation into release build jobs:

```bash
# CycloneDX SBOM Generation for Rust
cargo install cargo-cyclonedx
cargo cyclonedx --format json --output-pattern release-sbom.cdx.json

# Syft Universal Multi-Ecosystem SBOM Generation
syft dir:. -o cyclonedx-json=bom.json
```

---

## 5. Security Verification Checklist

- [ ] All dependencies are locked to immutable cryptographic hashes; floating version ranges are banned.
- [ ] Lockfiles (`Cargo.lock`, `package-lock.json`, etc.) are checked into git and enforced via `--locked` / `ci` commands.
- [ ] Internal packages use scoped namespaces to prevent dependency confusion attacks.
- [ ] GitHub Actions are pinned to full 40-character commit SHAs.
- [ ] CI workflows declare `permissions: read-all` as top-level baseline.
- [ ] Build provenance is generated and signed via Sigstore / Cosign following SLSA Level 3 principles.
- [ ] Machine-readable CycloneDX SBOMs are generated and archived with every release build.
- [ ] Automated vulnerability scanners (`cargo-audit`, `npm audit`, `trivy`) run on every pull request.
