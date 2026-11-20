---
name: owasp-ast-appsec-hardened
description: >-
  Master security engineering runbook for building, auditing, and hardening applications and agentic workflows to battle-hardened, impossibly high security standards based on the OWASP Agentic Skills Top 10 (AST10) and B1-B4 Trust Boundary Model. Use whenever designing, reviewing, writing, or refactoring application code, desktop shells (Tauri, Electron), web APIs, or AI agent skills.
---

# OWASP AST Application Security Master Hardening Runbook

This skill provides an end-to-end security architecture framework and operational checklist for building, refactoring, and auditing applications and AI agent skills to an uncompromising ("impossible-tier") security standard. It is derived from the **OWASP Agentic Skills Top 10 (AST10)** and the **B1–B4 Trust Boundary Pipeline Model**.

---

## 1. The B1–B4 Architectural Trust Model

When writing or reviewing application code, continuously evaluate every data and execution path against the four trust boundaries:

```
[ Developer / User Input ]
          │
      (B1: Context & Intent Boundary) ── AST03, AST09 (Sanitize context, enforce least privilege)
          ▼
   [ Application Core / Agent ]
          │
      (B2: Code & Repository Boundary) ── AST01, AST02, AST04 (Validate inputs, safe deserialization, SAST)
          ▼
 [ Local Filesystem / Subprocesses ]
          │
      (B3: Build & CI/CD Pipeline) ── AST02, AST07, AST08 (Immutable hash pinning, pre-mutation receipts)
          ▼
 [ Deployment / Production Host ] ── AST06, AST08, AST09 (Sandbox isolation, auth-bound sockets, audit receipts)
```

---

## 2. Mandatory Core Engineering Controls

### 2.1 File System & Path Traversal Lockdown
- **Zero-Trust Allowlisting**: Always reject negative blacklists. Enforce explicit whitelist sets for permitted directories and extensions.
- **Component-Level Containment**: Never check path boundaries using string prefix methods (`str.startswith`). On Windows and POSIX alike, resolve canonical paths and test component-wise prefix stripping:
  - **Rust**: `ChildPath.canonicalize()?.strip_prefix(&ParentPath.canonicalize()?).is_ok()`
  - **Node.js**:
    ```javascript
    const Rel = Path.relative(ParentDir, ChildPath);
    return !Rel.startsWith("..") && !Path.isAbsolute(Rel);
    ```
  - **Python**:
    ```python
    try:
        common = os.path.commonpath([os.path.realpath(child), os.path.realpath(parent)])
        return common == os.path.realpath(parent)
    except ValueError:
        return False
    ```
- **Archive Extraction (Zip Slip Defense)**: Always sanitize entry names before extracting or archiving:
  - Strip directory separators (`/`, `\`), null bytes (`\0`), and path traversal tokens (`..`).
  - Verify that the target destination is strictly contained within the intended directory.

### 2.2 Subprocess Execution & Denial of Service (DoS) Defense
- **Hard Execution Timeouts**: Every subprocess invocation must be bounded by a non-negotiable timeout (e.g., 15–30 seconds). If a command exceeds the limit, immediately send `SIGKILL` / `Child.kill()` and release worker threads.
- **Strict Binary Allowlisting**: Spawn only pre-vetted absolute binary paths.
- **Zero Shell Invocation**: Never invoke shell interpreters (`cmd.exe /c`, `powershell.exe -Command`, `sh -c`, `bash -c`) with dynamic arguments. Use direct argument arrays (`execFile` / `Command::args`).

### 2.3 Deserialization & Metadata Protection
- **Safe Loaders**: Forbid `yaml.load()`, `pickle.loads()`, `eval()`, or reflection-based deserializers.
- **Schema Validation**: Parse all configuration and data files against strict schemas (Pydantic, Zod, Serde) that reject unexpected keys.
- **Anti-Steganography Scan**: Inspect incoming markdown and text for zero-width Unicode characters, ASCII smuggling, and base64 payloads designed to hijack runtime logic.

### 2.4 Desktop & WebView Hardening (Tauri / Electron)
- **Content Security Policy (CSP)**: Eliminate `'unsafe-inline'` and `'unsafe-eval'`. Remove public third-party CDNs from `script-src`.
- **IPC Perimeter**: Set `withGlobalTauri: false`. Expose only scoped, input-validated native commands.
- **Output Sanitization**: Run all dynamically inserted HTML or SVG through DOMPurify with strict SVG profiles before setting `innerHTML`.
- **Attribute Encoding**: Never concatenate unescaped file paths into inline event handlers (`onclick="..."`). Use `addEventListener` and `dataset`.

### 2.5 Localhost Control Interfaces
- **Bind Address**: Bind local servers strictly to `127.0.0.1` or `::1`, never `0.0.0.0`.
- **Authentication**: Require high-entropy, per-session authentication tokens (`X-Auth-Token`) or HTTP-only cookies on all endpoints.
- **Host Header Verification**: Verify `Host` headers to prevent DNS rebinding attacks.

---

## 3. Systematic Security Audit Checklist

Before releasing or committing application code:

1. [ ] **Input Validation**: Are all inputs validated for type, length, character set, and format?
2. [ ] **Path Sandboxing**: Are all file operations strictly contained within tracked directories via component-wise checking?
3. [ ] **Process Guardrails**: Do all subprocesses enforce hard kill timeouts and use argument arrays?
4. [ ] **Deserialization**: Is data parsed exclusively with safe loaders and strict schema validation?
5. [ ] **XSS & DOM**: Is all user or generated markup sanitized with DOMPurify? Are HTML attributes properly encoded?
6. [ ] **Secrets & Identity**: Are credentials, API keys, and identity files (`SOUL.md`, `MEMORY.md`, `.env`) completely protected from unauthorized reads and writes?
7. [ ] **Dependency Pinning**: Are all package dependencies locked to immutable content hashes (`sha256:`)?
8. [ ] **Audit Trail**: Are high-risk actions logged with immutable, privacy-safe execution receipts?
