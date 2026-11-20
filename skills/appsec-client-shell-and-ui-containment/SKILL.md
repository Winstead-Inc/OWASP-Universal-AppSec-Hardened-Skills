---
name: appsec-client-shell-and-ui-containment
description: Hardens desktop shells (Tauri, Electron), WebViews, and frontend user interfaces against cross-site scripting (XSS), IPC breakout, clickjacking, and unsafe deep link execution. Use whenever building desktop GUI apps, web applications, single-page apps (SPAs), or configuring Content Security Policies (CSP).
---

# Client Shell, WebView & UI Containment Runbook

## Overview

Modern applications frequently bridge web frontend technologies with native operating system privileges via desktop shells like Tauri, Electron, or WebView2. If the frontend is compromised through Cross-Site Scripting (XSS), dependency poisoning, or prototype pollution, attackers can pivot across the Inter-Process Communication (IPC) bridge to achieve Remote Code Execution (RCE) on the host machine. This runbook establishes impenetrable isolation boundaries between client-side UI layers and host operating system execution.

---

## 1. Desktop Shell Isolation Standards

### 1.1 Tauri v1 & v2 Security Architecture

```text
    ┌────────────────────────────────────────────────────────┐
    │           TAURI SECURITY ISOLATION ARCHITECTURE        │
    └───────────────────────────┬────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  [ FRONTEND / WEBVIEW ]    [ IPC BARRIER ]     [ RUST HOST CORE ]
  withGlobalTauri: false    Scoped Capability   Explicit Whitelisting
  Strict Nonced CSP         No Shell Injection  No Unchecked FS Access
  DOMPurify Sanitization    Strict Arguments    Granular Permissions
```

1. **Rule 1 (`withGlobalTauri: false`)**: Never expose `window.__TAURI__` globally to the WebView window context. Import specific commands via module bundlers (`@tauri-apps/api/core`) to prevent third-party scripts or injected XSS payloads from invoking arbitrary backend commands.
2. **Rule 2 (IPC Capability Minimization)**: In Tauri v2, permissions must be strictly scoped in `src-tauri/capabilities/default.json`. Grant only specific command permissions (e.g. `core:default`, `custom:open_document`). Never grant wildcard permissions (`shell:all`, `fs:all`).
3. **Rule 3 (Shell Plugin Hardening)**: If `tauri-plugin-shell` is required, execute only pre-configured binaries defined in configuration with strict argument regular expressions. Never accept arbitrary command strings or shell flags from the frontend.
4. **Rule 4 (Isolation Pattern)**: For high-security environments, enable the Tauri Isolation Pattern (`tauri.conf.json -> build -> withGlobalTauri: false, security: { pattern: { use: "isolation" } }`), which cryptographically signs and intercepts IPC messages inside an isolated sandboxed iframe before they reach the Rust backend.

### 1.2 Electron Security Architecture
- `nodeIntegration: false` (MANDATORY). Never allow the renderer process direct access to Node.js APIs (`fs`, `child_process`).
- `contextIsolation: true` (MANDATORY). Run scripts in separate JavaScript execution contexts. Expose only minimal, validated functions to `window` via `contextBridge.exposeInMainWorld()`.
- `sandbox: true` (MANDATORY). Enforce OS-level chromium sandboxing on all renderer processes.
- `webSecurity: true` (MANDATORY). Never disable Same-Origin Policy.
- Intercept navigation: Handle `will-navigate` and `setWindowOpenHandler` to prevent the app from opening untrusted external URLs in the primary window.

---

## 2. Content Security Policy (CSP) Engineering

A robust Content Security Policy is the definitive line of defense against XSS, data exfiltration, and unauthorized script injection.

### 2.1 Battle-Hardened Strict CSP Matrix

```http
Content-Security-Policy:
    default-src 'none';
    script-src 'self' 'nonce-{RANDOM_CRYPTO_NONCE}';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' https://api.production.example;
    media-src 'self';
    frame-src 'none';
    object-src 'none';
    base-uri 'none';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
```

### 2.2 CSP Invariants
1. **Never use `'unsafe-inline'` for scripts**: Inline scripts must be eliminated. Where dynamic scripts are required, pass a cryptographically secure random nonce generated per request or build-time SHA-256 hash.
2. **Never use `'unsafe-eval'`**: Banned in all production environments. Prevents `eval()`, `new Function()`, and template injection payloads from executing.
3. **`frame-ancestors 'none'`**: Completely blocks the application from being framed within an `<iframe>`, preventing UI redressing and clickjacking.
4. **`base-uri 'none'`**: Prevents `<base href="...">` injection attacks from redirecting relative script imports to malicious origins.

---

## 3. Client-Side Sanitization & DOM Safety

### 3.1 Dangerous DOM Sinks Banned List
The following JavaScript properties and methods are hazardous when provided with user-controlled or dynamically rendered data:
- `element.innerHTML` (Banned for raw input; use `DOMPurify` or `textContent`)
- `element.outerHTML`
- `document.write()` / `document.writeln()`
- `eval()`
- `new Function()`
- `setTimeout("string")` / `setInterval("string")`

### 3.2 Production DOMPurify Sanitization Pattern

```typescript
// LAFS Compliant TypeScript Frontend Sanitization
import DOMPurify from "dompurify";

export class Secure_UI_Renderer
{
    private static readonly PURIFY_CONFIG: DOMPurify.Config =
    {
        USE_PROFILES:
        {
            html: true,
            svg: true,
            svgFilters: false,
        },
        ALLOWED_TAGS:
        [
            "b", "i", "em", "strong", "a", "p", "span",
            "ul", "ol", "li", "code", "pre", "blockquote",
            "svg", "path", "g", "circle", "rect", "line",
        ],
        ALLOWED_ATTR:
        [
            "href", "target", "rel", "class", "id",
            "viewBox", "d", "fill", "stroke", "stroke-width",
            "width", "height", "transform",
        ],
        ALLOW_DATA_ATTR: false,
        FORBID_TAGS: ["script", "iframe", "object", "embed", "link", "style"],
        FORBID_ATTR: ["onload", "onerror", "onclick", "onmouseover"],
    };

    public static Render_Safe_Markup(Target_Element: HTMLElement, Raw_Untrusted_Content: string): void
    {
        const Sanitized_HTML = DOMPurify.sanitize(Raw_Untrusted_Content, this.PURIFY_CONFIG);
        Target_Element.innerHTML = Sanitized_HTML as string;

        // Ensure all rendered external links open securely with noopener/noreferrer
        const Anchor_Tags = Target_Element.querySelectorAll("a");
        Anchor_Tags.forEach
        (
            (Anchor: HTMLAnchorElement) =>
            {
                Anchor.setAttribute("rel", "noopener noreferrer");
                Anchor.setAttribute("target", "_blank");
            }
        );
    }
}
```

---

## 4. Deep Links & Custom Protocol Schemes

Desktop and mobile apps registering custom URI schemes (`myapp://`) must treat protocol parameters as untrusted inputs.

1. **Protocol Validation**: Strictly parse the incoming URI and enforce an allowlist of valid route paths.
2. **Never Execute Shell or FS Operations Directly from Protocol Links**: Protocol handlers must never trigger write operations, file deletions, or process executions without explicit user re-confirmation in the GUI.
3. **Reject Path Traversal in URI Parameters**: Verify that URL parameters referencing files or directories are fully canonicalized and contained within permitted roots.

---

## 5. Security Verification Checklist

- [ ] Desktop shells disable global Tauri/Electron bindings (`withGlobalTauri: false`, `nodeIntegration: false`).
- [ ] IPC endpoints enforce least-privilege capability manifests and strict argument validation.
- [ ] Strict Content Security Policy configured without `'unsafe-inline'` or `'unsafe-eval'`.
- [ ] All dynamic HTML and SVG rendering passes through DOMPurify with strict tag/attribute allowlists.
- [ ] Dangerous sinks (`innerHTML`, `eval`, `document.write`) are audited and blocked.
- [ ] Custom URI schemes (`myapp://`) validate paths and require user interaction before privileged actions.
- [ ] Frames are blocked via `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
