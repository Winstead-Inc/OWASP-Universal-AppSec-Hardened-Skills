---
name: owasp-ast06-sandboxing-runtime-isolation
description: >-
  Implement OS sandboxing, containerized runtime isolation, localhost control interface authentication, and WebSocket security (OWASP AST06). Use when configuring agent execution environments, securing local HTTP/WebSocket endpoints, or applying system call filters (seccomp, Landlock).
---

# OWASP AST06: Sandboxing & Runtime Isolation

AST06 addresses weak isolation boundaries where skills or applications execute in host-mode with full user privileges, or expose unauthenticated local control interfaces (`127.0.0.1` or `0.0.0.0`) that can be hijacked by malicious browser tabs or local unprivileged processes (highlighted by *CVE-2026-28363 ClawJacked*, where a website hijacked local agents via brute-forced loopback WebSockets).

---

## 1. Threat Mechanics & Attack Vectors

1. **Host-Mode Execution**: Running skills or tasks directly on the developer's workstation with access to all user files, environment variables, and background processes.
2. **ClawJacked / Loopback WebSocket Hijacking**: A malicious webpage visited in a standard browser sends cross-origin WebSockets to `ws://localhost:<port>` to issue commands to an unauthenticated local agent.
3. **Public Interface Binding**: Binding development servers to `0.0.0.0` instead of `127.0.0.1`, exposing internal APIs to the local network or internet.
4. **Shared Process Memory**: Multiple skills sharing memory or temporary files without isolation, allowing cross-skill data snooping.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 OS-Level Sandboxing & Landlock / Seccomp
- On Linux, enforce **Landlock** or **seccomp-bpf** profiles to restrict filesystem access to dedicated sandbox paths and forbid unauthorized syscalls (`execve`, `ptrace`, `chroot`).
- On macOS, leverage `sandbox-exec` with strict `.sb` profiles restricting network and file operations.
- On Windows, use Job Objects and AppContainer isolation or Windows Sandbox.

### 2.2 Secure Localhost Binding & Authentication
Local HTTP/WebSocket servers must NEVER be left unauthenticated:
```javascript
// Node.js: Defensive loopback server configuration
const HTTP = require("node:http");
const Crypto = require("node:crypto");

const HOST = "127.0.0.1"; // NEVER 0.0.0.0
const PORT = 3000;
const SESSION_TOKEN = Crypto.randomBytes(32).toString("hex");

const Server = HTTP.createServer
(
    (Request, Response) =>
    {
        // 1. Host header validation (DNS Rebinding defense)
        const Host = (Request.headers.host || "").toLowerCase();
        if (Host !== `127.0.0.1:${PORT}` && Host !== `localhost:${PORT}`)
        {
            Response.writeHead
            (
                400,
                {
                    "Content-Type": "text/plain",
                }
            );
            return Response.end("Bad Request: Invalid Host Header");
        }

        // 2. Strict Origin / Anti-CSRF verification
        const Origin = Request.headers.origin;
        if (Origin && Origin !== `http://127.0.0.1:${PORT}` && Origin !== `http://localhost:${PORT}`)
        {
            Response.writeHead
            (
                403,
                {
                    "Content-Type": "text/plain",
                }
            );
            return Response.end("Forbidden: Cross-Origin Access Denied");
        }

        // 3. Mandatory Session Token Check for API endpoints
        const Token = Request.headers["x-auth-token"];
        if (Request.url.startsWith("/api/") && (!Token || Token !== SESSION_TOKEN))
        {
            Response.writeHead
            (
                403,
                {
                    "Content-Type": "application/json",
                }
            );
            return Response.end
            (
                JSON.stringify
                (
                    {
                        Error: "Missing or invalid session token",
                    }
                )
            );
        }

        // Process authorized request
    }
);
```

### 2.3 Per-Skill Ephemeral Sandboxes
- Execute each skill invocation within an isolated working directory.
- Clear temporary files, spawned processes, and scratch directories immediately upon task completion.
- Set process resource quotas: CPU limits, RAM limits (e.g. max 512MB), and execution timeouts (e.g. 30s).

### 2.4 Browser DevTools & Debug Interface Protection
- Never expose remote debugging ports (`--remote-debugging-port`) on public interfaces.
- Disable DevTools features in production binary releases of desktop applications (Tauri / Electron).

---

## 3. AST06 Review Checklist

- [ ] Does the application or skill execute within an isolated container or OS sandbox (not unconstrained host-mode)?
- [ ] Are local control interfaces bound strictly to `127.0.0.1` or `::1` (never `0.0.0.0`)?
- [ ] Are all local HTTP and WebSocket endpoints protected by cryptographically random authentication tokens?
- [ ] Is Host header validation and Origin checking active to block DNS rebinding and cross-site hijacking?
- [ ] Are process resource limits (memory, CPU, timeout) enforced on all worker executions?
