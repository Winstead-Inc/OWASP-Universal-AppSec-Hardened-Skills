---
name: appsec-observability-audit-logging-and-incident-response
description: Implements tamper-evident audit logging, log injection prevention, sensitive data redaction, telemetry, and circuit breaker kill switches. Use whenever designing logging frameworks, audit trails, compliance logging, monitoring, error telemetry, or emergency containment systems.
---

# Observability, Audit Logging & Incident Response Runbook

## Overview

Without rigorous, tamper-evident observability and structured audit logging, security teams operate blindly during an intrusion. Compromised systems frequently suffer from log forgery via CRLF injection, unauthorized log tampering, sensitive data leakage (PII, credentials) into telemetry platforms, and absence of emergency kill switches. This runbook establishes mandatory standards for structured security audit trails, cryptographic log integrity, data loss prevention (DLP) filtering, distributed tracing, and rapid incident containment.

---

## 1. Tamper-Evident Audit Logging Architecture

### 1.1 Structural JSON Audit Schema
Security audit events must follow a standardized, machine-readable JSON schema to facilitate automated ingestion into SIEM platforms (Elasticsearch, Splunk, Datadog):

```json
{
  "timestamp": "2026-11-20T14:30:00.000Z",
  "event_type": "USER_AUTHENTICATION_FAILED",
  "severity": "WARNING",
  "actor":
  {
    "user_id": "usr_99812739",
    "session_id": "ses_3391823",
    "ip_address": "198.51.100.42",
    "user_agent": "Mozilla/5.0..."
  },
  "action":
  {
    "resource_type": "ACCOUNT_CREDENTIALS",
    "resource_id": "usr_99812739",
    "operation": "LOGIN_PASSWORD_VERIFY",
    "outcome": "FAILURE",
    "reason": "INVALID_PASSWORD_HASH"
  },
  "context":
  {
    "request_id": "req_8812739102",
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "span_id": "00f067aa0ba902b7",
    "environment": "production"
  }
}
```

### 1.2 Cryptographic Log Chaining (Hash Chains)
For critical audit records (financial transactions, administrative privilege grants, security policy changes), implement an append-only forward hash chain. Each log record contains the SHA-256 hash of the preceding record:

$$
\text{Record Hash}_N = \text{SHA256}(\text{Record Content}_N \parallel \text{Record Hash}_{N-1})
$$

Any retroactive modification, insertion, or deletion of log entries immediately breaks the cryptographic hash chain, providing verifiable evidence of tampering.

---

## 2. Log Injection & CRLF Attack Mitigation

### 2.1 The Vulnerability
If an application writes unvalidated user input directly to plain text log files, an attacker can submit strings containing Carriage Return and Line Feed characters (`\r\n` or `\n`). This enables **Log Forgery**: inserting fake log entries to mislead forensic investigators or injecting malicious payloads targeting SIEM parsing engines.

### 2.2 Mandatory Sanitization Rule
Never log raw, unsanitized strings. Strip all control characters (`\r`, `\n`, `\t`, ASCII 0-31, 127) and encode non-printable characters before output:

```rust
// LAFS Compliant Rust Log Sanitizer
pub struct Secure_Log_Sanitizer;

impl Secure_Log_Sanitizer
{
    pub fn Sanitize_Entry(Raw_Input: &str) -> String
    {
        Raw_Input
            .chars()
            .map
            (
                |Character|
                {
                    match Character
                    {
                        '\r' | '\n' => ' ',
                        Character if Character.is_control() => '?',
                        Character => Character,
                    }
                }
            )
            .collect()
    }
}
```

---

## 3. Data Loss Prevention (DLP) & Sensitive Field Redaction

Logs must never become a shadow repository of credentials, personal identifiable information (PII), or confidential data.

### 3.1 Prohibited Log Data Matrix
The following fields must be permanently blocked or replaced with `[REDACTED]` prior to emission:
- **Authentication**: Passwords, API keys, bearer tokens, OAuth refresh tokens, private keys, session cookies.
- **Financial**: Credit card numbers (PAN), CVVs, bank account numbers (IBAN).
- **Personal Data**: Social Security numbers, government IDs, biometric data, personal health information.
- **Headers**: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`.

### 3.2 Automated Redaction Pipeline

```typescript
// LAFS Compliant Redaction Middleware
export class Telemetry_Redaction_Engine
{
    private static readonly SENSITIVE_KEY_PATTERNS: RegExp[] =
    [
        /password/i,
        /secret/i,
        /token/i,
        /auth/i,
        /credential/i,
        /credit_?card/i,
        /api_?key/i,
        /bearer/i,
    ];

    public static Redact_Object_Fields(Payload: Record<string, unknown>): Record<string, unknown>
    {
        const Cleaned_Payload: Record<string, unknown> = {};

        for (const [Key, Value] of Object.entries(Payload))
        {
            if (this.SENSITIVE_KEY_PATTERNS.some((Pattern) => Pattern.test(Key)))
            {
                Cleaned_Payload[Key] = "[REDACTED]";
            }
            else if (Value !== null && typeof Value === "object" && !Array.isArray(Value))
            {
                Cleaned_Payload[Key] = this.Redact_Object_Fields(Value as Record<string, unknown>);
            }
            else
            {
                Cleaned_Payload[Key] = Value;
            }
        }

        return Cleaned_Payload;
    }
}
```

---

## 4. Circuit Breakers, Rate Limiting & Emergency Kill Switches

When an active exploit, credential stuffing campaign, or critical vulnerability is detected, applications must support rapid containment without requiring full redeployment cycles.

### 4.1 Distributed Rate Limiting & Anomaly Throttling
- Enforce token bucket or leaky bucket rate limiters per IP, user ID, and API key.
- Apply progressive delays (tarpitting) to repeated failed authentication attempts.

### 4.2 Dynamic Emergency Kill Switches
- Maintain feature flag toggles that allow operations teams to immediately:
  1. Disable specific vulnerable endpoints or commands.
  2. Invalidate all active user sessions globally.
  3. Force read-only maintenance mode across databases.
  4. Disconnect compromised third-party integrations.

---

## 5. Security Verification Checklist

- [ ] Security events are emitted in structured JSON format with standardized actor and context schemas.
- [ ] CRLF and control characters are stripped from all log inputs to prevent log forgery.
- [ ] Passwords, tokens, authorization headers, and PII are automatically redacted by DLP filters.
- [ ] High-value audit events use cryptographic hash chaining to detect tampering.
- [ ] Outbound logs are forwarded to immutable, append-only storage (WORM storage / S3 Object Lock).
- [ ] Distributed tracing (`trace_id`, `span_id`) correlates security alerts across microservices.
- [ ] Dynamic emergency kill switches exist to isolate compromised features without code redeployment.
