---
name: appsec-network-transport-and-ssrf-defense
description: Hardens network transport protocols, TLS termination, HTTP security headers, and enforces impenetrable Server-Side Request Forgery (SSRF) and DNS rebinding protections. Use whenever performing outbound network requests, fetching user-supplied URLs, configuring web servers, or implementing webhook systems.
---

# Network Transport Security & SSRF Defense Runbook

## Overview

Network-facing applications are subject to severe transport interception, man-in-the-middle (MitM) attacks, and internal infrastructure pivot attacks. Among these, Server-Side Request Forgery (SSRF) has emerged as one of the most devastating cloud and enterprise threats, allowing adversaries to query internal microservices, AWS/GCP/Azure instance metadata (169.254.169.254), container orchestration control planes, and loopback administrative ports. This runbook establishes mandatory standards for transport encryption, HTTP headers, DNS rebinding mitigation, and ironclad SSRF defenses.

---

## 1. Transport Layer Security (TLS) Standards

### 1.1 Protocol & Cipher Governance
1. **TLS Version**: Enforce TLS 1.3 as default, with TLS 1.2 as the absolute minimum fallback. Disable TLS 1.0, TLS 1.1, SSLv3, and SSLv2 at the server and client configuration layers.
2. **Cipher Suites**: Restrict TLS 1.2/1.3 ciphers exclusively to AEAD suites providing Forward Secrecy:
   - `TLS_AES_256_GCM_SHA384`
   - `TLS_CHACHA20_POLY1305_SHA256`
   - `TLS_AES_128_GCM_SHA256`
   - `ECDHE-ECDSA-AES256-GCM-SHA384`
   - `ECDHE-RSA-AES256-GCM-SHA384`
3. **Strict SNI & Certificate Validation**: Always enforce full certificate validation (CA trust, expiration, domain matching, revocation via OCSP). Never disable certificate verification flags (e.g. `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False` in Python, or `InsecureSkipVerify: true` in Go) in any environment.

### 1.2 Mandatory HTTP Security Headers

| Header | Production Directive | Purpose |
| :--- | :--- | :--- |
| **Strict-Transport-Security (HSTS)** | `max-age=63072000; includeSubDomains; preload` | Forces HTTPS and prevents SSL stripping |
| **X-Content-Type-Options** | `nosniff` | Prevents MIME-sniffing drive-by downloads |
| **X-Frame-Options** | `DENY` | Mitigates clickjacking framing |
| **Referrer-Policy** | `strict-origin-when-cross-origin` | Protects sensitive URL parameters in referrers |
| **Content-Security-Policy** | (See Client Shell Runbook) | Prevents XSS, code injection, and framing |

---

## 2. Server-Side Request Forgery (SSRF) Defense Architecture

### 2.1 The Multi-Stage SSRF Threat Vector
Naive URL filters (such as regex matching or checking if host == "localhost") fail against hexadecimal IP notation (`0x7f000001`), decimal notation (`2130706433`), IPv6 representations (`[::1]`), DNS rebinding attacks, and HTTP 301/302 redirects.

```text
  [ User URL Input ] ──> [ 1. Parse Scheme (https only) ]
                               │
                               ▼
                      [ 2. Resolve DNS IP ]
                               │
                               ▼
            [ 3. Validate IP Against Denied Ranges ]
          (RFC 1918, Loopback, Link-Local, Cloud Metadata)
                               │
                               ▼
           [ 4. Connect DIRECTLY to Verified IP ]
              (Disable DNS Re-resolution / Rebinding)
                               │
                               ▼
              [ 5. Disable Automatic Redirects ]
           (Re-validate any 3xx redirect destination)
```

### 2.2 Prohibited IP Range Matrix
Every resolved IP address must be validated against the comprehensive prohibited CIDR ranges before opening a socket connection:

- **IPv4 Denied Blocks**:
  - `0.0.0.0/8` (Current network)
  - `10.0.0.0/8` (Private network, RFC 1918)
  - `100.64.0.0/10` (Carrier-grade NAT)
  - `127.0.0.0/8` (Loopback)
  - `169.254.0.0/16` (Link-local & AWS/GCP/Azure IMDS `169.254.169.254`)
  - `172.16.0.0/12` (Private network, RFC 1918)
  - `192.0.0.0/24` (IETF Protocol Assignments)
  - `192.0.2.0/24` (TEST-NET-1)
  - `192.168.0.0/16` (Private network, RFC 1918)
  - `198.18.0.0/15` (Network benchmark testing)
  - `198.51.100.0/24` (TEST-NET-2)
  - `203.0.113.0/24` (TEST-NET-3)
  - `224.0.0.0/4` (Multicast)
  - `240.0.0.0/4` (Reserved for future use)
  - `255.255.255.255/32` (Broadcast)
- **IPv6 Denied Blocks**:
  - `::/128` (Unspecified)
  - `::1/128` (Loopback)
  - `::ffff:0:0/96` (IPv4-mapped IPv6)
  - `100::/64` (Discard-only)
  - `2001:db8::/32` (Documentation)
  - `fc00::/7` (Unique Local Address, private)
  - `fe80::/10` (Link-Local)
  - `ff00::/8` (Multicast)

---

## 3. Production Implementation: SSRF-Safe HTTP Client (Rust)

```rust
use std::net::
{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
};
use url::Url;

pub struct Secure_Network_Gateway;

impl Secure_Network_Gateway
{
    pub fn Is_Prohibited_Ip(Address: &IpAddr) -> bool
    {
        match Address
        {
            IpAddr::V4(Ipv4) =>
            {
                let Octets = Ipv4.octets();
                Ipv4.is_loopback()
                    || Ipv4.is_private()
                    || Ipv4.is_link_local()
                    || Ipv4.is_broadcast()
                    || Ipv4.is_documentation()
                    || Octets[0] == 0
                    || (Octets[0] == 100 && (Octets[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
                    || (Octets[0] == 198 && (Octets[1] & 0xFE) == 18) // 198.18.0.0/15 Benchmark
                    || Octets[0] >= 224 // Multicast & Reserved
            }
            IpAddr::V6(Ipv6) =>
            {
                let Segments = Ipv6.segments();
                Ipv6.is_loopback()
                    || Ipv6.is_unspecified()
                    || (Segments[0] & 0xFE00) == 0xFC00 // Unique Local fc00::/7
                    || (Segments[0] & 0xFFC0) == 0xFE80 // Link-Local fe80::/10
                    || (Segments[0] & 0xFF00) == 0xFF00 // Multicast ff00::/8
                    || (Segments[0] == 0 && Segments[1] == 0 && Segments[2] == 0 && Segments[3] == 0 && Segments[4] == 0 && Segments[5] == 0xFFFF) // IPv4-mapped IPv6
            }
        }
    }

    pub fn Validate_Outbound_Target(Target_Url: &str) -> Result<(String, SocketAddr), String>
    {
        let Parsed = Url::parse(Target_Url)
            .map_err(|Error| format!("Malformed target URL: {Error}"))?;

        if Parsed.scheme() != "https"
        {
            return Err("Prohibited scheme: Only secure HTTPS is permitted".to_string());
        }

        let Host = Parsed.host_str()
            .ok_or_else(|| "Target URL is missing valid host component".to_string())?;

        let Port = Parsed.port_or_known_default().unwrap_or(443);

        use std::net::ToSocketAddrs;
        let Addr_Query = format!("{Host}:{Port}");
        let Resolved_Addresses: Vec<SocketAddr> = Addr_Query.to_socket_addrs()
            .map_err(|Error| format!("DNS resolution failure: {Error}"))?
            .collect();

        if Resolved_Addresses.is_empty()
        {
            return Err("DNS resolved zero valid addresses".to_string());
        }

        for Socket_Address in &Resolved_Addresses
        {
            if Self::Is_Prohibited_Ip(&Socket_Address.ip())
            {
                return Err(format!("SSRF Violation: Resolved address {} belongs to a prohibited private/internal network", Socket_Address.ip()));
            }
        }

        // Return the first validated SocketAddr to connect directly, preventing DNS rebinding
        Ok((Host.to_string(), Resolved_Addresses[0]))
    }
}
```

---

## 4. DNS Rebinding Defense Protocol

In a DNS rebinding attack, an attacker controls a domain name whose nameserver responds with a benign public IP on initial check (TTL=0), and immediately responds with `127.0.0.1` or `169.254.169.254` on the subsequent HTTP fetch.

### Mandatory Mitigations
1. **Socket Pinning**: Pin the resolved IP address directly when opening the TCP stream. The HTTP client must connect directly to the pre-validated `SocketAddr` and pass the original host name in the TLS SNI extension and HTTP `Host` header.
2. **Strict Redirect Interception**: Disable automatic redirect following in HTTP client configuration. Any 301/302/307 redirect must be intercepted, its `Location` header resolved, and the new destination IP passed through the complete validation pipeline before proceeding.
3. **Enforce Request Timeouts**: Apply aggressive connect (3-5 seconds) and read (10 seconds) timeouts to outbound webhooks to prevent slowloris/tarpit exhaustion.

---

## 5. Security Verification Checklist

- [ ] TLS 1.3/1.2 enforced across all public endpoints with forward-secrecy AEAD ciphers.
- [ ] Certificate validation is permanently enabled; zero instances of `InsecureSkipVerify` or disabled trust checks.
- [ ] Production servers emit strict HSTS, `X-Content-Type-Options: nosniff`, and clickjacking protection headers.
- [ ] All user-supplied outbound requests (webhooks, avatar fetches, document imports) undergo strict SSRF IP range filtering.
- [ ] Cloud metadata IP (`169.254.169.254`), IPv4-mapped IPv6, and loopback ranges are explicitly blocked.
- [ ] Sockets connect directly to pre-resolved IPs to eliminate DNS rebinding vulnerabilities.
- [ ] Automated HTTP redirect following is disabled or strictly re-validated on every hop.
