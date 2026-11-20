---
name: owasp-ast01-malicious-code-defense
description: >-
  Defend against malicious skills, code payloads, steganographic instructions, and unauthorized persistence mechanisms (OWASP AST01). Use when reviewing new skills, evaluating untrusted code snippets, auditing agent instructions, or designing canary sandboxes.
---

# OWASP AST01: Malicious Code & Skill Defense

AST01 addresses malicious agent skills, scripts, or instructions designed to compromise target hosts, establish persistence, steal credentials, or pivot across infrastructure (motivated by real-world threat campaigns such as *ClawHavoc* where over 1,100 malicious skills were seeded into public registries).

---

## 1. Threat Mechanics & Attack Vectors

1. **Typosquatting & Brand Impersonation**: Attacker publishes packages mimicking official tools (e.g. `g00gle-drive`, `solana-wallet-tracker`) that execute malicious code upon initialization.
2. **Hidden Natural Language Payloads**: Natural language instructions in `SKILL.md` containing jailbreak sequences, encoded payloads, or steganographic instructions instructing the agent to exfiltrate keys.
3. **Agent Identity Persistence**: Malicious skills modifying identity and memory files (`SOUL.md`, `MEMORY.md`, `AGENTS.md`, `.bashrc`, Startup folders) to survive session restarts.
4. **Secondary Staged Payloads**: Benign-looking install scripts that download and execute dynamic binaries during dependency setup (`curl | bash`).

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 Behavioral Verification (Beyond Regex Scanning)
Never rely solely on static pattern matching. Implement semantic and behavioral verification:
- Evaluate the **intent** of natural language instructions against declared functionality.
- Check for discrepancies between the stated tool description and the actual system calls performed.

### 2.2 Anti-Persistence & Identity File Guard
Strictly deny write access to all identity, memory, and startup files unless an explicit, elevated human approval is granted:

```python
# Defense: Identity and Persistence Guard
FORBIDDEN_PERSISTENCE_TARGETS = \
{
    "soul.md", "memory.md", "agents.md", "gemini.md",
    ".bashrc", ".bash_profile", ".zshrc", ".profile",
    "authorized_keys", "known_hosts", "id_rsa", "id_ed25519",
    "desktop.ini", "autorun.inf",
}

def Assert_Not_Identity_Target(Target_Path: str):
    Clean_Name = os.path.basename(Target_Path).strip().lower()
    if Clean_Name in FORBIDDEN_PERSISTENCE_TARGETS:
        raise PermissionError(f"Access denied: '{Clean_Name}' is a protected agent identity file.")
    if "startup" in Target_Path.lower():
        raise PermissionError("Access denied: Modifying OS startup folders is strictly prohibited.")
```

### 2.3 Canary Environment Isolation
Before deploying a new skill or untrusted tool:
1. Run the skill in an ephemeral, network-isolated container or VM with synthetic credentials.
2. Monitor all outbound syscalls, disk writes, and socket connections.
3. Confirm that observed operations match the stated functional scope.

### 2.4 Cryptographic Signature Verification
Verify package authenticity using ed25519 signatures and immutable SHA-256 hashes:
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

def verify_skill_manifest_signature(manifest_bytes: bytes, signature_hex: str, public_key_hex: str) -> bool:
    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        pub_key.verify(bytes.fromhex(signature_hex), manifest_bytes)
        return True
    except Exception:
        return False
```

---

## 3. AST01 Review Checklist

- [ ] Has publisher identity been verified against an authentic code-signing key?
- [ ] Are all scripts and natural language prompts reviewed for encoded payloads and unauthorized `curl`/`wget` calls?
- [ ] Is write access to identity files (`SOUL.md`, `MEMORY.md`, `AGENTS.md`) and OS startup directories strictly denied?
- [ ] Has the tool been tested in a canary sandbox prior to production installation?
