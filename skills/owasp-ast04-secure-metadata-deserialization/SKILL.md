---
name: owasp-ast04-secure-metadata-deserialization
description: >-
  Safeguard against unsafe deserialization, insecure metadata, YAML exploit tags, ASCII smuggling, and steganographic prompt injection (OWASP AST04). Use when parsing configuration files, reading YAML/JSON manifests, validating schemas, or processing untrusted structured data.
---

# OWASP AST04: Secure Deserialization & Metadata Protection

AST04 addresses vulnerabilities in parsing and processing metadata files (`SKILL.md`, `plugin.json`, `config.yaml`, frontmatter), including unsafe object deserialization (`PyYAML !!python/object`, Java/Ruby gadget chains), schema bypasses, ASCII smuggling, and zero-width steganography.

---

## 1. Threat Mechanics & Attack Vectors

1. **Unsafe Object Deserialization**: Exploiting parser tags such as `!!python/object/apply` in PyYAML or `ObjectInputStream` to instantiate arbitrary code during file loading.
2. **ASCII Smuggling & Unicode Steganography**: Embedding hidden Unicode control codes (e.g., zero-width spaces `\u200B`, tag characters `\uE0001`–`\uE007F`) in manifests or instructions to inject hidden prompts undetected by human reviewers.
3. **Schema Violation & Unexpected Keys**: Injecting unrecognized properties that trick lenient parsers or bypass permission validators.
4. **Deceptive Manifest Declarations**: Declaring a low risk tier (`risk_tier: L0`) while bundling tools with high-risk system access.

---

## 2. Defensive Controls & Implementation Patterns

### 2.1 Enforce Safe YAML & JSON Loaders
Never use raw or unsafe deserializers. Enforce safe parsing across all runtimes:

```python
# WRONG - Critical RCE via PyYAML
data = yaml.load(untrusted_stream)

# CORRECT - Safe Loader
data = yaml.safe_load(untrusted_stream)
```

In Ruby:
```ruby
# CORRECT - Safe YAML load
data = YAML.safe_load(untrusted_stream, permitted_classes: [Date, Time])
```

In Node.js / JavaScript:
```javascript
// Avoid eval or custom deserializers; use strict JSON.parse with schema verification
const data = JSON.parse(untrusted_string);
```

### 2.2 Anti-Smuggling & Steganography Detection
Sanitize all incoming text and metadata against non-printable, zero-width, and tag characters:

```python
import unicodedata
import re

def detect_and_strip_steganography(text: str) -> str:
    # Match zero-width spaces, zero-width joiners, and unicode tag characters (E0000-E007F)
    stego_pattern = re.compile(r'[\u200B-\u200D\uFEFF\U000E0001-\U000E007F]')
    if stego_pattern.search(text):
        raise ValueError("Security Alert: Steganographic / ASCII smuggling characters detected in metadata!")
    
    # Normalize unicode to NFKC
    return unicodedata.normalize('NFKC', text)
```

### 2.3 Strict Schema Validation (Reject Undeclared Keys)
Always validate parsed manifests against an explicit schema that forbids extra attributes:

```python
from pydantic import BaseModel, Field, Extra
from typing import List, Optional

class SkillManifestSchema(BaseModel):
    name: str = Field(..., regex=r'^[a-z0-9\-]+$')
    version: str = Field(..., regex=r'^\d+\.\d+\.\d+$')
    description: str = Field(..., min_length=10, max_length=500)
    platforms: List[str]
    permissions: dict
    risk_tier: str = Field(..., regex=r'^L[0-3]$')
    content_hash: str = Field(..., regex=r'^sha256:[a-f0-9]{64}$')

    class Config:
        extra = Extra.forbid  # Strict reject on any unexpected keys
```

### 2.4 Sandboxed Deserialization Context
Perform file parsing and schema validation inside an isolated subprocess or disposable worker with minimal privileges before granting the skill access to application runtime resources.

---

## 3. AST04 Review Checklist

- [ ] Are all YAML files loaded strictly with safe loaders (`yaml.safe_load`, never `yaml.load`)?
- [ ] Is input scanned for zero-width spaces, Unicode tags, and ASCII smuggling payloads?
- [ ] Is manifest structure strictly validated against a schema with unexpected keys forbidden?
- [ ] Does the declared `risk_tier` match the actual permissions requested?
- [ ] Are dependency files (`requirements.txt`, `package.json`) treated as untrusted code and validated before execution?
