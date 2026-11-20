# Contributing Guidelines

Guidelines for contributing to the **OWASP-Universal-AppSec-Hardened-Skills** repository.

---

> [!CAUTION]
> ### Mandatory Code Formatting & K&R Disclaimer
> 
> All code snippets, specifications, examples, and documentation in this repository must strictly adhere to the **Language-Agnostic Formatting Style (LAFS)**.
> 
> Kernighan & Ritchie (K&R) formatting (trailing opening delimiters, offset anchors, Egyptian brackets, and clumped closures) is strictly prohibited.
> 
> **DISCLAIMER:** Any code containing K&R slop—if found anywhere in this repository or submitted via pull requests—will be reformatted into clean LAFS geometry without the user's consent.
> 
> Contributors should run the bundled `LAFS.exe` tool across their changes before submitting a pull request.

---

## 1. Formatting Requirements (LAFS)

- **Column-Axis Parity**: The opening and closing delimiters of a multiline block must share the exact same column coordinate on the X-axis.
- **Detached Delimiters**: Delimiters must not hug the preceding semantic identifier or keyword.
- **Dimensional Purity**: Code must exist either as a single-line horizontal Monolith (within canvas limits) or as fully detached Symmetry.
- **Taxonomic Casing**:
  - `PascalCase` for functions, methods, parameters, and variables.
  - `Pascal_Snake_Case` for types, structs, enums, and interfaces.
  - `SCREAMING_SNAKE_CASE` for constants and static invariants.

---

## 2. Using `LAFS.exe`

Before opening a pull request, format all files:

```powershell
# Format files in-place
.\LAFS.exe -a -w

# Verify formatting
.\LAFS.exe --check -a
```

---

## 3. Markdown Formatting Standards

When editing or creating Markdown files:
- Adhere to the **Anti-80-Column Rule**: Do not insert artificial hard line breaks to fit legacy 80-column terminal dimensions. Paragraphs should flow naturally with soft word wrapping.
- Reserve hard newlines strictly for structural elements (headings, list items, blank lines between paragraphs, and code blocks).
