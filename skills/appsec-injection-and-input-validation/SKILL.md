---
name: appsec-injection-and-input-validation
description: >-
  Eliminate all injection vectors including SQL, NoSQL, OS Command, GraphQL, Server-Side Template (SSTI), LDAP, and ReDoS across general development. Use when writing database queries, executing commands, building search interfaces, formatting output, or parsing untrusted user data.
---

# Deep Injection Defense & Universal Input Validation

This skill provides an uncompromising engineering runbook for eliminating every form of injection vulnerability across all languages and frameworks. Injection occurs when untrusted user data is concatenated directly into an interpreter, command shell, or query engine.

---

## 1. Deep Injection Vectors & Universal Defenses

### 1.1 SQL & NoSQL Injection Defense
- **The Golden Rule**: Never concatenate, interpolate, or format strings into a SQL or database query. Always use parameterized queries or prepared statements.
- **Parameterized SQL (Rust / SQLx)**:
  ```rust
  // Safe: Fully parameterized query
  let User = sqlx::query_as::<_, UserRecord>("SELECT id, email, role FROM users WHERE id = $1 AND tenant_id = $2")
     .bind(UserId)
     .bind(TenantId)
     .fetch_optional(&Pool)
     .await?;
  ```
- **Parameterized SQL (Node.js / pg)**:
  ```javascript
  // Safe: Parameterized query array
  const result = await db.query
  (
      "SELECT id, email, role FROM users WHERE id = $1 AND tenant_id = $2",
      [userId, tenantId]
  );
  ```
- **Dynamic Identifiers (Table / Column Names)**: If table or column names must be dynamic, validate them against a strict in-code string allowlist. Never permit user-supplied strings directly in identifier positions:
  ```rust
  const ALLOWED_SORT_COLUMNS: &[&str] = &["created_at", "updated_at", "title", "price"];
  if !ALLOWED_SORT_COLUMNS.contains(&SortCol.as_str())
  {
      return Err("Invalid sort column requested".to_string());
  }
  ```

### 1.2 OS Command & Shell Injection Defense
- **Banish Shell Execution**: Never execute system commands through a shell interpreter (`sh -c`, `bash -c`, `cmd.exe /c`, `powershell.exe -Command`). Always spawn the binary directly with discrete, unquoted argument arrays:
  ```python
  # WRONG - Shell Injection Risk
  subprocess.run(f"convert {user_filename} output.png", shell=True)

  # CORRECT - Direct execution with argument array
  subprocess.run(["convert", "--", safe_filename, "output.png"], check=True)
  ```
- **Argument Injection Defense**: Use `--` before user-controlled filenames or parameters to prevent arguments from being interpreted as CLI flags (e.g. `--output=/etc/shadow`).

### 1.3 Server-Side Template Injection (SSTI) Defense
- Never pass user-supplied strings directly into template engine compilation functions (Jinja2, Handlebars, Tera, EJS).
- Always use pre-compiled, static template files and pass dynamic user input strictly as bounded context variables.

### 1.4 Regular Expression Denial of Service (ReDoS) Defense
- Avoid nested quantifiers and overlapping alternations (e.g. `(a+)+`, `(a|a)+`, `([a-zA-Z]+)*`).
- Use linear-time regular expression engines (Rust's `regex` crate, Google's `RE2`, Go's `regexp`) that guarantee $O(n)$ search time regardless of input structure.
- Always attach length limits to inputs before executing regular expressions.

---

## 2. General Input Validation Matrix

| Data Type | Validation Strategy | Invariant Constraints |
|---|---|---|
| **Text Identifiers (UUID / Slugs)** | Strict Character Allowlist | `^[a-zA-Z0-9_-]{1,64}$` |
| **Numeric Values (Counts / Amounts)** | Type Coercion & Range Assertion | Min $\ge 0$, Max $\le \text{Threshold}$, non-NaN |
| **Email Addresses** | Standard Regex + Length Check | Max 254 chars, single `@`, valid domain syntax |
| **File Names** | Base name extraction + extension allowlist | Strip `/`, `\`, null bytes, control chars, limit 128 chars |
| **JSON / Structured Payloads** | Schema Validation | Pydantic / Zod / Serde with `strict` and `forbid_extra` |

---

## 3. Injection Defense Checklist

- [ ] Are 100% of database queries parameterized with zero string interpolation?
- [ ] Are dynamic SQL table and column names strictly validated against hardcoded allowlists?
- [ ] Is `shell=True` / shell execution completely eliminated in favor of discrete argument arrays?
- [ ] Are all regex patterns analyzed for catastrophic backtracking (ReDoS) or run on linear-time engines?
- [ ] Are CLI commands protected with `--` separators before dynamic arguments?
