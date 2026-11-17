# CodeSentinel AI — Security Model & Defensive Architecture

## 1. Threat Model & Security Posture

CodeSentinel AI audits untrusted third-party and user-submitted codebases. Consequently, the application itself is engineered defensively with zero-trust architectural principles.

### Key Threats Addressed:
1. **Malicious Archive Ingestion (Zip-Slip & Zip-Bombs)**
2. **Arbitrary Code Execution via Scanned Files**
3. **Secret & Credential Harvesting**
4. **Path Traversal in Source Viewers**
5. **Prompt Injection from Scanned Code**
6. **Unauthorized Repository Alteration**

---

## 2. Defensive Controls Implementation

### 2.1 Secure Archive Ingestion & Zip-Slip Protection
When archives are uploaded, CodeSentinel validates every archive member:
```python
target_path = (target_dir / member.filename).resolve()
if not str(target_path).startswith(str(target_dir.resolve())):
    raise ValueError(f"Malicious zip entry attempting path traversal: {member.filename}")
```
Additionally, cumulative byte sizes are monitored to reject zip-bomb payloads exceeding the configured limit (50MB).

### 2.2 Zero Host Execution During Static Analysis
All code understanding, function resolution, taint analysis, and quality scanning rely on Python's built-in `ast` parsing and regular expression tokenization. At no point is untrusted code executed, imported, or eval'd.

### 2.3 Automatic Secret Redaction
When the Secret Sentinel identifies credentials, tokens, or private keys, all sensitive substrings in snippet previews and descriptions are automatically sanitized:
```python
def _redact(self, line: str) -> str:
    return re.sub(r'([\'"])(?:[A-Za-z0-9/+=]{8,})([\'"])', r'\1[REDACTED_SECRET]\2', line.strip())
```

### 2.4 Prompt Injection Defense in AI Assistance
Code repositories can contain adversarial prompt injection strings embedded in comments or documentation. CodeSentinel:
1. Encapsulates source code strictly inside structured JSON parameter fields rather than free-form system prompts.
2. Directs the assistant to ground statements exclusively in extracted AST facts.
3. Operates seamlessly in deterministic `Rule-Only` mode without requiring external LLM API calls.

### 2.5 Safe Remediation & Rollback Safeguards
- The original repository is never silently altered.
- All patches require explicit user consent via the "Approve & Apply Patch" button.
- A rollback snapshot (`.codesentinel_backup`) is created prior to any file modification.
- Automated static re-verification checks the file to ensure the patch genuinely resolved the vulnerability without introducing regressions.
