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
When archives are uploaded, CodeSentinel bounds the compressed upload, total extracted size, member count, and individual file size. Each archive path is resolved and checked to remain inside its generated project directory before extraction:
```python
target_path = (target_dir / member.filename).resolve()
target_path.relative_to(target_dir)
```
Symlink entries are skipped; invalid archives and failed extractions are rejected and their partial project directory is removed. GitHub ingestion accepts canonical HTTPS `github.com/owner/repo` URLs and downloads archives only from GitHub's archive host, without forwarding the repository token to that host.

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
- Applying a patch requires a persisted preview that matches the finding, file, generated diff, and submitted replacement.
- File paths are resolved inside the project directory; symbolic-link paths are rejected.
- The source contents must still match the approved preview before writing. A backup (`.codesentinel_backup`) is retained and replacement uses an atomic file operation.
- Static verification reruns the relevant scanner. A successful response means that scanner no longer reported the targeted finding; it is not proof that the application is free of vulnerabilities.

### 2.6 API and Browser Boundaries
- CORS origins are restricted to the configured origins rather than a wildcard.
- Unexpected server errors return a generic response; request validation errors do not echo submitted values.
- Audit-scoped finding and chain IDs prevent collisions across newly created audits. Ambiguous legacy finding IDs are rejected instead of selecting an arbitrary record.

### 2.7 Optional Single-User API Authentication
- `API_AUTH_ENABLED` defaults to `false` for local development. In this mode, the API and website are accessible without a sign-in prompt; do not expose this mode to untrusted networks. The website UI does not prompt for the API token.
- When `API_AUTH_ENABLED=true`, every `/api` route except health and session establishment/status requires a configured `API_ACCESS_TOKEN`; missing or shorter-than-32-character tokens leave protected routes unavailable.
- Browser sign-in exchanges the token for a signed, random-nonce session in a 12-hour `HttpOnly`, `SameSite=Strict` cookie scoped to `/api`. The server validates expiry and signature, stores only a hash of the nonce, and revokes that session on sign-out. The frontend does not persist the access token in browser storage.
- Cookie-authenticated mutating requests are restricted to configured CORS origins. CORS preflight and the health endpoint remain public.
- Cookies are `Secure` by default. Local HTTP development requires an explicit `AUTH_COOKIE_SECURE=false`; use HTTPS and retain the secure default elsewhere.
- API clients may still use the configured access token as a bearer credential. That credential remains valid until the deployment rotates it; it is not an expiring browser session and cannot be revoked by browser sign-out.
- This is one optional shared deployment identity. It does not provide user accounts, roles, or per-user tenant isolation. Do not expose it as a multi-user service.
