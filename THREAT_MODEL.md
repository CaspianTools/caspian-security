# Caspian Security — Threat Model

This document captures the assets, trust boundaries, adversaries, and
mitigations relevant to the Caspian Security VS Code extension and its CLI.
It's kept deliberately short — a threat model that isn't read isn't useful.
When the design changes, update this file in the same PR.

Scope: extension v9.3.0 and later. Earlier versions should be read against
the CHANGELOG for what was different.

---

## 1. Assets

What an attacker who compromises Caspian can obtain or influence.

| Asset | Why it matters |
|---|---|
| **The user's source code** (every file in the open workspace) | Caspian reads every supported file during a scan. Secrets, proprietary logic, PII in comments. |
| **AI provider API keys** (Anthropic / OpenAI / Gemini) | Stored in `vscode.SecretStorage` (OS keychain). A compromised extension can spend these. |
| **Scan results and learning data** (`resultsStore`, `fixTracker`, `fileStateTracker`, `fixPatternMemory`, `codebaseProfile`, `ruleIntelligenceStore`, `scanHistoryStore`) | Persisted under `context.storageUri`. As of v9.2.0, matched-text `pattern` fields are no longer persisted. |
| **Outbound network capability** | Caspian can call three AI providers, one telemetry endpoint, and npm/OSV registries. Any of these could be pointed at an attacker. |
| **The user's VS Code command surface** | A webview with unchecked `postMessage` could invoke arbitrary registered commands. |

## 2. Trust boundaries

Where adversary-controlled data meets Caspian-controlled code.

1. **The scanned source code itself.** Rules read `line`, `pattern`,
   `filePath`, etc. from whatever the workspace contains. A hostile
   repository is expected input, not a threat — but its content must never
   be treated as instructions. The most notable case is the AI-fix prompt
   (see §4.1).
2. **LLM response bodies.** Whatever the provider returns is *data*, not
   code. It's shown in a diff, applied only after user confirmation. A
   compromised provider returning a malicious patch is mitigated by the
   mandatory review-and-apply step — the user sees the diff before write.
3. **Webviews ↔ extension host.** The only transport is `postMessage`.
   Every `onDidReceiveMessage` handler treats inbound data as untrusted
   and validates command IDs against `ALLOWED_WEBVIEW_COMMANDS`
   ([src/webviewUtils.ts](src/webviewUtils.ts)).
4. **Persisted JSON stores.** On load, every field is parsed but not
   executed. `JSON.parse` errors fall back to default stores.
5. **Settings (`settings.json`).** Users can point `telemetryEndpoint` or
   `aiModel` anywhere — the telemetry endpoint is validated to be
   `https://` before use.

## 3. Adversaries we model

### A. Hostile workspace

A user opens a git repository that was crafted to attack the scanner.
Examples:

- A file containing ``` followed by "Ignore previous instructions…" to
  hijack the AI-fix prompt.
- A file path containing HTML-injection payloads.
- A `.caspianignore` with path-traversal patterns.
- A pathological input designed to trigger ReDoS on scan.

### B. Supply-chain / compromised update

An attacker publishes a malicious update of the extension (marketplace
account takeover), or compromises a downstream package consumed at
install time.

### C. Hostile local process / exfiltration

Another process on the user's machine can read extension storage. Laptops
with full-disk cloud sync (OneDrive, iCloud) effectively have an off-host
adversary too.

### D. Network adversary

Corporate TLS-intercepting proxy, a compromised DNS resolver, or an
attacker positioned on the user's network.

### E. Compromised LLM provider

Anthropic / OpenAI / Google infrastructure is compromised, or a
man-in-the-middle on the provider connection.

### F. Malicious webview

Any defence-in-depth scenario where a webview is compromised and sends
unexpected `postMessage`s.

## 4. Mitigations

Numbered to line up with the adversaries above.

### A. Hostile workspace

- User-supplied code is escape-hatched in the AI-fix prompt: triple-backtick
  fences are replaced with zero-width-space sequences, and the system
  prompt explicitly labels user sections as untrusted data
  ([src/aiFixService.ts](src/aiFixService.ts)).
- Scan has a 3-second per-file deadline and a 200 ms per-pattern ReDoS
  guard enforced at build time ([src/__tests__/redosGuard.test.ts](src/__tests__/redosGuard.test.ts)).
- File-path glob patterns in `.caspianignore` are matched against
  workspace-relative paths only; `..` sequences cannot escape the
  workspace ([src/caspianIgnore.ts](src/caspianIgnore.ts)).
- All HTML rendered in webviews passes through `escapeHtml` / `escapeAttr`.
  File paths and scan output are never interpolated as raw HTML.

### B. Supply-chain / compromised update

- Production `dependencies` are minimal; heavy lifting stays in
  `devDependencies` so a compromised dev dep cannot reach users.
- `package-lock.json` is committed; installs use `npm ci`.
- We publish to both VS Code Marketplace and Open VSX from the same
  signed VSIX so consumers can verify parity.
- The project's own CI runs `caspian-scan` against itself on every push
  ([`.github/workflows/self-scan.yml`](.github/workflows/self-scan.yml)).
- Reporting: see [SECURITY.md](SECURITY.md).

### C. Hostile local process

- API keys live in `vscode.SecretStorage` (OS keychain), never in
  `settings.json`.
- As of v9.2.0, `cachedIssues` are not persisted — the extension no
  longer writes matched secret text to disk.
- Storage path is `context.storageUri` (outside the workspace), so a
  stray `git add .` cannot commit it.

### D. Network adversary

- All outbound calls are HTTPS-only; the telemetry endpoint is validated
  to begin with `https://` before each use.
- Provider-issued TLS trust is used (no cert pinning yet — see §5).
- Gemini API key is sent via header (`x-goog-api-key`), not query string,
  so it doesn't appear in proxy / CDN access logs.

### E. Compromised LLM provider

- Every AI fix is shown in a VS Code diff view and requires two explicit
  user confirmations before the workspace is modified.
- Prompt consent dialog in v9.2.0 shows which provider, which file, and
  how much code will be sent — the user approves each invocation.
- Default is minimal-context mode: only ~20 lines around the finding
  leaves the workspace. Full-file mode is opt-in via
  `caspianSecurity.aiFixMinimalContext`.
- No automatic code execution — "apply fix" is always a manual action.

### F. Malicious webview

- Strict CSP on every panel:
  `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-<nonce>';`.
- Every `<script>` tag carries a per-render nonce.
- `localResourceRoots` scoped to `extensionUri` — webviews cannot reach
  files outside the extension directory.
- `postMessage` handlers reject any command ID not in
  `ALLOWED_WEBVIEW_COMMANDS`.
- No `enableCommandUris`, no `retainContextWhenHidden` for panels that
  don't need it.

## 5. Known residual risk

Things we know we haven't mitigated fully.

- **No TLS pinning** on outbound calls to providers or the telemetry
  endpoint. Corporate SSL-inspection proxies can still MITM. Tracked as
  a future consideration; pinning adds operational friction (cert
  rotation) that isn't worth it for the current threat level.
- **No attestation of the running extension binary** — we rely on VS
  Code Marketplace / Open VSX signature checks. Caspian doesn't verify
  itself at activation. Adding this is being considered for a future
  release.
- **AI-provider content moderation**. We don't redact secrets before
  sending to the provider; the minimal-context default keeps the surface
  small but a secret on the same line as the finding will still go out.
  Future work: client-side `pattern`-based redaction before the outbound
  POST.
- **No sandboxing of rule regexes beyond the ReDoS time budget.** A
  sufficiently bad regex could still consume 3 seconds of CPU per file.
  Acceptable for now; the build-time guard stops this at commit time.
- **Telemetry session ID** rotates daily but could correlate activity
  within a 24-hour window. The payload contains no file paths or
  identifiers, so the correlation value is low.

## 6. Assumptions we make

- VS Code's `SecretStorage` is trustworthy for the OS on which it runs.
- The user's machine is not actively compromised by root-level malware.
- The user's VS Code install is genuine (signature-verified by their OS
  package manager or the marketplace).
- `https://api.anthropic.com`, `https://api.openai.com`, and
  `https://generativelanguage.googleapis.com` honour their documented
  contracts; we don't defend against a provider that silently exfiltrates
  every prompt.

## Change log

| Date | Change |
|---|---|
| 2026-04-21 | Initial version (v9.3.0) |
