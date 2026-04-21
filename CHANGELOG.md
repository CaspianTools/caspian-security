# Changelog

All notable changes to the Caspian Security extension are documented in this file.

---

## [10.4.0] - 2026-04-21

Caspian is now a Model Context Protocol server. Any MCP client — Claude Desktop, Cursor, Zed, Cline — can call scans directly from tool use. "Use Caspian to scan this repo" goes from four-step manual flow to one-line prompt.

### Added

- **MCP server** ([src/cli/mcpServer.ts](src/cli/mcpServer.ts)) exposing four tools over stdio:
  - `scan` — workspace scan with optional severity filter and max-findings truncation; returns categorised summary + findings as JSON.
  - `scan_git_history` — spawns the existing git-history scanner and parses its JSON output.
  - `list_rules` — rule catalogue with optional category filter.
  - `explain_rule` — full description + suggestion + context-awareness / file-pattern metadata for a given rule code.
- **New bin entry** `caspian-mcp` alongside the existing `caspian-scan`, `caspian-git-history-scan`, `caspian-check-updates`. Launched via `npx caspian-security caspian-mcp` or globally.
- **[src/scanRunner.ts](src/scanRunner.ts)** — workspace-scan logic extracted so both the CLI and the MCP server share one implementation. `walkFiles()`, `resolveLanguage()`, `scanFile()`, and a new `runWorkspaceScan()` wrapper. No I/O concerns beyond `fs.readFileSync` — caller chooses the output format.
- **12 new unit tests** ([src/__tests__/mcpServer.test.ts](src/__tests__/mcpServer.test.ts)) exercising the four handlers + the dispatch layer directly. Smoke-verified end-to-end: `initialize` + `tools/list` over real stdio returns the tool catalogue.
- **Runtime dep: `@modelcontextprotocol/sdk` ^1.29.0.** First non-devDependency runtime dep on the project, but the SDK ships both ESM and CJS entries so it threads cleanly into our CommonJS build.

### Changed

- **[BUILD.md](BUILD.md) §3c** — Claude Desktop + Cursor wiring instructions with copy-pasteable `mcpServers` config.
- **[README.md](README.md) Install section** — adds the MCP block alongside VS Code, npm, and GitHub Actions paths.
- Test suite: **977 → 989** (+12 MCP handler tests). Rules unchanged at 295+.

### Security notes

- The MCP server is **stdio-only** — no network port, no auth tokens, no telemetry.
- Each tool call validates the `path` argument exists and is a directory before scanning.
- The `scan_git_history` tool is guarded by a `.git` directory check and respects the same 100 ms/file taint deadline and 3 s/file rule deadline as every other scan path.

## [10.3.0] - 2026-04-21

PR-scope scanning. Pair it with v10.1's baseline and your monorepo PR CI stops being a full-repo scan.

### Added

- **`--changed-since <ref>` CLI flag.** Restricts the scan to files that differ from the ref in a `<ref>...HEAD` diff. Three-dot semantics means "everything this branch adds since diverging from <ref>", not "everything different from <ref> right now" — so newer commits on the base branch don't pollute the set. `--diff-filter=d` excludes deletions (nothing to scan).
- **[src/gitDiff.ts](src/gitDiff.ts)** — `getChangedFilesSince(workspace, ref)` shells out to `git` via `spawnSync` and returns a Set of absolute paths. Clear error messages for missing ref, non-git repo, or git-not-installed.
- **GitHub Action `changed-since` input** — threads through to the CLI. Paired with `actions/checkout@v4 fetch-depth: 0` so the base ref resolves.
- **4 new unit tests** ([src/__tests__/gitDiff.test.ts](src/__tests__/gitDiff.test.ts)) covering: empty diff, absolute-path output, non-existent ref error, non-git-directory error. Shallow-clone tolerant.

### Why three-dot diff

`--changed-since origin/main` under two-dot semantics (`origin/main..HEAD`) would give the same files as three-dot in the common case — but if `origin/main` has moved forward since this branch diverged, two-dot includes files on `origin/main` that this branch never touched. Three-dot (`origin/main...HEAD`) uses the merge-base, which is what PR review UIs show. Caspian follows the PR-review convention.

### Example — monorepo CI workflow

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- uses: Caspian-Explorer/caspian-security/.github/actions/scan@v10.3.0
  with:
    baseline: .caspian-baseline.json
    changed-since: ${{ github.event.pull_request.base.sha }}
    fail-on: error
```

Result: full-repo scans measured in minutes collapse to seconds on typical PRs. The baseline handles the legacy backlog; `--changed-since` handles the review velocity.

### Changed

- CLI `--help` text documents `--changed-since`.
- [BUILD.md](BUILD.md) gains Section 3b — "PR-scope scanning with `--changed-since`".
- Test suite: **973 → 977** (+4 gitDiff). Rules unchanged at 295+.

## [10.2.0] - 2026-04-21

Caspian is now installable from **three** registries: VS Code Marketplace, Open VSX, and **npm**. The same rule engine reaches every developer — IDE, CLI, CI — through the channel most natural for their workflow.

### Added

- **npm distribution.** Same package, same name (`caspian-security`), same source tree. `npm install -g caspian-security` / `npx caspian-security caspian-scan .` / `npm install --save-dev caspian-security`. No more "clone the repo first" friction for non-GitHub CI pipelines (GitLab, CircleCI, Jenkins, Drone, BuildKite all work out of the box).
- **Three `bin` commands** — `caspian-scan` (main SARIF scanner), `caspian-git-history-scan` (secret scanner for git log), `caspian-check-updates` (dependency audit). All three read the CLI shebang that's already present in source.
- **`files` field** scoped tightly — only `out/`, LICENSE, README, CHANGELOG, SECURITY, THREAT_MODEL, and icon ship to npm. No source tree, no tests, no `.vsix` artefacts.
- **`npm run publish:npm`** script (runs `npm run compile` first, then `npm publish --access public`). Matches the existing `publish:vscode` + `publish:openvsx` pattern so all three registries publish from the same compiled bits.

### Changed

- **[BUILD.md](BUILD.md) publishing section** — rewritten around a three-registry table. Each channel gets its own auth / publish walkthrough. Documents that `require('caspian-security')` isn't supported (the `main` field points at the VS Code extension entry which needs `vscode`); use the bin commands instead.
- **[README.md](README.md)** — new "Install" section near the top covers VS Code / Open VSX / npm / GitHub Actions side by side. Overview copy updated to reflect the current scope (295+ rules, IaC + code, taint tracking, per-invocation consent default).

### Notes

- **Same rule engine, same SARIF, same baseline format** across all three channels. The extension's diagnostics, the CLI's SARIF output, and the Action's uploaded results are indistinguishable once you've stripped the UI chrome.
- Publishing to npm requires a maintainer `npm login` + OTP. The script is in place; actually pushing to the registry is a one-time action the owner runs when ready.

## [10.1.0] - 2026-04-21

The adoption-killer feature: **baseline / suppression file support**. Drop Caspian into any existing codebase without a big-bang remediation.

### Added

- **Baseline file support.** `caspian-scan --baseline .caspian-baseline.json` loads a per-file, per-rule count of known findings and suppresses them from the exit-code gate. Only NEW findings above the baseline counts fail the build. `--update-baseline` regenerates the file from the current scan.
- **`src/baseline.ts`** — `loadBaseline`, `buildBaseline`, `writeBaseline`, `applyBaseline`, `normalisePath`. Counts-based matching (no fingerprinting) so diffs are human-readable and the baseline auto-tightens as issues get fixed. Path-normalised so baselines survive Windows ↔ Linux CI.
- **GitHub Action `baseline` input.** Drop `baseline: .caspian-baseline.json` into your workflow; `.github/actions/scan/action.yml` threads it through to the CLI.
- **12 new unit tests** under `src/__tests__/baseline.test.ts` covering build, apply, normalisation, round-trip, and three flavours of load-error.

### Why counts, not fingerprints

Fingerprints either need a line number (fragile; breaks on every edit) or a normalised-context hash (fragile for different reasons and opaque in diffs). Per-file / per-rule counts are human-readable, git-diff-friendly, and auto-tighten: fix one of three findings, the count drops on `--update-baseline`, and adding a new one fails the build.

### Example

```bash
node out/cli/scan.js . --baseline .caspian-baseline.json --update-baseline
# (review + commit .caspian-baseline.json)
node out/cli/scan.js . --baseline .caspian-baseline.json --fail-on error
# → 0 new findings, exit 0
```

### Changed

- CLI help text documents `--baseline` and `--update-baseline`.
- [BUILD.md](BUILD.md) gains a "Section 3a — adopting Caspian into an existing codebase" with the full workflow.
- Rule totals unchanged at **295+**. Test suite: **961 → 973** (+12 baseline tests).

## [10.0.0] - 2026-04-21

**Caspian graduates from "code scanner" to "code + infrastructure scanner"** — and earns its major-version bump.

The major-version marker reflects a new scanning domain. Everything Caspian did before is preserved and improved; we added a parallel surface (Dockerfile, Terraform/HCL, Kubernetes YAML) that's as thorough as the existing 9.x code rules.

### Added — Infrastructure-as-code

- **Dockerfile rules (`DOCKER001`–`DOCKER008`).** `:latest` / unpinned base images, missing non-root `USER`, secrets baked into `ENV` / `ARG` / `RUN`, `ADD` from a URL, `curl | sh`, package-install without `--no-install-recommends` / pinned versions, `HEALTHCHECK NONE`. Fires on `Dockerfile`, `Containerfile`, `*.dockerfile`.
- **Terraform / HCL rules (`TF001`–`TF010`).** `0.0.0.0/0` ingress, public S3 ACLs / missing public-access blocks, wildcard IAM `Action` / `Resource` (HCL lowercase and JSON forms), `publicly_accessible = true` RDS, missing at-rest encryption on S3 / EBS / RDS, hardcoded `master_password`, disabled CloudTrail, `AdministratorAccess` attached to task/function roles, HTTP-without-HTTPS-redirect load balancers, KMS `kms:*` to account root. Fires on `.tf`, `.tfvars`, `.hcl`.
- **Kubernetes manifest rules (`K8S001`–`K8S008`).** `privileged: true`, `hostNetwork` / `hostPID` / `hostIPC: true`, `runAsUser: 0` / `allowPrivilegeEscalation: true`, `hostPath` volumes, dangerous Linux capabilities (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `BPF`), wildcard RBAC verbs / resources, `LoadBalancer` without `loadBalancerSourceRanges`. Fires on `*.yaml` / `*.yml`; excludes GitHub Actions workflows and `docker-compose.yaml`.

### Added — Quality gate

- **Vulnerable-corpus regression suite** (`src/__tests__/vulnerableCorpus.test.ts` + `src/__tests__/fixtures/vulnerable-corpus/`). Small synthetic fixture tree containing intentional vulnerabilities across every rule family. Each fixture has a minimum set of rule codes it MUST detect — any rule that stops firing breaks the build. Ratchet-style (new detections are fine; removed detections fail). No external repo downloads, CI-viable.
- Caught two real regressions during development: `JWT002` regex rejected string-literal secrets; `TF003` regex missed HCL's lowercase `actions` / `resources`. Both fixed in the same commit that added the test.

### Changed — CLI / file walker

- The CLI now scans `*.yaml`, `*.yml`, `*.tf`, `*.tfvars`, `*.hcl` by default, and special-cases filenames `Dockerfile`, `Containerfile`, `dockerfile`. Rules use `filePatterns.include` to scope per file type — Dockerfile rules don't fire on `.tf`, etc.
- New `resolveLanguage()` helper maps filename + extension to Caspian's `languageId` for downstream file-gated rules.

### Stats

- **Rule totals: 270+ → 295+.** Test suite: **880 → 961** (+81). Two new test suites (`vulnerableCorpus`, plus the 26 new rules contribute to `redosGuard`).
- Lint clean, compile clean, self-scan strict-mode clean.

### Upgrade notes

- No setting changes. No rule renames. Old code rules fire identically; new IaC rules only activate on matching file types.
- Users who keep `caspianSecurity.enabledLanguages` locked to code-only languages won't see IaC findings inside VS Code — the CLI still scans them in CI.

## [9.5.0] - 2026-04-21

Phase 3 of the roadmap. Caspian gains its first dataflow-aware analysis (intra-file taint tracking), a multi-line context fix that unblocks strict CI gating, and four new vulnerability-class families. The single biggest detection-quality jump since v8.0.

### Added — taint tracking (the moat)

- **Intra-file taint engine ([src/taint.ts](src/taint.ts))** — Caspian's first dataflow-aware analysis. Tracks user-input sources (`req.body / query / params / headers`, Flask `request.*`, PHP `$_GET / $_POST`, `process.argv / env`, Python `sys.argv / os.environ`) through simple variable assignments forward to dangerous sinks within the **same function**. Findings are emitted as 8 new rule codes:
  - `TAINT001` command injection (`exec / spawn`)
  - `TAINT002` eval / `new Function` / `vm.runInNewContext`
  - `TAINT003` filesystem path (path traversal)
  - `TAINT004` SQL sinks (`.query / .execute / .raw`)
  - `TAINT005` open redirect (`res.redirect / sendRedirect`)
  - `TAINT006` reflected XSS (`res.send / .innerHTML / document.write`)
  - `TAINT007` SSRF *with provenance* (`fetch / axios / requests` with tainted URL)
  - `TAINT008` prototype pollution via `Object.assign / _.merge / jQuery.extend`

  Sanitiser-aware: drops taint when the value passes through `validator.*`, `DOMPurify.sanitize`, `escape*`, `Number / parseInt`, Zod / Joi `.parse`, `new URL(...)`, `path.resolve(...)+startsWith`, `express-validator`. Performance-bounded: 200 lines / function, 50 in-flight tainted vars, 100 ms / file deadline. New setting `caspianSecurity.enableTaintTracking` (default `true`) gates the pass.
- **Limits documented openly** in the rule messages: no cross-function, no cross-file, no aliasing through arrays / objects / destructuring. Catches the 60–70 % of vulns that happen in a single controller; the rest needs a real taint analyser (Semgrep / CodeQL).

### Added — vulnerability coverage

- **OAuth hygiene (`OAUTH001`–`OAUTH006`)** — callback handles `code` without `state` verification (CSRF), authorize URL missing `state`, code exchange without PKCE, open-redirect via `redirect_uri`, deprecated implicit flow, wildcard `scope`. Slotted into AuthAccessControl.
- **LDAP injection (`LDAP001`–`LDAP003`)** — filter built via concatenation / template literal / Python f-string; Java `DirContext.search` without `LdapEncoder.filterEncode`; Python `python-ldap.search_s` without `escape_filter_chars`. Slotted into AuthAccessControl.
- **Command injection (`CMD001`–`CMD007`)** — Node `exec` with concatenated input, `spawn({shell:true})`, Python `os.system / subprocess(shell=True)`, PHP `shell_exec / passthru` with `$_GET / $_POST`, Ruby string-form `system / backticks / IO.popen`, Java `Runtime.exec / ProcessBuilder` with concatenation. Slotted into APISecurity.
- **Prototype pollution expansion (`FE007a` / `FE007b` / `FE007c`)** — `Object.assign({}, req.body)`, lodash `_.merge / _.defaultsDeep` with untrusted source, `{...req.body}` spread without schema validation. Original `FE007` (`__proto__` literal) gains `contextAware: true`.

### Fixed — F11 multi-line context awareness

- New shared module **[src/scanContext.ts](src/scanContext.ts)** with `buildLineStates(text)` — one-pass char-by-char walker that records per-line state (inside template literal, inside block comment, inside `${}` expression). Handles JS regex literals correctly, including character classes (`/[...]/`), so `/\`/g` no longer cascades the walker into a phantom template-literal state for the rest of the file.
- Both **`analyzer.ts`** (extension host) and **`cli/scan.ts`** consume it. `contextAware` rules now correctly skip matches inside multi-line template literals, JSDoc blocks, and across `${...}` expressions. Removes ~70 lines of duplicated context logic.
- **`XSS001` / `XSS002` / `CRED001`** marked `contextAware: true` so doc examples and webview-generation template literals stop false-positiving in projects that emit HTML to webviews.
- **Self-scan CI flipped back to `--fail-on error`** (was softened in v9.3.0). Caspian's own source now passes the strict gate.

### Changed

- **Rule totals: 240+ → 270+.** Test suite: **812 → 880**. Two new test suites (`scanContext.test.ts`, `taint.test.ts`).
- `.github/workflows/self-scan.yml` excludes `__tests__`, `rules`, `cli` (rationale documented in the workflow file — each is its own intentional design).

## [9.4.0] - 2026-04-21

Phase 2 of the roadmap — five new vulnerability-class families and a git-history secret scanner. All-additive release; no behaviour change to existing rules or workflows.

### Added — vulnerability coverage

- **SSRF (`SSRF001`–`SSRF009`).** Server-side fetch / axios / http / requests / urllib / RestTemplate / HttpClient / curl_exec / `http.Get` called with `req.*`, `request.*`, `params.*`, `body.*`, or a url-shaped user-input variable. Each rule has a shared `suppressIfNearby` allow-list so code that already validates URLs (`new URL(...) + isAllowedHost`, `sanitizeUrl`, SSRF-guard helpers) does not re-flag. Slotted into category APISecurity.
- **Insecure deserialization (`DESER001`–`DESER009`).** `pickle.loads`, `marshal.loads`, `yaml.load` (without `SafeLoader`), `yaml.unsafe_load`, Java `ObjectInputStream.readObject`, .NET `BinaryFormatter` / `SoapFormatter` / `NetDataContractSerializer`, PHP `unserialize($_GET|$_POST|$_REQUEST|$_COOKIE)`, Node `eval`/`Function`/`vm.runInNewContext` on `req.*`, Ruby `YAML.load` / `Marshal.load` on `params`. Slotted into InputValidationXSS.
- **SSTI / template injection (`SSTI001`–`SSTI008`).** Flask `render_template_string`, Jinja2 `Template(user_input)` / `env.from_string(user_input)`, EJS, Handlebars, Pug, Ruby ERB, Java Velocity + Freemarker, PHP Twig + Smarty — all anchored on "compile a template from a user-supplied string".
- **XXE (`XXE001`–`XXE009`).** Java `DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` without the three canonical hardening feature flags. Python `lxml.etree.*` without a safe parser. Python stdlib `xml.etree.ElementTree` / `xml.sax` / `xml.dom.minidom` (recommends `defusedxml`). .NET `XmlDocument` / `XmlTextReader` without `XmlResolver = null`. `.NET DtdProcessing = DtdProcessing.Parse`. PHP `simplexml_load_*` / `DOMDocument` without `libxml_disable_entity_loader`. Node `libxmljs.parseXml({ noent: true })`.
- **JWT misuse (`JWT001`–`JWT007`).** `alg: none` accepted; `jwt.verify(token, key)` without explicit `algorithms` list (algorithm-confusion risk); `jwt.decode()` used where `jwt.verify()` is required; PyJWT `decode` without `algorithms=`; Java `Jwts.parser().setSigningKey(...)` without `.requireAlgorithm(...)`; `ignoreExpiration: true` / `verify_exp=False`; missing `iss` / `aud` checks. Slotted into AuthAccessControl.

### Added — tooling

- **Git-history secret scanner CLI (`out/cli/gitHistoryScan.js`).** Walks every commit reachable from `--all` via `git log -p`, runs the provider-prefix secret rules against every ADDED line, and reports each historical leak with commit SHA, author, ISO date, file, and line number. Grouped-by-commit text output leads with "Next steps: rotate the secret at the provider NOW, then rewrite history with BFG / git-filter-repo, then wire up the CI Action so it cannot happen again". JSON output also available.
- New npm script `npm run scan-git-history`. `--rules secrets|all`, `--max-commits N`, `--format json|text`, `--output FILE` flags.

### Changed

- `package.json` description refreshed to reflect the new scope.
- Rule totals: **192 → 240+**. Test suite: **691 → 812**. Every new pattern passes the ReDoS guard (<200 ms on every adversarial input).

## [9.3.0] - 2026-04-21

Phase 1 improvements: CI-native workflow, provider-prefix secret detection, trust-signal documentation. No behaviour change to the VS Code extension itself beyond 28 new rules; big additions live off the extension (CLI, Action, docs).

### Added

- **28 provider-prefix secret rules (`TOKEN001`–`TOKEN028`).** Each pattern matches a specific vendor's token shape — Anthropic, OpenAI, Slack, Google API/OAuth, Stripe, Twilio, SendGrid, Mailgun, npm, Docker Hub, Shopify, Notion, Linear, Figma, Databricks, Hugging Face, Discord (bot + webhook), Bitbucket, Atlassian, DigitalOcean, Sentry, Postman, Pulumi, Square, GitLab runner, and HTTP basic-auth credentials embedded in URLs. Stripe live vs test, Discord bot vs webhook are split so severity matches impact. Every pattern is ReDoS-safe (build-time verified).
- **CLI scanner (`out/cli/scan.js`).** Runs the same rule set headlessly; emits SARIF 2.1, JSON, or plain text. Supports `--fail-on error|warning|info|never`, `--include`, `--exclude`, `--max-file-size`, `--output`. Mirrors the extension's Informational-cap and context-aware semantics. Exit codes are CI-friendly (0 = clean, 1 = threshold hit, 2 = scan crashed).
- **npm scripts:** `npm run scan`, `npm run self-scan`, `npm run publish:vscode`, `npm run publish:openvsx`.
- **Reusable GitHub Action** at [`.github/actions/scan/action.yml`](.github/actions/scan/action.yml). Consumers add `uses: Caspian-Explorer/caspian-security/.github/actions/scan@v9.3.0` and get a full SARIF-upload pipeline with no extra boilerplate. Copy-pasteable downstream example at [`.github/examples/caspian-scan.yml`](.github/examples/caspian-scan.yml).
- **Self-scan CI workflow** at [`.github/workflows/self-scan.yml`](.github/workflows/self-scan.yml). Caspian runs the CLI against its own source on every push / PR and uploads SARIF to the Security tab. Build fails on any Error-severity regression.
- **[SECURITY.md](SECURITY.md)** — coordinated-disclosure policy with GitHub Private Vulnerability Reporting link, triage SLAs per severity, in-scope / out-of-scope lists.
- **[THREAT_MODEL.md](THREAT_MODEL.md)** — assets, trust boundaries, adversaries (hostile workspace / supply chain / local process / network / compromised LLM / malicious webview), mitigations tied to file:line references, and known residual risks.
- **Open VSX publishing path.** `ovsx` devDependency installed; `npm run publish:openvsx` publishes from the same VSIX that goes to the VS Code Marketplace, reaching Cursor / Windsurf / VSCodium users.

### Changed

- `package.json` `description` refreshed to reflect the new rule count (192) and the CI / CLI / Open VSX story.
- [BUILD.md](BUILD.md) publishing section rewritten: VS Code Marketplace + Open VSX side-by-side, CLI usage, Action usage, and a placeholder for upcoming VSIX publisher signing.

## [9.2.0] - 2026-04-20

Security-hardening release. This version fixes nine self-audit findings affecting the extension's own data-flow, webview, and storage surface. No new scan rules; no functional regressions expected. All changes are defence-in-depth; no known in-the-wild exploitation.

### Security — Critical

- **AI fix provider: Gemini API key moved out of URL path.** Gemini calls now pass the key in the `x-goog-api-key` header instead of the `?key=...` query string, preventing key leakage via proxy logs, CDN edge logs, and `Referer` headers.
- **AI fix: explicit per-invocation consent.** A modal dialog now appears *before* any code is sent to the provider, showing which file, which provider, and how much code will be transmitted. Cancel is the default. Gated by the new `caspianSecurity.aiFixRequireConsent` setting (default `true`).
- **AI fix: minimal-context mode, on by default.** New setting `caspianSecurity.aiFixMinimalContext` (default `true`) sends only ~20 lines around the finding to the provider instead of the whole file. Old behaviour — sending `fullFileContent`, `functionScope`, and `variableDefinitions` — is now opt-in. The response is spliced back into the file locally.
- **Learning Dashboard: CSP + nonce added.** `learningPanel` previously had no Content-Security-Policy and used inline `onclick` handlers with string-concatenated command names. Replaced with a strict CSP (`default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-<nonce>';`), nonce-scoped `<script>`, and event-delegated `data-cmd` attributes validated against an allow-list.
- **Webview command bridge: allow-list enforced.** `resultsPanel`, `taskDetailPanel`, and `learningPanel` now reject any `runCommand` / `runCheck` message whose command ID isn't in a central allow-list (`src/webviewUtils.ts`). Previously a webview could invoke any registered VS Code command.

### Security — High

- **All webview panels now set `localResourceRoots: [extensionUri]`.** `resultsPanel`, `aiSettingsPanel`, `learningPanel`, `welcomePanel`, `taskDetailPanel`, and the `taskTreeProvider` webview view can no longer request files outside the extension directory via `vscode-webview-resource://` URIs.
- **Prompt-injection hardening.** `buildFixPrompt` now escapes triple-backtick fences in user-supplied code (`surroundingCode`, `fullFileContent`, `functionScope`, `variableDefinitions`, `originalLineText`) so a file containing ``` in a comment cannot break out of the markdown code block. The system prompt now explicitly flags user sections as untrusted data.
- **Telemetry: workspace-scoped opt-in.** Previously, clicking "Enable" on the telemetry prompt flipped `enableTelemetry` globally (every workspace, every project). Opt-in now writes to `ConfigurationTarget.Workspace`. The opt-in copy is also more truthful: it explicitly lists the full payload (rule codes, language IDs, AI provider name, session UUID), making clear that `aiProvider` is included.
- **Telemetry endpoint is now configurable + https-validated.** New `caspianSecurity.telemetryEndpoint` setting. The resolver ignores any value that doesn't start with `https://`, so a malformed or downgraded setting cannot redirect the payload.
- **Cached issue patterns no longer persisted.** `fileStateTracker.ts` used to serialise the full `cachedIssues` array to `file-state.json`, including `pattern` (the raw matched text from the source — e.g. `password = "hunter2"`). Cached issues are now dropped on save; the change-detection cache (hash / mtime / size) — the only part that actually drives the skip-unchanged optimisation — is kept. On restart, issues repopulate as each file is scanned this session.

### Security — Medium

- **Tightened analyzer timeout budget.** Per-file scan budget reduced from 10s to 3s, deadline polled every 25 lines instead of every 100, and the per-line length cap dropped from 5000 to 2000 characters. Real scans are unaffected; adversarial inputs are bounded sooner.
- **New `redosGuard` test.** Every `RegExp` on every rule is exercised against a library of catastrophic-backtracking inputs; the build fails if any pattern takes >200 ms.

### Added

- `caspianSecurity.aiFixMinimalContext` (boolean, default `true`)
- `caspianSecurity.aiFixRequireConsent` (boolean, default `true`)
- `caspianSecurity.telemetryEndpoint` (string, default `https://telemetry.caspiansecurity.dev/v1/report`)
- New shared module `src/webviewUtils.ts` exposing `ALLOWED_WEBVIEW_COMMANDS`, `isAllowedWebviewCommand()`, and `getNonce()`
- New tests: `src/__tests__/redosGuard.test.ts`, `src/__tests__/webviewUtils.test.ts`, `src/__tests__/aiFixPrompt.test.ts`

## [9.1.1] - 2026-04-20

### Fixed

- Declare `caspian-security.ignoreAllByRule` and `caspian-security.explainRule` in the `contributes.commands` manifest section to silence two VS Code menu-item validation warnings emitted during `vsce package`. Both commands were already registered at runtime and wired to the results panel webview — only their manifest declarations were missing.

## [9.1.0] - 2026-03-28

### Added

- Auto-verification of resolved findings — the system now watches scan results and automatically marks findings as verified when they disappear, eliminating the need to click Verify manually
- File system watchers for `package.json` and `package-lock.json` — dependency findings (DEP-OUTDATED, DEP-AUDIT) are automatically re-checked when packages change
- New `caspianSecurity.autoVerify` setting (default: true) to toggle auto-verification
- Quiet mode for background dependency re-checks triggered by file watchers
- Line-drift guard prevents false auto-verification when code findings shift lines
- Concurrency guard prevents overlapping dependency checks

## [9.0.8] - 2026-03-20

### Changed

- Add "Tasks" text label to the Tasks toolbar button

## [9.0.7] - 2026-03-20

### Changed

- Convert AI Settings button from primary (blue) labeled button to an icon-only gear button, moved to the far right of the toolbar
- Add Security Tasks icon button (checklist icon) to the Results panel toolbar for quick access to the task dashboard

## [9.0.6] - 2026-03-20

### Changed

- Redesign Results panel filter bar: collapse severity checkboxes into a single multi-select dropdown ("All Severities" / partial list), remove external labels from Category/File/Status/Search controls (first option or placeholder serves as label), move search to the same row, and apply a consistent subtle border with 4px rounded corners to all filter controls

## [9.0.5] - 2026-03-20

### Changed

- Switch Run toolbar icon from filled (`play-fill`) to outlined (`play`) Phosphor SVG, matching the visual weight of Copy and Export icons

## [9.0.4] - 2026-03-20

### Changed

- Replace Unicode icon characters on Run, Copy, and Export toolbar dropdown buttons with Phosphor SVG icons (`play`, `copy`, `download-simple`, `caret-down`), inlined directly to respect webview CSP

## [9.0.3] - 2026-03-20

### Changed

- Consolidate toolbar buttons into three dropdown menus: **Run** (Run Security Check, Check Current File, Check Entire Workspace, Scan Uncommitted Files), **Copy** (Copy All, Copy Errors, Copy Warnings, Copy Info), and **Export** (Export CSV, Export JSON, Export SARIF) — each with icon and chevron

## [9.0.2] - 2026-03-19

### Fixed

- Replace `"admin123"` example password with `"EXAMPLE_PASSWORD"` across all documentation, source comments, and test fixtures to resolve Open VSX secret-scanner false positive blocking extension publication

## [9.0.1] - 2026-03-12

### Changed

- Rename display name from "Caspian Security Extension" to "Caspian Security" across package.json, docs, and source code

## [9.0.0] - 2026-03-12

### Added

- **Welcome Experience** — first-run onboarding webview panel that shows on install with workspace scan, security posture overview, feature highlights, and quick start guide
- **Security Score** — real-time 0-100 security score in the status bar with grade (A-F), severity-weighted calculation, and click-for-details interaction
- **Triage Session** — guided walkthrough command that navigates to each pending issue one by one with AI Fix / Ignore / False Positive / Skip options
- **Bulk Ignore** — "Ignore All [RULE]" button on every finding in the Results Panel to bulk-ignore all instances of a rule code
- **Rule Explanation** — "Why?" button on every finding that shows the rule details, category, severity, and remediation guidance in a modal dialog
- **PR-Scoped Scanning** — "Scan Branch Changes" command that scans only files changed on the current branch vs main/master, with branch name in scan metadata
- **Test Suite** — 230 unit tests across 3 test suites: rule structure validation (211 tests for all 164 rules), caspianIgnore parsing/matching tests, and SecurityScore calculation tests
- **CI Pipeline** — GitHub Actions workflow (`ci.yml`) with lint, compile, test on Node 18/20, and VSIX packaging
- **Jest + ts-jest** testing infrastructure with vscode module mock

### Changed

- Results Panel actions cell now includes "Ignore All [CODE]" and "Why?" buttons for every pending issue
- Status bar now shows two items: the main Caspian status and the security score badge
- `package.json` adds 6 new commands: Welcome, Security Score, Triage Session, Scan Branch Changes, Ignore All By Rule, Explain Rule
- Git integration gains `getBranchChangedFiles()` and `getCurrentBranch()` methods for PR-scoped scanning

## [8.3.0] - 2026-03-11

### Added

- 31 new security rules (133 → 164 total) across web application and Android categories
- **Security Headers** (5 rules): HDR001–HDR005 — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cache-Control for sensitive responses
- **Input Validation** (5 rules): XSS012–XSS016 — Content-Type validation, server-side validation library reminders, HTML encoding, innerHTML sanitization, and template output encoding
- **Frontend Security** (4 rules): FE010–FE013 — window.open with user URLs, sensitive data in web storage, DOM-based XSS source-to-sink detection, and open redirect prevention
- **CSRF Protection** (2 rules): CSRF008–CSRF009 — double-submit cookie pattern and custom header AJAX protection reminders
- **Database Security** (1 rule): DB013 — parameterized query reminder
- **API Security** (2 rules): API015–API016 — server technology header leakage and Helmet middleware reminder
- **Android/Kotlin** (12 rules): KT-AUTH004–006 (receiver export, implicit intents, tapjacking), KT-XSS002–004 (WebView content access, mixed content, SSL error bypass), KT-ENC003–006 (hardcoded keys, weak crypto, cleartext traffic, certificate pinning), KT-CRED001 (hardcoded API keys), KT-LOG002 (clipboard data leakage)
- New `securityHeadersRules.ts` rule file for HTTP security header checks

## [8.2.0] - 2026-03-08

### Changed

- Replace task checklist TreeView with a custom WebviewView for the sidebar
- Task items now show two lines: title on line 1, due date and metadata on line 2
- Group headers (Overdue, Pending, etc.) render proper icons instead of literal `$(icon)` text
- Collapsible status groups with chevron indicators

## [8.1.4] - 2026-03-08

### Fixed

- Fix "No active editor found" error when clicking Run Check from the task detail panel
- Category-specific check commands now fall back to a workspace scan filtered by that category when no editor is open

## [8.1.3] - 2026-03-06

### Fixed

- Fix task detail panel buttons (Run Check, Mark Complete, Snooze, etc.) not responding to clicks
- Replace inline onclick handlers with addEventListener to comply with webview Content Security Policy

## [8.1.2] - 2026-03-06

### Fixed

- Fix high CPU / unresponsive extension when scanning large minified files (e.g. `pdf.worker.min.mjs`)
- Expand minified file path detection to cover `.min.mjs`, `.min.cjs`, and all `.min.*` extensions
- Reorder generated-file check before line splitting to avoid unnecessary work on skipped files
- Add line length limit (5000 chars) to skip minified lines that cause regex backtracking
- Add per-file analysis timeout (10 seconds) to prevent any single file from freezing VS Code
- Improve event loop yielding to run between every file instead of every 10 files

### Added

- New `caspianSecurity.maxFileSize` setting (default: 500KB) to skip oversized files automatically

---

## [8.1.1] - 2026-03-05

### Fixed

- Wire up "Run Check" button in task detail panel — clicking it now executes the task's associated scan command
- Add `runCheck` message handler and webview function for task-specific scans

### Changed

- Add post-task global rules to CLAUDE.md (version bump, docs, wiki, VSIX build, commit, notify)

---

## [8.1.0] - 2026-02-25

### Added

- **Task Detail Panel** — dedicated webview panel for viewing and managing security tasks with rich UI
- Interactive task actions: mark complete, snooze (1hr/4hrs/1day/3days/1week), change interval, dismiss, and reinstate
- Task metadata display: status badge, priority, interval, category, dates, completion count, and related rules
- `showTaskDetail` command for opening task details from the tree view
- Responsive design using VS Code theme variables with Content Security Policy

### Changed

- Tree view click now opens the detail panel instead of a quick-pick action menu
- `taskAction` command redirected to show the detail panel

---

## [8.0.5] - 2026-02-25

### Changed

- Remove Marketplace publish step from pre-commit checklist (now 11 steps)
- Add `.claude/` directory to `.gitignore`

---

## [8.0.4] - 2026-02-25

### Added

- **Git tag, GitHub Release, and Marketplace publish steps** in the pre-commit checklist (steps 8–11)
- **Global rule** prohibiting `Co-Authored-By` trailers in commit messages
- **Restored `.eslintrc.json`** — ESLint config is now tracked in git

### Changed

- Pre-commit checklist renumbered from 8 steps to 12 steps
- GitHub Discussions post moved from step 8 to step 12

---

## [8.0.3] - 2026-02-24

### Added

- **Kotlin/Android support** — `.kt` and `.kts` files are now scanned. All existing rules (secrets, weak crypto, HTTP URLs, SQL injection, etc.) apply automatically.
- **10 Android/Jetpack-specific security rules** scoped to Kotlin files:
  - `KT-AUTH001` — WebView JavaScript enabled (`setJavaScriptEnabled(true)`)
  - `KT-AUTH002` — WebView JavaScript interface exposed (`addJavascriptInterface`)
  - `KT-AUTH003` — Broadcast sent without receiver permission
  - `KT-XSS001` — WebView file access enabled (`setAllowFileAccess(true)`)
  - `KT-ENC001` — Insecure random number generator (`java.util.Random` instead of `SecureRandom`)
  - `KT-ENC002` — Unencrypted SharedPreferences (should use `EncryptedSharedPreferences`)
  - `KT-FILE001` — World-readable/writable file mode (`MODE_WORLD_READABLE`, `MODE_WORLD_WRITEABLE`)
  - `KT-FILE002` — Unsafe external storage access (`getExternalStorageDirectory`)
  - `KT-DB001` — Room `@RawQuery` annotation (potential SQL injection)
  - `KT-LOG001` — Android log statements that may leak sensitive data in production

---

## [8.0.2] - 2026-02-22

### Changed

- GitHub Discussion posts now link to the VS Code Marketplace instead of the GitHub repo

---

## [8.0.1] - 2026-02-22

### Changed

- Pre-commit standing instructions now require GitHub Wiki updates (clone, edit, push) instead of just flagging changes
- Pre-commit standing instructions now require posting a social-media-ready GitHub Discussion after every commit

---

## [8.0.0] - 2026-02-22

### Added

- **Learning Intelligence System** — the extension now learns from every scan, fix, ignore, false positive, and verification to get smarter over time
  - **Rule Intelligence Store** (`ruleIntelligence.ts`) — tracks per-rule effectiveness metrics: detection counts, false positive rates, fix rates, AI fix success rates, resolution times, broken down by language and file pattern
  - **Adaptive Confidence Engine** (`adaptiveConfidence.ts`) — replaces static heuristics with Bayesian-updated confidence scoring that adjusts based on accumulated user behavior (rules with high FP rates get downgraded, highly-acted-on rules get upgraded)
  - **Fix Pattern Memory** (`fixPatternMemory.ts`) — remembers successful AI fixes and offers instant replay for similar issues without an API call; normalizes code patterns for matching, tracks success rates, supports up to 500 patterns with LRU eviction
  - **Codebase Profile** (`codebaseProfile.ts`) — builds a project-specific intelligence profile: learns safe functions from AI fixes and FP dismissals (e.g., DOMPurify.sanitize neutralizes XSS rules), tracks hot zones by directory risk density, monitors security posture trends, detects regressions when previously fixed issues reappear
  - **Scan Insights Engine** (`scanInsights.ts`) — generates actionable insights: trend analysis (improving/degrading), noisy rule detection, regression alerts, hot zone identification, fix pattern availability, AI fix effectiveness, and category completion celebrations
  - **Opt-in Telemetry Service** (`telemetryService.ts`) — anonymized rule effectiveness statistics sent to developer endpoint (off by default, no code/paths/project names, user can preview exact payload before enabling)
  - **Learning Dashboard** (`learningPanel.ts`) — dedicated webview panel with overview stats, sortable rule effectiveness table, fix pattern library, codebase hot zones, security trend visualization, active insights with action buttons, and reset/export controls
- **New commands**: `Show Learning Dashboard`, `Reset All Learning Data`, `Export Learning Data`, `Preview Telemetry Data`
- **New setting**: `enableTelemetry` — opt-in anonymous rule statistics sharing (default: off)
- Learned safe pattern suppression in the scan engine — automatically suppresses findings when learned sanitizer functions are nearby
- Fix pattern memory check before AI API calls — offers instant cached fixes with success rate display

---

## [7.3.0] - 2026-02-22

### Added

- **Security Task Management system** — recurring security task tracking with per-project persistence, interval-based reminders, and auto-completion
  - 23 predefined security tasks across all 14 categories (dependencies, secrets, encryption, logging, infrastructure, auth, CORS, input validation, CSRF, API, database, file handling, frontend, business logic)
  - Configurable intervals: daily, weekly, biweekly, monthly, quarterly
  - Auto-completes tasks when relevant extension actions run (workspace scans, dependency checks)
  - 15-minute scheduler checks for overdue tasks and shows notification reminders
  - Snooze options (1 hour, 4 hours, 1 day, 3 days, 1 week) and dismiss/reinstate per task
  - Per-task interval override without affecting other tasks
- **Activity bar sidebar** — dedicated Caspian Security icon in the VS Code activity bar with Security Tasks tree view
  - Tasks grouped by status: Overdue, Pending, Completed, Snoozed, Dismissed
  - Sorted by priority within each group
  - Click any task to open quick pick with Complete/Snooze/Change Interval/Dismiss actions
  - Refresh button and "Complete All Overdue" action in title bar
- **New commands**: `Show Security Tasks`, `Refresh Security Tasks`, `Complete All Overdue Tasks`
- **New settings**: `enableTaskManagement` (master toggle), `taskReminders` (notification popups)
- **Task persistence** — task state stored in `security-tasks.json` via PersistenceManager, survives VS Code restarts

---

## [7.2.1] - 2026-02-21

### Added

- **Version bump step in CLAUDE.md** — pre-commit checklist now includes automatic version increment (patch by default) with `package.json`, `CHANGELOG.md`, and `package-lock.json` sync

---

## [7.2.0] - 2026-02-15

### Added

- **CLAUDE.md standing instructions** — pre-commit checklist enforcing lint, compile, code review, documentation updates, and packaging verification for every commit via Claude Code

- **Generated file detection** -- new `caspianSecurity.skipGeneratedFiles` setting (default: true) automatically skips scanning of auto-generated and minified files
  - Detects by path patterns (`.min.js`, `.bundle.js`, `workbox-*.js`, `sw.js`, `/dist/`, `/build/`, `/__generated__/`, etc.)
  - Detects by content markers (`@generated`, `@auto-generated`, `do not edit`, `code generator`, etc.)
  - Detects minified code via heuristic analysis (average line length > 300 characters)
- **ConfigManager singleton pattern** -- centralized configuration management with getInstance() for consistent access across the extension

### Changed

- **CRED005** (High-Entropy Strings) -- major false positive reduction:
  - Added `contextAware: true` to skip matches in comments
  - Added 8 negative patterns to exclude translation function calls (`t()`, `i18n()`, `translate()`, `__()`), route paths, URLs with multiple dots, UUIDs with dashes, long constant names, and test/mock data
  - Strengthened pattern matching to require actual base64 characteristics (padding `=` or special chars `+/`) instead of matching any 40+ character string
- **ENC010** (PII Logging Without Masking) -- made detection more precise:
  - Patterns now require object property access (`user.email`, `data.phone`) or PII-prefixed variables (`userEmail`, `customerPhone`)
  - Added 9 negative patterns to exclude false positives: `filename`, `filepath`, `pathname`, `dirname`, `basename`, `classname`, `typename`, `tagname`, `nodename`, `elementname`, `username`, `hostname`, `servername`, `databasename`, `languagename`, `frameworkname`, `packagename`, `displayname`, `appname`, `sitename`, email configuration references, and schema/type definitions
- **ENC003** (HTTP in Comments) -- now context-aware:
  - Added `contextAware: true` to skip HTTP URLs in documentation comments
  - Added negative patterns for example domains (`example.com`, `example.org`, `example.net`) and markdown links
- **FE003** (Missing rel="noopener noreferrer") -- fixed suppression logic:
  - Fixed `suppressIfNearby` check to include the current line (was incorrectly skipping it)
  - Added JSX/React-style patterns to detect `rel={...}` in addition to `rel="..."`

### Fixed

- CRED005 false positives on translation keys like `t('compareYourSpendingAgainstBudgetByCategory')` (30-40% of reported false positives)
- ENC010 false positives on non-PII variables like `console.log('filename:', filename)` and `logger.info('languageName:', 'en')` (15-20% of reported false positives)
- FE003 false positives on links that already have `rel="noopener noreferrer"` on the same line as `target="_blank"` (10-15% of reported false positives)
- ENC003 false positives on HTTP URLs in documentation comments like `// @see http://example.com/docs` (5-10% of reported false positives)
- Generated files being scanned (workbox bundles, service workers, minified JS) causing false positives (10-15% of reported false positives)

**Impact:** Based on production testing feedback, these changes reduce the overall false positive rate from ~70% to <20%.

---

## [7.1.0] - 2026-02-09

### Added

- **Show Informational toggle** -- new `caspianSecurity.showInformational` setting (default: true) lets users hide best-practice reminders and see only actionable security findings
- **Internal path severity reduction** -- new `caspianSecurity.reduceInternalPathSeverity` setting automatically downgrades severity for files in `/admin/`, `/scripts/`, `/internal/`, `/seed/`, `/migrations/`, `/fixtures/`, and `/tools/` directories
- **Informational rule line targeting** -- informational rules now collect multiple candidate matches and pick the most relevant line (preferring function bodies over imports and declarations) instead of firing on the first match

### Changed

- **DB011** (Default Credentials) -- fixed regex that incorrectly matched empty password initialization (`let password = ""`); added negative patterns for password generation contexts (`crypto.randomBytes`, `generatePassword`, etc.)
- **LOG005** (Password in Logs) -- rewritten patterns to require password as a variable reference, not just the word appearing inside a string literal; no longer flags instruction strings like "Users have been created with temporary passwords"
- **ENC010** (PII Logged Without Masking) -- now detects masking functions (`mask*()`, `redact*()`, `anonymize*()`) and suppresses when PII is already wrapped in protection; also checks nearby lines for masking patterns
- **ENC007** (Sensitive Data Logged) -- added same masking detection and instruction-string suppression as ENC010
- **BIZ007** (Client-side Quota) -- added negative patterns for database pagination terms (`limitCount`, `pageSize`, `.limit()`, `OFFSET`, `pagination`) to stop flagging Firestore/SQL query limits
- **BIZ004** (Trial Period Logic) -- now excludes seed, fixture, migration, and mock files entirely; reduces severity in scripts/admin/tools directories
- **FILE009** (Public Storage Bucket) -- replaced broad `/allUsers/i` pattern with context-specific patterns requiring cloud/IAM keywords on the same line; added negative patterns for JSX UI elements (`<SelectItem>`, `<MenuItem>`, etc.)
- **XSS004** (dangerouslySetInnerHTML) -- now suppresses when `JSON.stringify`, `DOMPurify`, or sanitization functions are present on the same line or nearby; also suppresses near `application/ld+json` script tags

### Fixed

- DB011 false positive on empty password variable initialization in password generation functions
- LOG005 false positive on instruction strings containing the word "password"
- ENC010 false positive on PII already wrapped in masking functions like `maskEmail()`
- BIZ007 false positive on Firestore `limitCount` pagination parameters
- BIZ004 false positive on admin seed utilities populating trial-plan reference data
- FILE009 false positive on `<SelectItem value="allUsers">` UI dropdown components
- XSS004 false positive on `dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}` for JSON-LD metadata

---

## [7.0.0] - 2026-02-07

### Added

- **Smart Context AI Fixes** -- AI fix prompts now include the entire enclosing function scope and traced variable definitions, extracted via VS Code's DocumentSymbolProvider. The AI sees the full function body instead of just 20 surrounding lines, producing significantly more accurate fixes for complex code.
- **Confidence Scoring (Deep Verify)** -- each detected issue now receives a confidence classification based on lightweight variable-source analysis:
  - **Critical** (red badge) -- hardcoded secret detected as a string literal (e.g., `password = "EXAMPLE_PASSWORD"`)
  - **Safe** (green badge) -- static string with no dynamic components (e.g., `query = "SELECT * FROM users"`)
  - **Verify Needed** (orange badge) -- dynamic value via concatenation or template interpolation (e.g., `query = "SELECT * FROM " + input`)
  - Confidence badges appear in the results panel next to the Verify button and in VS Code diagnostics
- **`.caspianignore` File** -- clicking "Ignore" now persists the decision to a `.caspianignore` file in the workspace root. Format: `RULE_CODE file/path.ts:line # optional reason`. The file is loaded on startup and watched for live changes, so teams can commit it to version control and share ignore decisions across machines.
- **SARIF v2.1.0 Export** -- new "Export SARIF" button in the results panel header. Generates a standards-compliant SARIF file that can be uploaded directly to GitHub Security Alerts (Security tab > Code scanning > Upload SARIF). Includes rule definitions, severity mapping, and physical source locations.
- New command: "Caspian Security: Export Results to SARIF"
- New files: `src/contextExtractor.ts`, `src/confidenceAnalyzer.ts`, `src/caspianIgnore.ts`

### Changed

- AI fix prompt now uses a security-expert instruction when function scope is available: "Fix the issue within the function scope shown above without breaking the surrounding logic"
- Ignore command now shows an optional input box for providing a reason before writing to `.caspianignore`
- Diagnostics now display confidence prefix when available (e.g., `[Critical] [Secrets] CRED001: ...`)
- Scanner filters out issues matching `.caspianignore` entries before publishing diagnostics

---

## [6.1.0] - 2026-02-03

### Added

- **Verify Button** -- manually verify if an issue has been resolved by re-scanning just that file
- **Verified Status** -- new fix status that confirms an issue is truly resolved (distinct from AI-fixed)
- Verify button appears on both Pending and Fixed issues in the results panel
- Progress bar now includes verified count in resolved total (e.g., "40/120 resolved (28 fixed, 5 verified, 7 ignored)")
- New command: "Caspian Security: Verify Issue Resolution"

### Changed

- Status filter dropdown now includes "Verified" option

---

## [6.0.0] - 2026-02-03

### Added

- **Context-Aware Analysis** -- rules can now detect if matches are inside comments, string literals, or JSX text and suppress false positives
- **Project Advisories** -- informational rules converted to project-level advisories that fire once per scan instead of per-line
- **Negative Patterns** -- rules can specify patterns that suppress matches (e.g., DB001 won't fire if parameterized queries are nearby)
- **Suppress-If-Nearby** -- rules can be suppressed when related safe patterns exist within N lines
- **File Pattern Filtering** -- rules can target specific file patterns (e.g., BIZ001 only fires in payment-related files)
- **.gitignore Check** -- CRED007a advisory warns if .env and other sensitive files aren't in .gitignore
- New `RuleType` enum: `CodeDetectable`, `Informational`, `ProjectAdvisory`
- New rule properties: `contextAware`, `negativePatterns`, `suppressIfNearby`, `filePatterns`

### Changed

- **DB001** (SQL Injection) -- now context-aware, won't flag string concatenation inside comments or when parameterized queries are nearby
- **FE001** (innerHTML) -- now context-aware, suppresses when DOMPurify.sanitize is nearby
- **FE003** (postMessage origin) -- now context-aware, won't flag inside comments
- **ENC005** (Weak Randomness) -- severity reduced from Error to Warning, more appropriate for non-cryptographic uses
- **BIZ001** (Premium Bypass) -- now only fires in payment/subscription-related files
- **CRED007** (.env Detection) -- split into code detection and project advisory for .gitignore check
- **DEP003-DEP006**, **ENC008** -- converted from per-line informational to project advisories
- **LOG004-LOG009** -- converted to project advisories (fire once per scan, not per file)

### Fixed

- False positives from SQL keywords in comments or documentation strings
- False positives from innerHTML in JSX text content
- Generic reminders appearing on arbitrary lines throughout codebase

---

## [5.0.0] - 2026-01-30

### Added

- **AI-Powered Fix Generation** -- click "AI Fix" on any security issue to generate and apply a fix using Claude, GPT-4, or Gemini
- **Issue Status Tracking** -- mark issues as fixed, ignored, or pending; status persists across VS Code restarts via workspaceState
- **Fix Progress Bar** -- results panel shows resolved count (e.g., "35/120 resolved (28 fixed, 7 ignored)")
- **Diff Preview** -- review AI-generated fixes side-by-side before applying; confirm or cancel
- **Post-Fix Verification** -- after applying a fix, the file is re-scanned to verify the issue is resolved
- **AI Settings Panel** -- dedicated webview to configure AI provider, model, and API key with connection testing
- **Secure API Key Storage** -- keys stored in VS Code SecretStorage (OS keychain), never in settings.json
- **3 AI Provider Support** -- Anthropic Claude, OpenAI GPT-4, and Google Gemini with provider-specific API handling
- **Fix Status Filter** -- filter results panel by status: All, Pending, Fixed, Ignored, Fix Failed
- **Status Bar Fix Info** -- status bar shows fix/ignore counts alongside issue count
- New commands: "Configure AI Fix Provider", "Fix Issue with AI", "Ignore Issue", "Reset Fix Tracker"
- New settings: `caspianSecurity.aiProvider` (anthropic/openai/gemini), `caspianSecurity.aiModel` (optional override)
- New files: `src/aiFixService.ts`, `src/fixTracker.ts`, `src/aiSettingsPanel.ts`

### Changed

- "Show Fix Suggestion" command upgraded to "Fix Issue (AI or Suggestion)" -- now attempts AI fix when configured, falls back to text suggestion
- Results panel table now includes an Actions column with per-issue AI Fix/Ignore buttons
- Fixed and ignored issues are visually dimmed in the results table
- Results panel header now includes "AI Settings" button

---

## [4.3.0] - 2026-01-29

### Added

- Dependency & stack update checker -- runs `npm outdated`, `npm audit`, and checks Node.js, TypeScript, and VS Code engine versions against latest releases
- New command: "Caspian Security: Check Dependency & Stack Updates" for on-demand dependency checking from the Command Palette
- Standalone CLI tool: `npm run check-updates` runs the dependency checker from the terminal without VS Code
- Dependency checks automatically included in workspace scans when the Dependencies & Supply Chain category is enabled
- New setting: `caspianSecurity.includeDependencyCheck` (default: true) to control whether workspace scans include dependency checking
- Dedicated "Caspian Security: Dependencies" Output Channel for detailed update and vulnerability reports
- Audit vulnerabilities and outdated packages surfaced as SecurityIssues in the Results Panel under the Dependencies & Supply Chain category
- New files: `src/dependencyChecker.ts` (core logic) and `src/cli/checkUpdates.ts` (standalone CLI entry point)

---

## [4.2.0] - 2026-01-29

### Added

- Pre-scan estimate with confirmation -- workspace scans now show file counts by language and total batches before scanning, with Start Scan/Cancel buttons
- Smart batch scanning -- files are grouped by language and split into batches of 50, with Continue/Stop prompts between each batch showing progress and what's next
- `.next/` directory excluded from workspace scans (Next.js build output)

### Fixed

- VS Code freezing during large workspace scans -- added event loop yielding every 10 files to keep the UI responsive
- Excessive UI updates during scanning -- debounced results store change events (300ms) to prevent thousands of webview re-renders

---

## [3.0.0] - 2025-01-29

### Added

- 133 security rules across 14 categories (up from 16 rules in v1.0)
- 14 security categories with dedicated per-category commands
- Per-category enable/disable toggle settings
- Full workspace scanning -- discovers and scans all project files on disk
- Cancellable workspace scans with file-level progress reporting
- Business Logic & Payment Security category (BIZ001--BIZ009)
- Logging & Monitoring category (LOG001--LOG009)
- Dependencies & Supply Chain category (DEP001--DEP006)
- Infrastructure & Deployment category (INFRA001--INFRA008)
- Informational rule type for process and policy reminders
- Category-scoped diagnostics that preserve other categories' results

### Changed

- Rule codes reorganized by category: AUTH, XSS, CSRF, CORS, ENC, API, DB, FILE, CRED, FE, BIZ, LOG, DEP, INFRA
- Workspace scan uses `findFiles()` to scan all files, not just open tabs
- Full Scan command falls back to workspace scan when no file is open
- Configuration uses individual boolean toggles per category instead of a single array

---

## [1.0.0] - Initial Release

### Added

- 16 security rules (SEC001--SEC016)
- Real-time analysis as you type with 1-second debounce
- Check on save
- 8 language support (JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust)
- Configurable severity levels
- Workspace-wide scanning for open documents
