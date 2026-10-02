# Caspian Security — Claude Code Instructions

## Global Rules

- **Do NOT include `Co-Authored-By` lines in commit messages.** Never add co-author trailers for Claude or any AI assistant.
- **Any update must trigger a documentation update when relevant.** Before finishing ANY task, ask: does this change behavior, commands, flags, configuration, output, defaults, or a user-facing feature? If yes, update every affected doc in the *same* change and keep them in sync — `README.md`, `ARCHITECTURE.md`, `BUILD.md`, `SETUP_GUIDE.md`, `QUICKSTART.md`, `START_HERE.md`, `CHANGELOG.md`, the `package.json` description, **`docs/USER_GUIDE.md`**, **`docs/user-guide.html`**, and the GitHub Wiki (especially the **User Guide** page, which mirrors `docs/USER_GUIDE.md`). The Markdown guide, the HTML guide, and the wiki User Guide must always match. If a change is purely internal with no user-facing or behavioral impact, say so explicitly rather than skipping the check silently.
- **After every task, complete ALL post-task steps.** Every code change requires:
  1. **Version bump** — increment `package.json` version, update `CHANGELOG.md`, run `npm install` to sync lock file.
  2. **Documentation updates** — update all affected docs: `README.md`, `ARCHITECTURE.md`, `BUILD.md`, `SETUP_GUIDE.md`, `QUICKSTART.md`, `START_HERE.md`, `docs/USER_GUIDE.md`, `docs/user-guide.html`, and the `package.json` description. Keep `docs/USER_GUIDE.md`, `docs/user-guide.html`, and the wiki **User Guide** page in sync.
  3. **Wiki updates** — if the change affects user-facing features, update the relevant GitHub Wiki pages (clone from `https://github.com/CaspianTools/caspian-security.wiki.git`, edit, commit, push). Always mirror `docs/USER_GUIDE.md` into the wiki **User Guide** page.
  4. **Build VSIX** — run `vsce package` to produce a new `.vsix` with the incremented version number. Confirm it packages without errors.
  5. **Commit** — stage all changed files and commit with a descriptive message following the Pre-Commit Checklist below (lint, compile, review, tag, push, release, Public-Assets release note).
  6. **Notify the user** — always tell the user the new version number and confirm the VSIX was built successfully. Never silently skip this.
  Never skip these steps. They apply to every task, no matter how small. If you forget any step, go back and complete it before moving on.

## Pre-Commit Checklist

Before every `git commit`, follow these steps **in order**. Do not skip any step. If a step fails, fix the issue and re-run from that step before continuing.

### 1. Lint
```
npm run lint
```
Fix all linting errors. Never use `--no-verify` to bypass lint failures.

### 2. Compile
```
npm run compile
```
Fix all TypeScript compilation errors before proceeding.

### 3. Review Changed Files
Review all staged and modified files for:
- Accidental debug code (`console.log`, `debugger`, leftover `TODO`/`FIXME` comments)
- Hardcoded secrets, credentials, or API keys
- Unused imports or dead code introduced by the changes

If any issues are found, fix them before proceeding.

### 4. Bump Version
Increment the version number for every commit:

1. **`package.json`** — bump the `version` field (patch by default, e.g., `7.2.0` → `7.2.1`; use minor for new features, major for breaking changes).
2. **`CHANGELOG.md`** — add a new `## [X.Y.Z] - YYYY-MM-DD` heading above the previous version.
3. Run `npm install` to sync `package-lock.json` with the new version.

### 5. Update Documentation
Update **all** documentation affected by the changes:

1. **CHANGELOG.md** — add entries under the current version heading using the existing format (`### Added`, `### Changed`, `### Fixed`).
2. **Review and update** any of these docs if the changes affect their content:
   - `README.md` — user-facing extension documentation / marketplace listing
   - `ARCHITECTURE.md` — system design and component descriptions
   - `BUILD.md` — build and development instructions
   - `SETUP_GUIDE.md` — deployment and configuration guide
   - `QUICKSTART.md` — quickstart guide
   - `START_HERE.md` — documentation index
3. **package.json** `description` field — update if the extension's capabilities changed.
4. **GitHub Wiki** — if the changes affect features documented in the wiki, update the relevant wiki pages:
   - Clone the wiki repo: `git clone https://github.com/CaspianTools/caspian-security.wiki.git /tmp/caspian-wiki`
   - Edit the affected pages (Home.md, Getting-Started.md, User-Guide.md, Terminal-Usage.md, AI-Agent-Integration.md, Configuration.md, AI-Fixes.md, Confidence-Scoring.md, Caspianignore.md, SARIF-Export.md, Rule-Reference.md, FAQ.md, _Sidebar.md)
   - Keep `User-Guide.md` mirrored to `docs/USER_GUIDE.md` in the main repo (copy it over on any user-facing change)
   - If a new feature warrants its own wiki page, create it and add a link in `_Sidebar.md` and `Home.md`
   - Commit and push: `cd /tmp/caspian-wiki && git add -A && git commit -m "<description>" && git push`
   - If no wiki pages are affected, skip this step.

### 6. Verify Packaging
```
vsce package
```
Confirm the extension packages into a `.vsix` without errors. Keep the `.vsix` file locally — it is needed for marketplace submission. It is already gitignored (`*.vsix`) so it will not be committed.

### 7. Commit
Create the commit with a descriptive message in imperative mood, matching the project's established style (e.g., "Add persistent scan memory" not "Added persistent scan memory"). Do **not** include `Co-Authored-By` trailers.

### 8. Tag
Create an annotated git tag for the new version:
```bash
git tag -a vX.Y.Z -m "vX.Y.Z — <short summary>"
```

### 9. Push
Push the commit and tag to the remote:
```bash
git push origin main --tags
```

### 10. Create GitHub Release
Create a GitHub Release with the `.vsix` attached:
```bash
gh release create vX.Y.Z caspian-security-X.Y.Z.vsix \
  --title "vX.Y.Z — <short summary>" \
  --notes "<changelog entries for this version>"
```

### 11. Publish the update in Public-Assets
Every release gets its own Markdown release note in the public **[`CaspianTools/Public-Assets`](https://github.com/CaspianTools/Public-Assets)** repo, in the `caspian-security/` folder. caspiantools.com reads that repo to build the project page's "Updates" section and the RSS / JSON feeds, so pushing the file there is the whole publishing step. **Do not post to GitHub Discussions — that flow ended on 2026-10-01; existing Discussions stay but nothing new goes there.**

The local clone is `../Public-Assets` (`C:\Users\user\GitHub\Public-Assets`). If it's missing, run `gh repo clone CaspianTools/Public-Assets ../Public-Assets`. Always `git pull` in it before you write.

**Where it goes:**
```
Public-Assets/caspian-security/release-notes/
├── README.md            ← index, newest first: add this release's row at the TOP of the table
└── <major>.<minor>/     ← e.g. 9.0/  (create it for the first release of a new minor line)
    └── <X.Y.Z>.md       ← e.g. 9.0.1.md: bare version, no "v" prefix
```
`release-notes/README.md` doesn't exist yet: create it on the first release, modelled on `Public-Assets/caspian-taskmaster/release-notes/README.md` (a one-line intro, then a `| Version | Date | Headline |` table whose rows link to `<major>.<minor>/<X.Y.Z>.md`).

**How to write it.** Copy `Public-Assets/_templates/release-note.md` and fill in every field. Use [`caspian-taskmaster/release-notes/1.31/1.31.2.md`](https://github.com/CaspianTools/Public-Assets/blob/main/caspian-taskmaster/release-notes/1.31/1.31.2.md) as the worked example.
- **Front matter:** `product: Caspian Security`, `version` (bare `X.Y.Z`), `date` (same as the CHANGELOG heading), `type` (`patch` / `minor` / `major`) and `headline`.
- **Top section (social-media-ready):** the user copy-pastes everything above `## Full changes` straight to Twitter/X, LinkedIn and similar sites, so keep it short and punchy.
  - `# Caspian Security X.Y.Z: <headline>`. The headline is action-oriented, attention-grabbing and user-facing, under 100 characters (e.g., "Your scanner now learns from every fix").
  - A 1–3 sentence intro.
  - 2–4 bullets of what's new. Use emojis sparingly for visual appeal.
  - A one-line value proposition.
  - **Always include the Marketplace link:** https://marketplace.visualstudio.com/items?itemName=CaspianTools.caspian-security
- **`## Full changes`:** this version's CHANGELOG section, verbatim. Never link into a private repo; readers of Public-Assets can't open it.
- **`## Get it`:** the Marketplace and Open VSX (https://open-vsx.org/extension/CaspianTools/caspian-security) links.

**Example top section:**
> # Caspian Security 8.0.0: Your scanner now learns from every fix
>
> Caspian Security 8.0 is here — the extension now gets smarter with every scan.
>
> - Learns which rules produce real issues vs false positives
> - Remembers successful AI fixes and replays them instantly
> - New Learning Dashboard with rule effectiveness, hot zones & trends
> - Opt-in telemetry — preview exactly what's shared before enabling
>
> https://marketplace.visualstudio.com/items?itemName=CaspianTools.caspian-security

**Non-release notices** (no version number) go in `updates/` instead: copy `Public-Assets/_templates/update.md` to `caspian-security/updates/<YYYY>/<YYYY-MM-DD>-<slug>.md`, with front matter `product`, `title` (quote it if it contains ` #`), `date`, `type` (`feature` / `fix` / `release` / `notice`), `social` (`false` = feed and website only) and `draft` (`true` = committed but not published). Body: two to five plain sentences for users, not developers.

**Then validate, commit and push Public-Assets:**
```bash
cd ../Public-Assets
node scripts/build-index.mjs --validate
git add caspian-security/release-notes     # only the new file(s) and the index row, never index.json
git commit -m "Add caspian-security X.Y.Z update"
git push origin main
```
Never commit `index.json`; the Build index workflow regenerates it on push. Never rename or move a published file — its path is its permanent ID in the feeds, so a moved file shows up as a new post.

Tell the user the note's URL: `https://github.com/CaspianTools/Public-Assets/blob/main/caspian-security/release-notes/<major>.<minor>/<X.Y.Z>.md`. It appears on https://caspiantools.com/projects/caspian-security and in https://caspiantools.com/feeds/caspian-security.xml after the next daily site rebuild (05:00 UTC).

## Worktrees & the ship rule

Claude Code can run parallel sessions in isolated **git worktrees** (`claude --worktree <name>`, or ask it to "work in a worktree" → the `EnterWorktree` tool). A worktree lives under `.claude/worktrees/<name>/` on branch `worktree-<name>`, branched **`fresh` from `origin/main`** by default (set `worktree.baseRef: "head"` in `.claude/settings.json` to carry local HEAD instead). `.claude/worktrees/` is gitignored and **`.worktreeinclude`** copies any local secrets (the `.env*` files) into new worktrees — see those two files. `node_modules`, the compiled `out/` tree, and packaged `*.vsix` files are *not* copied: run `npm install` (and `npm run compile`) in each new worktree.

**The catch:** for this repo "shipping" is a **deliberate, manual release**, not an automatic push-to-`main` deploy. On push/PR to `main`, CI only *validates* — `ci.yml` runs lint → compile → test and packages a throwaway VSIX artifact (`vsce package --no-git-tag-version`), and `self-scan.yml` scans our own `src/` and uploads SARIF. **Neither publishes.** (A third workflow, `release.yml`, *does* publish — tag, GitHub Release, Marketplace/Open VSX — but only on a deliberate manual `workflow_dispatch`, never automatically.) The extension actually goes live only when a human runs the [Pre-Commit Checklist](#pre-commit-checklist) tail — `vsce package`, `git tag`, `gh release create`, then `vsce publish` / `ovsx publish` to the VS Code Marketplace + Open VSX. So pushing a branch (or even `main`) never ships by itself; the release commands do. That makes the standing "bump + tag + release" flow something you must **hold** inside a worktree until the owner signs off:

1. **Commit, pause before landing.** Auto-commit finished work on the `worktree-<name>` branch, then **stop and report**. Never merge to `main`, push `main`, tag, `gh release create`, or `vsce/ovsx publish` (the steps that ship) without the owner's explicit go-ahead. *(On `main` — the normal solo flow — the rule is unchanged: run the full Pre-Commit Checklist and release.)*
2. **Serialize landings — one at a time.** Never land two worktrees to `main` in parallel. If another worktree/session is still in flight, wait for it to land first. There's no live cross-session signal, so "wait" means: at land time `git fetch` and rebase onto whatever `origin/main` now is; if the owner says another is mid-flight, hold until told it's done.
3. **Resolve conflicts in the worktree, never on `main`.** At land time: `git fetch origin` → **rebase `worktree-<name>` onto the latest `origin/main`** → resolve every conflict *there*, so `main` only ever receives an already-merged, clean tree.
4. **Finalize the version bump last.** The `package.json` `version`, the new `## [X.Y.Z] - YYYY-MM-DD` heading in `CHANGELOG.md`, and the synced `package-lock.json` (`npm install`) are the *guaranteed* collision between two shippable worktrees — plus the `vX.Y.Z` git tag and the versioned `.vsix` filename. Don't fix the number until after the rebase — take *current-main + 1*, bump `package.json` + `CHANGELOG.md`, and re-run `npm install`.
5. **Re-verify + rebuild after resolving.** Re-run the Pre-Commit Checklist gates on the rebased tree: `npm run lint`, `npm run compile`, `npm test`, then `vsce package` to confirm it still packages cleanly. Also refresh any affected docs (`README.md`, `ARCHITECTURE.md`, `BUILD.md`, `SETUP_GUIDE.md`, `QUICKSTART.md`, `START_HERE.md`, `docs/USER_GUIDE.md`, `docs/user-guide.html`, and the wiki User Guide) so they match the merged result. A conflict resolution that isn't re-verified is a bug waiting to ship.
6. **Only then ship.** Fast-forward `main` to the clean, verified branch → `git push origin main --tags` → `gh release create vX.Y.Z caspian-security-X.Y.Z.vsix …` → `vsce publish` + `ovsx publish` → publish the release note in Public-Assets (step 11 above). **Never push a conflicted or failing tree to `main`, and never publish from an unverified branch.**

For solo, single-stream work that ships immediately, **skip worktrees and work on `main` directly** — the rule needs no adaptation. Reserve worktrees for genuine parallelism (two tasks at once) or experiments you may not ship.
