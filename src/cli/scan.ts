#!/usr/bin/env node
/**
 * Caspian Security — CLI scanner.
 *
 * Runs the same rule set as the VS Code extension against a workspace, emits
 * SARIF 2.1 (or JSON / plain text), and sets its exit code based on the
 * highest-severity finding. Designed to be dropped into CI — GitHub Actions'
 * `upload-sarif` step can consume the SARIF output directly.
 *
 * Usage:
 *   caspian-scan [path]
 *       --output <file>         default: stdout
 *       --format sarif|json|text  default: sarif
 *       --fail-on error|warning|info|never  default: error
 *       --include <glob,glob>   additional include patterns
 *       --exclude <glob,glob>   additional exclude patterns
 *       --max-file-size <bytes> default: 500000
 *
 * Exit codes:
 *   0  scan ran, no finding at or above the --fail-on threshold
 *   1  scan ran, at least one finding at or above the --fail-on threshold
 *   2  scan failed to run (bad args, I/O error, parse failure)
 *
 * This file deliberately does NOT import `vscode`. It mirrors the scan
 * semantics of src/analyzer.ts (severity filtering, context-awareness,
 * suppressIfNearby, negativePatterns, file-size cap, generated-file skip)
 * but reads files via Node's fs module so it can run in CI.
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from '../rules';
import {
  SecurityRule,
  SecurityIssue,
  SecuritySeverity,
  RuleType,
  SEVERITY_LABELS,
  CATEGORY_LABELS,
} from '../types';
import { isGeneratedFile } from '../generatedFileDetector';
import { buildLineStates, isInsideComment, isInsideStringContent } from '../scanContext';
import { runTaintAnalysis } from '../taint';

// --- CLI argument parsing -------------------------------------------------

interface CliOptions {
  workspace: string;
  output?: string;
  format: 'sarif' | 'json' | 'text';
  failOn: 'error' | 'warning' | 'info' | 'never';
  include: string[];
  exclude: string[];
  maxFileSize: number;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    workspace: process.cwd(),
    format: 'sarif',
    failOn: 'error',
    include: [],
    exclude: [],
    maxFileSize: 500_000,
  };

  let positionalSeen = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) {
        throw new Error(`${a} requires a value`);
      }
      return v;
    };
    switch (a) {
      case '-h':
      case '--help':
        printHelp();
        process.exit(0);
        break;
      case '-o':
      case '--output':
        opts.output = next();
        break;
      case '--format': {
        const v = next();
        if (v !== 'sarif' && v !== 'json' && v !== 'text') {
          throw new Error(`--format must be sarif|json|text (got ${v})`);
        }
        opts.format = v;
        break;
      }
      case '--fail-on': {
        const v = next();
        if (v !== 'error' && v !== 'warning' && v !== 'info' && v !== 'never') {
          throw new Error(`--fail-on must be error|warning|info|never (got ${v})`);
        }
        opts.failOn = v;
        break;
      }
      case '--include':
        opts.include.push(...next().split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '--exclude':
        opts.exclude.push(...next().split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '--max-file-size':
        opts.maxFileSize = Math.max(0, parseInt(next(), 10) || 0);
        break;
      default:
        if (a.startsWith('-')) {
          throw new Error(`unknown flag: ${a}`);
        }
        if (positionalSeen) {
          throw new Error(`only one positional workspace path is allowed (got ${a})`);
        }
        opts.workspace = path.resolve(a);
        positionalSeen = true;
    }
  }

  if (!fs.existsSync(opts.workspace)) {
    throw new Error(`workspace path does not exist: ${opts.workspace}`);
  }
  return opts;
}

function printHelp(): void {
  process.stdout.write(
    'caspian-scan [path]\n' +
    '  --output <file>               write results to file (default: stdout)\n' +
    '  --format sarif|json|text      output format (default: sarif)\n' +
    '  --fail-on error|warning|info|never\n' +
    '                                minimum severity that causes non-zero exit (default: error)\n' +
    '  --include <glob,glob,...>     additional file-path substrings to include\n' +
    '  --exclude <glob,glob,...>     additional file-path substrings to exclude\n' +
    '  --max-file-size <bytes>       skip files larger than this (default: 500000)\n' +
    '\n' +
    'Exit codes: 0 = clean, 1 = findings at/above threshold, 2 = scan failed\n'
  );
}

// --- Filesystem walk ------------------------------------------------------

const DEFAULT_EXTENSIONS = new Set([
  'js', 'jsx', 'mjs', 'cjs',
  'ts', 'tsx',
  'py',
  'java',
  'cs',
  'php',
  'go',
  'rs',
  'kt', 'kts',
]);

const DEFAULT_EXCLUDES = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  'vendor',
  '__pycache__',
  'target',   // Rust / Java
];

const EXT_TO_LANGUAGE: Record<string, string> = {
  js: 'javascript', jsx: 'javascriptreact', mjs: 'javascript', cjs: 'javascript',
  ts: 'typescript', tsx: 'typescriptreact',
  py: 'python',
  java: 'java',
  cs: 'csharp',
  php: 'php',
  go: 'go',
  rs: 'rust',
  kt: 'kotlin', kts: 'kotlin',
};

function walkFiles(root: string, excludes: string[], extraIncludes: string[]): string[] {
  const found: string[] = [];
  const skipSet = new Set(DEFAULT_EXCLUDES.concat(excludes));

  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // permission, broken symlink, etc.
    }

    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (skipSet.has(ent.name)) { continue; }
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) { continue; }

      const ext = path.extname(ent.name).slice(1).toLowerCase();
      const includedByExt = DEFAULT_EXTENSIONS.has(ext);
      const includedByFlag = extraIncludes.some(tok => full.includes(tok));
      if (!includedByExt && !includedByFlag) { continue; }
      found.push(full);
    }
  }
  return found;
}

// --- Core scan loop -------------------------------------------------------
// Context-awareness helpers (isInsideComment / isInsideStringContent) live
// in ../scanContext and are shared with the VS Code extension analyzer so
// both the CLI and the extension see the same multi-line context (F11).

interface FileResult {
  filePath: string;
  relativePath: string;
  languageId: string;
  issues: SecurityIssue[];
}

function scanFile(
  filePath: string,
  text: string,
  rules: SecurityRule[]
): SecurityIssue[] {
  const lines = text.split('\n');
  const issues: SecurityIssue[] = [];

  // F11: pre-compute per-line context state so multi-line template literals
  // and block comments are recognised by contextAware rules.
  const lineStates = buildLineStates(text);

  // Mirror of src/analyzer.ts semantics: Informational rules are deferred —
  // we collect up to 10 candidate lines per rule, then pick one "best"
  // candidate after the file is fully scanned. Without this the CLI would
  // flood SARIF output with dozens of identical `Reminder` findings per file.
  const informationalFired = new Set<string>();
  const informationalCandidates = new Map<string, SecurityIssue[]>();

  const deadline = Date.now() + 3000;

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    if (lineNum % 25 === 0 && lineNum > 0 && Date.now() > deadline) { break; }
    const line = lines[lineNum];
    if (line.length > 2000) { continue; }
    const lineLower = line.toLowerCase();

    for (const rule of rules) {
      if (rule.ruleType === RuleType.ProjectAdvisory) { continue; }
      if (rule.ruleType === RuleType.Informational && informationalFired.has(rule.code)) {
        const existing = informationalCandidates.get(rule.code);
        if (existing && existing.length >= 10) { continue; }
      }

      if (rule.filePatterns) {
        if (rule.filePatterns.include && !rule.filePatterns.include.some(p => p.test(filePath))) { continue; }
        if (rule.filePatterns.exclude && rule.filePatterns.exclude.some(p => p.test(filePath))) { continue; }
      }

      for (const pattern of rule.patterns) {
        let matched = false, column = 0, matchText = '';
        try {
          if (typeof pattern === 'string') {
            const pLower = pattern.toLowerCase();
            if (lineLower.includes(pLower)) {
              matched = true;
              column = lineLower.indexOf(pLower);
              matchText = pattern;
            }
          } else if (pattern instanceof RegExp) {
            const m = pattern.exec(line);
            if (m) { matched = true; column = m.index; matchText = m[0]; }
          }
        } catch {
          continue;
        }
        if (!matched) { continue; }

        if (rule.contextAware) {
          const ls = lineStates[lineNum];
          if (isInsideComment(line, column, ls) || isInsideStringContent(line, column, ls)) { continue; }
        }

        if (rule.negativePatterns) {
          let negated = false;
          for (const neg of rule.negativePatterns) {
            if (typeof neg === 'string') {
              if (lineLower.includes(neg.toLowerCase())) { negated = true; break; }
            } else if (neg instanceof RegExp) {
              if (neg.test(line)) { negated = true; break; }
            }
          }
          if (negated) { continue; }
        }

        if (rule.suppressIfNearby) {
          let suppressed = false;
          const s = Math.max(0, lineNum - 3);
          const e = Math.min(lines.length - 1, lineNum + 3);
          for (let j = s; j <= e && !suppressed; j++) {
            for (const sp of rule.suppressIfNearby) {
              if (sp.test(lines[j])) { suppressed = true; break; }
            }
          }
          if (suppressed) { continue; }
        }

        let effectiveSev = rule.severity;
        if (rule.filePatterns?.reduceSeverityIn && rule.filePatterns.reduceSeverityIn.some(p => p.test(filePath))) {
          effectiveSev = SecuritySeverity.Info;
        }

        const issue: SecurityIssue = {
          line: lineNum,
          column,
          message: rule.message,
          severity: effectiveSev,
          suggestion: rule.suggestion,
          code: rule.code,
          pattern: matchText,
          category: rule.category,
        };

        if (rule.ruleType === RuleType.Informational) {
          if (!informationalCandidates.has(rule.code)) {
            informationalCandidates.set(rule.code, []);
          }
          informationalCandidates.get(rule.code)!.push(issue);
          informationalFired.add(rule.code);
        } else {
          issues.push(issue);
        }
        break; // one match per rule per line
      }
    }
  }

  // Phase 3 (v9.5.0): intra-file taint pass. Bounded to 100 ms / file.
  try {
    const taintFindings = runTaintAnalysis(text, 100);
    for (const t of taintFindings) {
      issues.push(t);
    }
  } catch {
    // Don't let taint failures hide regular findings.
  }

  // For each Informational rule, keep at most one issue per file — prefer
  // lines inside function bodies over imports/declarations (same heuristic
  // as the extension's analyzer).
  for (const candidates of informationalCandidates.values()) {
    if (candidates.length === 0) { continue; }
    issues.push(pickBestInformationalCandidate(candidates, lines));
  }

  return issues;
}

function pickBestInformationalCandidate(candidates: SecurityIssue[], lines: string[]): SecurityIssue {
  if (candidates.length === 1) { return candidates[0]; }
  const DECL = /^\s*(?:import\s|export\s(?:type|interface|default)|const\s|let\s|var\s|type\s|interface\s|class\s)/;
  const FN_BODY = /(?:function\s|=>\s*\{|\.(?:then|catch|map|forEach|filter|reduce)\s*\()/;
  let best = candidates[0];
  let bestScore = -1;
  for (const c of candidates) {
    const line = lines[c.line] || '';
    let score = 1;
    if (DECL.test(line)) { score = 0; }
    if (FN_BODY.test(line)) { score += 2; }
    if (/\w+\s*\(/.test(line) && !DECL.test(line)) { score += 1; }
    if (score > bestScore) { bestScore = score; best = c; }
  }
  return best;
}

// --- Output formatters ----------------------------------------------------

function toSARIF(results: FileResult[], toolVersion: string): string {
  const rulesMap = new Map<string, { id: string; category: string; message: string; suggestion: string }>();
  const sarifResults: any[] = [];

  for (const r of results) {
    for (const issue of r.issues) {
      if (!rulesMap.has(issue.code)) {
        rulesMap.set(issue.code, {
          id: issue.code,
          category: CATEGORY_LABELS[issue.category] || issue.category,
          message: issue.message,
          suggestion: issue.suggestion,
        });
      }
      let level: string;
      switch (issue.severity) {
        case SecuritySeverity.Error: level = 'error'; break;
        case SecuritySeverity.Warning: level = 'warning'; break;
        default: level = 'note';
      }
      sarifResults.push({
        ruleId: issue.code,
        ruleIndex: Array.from(rulesMap.keys()).indexOf(issue.code),
        level,
        message: { text: `${issue.message}\n\nSuggestion: ${issue.suggestion}` },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: r.relativePath.replace(/\\/g, '/'),
              uriBaseId: '%SRCROOT%',
            },
            region: { startLine: issue.line + 1, startColumn: issue.column + 1 },
          },
        }],
      });
    }
  }

  const sarifRules = Array.from(rulesMap.values()).map(rule => ({
    id: rule.id,
    shortDescription: { text: rule.message },
    fullDescription: { text: rule.suggestion },
    properties: { category: rule.category },
  }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Caspian Security',
          version: toolVersion,
          informationUri: 'https://marketplace.visualstudio.com/items?itemName=CaspianTools.caspian-security',
          rules: sarifRules,
        },
      },
      results: sarifResults,
    }],
  }, null, 2);
}

function toJSONOutput(results: FileResult[]): string {
  const issues = results.flatMap(r =>
    r.issues.map(issue => ({
      file: r.relativePath,
      line: issue.line + 1,
      column: issue.column + 1,
      severity: SEVERITY_LABELS[issue.severity],
      code: issue.code,
      category: CATEGORY_LABELS[issue.category],
      message: issue.message,
      suggestion: issue.suggestion,
      pattern: issue.pattern,
    }))
  );
  return JSON.stringify({ issues }, null, 2);
}

function toText(results: FileResult[]): string {
  const out: string[] = [];
  let total = 0;
  for (const r of results) {
    if (!r.issues.length) { continue; }
    total += r.issues.length;
    out.push(`--- ${r.relativePath} (${r.issues.length} issue(s)) ---`);
    for (const issue of r.issues) {
      out.push(`  [${SEVERITY_LABELS[issue.severity]}] ${issue.code} (Line ${issue.line + 1}): ${issue.message}`);
      out.push(`    Suggestion: ${issue.suggestion}`);
    }
    out.push('');
  }
  out.unshift(`Caspian Security CLI — ${total} finding(s) across ${results.filter(r => r.issues.length).length} file(s)`, '='.repeat(60), '');
  return out.join('\n');
}

// --- Entry point ----------------------------------------------------------

function resolveVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8'));
    return pkg.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function worstSeverity(results: FileResult[]): SecuritySeverity | null {
  let worst: SecuritySeverity | null = null;
  for (const r of results) {
    for (const issue of r.issues) {
      if (worst === null || issue.severity > worst) { worst = issue.severity; }
    }
  }
  return worst;
}

function meetsFailThreshold(worst: SecuritySeverity | null, failOn: CliOptions['failOn']): boolean {
  if (worst === null || failOn === 'never') { return false; }
  const thresholds: Record<Exclude<CliOptions['failOn'], 'never'>, SecuritySeverity> = {
    info: SecuritySeverity.Info,
    warning: SecuritySeverity.Warning,
    error: SecuritySeverity.Error,
  };
  return worst >= thresholds[failOn];
}

async function main(): Promise<void> {
  let opts: CliOptions;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err: any) {
    process.stderr.write(`caspian-scan: ${err.message}\n`);
    printHelp();
    process.exit(2);
  }

  const rules = getAllRules();
  const files = walkFiles(opts.workspace, opts.exclude, opts.include);

  const results: FileResult[] = [];
  let filesSkipped = 0;

  for (const fp of files) {
    let stat: fs.Stats;
    try {
      stat = fs.statSync(fp);
    } catch {
      continue;
    }
    if (opts.maxFileSize > 0 && stat.size > opts.maxFileSize) { filesSkipped++; continue; }

    let text: string;
    try {
      text = fs.readFileSync(fp, 'utf-8');
    } catch {
      continue;
    }

    if (isGeneratedFile(fp, text)) { filesSkipped++; continue; }

    const ext = path.extname(fp).slice(1).toLowerCase();
    const languageId = EXT_TO_LANGUAGE[ext] || ext;
    const relativePath = path.relative(opts.workspace, fp) || fp;

    const issues = scanFile(fp, text, rules);
    if (issues.length > 0) {
      results.push({ filePath: fp, relativePath, languageId, issues });
    }
  }

  // Summarise to stderr so piping --format=sarif works
  const totalIssues = results.reduce((n, r) => n + r.issues.length, 0);
  process.stderr.write(
    `caspian-scan: scanned ${files.length} file(s), ${filesSkipped} skipped, ${totalIssues} finding(s)\n`
  );

  let output: string;
  switch (opts.format) {
    case 'json': output = toJSONOutput(results); break;
    case 'text': output = toText(results); break;
    case 'sarif':
    default: output = toSARIF(results, resolveVersion());
  }

  if (opts.output) {
    fs.writeFileSync(opts.output, output, 'utf-8');
  } else {
    process.stdout.write(output + '\n');
  }

  process.exit(meetsFailThreshold(worstSeverity(results), opts.failOn) ? 1 : 0);
}

main().catch((err: Error) => {
  process.stderr.write(`caspian-scan: fatal — ${err.message}\n`);
  process.exit(2);
});
