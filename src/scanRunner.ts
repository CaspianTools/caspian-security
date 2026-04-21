/**
 * Workspace scan logic, extracted from src/cli/scan.ts so both the CLI
 * entry point and the MCP server share the same implementation. No I/O
 * concerns live here — that's the caller's job (writing SARIF, emitting
 * JSON to stdout, responding to an MCP tool-call, etc.).
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from './rules';
import {
  SecurityRule,
  SecurityIssue,
  SecuritySeverity,
  RuleType,
} from './types';
import { isGeneratedFile } from './generatedFileDetector';
import { buildLineStates, isInsideComment, isInsideStringContent } from './scanContext';
import { runTaintAnalysis } from './taint';

const DEFAULT_EXTENSIONS = new Set([
  'js', 'jsx', 'mjs', 'cjs',
  'ts', 'tsx',
  'py', 'java', 'cs', 'php', 'go', 'rs',
  'kt', 'kts',
  'yaml', 'yml',
  'tf', 'tfvars', 'hcl',
]);

const DEFAULT_FILENAMES = new Set([
  'Dockerfile', 'dockerfile', 'Containerfile',
]);

const EXT_TO_LANGUAGE: Record<string, string> = {
  js: 'javascript', jsx: 'javascriptreact', mjs: 'javascript', cjs: 'javascript',
  ts: 'typescript', tsx: 'typescriptreact',
  py: 'python',
  java: 'java', cs: 'csharp', php: 'php', go: 'go', rs: 'rust',
  kt: 'kotlin', kts: 'kotlin',
  yaml: 'yaml', yml: 'yaml',
  tf: 'terraform', tfvars: 'terraform', hcl: 'terraform',
};

const FILENAME_TO_LANGUAGE: Record<string, string> = {
  Dockerfile: 'dockerfile', dockerfile: 'dockerfile', Containerfile: 'dockerfile',
};

const DEFAULT_EXCLUDES = [
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', 'vendor', '__pycache__', 'target',
];

export interface RunScanOptions {
  workspace: string;
  include?: string[];
  exclude?: string[];
  maxFileSize?: number;
  runTaint?: boolean;
}

export interface FileResult {
  filePath: string;
  relativePath: string;
  languageId: string;
  issues: SecurityIssue[];
}

export interface RunScanResult {
  results: FileResult[];
  filesScanned: number;
  filesSkipped: number;
  totalIssues: number;
}

export function walkFiles(root: string, excludes: string[] = [], extraIncludes: string[] = []): string[] {
  const found: string[] = [];
  const skipSet = new Set(DEFAULT_EXCLUDES.concat(excludes));

  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
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
      const includedByName = DEFAULT_FILENAMES.has(ent.name);
      const includedByFlag = extraIncludes.some(tok => full.includes(tok));
      if (!includedByExt && !includedByName && !includedByFlag) { continue; }
      found.push(full);
    }
  }
  return found;
}

export function resolveLanguage(filePath: string): string {
  const base = path.basename(filePath);
  if (FILENAME_TO_LANGUAGE[base]) { return FILENAME_TO_LANGUAGE[base]; }
  const ext = path.extname(base).slice(1).toLowerCase();
  return EXT_TO_LANGUAGE[ext] || ext;
}

export function scanFile(filePath: string, text: string, rules: SecurityRule[], runTaint: boolean = true): SecurityIssue[] {
  const lines = text.split('\n');
  const issues: SecurityIssue[] = [];
  const lineStates = buildLineStates(text);
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
        break;
      }
    }
  }

  if (runTaint) {
    try {
      const taintFindings = runTaintAnalysis(text, 100);
      for (const t of taintFindings) { issues.push(t); }
    } catch { /* don't let taint failures hide regular findings */ }
  }

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

/**
 * Scan every eligible file under `options.workspace` and return the
 * results. I/O-free beyond fs.readFileSync on the files themselves —
 * the caller chooses how to present / persist the data.
 */
export function runWorkspaceScan(options: RunScanOptions): RunScanResult {
  const rules = getAllRules();
  const maxFileSize = options.maxFileSize ?? 500_000;
  const files = walkFiles(options.workspace, options.exclude || [], options.include || []);
  const results: FileResult[] = [];
  let filesSkipped = 0;

  for (const fp of files) {
    let stat: fs.Stats;
    try { stat = fs.statSync(fp); } catch { continue; }
    if (maxFileSize > 0 && stat.size > maxFileSize) { filesSkipped++; continue; }

    let text: string;
    try { text = fs.readFileSync(fp, 'utf-8'); } catch { continue; }

    if (isGeneratedFile(fp, text)) { filesSkipped++; continue; }

    const languageId = resolveLanguage(fp);
    const relativePath = path.relative(options.workspace, fp) || fp;
    const issues = scanFile(fp, text, rules, options.runTaint !== false);
    if (issues.length > 0) {
      results.push({ filePath: fp, relativePath, languageId, issues });
    }
  }

  const totalIssues = results.reduce((n, r) => n + r.issues.length, 0);
  return { results, filesScanned: files.length, filesSkipped, totalIssues };
}
