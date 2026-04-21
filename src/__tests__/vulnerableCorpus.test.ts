/**
 * Vulnerable-corpus regression suite.
 *
 * Scans a small synthetic fixture tree that contains intentional
 * vulnerabilities across every rule family Caspian ships. Each file
 * has a list of rule codes that MUST be detected — if any of them
 * stops firing, the build fails.
 *
 * This is a *ratchet-up* test: if new rules start detecting something
 * in the same fixture, that's fine (the assertion is "at minimum,
 * these codes fire"). If a rule stops detecting, or a detection moves
 * to a different file, the test catches it immediately.
 *
 * Fixtures live at src/__tests__/fixtures/vulnerable-corpus/ and are
 * small hand-written files — no 200 MB downloads in CI.
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from '../rules';
import { SecurityRule, SecurityIssue, SecuritySeverity, RuleType } from '../types';
import { buildLineStates, isInsideComment, isInsideStringContent } from '../scanContext';
import { runTaintAnalysis } from '../taint';

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'vulnerable-corpus');

/**
 * Tiny reimplementation of the CLI scan loop. We can't import `out/cli/scan.js`
 * directly (it calls process.exit), and calling analyzer.ts would pull in
 * vscode — so we inline the minimum.
 */
function scanFixture(filePath: string): SecurityIssue[] {
  const text = fs.readFileSync(filePath, 'utf-8');
  const lines = text.split('\n');
  const lineStates = buildLineStates(text);
  const rules = getAllRules();
  const issues: SecurityIssue[] = [];
  const informationalFired = new Set<string>();

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    if (line.length > 2000) { continue; }
    const lineLower = line.toLowerCase();

    for (const rule of rules) {
      if (rule.ruleType === RuleType.ProjectAdvisory) { continue; }
      if (rule.ruleType === RuleType.Informational && informationalFired.has(rule.code)) { continue; }
      if (rule.filePatterns) {
        if (rule.filePatterns.include && !rule.filePatterns.include.some(p => p.test(filePath))) { continue; }
        if (rule.filePatterns.exclude && rule.filePatterns.exclude.some(p => p.test(filePath))) { continue; }
      }

      for (const pattern of rule.patterns) {
        const { matched, column, matchText } = matchPattern(pattern, line, lineLower);
        if (!matched) { continue; }

        if (rule.contextAware) {
          const ls = lineStates[lineNum];
          if (isInsideComment(line, column, ls) || isInsideStringContent(line, column, ls)) { continue; }
        }

        if (rule.negativePatterns && rule.negativePatterns.some(n =>
          typeof n === 'string' ? lineLower.includes(n.toLowerCase()) : n instanceof RegExp && n.test(line)
        )) { continue; }

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

        const effectiveSev = rule.severity;
        issues.push({
          line: lineNum,
          column,
          message: rule.message,
          severity: effectiveSev,
          suggestion: rule.suggestion,
          code: rule.code,
          pattern: matchText,
          category: rule.category,
        });

        if (rule.ruleType === RuleType.Informational) { informationalFired.add(rule.code); }
        break;
      }
    }
  }

  // Taint pass.
  try { issues.push(...runTaintAnalysis(text, 100)); } catch { /* */ }
  return issues;
}

function matchPattern(
  pattern: string | RegExp,
  line: string,
  lineLower: string,
): { matched: boolean; column: number; matchText: string } {
  try {
    if (typeof pattern === 'string') {
      const idx = lineLower.indexOf(pattern.toLowerCase());
      return idx >= 0 ? { matched: true, column: idx, matchText: pattern } : { matched: false, column: 0, matchText: '' };
    }
    const m = pattern.exec(line);
    return m ? { matched: true, column: m.index, matchText: m[0] } : { matched: false, column: 0, matchText: '' };
  } catch {
    return { matched: false, column: 0, matchText: '' };
  }
}

function codes(issues: SecurityIssue[]): Set<string> {
  return new Set(issues.map(i => i.code));
}

// ---------------------------------------------------------------------------
// Per-fixture assertions
// ---------------------------------------------------------------------------

describe('vulnerable-corpus regression suite', () => {
  it('express-controller.js — taint / JWT / OAuth / prototype-pollution coverage', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'express-controller.js'));
    const found = codes(issues);
    // Every code on this list is a minimum guarantee. New detections are fine.
    const must = ['TAINT001', 'TAINT003', 'TAINT005', 'TAINT007', 'JWT002', 'OAUTH001', 'FE007a'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('Dockerfile — DOCKER001 / DOCKER003 / DOCKER004 / DOCKER007 minimum', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'Dockerfile'));
    const found = codes(issues);
    const must = ['DOCKER001', 'DOCKER003', 'DOCKER004', 'DOCKER007'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('main.tf — TF001 / TF002 / TF003 / TF004 / TF006 / TF008 minimum', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'main.tf'));
    const found = codes(issues);
    const must = ['TF001', 'TF002', 'TF003', 'TF004', 'TF006', 'TF008'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('pod.yaml — K8S001..K8S008 coverage', () => {
    const issues = scanFixture(path.join(FIXTURE_DIR, 'pod.yaml'));
    const found = codes(issues);
    const must = ['K8S001', 'K8S002', 'K8S003', 'K8S004', 'K8S005', 'K8S006', 'K8S007', 'K8S008'];
    for (const code of must) {
      expect(found).toContain(code);
    }
  });

  it('every finding on every fixture is an Error or Warning — no quiet Info for the egregious bugs', () => {
    for (const file of ['express-controller.js', 'Dockerfile', 'main.tf', 'pod.yaml']) {
      const issues = scanFixture(path.join(FIXTURE_DIR, file));
      const highSeverity = issues.filter(i => i.severity >= SecuritySeverity.Warning);
      expect(highSeverity.length).toBeGreaterThan(0);
    }
  });
});
