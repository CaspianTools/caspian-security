import * as vscode from 'vscode';
import { SecurityRule, SecurityIssue, SecurityCategory, SecuritySeverity, RuleType, ProjectAdvisory } from './types';
import { getAllRules, getRulesByCategory, getRuleByCode as registryGetRuleByCode } from './rules';
import { classifyConfidence } from './confidenceAnalyzer';
import { AdaptiveConfidenceEngine } from './adaptiveConfidence';
import { CodebaseProfile } from './codebaseProfile';
import { isGeneratedFile } from './generatedFileDetector';
import { ConfigManager } from './configManager';
import { buildLineStates, isInsideComment, isInsideStringContent } from './scanContext';
import { runTaintAnalysis } from './taint';

export class SecurityAnalyzer {
  private allRules: SecurityRule[];
  private adaptiveConfidence: AdaptiveConfidenceEngine | undefined;
  private codebaseProfile: CodebaseProfile | undefined;

  constructor() {
    this.allRules = getAllRules();
  }

  setAdaptiveConfidence(engine: AdaptiveConfidenceEngine): void {
    this.adaptiveConfidence = engine;
  }

  setCodebaseProfile(profile: CodebaseProfile): void {
    this.codebaseProfile = profile;
  }

  async analyzeDocument(
    document: vscode.TextDocument,
    categories?: SecurityCategory[]
  ): Promise<SecurityIssue[]> {
    try {
      const rules = this.resolveRules(categories);
      const issues: SecurityIssue[] = [];
      const text = document.getText();
      const filePath = document.uri.fsPath;

      // Skip generated files if enabled (check BEFORE splitting into lines)
      const config = ConfigManager.getInstance();
      if (config.getSkipGeneratedFiles() && isGeneratedFile(filePath, text)) {
        return [];
      }

      // Skip files exceeding max size
      const maxFileSize = config.getMaxFileSize();
      if (maxFileSize > 0 && text.length > maxFileSize) {
        return [];
      }

      const lines = text.split('\n');
      const informationalFired = new Set<string>();
      const informationalCandidates = new Map<string, SecurityIssue[]>();
      // F11 (v9.5.0): one-pass pre-computation of per-line "is this inside a
      // multi-line string / block comment". Consumed below by contextAware
      // filtering so template literals that span hundreds of lines stop
      // confusing the scanner.
      const lineStates = buildLineStates(text);
      // Per-file budget: tightened from 10s → 3s. A healthy rule run completes
      // in <100ms on a large file; a pathological regex against adversarial
      // input is the only realistic way to approach this limit, so a shorter
      // budget bounds the ReDoS blast radius without affecting real scans.
      const deadline = Date.now() + 3000;

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        // Poll the deadline more frequently than before (every 25 lines vs
        // every 100) so a runaway regex on a single long line cannot push
        // us far past the budget.
        if (lineNum % 25 === 0 && lineNum > 0 && Date.now() > deadline) {
          break;
        }

        const line = lines[lineNum];

        // Skip extremely long lines (likely minified code). Dropped from 5000
        // → 2000 chars to bound per-line regex execution time; generated/
        // minified files are already excluded elsewhere, so this only kicks
        // in for true outliers.
        if (line.length > 2000) {
          continue;
        }

        const lineLower = line.toLowerCase();

        for (const rule of rules) {
          // Skip project advisories — they are handled at workspace scan level
          if (rule.ruleType === RuleType.ProjectAdvisory) {
            continue;
          }

          if (rule.ruleType === RuleType.Informational && informationalFired.has(rule.code)) {
            // Allow collecting up to 10 candidates for better line targeting
            const existing = informationalCandidates.get(rule.code);
            if (existing && existing.length >= 10) {
              continue;
            }
          }

          // File-pattern exclusion: skip if file doesn't match include or matches exclude
          if (rule.filePatterns) {
            if (rule.filePatterns.include && !rule.filePatterns.include.some(p => p.test(filePath))) {
              continue;
            }
            if (rule.filePatterns.exclude && rule.filePatterns.exclude.some(p => p.test(filePath))) {
              continue;
            }
          }

          for (const pattern of rule.patterns) {
            try {
              let matched = false;
              let column = 0;
              let matchText = '';

              if (typeof pattern === 'string') {
                const patternLower = pattern.toLowerCase();
                if (lineLower.includes(patternLower)) {
                  matched = true;
                  column = lineLower.indexOf(patternLower);
                  matchText = pattern;
                }
              } else if (pattern instanceof RegExp) {
                const match = pattern.exec(line);
                if (match) {
                  matched = true;
                  column = match.index;
                  matchText = match[0];
                }
              }

              if (!matched) {
                continue;
              }

              // Context-aware filtering: skip matches inside comments, strings, or JSX text.
              // F11: lineStates[lineNum] carries the comment/string state
              // inherited from the PREVIOUS line so multi-line template
              // literals / block comments are now handled correctly.
              if (rule.contextAware) {
                const ls = lineStates[lineNum];
                if (isInsideComment(line, column, ls) ||
                    isInsideStringContent(line, column, ls) ||
                    isInsideJSXText(line, column)) {
                  continue;
                }
              }

              // Negative patterns: skip if any negative pattern matches the line
              if (rule.negativePatterns) {
                let negated = false;
                for (const neg of rule.negativePatterns) {
                  if (typeof neg === 'string') {
                    if (lineLower.includes(neg.toLowerCase())) {
                      negated = true;
                      break;
                    }
                  } else if (neg instanceof RegExp) {
                    if (neg.test(line)) {
                      negated = true;
                      break;
                    }
                  }
                }
                if (negated) {
                  continue;
                }
              }

              // SuppressIfNearby: check surrounding lines (including current) for suppression patterns
              if (rule.suppressIfNearby) {
                let suppressed = false;
                const startLine = Math.max(0, lineNum - 3);
                const endLine = Math.min(lines.length - 1, lineNum + 3);
                for (let nearby = startLine; nearby <= endLine; nearby++) {
                  for (const suppressPattern of rule.suppressIfNearby) {
                    if (suppressPattern.test(lines[nearby])) {
                      suppressed = true;
                      break;
                    }
                  }
                  if (suppressed) { break; }
                }
                if (suppressed) {
                  continue;
                }
              }

              // Learned safe pattern suppression
              if (this.codebaseProfile &&
                  this.codebaseProfile.hasLearnedSuppression(rule.code, line, lines, lineNum)) {
                continue;
              }

              // Determine effective severity (file-pattern-based reduction)
              let effectiveSeverity = rule.severity;
              if (rule.filePatterns?.reduceSeverityIn) {
                if (rule.filePatterns.reduceSeverityIn.some(p => p.test(filePath))) {
                  effectiveSeverity = SecuritySeverity.Info;
                }
              }

              const confidenceLevel = this.adaptiveConfidence
                ? this.adaptiveConfidence.classify(
                    lines, lineNum, column, matchText, rule.code,
                    document.languageId, filePath
                  )
                : classifyConfidence(lines, lineNum, column, matchText, rule.code);

              const issue: SecurityIssue = {
                line: lineNum,
                column,
                message: rule.message,
                severity: effectiveSeverity,
                suggestion: rule.suggestion,
                code: rule.code,
                pattern: matchText,
                category: rule.category,
                confidenceLevel,
              };

              if (rule.ruleType === RuleType.Informational) {
                // Defer informational issues: collect candidates and pick the best line later
                if (!informationalCandidates.has(rule.code)) {
                  informationalCandidates.set(rule.code, []);
                }
                informationalCandidates.get(rule.code)!.push(issue);
                informationalFired.add(rule.code);
              } else {
                issues.push(issue);
              }

              break;
            } catch (e) {
              console.error('Error processing pattern:', e);
            }
          }
        }
      }

      // Phase 3 (v9.5.0): intra-file taint pass. Bounded budget so a
      // pathological file can't blow the per-file deadline. Off-switch via
      // `caspianSecurity.enableTaintTracking` setting.
      if (config.getEnableTaintTracking()) {
        try {
          const taintFindings = runTaintAnalysis(text, 100);
          for (const t of taintFindings) {
            issues.push(t);
          }
        } catch (e) {
          console.error('Taint analysis failed:', e);
        }
      }

      // For informational rules, pick the most relevant line (prefer function bodies over imports/declarations)
      for (const [, candidates] of informationalCandidates) {
        if (candidates.length === 0) { continue; }
        const best = pickBestInformationalCandidate(candidates, lines);
        issues.push(best);
      }

      return issues;
    } catch (error) {
      console.error('Error analyzing document:', error);
      return [];
    }
  }

  collectProjectAdvisories(
    document: vscode.TextDocument,
    categories?: SecurityCategory[]
  ): ProjectAdvisory[] {
    const rules = this.resolveRules(categories);
    const advisories: ProjectAdvisory[] = [];
    const text = document.getText();
    const lines = text.split('\n');
    const fired = new Set<string>();

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      const lineLower = line.toLowerCase();

      for (const rule of rules) {
        if (rule.ruleType !== RuleType.ProjectAdvisory) { continue; }
        if (fired.has(rule.code)) { continue; }

        for (const pattern of rule.patterns) {
          let matched = false;
          if (typeof pattern === 'string') {
            if (lineLower.includes(pattern.toLowerCase())) { matched = true; }
          } else if (pattern instanceof RegExp) {
            if (pattern.test(line)) { matched = true; }
          }

          if (matched) {
            advisories.push({
              code: rule.code,
              message: rule.message,
              suggestion: rule.suggestion,
              category: rule.category,
              triggeredBy: document.uri.fsPath,
            });
            fired.add(rule.code);
            break;
          }
        }
      }
    }

    return advisories;
  }

  getRuleByCode(code: string): SecurityRule | undefined {
    return registryGetRuleByCode(code);
  }

  private resolveRules(categories?: SecurityCategory[]): SecurityRule[] {
    if (!categories || categories.length === 0) {
      return this.allRules;
    }
    return categories.flatMap(cat => getRulesByCategory(cat));
  }
}

/**
 * Check if a match position falls inside JSX text content (between > and <).
 * This is a heuristic: we look for a preceding > (end of opening tag) with no
 * subsequent < before our column.
 */
function isInsideJSXText(line: string, column: number): boolean {
  const before = line.substring(0, column);

  // Find the last > before the match
  const lastClose = before.lastIndexOf('>');
  if (lastClose === -1) { return false; }

  // Check there's no < between that > and our column (would mean a new tag started)
  const afterClose = before.substring(lastClose + 1);
  if (afterClose.includes('<')) { return false; }

  // Check there's a < after the match (closing tag)
  const after = line.substring(column);
  if (after.includes('<')) { return true; }

  return false;
}

/**
 * For informational rules that fire once per file, pick the most relevant line
 * from collected candidates. Prefers lines inside function bodies over
 * imports, declarations, and type annotations.
 */
function pickBestInformationalCandidate(candidates: SecurityIssue[], lines: string[]): SecurityIssue {
  if (candidates.length === 1) { return candidates[0]; }

  const DECLARATION_PATTERN = /^\s*(?:import\s|export\s(?:type|interface|default)|const\s|let\s|var\s|type\s|interface\s|class\s)/;
  const FUNCTION_BODY_PATTERN = /(?:function\s|=>\s*\{|\.(?:then|catch|map|forEach|filter|reduce)\s*\()/;

  // Score each candidate: higher is better
  let bestScore = -1;
  let bestCandidate = candidates[0];

  for (const candidate of candidates) {
    const line = lines[candidate.line] || '';
    let score = 1; // base score

    // Penalize imports and declarations
    if (DECLARATION_PATTERN.test(line)) {
      score = 0;
    }

    // Boost lines that look like they're inside function bodies
    if (FUNCTION_BODY_PATTERN.test(line)) {
      score += 2;
    }

    // Boost lines with function calls (more likely to be executable code)
    if (/\w+\s*\(/.test(line) && !DECLARATION_PATTERN.test(line)) {
      score += 1;
    }

    if (score > bestScore) {
      bestScore = score;
      bestCandidate = candidate;
    }
  }

  return bestCandidate;
}
