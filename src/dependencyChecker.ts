import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { runOsvCheck, OsvCheckResult } from './osvScanner';

// ---- Interfaces ----

export interface OutdatedPackage {
  name: string;
  current: string;
  wanted: string;
  latest: string;
  type: 'dependencies' | 'devDependencies';
  updateType: 'patch' | 'minor' | 'major' | 'unknown';
}

export interface AuditVulnerability {
  name: string;
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical';
  title: string;
  url: string;
  range: string;
  fixAvailable: boolean;
}

export interface AuditSummary {
  totalVulnerabilities: number;
  bySeverity: Record<string, number>;
  vulnerabilities: AuditVulnerability[];
}

export interface StackVersionInfo {
  component: string;
  currentVersion: string;
  latestVersion: string | null;
  isOutdated: boolean;
  updateType: 'patch' | 'minor' | 'major' | 'unknown' | 'up-to-date';
}

export interface DependencyCheckResult {
  outdatedPackages: OutdatedPackage[];
  auditSummary: AuditSummary;
  stackVersions: StackVersionInfo[];
  /** Present when the opt-in OSV.dev multi-ecosystem check ran. */
  osv?: OsvCheckResult;
  checkedAt: Date;
  projectPath: string;
  errors: string[];
}

export interface DependencyCheckOptions {
  /**
   * Opt-in: also check non-npm manifests (requirements.txt, go.mod,
   * Cargo.lock/Cargo.toml, pom.xml, Gemfile.lock, composer.lock) against the
   * OSV.dev API. Sends dependency names and versions — never code — to
   * api.osv.dev.
   */
  includeOsv?: boolean;
}

// ---- Utilities ----

function parseSemver(v: string): [number, number, number] | null {
  const match = v.replace(/^[v^~>=<\s]*/, '').match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) { return null; }
  return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])];
}

export function computeUpdateType(current: string, latest: string): 'patch' | 'minor' | 'major' | 'unknown' {
  const c = parseSemver(current);
  const l = parseSemver(latest);
  if (!c || !l) { return 'unknown'; }
  if (c[0] !== l[0]) { return 'major'; }
  if (c[1] !== l[1]) { return 'minor'; }
  if (c[2] !== l[2]) { return 'patch'; }
  return 'unknown';
}

function execCommand(command: string, cwd: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    exec(command, { cwd, timeout: 30000, encoding: 'utf-8' }, (error, stdout, stderr) => {
      // npm outdated and npm audit return non-zero exit codes when findings exist.
      // We still want the stdout in those cases.
      const out = stdout || (error as any)?.stdout || '';
      const err = stderr || (error as any)?.stderr || '';
      resolve({ stdout: out, stderr: err });
    });
  });
}

// ---- Check Functions ----

async function runNpmOutdated(projectPath: string): Promise<{ packages: OutdatedPackage[]; error?: string }> {
  const { stdout } = await execCommand('npm outdated --json', projectPath);

  if (!stdout.trim()) {
    return { packages: [] };
  }

  try {
    const parsed = JSON.parse(stdout);
    const packages: OutdatedPackage[] = Object.entries(parsed).map(([name, info]: [string, any]) => ({
      name,
      current: info.current || 'N/A',
      wanted: info.wanted || 'N/A',
      latest: info.latest || 'N/A',
      type: (info.type === 'devDependencies' ? 'devDependencies' : 'dependencies') as 'dependencies' | 'devDependencies',
      updateType: computeUpdateType(info.current || '', info.latest || ''),
    }));
    return { packages };
  } catch (parseError) {
    return { packages: [], error: `Failed to parse npm outdated output: ${parseError}` };
  }
}

async function runNpmAudit(projectPath: string): Promise<{ summary: AuditSummary; error?: string }> {
  const emptySummary: AuditSummary = { totalVulnerabilities: 0, bySeverity: {}, vulnerabilities: [] };
  const { stdout } = await execCommand('npm audit --json', projectPath);

  if (!stdout.trim()) {
    return { summary: emptySummary };
  }

  try {
    const parsed = JSON.parse(stdout);

    // npm v7+ uses auditReportVersion 2 with a `vulnerabilities` object
    if (parsed.vulnerabilities && typeof parsed.vulnerabilities === 'object') {
      const vulnerabilities: AuditVulnerability[] = [];
      const bySeverity: Record<string, number> = {};

      for (const [name, info] of Object.entries(parsed.vulnerabilities) as [string, any][]) {
        const severity = info.severity || 'info';
        bySeverity[severity] = (bySeverity[severity] || 0) + 1;

        // Extract title and url from the `via` array
        let title = '';
        let url = '';
        let range = info.range || '';
        if (Array.isArray(info.via)) {
          for (const v of info.via) {
            if (typeof v === 'object' && v.title) {
              title = v.title;
              url = v.url || '';
              if (v.range) { range = v.range; }
              break;
            }
          }
        }

        vulnerabilities.push({
          name,
          severity,
          title: title || `Vulnerability in ${name}`,
          url,
          range,
          fixAvailable: !!info.fixAvailable,
        });
      }

      const total = parsed.metadata?.vulnerabilities?.total
        || Object.values(bySeverity).reduce((a: number, b: number) => a + b, 0);

      return {
        summary: { totalVulnerabilities: total, bySeverity, vulnerabilities },
      };
    }

    // npm v6 format uses an `advisories` object
    if (parsed.advisories && typeof parsed.advisories === 'object') {
      const vulnerabilities: AuditVulnerability[] = [];
      const bySeverity: Record<string, number> = {};

      for (const [, advisory] of Object.entries(parsed.advisories) as [string, any][]) {
        const severity = advisory.severity || 'info';
        bySeverity[severity] = (bySeverity[severity] || 0) + 1;
        vulnerabilities.push({
          name: advisory.module_name || 'unknown',
          severity,
          title: advisory.title || '',
          url: advisory.url || '',
          range: advisory.vulnerable_versions || '',
          fixAvailable: !!advisory.patched_versions && advisory.patched_versions !== '<0.0.0',
        });
      }

      const total = parsed.metadata?.vulnerabilities?.total
        || Object.values(bySeverity).reduce((a: number, b: number) => a + b, 0);

      return {
        summary: { totalVulnerabilities: total, bySeverity, vulnerabilities },
      };
    }

    return { summary: emptySummary };
  } catch (parseError) {
    return { summary: emptySummary, error: `Failed to parse npm audit output: ${parseError}` };
  }
}

async function checkStackVersions(projectPath: string): Promise<{ versions: StackVersionInfo[]; errors: string[] }> {
  const versions: StackVersionInfo[] = [];
  const errors: string[] = [];

  // Check Node.js version
  try {
    const { stdout: nodeLocal } = await execCommand('node -v', projectPath);
    const currentNode = nodeLocal.trim().replace(/^v/, '');
    const { stdout: nodeLatest } = await execCommand('npm view node version', projectPath);
    const latestNode = nodeLatest.trim();
    const nodeUpdate = computeUpdateType(currentNode, latestNode);
    versions.push({
      component: 'Node.js',
      currentVersion: currentNode,
      latestVersion: latestNode || null,
      isOutdated: nodeUpdate !== 'unknown' || (!!latestNode && currentNode !== latestNode),
      updateType: nodeUpdate === 'unknown' && latestNode && currentNode !== latestNode ? 'major' : nodeUpdate === 'unknown' ? 'up-to-date' : nodeUpdate,
    });
  } catch (e) {
    errors.push(`Failed to check Node.js version: ${e}`);
  }

  // Check TypeScript version
  try {
    const pkgJsonPath = path.join(projectPath, 'package.json');
    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    const tsDeclared = pkgJson.devDependencies?.typescript || pkgJson.dependencies?.typescript || '';

    if (tsDeclared) {
      const currentTs = tsDeclared.replace(/^[^0-9]*/, '');
      const { stdout: tsLatest } = await execCommand('npm view typescript version', projectPath);
      const latestTs = tsLatest.trim();
      const tsUpdate = computeUpdateType(currentTs, latestTs);
      versions.push({
        component: 'TypeScript',
        currentVersion: currentTs,
        latestVersion: latestTs || null,
        isOutdated: tsUpdate !== 'unknown',
        updateType: tsUpdate === 'unknown' ? 'up-to-date' : tsUpdate,
      });
    }
  } catch (e) {
    errors.push(`Failed to check TypeScript version: ${e}`);
  }

  // Check VS Code engine version
  try {
    const pkgJsonPath = path.join(projectPath, 'package.json');
    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    const vscodeEngine = pkgJson.engines?.vscode || '';

    if (vscodeEngine) {
      const currentVscode = vscodeEngine.replace(/^[^0-9]*/, '');
      const { stdout: vscodeLatest } = await execCommand('npm view @types/vscode version', projectPath);
      const latestVscode = vscodeLatest.trim();
      const vscodeUpdate = computeUpdateType(currentVscode, latestVscode);
      versions.push({
        component: 'VS Code Engine',
        currentVersion: currentVscode,
        latestVersion: latestVscode || null,
        isOutdated: vscodeUpdate !== 'unknown',
        updateType: vscodeUpdate === 'unknown' ? 'up-to-date' : vscodeUpdate,
      });
    }
  } catch (e) {
    errors.push(`Failed to check VS Code engine version: ${e}`);
  }

  return { versions, errors };
}

// ---- Main Entry Point ----

export async function checkDependencies(
  projectPath: string,
  options: DependencyCheckOptions = {}
): Promise<DependencyCheckResult> {
  const errors: string[] = [];
  const hasPackageJson = fs.existsSync(path.join(projectPath, 'package.json'));

  // The OSV check covers non-npm ecosystems, so it runs regardless of package.json.
  const osvPromise: Promise<OsvCheckResult | undefined> = options.includeOsv
    ? runOsvCheck(projectPath)
    : Promise.resolve(undefined);

  if (!hasPackageJson) {
    const osv = await osvPromise;
    if (!osv) {
      errors.push('No package.json found in project directory');
    } else {
      errors.push('No package.json found — npm checks skipped (OSV.dev check still ran)');
      errors.push(...osv.errors);
    }
    return {
      outdatedPackages: [],
      auditSummary: { totalVulnerabilities: 0, bySeverity: {}, vulnerabilities: [] },
      stackVersions: [],
      osv,
      checkedAt: new Date(),
      projectPath,
      errors,
    };
  }

  // Run all checks concurrently
  const [outdatedResult, auditResult, stackResult, osvResult] = await Promise.all([
    runNpmOutdated(projectPath),
    runNpmAudit(projectPath),
    checkStackVersions(projectPath),
    osvPromise,
  ]);

  if (outdatedResult.error) { errors.push(outdatedResult.error); }
  if (auditResult.error) { errors.push(auditResult.error); }
  errors.push(...stackResult.errors);
  if (osvResult) { errors.push(...osvResult.errors); }

  return {
    outdatedPackages: outdatedResult.packages,
    auditSummary: auditResult.summary,
    stackVersions: stackResult.versions,
    osv: osvResult,
    checkedAt: new Date(),
    projectPath,
    errors,
  };
}

// ---- Text Formatter ----

export function formatResultsAsText(result: DependencyCheckResult): string {
  const lines: string[] = [];

  // Outdated packages
  lines.push(`OUTDATED PACKAGES (${result.outdatedPackages.length} found)`);
  lines.push('-'.repeat(50));
  if (result.outdatedPackages.length === 0) {
    lines.push('  All packages are up to date.');
  } else {
    for (const pkg of result.outdatedPackages) {
      const typeLabel = pkg.type === 'devDependencies' ? '  [devDependency]' : '';
      const padName = pkg.name.padEnd(25);
      const padCurrent = pkg.current.padEnd(10);
      const padLatest = pkg.latest.padEnd(10);
      lines.push(`  ${padName} ${padCurrent} -> ${padLatest} (${pkg.updateType})${typeLabel}`);
    }
  }
  lines.push('');

  // Security vulnerabilities
  lines.push(`SECURITY VULNERABILITIES (${result.auditSummary.totalVulnerabilities} found)`);
  lines.push('-'.repeat(50));
  if (result.auditSummary.vulnerabilities.length === 0) {
    lines.push('  No known vulnerabilities.');
  } else {
    for (const vuln of result.auditSummary.vulnerabilities) {
      lines.push(`  [${vuln.severity.toUpperCase()}] ${vuln.title || vuln.name}`);
      if (vuln.range) {
        lines.push(`    Affected: ${vuln.name} ${vuln.range}`);
      }
      lines.push(`    Fix available: ${vuln.fixAvailable ? 'Yes' : 'No'}`);
      if (vuln.url) {
        lines.push(`    Details: ${vuln.url}`);
      }
      lines.push('');
    }
  }
  lines.push('');

  // OSV.dev multi-ecosystem check (opt-in)
  if (result.osv) {
    lines.push(`OSV.DEV MULTI-ECOSYSTEM CHECK (${result.osv.vulnerabilities.length} found)`);
    lines.push('-'.repeat(50));
    if (result.osv.manifestsScanned.length === 0) {
      lines.push('  No supported manifests found (requirements.txt, go.mod, Cargo.lock/Cargo.toml, pom.xml, Gemfile.lock, composer.lock).');
    } else {
      lines.push(`  Manifests: ${result.osv.manifestsScanned.join(', ')} (${result.osv.packagesQueried} package(s) checked)`);
      if (result.osv.vulnerabilities.length === 0) {
        lines.push('  No known vulnerabilities.');
      } else {
        lines.push('');
        for (const vuln of result.osv.vulnerabilities) {
          lines.push(`  [${vuln.severity.toUpperCase()}] ${vuln.id} — ${vuln.packageName}@${vuln.packageVersion} (${vuln.ecosystem}, ${vuln.manifest})`);
          if (vuln.summary) {
            lines.push(`    ${vuln.summary}`);
          }
          lines.push(`    Fixed in: ${vuln.fixedVersion || 'no fix listed'}`);
          lines.push(`    Details: ${vuln.url}`);
          lines.push('');
        }
      }
    }
    lines.push('');
  }

  // Stack versions
  lines.push('STACK VERSIONS');
  lines.push('-'.repeat(50));
  if (result.stackVersions.length === 0) {
    lines.push('  No stack version info available.');
  } else {
    for (const sv of result.stackVersions) {
      const padComponent = sv.component.padEnd(18);
      const latestStr = sv.latestVersion ? `(latest: ${sv.latestVersion})` : '';
      const statusStr = sv.updateType === 'up-to-date' ? '[up to date]' : `[${sv.updateType} update available]`;
      lines.push(`  ${padComponent} ${sv.currentVersion.padEnd(12)} ${latestStr.padEnd(25)} ${statusStr}`);
    }
  }
  lines.push('');

  // Summary
  lines.push('SUMMARY');
  lines.push('-'.repeat(50));
  const majorCount = result.outdatedPackages.filter(p => p.updateType === 'major').length;
  const minorCount = result.outdatedPackages.filter(p => p.updateType === 'minor').length;
  const patchCount = result.outdatedPackages.filter(p => p.updateType === 'patch').length;

  lines.push(`  ${result.outdatedPackages.length} outdated package(s)${result.outdatedPackages.length > 0 ? ` (${majorCount} major, ${minorCount} minor, ${patchCount} patch)` : ''}`);
  lines.push(`  ${result.auditSummary.totalVulnerabilities} vulnerability(ies)${result.auditSummary.vulnerabilities.length > 0 ? ` (${Object.entries(result.auditSummary.bySeverity).map(([k, v]) => `${v} ${k}`).join(', ')})` : ''}`);

  if (result.osv) {
    lines.push(`  ${result.osv.vulnerabilities.length} OSV.dev advisory(ies) across ${result.osv.manifestsScanned.length} manifest(s)`);
  }

  const outdatedStack = result.stackVersions.filter(s => s.updateType !== 'up-to-date');
  lines.push(`  ${outdatedStack.length} stack component(s) with available updates`);

  // Errors
  if (result.errors.length > 0) {
    lines.push('');
    lines.push('ERRORS');
    lines.push('-'.repeat(50));
    for (const err of result.errors) {
      lines.push(`  ${err}`);
    }
  }

  return lines.join('\n');
}
