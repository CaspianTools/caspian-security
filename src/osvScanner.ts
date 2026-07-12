/**
 * OSV.dev multi-ecosystem dependency vulnerability scanner.
 *
 * Parses dependency manifests for non-npm ecosystems (PyPI, Go, crates.io,
 * Maven, RubyGems, Packagist) and checks the pinned versions against the
 * OSV.dev vulnerability database (https://osv.dev — Google/GitHub-backed,
 * aggregates the GitHub Advisory Database and more).
 *
 * Privacy: only dependency names, versions, and ecosystem labels are sent
 * to api.osv.dev — never source code. The check is opt-in everywhere it is
 * exposed (VS Code setting `caspianSecurity.osvCheck`, CLI flag `--osv`).
 *
 * No `vscode` imports here — this module is shared by the extension and CLI.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';

// ---- Types ----

export type OsvSeverity = 'critical' | 'high' | 'moderate' | 'low' | 'unknown';

export interface OsvPackageRef {
  name: string;
  version: string;
  /** OSV ecosystem identifier, e.g. 'PyPI', 'Go', 'crates.io', 'Maven', 'RubyGems', 'Packagist'. */
  ecosystem: string;
  /** Manifest file (relative to the project root) the package was read from. */
  manifest: string;
}

export interface OsvVulnerability {
  id: string;
  aliases: string[];
  summary: string;
  severity: OsvSeverity;
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  manifest: string;
  fixedVersion?: string;
  url: string;
}

export interface OsvCheckResult {
  manifestsScanned: string[];
  packagesQueried: number;
  vulnerabilities: OsvVulnerability[];
  errors: string[];
}

// ---- Manifest parsers (pure functions, unit-testable) ----

/** requirements.txt — only exact pins (`pkg==1.2.3`) are queryable. */
export function parseRequirementsTxt(content: string, manifest: string): OsvPackageRef[] {
  const refs: OsvPackageRef[] = [];
  for (const rawLine of content.split('\n')) {
    let line = rawLine.replace(/#.*$/, '').trim();
    if (!line || line.startsWith('-')) { continue; } // skip options like -r, -e, --hash
    line = line.split(';')[0].trim(); // strip environment markers
    const match = line.match(/^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][A-Za-z0-9.+!_-]*)$/);
    if (match) {
      refs.push({ name: match[1], version: match[2], ecosystem: 'PyPI', manifest });
    }
  }
  return refs;
}

/** go.mod — `require` directives, single-line and block form. Includes `// indirect` modules. */
export function parseGoMod(content: string, manifest: string): OsvPackageRef[] {
  const refs: OsvPackageRef[] = [];
  let inRequireBlock = false;
  for (const rawLine of content.split('\n')) {
    const line = rawLine.replace(/\/\/.*$/, '').trim();
    if (!line) { continue; }
    if (inRequireBlock) {
      if (line === ')') { inRequireBlock = false; continue; }
      const match = line.match(/^([^\s]+)\s+v([0-9][^\s]*)$/);
      if (match) {
        refs.push({ name: match[1], version: match[2], ecosystem: 'Go', manifest });
      }
      continue;
    }
    if (/^require\s*\($/.test(line)) { inRequireBlock = true; continue; }
    const single = line.match(/^require\s+([^\s]+)\s+v([0-9][^\s]*)$/);
    if (single) {
      refs.push({ name: single[1], version: single[2], ecosystem: 'Go', manifest });
    }
  }
  return refs;
}

/** Cargo.lock — exact resolved versions, preferred over Cargo.toml. */
export function parseCargoLock(content: string, manifest: string): OsvPackageRef[] {
  const refs: OsvPackageRef[] = [];
  const blocks = content.split(/\[\[package\]\]/).slice(1);
  for (const block of blocks) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m);
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m);
    if (name && version) {
      refs.push({ name: name[1], version: version[1], ecosystem: 'crates.io', manifest });
    }
  }
  return refs;
}

/**
 * Cargo.toml — fallback when no Cargo.lock exists. Requirement strings like
 * `^1.2.3` are approximated by their base version.
 */
export function parseCargoToml(content: string, manifest: string): OsvPackageRef[] {
  const refs: OsvPackageRef[] = [];
  const depSections = /^(?:workspace\.)?(?:dependencies|dev-dependencies|build-dependencies)$/;
  let inDeps = false;
  for (const rawLine of content.split('\n')) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) { continue; }
    const section = line.match(/^\[([^\]]+)\]$/);
    if (section) {
      inDeps = depSections.test(section[1]);
      continue;
    }
    if (!inDeps) { continue; }
    let match = line.match(/^([A-Za-z0-9._-]+)\s*=\s*"([^"]+)"$/);
    if (!match) {
      const inline = line.match(/^([A-Za-z0-9._-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)".*\}$/);
      if (inline) { match = inline; }
    }
    if (match) {
      const version = match[2].replace(/^[\^~=\s]+/, '');
      if (/^\d+(\.\d+){0,2}([.+-][A-Za-z0-9.]+)?$/.test(version)) {
        refs.push({ name: match[1], version, ecosystem: 'crates.io', manifest });
      }
    }
  }
  return refs;
}

/** pom.xml — literal `<version>` values plus simple `${property}` resolution. */
export function parsePomXml(content: string, manifest: string): OsvPackageRef[] {
  const refs: OsvPackageRef[] = [];

  const properties: Record<string, string> = {};
  const propsBlock = content.match(/<properties>([\s\S]*?)<\/properties>/);
  if (propsBlock) {
    const propRegex = /<([A-Za-z0-9._-]+)>([^<]+)<\/\1>/g;
    let propMatch: RegExpExecArray | null;
    while ((propMatch = propRegex.exec(propsBlock[1])) !== null) {
      properties[propMatch[1]] = propMatch[2].trim();
    }
  }

  const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
  let depMatch: RegExpExecArray | null;
  while ((depMatch = depRegex.exec(content)) !== null) {
    const block = depMatch[1];
    const groupId = block.match(/<groupId>([^<]+)<\/groupId>/);
    const artifactId = block.match(/<artifactId>([^<]+)<\/artifactId>/);
    const versionTag = block.match(/<version>([^<]+)<\/version>/);
    if (!groupId || !artifactId || !versionTag) { continue; }
    let version = versionTag[1].trim();
    const propRef = version.match(/^\$\{([^}]+)\}$/);
    if (propRef) {
      const resolved = properties[propRef[1]];
      if (!resolved) { continue; }
      version = resolved;
    }
    if (!/^\d/.test(version)) { continue; }
    refs.push({
      name: `${groupId[1].trim()}:${artifactId[1].trim()}`,
      version,
      ecosystem: 'Maven',
      manifest,
    });
  }
  return refs;
}

/** Gemfile.lock — resolved gem versions from the GEM specs section. */
export function parseGemfileLock(content: string, manifest: string): OsvPackageRef[] {
  const refs: OsvPackageRef[] = [];
  let inGemSection = false;
  let inSpecs = false;
  for (const line of content.split('\n')) {
    if (/^[A-Z]/.test(line)) {
      inGemSection = line.trim() === 'GEM';
      inSpecs = false;
      continue;
    }
    if (inGemSection && line.trim() === 'specs:') { inSpecs = true; continue; }
    if (!inSpecs) { continue; }
    // Exactly four spaces of indent = a resolved gem; deeper indent = its dependencies.
    const match = line.match(/^    ([A-Za-z0-9._-]+) \(([0-9][A-Za-z0-9.]*)/);
    if (match) {
      refs.push({ name: match[1], version: match[2], ecosystem: 'RubyGems', manifest });
    }
  }
  return refs;
}

/** composer.lock — resolved PHP package versions. */
export function parseComposerLock(content: string, manifest: string): OsvPackageRef[] {
  const refs: OsvPackageRef[] = [];
  try {
    const parsed = JSON.parse(content);
    for (const group of [parsed.packages, parsed['packages-dev']]) {
      if (!Array.isArray(group)) { continue; }
      for (const pkg of group) {
        if (typeof pkg?.name === 'string' && typeof pkg?.version === 'string') {
          refs.push({
            name: pkg.name,
            version: pkg.version.replace(/^v/, ''),
            ecosystem: 'Packagist',
            manifest,
          });
        }
      }
    }
  } catch {
    // Malformed JSON — caller reports the manifest as unparseable.
  }
  return refs;
}

// ---- Manifest discovery ----

interface ManifestSpec {
  file: string;
  parse: (content: string, manifest: string) => OsvPackageRef[];
  /** If set, skip this manifest when the named sibling file exists (lockfile preferred). */
  skipIfPresent?: string;
}

const MANIFESTS: ManifestSpec[] = [
  { file: 'requirements.txt', parse: parseRequirementsTxt },
  { file: 'go.mod', parse: parseGoMod },
  { file: 'Cargo.lock', parse: parseCargoLock },
  { file: 'Cargo.toml', parse: parseCargoToml, skipIfPresent: 'Cargo.lock' },
  { file: 'pom.xml', parse: parsePomXml },
  { file: 'Gemfile.lock', parse: parseGemfileLock },
  { file: 'composer.lock', parse: parseComposerLock },
];

/** Discover and parse supported manifests in the project root. */
export function collectOsvPackages(projectPath: string): {
  packages: OsvPackageRef[];
  manifests: string[];
  errors: string[];
} {
  const packages: OsvPackageRef[] = [];
  const manifests: string[] = [];
  const errors: string[] = [];

  for (const spec of MANIFESTS) {
    const filePath = path.join(projectPath, spec.file);
    if (!fs.existsSync(filePath)) { continue; }
    if (spec.skipIfPresent && fs.existsSync(path.join(projectPath, spec.skipIfPresent))) { continue; }
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const refs = spec.parse(content, spec.file);
      manifests.push(spec.file);
      packages.push(...refs);
    } catch (e) {
      errors.push(`Failed to read ${spec.file}: ${e}`);
    }
  }

  // Dedupe identical name@version per ecosystem.
  const seen = new Set<string>();
  const deduped = packages.filter(p => {
    const key = `${p.ecosystem}|${p.name}|${p.version}`;
    if (seen.has(key)) { return false; }
    seen.add(key);
    return true;
  });

  return { packages: deduped, manifests, errors };
}

// ---- OSV record helpers (unit-testable) ----

/** Extract a normalized severity from a raw OSV vulnerability record. */
export function severityFromOsvRecord(record: any): OsvSeverity {
  const dbSeverity = (record?.database_specific?.severity || '').toString().toUpperCase();
  switch (dbSeverity) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MODERATE':
    case 'MEDIUM': return 'moderate';
    case 'LOW': return 'low';
  }
  // Fall back to a coarse read of the CVSS vector when present.
  const cvss = Array.isArray(record?.severity)
    ? record.severity.find((s: any) => typeof s?.score === 'string' && s.score.startsWith('CVSS:'))
    : undefined;
  if (cvss) {
    // No numeric base score in OSV vectors; approximate from impact metrics.
    const vector: string = cvss.score;
    const highImpact = /\/(C|I|A):H/.test(vector);
    const networkVector = /AV:N/.test(vector);
    if (highImpact && networkVector) { return 'high'; }
    if (highImpact || networkVector) { return 'moderate'; }
    return 'low';
  }
  return 'unknown';
}

/** Extract the first fixed version for a package from a raw OSV record. */
export function extractFixedVersion(record: any, packageName: string, ecosystem: string): string | undefined {
  if (!Array.isArray(record?.affected)) { return undefined; }
  for (const affected of record.affected) {
    if (affected?.package?.name !== packageName || affected?.package?.ecosystem !== ecosystem) { continue; }
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (typeof event?.fixed === 'string') { return event.fixed; }
      }
    }
  }
  return undefined;
}

// ---- OSV API client ----

const OSV_HOST = 'api.osv.dev';
const QUERY_BATCH_SIZE = 500;
const MAX_DETAIL_FETCHES = 60;
const DETAIL_CONCURRENCY = 8;
const REQUEST_TIMEOUT_MS = 15000;

function osvRequest(method: 'GET' | 'POST', apiPath: string, body?: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = https.request(
      {
        host: OSV_HOST,
        path: apiPath,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
        timeout: REQUEST_TIMEOUT_MS,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`OSV API ${method} ${apiPath} returned HTTP ${res.statusCode}`));
            return;
          }
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error(`OSV API returned invalid JSON: ${e}`));
          }
        });
      }
    );
    req.on('timeout', () => { req.destroy(new Error('OSV API request timed out')); });
    req.on('error', reject);
    if (payload) { req.write(payload); }
    req.end();
  });
}

interface VulnHit {
  id: string;
  pkg: OsvPackageRef;
}

async function queryBatch(packages: OsvPackageRef[]): Promise<VulnHit[]> {
  const hits: VulnHit[] = [];
  for (let offset = 0; offset < packages.length; offset += QUERY_BATCH_SIZE) {
    const chunk = packages.slice(offset, offset + QUERY_BATCH_SIZE);
    const body = {
      queries: chunk.map(p => ({
        package: { name: p.name, ecosystem: p.ecosystem },
        version: p.version,
      })),
    };
    const response = await osvRequest('POST', '/v1/querybatch', body);
    const results = Array.isArray(response?.results) ? response.results : [];
    for (let i = 0; i < chunk.length; i++) {
      const vulns = results[i]?.vulns;
      if (!Array.isArray(vulns)) { continue; }
      for (const vuln of vulns) {
        if (typeof vuln?.id === 'string') {
          hits.push({ id: vuln.id, pkg: chunk[i] });
        }
      }
    }
  }
  return hits;
}

async function fetchVulnDetails(ids: string[]): Promise<Map<string, any>> {
  const details = new Map<string, any>();
  for (let offset = 0; offset < ids.length; offset += DETAIL_CONCURRENCY) {
    const chunk = ids.slice(offset, offset + DETAIL_CONCURRENCY);
    const records = await Promise.all(
      chunk.map(id => osvRequest('GET', `/v1/vulns/${encodeURIComponent(id)}`).catch(() => undefined))
    );
    chunk.forEach((id, i) => {
      if (records[i]) { details.set(id, records[i]); }
    });
  }
  return details;
}

// ---- Main entry point ----

/**
 * Run the OSV.dev check against every supported manifest in the project root.
 * Network errors are captured in `errors` — the function never throws.
 */
export async function runOsvCheck(projectPath: string): Promise<OsvCheckResult> {
  const { packages, manifests, errors } = collectOsvPackages(projectPath);
  const result: OsvCheckResult = {
    manifestsScanned: manifests,
    packagesQueried: packages.length,
    vulnerabilities: [],
    errors,
  };
  if (packages.length === 0) { return result; }

  let hits: VulnHit[];
  try {
    hits = await queryBatch(packages);
  } catch (e: any) {
    result.errors.push(`OSV.dev query failed: ${e?.message || e}`);
    return result;
  }
  if (hits.length === 0) { return result; }

  const uniqueIds = Array.from(new Set(hits.map(h => h.id)));
  const cappedIds = uniqueIds.slice(0, MAX_DETAIL_FETCHES);
  if (uniqueIds.length > cappedIds.length) {
    result.errors.push(
      `OSV.dev returned ${uniqueIds.length} advisories; detail lookup capped at ${MAX_DETAIL_FETCHES}. ` +
      'Remaining advisories are listed without summaries.'
    );
  }
  const details = await fetchVulnDetails(cappedIds);

  for (const hit of hits) {
    const record = details.get(hit.id);
    result.vulnerabilities.push({
      id: hit.id,
      aliases: Array.isArray(record?.aliases) ? record.aliases : [],
      summary: record?.summary || record?.details?.split('\n')[0] || `Known vulnerability in ${hit.pkg.name}`,
      severity: record ? severityFromOsvRecord(record) : 'unknown',
      packageName: hit.pkg.name,
      packageVersion: hit.pkg.version,
      ecosystem: hit.pkg.ecosystem,
      manifest: hit.pkg.manifest,
      fixedVersion: record ? extractFixedVersion(record, hit.pkg.name, hit.pkg.ecosystem) : undefined,
      url: `https://osv.dev/vulnerability/${hit.id}`,
    });
  }

  const severityRank: Record<OsvSeverity, number> = { critical: 0, high: 1, moderate: 2, low: 3, unknown: 4 };
  result.vulnerabilities.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
  return result;
}
