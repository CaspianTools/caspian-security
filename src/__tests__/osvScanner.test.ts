import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { EventEmitter } from 'events';
import * as https from 'https';
jest.mock('https', () => ({ request: jest.fn() }));
import {
  runOsvCheck,
  parseRequirementsTxt,
  parseGoMod,
  parseCargoLock,
  parseCargoToml,
  parsePomXml,
  parseGemfileLock,
  parseComposerLock,
  severityFromOsvRecord,
  extractFixedVersion,
} from '../osvScanner';

describe('osvScanner manifest parsers', () => {
  describe('parseRequirementsTxt', () => {
    it('parses exact pins and ignores everything else', () => {
      const content = [
        '# comment',
        'flask==2.0.1',
        'requests[security]==2.25.0  # inline comment',
        'django>=3.0',            // range — not queryable
        '-r other-requirements.txt',
        '--hash=sha256:abc',
        'uwsgi==2.0.20; sys_platform == "linux"',
        '',
      ].join('\n');
      const refs = parseRequirementsTxt(content, 'requirements.txt');
      expect(refs).toEqual([
        { name: 'flask', version: '2.0.1', ecosystem: 'PyPI', manifest: 'requirements.txt' },
        { name: 'requests', version: '2.25.0', ecosystem: 'PyPI', manifest: 'requirements.txt' },
        { name: 'uwsgi', version: '2.0.20', ecosystem: 'PyPI', manifest: 'requirements.txt' },
      ]);
    });
  });

  describe('parseGoMod', () => {
    it('parses block and single-line requires, strips v prefix', () => {
      const content = [
        'module example.com/myapp',
        '',
        'go 1.21',
        '',
        'require (',
        '\tgithub.com/gin-gonic/gin v1.9.0',
        '\tgolang.org/x/crypto v0.14.0 // indirect',
        ')',
        '',
        'require github.com/stretchr/testify v1.8.4',
        '',
        'replace example.com/old => example.com/new v1.0.0',
      ].join('\n');
      const refs = parseGoMod(content, 'go.mod');
      expect(refs).toEqual([
        { name: 'github.com/gin-gonic/gin', version: '1.9.0', ecosystem: 'Go', manifest: 'go.mod' },
        { name: 'golang.org/x/crypto', version: '0.14.0', ecosystem: 'Go', manifest: 'go.mod' },
        { name: 'github.com/stretchr/testify', version: '1.8.4', ecosystem: 'Go', manifest: 'go.mod' },
      ]);
    });
  });

  describe('parseCargoLock', () => {
    it('parses [[package]] blocks', () => {
      const content = [
        'version = 3',
        '',
        '[[package]]',
        'name = "serde"',
        'version = "1.0.190"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        '',
        '[[package]]',
        'name = "tokio"',
        'version = "1.33.0"',
      ].join('\n');
      const refs = parseCargoLock(content, 'Cargo.lock');
      expect(refs).toEqual([
        { name: 'serde', version: '1.0.190', ecosystem: 'crates.io', manifest: 'Cargo.lock' },
        { name: 'tokio', version: '1.33.0', ecosystem: 'crates.io', manifest: 'Cargo.lock' },
      ]);
    });
  });

  describe('parseCargoToml', () => {
    it('parses dependency sections and strips requirement operators', () => {
      const content = [
        '[package]',
        'name = "myapp"',
        'version = "0.1.0"',
        '',
        '[dependencies]',
        'serde = "^1.0.190"',
        'tokio = { version = "1.33.0", features = ["full"] }',
        'local-thing = { path = "../local" }',
        '',
        '[dev-dependencies]',
        'criterion = "0.5"',
      ].join('\n');
      const refs = parseCargoToml(content, 'Cargo.toml');
      expect(refs).toEqual([
        { name: 'serde', version: '1.0.190', ecosystem: 'crates.io', manifest: 'Cargo.toml' },
        { name: 'tokio', version: '1.33.0', ecosystem: 'crates.io', manifest: 'Cargo.toml' },
        { name: 'criterion', version: '0.5', ecosystem: 'crates.io', manifest: 'Cargo.toml' },
      ]);
    });

    it('does not pick up package metadata outside dependency sections', () => {
      const content = ['[package]', 'name = "myapp"', 'version = "0.1.0"'].join('\n');
      expect(parseCargoToml(content, 'Cargo.toml')).toEqual([]);
    });
  });

  describe('parsePomXml', () => {
    it('parses literal versions and resolves simple properties', () => {
      const content = `
<project>
  <properties>
    <jackson.version>2.15.2</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>\${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>no-version</artifactId>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>unresolved</artifactId>
      <version>\${missing.property}</version>
    </dependency>
  </dependencies>
</project>`;
      const refs = parsePomXml(content, 'pom.xml');
      expect(refs).toEqual([
        { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'Maven', manifest: 'pom.xml' },
        { name: 'com.fasterxml.jackson.core:jackson-databind', version: '2.15.2', ecosystem: 'Maven', manifest: 'pom.xml' },
      ]);
    });
  });

  describe('parseGemfileLock', () => {
    it('parses resolved gems, skipping nested dependency lines', () => {
      const content = [
        'GEM',
        '  remote: https://rubygems.org/',
        '  specs:',
        '    rails (7.0.4)',
        '      actionpack (= 7.0.4)',
        '    nokogiri (1.13.10)',
        '',
        'PLATFORMS',
        '  ruby',
      ].join('\n');
      const refs = parseGemfileLock(content, 'Gemfile.lock');
      expect(refs).toEqual([
        { name: 'rails', version: '7.0.4', ecosystem: 'RubyGems', manifest: 'Gemfile.lock' },
        { name: 'nokogiri', version: '1.13.10', ecosystem: 'RubyGems', manifest: 'Gemfile.lock' },
      ]);
    });
  });

  describe('parseComposerLock', () => {
    it('parses packages and packages-dev, stripping v prefix', () => {
      const content = JSON.stringify({
        packages: [{ name: 'symfony/http-kernel', version: 'v5.4.20' }],
        'packages-dev': [{ name: 'phpunit/phpunit', version: '9.6.3' }],
      });
      const refs = parseComposerLock(content, 'composer.lock');
      expect(refs).toEqual([
        { name: 'symfony/http-kernel', version: '5.4.20', ecosystem: 'Packagist', manifest: 'composer.lock' },
        { name: 'phpunit/phpunit', version: '9.6.3', ecosystem: 'Packagist', manifest: 'composer.lock' },
      ]);
    });

    it('returns empty on malformed JSON', () => {
      expect(parseComposerLock('{not json', 'composer.lock')).toEqual([]);
    });
  });
});

describe('osvScanner record helpers', () => {
  describe('severityFromOsvRecord', () => {
    it('prefers database_specific.severity', () => {
      expect(severityFromOsvRecord({ database_specific: { severity: 'CRITICAL' } })).toBe('critical');
      expect(severityFromOsvRecord({ database_specific: { severity: 'HIGH' } })).toBe('high');
      expect(severityFromOsvRecord({ database_specific: { severity: 'MODERATE' } })).toBe('moderate');
      expect(severityFromOsvRecord({ database_specific: { severity: 'LOW' } })).toBe('low');
    });

    it('approximates from a CVSS vector when database severity is missing', () => {
      const record = {
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      };
      expect(severityFromOsvRecord(record)).toBe('high');
    });

    it('returns unknown when nothing usable is present', () => {
      expect(severityFromOsvRecord({})).toBe('unknown');
      expect(severityFromOsvRecord(undefined)).toBe('unknown');
    });
  });

  describe('extractFixedVersion', () => {
    it('finds the fixed event for the matching package', () => {
      const record = {
        affected: [
          {
            package: { name: 'flask', ecosystem: 'PyPI' },
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.2.5' }] }],
          },
        ],
      };
      expect(extractFixedVersion(record, 'flask', 'PyPI')).toBe('2.2.5');
      expect(extractFixedVersion(record, 'django', 'PyPI')).toBeUndefined();
      expect(extractFixedVersion({}, 'flask', 'PyPI')).toBeUndefined();
    });
  });
});

describe('runOsvCheck end-to-end (mocked HTTPS)', () => {
  let tmpDir: string;

  /** Route table: "METHOD /path" → { status, body }. */
  function mockOsvApi(routes: Record<string, { status?: number; body: unknown }>): void {
    (https.request as jest.Mock).mockImplementation(((options: any, cb: any) => {
      const req: any = new EventEmitter();
      req.write = () => undefined;
      req.destroy = () => undefined;
      req.end = () => {
        const route = routes[`${options.method} ${options.path}`];
        const res: any = new EventEmitter();
        res.statusCode = route?.status ?? (route ? 200 : 404);
        process.nextTick(() => {
          cb(res);
          res.emit('data', JSON.stringify(route?.body ?? {}));
          res.emit('end');
        });
      };
      return req;
    }) as any);
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-test-'));
  });

  afterEach(() => {
    (https.request as jest.Mock).mockReset();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('assembles vulnerabilities from querybatch hits and detail records', async () => {
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==0.12\nrequests==2.31.0\n');
    mockOsvApi({
      'POST /v1/querybatch': {
        body: {
          results: [
            { vulns: [{ id: 'GHSA-562c-5r94-xh97', modified: '2023-01-01T00:00:00Z' }] },
            {}, // requests 2.31.0 — clean
          ],
        },
      },
      'GET /v1/vulns/GHSA-562c-5r94-xh97': {
        body: {
          id: 'GHSA-562c-5r94-xh97',
          summary: 'Flask vulnerable to possible disclosure of permanent session cookie',
          aliases: ['CVE-2019-1010083'],
          database_specific: { severity: 'HIGH' },
          affected: [
            {
              package: { name: 'flask', ecosystem: 'PyPI' },
              ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0' }] }],
            },
          ],
        },
      },
    });

    const result = await runOsvCheck(tmpDir);
    expect(result.manifestsScanned).toEqual(['requirements.txt']);
    expect(result.packagesQueried).toBe(2);
    expect(result.errors).toEqual([]);
    expect(result.vulnerabilities).toEqual([
      {
        id: 'GHSA-562c-5r94-xh97',
        aliases: ['CVE-2019-1010083'],
        summary: 'Flask vulnerable to possible disclosure of permanent session cookie',
        severity: 'high',
        packageName: 'flask',
        packageVersion: '0.12',
        ecosystem: 'PyPI',
        manifest: 'requirements.txt',
        fixedVersion: '1.0',
        url: 'https://osv.dev/vulnerability/GHSA-562c-5r94-xh97',
      },
    ]);
  });

  it('captures API failures as errors instead of throwing', async () => {
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==0.12\n');
    mockOsvApi({ 'POST /v1/querybatch': { status: 403, body: {} } });

    const result = await runOsvCheck(tmpDir);
    expect(result.vulnerabilities).toEqual([]);
    expect(result.errors.some(e => e.includes('OSV.dev query failed'))).toBe(true);
  });

  it('returns immediately when no supported manifests exist', async () => {
    const result = await runOsvCheck(tmpDir);
    expect(result.manifestsScanned).toEqual([]);
    expect(result.packagesQueried).toBe(0);
    expect(result.vulnerabilities).toEqual([]);
  });

  it('prefers Cargo.lock over Cargo.toml when both exist', async () => {
    fs.writeFileSync(path.join(tmpDir, 'Cargo.toml'), '[dependencies]\nserde = "^1.0.0"\n');
    fs.writeFileSync(
      path.join(tmpDir, 'Cargo.lock'),
      '[[package]]\nname = "serde"\nversion = "1.0.190"\n'
    );
    mockOsvApi({ 'POST /v1/querybatch': { body: { results: [{}] } } });

    const result = await runOsvCheck(tmpDir);
    expect(result.manifestsScanned).toEqual(['Cargo.lock']);
    expect(result.packagesQueried).toBe(1);
  });
});
