import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  buildBaseline,
  applyBaseline,
  loadBaseline,
  writeBaseline,
  normalisePath,
  Baseline,
} from '../baseline';
import { SecurityIssue, SecuritySeverity, SecurityCategory } from '../types';

function issue(partial: Partial<SecurityIssue & { filePath: string }>): SecurityIssue & { filePath: string } {
  return {
    filePath: 'src/a.js',
    line: 0,
    column: 0,
    code: 'XSS001',
    message: 'x',
    suggestion: 'y',
    severity: SecuritySeverity.Warning,
    category: SecurityCategory.InputValidationXSS,
    pattern: '',
    ...partial,
  };
}

describe('normalisePath', () => {
  it('folds Windows separators to POSIX', () => {
    expect(normalisePath('src\\foo\\bar.ts')).toBe('src/foo/bar.ts');
    expect(normalisePath('src/foo/bar.ts')).toBe('src/foo/bar.ts');
  });
});

describe('buildBaseline', () => {
  it('counts per (file, rule) pair', () => {
    const issues = [
      issue({ filePath: 'src/a.js', code: 'XSS001' }),
      issue({ filePath: 'src/a.js', code: 'XSS001' }),
      issue({ filePath: 'src/a.js', code: 'CRED001' }),
      issue({ filePath: 'src/b.js', code: 'XSS001' }),
    ];
    const baseline = buildBaseline(issues, '10.1.0');
    expect(baseline.counts['src/a.js']['XSS001']).toBe(2);
    expect(baseline.counts['src/a.js']['CRED001']).toBe(1);
    expect(baseline.counts['src/b.js']['XSS001']).toBe(1);
    expect(baseline.generatedBy).toMatch(/caspian-security 10\.1\.0/);
  });

  it('normalises Windows paths so the baseline is cross-platform', () => {
    const issues = [issue({ filePath: 'src\\a.js', code: 'XSS001' })];
    const baseline = buildBaseline(issues, '10.1.0');
    expect(baseline.counts['src/a.js']['XSS001']).toBe(1);
    expect(baseline.counts['src\\a.js']).toBeUndefined();
  });
});

describe('applyBaseline', () => {
  it('suppresses all current findings when the baseline count matches', () => {
    const baseline: Baseline = {
      version: 1, generatedAt: '', generatedBy: '',
      counts: { 'src/a.js': { 'XSS001': 2 } },
    };
    const result = applyBaseline(
      [
        issue({ filePath: 'src/a.js', code: 'XSS001' }),
        issue({ filePath: 'src/a.js', code: 'XSS001' }),
      ],
      baseline,
    );
    expect(result.baselined).toHaveLength(2);
    expect(result.newFindings).toHaveLength(0);
  });

  it('flags the excess beyond the baseline as new', () => {
    const baseline: Baseline = {
      version: 1, generatedAt: '', generatedBy: '',
      counts: { 'src/a.js': { 'XSS001': 1 } },
    };
    const result = applyBaseline(
      [
        issue({ filePath: 'src/a.js', code: 'XSS001', line: 10 }),
        issue({ filePath: 'src/a.js', code: 'XSS001', line: 20 }),
        issue({ filePath: 'src/a.js', code: 'XSS001', line: 30 }),
      ],
      baseline,
    );
    expect(result.baselined).toHaveLength(1);
    expect(result.newFindings).toHaveLength(2);
  });

  it('treats (file, rule) not in the baseline as all-new', () => {
    const baseline: Baseline = {
      version: 1, generatedAt: '', generatedBy: '',
      counts: { 'src/a.js': { 'XSS001': 5 } },
    };
    const result = applyBaseline(
      [
        // Same file, DIFFERENT rule — no budget, all new.
        issue({ filePath: 'src/a.js', code: 'CRED001' }),
        // Different file — no budget either.
        issue({ filePath: 'src/b.js', code: 'XSS001' }),
      ],
      baseline,
    );
    expect(result.baselined).toHaveLength(0);
    expect(result.newFindings).toHaveLength(2);
  });

  it('handles the case where the baseline over-counts (fix landed since baseline generated)', () => {
    const baseline: Baseline = {
      version: 1, generatedAt: '', generatedBy: '',
      counts: { 'src/a.js': { 'XSS001': 5 } },
    };
    const result = applyBaseline(
      [issue({ filePath: 'src/a.js', code: 'XSS001' })],
      baseline,
    );
    expect(result.baselined).toHaveLength(1);
    expect(result.newFindings).toHaveLength(0);
  });

  it('normalises path separators when matching', () => {
    const baseline: Baseline = {
      version: 1, generatedAt: '', generatedBy: '',
      counts: { 'src/a.js': { 'XSS001': 1 } },
    };
    const result = applyBaseline(
      [issue({ filePath: 'src\\a.js', code: 'XSS001' })],
      baseline,
    );
    expect(result.baselined).toHaveLength(1);
    expect(result.newFindings).toHaveLength(0);
  });
});

describe('writeBaseline + loadBaseline roundtrip', () => {
  it('survives a round trip with stable key ordering', () => {
    const tmp = path.join(os.tmpdir(), `caspian-baseline-test-${Date.now()}.json`);
    const baseline: Baseline = {
      version: 1,
      generatedAt: '2026-04-21T00:00:00Z',
      generatedBy: 'caspian-security 10.1.0',
      counts: {
        // Unsorted on input — writer should sort on disk.
        'src/z.js': { 'ZZZ': 1, 'AAA': 2 },
        'src/a.js': { 'XSS001': 3 },
      },
    };
    writeBaseline(tmp, baseline);
    const raw = fs.readFileSync(tmp, 'utf-8');
    // Files should appear in sorted order on disk.
    expect(raw.indexOf('src/a.js')).toBeLessThan(raw.indexOf('src/z.js'));
    // Rules within a file should also be sorted.
    expect(raw.indexOf('AAA')).toBeLessThan(raw.indexOf('ZZZ'));
    const reloaded = loadBaseline(tmp);
    expect(reloaded.counts['src/a.js']['XSS001']).toBe(3);
    expect(reloaded.counts['src/z.js']['AAA']).toBe(2);
    fs.unlinkSync(tmp);
  });
});

describe('loadBaseline error handling', () => {
  it('throws a clear error for a missing file', () => {
    expect(() => loadBaseline('/nonexistent/baseline.json')).toThrow(/not readable/);
  });

  it('throws a clear error for invalid JSON', () => {
    const tmp = path.join(os.tmpdir(), `caspian-bad-${Date.now()}.json`);
    fs.writeFileSync(tmp, 'not json', 'utf-8');
    expect(() => loadBaseline(tmp)).toThrow(/not valid JSON/);
    fs.unlinkSync(tmp);
  });

  it('throws a clear error for wrong-shape JSON', () => {
    const tmp = path.join(os.tmpdir(), `caspian-bad-${Date.now()}.json`);
    fs.writeFileSync(tmp, JSON.stringify({ version: 99 }), 'utf-8');
    expect(() => loadBaseline(tmp)).toThrow(/unsupported shape/);
    fs.unlinkSync(tmp);
  });
});
