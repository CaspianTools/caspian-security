import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadIgnoreFile, appendIgnoreEntry, isIgnored, IgnoreEntry } from '../caspianIgnore';

describe('caspianIgnore', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('loadIgnoreFile', () => {
    test('returns empty array when file does not exist', () => {
      const entries = loadIgnoreFile(tmpDir);
      expect(entries).toEqual([]);
    });

    test('parses basic entries', () => {
      const content = `# Comment\nCRED001 src/config.ts\nDB001 src/db.ts:42\n`;
      fs.writeFileSync(path.join(tmpDir, '.caspianignore'), content);
      const entries = loadIgnoreFile(tmpDir);
      expect(entries).toHaveLength(2);
      expect(entries[0]).toEqual({ ruleCode: 'CRED001', filePath: 'src/config.ts', line: undefined, reason: undefined });
      expect(entries[1]).toEqual({ ruleCode: 'DB001', filePath: 'src/db.ts', line: 42, reason: undefined });
    });

    test('parses entries with reasons', () => {
      const content = `CRED001 src/config.ts:10 # sanitized upstream\n`;
      fs.writeFileSync(path.join(tmpDir, '.caspianignore'), content);
      const entries = loadIgnoreFile(tmpDir);
      expect(entries).toHaveLength(1);
      expect(entries[0].reason).toBe('sanitized upstream');
      expect(entries[0].line).toBe(10);
    });

    test('skips comments and blank lines', () => {
      const content = `# This is a comment\n\n  \n# Another comment\nCRED001 src/a.ts\n`;
      fs.writeFileSync(path.join(tmpDir, '.caspianignore'), content);
      const entries = loadIgnoreFile(tmpDir);
      expect(entries).toHaveLength(1);
    });

    test('normalizes backslashes to forward slashes', () => {
      const content = `CRED001 src\\config\\secrets.ts\n`;
      fs.writeFileSync(path.join(tmpDir, '.caspianignore'), content);
      const entries = loadIgnoreFile(tmpDir);
      expect(entries[0].filePath).toBe('src/config/secrets.ts');
    });
  });

  describe('appendIgnoreEntry', () => {
    test('creates file with header when it does not exist', () => {
      appendIgnoreEntry(tmpDir, { ruleCode: 'XSS001', filePath: 'src/app.ts' });
      const content = fs.readFileSync(path.join(tmpDir, '.caspianignore'), 'utf-8');
      expect(content).toContain('# Caspian Security Ignore File');
      expect(content).toContain('XSS001 src/app.ts');
    });

    test('appends to existing file', () => {
      fs.writeFileSync(path.join(tmpDir, '.caspianignore'), 'CRED001 src/a.ts\n');
      appendIgnoreEntry(tmpDir, { ruleCode: 'XSS001', filePath: 'src/b.ts' });
      const entries = loadIgnoreFile(tmpDir);
      expect(entries).toHaveLength(2);
    });

    test('includes line number when provided', () => {
      appendIgnoreEntry(tmpDir, { ruleCode: 'DB001', filePath: 'src/db.ts', line: 42 });
      const content = fs.readFileSync(path.join(tmpDir, '.caspianignore'), 'utf-8');
      expect(content).toContain('DB001 src/db.ts:42');
    });

    test('includes reason when provided', () => {
      appendIgnoreEntry(tmpDir, { ruleCode: 'CRED001', filePath: 'src/a.ts', reason: 'sanitized' });
      const content = fs.readFileSync(path.join(tmpDir, '.caspianignore'), 'utf-8');
      expect(content).toContain('# sanitized');
    });
  });

  describe('isIgnored', () => {
    test('matches exact rule and file', () => {
      const entries: IgnoreEntry[] = [{ ruleCode: 'CRED001', filePath: 'src/config.ts' }];
      expect(isIgnored(entries, 'CRED001', 'src/config.ts')).toBe(true);
    });

    test('does not match different rule', () => {
      const entries: IgnoreEntry[] = [{ ruleCode: 'CRED001', filePath: 'src/config.ts' }];
      expect(isIgnored(entries, 'XSS001', 'src/config.ts')).toBe(false);
    });

    test('does not match different file', () => {
      const entries: IgnoreEntry[] = [{ ruleCode: 'CRED001', filePath: 'src/config.ts' }];
      expect(isIgnored(entries, 'CRED001', 'src/other.ts')).toBe(false);
    });

    test('matches specific line (0-based issue line vs 1-based entry line)', () => {
      const entries: IgnoreEntry[] = [{ ruleCode: 'CRED001', filePath: 'src/config.ts', line: 10 }];
      // issue line 9 (0-based) should match entry line 10 (1-based)
      expect(isIgnored(entries, 'CRED001', 'src/config.ts', 9)).toBe(true);
      expect(isIgnored(entries, 'CRED001', 'src/config.ts', 10)).toBe(false);
    });

    test('file-wide ignore matches any line', () => {
      const entries: IgnoreEntry[] = [{ ruleCode: 'CRED001', filePath: 'src/config.ts' }];
      expect(isIgnored(entries, 'CRED001', 'src/config.ts', 0)).toBe(true);
      expect(isIgnored(entries, 'CRED001', 'src/config.ts', 999)).toBe(true);
    });

    test('normalizes backslashes in path comparison', () => {
      const entries: IgnoreEntry[] = [{ ruleCode: 'CRED001', filePath: 'src/config.ts' }];
      expect(isIgnored(entries, 'CRED001', 'src\\config.ts')).toBe(true);
    });
  });
});
