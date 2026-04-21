import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { getChangedFilesSince } from '../gitDiff';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

describe('getChangedFilesSince', () => {
  it('returns an empty set when diffing HEAD against itself', () => {
    // HEAD...HEAD is trivially empty — a useful invariant to pin down
    // because it proves the parse is working on a successful run.
    const result = getChangedFilesSince(REPO_ROOT, 'HEAD');
    expect(result.ref).toBe('HEAD');
    expect(result.diffCount).toBe(0);
    expect(result.files.size).toBe(0);
  });

  it('returns absolute paths when there is a diff', () => {
    // HEAD~1...HEAD — whatever the last commit touched. In a shallow clone
    // (actions/checkout default) HEAD~1 is unreachable — tolerate that by
    // skipping the assertion when the ref doesn't resolve.
    let result;
    try {
      result = getChangedFilesSince(REPO_ROOT, 'HEAD~1');
    } catch (err: any) {
      if (/unknown revision/.test(err.message) || /does not have any commits/.test(err.message)) {
        // Shallow clone on CI — acceptable skip.
        return;
      }
      throw err;
    }
    expect(result.files.size).toBeGreaterThanOrEqual(0);
    for (const f of result.files) {
      expect(path.isAbsolute(f)).toBe(true);
      expect(f.startsWith(REPO_ROOT)).toBe(true);
    }
  });

  it('throws a clear error for a non-existent ref', () => {
    expect(() => getChangedFilesSince(REPO_ROOT, 'definitely-not-a-ref-xxzzyy')).toThrow(
      /(may not exist|unknown revision|not a git repo)/,
    );
  });

  it('throws a clear error for a non-git directory', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'caspian-not-a-repo-'));
    try {
      expect(() => getChangedFilesSince(tmp, 'HEAD')).toThrow(
        /(may not exist|not a git repo|exited with code)/,
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
