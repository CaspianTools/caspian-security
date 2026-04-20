import { getAllRules } from '../rules';

/**
 * Defence-in-depth test against catastrophic backtracking in rule patterns.
 *
 * Every `RegExp` pattern on every rule is exercised against a small library
 * of known ReDoS-trigger shapes. No single pattern is permitted to take more
 * than {@link MAX_MS} on any adversarial input — if one does, the regex is
 * almost certainly unsafe and should be rewritten (add non-capturing groups,
 * flatten alternations, anchor the match).
 *
 * The analyzer has a per-file soft deadline, but that is a last-line
 * mitigation. This test catches the root cause at build time.
 */

const MAX_MS = 200;

// Strings shaped to provoke backtracking in patterns that mix `.*` with
// alternation or nested quantifiers. Kept small so a healthy regex finishes
// in microseconds; a vulnerable one blows way past MAX_MS.
const ADVERSARIAL_INPUTS: string[] = [
  'a'.repeat(200),
  'a'.repeat(200) + '!',
  'ab'.repeat(100),
  'ab'.repeat(100) + 'x',
  '"' + 'a'.repeat(120) + '\'',
  'x'.repeat(80) + '${' + 'y'.repeat(80) + '}',
  '//' + 'a'.repeat(180),
  '(' + 'a'.repeat(100) + ')',
  'http://' + 'a'.repeat(150) + '/',
  'SELECT ' + 'x'.repeat(150) + " WHERE id='" + 'y'.repeat(80),
];

describe('ReDoS guard', () => {
  const rules = getAllRules();

  it('has rules to check', () => {
    expect(rules.length).toBeGreaterThan(0);
  });

  for (const rule of rules) {
    for (let i = 0; i < rule.patterns.length; i++) {
      const pattern = rule.patterns[i];
      if (!(pattern instanceof RegExp)) { continue; }

      it(`${rule.code} pattern #${i} finishes on adversarial inputs`, () => {
        for (const input of ADVERSARIAL_INPUTS) {
          const started = Date.now();
          try {
            pattern.exec(input);
          } catch {
            // A thrown error is fine — it's still bounded execution.
          }
          const elapsed = Date.now() - started;
          if (elapsed > MAX_MS) {
            throw new Error(
              `Rule ${rule.code}, pattern #${i} (${pattern.source}) took ${elapsed}ms ` +
              `on input of length ${input.length}. This regex is ReDoS-prone — ` +
              `flatten alternations, avoid nested quantifiers, or anchor the match.`
            );
          }
        }
      });
    }
  }
});
