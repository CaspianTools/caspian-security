import { runTaintAnalysis } from '../taint';

function fixture(...lines: string[]): string {
  return lines.join('\n');
}

describe('runTaintAnalysis — TAINT001 (command injection)', () => {
  it('flags req.body flowing into child_process.exec within one function', () => {
    const text = fixture(
      'function handler(req, res) {',
      '  const cmd = req.body.command;',
      '  child_process.exec(cmd);',
      '  res.send("ok");',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe('TAINT001');
    expect(findings[0].line).toBe(2);
    expect(findings[0].message).toMatch(/'cmd' was tainted at line 2/);
  });

  it('does NOT flag when the variable is sanitised first', () => {
    const text = fixture(
      'function handler(req, res) {',
      '  const cmd = req.body.command;',
      '  const safe = sanitizeInput(cmd);',
      '  child_process.exec(safe);',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag when the variable is in a different function', () => {
    const text = fixture(
      'function inner() {',
      '  const cmd = req.body.x;',
      '}',
      'function outer() {',
      '  child_process.exec(cmd);',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings).toHaveLength(0);
  });
});

describe('runTaintAnalysis — TAINT002 (eval)', () => {
  it('flags direct eval(req.body.code)', () => {
    const text = fixture(
      'function handler(req, res) {',
      '  eval(req.body.code);',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings.some(f => f.code === 'TAINT002')).toBe(true);
  });

  it('flags new Function(tainted)', () => {
    const text = fixture(
      'function build(req) {',
      '  const code = req.query.expr;',
      '  return new Function(code);',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings.some(f => f.code === 'TAINT002')).toBe(true);
  });
});

describe('runTaintAnalysis — TAINT003 (path)', () => {
  it('flags fs.readFile with tainted path', () => {
    const text = fixture(
      'function serve(req, res) {',
      '  const file = req.params.filename;',
      '  fs.readFile(file, callback);',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings.some(f => f.code === 'TAINT003')).toBe(true);
  });
});

describe('runTaintAnalysis — TAINT005 (open redirect)', () => {
  it('flags res.redirect(req.query.url)', () => {
    const text = fixture(
      'function login(req, res) {',
      '  res.redirect(req.query.next);',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings.some(f => f.code === 'TAINT005')).toBe(true);
  });
});

describe('runTaintAnalysis — TAINT007 (SSRF with provenance)', () => {
  it('flags fetch(req.body.url) inside a controller', () => {
    const text = fixture(
      'function proxy(req, res) {',
      '  const target = req.body.target;',
      '  fetch(target).then(r => r.text());',
      '}',
    );
    const findings = runTaintAnalysis(text);
    expect(findings.some(f => f.code === 'TAINT007')).toBe(true);
  });
});

describe('runTaintAnalysis — bounds', () => {
  it('handles a 0-line file without crashing', () => {
    expect(runTaintAnalysis('')).toEqual([]);
  });

  it('handles a file with no functions without crashing', () => {
    const text = 'const x = 1;\nconst y = 2;\n';
    expect(runTaintAnalysis(text)).toEqual([]);
  });

  it('respects the deadline budget', () => {
    // A pathologically long function — the engine should bail out, not hang.
    const big = ['function foo() {'];
    for (let i = 0; i < 5000; i++) { big.push(`  const x${i} = 1;`); }
    big.push('}');
    const text = big.join('\n');
    const t0 = Date.now();
    const result = runTaintAnalysis(text, 50);
    const elapsed = Date.now() - t0;
    expect(elapsed).toBeLessThan(500); // generous slack for CI noise
    expect(Array.isArray(result)).toBe(true);
  });
});
