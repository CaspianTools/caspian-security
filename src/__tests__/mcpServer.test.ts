/**
 * MCP tool-handler tests.
 *
 * We test the handler functions directly without instantiating an MCP
 * Server. Goal: prove the tool-call → ToolResponse contract is stable
 * and the happy-path shape is what an MCP client would consume.
 */

import * as path from 'path';
import { handleScan, handleListRules, handleExplainRule, dispatchTool } from '../cli/mcpServer';

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'vulnerable-corpus');

function parseText(resp: { content: Array<{ type: string; text: string }> }): any {
  const first = resp.content[0];
  expect(first?.type).toBe('text');
  return JSON.parse(first.text);
}

describe('MCP tool: scan', () => {
  it('returns a summary + findings for a workspace with known vulnerabilities', () => {
    const resp = handleScan({ path: FIXTURE_DIR });
    expect((resp as any).isError).toBeFalsy();
    const body = parseText(resp);
    expect(body.summary).toBeDefined();
    expect(body.summary.files_scanned).toBeGreaterThan(0);
    expect(body.summary.total_findings).toBeGreaterThan(0);
    expect(Array.isArray(body.findings)).toBe(true);
    const codes = new Set(body.findings.map((f: any) => f.code));
    // The corpus contains DOCKER001 (base image :latest) deterministically.
    expect(codes.has('DOCKER001')).toBe(true);
  });

  it('truncates to max_findings and reports truncation in the summary', () => {
    const resp = handleScan({ path: FIXTURE_DIR, max_findings: 2 });
    const body = parseText(resp);
    expect(body.findings.length).toBeLessThanOrEqual(2);
    if (body.summary.total_findings > 2) {
      expect(body.summary.truncated).toBe(true);
      expect(body.summary.returned).toBe(body.findings.length);
    }
  });

  it('filters by severity threshold', () => {
    const respInfo = handleScan({ path: FIXTURE_DIR, severity: 'info' });
    const respErr = handleScan({ path: FIXTURE_DIR, severity: 'error' });
    const infoCount = parseText(respInfo).summary.total_findings;
    const errCount = parseText(respErr).summary.total_findings;
    expect(errCount).toBeLessThanOrEqual(infoCount);
    // Error-severity findings exist in the corpus (DOCKER003, TF001, etc.).
    expect(errCount).toBeGreaterThan(0);
  });

  it('returns an error for a non-existent path', () => {
    const resp = handleScan({ path: '/definitely/does/not/exist-xyzzy' });
    expect((resp as any).isError).toBe(true);
    expect(resp.content[0].text).toMatch(/path does not exist/);
  });

  it('returns an error for a missing path argument', () => {
    const resp = handleScan({});
    expect((resp as any).isError).toBe(true);
    expect(resp.content[0].text).toMatch(/path/);
  });
});

describe('MCP tool: list_rules', () => {
  it('returns the full rule catalogue without a filter', () => {
    const resp = handleListRules({});
    const body = parseText(resp);
    expect(body.count).toBeGreaterThan(100);
    expect(body.total_available).toBe(body.count);
    const sample = body.rules[0];
    expect(sample.code).toBeDefined();
    expect(sample.category).toBeDefined();
    expect(sample.severity).toBeDefined();
  });

  it('filters by category substring', () => {
    const resp = handleListRules({ category: 'authentication' });
    const body = parseText(resp);
    expect(body.count).toBeGreaterThan(0);
    expect(body.count).toBeLessThan(body.total_available);
    for (const r of body.rules) {
      expect(r.category.toLowerCase()).toContain('authentication');
    }
  });
});

describe('MCP tool: explain_rule', () => {
  it('returns the full description for a known rule code', () => {
    const resp = handleExplainRule({ code: 'SSRF001' });
    const body = parseText(resp);
    expect(body.code).toBe('SSRF001');
    expect(body.message).toMatch(/fetch/i);
    expect(body.suggestion).toBeDefined();
    expect(body.category).toBe('API Security');
  });

  it('returns an error for an unknown rule code', () => {
    const resp = handleExplainRule({ code: 'NOT_A_REAL_RULE' });
    expect((resp as any).isError).toBe(true);
    expect(resp.content[0].text).toMatch(/unknown rule code/);
  });

  it('returns an error for a missing code argument', () => {
    const resp = handleExplainRule({});
    expect((resp as any).isError).toBe(true);
  });
});

describe('MCP dispatchTool', () => {
  it('routes each known tool name to the right handler', () => {
    const listResp = dispatchTool('list_rules', {});
    expect((listResp as any).isError).toBeFalsy();
    expect(parseText(listResp).count).toBeGreaterThan(0);

    const explainResp = dispatchTool('explain_rule', { code: 'JWT001' });
    expect((explainResp as any).isError).toBeFalsy();
    expect(parseText(explainResp).code).toBe('JWT001');
  });

  it('returns an error for an unknown tool name', () => {
    const resp = dispatchTool('not_a_real_tool', {});
    expect((resp as any).isError).toBe(true);
    expect(resp.content[0].text).toMatch(/unknown tool/);
  });
});
