#!/usr/bin/env node
/**
 * Caspian Security — Model Context Protocol server.
 *
 * Exposes Caspian's scanning capabilities as MCP tools so any MCP
 * client (Claude Desktop, Cursor, Zed AI, cline.bot, etc.) can call
 * them directly from tool use. One stdio-based server process per
 * client — started by the client as a subprocess.
 *
 * Tools:
 *   scan             Scan a workspace path, return findings (JSON).
 *   scan_git_history Walk git history for leaked secrets.
 *   list_rules       Enumerate all rule codes / categories / severities.
 *   explain_rule     Return the full description + suggestion for a rule code.
 *
 * Transport: stdio (standard for local MCP servers). Clients spawn this
 * bin from their config:
 *
 *   // Claude Desktop claude_desktop_config.json
 *   {
 *     "mcpServers": {
 *       "caspian-security": {
 *         "command": "npx",
 *         "args": ["-y", "caspian-security", "caspian-mcp"]
 *       }
 *     }
 *   }
 *
 * The server has no network access, no telemetry, and no persistent
 * state — it's a thin wrapper over the same scanRunner the CLI uses.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { runWorkspaceScan } from '../scanRunner';
import { getAllRules, getRuleByCode } from '../rules';
import { CATEGORY_LABELS, SEVERITY_LABELS } from '../types';

// --- Tool definitions -----------------------------------------------------

const TOOLS = [
  {
    name: 'scan',
    description:
      'Run Caspian Security against a workspace path. Returns findings grouped by file, ' +
      'including line/column, rule code, category, severity, message, and suggested fix. ' +
      'Use this when the user asks to check code for security issues, audit a repo, or find vulnerabilities.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the workspace / directory to scan. Must exist and be readable.',
        },
        include: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional file-path substrings to force-include beyond the default file types.',
        },
        exclude: {
          type: 'array',
          items: { type: 'string' },
          description: 'Directory basenames to skip (added to node_modules/.git/dist/build/out/coverage defaults).',
        },
        severity: {
          type: 'string',
          enum: ['error', 'warning', 'info'],
          description: 'Minimum severity to include in the response (default: info — all findings).',
        },
        max_findings: {
          type: 'integer',
          description: 'Truncate the response to this many findings (default: 200). Full counts are still reported in the summary.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'scan_git_history',
    description:
      'Walk the full git history of a repository and flag any secret-shaped string added in any commit. ' +
      'Reports commit SHA, author, date, file, and line. Use this after onboarding a repo to surface credentials ' +
      'that may have leaked historically, even if "fixed" in a later commit.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to a git repository (must contain a .git directory).',
        },
        max_commits: {
          type: 'integer',
          description: 'Stop after N commits (default: all). Useful for very old repos.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'list_rules',
    description:
      'Enumerate every rule Caspian knows about. Returns rule code, category, severity, and one-line message. ' +
      'Use this for discovery / filtering before a scan.',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          description: 'Optional category filter (e.g. "Authentication & Access Control").',
        },
      },
    },
  },
  {
    name: 'explain_rule',
    description:
      'Return the full description and suggested remediation for a given rule code (e.g. "SSRF001", "TAINT003"). ' +
      'Use this when the user asks "what does rule X mean" or wants a remediation reference.',
    inputSchema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'The rule code (e.g. "TAINT001", "DOCKER003", "K8S001").',
        },
      },
      required: ['code'],
    },
  },
];

// --- Tool handlers --------------------------------------------------------

interface ToolResponse {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

function toolError(msg: string): ToolResponse {
  return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
}

function toolText(body: unknown): ToolResponse {
  const text = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
  return { content: [{ type: 'text', text }] };
}

function validatePath(p: unknown): string {
  if (typeof p !== 'string' || !p) { throw new Error('`path` must be a non-empty string'); }
  const abs = path.resolve(p);
  if (!fs.existsSync(abs)) { throw new Error(`path does not exist: ${abs}`); }
  if (!fs.statSync(abs).isDirectory()) { throw new Error(`path is not a directory: ${abs}`); }
  return abs;
}

export function handleScan(args: any): ToolResponse {
  let workspace: string;
  try { workspace = validatePath(args?.path); } catch (err: any) { return toolError(err.message); }

  const minSev = args?.severity || 'info';
  const sevThreshold = minSev === 'error' ? 2 : minSev === 'warning' ? 1 : 0;
  const maxFindings = typeof args?.max_findings === 'number' ? args.max_findings : 200;

  const result = runWorkspaceScan({
    workspace,
    include: Array.isArray(args?.include) ? args.include : [],
    exclude: Array.isArray(args?.exclude) ? args.exclude : [],
  });

  // Flatten + filter.
  const flat = result.results.flatMap(r =>
    r.issues
      .filter(i => i.severity >= sevThreshold)
      .map(i => ({
        file: r.relativePath.replace(/\\/g, '/'),
        line: i.line + 1,
        column: i.column + 1,
        severity: SEVERITY_LABELS[i.severity],
        code: i.code,
        category: CATEGORY_LABELS[i.category] || i.category,
        message: i.message,
        suggestion: i.suggestion,
      }))
  );

  const truncated = flat.slice(0, maxFindings);

  // Category histogram for the summary.
  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const f of flat) {
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  return toolText({
    summary: {
      files_scanned: result.filesScanned,
      files_skipped: result.filesSkipped,
      total_findings: flat.length,
      returned: truncated.length,
      truncated: flat.length > truncated.length,
      by_severity: bySeverity,
      by_category: byCategory,
    },
    findings: truncated,
  });
}

export function handleGitHistoryScan(args: any): ToolResponse {
  let workspace: string;
  try { workspace = validatePath(args?.path); } catch (err: any) { return toolError(err.message); }
  if (!fs.existsSync(path.join(workspace, '.git'))) {
    return toolError(`not a git repository (no .git at ${workspace})`);
  }

  // Shell out to the existing gitHistoryScan CLI in JSON mode. Cheaper than
  // duplicating its stream-parsing state machine here; the CLI is already
  // battle-tested.
  const cliPath = path.join(__dirname, 'gitHistoryScan.js');
  const cmdArgs = [cliPath, workspace, '--format', 'json', '--rules', 'secrets'];
  if (typeof args?.max_commits === 'number' && args.max_commits > 0) {
    cmdArgs.push('--max-commits', String(args.max_commits));
  }

  const result = spawnSync('node', cmdArgs, {
    encoding: 'utf-8',
    maxBuffer: 200 * 1024 * 1024,
  });
  if (result.error) { return toolError(`failed to spawn git-history scan: ${result.error.message}`); }
  if (result.status === 2) {
    return toolError(`git-history scan failed: ${(result.stderr || '').trim()}`);
  }
  try {
    const parsed = JSON.parse(result.stdout);
    return toolText(parsed);
  } catch (err: any) {
    return toolError(`could not parse scan output: ${err.message}`);
  }
}

export function handleListRules(args: any): ToolResponse {
  const rules = getAllRules();
  const filter = typeof args?.category === 'string' ? args.category.toLowerCase() : '';
  const filtered = rules.filter(r => {
    if (!filter) { return true; }
    const label = (CATEGORY_LABELS[r.category] || r.category).toLowerCase();
    return label.includes(filter);
  });
  const summary = filtered.map(r => ({
    code: r.code,
    category: CATEGORY_LABELS[r.category] || r.category,
    severity: SEVERITY_LABELS[r.severity],
    rule_type: r.ruleType,
    message: r.message,
  }));
  return toolText({
    count: summary.length,
    total_available: rules.length,
    rules: summary,
  });
}

export function handleExplainRule(args: any): ToolResponse {
  const code = typeof args?.code === 'string' ? args.code : '';
  if (!code) { return toolError('`code` must be a non-empty string (e.g. "SSRF001")'); }
  const rule = getRuleByCode(code);
  if (!rule) { return toolError(`unknown rule code: ${code}`); }
  return toolText({
    code: rule.code,
    category: CATEGORY_LABELS[rule.category] || rule.category,
    severity: SEVERITY_LABELS[rule.severity],
    rule_type: rule.ruleType,
    message: rule.message,
    suggestion: rule.suggestion,
    context_aware: rule.contextAware === true,
    file_patterns: rule.filePatterns
      ? {
          include: rule.filePatterns.include?.map(r => r.source),
          exclude: rule.filePatterns.exclude?.map(r => r.source),
        }
      : undefined,
  });
}

export function dispatchTool(name: string, args: unknown): ToolResponse {
  switch (name) {
    case 'scan': return handleScan(args);
    case 'scan_git_history': return handleGitHistoryScan(args);
    case 'list_rules': return handleListRules(args);
    case 'explain_rule': return handleExplainRule(args);
    default:
      return toolError(`unknown tool: ${name}`);
  }
}

// --- Server bootstrap -----------------------------------------------------

export async function startMcpServer(): Promise<void> {
  const pkg = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')
  );
  const server = new Server(
    { name: 'caspian-security', version: pkg.version || '0.0.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req: any) => {
    const name: string = req.params?.name;
    const args: unknown = req.params?.arguments;
    try {
      return dispatchTool(name, args) as any;
    } catch (err: any) {
      return toolError(err?.message || 'internal error') as any;
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Server is now live on stdio. MCP clients speak JSON-RPC over it.
}

if (require.main === module) {
  startMcpServer().catch((err: Error) => {
    process.stderr.write(`caspian-mcp: fatal — ${err.message}\n`);
    process.exit(1);
  });
}
