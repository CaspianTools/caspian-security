/**
 * Unified `caspian` dispatcher tests.
 *
 * We drive runCaspian() directly, capturing stdout/stderr and intercepting
 * process.exit (each subcommand owns its own exit code). We only exercise the
 * routing surface — the delegated scanners/servers are covered by their own
 * tests, so here we route to their `--help`/error paths rather than run real
 * scans.
 */

import { runCaspian } from '../cli/caspian';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../../package.json');

class ExitSignal extends Error {
  constructor(public code: number) { super(`exit ${code}`); }
}

async function invoke(argv: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  let stdout = '';
  let stderr = '';
  const outSpy = jest.spyOn(process.stdout, 'write').mockImplementation(((chunk: any) => { stdout += String(chunk); return true; }) as any);
  const errSpy = jest.spyOn(process.stderr, 'write').mockImplementation(((chunk: any) => { stderr += String(chunk); return true; }) as any);
  const exitSpy = jest.spyOn(process, 'exit').mockImplementation(((code?: number) => { throw new ExitSignal(code ?? 0); }) as any);
  let code: number | null = null;
  try {
    await runCaspian(argv);
  } catch (e) {
    if (e instanceof ExitSignal) { code = e.code; } else { throw e; }
  } finally {
    outSpy.mockRestore();
    errSpy.mockRestore();
    exitSpy.mockRestore();
  }
  return { code, stdout, stderr };
}

describe('caspian dispatcher — meta', () => {
  it('prints the version with --version', async () => {
    const { code, stdout } = await invoke(['--version']);
    expect(code).toBe(0);
    expect(stdout.trim()).toBe(pkg.version);
  });

  it('strips a redundant leading `caspian` token (legacy npx form)', async () => {
    // `npx -y caspian-security caspian <sub>` (pre-10.7.3 docs) now resolves the
    // `caspian-security` bin directly, so the extra `caspian` token lands here. The
    // shim drops it — without the shim this would exit 2 as an unknown command.
    const { code, stdout } = await invoke(['caspian', '--version']);
    expect(code).toBe(0);
    expect(stdout.trim()).toBe(pkg.version);
  });

  it('prints usage with no args and with help', async () => {
    for (const argv of [[], ['help'], ['--help']]) {
      const { code, stdout } = await invoke(argv);
      expect(code).toBe(0);
      expect(stdout).toContain('Usage: caspian');
      expect(stdout).toContain('scan');
      expect(stdout).toContain('mcp-config');
    }
  });

  it('exits 2 on an unknown command and shows help', async () => {
    const { code, stderr, stdout } = await invoke(['frobnicate']);
    expect(code).toBe(2);
    expect(stderr).toContain('unknown command');
    expect(stdout).toContain('Usage: caspian');
  });
});

describe('caspian dispatcher — snippet', () => {
  it('prints a paste-ready block for a valid agent', async () => {
    const { code, stdout } = await invoke(['snippet', '--agent', 'claude', '--mode', 'after-edits']);
    expect(code).toBe(0);
    expect(stdout).toContain('Caspian Security');
    expect(stdout).toContain('npx -y caspian-security scan .');
  });

  it('rejects an invalid --agent with exit 2', async () => {
    const { code, stderr } = await invoke(['snippet', '--agent', 'bogus']);
    expect(code).toBe(2);
    expect(stderr).toContain('--agent must be one of');
  });

  it('rejects an invalid --mode with exit 2', async () => {
    const { code, stderr } = await invoke(['snippet', '--mode', 'whenever']);
    expect(code).toBe(2);
    expect(stderr).toContain('--mode must be one of');
  });
});

describe('caspian dispatcher — mcp-config', () => {
  it('prints valid config for a client', async () => {
    const { code, stdout } = await invoke(['mcp-config', '--client', 'cursor']);
    expect(code).toBe(0);
    expect(stdout).toContain('"mcpServers"');
    expect(stdout).toContain('.cursor/mcp.json');
  });

  it('rejects an invalid --client with exit 2', async () => {
    const { code, stderr } = await invoke(['mcp-config', '--client', 'notepad']);
    expect(code).toBe(2);
    expect(stderr).toContain('--client must be one of');
  });
});

describe('caspian dispatcher — delegation', () => {
  // We route an *invalid flag* rather than --help: the delegated CLIs wrap
  // parseArgs in try/catch and call process.exit(2) with their own name in the
  // error, which uniquely proves the subcommand reached that scanner. (A
  // delegated --help would call the real exit(0); under our throwing exit mock
  // that gets caught by the delegate's try/catch and re-exits 2 — an artifact of
  // the mock, not the routing.)
  it('routes `scan` to the CLI scanner', async () => {
    const { code, stderr } = await invoke(['scan', '--nope']);
    expect(code).toBe(2);
    expect(stderr).toContain('caspian-scan');
  });

  it('routes `git-history` to the git-history scanner', async () => {
    const { code, stderr } = await invoke(['git-history', '--nope']);
    expect(code).toBe(2);
    expect(stderr).toContain('caspian-git-history-scan');
  });
});
