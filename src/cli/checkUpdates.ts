#!/usr/bin/env node

import * as path from 'path';
import { checkDependencies, formatResultsAsText } from '../dependencyChecker';

function printHelp(): void {
  console.log(
    'Usage: caspian check-updates [path] [options]\n' +
    '\n' +
    'Runs npm outdated + npm audit + stack version checks against a project.\n' +
    '\n' +
    'Options:\n' +
    '  --osv        Also check non-npm manifests (requirements.txt, go.mod,\n' +
    '               Cargo.lock/Cargo.toml, pom.xml, Gemfile.lock, composer.lock)\n' +
    '               against the OSV.dev vulnerability database. Sends dependency\n' +
    '               names and versions (never code) to api.osv.dev.\n' +
    '  -h, --help   Show this help.\n' +
    '\n' +
    'Exit codes: 0 = clean, 1 = high/critical vulnerabilities found, 2 = check failed.'
  );
}

export async function runCheckUpdatesCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  if (argv.includes('-h') || argv.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  const includeOsv = argv.includes('--osv');
  const positional = argv.filter(a => !a.startsWith('-'));
  const projectPath = positional[0] || process.cwd();
  const resolvedPath = path.resolve(projectPath);

  console.log('Caspian Security: Dependency & Stack Update Check');
  console.log(`Project: ${resolvedPath}`);
  console.log('='.repeat(50));
  console.log('');

  try {
    const result = await checkDependencies(resolvedPath, { includeOsv });
    const output = formatResultsAsText(result);
    console.log(output);

    // Exit with code 1 if there are critical/high vulnerabilities
    const hasHighSeverity = result.auditSummary.vulnerabilities.some(
      v => v.severity === 'high' || v.severity === 'critical'
    ) || (result.osv?.vulnerabilities || []).some(
      v => v.severity === 'high' || v.severity === 'critical'
    );
    process.exit(hasHighSeverity ? 1 : 0);
  } catch (error) {
    console.error('Error running dependency check:', error);
    process.exit(2);
  }
}

if (require.main === module) {
  runCheckUpdatesCli().catch((error) => {
    console.error('Error running dependency check:', error);
    process.exit(2);
  });
}
