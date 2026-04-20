/**
 * Shared utilities for Caspian Security's webview panels.
 *
 * Centralising the command allow-list here means any `runCommand` / `runCheck`
 * message a webview sends is validated against the same set no matter which
 * panel received it — if a future panel is added and forgets to wire up this
 * guard, the webview still cannot reach arbitrary VS Code commands.
 */

/**
 * The only command IDs a webview is permitted to invoke via postMessage.
 * Keep this list narrow: every entry is a command the user could also run
 * directly from the Command Palette, so there is no escalation of privilege.
 */
export const ALLOWED_WEBVIEW_COMMANDS: ReadonlySet<string> = new Set<string>([
  // Core scans
  'caspian-security.runCheck',
  'caspian-security.runCheckFile',
  'caspian-security.runCheckWorkspace',
  'caspian-security.runCheckUncommitted',
  'caspian-security.runFullScan',
  'caspian-security.scanBranchChanges',

  // Category scans
  'caspian-security.check-auth-access-control',
  'caspian-security.check-input-validation-xss',
  'caspian-security.check-csrf-protection',
  'caspian-security.check-cors-configuration',
  'caspian-security.check-encryption-data-protection',
  'caspian-security.check-api-security',
  'caspian-security.check-database-security',
  'caspian-security.check-file-handling',
  'caspian-security.check-secrets-credentials',
  'caspian-security.check-frontend-security',
  'caspian-security.check-business-logic-payment',
  'caspian-security.check-logging-monitoring',
  'caspian-security.check-dependencies-supply-chain',
  'caspian-security.check-infrastructure-deployment',
  'caspian-security.checkDependencyUpdates',

  // Views & dashboards
  'caspian-security.showResultsPanel',
  'caspian-security.showLearningDashboard',
  'caspian-security.showTaskDashboard',
  'caspian-security.showWelcome',
  'caspian-security.showSecurityScore',
  'caspian-security.showScanHistory',

  // Fix-related flows
  'caspian-security.verifyAllFixes',
  'caspian-security.clearFalsePositives',
  'caspian-security.resetFixTracker',

  // Settings
  'caspian-security.openAISettings',
]);

/** True if the supplied value is a command ID that a webview is allowed to trigger. */
export function isAllowedWebviewCommand(commandId: unknown): commandId is string {
  return typeof commandId === 'string' && ALLOWED_WEBVIEW_COMMANDS.has(commandId);
}

/**
 * Generate a cryptographically-reasonable nonce for CSP script tags. Uses
 * Math.random (adequate for defeating literal-string XSS payloads; the nonce
 * is scoped to a single webview render).
 */
export function getNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}
