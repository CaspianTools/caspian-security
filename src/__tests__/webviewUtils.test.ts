import { isAllowedWebviewCommand, ALLOWED_WEBVIEW_COMMANDS } from '../webviewUtils';

describe('isAllowedWebviewCommand', () => {
  it('accepts every entry in the declared allow-list', () => {
    for (const cmd of ALLOWED_WEBVIEW_COMMANDS) {
      expect(isAllowedWebviewCommand(cmd)).toBe(true);
    }
  });

  it('rejects dangerous VS Code built-in commands even if they start with a safe prefix', () => {
    const dangerous = [
      'workbench.action.terminal.new',
      'workbench.action.openSettings',
      'vscode.diff',
      'workbench.action.files.newFile',
      'caspian-security.runCheck; rm -rf /',
      'caspian-security.',
      '',
    ];
    for (const cmd of dangerous) {
      expect(isAllowedWebviewCommand(cmd)).toBe(false);
    }
  });

  it('rejects non-string values from an adversarial webview', () => {
    expect(isAllowedWebviewCommand(undefined)).toBe(false);
    expect(isAllowedWebviewCommand(null)).toBe(false);
    expect(isAllowedWebviewCommand(123)).toBe(false);
    expect(isAllowedWebviewCommand({ toString: () => 'caspian-security.runCheck' })).toBe(false);
    expect(isAllowedWebviewCommand(['caspian-security.runCheck'])).toBe(false);
  });

  it('is case-sensitive — casing differences are rejected', () => {
    expect(isAllowedWebviewCommand('Caspian-Security.runCheck')).toBe(false);
    expect(isAllowedWebviewCommand('caspian-security.runCHECK')).toBe(false);
  });
});
