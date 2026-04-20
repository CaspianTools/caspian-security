import * as vscode from 'vscode';
import { ResultsStore } from './resultsStore';
import { SecuritySeverity, CATEGORY_LABELS, SEVERITY_LABELS } from './types';

const WELCOME_SHOWN_KEY = 'caspianSecurity.welcomeShownVersion';

export class WelcomePanel implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private extensionUri: vscode.Uri,
    private resultsStore: ResultsStore,
    private globalState: vscode.Memento,
    private extensionVersion: string,
  ) {}

  /**
   * Show the welcome panel if this is the first activation for this version,
   * or if the user has never seen the welcome screen.
   */
  shouldShowOnActivation(): boolean {
    const shownVersion = this.globalState.get<string>(WELCOME_SHOWN_KEY);
    return !shownVersion;
  }

  markAsShown(): void {
    this.globalState.update(WELCOME_SHOWN_KEY, this.extensionVersion);
  }

  show(): void {
    if (this.panel) {
      this.panel.reveal(vscode.ViewColumn.One);
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'caspianWelcome',
      'Welcome to Caspian Security',
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: false,
        localResourceRoots: [this.extensionUri],
      }
    );

    this.panel.webview.html = this.getHtml();

    this.panel.webview.onDidReceiveMessage(
      (msg) => this.handleMessage(msg),
      null,
      this.disposables
    );

    this.panel.onDidDispose(() => {
      this.panel = undefined;
    }, null, this.disposables);

    this.markAsShown();
  }

  /**
   * Show the welcome panel with scan results populated.
   */
  showWithResults(): void {
    this.show();
    setTimeout(() => this.sendResults(), 200);
  }

  /**
   * Update results if the panel is already visible. Does not reveal the panel.
   */
  updateResults(): void {
    if (this.panel) {
      this.sendResults();
    }
  }

  private sendResults(): void {
    if (!this.panel) { return; }
    const allResults = this.resultsStore.getAllResults();
    const totalIssues = allResults.reduce((sum, r) => sum + r.issues.length, 0);
    const totalFiles = allResults.length;

    const bySeverity: Record<string, number> = { Error: 0, Warning: 0, Info: 0 };
    const byCategory: Record<string, number> = {};

    for (const result of allResults) {
      for (const issue of result.issues) {
        const sevLabel = SEVERITY_LABELS[issue.severity];
        bySeverity[sevLabel] = (bySeverity[sevLabel] || 0) + 1;
        const catLabel = CATEGORY_LABELS[issue.category];
        byCategory[catLabel] = (byCategory[catLabel] || 0) + 1;
      }
    }

    // Sort categories by count descending
    const sortedCategories = Object.entries(byCategory)
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({ name, count }));

    this.panel.webview.postMessage({
      type: 'scanResults',
      data: { totalIssues, totalFiles, bySeverity, categories: sortedCategories },
    });
  }

  private async handleMessage(msg: any): Promise<void> {
    switch (msg.type) {
      case 'runWorkspaceScan':
        await vscode.commands.executeCommand('caspian-security.runCheckWorkspace');
        break;
      case 'openResultsPanel':
        await vscode.commands.executeCommand('caspian-security.showResultsPanel');
        break;
      case 'openAISettings':
        await vscode.commands.executeCommand('caspian-security.openAISettings');
        break;
      case 'openSettings':
        await vscode.commands.executeCommand('workbench.action.openSettings', 'caspianSecurity');
        break;
      case 'openLearningDashboard':
        await vscode.commands.executeCommand('caspian-security.showLearningDashboard');
        break;
      case 'dismiss':
        this.panel?.dispose();
        break;
    }
  }

  private getHtml(): string {
    const nonce = getNonce();
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <title>Welcome to Caspian Security</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size, 13px);
      padding: 0;
      display: flex;
      justify-content: center;
    }
    .container {
      max-width: 720px;
      width: 100%;
      padding: 32px 24px 48px 24px;
    }
    .hero {
      text-align: center;
      padding: 24px 0 20px 0;
    }
    .hero h1 {
      font-size: 24px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .hero .version {
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
      margin-bottom: 12px;
    }
    .hero p {
      font-size: 14px;
      color: var(--vscode-descriptionForeground);
      line-height: 1.5;
    }

    .scan-prompt {
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
      border-radius: 6px;
      padding: 20px 24px;
      text-align: center;
      margin: 16px 0 24px 0;
    }
    .scan-prompt h2 {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .scan-prompt p {
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
      margin-bottom: 14px;
    }

    .scan-results {
      display: none;
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
      border-radius: 6px;
      padding: 20px 24px;
      margin: 16px 0 24px 0;
    }
    .scan-results.visible { display: block; }
    .scan-results h2 {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .scan-results .stats {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }
    .stat-card {
      flex: 1;
      min-width: 100px;
      background: var(--vscode-editor-background);
      border-radius: 4px;
      padding: 12px;
      text-align: center;
    }
    .stat-card .number {
      font-size: 28px;
      font-weight: 700;
    }
    .stat-card .label {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      margin-top: 2px;
    }
    .stat-error .number { color: var(--vscode-errorForeground, #f44336); }
    .stat-warning .number { color: var(--vscode-editorWarning-foreground, #ff9800); }
    .stat-info .number { color: var(--vscode-editorInfo-foreground, #2196f3); }
    .stat-total .number { color: var(--vscode-editor-foreground); }

    .category-bars {
      margin-top: 12px;
    }
    .category-bar {
      display: flex;
      align-items: center;
      margin-bottom: 6px;
      font-size: 12px;
    }
    .category-bar .cat-name {
      width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .category-bar .bar-track {
      flex: 1;
      height: 8px;
      background: var(--vscode-editor-background);
      border-radius: 4px;
      margin: 0 8px;
      overflow: hidden;
    }
    .category-bar .bar-fill {
      height: 100%;
      background: var(--vscode-progressBar-background, #0078d4);
      border-radius: 4px;
      transition: width 0.4s ease;
    }
    .category-bar .cat-count {
      font-weight: 600;
      min-width: 30px;
      text-align: right;
    }

    .btn {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 8px 20px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      border-radius: 4px;
    }
    .btn:hover { background: var(--vscode-button-hoverBackground); }
    .btn-secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    .btn-secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .btn-row { display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; }

    .features {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin: 24px 0;
    }
    .feature {
      background: var(--vscode-input-background);
      border-radius: 6px;
      padding: 14px 16px;
    }
    .feature h3 {
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 4px;
    }
    .feature p {
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
      line-height: 1.4;
    }

    .quick-start {
      margin-top: 24px;
    }
    .quick-start h2 {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .step {
      display: flex;
      gap: 12px;
      margin-bottom: 12px;
      align-items: flex-start;
    }
    .step-number {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      font-weight: 700;
      flex-shrink: 0;
    }
    .step-content h4 {
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 2px;
    }
    .step-content p {
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
      line-height: 1.4;
    }
    kbd {
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
      border-radius: 3px;
      padding: 1px 5px;
      font-size: 11px;
      font-family: var(--vscode-editor-fontFamily, monospace);
    }

    .footer {
      text-align: center;
      margin-top: 24px;
      padding-top: 16px;
      border-top: 1px solid var(--vscode-panel-border);
    }
    .footer p {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
    }
    .footer a {
      color: var(--vscode-textLink-foreground);
      text-decoration: none;
    }
    .footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <h1>Caspian Security</h1>
      <div class="version">v${this.extensionVersion}</div>
      <p>Context-aware security analysis with AI-powered fixes.<br>164 rules across 14 categories. Zero configuration required.</p>
    </div>

    <div class="scan-prompt" id="scan-prompt">
      <h2>Scan Your Workspace</h2>
      <p>Run a full workspace scan to see your project's security posture instantly.</p>
      <div class="btn-row">
        <button class="btn" id="btn-scan">Scan Workspace Now</button>
      </div>
    </div>

    <div class="scan-results" id="scan-results">
      <h2>Your Security Posture</h2>
      <div class="stats">
        <div class="stat-card stat-total">
          <div class="number" id="stat-total">0</div>
          <div class="label">Total Issues</div>
        </div>
        <div class="stat-card stat-error">
          <div class="number" id="stat-errors">0</div>
          <div class="label">Errors</div>
        </div>
        <div class="stat-card stat-warning">
          <div class="number" id="stat-warnings">0</div>
          <div class="label">Warnings</div>
        </div>
        <div class="stat-card stat-info">
          <div class="number" id="stat-info">0</div>
          <div class="label">Info</div>
        </div>
      </div>
      <div class="category-bars" id="category-bars"></div>
      <div class="btn-row" style="margin-top: 16px;">
        <button class="btn" id="btn-view-results">View Full Results</button>
        <button class="btn btn-secondary" id="btn-ai-settings">Configure AI Fixes</button>
      </div>
    </div>

    <div class="features">
      <div class="feature">
        <h3>Real-Time Scanning</h3>
        <p>Detects vulnerabilities as you type. No manual triggers needed for open files.</p>
      </div>
      <div class="feature">
        <h3>AI-Powered Fixes</h3>
        <p>One-click AI fixes with full function-level context. Supports Claude, GPT-4, and Gemini.</p>
      </div>
      <div class="feature">
        <h3>Adaptive Learning</h3>
        <p>Learns your codebase patterns. Reduces false positives over time. Replays cached fixes instantly.</p>
      </div>
      <div class="feature">
        <h3>Confidence Scoring</h3>
        <p>Bayesian confidence levels tell you which findings are Critical, Safe, or need verification.</p>
      </div>
      <div class="feature">
        <h3>SARIF Export</h3>
        <p>Export results in SARIF v2.1.0 for GitHub Security Alerts. Also JSON and CSV.</p>
      </div>
      <div class="feature">
        <h3>Security Tasks</h3>
        <p>23 recurring security tasks keep you on track with audits, rotations, and compliance checks.</p>
      </div>
    </div>

    <div class="quick-start">
      <h2>Quick Start</h2>
      <div class="step">
        <div class="step-number">1</div>
        <div class="step-content">
          <h4>Open a file</h4>
          <p>Caspian scans automatically when you open or edit JavaScript, TypeScript, Python, Java, C#, PHP, Go, Rust, or Kotlin files.</p>
        </div>
      </div>
      <div class="step">
        <div class="step-number">2</div>
        <div class="step-content">
          <h4>Review findings</h4>
          <p>Issues appear in the Problems panel with severity and confidence badges. Open the Results Panel for the full view.</p>
        </div>
      </div>
      <div class="step">
        <div class="step-number">3</div>
        <div class="step-content">
          <h4>Fix with AI</h4>
          <p>Click <strong>AI Fix</strong> on any finding. Configure your API key via <kbd>Ctrl+Shift+P</kbd> &gt; "Caspian Security: Configure AI Fix Provider".</p>
        </div>
      </div>
      <div class="step">
        <div class="step-number">4</div>
        <div class="step-content">
          <h4>Triage and learn</h4>
          <p>Mark false positives to train the learning system. Ignore findings to add them to <code>.caspianignore</code> for the whole team.</p>
        </div>
      </div>
    </div>

    <div class="footer">
      <div class="btn-row" style="margin-bottom: 12px;">
        <button class="btn btn-secondary" id="btn-settings">Extension Settings</button>
        <button class="btn btn-secondary" id="btn-learning">Learning Dashboard</button>
        <button class="btn btn-secondary" id="btn-dismiss">Got it, let's go</button>
      </div>
      <p>You can reopen this page anytime via <kbd>Ctrl+Shift+P</kbd> &gt; "Caspian Security: Welcome"</p>
    </div>
  </div>

<script nonce="${nonce}">
(function() {
  const vscode = acquireVsCodeApi();

  document.getElementById('btn-scan').addEventListener('click', () => {
    vscode.postMessage({ type: 'runWorkspaceScan' });
    document.getElementById('btn-scan').textContent = 'Scanning...';
    document.getElementById('btn-scan').disabled = true;
  });

  document.getElementById('btn-view-results').addEventListener('click', () => {
    vscode.postMessage({ type: 'openResultsPanel' });
  });

  document.getElementById('btn-ai-settings').addEventListener('click', () => {
    vscode.postMessage({ type: 'openAISettings' });
  });

  document.getElementById('btn-settings').addEventListener('click', () => {
    vscode.postMessage({ type: 'openSettings' });
  });

  document.getElementById('btn-learning').addEventListener('click', () => {
    vscode.postMessage({ type: 'openLearningDashboard' });
  });

  document.getElementById('btn-dismiss').addEventListener('click', () => {
    vscode.postMessage({ type: 'dismiss' });
  });

  window.addEventListener('message', event => {
    const msg = event.data;
    if (msg.type === 'scanResults') {
      const d = msg.data;
      document.getElementById('scan-prompt').style.display = 'none';
      document.getElementById('scan-results').classList.add('visible');

      document.getElementById('stat-total').textContent = d.totalIssues;
      document.getElementById('stat-errors').textContent = d.bySeverity.Error || 0;
      document.getElementById('stat-warnings').textContent = d.bySeverity.Warning || 0;
      document.getElementById('stat-info').textContent = d.bySeverity.Info || 0;

      const barsEl = document.getElementById('category-bars');
      const maxCount = d.categories.length > 0 ? d.categories[0].count : 1;
      barsEl.innerHTML = d.categories.map(function(cat) {
        const pct = Math.round((cat.count / maxCount) * 100);
        return '<div class="category-bar">'
          + '<span class="cat-name">' + escapeHtml(cat.name) + '</span>'
          + '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>'
          + '<span class="cat-count">' + cat.count + '</span>'
          + '</div>';
      }).join('');
    }
  });

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s || '';
    return div.innerHTML;
  }
})();
</script>
</body>
</html>`;
  }

  dispose(): void {
    this.panel?.dispose();
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }
}

function getNonce(): string {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
