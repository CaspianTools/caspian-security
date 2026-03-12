import * as vscode from 'vscode';
import { ResultsStore } from './resultsStore';
import { FixTracker } from './fixTracker';
import { SecuritySeverity, SEVERITY_LABELS } from './types';

export class SecurityScoreService implements vscode.Disposable {
  private statusBarItem: vscode.StatusBarItem;
  private disposables: vscode.Disposable[] = [];
  private currentScore = 100;

  constructor(
    private resultsStore: ResultsStore,
    private fixTracker?: FixTracker,
  ) {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      99 // just to the right of the main Caspian status bar item (priority 100)
    );
    this.statusBarItem.command = 'caspian-security.showSecurityScore';
    this.statusBarItem.text = '$(shield) Score: --';
    this.statusBarItem.tooltip = 'Caspian Security Score — Run a scan to calculate';
    this.statusBarItem.show();

    this.resultsStore.onDidChange(() => {
      this.recalculate();
    }, null, this.disposables);

    if (this.fixTracker) {
      this.fixTracker.onDidChange(() => {
        this.recalculate();
      }, null, this.disposables);
    }
  }

  getScore(): number {
    return this.currentScore;
  }

  recalculate(): void {
    const allResults = this.resultsStore.getAllResults();
    const totalFiles = allResults.length;

    if (totalFiles === 0) {
      this.currentScore = 100;
      this.updateStatusBar();
      return;
    }

    // Count issues weighted by severity
    let weightedPenalty = 0;
    let totalIssues = 0;

    for (const result of allResults) {
      for (const issue of result.issues) {
        // Check if this issue has been fixed or ignored
        const key = this.fixTracker
          ? FixTracker.makeKey(result.relativePath, issue.code, issue.line, issue.pattern)
          : '';
        const record = this.fixTracker?.getRecord(key);

        if (record?.status === 'fixed' || record?.status === 'verified' || record?.status === 'ignored') {
          continue; // Don't penalize resolved issues
        }

        totalIssues++;

        // Severity weights: Error = 3, Warning = 1.5, Info = 0.5
        switch (issue.severity) {
          case SecuritySeverity.Error:
            weightedPenalty += 3;
            break;
          case SecuritySeverity.Warning:
            weightedPenalty += 1.5;
            break;
          case SecuritySeverity.Info:
            weightedPenalty += 0.5;
            break;
        }
      }
    }

    // Score formula: starts at 100, loses points per weighted issue
    // Normalized by file count so large projects aren't unfairly penalized
    // penalty per file = weightedPenalty / totalFiles
    // Score drops faster for high density, bottoms out at 0
    const penaltyPerFile = totalFiles > 0 ? weightedPenalty / totalFiles : 0;
    // Each point of penalty-per-file costs ~5 score points, capped at 100
    const rawScore = Math.max(0, Math.round(100 - (penaltyPerFile * 5)));
    this.currentScore = rawScore;
    this.updateStatusBar();
  }

  private updateStatusBar(): void {
    const score = this.currentScore;
    let icon: string;
    let bgColor: vscode.ThemeColor | undefined;

    if (score >= 90) {
      icon = '$(pass)';
      bgColor = undefined;
    } else if (score >= 70) {
      icon = '$(warning)';
      bgColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
      icon = '$(error)';
      bgColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    }

    this.statusBarItem.text = `${icon} Score: ${score}/100`;
    this.statusBarItem.tooltip = this.buildTooltip();
    this.statusBarItem.backgroundColor = bgColor;
  }

  private buildTooltip(): string {
    const allResults = this.resultsStore.getAllResults();
    const totalFiles = allResults.length;
    let errors = 0, warnings = 0, infos = 0, resolved = 0;

    for (const result of allResults) {
      for (const issue of result.issues) {
        const key = this.fixTracker
          ? FixTracker.makeKey(result.relativePath, issue.code, issue.line, issue.pattern)
          : '';
        const record = this.fixTracker?.getRecord(key);

        if (record?.status === 'fixed' || record?.status === 'verified' || record?.status === 'ignored') {
          resolved++;
          continue;
        }

        switch (issue.severity) {
          case SecuritySeverity.Error: errors++; break;
          case SecuritySeverity.Warning: warnings++; break;
          case SecuritySeverity.Info: infos++; break;
        }
      }
    }

    const total = errors + warnings + infos;
    const lines = [
      `Caspian Security Score: ${this.currentScore}/100`,
      `${totalFiles} file(s) scanned`,
      `${total} open issue(s): ${errors} errors, ${warnings} warnings, ${infos} info`,
    ];
    if (resolved > 0) {
      lines.push(`${resolved} resolved`);
    }
    lines.push('Click for details');
    return lines.join('\n');
  }

  async showScoreDetails(): Promise<void> {
    const score = this.currentScore;
    const allResults = this.resultsStore.getAllResults();
    let errors = 0, warnings = 0, infos = 0;

    for (const result of allResults) {
      for (const issue of result.issues) {
        const key = this.fixTracker
          ? FixTracker.makeKey(result.relativePath, issue.code, issue.line, issue.pattern)
          : '';
        const record = this.fixTracker?.getRecord(key);
        if (record?.status === 'fixed' || record?.status === 'verified' || record?.status === 'ignored') {
          continue;
        }
        switch (issue.severity) {
          case SecuritySeverity.Error: errors++; break;
          case SecuritySeverity.Warning: warnings++; break;
          case SecuritySeverity.Info: infos++; break;
        }
      }
    }

    let grade: string;
    if (score >= 90) { grade = 'A'; }
    else if (score >= 80) { grade = 'B'; }
    else if (score >= 70) { grade = 'C'; }
    else if (score >= 60) { grade = 'D'; }
    else { grade = 'F'; }

    const choice = await vscode.window.showInformationMessage(
      `Security Score: ${score}/100 (Grade ${grade}) | ${errors} errors, ${warnings} warnings, ${infos} info`,
      'View Results',
      'Run Workspace Scan'
    );

    if (choice === 'View Results') {
      await vscode.commands.executeCommand('caspian-security.showResultsPanel');
    } else if (choice === 'Run Workspace Scan') {
      await vscode.commands.executeCommand('caspian-security.runCheckWorkspace');
    }
  }

  dispose(): void {
    this.statusBarItem.dispose();
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }
}
