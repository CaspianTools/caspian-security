import * as vscode from 'vscode';
import { resolveFix, FixResult } from './fixes';

/**
 * VS Code quick-fix provider for Caspian diagnostics.
 *
 * For each diagnostic whose rule code has a registered mechanical fix,
 * produces a {@link vscode.CodeAction} with the prepared
 * {@link vscode.WorkspaceEdit}. Shows up as the lightbulb / Ctrl+.
 * menu next to the finding.
 *
 * No AI involved — these fixes are deterministic text transformations.
 * For anything that requires judgement, users still reach for
 * `Caspian Security: Fix Issue with AI`.
 */
export class CaspianCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'Caspian Security') { continue; }
      const ruleCode = typeof diagnostic.code === 'string'
        ? diagnostic.code
        : typeof diagnostic.code === 'object' && diagnostic.code && typeof (diagnostic.code as any).value === 'string'
          ? String((diagnostic.code as any).value)
          : null;
      if (!ruleCode) { continue; }

      const fix = resolveFix(
        ruleCode,
        document,
        diagnostic.range.start.line,
        diagnostic.range.start.character,
      );
      if (!fix) { continue; }

      const action = buildCodeAction(document, diagnostic, fix);
      actions.push(action);
    }

    return actions;
  }
}

function buildCodeAction(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic,
  fix: FixResult,
): vscode.CodeAction {
  const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
  action.diagnostics = [diagnostic];
  action.isPreferred = fix.preferred === true;

  const edit = new vscode.WorkspaceEdit();
  for (const e of fix.edits) {
    const range = new vscode.Range(
      new vscode.Position(e.startLine, e.startCol),
      new vscode.Position(e.endLine, e.endCol),
    );
    edit.replace(document.uri, range, e.newText);
  }
  action.edit = edit;
  return action;
}

/**
 * Call from the extension's activate() once to register the provider
 * for every enabled language.
 */
export function registerCaspianCodeActionProvider(
  context: vscode.ExtensionContext,
  enabledLanguages: string[],
): void {
  for (const lang of enabledLanguages) {
    context.subscriptions.push(
      vscode.languages.registerCodeActionsProvider(
        { language: lang },
        new CaspianCodeActionProvider(),
        { providedCodeActionKinds: CaspianCodeActionProvider.providedCodeActionKinds },
      ),
    );
  }
  // Also register for file types that don't have a canonical languageId:
  // dockerfile, yaml, terraform (HCL).
  const fileTypes: vscode.DocumentFilter[] = [
    { language: 'dockerfile' },
    { language: 'yaml' },
    { language: 'terraform' },
    { pattern: '**/Dockerfile' },
    { pattern: '**/*.dockerfile' },
    { pattern: '**/*.tf' },
    { pattern: '**/*.tfvars' },
    { pattern: '**/*.hcl' },
    { pattern: '**/*.yaml' },
    { pattern: '**/*.yml' },
  ];
  for (const selector of fileTypes) {
    context.subscriptions.push(
      vscode.languages.registerCodeActionsProvider(
        selector,
        new CaspianCodeActionProvider(),
        { providedCodeActionKinds: CaspianCodeActionProvider.providedCodeActionKinds },
      ),
    );
  }
}
