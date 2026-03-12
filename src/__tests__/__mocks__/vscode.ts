// Minimal vscode mock for testing rule logic outside the extension host

export enum DiagnosticSeverity {
  Error = 0,
  Warning = 1,
  Information = 2,
  Hint = 3,
}

export class Position {
  constructor(public line: number, public character: number) {}
}

export class Range {
  constructor(public start: Position, public end: Position) {}
}

export class Diagnostic {
  constructor(
    public range: Range,
    public message: string,
    public severity?: DiagnosticSeverity
  ) {}
  code?: string | number;
  source?: string;
}

export class Uri {
  static file(path: string) { return { fsPath: path, toString: () => path, scheme: 'file' }; }
  static parse(value: string) { return { fsPath: value, toString: () => value, scheme: 'file' }; }
}

export class EventEmitter {
  private listeners: Array<(...args: any[]) => void> = [];
  event = (listener: (...args: any[]) => void) => {
    this.listeners.push(listener);
    return { dispose: () => {} };
  };
  fire(...args: any[]) {
    this.listeners.forEach(l => l(...args));
  }
  dispose() { this.listeners = []; }
}

export class ThemeColor {
  constructor(public id: string) {}
}

export const window = {
  createStatusBarItem: () => ({
    show: () => {},
    hide: () => {},
    dispose: () => {},
    text: '',
    tooltip: '',
    command: '',
    backgroundColor: undefined,
  }),
  createOutputChannel: () => ({
    appendLine: () => {},
    show: () => {},
    dispose: () => {},
  }),
  showInformationMessage: async (..._args: any[]) => undefined,
  showWarningMessage: async (..._args: any[]) => undefined,
  showErrorMessage: async (..._args: any[]) => undefined,
  createWebviewPanel: () => ({
    webview: { html: '', onDidReceiveMessage: () => ({ dispose: () => {} }), postMessage: () => {} },
    reveal: () => {},
    dispose: () => {},
    onDidDispose: () => ({ dispose: () => {} }),
  }),
};

export const workspace = {
  workspaceFolders: [],
  getConfiguration: () => ({
    get: (key: string, defaultValue?: any) => defaultValue,
  }),
  onDidChangeConfiguration: () => ({ dispose: () => {} }),
  createFileSystemWatcher: () => ({
    onDidChange: () => ({ dispose: () => {} }),
    onDidCreate: () => ({ dispose: () => {} }),
    onDidDelete: () => ({ dispose: () => {} }),
    dispose: () => {},
  }),
};

export const commands = {
  registerCommand: () => ({ dispose: () => {} }),
  executeCommand: async () => {},
};

export const languages = {
  createDiagnosticCollection: () => ({
    set: () => {},
    delete: () => {},
    clear: () => {},
    dispose: () => {},
  }),
};

export const env = {
  clipboard: { writeText: async () => {} },
};

export const extensions = {
  getExtension: () => undefined,
};

export const StatusBarAlignment = { Left: 1, Right: 2 };
export const ViewColumn = { One: 1, Two: 2 };
