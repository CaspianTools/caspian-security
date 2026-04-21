import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Command-injection rules — language-by-language coverage of the
 * "execute a shell command built from data" anti-pattern.
 *
 * The taint engine catches the dataflow case for Node sinks already
 * (TAINT001). These rules complement it by flagging suspect call
 * shapes regardless of whether the dataflow is single-line or
 * cross-function. They also cover languages the taint engine
 * doesn't (PHP, Ruby, Python proc spawning).
 *
 * Rule of thumb across the rule family:
 *   - Use `shell: false` (default) and pass args as an array.
 *   - If you absolutely need a shell, build the argv yourself and use
 *     `execFile` / `spawn` with the shell path explicit and the
 *     command pre-quoted.
 *   - Validate input against an allow-list before it goes anywhere
 *     near a process spawner.
 */

const cat = SecurityCategory.APISecurity;
const ruleType = RuleType.CodeDetectable;

const baseSuggestion =
  'Pass the command and its arguments as separate array elements (no shell interpolation). ' +
  'For Node, prefer execFile / spawn with `shell: false`. Validate user input against an explicit ' +
  'allow-list before it reaches any spawner.';

export const cmdInjectionRules: SecurityRule[] = [
  {
    code: 'CMD001',
    message: 'child_process.exec / execSync called with concatenated user input',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*['"`][^'"`]*['"`]\s*\+\s*(?:req|request|ctx)\.(?:query|body|params|headers)/,
      /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*\`[^\`]*\$\{\s*(?:req|request|ctx)\.(?:query|body|params|headers)/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'CMD002',
    message: 'child_process.spawn called with `shell: true` and a user-influenced command',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bspawn(?:Sync)?\s*\([^)]+,\s*[^)]+,\s*\{[^}]*shell\s*:\s*true/,
    ],
    suggestion:
      '`shell: true` makes spawn equivalent to exec — the entire command goes through /bin/sh, defeating ' +
      'the array-arg protection. Drop `shell: true` and let spawn pass args directly.',
    category: cat,
    ruleType,
  },
  {
    code: 'CMD003',
    message: 'Python os.system / os.popen with concatenated input',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bos\.(?:system|popen)\s*\(\s*['"`][^'"`]*['"`]\s*\+\s*(?:request\.|sys\.argv|user_input)/,
      /\bos\.(?:system|popen)\s*\(\s*f['"][^'"]*\{(?:request\.|sys\.argv|user_input)/,
    ],
    suggestion:
      'Replace os.system / os.popen with subprocess.run([cmd, arg1, arg2], shell=False). ' +
      'Never let user input reach a shell.',
    category: cat,
    ruleType,
  },
  {
    code: 'CMD004',
    message: 'Python subprocess called with shell=True',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True/,
    ],
    suppressIfNearby: [
      /shlex\.quote/,
      /shlex\.split/,
    ],
    suggestion:
      'subprocess + shell=True invites injection. Drop shell=True and pass argv as a list. If you ' +
      'absolutely need a shell, run shlex.quote on every interpolated value first.',
    category: cat,
    ruleType,
  },
  {
    code: 'CMD005',
    message: 'PHP shell_exec / passthru / system / exec / proc_open with $_GET / $_POST',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b(?:shell_exec|passthru|system|exec|proc_open|popen)\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    ],
    suggestion:
      'Use escapeshellarg() on every user-controlled component, OR avoid the shell entirely with ' +
      'pcntl_exec / language-level libraries. Better: redesign the workflow so user input never reaches a shell.',
    category: cat,
    ruleType,
  },
  {
    code: 'CMD006',
    message: 'Ruby `system` / backticks / IO.popen with interpolated user input',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsystem\s*\(\s*['"][^'"]*#\{(?:params|request|cookies)/,
      /`[^`]*#\{(?:params|request|cookies)/,
      /\bIO\.popen\s*\(\s*['"][^'"]*#\{(?:params|request|cookies)/,
    ],
    suggestion:
      'Pass the command and args as an array: system("git", "log", "--", path). Avoid backticks and ' +
      'string-form system() with user input.',
    category: cat,
    ruleType,
  },
  {
    code: 'CMD007',
    message: 'Java Runtime.exec / ProcessBuilder with concatenated user input',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*['"][^'"]*['"]\s*\+\s*request\./,
      /\bnew\s+ProcessBuilder\s*\(\s*['"][^'"]*['"]\s*\+\s*request\./,
    ],
    suggestion:
      'Use ProcessBuilder with a List<String> of pre-validated args. Never concatenate request data into a ' +
      'command string passed to Runtime.exec(String).',
    category: cat,
    ruleType,
  },
];
