import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Insecure-deserialization rules.
 *
 * Across every language family there is one pattern with the same shape:
 * untrusted bytes are handed to a deserializer that can reconstruct
 * arbitrary typed objects — and invoke their constructors / magic methods —
 * during the decode. The result is remote code execution.
 *
 * These rules match the sink itself rather than requiring a visible
 * taint path, because *the sink is the problem*. `pickle.loads()` on
 * user input is never acceptable; even on trusted bytes it is an
 * anti-pattern. The severity reflects this: if the sink fires,
 * something is wrong.
 *
 * For YAML we split the rule into:
 *   - `DESER004` (Error): explicit unsafe variant (`yaml.unsafe_load`,
 *     `yaml.load` without a safe loader).
 *   - `DESER004s` (Warning): `yaml.load` where a Loader argument is
 *     present — we can't see whether it's `SafeLoader` without a parser,
 *     so we warn and let the user review.
 */

const cat = SecurityCategory.InputValidationXSS;
const ruleType = RuleType.CodeDetectable;

const pickleSuggestion =
  'pickle / cPickle / dill / joblib deserialize arbitrary classes and invoke their __reduce__ / __setstate__ ' +
  'during load — equivalent to remote code execution on the sender. Use JSON, msgpack, or protobuf for ' +
  'untrusted data. For trusted-only data, still prefer `pickle.HIGHEST_PROTOCOL` and verify the source ' +
  'with a signature.';

const yamlSuggestion =
  'yaml.load / yaml.unsafe_load can instantiate arbitrary Python classes — RCE on untrusted input. ' +
  'Switch to `yaml.safe_load(...)` (or `yaml.load(..., Loader=yaml.SafeLoader)`).';

export const deserializationRules: SecurityRule[] = [
  {
    code: 'DESER001',
    message: 'Python pickle.loads / pickle.load — RCE on untrusted bytes',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b(?:pickle|cPickle|_pickle|dill|joblib)\.(?:loads|load)\s*\(/,
      /\bshelve\.open\s*\(/,
    ],
    suggestion: pickleSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'DESER002',
    message: 'Python marshal.loads — deserializes code objects, RCE on untrusted bytes',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bmarshal\.(?:loads|load)\s*\(/,
    ],
    suggestion: 'marshal is for Python internal bytecode only. Use JSON or msgpack for untrusted data.',
    category: cat,
    ruleType,
  },
  {
    code: 'DESER003',
    message: 'Python yaml.unsafe_load — executes arbitrary Python classes',
    severity: SecuritySeverity.Error,
    patterns: [
      /\byaml\.unsafe_load\w*\s*\(/,
    ],
    suggestion: yamlSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'DESER004',
    message: 'Python yaml.load without SafeLoader — may execute arbitrary classes',
    severity: SecuritySeverity.Error,
    patterns: [
      /\byaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|BaseLoader))/,
    ],
    negativePatterns: [
      /Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|BaseLoader)/,
      /yaml\.safe_load/,
    ],
    suggestion: yamlSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'DESER005',
    message: 'Java ObjectInputStream.readObject — notorious RCE sink (known as the "Java serialization" bug class)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bObjectInputStream\s*\([^)]*\)[^;]*\.readObject\s*\(/,
      /\.\s*readObject\s*\(\s*\)[^;]*\s*;[\s\S]{0,160}?ObjectInputStream/,
      /new\s+ObjectInputStream\s*\(/,
    ],
    suggestion:
      'Java serialization instantiates arbitrary classes via readObject() — the classic path to RCE ' +
      '(CVE-2015-7501, CVE-2017-5638, etc.). Use JSON (Jackson with a safe default typing policy), protobuf, ' +
      'or Kryo with a registered class whitelist. If you must keep readObject, install a look-ahead ' +
      'ObjectInputFilter with an explicit allow-list.',
    category: cat,
    ruleType,
  },
  {
    code: 'DESER006',
    message: '.NET BinaryFormatter / SoapFormatter / NetDataContractSerializer — RCE sink, removed in .NET 8+',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bBinaryFormatter\s*\(\s*\)\s*\.\s*Deserialize\s*\(/,
      /\bSoapFormatter\s*\(\s*\)\s*\.\s*Deserialize\s*\(/,
      /\bNetDataContractSerializer\s*\(\s*\)\s*\.\s*ReadObject\s*\(/,
      /\bLosFormatter\s*\(\s*\)\s*\.\s*Deserialize\s*\(/,
    ],
    suggestion:
      'Microsoft removed BinaryFormatter in .NET 8 specifically because of this class of bug. ' +
      'Use System.Text.Json or DataContractJsonSerializer with KnownTypes.',
    category: cat,
    ruleType,
  },
  {
    code: 'DESER007',
    message: 'PHP unserialize() on user input — RCE via __wakeup / __destruct magic methods',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
      /\bunserialize\s*\(\s*(?:file_get_contents|base64_decode)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
    ],
    suggestion:
      'PHP unserialize() triggers magic methods on the deserialized object. Use json_decode for untrusted ' +
      'data, or (PHP 7+) unserialize with the `allowed_classes => [...]` option.',
    category: cat,
    ruleType,
  },
  {
    code: 'DESER008',
    message: 'Node eval / Function constructor / vm.runInNewContext on user input — RCE',
    severity: SecuritySeverity.Error,
    patterns: [
      /\beval\s*\(\s*(?:req|request|ctx)\.(?:query|body|params|headers)/,
      /\bnew\s+Function\s*\(\s*(?:req|request|ctx)\.(?:query|body|params|headers)/,
      /\bvm\.(?:runInNewContext|runInThisContext|runInContext|createScript|Script)\s*\(\s*(?:req|request|ctx)\.(?:query|body|params|headers)/,
    ],
    suggestion:
      'Never pass untrusted input to eval / Function / vm.runInNewContext. If you need a sandbox, use ' +
      'isolated-vm or a WASM runtime — both of which still require a tight API surface.',
    category: cat,
    ruleType,
  },
  {
    code: 'DESER009',
    message: 'Ruby YAML.load / Marshal.load on untrusted input — RCE',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bYAML\.load\s*\(\s*(?:params|request|cookies)/,
      /\bMarshal\.load\s*\(\s*(?:params|request|cookies)/,
      /\bPsych\.load\s*\(/,
    ],
    suggestion:
      'Ruby YAML.load / Marshal.load reconstruct arbitrary objects — RCE on attacker input. ' +
      'Use YAML.safe_load or JSON.parse.',
    category: cat,
    ruleType,
  },
];
