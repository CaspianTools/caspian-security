import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const frontendRules: SecurityRule[] = [
  {
    code: 'FE001',
    message: 'Unsafe eval() usage allows arbitrary code execution',
    severity: SecuritySeverity.Error,
    patterns: [
      /\beval\s*\(/,
      /new\s+Function\s*\(/,
      /setTimeout\s*\(\s*['"`]/,
      /setInterval\s*\(\s*['"`]/,
    ],
    suggestion: 'Avoid eval(), new Function(), and string arguments to setTimeout/setInterval',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
    contextAware: true,
  },
  {
    code: 'FE002',
    message: 'postMessage without origin validation',
    severity: SecuritySeverity.Warning,
    patterns: [
      /postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)/,
    ],
    suggestion: 'Always specify target origin in postMessage and verify event.origin in message handlers',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE003',
    message: 'Opening links without rel="noopener noreferrer"',
    severity: SecuritySeverity.Warning,
    patterns: [
      /target\s*=\s*['"]_blank['"]/i,
    ],
    suppressIfNearby: [
      /rel\s*=\s*['"][^'"]*noopener[^'"]*noreferrer[^'"]*['"]/i,
      /rel\s*=\s*['"][^'"]*noreferrer[^'"]*noopener[^'"]*['"]/i,
      // JSX/React style with curly braces
      /rel\s*=\s*\{[^}]*noopener[^}]*noreferrer[^}]*\}/i,
      /rel\s*=\s*\{[^}]*noreferrer[^}]*noopener[^}]*\}/i,
    ],
    suggestion: 'Add rel="noopener noreferrer" to links with target="_blank" to prevent tab-nabbing',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.Informational,
  },
  {
    code: 'FE004',
    message: 'Insecure use of iframe without sandbox',
    severity: SecuritySeverity.Warning,
    patterns: [
      /<iframe(?![^>]*sandbox)[^>]*>/i,
    ],
    suggestion: 'Add sandbox attribute to iframes to restrict embedded content capabilities',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE005',
    message: 'Script loaded from external CDN without integrity check',
    severity: SecuritySeverity.Warning,
    patterns: [
      /<script\s+src\s*=\s*['"]https?:\/\/(?![^'"]*localhost)[^'"]*['"](?![^>]*integrity)[^>]*>/i,
    ],
    suggestion: 'Add Subresource Integrity (SRI) hash attributes to external script tags',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE006',
    message: 'Sensitive data stored via document.cookie',
    severity: SecuritySeverity.Warning,
    patterns: [
      /document\.cookie\s*=/i,
    ],
    suggestion: 'Use Secure, HttpOnly, and SameSite flags on cookies; prefer server-side cookie setting',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE007',
    message: 'Prototype pollution: unsafe __proto__ or constructor access',
    severity: SecuritySeverity.Warning,
    patterns: [
      /__proto__/,
      /\bconstructor\s*\[/,
    ],
    contextAware: true,
    suggestion: 'Use Object.create(null) for dictionaries; validate keys to prevent __proto__ and constructor pollution',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    // Phase 3 (v9.5.0) — Object.assign / spread of untrusted objects.
    // The taint engine flags the same shape with provenance (TAINT008);
    // this rule fires on the static call regardless of whether the data
    // crossed a function boundary.
    code: 'FE007a',
    message: 'Object.assign with a request-shaped second argument — prototype pollution risk',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bObject\.assign\s*\(\s*\{[^}]*\}\s*,\s*(?:req|request|ctx)\.(?:body|query|params)/,
      /\bObject\.assign\s*\(\s*[\w$]+\s*,\s*(?:req|request|ctx)\.(?:body|query|params)/,
    ],
    suppressIfNearby: [
      /\bvalidate(?:Body|Input|Schema)\s*\(/,
      /\bzod\.|\bjoi\./i,
      /\.parse\s*\(/,
    ],
    suggestion:
      'Object.assign of a user-controlled second arg can pollute Object.prototype via the __proto__ key. ' +
      'Validate the body against a schema (Zod / Joi / express-validator) BEFORE merging, or use a manual ' +
      'allow-list copy: `for (const k of ALLOWED) target[k] = source[k];`',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE007b',
    message: 'lodash _.merge / _.defaultsDeep with untrusted source — prototype pollution',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b_\.(?:merge|mergeWith|defaultsDeep)\s*\(\s*[^,]+,\s*(?:req|request|ctx)\.(?:body|query|params)/,
    ],
    suppressIfNearby: [
      /lodash@(?:4\.17\.21|4\.18|5\.|6\.|7\.)/, // recent versions are patched
    ],
    suggestion:
      'lodash <= 4.17.20 has known prototype-pollution CVEs in merge / defaultsDeep / mergeWith. ' +
      'Upgrade to >= 4.17.21 AND validate the source object against a schema before merging.',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE007c',
    message: 'Spread of req.body/query/params into a trusted object — prototype pollution',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\{\s*\.\.\.(?:req|request|ctx)\.(?:body|query|params)/,
    ],
    suppressIfNearby: [
      /\bvalidate(?:Body|Input|Schema)\s*\(/,
      /\bzod\.|\bjoi\./i,
      /\.parse\s*\(/,
    ],
    suggestion:
      'Spreading user-controlled objects copies every key including `__proto__` (in older Node / browser ' +
      'engines without the spread-pollution fix). Validate against a schema first, or build the target ' +
      'with an explicit allow-list.',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE008',
    message: 'Reminder: Add Subresource Integrity for third-party CDN resources',
    severity: SecuritySeverity.Info,
    patterns: [
      /cdn\.|unpkg\.com|cdnjs|jsdelivr/i,
    ],
    suggestion: 'Add integrity and crossorigin attributes to all third-party script and link tags',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.Informational,
  },
  {
    code: 'FE009',
    message: 'Reminder: Client-side validation is for UX only — server-side validation is required for security',
    severity: SecuritySeverity.Info,
    patterns: [
      /checkValidity\s*\(/,
      /setCustomValidity\s*\(/,
      /\.validity\./,
      /reportValidity\s*\(/,
    ],
    suggestion: 'Client-side validation improves user experience but can be bypassed. Always validate and sanitize all inputs on the server side as the authoritative security boundary',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.Informational,
  },
  {
    code: 'FE010',
    message: 'window.open() with user-controlled URL',
    severity: SecuritySeverity.Warning,
    patterns: [
      /window\.open\s*\(\s*(?:req|request|params|query|body|user|url|href|input|data)\b/i,
      /window\.open\s*\(\s*\w+\s*[+,]/,
    ],
    negativePatterns: [/encodeURI/i, /validateUrl/i, /isValidUrl/i, /whitelist/i, /allowedUrl/i],
    suggestion:
      'Validate and sanitize URLs before passing to window.open(). Check the URL scheme (allow only https:) and validate against an allowlist to prevent javascript: or data: URL injection.',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE011',
    message: 'Sensitive data stored in localStorage/sessionStorage',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"].*(?:token|password|secret|session|auth|jwt|credential|apiKey|api_key)/i,
    ],
    suggestion:
      'Do not store sensitive data (tokens, passwords, secrets) in localStorage or sessionStorage — they are accessible to any JavaScript on the page, including XSS payloads. Use httpOnly cookies for auth tokens.',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE012',
    message: 'DOM-based XSS: user-controllable source flows into a DOM sink',
    severity: SecuritySeverity.Error,
    patterns: [
      /(?:location\.hash|location\.search|location\.href|document\.URL|document\.referrer).*\.innerHTML/i,
      /\.innerHTML\s*=.*(?:location\.hash|location\.search|location\.href|document\.URL|document\.referrer)/i,
      /document\.write\s*\(.*(?:location\.hash|location\.search|location\.href|document\.URL|document\.referrer)/i,
    ],
    suggestion:
      'Never pass user-controllable DOM sources (location.hash, location.search, document.referrer) into DOM sinks (innerHTML, document.write). Use textContent for safe insertion or sanitize with DOMPurify.',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE013',
    message: 'Unvalidated redirect using user input — open redirect risk',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:window\.location|location\.href|location\.assign|location\.replace)\s*=\s*(?:req|request|params|query|url|href|input|data)\b/i,
      /res\.redirect\s*\(\s*(?:req|request)\./i,
    ],
    negativePatterns: [/whitelist/i, /allowedUrl/i, /validateUrl/i, /isValidUrl/i, /safeRedirect/i],
    suggestion:
      'Validate redirect URLs against an allowlist of trusted domains. Never redirect to a user-supplied URL without validation — attackers can redirect users to phishing sites.',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
];
