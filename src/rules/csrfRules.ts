import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const csrfRules: SecurityRule[] = [
  {
    code: 'CSRF001',
    message: 'Form without CSRF token',
    severity: SecuritySeverity.Warning,
    patterns: [
      /<form\s[^>]*method\s*=\s*['"]post['"][^>]*>/i,
    ],
    suggestion: 'Include a CSRF token in all POST forms (e.g., csrf_token, _token, csrfmiddlewaretoken)',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CSRF002',
    message: 'CSRF protection explicitly disabled',
    severity: SecuritySeverity.Error,
    patterns: [
      /csrf\s*[:=]\s*false/i,
      /csrfProtection\s*[:=]\s*false/i,
      /@csrf_exempt/i,
      /csrf_exempt/i,
    ],
    suggestion: 'Do not disable CSRF protection; if needed for an API endpoint, use token-based auth instead',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CSRF003',
    message: 'Cookie SameSite set to None',
    severity: SecuritySeverity.Warning,
    patterns: [
      /sameSite\s*:\s*['"]none['"]/i,
    ],
    suggestion: 'Set SameSite=Lax or SameSite=Strict on cookies to prevent CSRF',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CSRF004',
    message: 'State-changing operation using GET method',
    severity: SecuritySeverity.Warning,
    patterns: [
      /app\.get\s*\(.*(?:delete|remove|update|create|modify)/i,
      /router\.get\s*\(.*(?:delete|remove|update|create|modify)/i,
    ],
    suggestion: 'Use POST, PUT, or DELETE methods for state-changing operations, not GET',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CSRF005',
    message: 'Reminder: Verify CSRF tokens are validated on all state-changing endpoints',
    severity: SecuritySeverity.Info,
    patterns: [
      /app\.(?:post|put|patch|delete)\s*\(/i,
      /router\.(?:post|put|patch|delete)\s*\(/i,
    ],
    suggestion: 'Ensure CSRF middleware is applied before route handlers for POST/PUT/PATCH/DELETE',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CSRF006',
    message: 'CSRF token may not be cryptographically random',
    severity: SecuritySeverity.Warning,
    patterns: [
      /csrf.*Math\.random/i,
      /token.*Math\.random/i,
      /Math\.random.*csrf/i,
      /Math\.random.*token/i,
    ],
    suggestion: 'Generate CSRF tokens using a CSPRNG (e.g., crypto.randomBytes, crypto.getRandomValues) — never use Math.random()',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CSRF007',
    message: 'Reminder: Ensure CSRF tokens expire and are rotated per session',
    severity: SecuritySeverity.Info,
    patterns: [
      /csrfToken/i,
      /csrf_token/i,
      /_csrf/i,
    ],
    suggestion: 'Set a reasonable expiration on CSRF tokens and regenerate them on login/session rotation',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CSRF008',
    message: 'Reminder: Consider double-submit cookie pattern for CSRF protection',
    severity: SecuritySeverity.Info,
    patterns: [
      /res\.cookie\s*\(/i,
      /setCookie\s*\(/i,
    ],
    suppressIfNearby: [/csrf/i, /xsrf/i, /double.?submit/i, /csrfToken/i],
    suggestion:
      'For stateless APIs, consider the double-submit cookie pattern: set a random CSRF token in a cookie and require the client to send the same value in a header. Verify both match on the server.',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CSRF009',
    message: 'Reminder: Use custom request header (X-Requested-With) for AJAX CSRF protection',
    severity: SecuritySeverity.Info,
    patterns: [
      /XMLHttpRequest/i,
      /fetch\s*\(\s*['"`]/i,
      /axios\.\w+\s*\(/i,
    ],
    suppressIfNearby: [/X-Requested-With/i, /csrf/i, /xsrf/i, /X-CSRF/i, /csrfToken/i],
    suggestion:
      'Require a custom header (e.g., X-Requested-With) on state-changing AJAX requests. Browsers enforce CORS preflight for custom headers, preventing simple cross-origin CSRF attacks.',
    category: SecurityCategory.CSRFProtection,
    ruleType: RuleType.Informational,
  },
];
