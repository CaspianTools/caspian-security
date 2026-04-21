import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Server-Side Request Forgery (SSRF) detection.
 *
 * SSRF is when user-controlled data flows into the URL / host of an outbound
 * HTTP call made by the server. The classic impact is reading cloud metadata
 * endpoints (`169.254.169.254`), internal admin interfaces (`localhost:2375`),
 * or performing port scans from the server's vantage.
 *
 * Detection strategy:
 *   - Match each language's idiomatic HTTP sinks (fetch / axios / requests /
 *     httpx / RestTemplate / HttpClient / URLConnection / curl_exec / etc.).
 *   - Require that the first-or-URL argument comes from a known user-input
 *     source — `req.` / `request.` / `req.query` / `req.body` / `req.params`
 *     / `params.` / `query.` / `body.` / `user.` — or from a variable whose
 *     name contains `userUrl`, `input`, `target`, `dest`, `redirect`, etc.
 *   - Allow a `suppressIfNearby` escape hatch for code that validates the
 *     URL (`new URL(...)` + host allow-list, `isAllowedHost`, `validateUrl`,
 *     `SafeUrl.`, etc.). False-positive tolerance matters here — teams that
 *     already have a URL validator hate re-flagging.
 *
 * All patterns use anchored character classes and bounded quantifiers so the
 * ReDoS guard test passes.
 */

const cat = SecurityCategory.APISecurity;
const ruleType = RuleType.CodeDetectable;

// Reused user-input token — matches the fragment that typically indicates
// the argument came from request data. Kept in one place so adjustments
// apply everywhere.
const REQ = String.raw`(?:req|request|ctx|context)\.(?:query|body|params|input|url|headers|cookies)`;
const USER = String.raw`(?:req|request)\.user\.[\w]+`;
const USER_VAR = String.raw`\b(?:userUrl|targetUrl|redirectUrl|webhookUrl|callbackUrl|externalUrl|destination|dest|input|targetHost)\b`;

const safeNearby: RegExp[] = [
  /isAllowedHost|isInAllowlist|validateUrl|sanitizeUrl|SafeUrl\.|url\.allowlist/i,
  /new\s+URL\s*\([^)]+\)[\s\S]{0,80}(?:allowlist|hostname\s*===?|host\s*===?)/i,
  /\bssrf(?:-|_)?guard/i,
];

const suggestion =
  'Validate this URL against an explicit host allow-list BEFORE the request. ' +
  'Reject private IPs (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fc00::/7), ' +
  'metadata endpoints (169.254.169.254, metadata.google.internal), and non-HTTPS schemes.';

export const ssrfRules: SecurityRule[] = [
  {
    code: 'SSRF001',
    message: 'Outbound fetch() called with a user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      new RegExp(String.raw`\bfetch\s*\(\s*(?:\`[^\`]*\$\{[^}]*(?:${REQ}|${USER})|${REQ}|${USER}|${USER_VAR})`),
    ],
    suppressIfNearby: safeNearby,
    contextAware: true,
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF002',
    message: 'Outbound axios call with a user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      new RegExp(
        String.raw`\baxios(?:\.(?:get|post|put|delete|patch|head|request))?\s*\(\s*(?:\`[^\`]*\$\{[^}]*(?:${REQ}|${USER})|${REQ}|${USER}|${USER_VAR})`
      ),
    ],
    suppressIfNearby: safeNearby,
    contextAware: true,
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF003',
    message: 'Node http/https get/request called with a user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      new RegExp(
        String.raw`\bhttps?\.(?:get|request)\s*\(\s*(?:\`[^\`]*\$\{[^}]*(?:${REQ}|${USER})|${REQ}|${USER}|${USER_VAR})`
      ),
    ],
    suppressIfNearby: safeNearby,
    contextAware: true,
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF004',
    message: 'Python requests call with a user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      /\brequests\.(?:get|post|put|delete|patch|head|request)\s*\(\s*(?:request\.(?:args|form|json|values)|flask\.request\.(?:args|form|json)|g\.request\.)/i,
    ],
    suppressIfNearby: safeNearby,
    contextAware: true,
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF005',
    message: 'Python urllib.request.urlopen called with a user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      /\burllib\.request\.urlopen\s*\(\s*(?:request\.|flask\.request\.|\w*(?:user|target|input)[\w]*url)/i,
      /\burlopen\s*\(\s*(?:request\.|flask\.request\.|\w*(?:user|target|input)[\w]*url)/i,
    ],
    suppressIfNearby: safeNearby,
    contextAware: true,
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF006',
    message: 'Java RestTemplate / HttpClient / URL.openConnection with user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b(?:restTemplate|restClient)\.(?:getForObject|exchange|postForObject|execute)\s*\([^)]*\brequest\.(?:getParameter|getQueryString|getHeader)/i,
      /\bnew\s+URL\s*\(\s*request\.(?:getParameter|getQueryString|getHeader)/i,
      /\bHttpRequest\.newBuilder\s*\(\s*\)\.uri\s*\(\s*URI\.create\s*\([^)]*request\.(?:getParameter|getHeader)/i,
    ],
    suppressIfNearby: safeNearby,
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF007',
    message: 'PHP curl / file_get_contents / fopen with a user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
      /\bfile_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
      /\bfopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF008',
    message: 'Go http.Get / http.Post called with a user-controlled URL',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bhttp\.(?:Get|Post|Head|PostForm|NewRequest)\s*\(\s*(?:r\.URL\.Query\(\)|r\.FormValue|r\.Form\.Get|c\.Query|c\.PostForm)/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSRF009',
    message: 'Webhook / callback URL loaded from request and fetched without allow-listing',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\b(?:const|let|var)\s+\w*(?:webhook|callback|redirect)\w*\s*=\s*(?:req|request|ctx)\.(?:query|body|params|input)/i,
    ],
    suppressIfNearby: safeNearby,
    suggestion,
    category: cat,
    ruleType,
  },
];
