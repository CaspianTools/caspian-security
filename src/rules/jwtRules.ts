import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * JWT misuse rules — algorithm confusion, `alg: none`, missing audience
 * / issuer validation, expired-token acceptance.
 *
 * Three bug shapes dominate real incidents:
 *
 * 1. **Algorithm confusion.** Code that verifies with a public key but
 *    accepts `alg: HS256` lets the attacker sign their own token using
 *    the public key as the HMAC secret. Caused by `jwt.verify(token, key)`
 *    without an explicit `algorithms` list.
 *
 * 2. **`alg: none` accepted.** A parser configured with `algorithms:
 *    ['HS256', 'none']` (or no list) lets an attacker strip the
 *    signature entirely.
 *
 * 3. **Decode without verify.** `jwt.decode(token)` returns the claims
 *    without checking the signature. Code that trusts the result is
 *    completely broken.
 */

const cat = SecurityCategory.AuthAccessControl;
const ruleType = RuleType.CodeDetectable;

export const jwtRules: SecurityRule[] = [
  {
    code: 'JWT001',
    message: 'jwt.verify / jwt.decode accepting `alg: none` — signature stripping',
    severity: SecuritySeverity.Error,
    patterns: [
      /\balgorithms?\s*:\s*\[[^\]]*['"]none['"]/i,
      /\balg\s*:\s*['"]none['"]/i,
      /\bsetAllowedAlgorithms\s*\([^)]*['"]none['"]/i,
      /\balgorithms\s*=\s*\[[^\]]*['"]none['"]/i,
    ],
    suggestion:
      'Never accept alg=none. Restrict the verifier to the specific algorithm your tokens use — e.g. ' +
      '{ algorithms: ["RS256"] } — and reject everything else.',
    category: cat,
    ruleType,
  },
  {
    code: 'JWT002',
    message: 'jsonwebtoken.verify() without explicit algorithms list — algorithm confusion risk',
    severity: SecuritySeverity.Error,
    patterns: [
      // `jwt.verify(token, key)` with only 2-3 args and no `algorithms` key anywhere in the options.
      // Bounded: must be on one line, opts object must be short, no `algorithms:` inside.
      /\bjwt\.verify\s*\(\s*\w[\w.]*\s*,\s*\w[\w.]*\s*(?:,\s*\{[^}]{0,200}\}\s*)?\)/,
    ],
    negativePatterns: [
      /algorithms?\s*:\s*\[/,
      /\.requireAlgorithm\s*\(/,
    ],
    suppressIfNearby: [
      /algorithms?\s*:\s*\[/,
      /\.requireAlgorithm\s*\(/,
    ],
    suggestion:
      'Pass `{ algorithms: ["RS256"] }` (or whatever your tokens use) as the third argument. ' +
      'Without this, a token signed with HS256 using the public key as the HMAC secret will verify — ' +
      'the classic algorithm-confusion attack.',
    category: cat,
    ruleType,
  },
  {
    code: 'JWT003',
    message: 'jwt.decode() used where jwt.verify() is required — no signature check',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bjwt\.decode\s*\(\s*\w/,
      /\bjsonwebtoken\.decode\s*\(\s*\w/,
    ],
    suppressIfNearby: [
      // Allowed when you only want to peek at the header to dispatch on `kid`.
      /decode\s*\([^)]*,\s*\{[^}]*complete\s*:\s*true/,
      /\.header/,
    ],
    suggestion:
      'jwt.decode() does NOT verify the signature. Only use it to inspect the header when fetching the ' +
      'signing key (e.g. to look up the `kid`). For authentication, always use jwt.verify().',
    category: cat,
    ruleType,
  },
  {
    code: 'JWT004',
    message: 'PyJWT decode without algorithms argument',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bjwt\.decode\s*\(\s*\w[\w.]*\s*,\s*\w[\w.]*\s*\)/,
    ],
    negativePatterns: [
      /algorithms\s*=\s*\[/,
    ],
    suggestion:
      'PyJWT ≥ 2.0 requires the `algorithms` argument — older code that relied on the default is insecure. ' +
      'Use `jwt.decode(token, key, algorithms=["RS256"])`.',
    category: cat,
    ruleType,
  },
  {
    code: 'JWT005',
    message: 'Java JWT parser without requireAlgorithm() — algorithm confusion risk',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bJwts\.parser(?:Builder)?\s*\(\s*\)\s*\.setSigningKey\s*\(/,
    ],
    suppressIfNearby: [
      /\.requireAlgorithm\s*\(/,
      /\.setAllowedClockSkewSeconds\s*\(/,
    ],
    suggestion:
      'Chain .requireAlgorithm(SignatureAlgorithm.RS256) (or whichever algorithm you use) on the ' +
      'Jwts.parser() builder. Otherwise JJWT will accept any algorithm that matches the key type.',
    category: cat,
    ruleType,
  },
  {
    code: 'JWT006',
    message: 'JWT verification ignores `exp` (expiration) — replay-forever token',
    severity: SecuritySeverity.Warning,
    patterns: [
      /ignoreExpiration\s*:\s*true/i,
      /verify_exp\s*=\s*False/i,
      /verify_expiration\s*=\s*False/i,
      /setAllowedClockSkewSeconds\s*\(\s*(?:31536000|604800|3600000)/,
    ],
    suggestion:
      'Allow a small clock-skew tolerance (±30s) but never disable expiry. A 7-day token that can be ' +
      'replayed for years is a near-equivalent of a static credential.',
    category: cat,
    ruleType,
  },
  {
    code: 'JWT007',
    message: 'JWT verification missing issuer/audience check',
    severity: SecuritySeverity.Info,
    patterns: [
      /\bjwt\.verify\s*\(/,
      /\bjsonwebtoken\.verify\s*\(/,
    ],
    suppressIfNearby: [
      /issuer\s*:/,
      /audience\s*:/,
      /requireIssuer/,
      /requireAudience/,
    ],
    suggestion:
      'Validate the `iss` (issuer) and `aud` (audience) claims. A token legitimately issued for one ' +
      'service should not be usable against another.',
    category: cat,
    ruleType,
  },
];
