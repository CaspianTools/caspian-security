import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * OAuth / OIDC hygiene rules.
 *
 * Three classes of bug we keep seeing in OAuth integrations:
 *
 * 1. **No `state` parameter validation.** The callback handler reads
 *    `req.query.code` and exchanges it for a token without checking
 *    that `req.query.state` matches the value the server stored at
 *    authorize-time. Without state, an attacker can CSRF the callback
 *    and bind their own social login to the victim's session.
 *
 * 2. **No PKCE.** Public clients (mobile, SPA) using auth-code flow
 *    must include `code_verifier` / `code_challenge`. Without it the
 *    code is interceptable.
 *
 * 3. **Open redirect via `redirect_uri`.** The handler reads
 *    `req.query.redirect_uri` and redirects without checking it
 *    against an allow-list. Classic phishing primitive.
 *
 * Detection here is intentionally syntactic — we look for the bug
 * shapes rather than trying to prove the control flow. False
 * positives are mitigated with `suppressIfNearby` for the canonical
 * mitigations.
 */

const cat = SecurityCategory.AuthAccessControl;
const ruleType = RuleType.CodeDetectable;

export const oauthRules: SecurityRule[] = [
  {
    code: 'OAUTH001',
    message: 'OAuth callback handles `code` without verifying `state` — CSRF risk',
    severity: SecuritySeverity.Error,
    patterns: [
      // `req.query.code` (or .body.code / .params.code) handled in a function
      // that doesn't look at `state`. Triggered on the read of `code`; suppression
      // requires `state` to appear within ±10 lines.
      /(?:req|request|ctx)\.(?:query|body|params)\.(?:code|authorization_code)\b/,
    ],
    suppressIfNearby: [
      /\.(?:state|nonce)\b/,
      /verifyState\s*\(/,
      /checkState\s*\(/,
      /storedState/i,
      /sessionState/i,
    ],
    suggestion:
      'Bind a cryptographically-random `state` value to the user session at authorize-time, ' +
      'and verify it on the callback before exchanging the code. Without this, an attacker ' +
      'can CSRF the callback and link their account to the victim\'s session.',
    category: cat,
    ruleType,
  },
  {
    code: 'OAUTH002',
    message: 'OAuth authorize URL built without `state` parameter',
    severity: SecuritySeverity.Error,
    patterns: [
      /response_type=(?:code|token)(?![\s\S]{0,300}state=)/,
    ],
    suggestion:
      'Append `state=<crypto-random>` to the authorize URL and store the same value in the user session. ' +
      'Reject the callback if state is missing or doesn\'t match.',
    category: cat,
    ruleType,
  },
  {
    code: 'OAUTH003',
    message: 'OAuth code exchange without PKCE — public-client risk',
    severity: SecuritySeverity.Warning,
    patterns: [
      /grant_type=authorization_code(?![\s\S]{0,300}code_verifier=)/,
    ],
    suppressIfNearby: [
      /code_verifier/,
      /code_challenge/,
      /pkce/i,
    ],
    suggestion:
      'For SPAs and mobile apps, use PKCE: include code_challenge / code_challenge_method=S256 in the ' +
      'authorize call and code_verifier in the token exchange. Confidential clients (server-to-server with ' +
      'a client secret) can skip PKCE, but it\'s recommended for them too.',
    category: cat,
    ruleType,
  },
  {
    code: 'OAUTH004',
    message: 'Redirect target taken from `req.query.redirect_uri` without validation — open redirect',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b(?:res|response)\.(?:redirect|location)\s*\(\s*(?:req|request|ctx)\.(?:query|body|params)\.(?:redirect_uri|next|url|returnTo|return_to|continue)\b/i,
    ],
    suppressIfNearby: [
      /isAllowedRedirect\s*\(/,
      /validateRedirect\s*\(/,
      /allowedRedirects?\s*[:.=]/i,
      /\.startsWith\s*\(\s*['"](?:\/|https:\/\/)/,
    ],
    suggestion:
      'Validate the redirect target against an explicit allow-list of internal paths or origins. ' +
      'Reject anything that doesn\'t start with `/` (relative) or a known origin.',
    category: cat,
    ruleType,
  },
  {
    code: 'OAUTH005',
    message: 'OAuth implicit flow (`response_type=token`) — deprecated, prefer auth-code + PKCE',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\bresponse_type\s*[:=]\s*['"]?token\b/,
    ],
    suggestion:
      'The implicit flow is deprecated by the OAuth 2.1 spec because it leaks tokens through the ' +
      'browser address bar / referer. Switch to authorization code with PKCE.',
    category: cat,
    ruleType,
  },
  {
    code: 'OAUTH006',
    message: 'OAuth `scope` parameter missing or set to wildcard',
    severity: SecuritySeverity.Info,
    patterns: [
      /\bscope\s*[:=]\s*['"](?:\*|all|.*\.\*)['"]/i,
    ],
    suggestion:
      'Request the minimum scope set your app actually needs. Wildcard scopes invite excessive consent ' +
      'screens and broader tokens than necessary.',
    category: cat,
    ruleType,
  },
];
