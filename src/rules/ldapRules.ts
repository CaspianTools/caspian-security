import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * LDAP injection rules.
 *
 * LDAP filters use the syntax `(attr=value)`, with `&`, `|`, `!` as
 * boolean operators. If user input lands in an unescaped position,
 * the attacker can break out: `*)(uid=*))(|(uid=*` turns a bind check
 * into "match any user", letting them log in as anyone.
 *
 * The fix is the same in every language: pre-escape the value with
 * the platform's LDAP-escape utility (`ldapjs.escape`,
 * `org.springframework.ldap.support.LdapEncoder.filterEncode`,
 * Python `ldap.filter.escape_filter_chars`, .NET `LdapFilter.EscapeValue`).
 */

const cat = SecurityCategory.AuthAccessControl;
const ruleType = RuleType.CodeDetectable;

const suggestion =
  'Escape the value before placing it in an LDAP filter: ldapjs.escape(value), ' +
  'ldap.filter.escape_filter_chars(value), LdapEncoder.filterEncode(value), or ' +
  'parameterised search APIs that handle escaping for you.';

export const ldapRules: SecurityRule[] = [
  {
    code: 'LDAP001',
    message: 'LDAP filter built via string concatenation with user input',
    severity: SecuritySeverity.Error,
    patterns: [
      // `(uid=` + var, `(cn=` + var, etc. — the canonical pattern.
      /\(\s*[a-zA-Z]+\s*=\s*['"]?\s*\+\s*(?:req|request|ctx|params|body|query|user|input|userInput|name)/,
      // Template literal: `(uid=${tainted})`
      /\(\s*[a-zA-Z]+\s*=\$\{\s*(?:req|request|ctx)\.(?:query|body|params)/,
      // Python f-string filter: f"(uid={user_input})"
      /f['"][^'"]*\([\w]+=\{(?:request\.|flask\.request\.|user_input|username)/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'LDAP002',
    message: 'Java DirContext / LdapTemplate search filter built without LdapEncoder.filterEncode',
    severity: SecuritySeverity.Error,
    patterns: [
      /\.search\s*\(\s*[^,]+,\s*['"]\([\w]+=['"]\s*\+\s*(?:request\.|user)/,
      /\.search\s*\(\s*[^,]+,\s*String\.format\s*\(\s*['"]\([\w]+=%s\)['"]\s*,\s*(?!.*filterEncode)/,
    ],
    suppressIfNearby: [
      /LdapEncoder\.filterEncode/,
      /LdapName\b/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'LDAP003',
    message: 'Python python-ldap filter built without escape_filter_chars',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsearch_s\s*\(\s*[^,]+,\s*[^,]+,\s*['"]\([\w]+=%s\)['"]\s*%\s*(?:request\.|input|username)/,
      /\bsearch_s\s*\(\s*[^,]+,\s*[^,]+,\s*f['"]\([\w]+=\{(?!.*escape_filter_chars)/,
    ],
    suppressIfNearby: [
      /escape_filter_chars/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
];
