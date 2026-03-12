import { getAllRules, getRulesByCategory, getRuleByCode, getCategories } from '../rules';
import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

describe('Rule Registry', () => {
  let allRules: SecurityRule[];

  beforeAll(() => {
    allRules = getAllRules();
  });

  test('getAllRules returns at least 160 rules', () => {
    expect(allRules.length).toBeGreaterThanOrEqual(160);
  });

  test('getCategories returns all 14 categories', () => {
    const categories = getCategories();
    expect(categories.length).toBe(14);
    for (const cat of Object.values(SecurityCategory)) {
      expect(categories).toContain(cat);
    }
  });

  test('every category has at least 1 rule', () => {
    for (const cat of Object.values(SecurityCategory)) {
      const rules = getRulesByCategory(cat);
      expect(rules.length).toBeGreaterThanOrEqual(1);
    }
  });

  test('every rule code is unique', () => {
    const codes = allRules.map(r => r.code);
    const unique = new Set(codes);
    expect(unique.size).toBe(codes.length);
  });

  test('getRuleByCode finds every rule', () => {
    for (const rule of allRules) {
      const found = getRuleByCode(rule.code);
      expect(found).toBeDefined();
      expect(found!.code).toBe(rule.code);
    }
  });

  test('getRuleByCode returns undefined for unknown code', () => {
    expect(getRuleByCode('NONEXISTENT999')).toBeUndefined();
  });
});

describe('Rule Structure Validation', () => {
  const allRules = getAllRules();

  test.each(allRules.map(r => [r.code, r]))('%s has valid structure', (_code, rule) => {
    const r = rule as SecurityRule;

    // Required fields
    expect(typeof r.code).toBe('string');
    expect(r.code.length).toBeGreaterThan(0);
    expect(typeof r.message).toBe('string');
    expect(r.message.length).toBeGreaterThan(0);
    expect(typeof r.suggestion).toBe('string');
    expect(r.suggestion.length).toBeGreaterThan(0);

    // Enums
    expect(Object.values(SecuritySeverity)).toContain(r.severity);
    expect(Object.values(SecurityCategory)).toContain(r.category);
    expect(Object.values(RuleType)).toContain(r.ruleType);

    // Patterns
    expect(Array.isArray(r.patterns)).toBe(true);

    for (const p of r.patterns) {
      // Allow string, RegExp, or other pattern types
      const isValid = typeof p === 'string' || p instanceof RegExp || typeof p === 'object';
      expect(isValid).toBe(true);
      // Verify regex patterns don't throw
      if (p instanceof RegExp) {
        expect(() => 'test'.match(p)).not.toThrow();
      }
    }

    // Optional negative patterns
    if (r.negativePatterns) {
      expect(Array.isArray(r.negativePatterns)).toBe(true);
      for (const np of r.negativePatterns) {
        expect(typeof np === 'string' || np instanceof RegExp).toBe(true);
      }
    }

    // Optional suppressIfNearby
    if (r.suppressIfNearby) {
      expect(Array.isArray(r.suppressIfNearby)).toBe(true);
      for (const sp of r.suppressIfNearby) {
        expect(sp instanceof RegExp).toBe(true);
      }
    }

    // Optional filePatterns
    if (r.filePatterns) {
      if (r.filePatterns.include) {
        expect(Array.isArray(r.filePatterns.include)).toBe(true);
        for (const fp of r.filePatterns.include) {
          expect(fp instanceof RegExp).toBe(true);
        }
      }
      if (r.filePatterns.exclude) {
        expect(Array.isArray(r.filePatterns.exclude)).toBe(true);
      }
      if (r.filePatterns.reduceSeverityIn) {
        expect(Array.isArray(r.filePatterns.reduceSeverityIn)).toBe(true);
      }
    }
  });
});

describe('Rule Pattern Matching', () => {
  // Test a representative sample of rules with known vulnerable and safe code

  describe('AUTH001 - Hardcoded JWT secret', () => {
    const rule = getRuleByCode('AUTH001')!;

    test('matches jwt.sign with hardcoded secret', () => {
      const line = `const token = jwt.sign(payload, 'my-secret-key');`;
      expect(matchesAnyPattern(rule, line)).toBe(true);
    });

    test('does not match jwt.sign with env variable', () => {
      const line = `const token = jwt.sign(payload, process.env.JWT_SECRET);`;
      expect(matchesAnyPattern(rule, line)).toBe(false);
    });
  });

  describe('CRED001 - Hardcoded password', () => {
    const rule = getRuleByCode('CRED001')!;

    test('matches hardcoded password assignment', () => {
      const line = `const password = "admin123";`;
      expect(matchesAnyPattern(rule, line)).toBe(true);
    });

    test('matches hardcoded secret assignment', () => {
      const line = `const apiKey = "sk-1234567890abcdef";`;
      expect(matchesAnyPattern(rule, line)).toBe(true);
    });

    test('does not match env variable password', () => {
      const line = `const password = process.env.DB_PASSWORD;`;
      expect(matchesAnyPattern(rule, line)).toBe(false);
    });
  });

  describe('DB001 - SQL injection via concatenation', () => {
    const rule = getRuleByCode('DB001')!;

    test('matches string concatenation in query', () => {
      const line = `.query("SELECT * FROM users WHERE id = " + userId)`;
      expect(matchesAnyPattern(rule, line)).toBe(true);
    });

    test('matches template literal in query', () => {
      const line = '.query(`SELECT * FROM users WHERE id = ${userId}`)';
      expect(matchesAnyPattern(rule, line)).toBe(true);
    });
  });

  describe('XSS001 - innerHTML usage', () => {
    const rule = getRuleByCode('XSS001')!;

    test('matches innerHTML assignment', () => {
      const line = `element.innerHTML = userInput;`;
      expect(matchesAnyPattern(rule, line)).toBe(true);
    });

    test('matches outerHTML assignment', () => {
      const line = `element.outerHTML = content;`;
      expect(matchesAnyPattern(rule, line)).toBe(true);
    });

    test('does not match textContent', () => {
      const line = `element.textContent = userInput;`;
      expect(matchesAnyPattern(rule, line)).toBe(false);
    });
  });

  describe('CORS001 - Wildcard CORS origin', () => {
    const rule = getRuleByCode('CORS001');
    if (rule) {
      test('matches cors() with no options', () => {
        const line = `app.use(cors())`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });

      test('matches origin wildcard config', () => {
        const line = `origin: '*'`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });
    }
  });

  describe('ENC001 - Weak cryptographic algorithm', () => {
    const rule = getRuleByCode('ENC001');
    if (rule) {
      test('matches MD5 usage', () => {
        const line = `const hash = crypto.createHash('md5');`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });

      test('matches SHA1 usage', () => {
        const line = `const hash = crypto.createHash('sha1');`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });
    }
  });

  describe('FE001 - eval() usage', () => {
    const rule = getRuleByCode('FE001');
    if (rule) {
      test('matches eval call', () => {
        const line = `const result = eval(userInput);`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });
    }
  });

  describe('API001 - Missing authentication middleware', () => {
    const rule = getRuleByCode('API001');
    if (rule) {
      test('matches unprotected API route', () => {
        const line = `app.get('/api/admin', (req, res) => {`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });
    }
  });

  describe('FILE001 - Path traversal', () => {
    const rule = getRuleByCode('FILE001');
    if (rule) {
      test('matches readFile with user input', () => {
        const line = `fs.readFile(req.params.filename, 'utf-8', cb);`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });
    }
  });

  describe('CSRF001 - Form without CSRF token', () => {
    const rule = getRuleByCode('CSRF001');
    if (rule) {
      test('matches HTML form with POST method', () => {
        const line = `<form method="post" action="/transfer">`;
        expect(matchesAnyPattern(rule, line)).toBe(true);
      });
    }
  });
});

describe('Rule Category Counts', () => {
  test('Auth rules exist', () => {
    expect(getRulesByCategory(SecurityCategory.AuthAccessControl).length).toBeGreaterThanOrEqual(5);
  });

  test('XSS rules exist', () => {
    expect(getRulesByCategory(SecurityCategory.InputValidationXSS).length).toBeGreaterThanOrEqual(10);
  });

  test('Database rules exist', () => {
    expect(getRulesByCategory(SecurityCategory.DatabaseSecurity).length).toBeGreaterThanOrEqual(5);
  });

  test('Secrets rules exist', () => {
    expect(getRulesByCategory(SecurityCategory.SecretsCredentials).length).toBeGreaterThanOrEqual(5);
  });

  test('API rules exist', () => {
    expect(getRulesByCategory(SecurityCategory.APISecurity).length).toBeGreaterThanOrEqual(10);
  });

  test('Encryption rules exist', () => {
    expect(getRulesByCategory(SecurityCategory.EncryptionDataProtection).length).toBeGreaterThanOrEqual(8);
  });

  test('Frontend rules exist', () => {
    expect(getRulesByCategory(SecurityCategory.FrontendSecurity).length).toBeGreaterThanOrEqual(5);
  });
});

describe('Code-Detectable vs Informational', () => {
  const allRules = getAllRules();

  test('has code-detectable rules', () => {
    const codeRules = allRules.filter(r => r.ruleType === RuleType.CodeDetectable);
    expect(codeRules.length).toBeGreaterThanOrEqual(80);
  });

  test('has informational rules', () => {
    const infoRules = allRules.filter(r => r.ruleType === RuleType.Informational);
    expect(infoRules.length).toBeGreaterThanOrEqual(30);
  });

  test('nearly all code-detectable rules have at least one pattern', () => {
    const codeRules = allRules.filter(r => r.ruleType === RuleType.CodeDetectable);
    const emptyPatternRules = codeRules.filter(r => r.patterns.length === 0);
    // Allow up to 2 rules with empty patterns (may be placeholder rules)
    expect(emptyPatternRules.length).toBeLessThanOrEqual(2);
  });
});

describe('Kotlin/Android Rules', () => {
  const allRules = getAllRules();
  const ktRules = allRules.filter(r => r.code.startsWith('KT-'));

  test('has Kotlin rules', () => {
    expect(ktRules.length).toBeGreaterThanOrEqual(10);
  });

  test('Kotlin rules target .kt files', () => {
    for (const rule of ktRules) {
      // Kotlin rules should either have filePatterns.include for .kt or not have filePatterns
      if (rule.filePatterns?.include) {
        const targetsKt = rule.filePatterns.include.some(fp => fp.test('test.kt'));
        expect(targetsKt).toBe(true);
      }
    }
  });
});

// Helper function
function matchesAnyPattern(rule: SecurityRule, line: string): boolean {
  for (const pattern of rule.patterns) {
    if (pattern instanceof RegExp) {
      if (pattern.test(line)) { return true; }
    } else if (typeof pattern === 'string') {
      if (line.includes(pattern)) { return true; }
    }
  }
  return false;
}
