import { SecurityScoreService } from '../securityScore';
import { ResultsStore } from '../resultsStore';
import { SecuritySeverity, SecurityCategory, RuleType } from '../types';

describe('SecurityScoreService', () => {
  let resultsStore: ResultsStore;
  let scoreService: SecurityScoreService;

  beforeEach(() => {
    resultsStore = new ResultsStore();
    scoreService = new SecurityScoreService(resultsStore);
  });

  afterEach(() => {
    scoreService.dispose();
    resultsStore.dispose();
  });

  test('starts with score 100', () => {
    scoreService.recalculate();
    expect(scoreService.getScore()).toBe(100);
  });

  test('score decreases with errors', () => {
    resultsStore.setFileResults('file:///test.ts', {
      filePath: '/test.ts',
      relativePath: 'test.ts',
      languageId: 'typescript',
      issues: [
        {
          line: 0, column: 0, message: 'test', severity: SecuritySeverity.Error,
          suggestion: 'fix it', code: 'TEST001', pattern: 'test',
          category: SecurityCategory.SecretsCredentials,
        },
      ],
      scannedAt: new Date(),
    });

    scoreService.recalculate();
    expect(scoreService.getScore()).toBeLessThan(100);
  });

  test('errors penalize more than warnings', () => {
    // Set up file with 1 error
    resultsStore.setFileResults('file:///error.ts', {
      filePath: '/error.ts', relativePath: 'error.ts', languageId: 'typescript',
      issues: [{
        line: 0, column: 0, message: 'error test', severity: SecuritySeverity.Error,
        suggestion: 'fix it', code: 'TEST001', pattern: 'test',
        category: SecurityCategory.SecretsCredentials,
      }],
      scannedAt: new Date(),
    });
    scoreService.recalculate();
    const errorScore = scoreService.getScore();

    // Reset and set up file with 1 warning
    resultsStore.clearAll();
    resultsStore.setFileResults('file:///warning.ts', {
      filePath: '/warning.ts', relativePath: 'warning.ts', languageId: 'typescript',
      issues: [{
        line: 0, column: 0, message: 'warning test', severity: SecuritySeverity.Warning,
        suggestion: 'fix it', code: 'TEST002', pattern: 'test',
        category: SecurityCategory.SecretsCredentials,
      }],
      scannedAt: new Date(),
    });
    scoreService.recalculate();
    const warningScore = scoreService.getScore();

    expect(errorScore).toBeLessThan(warningScore);
  });

  test('score never goes below 0', () => {
    // Add many errors
    const issues = Array.from({ length: 100 }, (_, i) => ({
      line: i, column: 0, message: `error ${i}`, severity: SecuritySeverity.Error,
      suggestion: 'fix it', code: `TEST${i}`, pattern: 'test',
      category: SecurityCategory.SecretsCredentials as SecurityCategory,
    }));

    resultsStore.setFileResults('file:///heavy.ts', {
      filePath: '/heavy.ts', relativePath: 'heavy.ts', languageId: 'typescript',
      issues,
      scannedAt: new Date(),
    });

    scoreService.recalculate();
    expect(scoreService.getScore()).toBeGreaterThanOrEqual(0);
  });
});
