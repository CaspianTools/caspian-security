import { SecurityRule, SecurityCategory } from '../types';
import { authRules } from './authRules';
import { inputValidationRules } from './inputValidationRules';
import { csrfRules } from './csrfRules';
import { corsRules } from './corsRules';
import { encryptionRules } from './encryptionRules';
import { apiSecurityRules } from './apiSecurityRules';
import { databaseRules } from './databaseRules';
import { fileHandlingRules } from './fileHandlingRules';
import { secretsRules } from './secretsRules';
import { providerSecretsRules } from './providerSecretsRules';
import { ssrfRules } from './ssrfRules';
import { deserializationRules } from './deserializationRules';
import { sstiRules } from './sstiRules';
import { xxeRules } from './xxeRules';
import { jwtRules } from './jwtRules';
import { frontendRules } from './frontendRules';
import { businessLogicRules } from './businessLogicRules';
import { loggingRules } from './loggingRules';
import { dependenciesRules } from './dependenciesRules';
import { infrastructureRules } from './infrastructureRules';
import {
  kotlinAuthRules,
  kotlinXssRules,
  kotlinEncryptionRules,
  kotlinFileRules,
  kotlinDatabaseRules,
  kotlinLoggingRules,
  kotlinSecretsRules,
} from './kotlinAndroidRules';
import { securityHeadersRules } from './securityHeadersRules';

const allRulesByCategory: Record<SecurityCategory, SecurityRule[]> = {
  [SecurityCategory.AuthAccessControl]: [...authRules, ...jwtRules, ...kotlinAuthRules],
  [SecurityCategory.InputValidationXSS]: [
    ...inputValidationRules,
    ...deserializationRules,
    ...sstiRules,
    ...xxeRules,
    ...kotlinXssRules,
  ],
  [SecurityCategory.CSRFProtection]: csrfRules,
  [SecurityCategory.CORSConfiguration]: corsRules,
  [SecurityCategory.EncryptionDataProtection]: [...encryptionRules, ...kotlinEncryptionRules],
  [SecurityCategory.APISecurity]: [...apiSecurityRules, ...ssrfRules],
  [SecurityCategory.DatabaseSecurity]: [...databaseRules, ...kotlinDatabaseRules],
  [SecurityCategory.FileHandling]: [...fileHandlingRules, ...kotlinFileRules],
  [SecurityCategory.SecretsCredentials]: [...secretsRules, ...providerSecretsRules, ...kotlinSecretsRules],
  [SecurityCategory.FrontendSecurity]: frontendRules,
  [SecurityCategory.BusinessLogicPayment]: businessLogicRules,
  [SecurityCategory.LoggingMonitoring]: [...loggingRules, ...kotlinLoggingRules],
  [SecurityCategory.DependenciesSupplyChain]: dependenciesRules,
  [SecurityCategory.InfrastructureDeployment]: [...infrastructureRules, ...securityHeadersRules],
};

export function getAllRules(): SecurityRule[] {
  return Object.values(allRulesByCategory).flat();
}

export function getRulesByCategory(category: SecurityCategory): SecurityRule[] {
  return allRulesByCategory[category] || [];
}

export function getRuleByCode(code: string): SecurityRule | undefined {
  return getAllRules().find(r => r.code === code);
}

export function getCategories(): SecurityCategory[] {
  return Object.values(SecurityCategory);
}
