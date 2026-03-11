import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

const ktOnly = { include: [/\.kts?$/i] };

export const kotlinAuthRules: SecurityRule[] = [
  {
    code: 'KT-AUTH001',
    message: 'WebView has JavaScript enabled',
    severity: SecuritySeverity.Warning,
    patterns: [/\.setJavaScriptEnabled\s*\(\s*true\s*\)/],
    suggestion:
      'Only enable JavaScript in WebView if strictly necessary. Validate all content loaded and use a Content Security Policy.',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-AUTH002',
    message: 'WebView exposes native interface to JavaScript (addJavascriptInterface)',
    severity: SecuritySeverity.Error,
    patterns: [/\.addJavascriptInterface\s*\(/],
    suggestion:
      'addJavascriptInterface exposes Kotlin/Java objects to JS. Restrict to trusted, first-party content and require API level >= 17 (@JavascriptInterface annotation).',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-AUTH003',
    message: 'Broadcast sent without receiver permission',
    severity: SecuritySeverity.Warning,
    patterns: [/sendBroadcast\s*\(\s*(?!.*permission)/],
    suggestion:
      'Use sendBroadcast(intent, receiverPermission) or LocalBroadcastManager to prevent other apps from receiving sensitive broadcasts.',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-AUTH004',
    message: 'registerReceiver without RECEIVER_NOT_EXPORTED flag',
    severity: SecuritySeverity.Warning,
    patterns: [/\.registerReceiver\s*\(/],
    negativePatterns: [/RECEIVER_NOT_EXPORTED/, /RECEIVER_EXPORTED/, /LocalBroadcastManager/],
    suggestion:
      'On Android 14+, registerReceiver requires an explicit RECEIVER_EXPORTED or RECEIVER_NOT_EXPORTED flag. Use RECEIVER_NOT_EXPORTED unless the receiver must be accessible to other apps.',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-AUTH005',
    message: 'Implicit intent may leak sensitive data to other apps',
    severity: SecuritySeverity.Warning,
    patterns: [
      /Intent\s*\(\s*"[^"]*"\s*\)/,
      /Intent\s*\(\s*\)/,
    ],
    negativePatterns: [/setPackage/, /setClassName/, /setComponent/, /ComponentName/, /explicit/i],
    suggestion:
      'Implicit intents can be intercepted by other apps. Use explicit intents (specify the target component) when sending sensitive data, or set the package with setPackage().',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-AUTH006',
    message: 'Click listener without tapjacking protection (filterTouchesWhenObscured)',
    severity: SecuritySeverity.Info,
    patterns: [/setOnClickListener/i, /setOnTouchListener/i],
    suppressIfNearby: [/filterTouchesWhenObscured/i, /FILTER_TOUCHES_WHEN_OBSCURED/],
    suggestion:
      'Set android:filterTouchesWhenObscured="true" on sensitive UI elements or call setFilterTouchesWhenObscured(true) to prevent tapjacking attacks where a malicious overlay intercepts touches.',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.Informational,
    filePatterns: ktOnly,
  },
];

export const kotlinXssRules: SecurityRule[] = [
  {
    code: 'KT-XSS001',
    message: 'WebView file access enabled — allows file:// URI access',
    severity: SecuritySeverity.Warning,
    patterns: [/\.setAllowFileAccess\s*\(\s*true\s*\)/],
    suggestion:
      'setAllowFileAccess(true) lets web content read local files. Set to false unless your app explicitly requires it, and restrict to trusted origins.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-XSS002',
    message: 'WebView content access enabled — content:// URIs accessible from web content',
    severity: SecuritySeverity.Warning,
    patterns: [/\.setAllowContentAccess\s*\(\s*true\s*\)/],
    suggestion:
      'setAllowContentAccess(true) allows web content to access content providers via content:// URIs. Set to false unless your app explicitly needs this, and restrict to trusted content.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-XSS003',
    message: 'WebView allows mixed content — HTTP resources loaded on HTTPS pages',
    severity: SecuritySeverity.Warning,
    patterns: [
      /MIXED_CONTENT_ALWAYS_ALLOW/,
      /setMixedContentMode\s*\(\s*0\s*\)/,
    ],
    suggestion:
      'MIXED_CONTENT_ALWAYS_ALLOW lets HTTP resources load on HTTPS pages, enabling man-in-the-middle attacks. Use MIXED_CONTENT_NEVER_ALLOW or MIXED_CONTENT_COMPATIBILITY_MODE.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-XSS004',
    message: 'WebView SSL error handler overridden — certificate validation bypassed',
    severity: SecuritySeverity.Error,
    patterns: [
      /onReceivedSslError[\s\S]*?\.proceed\s*\(/,
      /SslErrorHandler.*\.proceed\s*\(/,
      /handler\.proceed\s*\(\s*\)/,
    ],
    suppressIfNearby: [/handler\.cancel\s*\(/, /super\.onReceivedSslError/],
    suggestion:
      'Calling handler.proceed() in onReceivedSslError bypasses SSL certificate validation, making the app vulnerable to man-in-the-middle attacks. Always call handler.cancel() for invalid certificates in production.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinEncryptionRules: SecurityRule[] = [
  {
    code: 'KT-ENC001',
    message: 'Insecure random number generator (java.util.Random)',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\bnew\s+Random\s*\(/,
      /\bRandom\s*\(\s*\)\b/,
      /java\.util\.Random\s*\(/,
    ],
    negativePatterns: [/SecureRandom/],
    suggestion:
      'Use java.security.SecureRandom for any security-sensitive randomness (tokens, session IDs, salts). java.util.Random is predictable.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-ENC002',
    message: 'Unencrypted SharedPreferences — may expose sensitive data',
    severity: SecuritySeverity.Warning,
    patterns: [/getSharedPreferences\s*\(/],
    negativePatterns: [/EncryptedSharedPreferences/i],
    suggestion:
      'Use androidx.security.crypto.EncryptedSharedPreferences for any sensitive data (tokens, credentials, PII). Plain SharedPreferences are stored unencrypted on disk.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-ENC003',
    message: 'Hardcoded encryption key — secret visible in source code',
    severity: SecuritySeverity.Error,
    patterns: [
      /SecretKeySpec\s*\(\s*"[^"]+"/,
      /SecretKeySpec\s*\(\s*'[^']+'/,
      /SecretKeySpec\s*\(\s*byteArrayOf\s*\(/,
    ],
    suggestion:
      'Never hardcode encryption keys in source code. Use Android Keystore to generate and store keys securely, or derive keys from user credentials using PBKDF2/Argon2.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-ENC004',
    message: 'Weak cryptographic algorithm — use AES-GCM or ChaCha20',
    severity: SecuritySeverity.Warning,
    patterns: [
      /Cipher\.getInstance\s*\(\s*"(?:DES|RC4|Blowfish|AES\/ECB)/i,
      /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"/i,
    ],
    negativePatterns: [/checksum/i, /fingerprint/i, /etag/i],
    suggestion:
      'DES, RC4, Blowfish, and AES/ECB are weak or insecure. Use AES/GCM/NoPadding for encryption and SHA-256+ for hashing. MD5 and SHA-1 are broken for security purposes.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-ENC005',
    message: 'Cleartext traffic may be permitted — data sent unencrypted',
    severity: SecuritySeverity.Warning,
    patterns: [
      /cleartextTrafficPermitted\s*=\s*["']?true/i,
      /usesCleartextTraffic\s*=\s*true/i,
      /android:usesCleartextTraffic\s*=\s*["']true["']/i,
    ],
    suggestion:
      'Cleartext (HTTP) traffic is vulnerable to interception. Set cleartextTrafficPermitted to false in your Network Security Configuration and use HTTPS for all API calls.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.CodeDetectable,
    filePatterns: { include: [/\.kts?$/i, /\.xml$/i] },
  },
  {
    code: 'KT-ENC006',
    message: 'HTTP client without certificate pinning — vulnerable to MitM with rogue CA',
    severity: SecuritySeverity.Warning,
    patterns: [
      /OkHttpClient\.Builder\s*\(/,
      /OkHttpClient\s*\(/,
      /Retrofit\.Builder\s*\(/,
    ],
    suppressIfNearby: [/CertificatePinner/i, /certificatePinner/i, /\.sslSocketFactory\s*\(/],
    suggestion:
      'Configure certificate pinning with OkHttp CertificatePinner or Network Security Configuration to prevent man-in-the-middle attacks using compromised certificate authorities.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.Informational,
    filePatterns: ktOnly,
  },
];

export const kotlinFileRules: SecurityRule[] = [
  {
    code: 'KT-FILE001',
    message: 'File created with world-readable or world-writable mode',
    severity: SecuritySeverity.Error,
    patterns: [/MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/],
    suggestion:
      'MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE are deprecated and insecure. Use MODE_PRIVATE (0) and share data via ContentProvider or FileProvider instead.',
    category: SecurityCategory.FileHandling,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-FILE002',
    message: 'External storage access — data is not encrypted and accessible to other apps',
    severity: SecuritySeverity.Warning,
    patterns: [
      /getExternalStorageDirectory\s*\(/,
      /Environment\.getExternalStorage/,
    ],
    suggestion:
      'Prefer app-specific external storage (getExternalFilesDir) or internal storage for sensitive data. External storage is readable by any app with READ_EXTERNAL_STORAGE permission.',
    category: SecurityCategory.FileHandling,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinDatabaseRules: SecurityRule[] = [
  {
    code: 'KT-DB001',
    message: 'Room @RawQuery — ensure inputs are not user-controlled',
    severity: SecuritySeverity.Warning,
    patterns: [/@RawQuery/],
    suggestion:
      'Raw queries bypass Room\'s compile-time SQL verification. If user input drives the query, use parameterised queries (@Query with :param bindings) to prevent SQL injection.',
    category: SecurityCategory.DatabaseSecurity,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinLoggingRules: SecurityRule[] = [
  {
    code: 'KT-LOG001',
    message: 'Android log statement may expose sensitive data in production',
    severity: SecuritySeverity.Info,
    patterns: [
      /\bLog\.[dvie]\s*\(/,
      /\bLog\.wtf\s*\(/,
    ],
    suggestion:
      'Strip or guard debug/verbose log statements in release builds using ProGuard rules or a logging wrapper that respects BuildConfig.DEBUG. Logs are readable by other apps on rooted devices and via adb.',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-LOG002',
    message: 'Sensitive data copied to clipboard — accessible to other apps',
    severity: SecuritySeverity.Warning,
    patterns: [
      /ClipData\.newPlainText\s*\(.*(?:password|token|secret|key|ssn|credit)/i,
      /clipboardManager.*(?:password|token|secret|key|credential)/i,
    ],
    suggestion:
      'Avoid copying sensitive data (passwords, tokens, keys) to the clipboard. On Android 12 and below, any app can read clipboard contents. Use secure input fields or in-app copy mechanisms instead.',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinSecretsRules: SecurityRule[] = [
  {
    code: 'KT-CRED001',
    message: 'Hardcoded API key or password in Kotlin source',
    severity: SecuritySeverity.Error,
    patterns: [
      /(?:API_KEY|apiKey|api_key|SECRET_KEY|secretKey|PASSWORD|password)\s*[:=]\s*"[^"]{8,}"/,
      /(?:API_KEY|apiKey|api_key|SECRET_KEY|secretKey|PASSWORD|password)\s*[:=]\s*'[^']{8,}'/,
    ],
    negativePatterns: [
      /BuildConfig\./,
      /getString\s*\(/,
      /System\.getenv/,
      /getenv\s*\(/,
      /TODO/i,
      /PLACEHOLDER/i,
      /example/i,
    ],
    suggestion:
      'Never hardcode API keys, secrets, or passwords in source code. Use BuildConfig fields, Android Keystore, or encrypted SharedPreferences to store credentials securely.',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];
