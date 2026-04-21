import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Server-Side Template Injection (SSTI).
 *
 * An SSTI is any case where untrusted input is compiled or rendered as a
 * template rather than as data supplied to a template. The line that gets
 * devs here is subtle: `render_template(template_file, user=user_input)`
 * is safe — `render_template_string(user_input)` is not.
 *
 * Each rule targets one template engine's "compile-from-string" sink. The
 * pattern is always the same shape: a compile / render / from_string /
 * eval / parse call, with an argument that comes from `req.*`, `request.*`,
 * `params.*`, or similar user-data source.
 */

const cat = SecurityCategory.InputValidationXSS;
const ruleType = RuleType.CodeDetectable;

const tainted = String.raw`(?:req|request|ctx|context)\.(?:query|body|params|input|url)`;

const suggestion =
  'Render trusted template files with user input as data — never compile user-provided strings as a template. ' +
  'If dynamic templates are required, sandbox the engine and restrict the accessible globals.';

export const sstiRules: SecurityRule[] = [
  {
    code: 'SSTI001',
    message: 'Flask render_template_string with user-controlled template',
    severity: SecuritySeverity.Error,
    patterns: [
      /\brender_template_string\s*\(\s*(?:request\.(?:args|form|json|values)|flask\.request\.|params\.)/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSTI002',
    message: 'Jinja2 Template / from_string compiled from user input',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bjinja2?\.Template\s*\(\s*(?:request\.|flask\.request\.|params\.)/i,
      /\bEnvironment\s*\([^)]*\)[\s\S]{0,120}?\.from_string\s*\(\s*(?:request\.|flask\.request\.|params\.)/i,
      /\.from_string\s*\(\s*(?:request\.(?:args|form|json|values)|flask\.request\.)/i,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSTI003',
    message: 'Node EJS render / compile from a user-controlled template string',
    severity: SecuritySeverity.Error,
    patterns: [
      new RegExp(String.raw`\bejs\.(?:render|compile)\s*\(\s*${tainted}`),
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSTI004',
    message: 'Handlebars compile / precompile from user input',
    severity: SecuritySeverity.Error,
    patterns: [
      new RegExp(String.raw`\bHandlebars\.(?:compile|precompile)\s*\(\s*${tainted}`),
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSTI005',
    message: 'Pug / Jade render / compile from user input',
    severity: SecuritySeverity.Error,
    patterns: [
      new RegExp(String.raw`\b(?:pug|jade)\.(?:render|compile)\s*\(\s*${tainted}`),
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSTI006',
    message: 'Ruby ERB.new with user-controlled template string',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bERB\.new\s*\(\s*(?:params|request|cookies)\[/,
      /\bErubi(?:s|::)?\.new\s*\(\s*(?:params|request|cookies)\[/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSTI007',
    message: 'Java Velocity / Freemarker evaluating user-supplied template',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bVelocity\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*request\.(?:getParameter|getHeader)/,
      /\bvelocityEngine\.evaluate\s*\([^)]*request\.(?:getParameter|getHeader)/,
      /\bnew\s+Template\s*\(\s*[^,]+,\s*new\s+StringReader\s*\(\s*request\.(?:getParameter|getHeader)/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'SSTI008',
    message: 'Twig / Smarty rendering a user-supplied template (PHP)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bTwig_Environment[^;]*->render\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
      /\bSmarty[^;]*->fetch\s*\(\s*['"]string:[^'"]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    ],
    suggestion,
    category: cat,
    ruleType,
  },
];
