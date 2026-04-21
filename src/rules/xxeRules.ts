import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * XML External Entity (XXE) rules.
 *
 * XXE is what happens when an XML parser resolves `<!ENTITY xxe SYSTEM
 * "file:///etc/passwd">` inside user-supplied XML. The fix in every
 * language is the same — tell the parser to disable DTD processing and
 * external-entity resolution before handing it the payload.
 *
 * Detection targets the *parser instantiation* with unsafe defaults /
 * missing hardening calls, rather than the `parse()` call itself. That's
 * where the bug is: the call to `parse` is harmless if the parser has been
 * configured securely upstream.
 */

const cat = SecurityCategory.InputValidationXSS;
const ruleType = RuleType.CodeDetectable;

// If any of these hardening patterns are within ±3 lines, we treat the
// parser as hardened and suppress the finding.
const hardenedNearby: RegExp[] = [
  /setFeature\s*\(\s*['"]http:\/\/apache\.org\/xml\/features\/(?:disallow-doctype-decl|nonvalidating\/load-(?:external-dtd|dtd-grammar))['"]\s*,\s*(?:true|false)\s*\)/,
  /setFeature\s*\(\s*['"]http:\/\/xml\.org\/sax\/features\/external-(?:general|parameter)-entities['"]\s*,\s*false\s*\)/,
  /setExpandEntityReferences\s*\(\s*false\s*\)/,
  /setXIncludeAware\s*\(\s*false\s*\)/,
  /\.XmlResolver\s*=\s*null/,
  /DtdProcessing\.(?:Prohibit|Ignore)/,
  /resolve_entities\s*=\s*False/,
  /no_network\s*=\s*True/,
  /defusedxml/,
  /libxml_disable_entity_loader\s*\(\s*true\s*\)/,
  /LIBXML_NONET/,
];

export const xxeRules: SecurityRule[] = [
  {
    code: 'XXE001',
    message: 'Java DocumentBuilderFactory without XXE hardening',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bDocumentBuilderFactory\.newInstance\s*\(\s*\)/,
    ],
    suppressIfNearby: hardenedNearby,
    suggestion:
      'Before calling newDocumentBuilder(), set: ' +
      'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); ' +
      'factory.setFeature("http://xml.org/sax/features/external-general-entities", false); ' +
      'factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false); ' +
      'factory.setXIncludeAware(false); factory.setExpandEntityReferences(false).',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE002',
    message: 'Java SAXParserFactory without XXE hardening',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bSAXParserFactory\.newInstance\s*\(\s*\)/,
    ],
    suppressIfNearby: hardenedNearby,
    suggestion:
      'Call factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); ' +
      'factory.setFeature("http://xml.org/sax/features/external-general-entities", false); ' +
      'factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false).',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE003',
    message: 'Java XMLInputFactory without external-entity / DTD lockdown',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bXMLInputFactory\.newInstance\s*\(\s*\)/,
      /\bXMLInputFactory\.newFactory\s*\(\s*\)/,
    ],
    suppressIfNearby: hardenedNearby,
    suggestion:
      'Call factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false); ' +
      'factory.setProperty(XMLInputFactory.SUPPORT_DTD, false).',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE004',
    message: 'Python lxml.etree.fromstring / parse without a safe parser',
    severity: SecuritySeverity.Error,
    patterns: [
      /\blxml\.etree\.(?:fromstring|parse|XML|ElementTree|iterparse)\s*\(/,
      /\betree\.(?:fromstring|parse|XML|iterparse)\s*\(/,
    ],
    suppressIfNearby: [
      ...hardenedNearby,
      /XMLParser\s*\([^)]*resolve_entities\s*=\s*False/,
      /XMLParser\s*\([^)]*no_network\s*=\s*True/,
      /from\s+defusedxml/,
    ],
    suggestion:
      'Pass a hardened parser: etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, load_dtd=False). ' +
      'Better yet, use the `defusedxml` library — it is a drop-in replacement that is safe by default.',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE005',
    message: 'Python xml.etree.ElementTree / xml.sax — use defusedxml instead',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\bxml\.etree\.ElementTree\.(?:parse|fromstring|iterparse)\s*\(/,
      /\bxml\.sax\.(?:parse|parseString|make_parser)\s*\(/,
      /\bxml\.dom\.minidom\.(?:parse|parseString)\s*\(/,
    ],
    suppressIfNearby: [
      /from\s+defusedxml/,
      /defusedxml\./,
    ],
    suggestion:
      'Stdlib XML parsers are vulnerable to billion-laughs / XXE. Switch to `defusedxml` — ' +
      '`from defusedxml import ElementTree as ET` — which has the same API but safe defaults.',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE006',
    message: '.NET XmlDocument / XmlTextReader without XmlResolver = null',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bnew\s+XmlDocument\s*\(\s*\)/,
      /\bnew\s+XmlTextReader\s*\(/,
    ],
    suppressIfNearby: hardenedNearby,
    suggestion:
      'Immediately set `.XmlResolver = null` on the newly created XmlDocument / XmlTextReader — the ' +
      'default resolver fetches external DTDs. On .NET 4.5.2+, prefer XmlReader.Create with ' +
      'XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }.',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE007',
    message: '.NET XmlReaderSettings.DtdProcessing is Parse (unsafe)',
    severity: SecuritySeverity.Error,
    patterns: [
      /DtdProcessing\s*=\s*DtdProcessing\.Parse/,
    ],
    suggestion:
      'Set DtdProcessing = DtdProcessing.Prohibit (or Ignore). Parse allows DTDs — required only for trusted ' +
      'legacy XML formats.',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE008',
    message: 'PHP simplexml / DOMDocument without libxml_disable_entity_loader (pre-PHP 8 era code)',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\bsimplexml_load_(?:string|file)\s*\(/,
      /\bDOMDocument\s*\(\s*\)/,
    ],
    suppressIfNearby: [
      /libxml_disable_entity_loader\s*\(\s*true\s*\)/,
      /LIBXML_NONET/,
      /LIBXML_DTDLOAD/,
      /PHP_VERSION_ID\s*>=\s*80000/,
    ],
    suggestion:
      'PHP 8.0 made `libxml_disable_entity_loader` a no-op and changed the default. For PHP < 8 call ' +
      '`libxml_disable_entity_loader(true)` before parsing, and pass `LIBXML_NONET` to the parse call.',
    category: cat,
    ruleType,
  },
  {
    code: 'XXE009',
    message: 'Node libxmljs parseXml with noent: true (enables entity expansion)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\blibxmljs2?\.parseXml\s*\([^)]*noent\s*:\s*true/,
      /\blibxmljs2?\.parseXmlString\s*\([^)]*noent\s*:\s*true/,
    ],
    suggestion:
      '`noent: true` tells libxml2 to substitute entities — exactly the feature XXE exploits. Remove it ' +
      'or set `noent: false` (the default).',
    category: cat,
    ruleType,
  },
];
