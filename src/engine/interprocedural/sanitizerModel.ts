import { SanitizerDefinition, TaintThreatType, SinkContext } from './types';

export const KNOWN_SANITIZERS: SanitizerDefinition[] = [
  {
    name: 'Number',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    validContexts: ['SQL_QUERY', 'COMMAND_EXEC', 'PATH_RESOLVE', 'HTML_BODY'],
    description: 'Casts input to numeric primitive. Valid for numeric SQL IDs, commands, and paths. NOT valid for HTML attributes or full URLs.',
  },
  {
    name: 'parseInt',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    validContexts: ['SQL_QUERY', 'COMMAND_EXEC', 'PATH_RESOLVE', 'HTML_BODY'],
    description: 'Parses integer value. Strips SQL quotes, operators, and injection strings.',
  },
  {
    name: 'parseFloat',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    validContexts: ['SQL_QUERY', 'COMMAND_EXEC', 'PATH_RESOLVE', 'HTML_BODY'],
    description: 'Parses floating point number, stripping injection payloads.',
  },
  {
    name: 'Math.floor',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    validContexts: ['SQL_QUERY', 'COMMAND_EXEC', 'PATH_RESOLVE', 'HTML_BODY'],
    description: 'Numeric mathematical floor conversion, stripping injection strings.',
  },
  {
    name: 'Math.round',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    validContexts: ['SQL_QUERY', 'COMMAND_EXEC', 'PATH_RESOLVE', 'HTML_BODY'],
    description: 'Numeric mathematical round conversion, stripping injection strings.',
  },
  {
    name: 'Math.ceil',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    validContexts: ['SQL_QUERY', 'COMMAND_EXEC', 'PATH_RESOLVE', 'HTML_BODY'],
    description: 'Numeric mathematical ceiling conversion, stripping injection strings.',
  },
  {
    name: 'escapeHtml',
    neutralizesThreats: ['XSS'],
    validContexts: ['HTML_BODY'],
    description: 'HTML entity encoder. Protects ONLY HTML body text. Does NOT sanitize SQL, JavaScript contexts, HTML attributes, or URLs.',
  },
  {
    name: 'escapeHtmlAttribute',
    neutralizesThreats: ['XSS'],
    validContexts: ['HTML_ATTRIBUTE'],
    description: 'HTML attribute encoder for attribute values. Does NOT sanitize JavaScript or raw URLs.',
  },
  {
    name: 'encodeURIComponent',
    neutralizesThreats: ['XSS'],
    validContexts: ['URL_COMPONENT'],
    description: 'URI component encoder. Protects URL parameter/query components. Does NOT neutralize complete URL destinations against javascript: pseudoprotocols.',
  },
  {
    name: 'isValidUrl',
    neutralizesThreats: ['XSS'],
    validContexts: ['URL_DESTINATION', 'URL_COMPONENT', 'URL_CONTEXT'],
    description: 'Validates complete URL destination, ensuring safe http/https schemes and preventing javascript: or data: injection.',
  },
  {
    name: 'sanitizeUrl',
    neutralizesThreats: ['XSS'],
    validContexts: ['URL_DESTINATION', 'URL_COMPONENT', 'URL_CONTEXT'],
    description: 'Sanitizes complete URL destination against dangerous protocols (javascript:, vbscript:, data:).',
  },
  {
    name: 'escapeSql',
    neutralizesThreats: ['SQL_INJECTION'],
    validContexts: ['SQL_QUERY'],
    description: 'SQL string escaping function. Valid ONLY in SQL query contexts.',
  },
];

export function lookupSanitizer(name: string): SanitizerDefinition | undefined {
  const normalized = name.trim().toLowerCase();
  return KNOWN_SANITIZERS.find(s => s.name.toLowerCase() === normalized);
}

export function isBuiltinSanitizer(name: string): boolean {
  return lookupSanitizer(name) !== undefined;
}

export function doesNeutralizeThreat(sanitizerName: string, threat: TaintThreatType): boolean {
  const def = lookupSanitizer(sanitizerName);
  if (!def) return false;
  return def.neutralizesThreats.includes(threat);
}

export function doesNeutralizeThreatInContext(
  sanitizerName: string,
  threat: TaintThreatType,
  context: SinkContext
): boolean {
  const def = lookupSanitizer(sanitizerName);
  if (!def) return false;
  const threatMatches = def.neutralizesThreats.includes(threat);

  // Normalize legacy URL_CONTEXT if requested
  let contextMatches = def.validContexts.includes(context);
  if (!contextMatches && context === 'URL_CONTEXT') {
    contextMatches = def.validContexts.includes('URL_DESTINATION');
  }

  return threatMatches && contextMatches;
}
