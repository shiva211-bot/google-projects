import { SanitizerDefinition, TaintThreatType, SinkContext } from './types';

export const KNOWN_SANITIZERS: SanitizerDefinition[] = [
  {
    name: 'Number',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XSS'],
    validContexts: ['SQL_QUERY', 'HTML_BODY', 'HTML_ATTRIBUTE', 'URL_CONTEXT', 'COMMAND_EXEC', 'PATH_RESOLVE'],
    description: 'Casts input to numeric primitive. Valid for numeric SQL IDs, body text, and parameters.',
  },
  {
    name: 'parseInt',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XSS'],
    validContexts: ['SQL_QUERY', 'HTML_BODY', 'HTML_ATTRIBUTE', 'URL_CONTEXT', 'COMMAND_EXEC', 'PATH_RESOLVE'],
    description: 'Parses integer value, stripping SQL quotes, operators, and script tags.',
  },
  {
    name: 'parseFloat',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XSS'],
    validContexts: ['SQL_QUERY', 'HTML_BODY', 'HTML_ATTRIBUTE', 'URL_CONTEXT', 'COMMAND_EXEC', 'PATH_RESOLVE'],
    description: 'Parses floating point number, stripping injection payloads.',
  },
  {
    name: 'Math.floor',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XSS'],
    validContexts: ['SQL_QUERY', 'HTML_BODY', 'HTML_ATTRIBUTE', 'URL_CONTEXT', 'COMMAND_EXEC', 'PATH_RESOLVE'],
    description: 'Numeric mathematical floor conversion, stripping injection strings.',
  },
  {
    name: 'Math.round',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XSS'],
    validContexts: ['SQL_QUERY', 'HTML_BODY', 'HTML_ATTRIBUTE', 'URL_CONTEXT', 'COMMAND_EXEC', 'PATH_RESOLVE'],
    description: 'Numeric mathematical round conversion, stripping injection strings.',
  },
  {
    name: 'Math.ceil',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XSS'],
    validContexts: ['SQL_QUERY', 'HTML_BODY', 'HTML_ATTRIBUTE', 'URL_CONTEXT', 'COMMAND_EXEC', 'PATH_RESOLVE'],
    description: 'Numeric mathematical ceiling conversion, stripping injection strings.',
  },
  {
    name: 'escapeHtml',
    neutralizesThreats: ['XSS'],
    validContexts: ['HTML_BODY'],
    // CRITICAL: escapeHtml DOES NOT neutralize SQL_QUERY, JAVASCRIPT_CONTEXT, or URL_CONTEXT!
    description: 'HTML entity encoder. Protects ONLY HTML body text. Does NOT sanitize SQL, JavaScript contexts, or URLs.',
  },
  {
    name: 'encodeURIComponent',
    neutralizesThreats: ['XSS'],
    validContexts: ['URL_CONTEXT'],
    // CRITICAL: encodeURIComponent is ONLY valid for URL query components!
    description: 'URI component encoder. Protects URL parameter context. Does NOT neutralize SQL, HTML body, or JS execution.',
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
  const contextMatches = def.validContexts.includes(context);
  return threatMatches && contextMatches;
}
