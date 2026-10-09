import { SanitizerDefinition, TaintThreatType } from './types';

export const KNOWN_SANITIZERS: SanitizerDefinition[] = [
  {
    name: 'Number',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    description: 'Casts input to numeric primitive, neutralizing SQL string and command injection.',
  },
  {
    name: 'parseInt',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    description: 'Parses integer value, stripping SQL quotes, operators, and path separators.',
  },
  {
    name: 'parseFloat',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    description: 'Parses floating point number, stripping injection payloads.',
  },
  {
    name: 'Math.floor',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    description: 'Numeric mathematical floor conversion, stripping injection strings.',
  },
  {
    name: 'Math.round',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    description: 'Numeric mathematical round conversion, stripping injection strings.',
  },
  {
    name: 'Math.ceil',
    neutralizesThreats: ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'],
    description: 'Numeric mathematical ceiling conversion, stripping injection strings.',
  },
  {
    name: 'escapeHtml',
    neutralizesThreats: ['XSS'], // NOTE: Does NOT neutralize SQL_INJECTION!
    description: 'HTML entity encoder. Protects against DOM XSS but DOES NOT neutralize SQL Injection.',
  },
  {
    name: 'encodeURIComponent',
    neutralizesThreats: ['XSS'], // NOTE: Does NOT neutralize SQL_INJECTION!
    description: 'URI component encoder. Does NOT neutralize SQL Injection.',
  },
  {
    name: 'escapeSql',
    neutralizesThreats: ['SQL_INJECTION'],
    description: 'SQL string escaping function.',
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
