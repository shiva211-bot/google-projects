import { ASTNode, ASTToken, HalsteadMetrics } from '../ast/types';

export function calculateHalsteadMetrics(tokens: ASTToken[], code: string): HalsteadMetrics {
  const operators = new Set<string>();
  const operands = new Set<string>();

  let totalOperators = 0;
  let totalOperands = 0;

  const OPERATOR_TYPES = new Set([
    '=', '+=', '-=', '*=', '/=', '==', '===', '!=', '!==',
    '<', '>', '<=', '>=', '+', '-', '*', '/', '%', '++', '--',
    '&&', '||', '!', '??', '?', ':', '.', ',', ';',
    '(', ')', '[', ']', '{', '}', '=>',
  ]);

  const KEYWORD_OPERATORS = new Set([
    'return', 'if', 'else', 'for', 'while', 'do', 'switch', 'case',
    'try', 'catch', 'finally', 'throw', 'new', 'typeof', 'instanceof',
    'in', 'delete', 'void', 'await', 'async', 'const', 'let', 'var', 'function',
  ]);

  tokens.forEach((tok) => {
    const val = tok.value;
    if (OPERATOR_TYPES.has(val) || KEYWORD_OPERATORS.has(val)) {
      operators.add(val);
      totalOperators++;
    } else if (tok.type === 'name' || tok.type === 'num' || tok.type === 'string') {
      operands.add(val);
      totalOperands++;
    }
  });

  // Guard against division by zero on empty inputs
  const n1 = Math.max(1, operators.size);
  const n2 = Math.max(1, operands.size);
  const N1 = Math.max(1, totalOperators);
  const N2 = Math.max(1, totalOperands);

  const vocabulary = n1 + n2;
  const length = N1 + N2;
  const calculatedLength = Math.round(n1 * Math.log2(n1) + n2 * Math.log2(n2));
  const volume = Number((length * Math.log2(vocabulary)).toFixed(2));
  const difficulty = Number(((n1 / 2) * (N2 / n2)).toFixed(2));
  const effort = Number((difficulty * volume).toFixed(2));
  const timeSeconds = Number((effort / 18).toFixed(2));
  const bugsDelivered = Number((volume / 3000).toFixed(3));

  return {
    distinctOperators: n1,
    distinctOperands: n2,
    totalOperators: N1,
    totalOperands: N2,
    vocabulary,
    length,
    calculatedLength,
    volume,
    difficulty,
    effort,
    timeSeconds,
    bugsDelivered,
  };
}

export function calculateMaintainabilityIndex(
  volume: number,
  cyclomaticComplexity: number,
  linesOfCode: number
): number {
  // SEI Standard Maintainability Index Formula:
  // MI = max(0, (171 - 5.2 * ln(V) - 0.23 * CC - 16.2 * ln(LOC)) * 100 / 171)
  const safeV = Math.max(1, volume);
  const safeLOC = Math.max(1, linesOfCode);

  const rawMI = 171 - (5.2 * Math.log(safeV)) - (0.23 * cyclomaticComplexity) - (16.2 * Math.log(safeLOC));
  const normalized = (rawMI * 100) / 171;

  return Math.max(0, Math.min(100, Math.round(normalized)));
}

export function calculateCognitiveComplexity(ast: ASTNode | null): number {
  let complexity = 0;

  function traverse(node: any, nestingLevel: number) {
    if (!node || typeof node !== 'object') return;

    let currentNesting = nestingLevel;

    // Control flow structures increment complexity + nesting penalty
    if (
      node.type === 'IfStatement' ||
      node.type === 'ForStatement' ||
      node.type === 'ForInStatement' ||
      node.type === 'ForOfStatement' ||
      node.type === 'WhileStatement' ||
      node.type === 'DoWhileStatement' ||
      node.type === 'CatchClause'
    ) {
      complexity += (1 + nestingLevel);
      currentNesting = nestingLevel + 1;
    } else if (node.type === 'ConditionalExpression') {
      // Ternary ? : operator
      complexity += (1 + nestingLevel);
    } else if (node.type === 'LogicalExpression') {
      // && or ||
      complexity += 1;
    }

    // Traverse children
    for (const key in node) {
      if (key !== 'loc' && key !== 'range') {
        const child = node[key];
        if (Array.isArray(child)) {
          child.forEach(c => traverse(c, currentNesting));
        } else if (child && typeof child === 'object') {
          traverse(child, currentNesting);
        }
      }
    }
  }

  if (ast) {
    traverse(ast, 0);
  }

  return complexity;
}
