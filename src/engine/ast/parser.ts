import * as acorn from 'acorn';
import { ASTNode, ASTToken, SourceLocation } from './types';

/**
 * ESTree ECMAScript AST Parser powered by Acorn.
 * Note: Performs syntactic preparation for standard ESNext; does not claim
 * semantic TypeScript AST typing (operates on standard ECMAScript constructs).
 */
function sanitizeForAcorn(sourceCode: string): string {
  let code = sourceCode;

  // 1. Strip import type statements: import type { ... } from '...'
  code = code.replace(/import\s+type\s+[^;]+;/g, '// stripped import type');

  // 2. Strip TypeScript interface and type aliases
  code = code.replace(/(?:export\s+)?interface\s+[A-Za-z0-9_<>,\s\n]+{[^}]*}/g, '/* TS Interface */');
  code = code.replace(/(?:export\s+)?type\s+[A-Za-z0-9_<>,\s]+=[^;]+;/g, '/* TS Type */');

  // 3. Strip function return type annotations: ): Promise<void> => or ): string {
  code = code.replace(/\):\s*[A-Za-z0-9_<>[\]|,.\s]+(\s*=>|\s*\{)/g, ')$1');

  // 4. Strip variable type annotations: const x: number = 5 -> const x = 5
  code = code.replace(/(\bconst|\blet|\bvar)\s+([A-Za-z0-9_]+)\s*:\s*[A-Za-z0-9_<>[\]|,.\s]+\s*=/g, '$1 $2 =');

  // 5. Strip 'as Type' casts
  code = code.replace(/\s+as\s+[A-Za-z0-9_<>[\]|]+/g, '');

  // 6. Strip non-null assertion operators: x!.foo -> x.foo
  code = code.replace(/([A-Za-z0-9_\])])!([.[\s])/g, '$1$2');

  // 7. Strip simple JSX elements to mock function calls if present: <div ...> -> React.createElement('div')
  // We keep line numbers aligned by replacing with equal line breaks
  code = code.replace(/<([A-Za-z0-9_.]+)([^>]*)>(.*?)<\/\1>/gs, (match, tag) => {
    const linesCount = (match.match(/\n/g) || []).length;
    return `/* JSX <${tag}> */` + '\n'.repeat(linesCount);
  });
  code = code.replace(/<([A-Za-z0-9_.]+)([^>]*)\/>/g, '/* JSX self-close */');

  return code;
}

export interface ParseResult {
  ast: ASTNode | null;
  tokens: ASTToken[];
  errors: string[];
}

export function parseSourceCode(sourceCode: string, filename: string): ParseResult {
  const errors: string[] = [];
  const tokens: ASTToken[] = [];

  const sanitized = sanitizeForAcorn(sourceCode);

  try {
    const parsed = acorn.parse(sanitized, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      ranges: true,
      onToken: (tok) => {
        tokens.push({
          type: tok.type.label,
          value: sanitized.slice(tok.start, tok.end),
          start: tok.start,
          end: tok.end,
          loc: tok.loc ? {
            start: { line: tok.loc.start.line, column: tok.loc.start.column },
            end: { line: tok.loc.end.line, column: tok.loc.end.column }
          } : undefined
        });
      }
    }) as ASTNode;

    return { ast: parsed, tokens, errors };
  } catch (err: any) {
    // If strict module parse fails, try script mode
    try {
      const parsed = acorn.parse(sanitized, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        locations: true,
        ranges: true,
      }) as ASTNode;
      return { ast: parsed, tokens, errors: [] };
    } catch (innerErr: any) {
      errors.push(`AST Parser warning on ${filename}: ${innerErr.message || 'Syntax parse exception'}`);
      
      // Fallback synthetic AST representation for non-JS/TS languages like Python/Go/SQL
      const syntheticAST = createSyntheticAST(sourceCode, filename);
      return { ast: syntheticAST, tokens, errors };
    }
  }
}

/**
 * Fallback AST generator for non-JS languages or syntax edge cases
 * ensures AST-based visitors and CFG still construct structured trees.
 */
function createSyntheticAST(code: string, filename: string): ASTNode {
  const lines = code.split('\n');
  const body: ASTNode[] = [];

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();
    if (!trimmed) return;

    if (trimmed.startsWith('def ') || trimmed.startsWith('func ')) {
      body.push({
        type: 'FunctionDeclaration',
        id: { type: 'Identifier', name: trimmed.split(' ')[1]?.split('(')[0] || 'fn' },
        start: idx,
        end: idx + line.length,
        loc: {
          start: { line: lineNum, column: 0 },
          end: { line: lineNum, column: line.length }
        },
        body: { type: 'BlockStatement', body: [] }
      });
    } else if (trimmed.startsWith('if ') || trimmed.startsWith('elif ')) {
      body.push({
        type: 'IfStatement',
        start: idx,
        end: idx + line.length,
        loc: {
          start: { line: lineNum, column: 0 },
          end: { line: lineNum, column: line.length }
        },
        consequent: { type: 'BlockStatement', body: [] }
      });
    } else {
      body.push({
        type: 'ExpressionStatement',
        start: idx,
        end: idx + line.length,
        loc: {
          start: { line: lineNum, column: 0 },
          end: { line: lineNum, column: line.length }
        },
        expression: { type: 'Identifier', name: trimmed.slice(0, 30) }
      });
    }
  });

  return {
    type: 'Program',
    sourceType: 'module',
    start: 0,
    end: code.length,
    loc: {
      start: { line: 1, column: 0 },
      end: { line: lines.length, column: lines[lines.length - 1]?.length || 0 }
    },
    body
  };
}
