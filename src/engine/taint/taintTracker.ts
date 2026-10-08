import { ASTNode, TaintVulnerability, TaintTraceStep } from '../ast/types';

interface TaintSymbol {
  name: string;
  line: number;
  sourceExpression: string;
  rootSource: {
    name: string;
    line: number;
    expression: string;
  };
  propagationHistory: {
    line: number;
    variable: string;
    expression: string;
  }[];
}

export function performTaintAnalysis(ast: ASTNode | null, code: string): TaintVulnerability[] {
  const vulnerabilities: TaintVulnerability[] = [];
  if (!ast) return vulnerabilities;

  const taintedSymbols = new Map<string, TaintSymbol>();
  let vulnCounter = 1;

  const lines = code.split('\n');

  function getLine(node: ASTNode): number {
    return node.loc?.start?.line || 1;
  }

  function getSnippet(node: ASTNode): string {
    if (node.loc) {
      const line = node.loc.start.line - 1;
      return lines[line]?.trim() || '';
    }
    return '';
  }

  // 1. AST Visitor to detect Taint Sources and Assignments
  function inspectNode(node: any, parent?: any) {
    if (!node || typeof node !== 'object') return;

    // Detect Source: Variable Declarator with req.body / req.query / params / input
    if (node.type === 'VariableDeclarator') {
      const line = getLine(node);
      const varName = node.id?.name;
      const init = node.init;

      // Check destructuring: const { username, tenantId } = req.body
      if (node.id?.type === 'ObjectPattern' && init) {
        const initStr = getSnippet(node);
        if (/req\.(body|query|params|headers)|request\.|input/i.test(initStr)) {
          for (const prop of node.id.properties || []) {
            const propName = prop.key?.name || prop.value?.name;
            if (propName) {
              taintedSymbols.set(propName, {
                name: propName,
                line,
                sourceExpression: initStr,
                rootSource: {
                  name: propName,
                  line,
                  expression: initStr,
                },
                propagationHistory: [],
              });
            }
          }
        }
      }

      // Check direct assignment from source: const x = req.body.username
      if (varName && init) {
        const snippet = getSnippet(node);
        if (/req\.(body|query|params|headers)|request\.|payload\.|prompt\(/i.test(snippet)) {
          taintedSymbols.set(varName, {
            name: varName,
            line,
            sourceExpression: snippet,
            rootSource: {
              name: varName,
              line,
              expression: snippet,
            },
            propagationHistory: [],
          });
        }
      }

      // Propagate taint through Template Literals: const query = `SELECT ... ${username}`
      if (varName && init?.type === 'TemplateLiteral') {
        const expressions = init.expressions || [];
        for (const expr of expressions) {
          const exprName = expr.name;
          if (exprName && taintedSymbols.has(exprName)) {
            const parentSymbol = taintedSymbols.get(exprName)!;
            const snippet = getSnippet(node);

            taintedSymbols.set(varName, {
              name: varName,
              line,
              sourceExpression: snippet,
              rootSource: parentSymbol.rootSource,
              propagationHistory: [
                ...parentSymbol.propagationHistory,
                {
                  line,
                  variable: varName,
                  expression: snippet,
                },
              ],
            });
          }
        }
      }

      // Propagate taint through direct variable assignment: const alias = taintedVar;
      if (varName && init?.type === 'Identifier') {
        const initName = init.name;
        if (initName && taintedSymbols.has(initName)) {
          const parentSymbol = taintedSymbols.get(initName)!;
          const snippet = getSnippet(node);

          taintedSymbols.set(varName, {
            name: varName,
            line,
            sourceExpression: snippet,
            rootSource: parentSymbol.rootSource,
            propagationHistory: [
              ...parentSymbol.propagationHistory,
              {
                line,
                variable: varName,
                expression: snippet,
              },
            ],
          });
        }
      }
    }

    // Detect Sinks: CallExpressions
    if (node.type === 'CallExpression') {
      const line = getLine(node);
      const callee = node.callee;
      const calleeName = callee?.name || callee?.property?.name || '';
      const fullCall = getSnippet(node);

      // Check if this query is parameterized (safe query check!)
      // If 2nd argument exists and is array/params, and 1st argument is string literal with '?' or '$1'
      const isParameterized =
        node.arguments?.length >= 2 &&
        (node.arguments[0]?.type === 'Literal' && (/\?|\$\d/.test(node.arguments[0].value || '')));

      // SINK 1: SQL Injection (db.query, client.query, connection.query, session.execute)
      if (!isParameterized && (/(query|execute|raw|sql|find_by_sql)/i.test(calleeName) || /db\.query|db\.execute/i.test(fullCall))) {
        const firstArg = node.arguments?.[0];
        const argName = firstArg?.name;

        // Passed variable tainted?
        if (argName && taintedSymbols.has(argName)) {
          const taintedSym = taintedSymbols.get(argName)!;
          const root = taintedSym.rootSource;

          const steps: TaintTraceStep[] = [
            {
              stepNumber: 1,
              type: 'source',
              line: root.line,
              variable: root.name,
              expression: root.expression,
              description: `Untrusted user input ingested from request body/params.`,
            },
          ];

          // Add intermediate propagations
          taintedSym.propagationHistory.forEach((prop, idx) => {
            steps.push({
              stepNumber: steps.length + 1,
              type: 'propagation',
              line: prop.line,
              variable: prop.variable,
              expression: prop.expression,
              description: `Tainted variable concatenated or interpolated into query string without sanitization.`,
            });
          });

          // Add sink step
          steps.push({
            stepNumber: steps.length + 1,
            type: 'sink',
            line,
            expression: fullCall,
            description: `Un-parameterized query passed directly into SQL execution sink (${calleeName}).`,
          });

          vulnerabilities.push({
            id: `taint-sqli-${vulnCounter++}`,
            vulnerabilityType: 'SQL_INJECTION',
            sourceName: root.name,
            sinkName: `${calleeName}()`,
            sourceLine: root.line,
            sinkLine: line,
            taintPath: steps,
          });
        }
      }

      // SINK 2: Code Injection / Eval (eval, exec, Function)
      if (calleeName === 'eval' || calleeName === 'exec' || calleeName === 'execSync') {
        const firstArg = node.arguments?.[0];
        const argName = firstArg?.name;
        const steps: TaintTraceStep[] = [
          {
            stepNumber: 1,
            type: 'source',
            line,
            expression: fullCall,
            description: `Dynamic expression input accepted.`,
          },
          {
            stepNumber: 2,
            type: 'sink',
            line,
            expression: fullCall,
            description: `Passed directly into interpreter dynamic evaluation sink (${calleeName}).`,
          },
        ];

        vulnerabilities.push({
          id: `taint-rce-${vulnCounter++}`,
          vulnerabilityType: 'COMMAND_INJECTION',
          sourceName: argName || 'filter_formula',
          sinkName: `${calleeName}()`,
          sourceLine: line,
          sinkLine: line,
          taintPath: steps,
        });
      }
    }

    // Recurse child nodes
    for (const key in node) {
      if (key !== 'loc' && key !== 'range') {
        const child = node[key];
        if (Array.isArray(child)) {
          child.forEach(c => inspectNode(c, node));
        } else if (child && typeof child === 'object') {
          inspectNode(child, node);
        }
      }
    }
  }

  inspectNode(ast);

  return vulnerabilities;
}
