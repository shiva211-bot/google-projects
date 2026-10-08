import { ASTNode } from '../ast/types';
import { CallGraph } from './callGraph';
import { doesNeutralizeThreat, lookupSanitizer } from './sanitizerModel';
import { 
  InterproceduralTaintVulnerability, 
  InterproceduralPathStep, 
  TaintThreatType 
} from './types';

interface TaintedVariable {
  name: string;
  scope: string; // 'global' or function name
  threat: TaintThreatType;
  sanitized: boolean;
  sanitizerName?: string;
  sanitizerLine?: number;
  properties?: Set<string>; // If object, which properties are tainted
  history: InterproceduralPathStep[];
}

export function performInterproceduralTaintAnalysis(
  ast: ASTNode | null,
  filename = 'source.js'
): InterproceduralTaintVulnerability[] {
  const vulnerabilities: InterproceduralTaintVulnerability[] = [];
  if (!ast) return vulnerabilities;

  const callGraph = new CallGraph(ast);
  const taintedVars = new Map<string, TaintedVariable>();
  let vulnCount = 1;

  function makeKey(scope: string, varName: string): string {
    return `${scope}::${varName}`;
  }

  function getVar(scope: string, varName: string): TaintedVariable | undefined {
    return taintedVars.get(makeKey(scope, varName)) || taintedVars.get(makeKey('global', varName));
  }

  function extractMemberString(expr: any): string {
    if (!expr) return '';
    if (expr.type === 'Identifier') return expr.name;
    if (expr.type === 'MemberExpression') {
      const obj = extractMemberString(expr.object);
      const prop = expr.property?.name || expr.property?.value || '';
      return obj ? `${obj}.${prop}` : prop;
    }
    return '';
  }

  function evaluateExpressionTaint(
    expr: any, 
    scope: string,
    visitedFns = new Set<string>()
  ): { isTainted: boolean; history: InterproceduralPathStep[]; isSanitized: boolean } {
    if (!expr) return { isTainted: false, history: [], isSanitized: false };

    // Case 1: Direct identifier: id
    if (expr.type === 'Identifier') {
      const t = getVar(scope, expr.name);
      if (t) {
        return { isTainted: true, history: t.history, isSanitized: t.sanitized };
      }
    }

    // Case 2: TemplateLiteral: `SELECT ... ${id}`
    if (expr.type === 'TemplateLiteral') {
      for (const exp of expr.expressions || []) {
        const sub = evaluateExpressionTaint(exp, scope, visitedFns);
        if (sub.isTainted) {
          const line = expr.loc?.start?.line || 1;
          const step: InterproceduralPathStep = {
            stepNumber: sub.history.length + 1,
            type: 'TEMPLATE',
            line,
            function: scope !== 'global' ? scope : undefined,
            functionName: scope,
            description: `Interpolated into template literal string`,
          };
          return { isTainted: true, history: [...sub.history, step], isSanitized: sub.isSanitized };
        }
      }
    }

    // Case 3: BinaryExpression (+): 'SELECT ...' + id
    if (expr.type === 'BinaryExpression' && expr.operator === '+') {
      const left = evaluateExpressionTaint(expr.left, scope, visitedFns);
      if (left.isTainted) return left;
      const right = evaluateExpressionTaint(expr.right, scope, visitedFns);
      if (right.isTainted) return right;
    }

    // Case 4: MemberExpression: direct source or data.query / input.query
    if (expr.type === 'MemberExpression') {
      const objStr = extractMemberString(expr);

      // Case 4A: Direct untrusted source: req.body.name / req.query.id / req.params.id
      if (/req\.(body|query|params|headers)|request\.|input/i.test(objStr)) {
        const line = expr.loc?.start?.line || 1;
        const step: InterproceduralPathStep = {
          stepNumber: 1,
          type: 'SOURCE',
          line,
          function: scope !== 'global' ? scope : undefined,
          functionName: scope,
          symbol: objStr,
          description: `Tainted input ingested from ${objStr}`,
        };
        return { isTainted: true, history: [step], isSanitized: false };
      }

      // Case 4B: Member of tainted object: data.query
      const objName = expr.object?.name;
      const propName = expr.property?.name || expr.property?.value;
      if (objName) {
        const t = getVar(scope, objName);
        if (t && (t.properties?.has(propName) || !t.properties)) {
          const line = expr.loc?.start?.line || 1;
          const step: InterproceduralPathStep = {
            stepNumber: t.history.length + 1,
            type: 'PROPERTY_ACCESS',
            line,
            function: scope !== 'global' ? scope : undefined,
            functionName: scope,
            symbol: `${objName}.${propName}`,
            description: `Accessed object property '${objName}.${propName}'`,
          };
          return { isTainted: true, history: [...t.history, step], isSanitized: t.sanitized };
        }
      }
    }

    // Case 5: CallExpression: Sanitizers or User-Defined Functions
    if (expr.type === 'CallExpression') {
      const calleeName = extractCalleeName(expr.callee);
      const isUserFunction = calleeName ? callGraph.getFunction(calleeName) !== undefined : false;

      // Sanitizer Call: Number(id) / parseInt(id) / escapeHtml(id)
      const isKnownSanitizer = calleeName && !isUserFunction && (
        lookupSanitizer(calleeName) !== undefined ||
        calleeName.toLowerCase().includes('sanitize') ||
        calleeName.toLowerCase().includes('escape')
      );

      if (isKnownSanitizer && expr.arguments?.length > 0) {
        const arg0 = expr.arguments[0];
        const argEval = evaluateExpressionTaint(arg0, scope, visitedFns);
        if (argEval.isTainted) {
          const neutralizesSQL = doesNeutralizeThreat(calleeName, 'SQL_INJECTION') ||
            calleeName.toLowerCase().includes('sanitize');
          const line = expr.loc?.start?.line || 1;
          const step: InterproceduralPathStep = {
            stepNumber: argEval.history.length + 1,
            type: 'SANITIZER',
            line,
            function: scope !== 'global' ? scope : undefined,
            functionName: scope,
            symbol: calleeName,
            description: neutralizesSQL
              ? `Passed through sanitizer '${calleeName}()' (Neutralizes SQL Injection: TAINT -> SANITIZER -> CLEAN)`
              : `Passed through '${calleeName}()' (Does NOT neutralize SQL Injection: REMAYS TAINTED)`,
          };
          return {
            isTainted: true,
            isSanitized: neutralizesSQL ? true : argEval.isSanitized,
            history: [...argEval.history, step],
          };
        }
      }

      // User function call returning an expression: return f(x);
      if (isUserFunction && calleeName && !visitedFns.has(calleeName)) {
        const nextVisited = new Set(visitedFns);
        nextVisited.add(calleeName);
        const targetFn = callGraph.getFunction(calleeName)!;
        for (const retNode of targetFn.returnNodes) {
          const retEval = evaluateExpressionTaint(retNode, calleeName, nextVisited);
          if (retEval.isTainted) {
            const stepRet: InterproceduralPathStep = {
              stepNumber: retEval.history.length + 1,
              type: 'RETURN',
              line: retNode.loc?.start?.line || targetFn.endLine,
              function: calleeName,
              functionName: calleeName,
              description: `Returned from function '${calleeName}()'`,
            };
            return {
              isTainted: true,
              isSanitized: retEval.isSanitized,
              history: [...retEval.history, stepRet],
            };
          }
        }
      }
    }

    return { isTainted: false, history: [], isSanitized: false };
  }

  function extractCalleeName(callee: any): string | null {
    if (!callee) return null;
    if (callee.type === 'Identifier') return callee.name;
    if (callee.type === 'MemberExpression') {
      const obj = callee.object?.name || '';
      const prop = callee.property?.name || '';
      return obj ? `${obj}.${prop}` : prop;
    }
    return null;
  }

  // 1. Initial Pass: Ingest Sources, Object Literals, and Local Destructuring
  function scanScope(node: any, currentScope = 'global') {
    if (!node || typeof node !== 'object') return;

    let nextScope = currentScope;
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      nextScope = node.id.name;
    } else if (
      node.type === 'VariableDeclarator' &&
      node.id?.name &&
      (node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')
    ) {
      nextScope = node.id.name;
    }

    // Check variable declarator
    if (node.type === 'VariableDeclarator') {
      const line = node.loc?.start?.line || 1;
      const varName = node.id?.name;
      const init = node.init;

      // Pattern A: Direct source assignment: const id = req.query.id
      if (varName && init) {
        if (init.type === 'MemberExpression') {
          const objStr = extractMemberString(init);
          if (/req\.(body|query|params|headers)|request\.|input/i.test(objStr)) {
            const step: InterproceduralPathStep = {
              stepNumber: 1,
              type: 'SOURCE',
              line,
              function: currentScope !== 'global' ? currentScope : undefined,
              functionName: currentScope,
              symbol: objStr,
              description: `Tainted input ingested from ${objStr}`,
            };

            taintedVars.set(makeKey(currentScope, varName), {
              name: varName,
              scope: currentScope,
              threat: 'SQL_INJECTION',
              sanitized: false,
              history: [step],
            });
          }
        }

        // Pattern B: Object creation: const input = { query: `... ${req.query.id}` }
        if (init.type === 'ObjectExpression') {
          const taintedProps = new Set<string>();
          const initialHistory: InterproceduralPathStep[] = [];

          for (const prop of init.properties || []) {
            const propName = prop.key?.name || prop.key?.value;
            if (propName && prop.value) {
              // Direct source in property value: `... ${req.query.id}`
              let propEval = evaluateExpressionTaint(prop.value, currentScope);
              
              // Also check if prop.value directly contains req.query.id
              if (!propEval.isTainted && prop.value.type === 'TemplateLiteral') {
                for (const expr of prop.value.expressions || []) {
                  const mStr = extractMemberString(expr);
                  if (/req\.(body|query|params|headers)|request\.|input/i.test(mStr)) {
                    const stepSrc: InterproceduralPathStep = {
                      stepNumber: 1,
                      type: 'SOURCE',
                      line: expr.loc?.start?.line || line,
                      function: currentScope !== 'global' ? currentScope : undefined,
                      functionName: currentScope,
                      symbol: mStr,
                      description: `Tainted input ingested from ${mStr}`,
                    };
                    const stepTpl: InterproceduralPathStep = {
                      stepNumber: 2,
                      type: 'TEMPLATE',
                      line,
                      function: currentScope !== 'global' ? currentScope : undefined,
                      functionName: currentScope,
                      description: `Interpolated into template literal string`,
                    };
                    propEval = {
                      isTainted: true,
                      isSanitized: false,
                      history: [stepSrc, stepTpl],
                    };
                    break;
                  }
                }
              }

              if (propEval.isTainted) {
                taintedProps.add(propName);
                initialHistory.push(...propEval.history);
                initialHistory.push({
                  stepNumber: initialHistory.length + 1,
                  type: 'OBJECT_CREATION',
                  line,
                  function: currentScope !== 'global' ? currentScope : undefined,
                  functionName: currentScope,
                  symbol: `${varName}.${propName}`,
                  description: `Object '${varName}' instantiated with tainted property '${propName}'`,
                });
              }
            }
          }

          if (taintedProps.size > 0) {
            taintedVars.set(makeKey(currentScope, varName), {
              name: varName,
              scope: currentScope,
              threat: 'SQL_INJECTION',
              sanitized: false,
              properties: taintedProps,
              history: initialHistory,
            });
          }
        }

        // Pattern C: Destructuring from source: const { username } = req.body;
        if (node.id?.type === 'ObjectPattern' && init) {
          const initStr = extractMemberString(init);
          if (/req\.(body|query|params|headers)|request\.|input/i.test(initStr)) {
            for (const prop of node.id.properties || []) {
              const propName = prop.key?.name || prop.value?.name;
              if (propName) {
                const step: InterproceduralPathStep = {
                  stepNumber: 1,
                  type: 'SOURCE',
                  line,
                  function: currentScope !== 'global' ? currentScope : undefined,
                  functionName: currentScope,
                  symbol: `${initStr}.${propName}`,
                  description: `Tainted input ingested via destructuring from ${initStr}`,
                };

                taintedVars.set(makeKey(currentScope, propName), {
                  name: propName,
                  scope: currentScope,
                  threat: 'SQL_INJECTION',
                  sanitized: false,
                  history: [step],
                });
              }
            }
          }
        }
      }
    }

    for (const key in node) {
      if (key !== 'loc' && typeof node[key] === 'object') {
        scanScope(node[key], nextScope);
      }
    }
  }

  scanScope(ast, 'global');

  // 2. Fixed-Point Interprocedural Propagation (Iterations up to 10 until fixed-point)
  let changed = true;
  let iterations = 0;

  while (changed && iterations < 10) {
    changed = false;
    iterations++;

    // Subpass A: Local variable aliasing & destructuring in all scopes
    function scanLocalAliases(node: any, currentScope = 'global') {
      if (!node || typeof node !== 'object') return;

      let nextScope = currentScope;
      if (node.type === 'FunctionDeclaration' && node.id?.name) {
        nextScope = node.id.name;
      } else if (
        node.type === 'VariableDeclarator' &&
        node.id?.name &&
        (node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')
      ) {
        nextScope = node.id.name;
      }

      if (node.type === 'VariableDeclarator') {
        const line = node.loc?.start?.line || 1;
        const varName = node.id?.name;
        const init = node.init;

        // Case: const localAlias = searchTerm; (Aliasing)
        if (varName && init?.type === 'Identifier') {
          const sourceTaint = getVar(currentScope, init.name);
          const targetKey = makeKey(currentScope, varName);

          if (sourceTaint && !taintedVars.has(targetKey)) {
            const step: InterproceduralPathStep = {
              stepNumber: sourceTaint.history.length + 1,
              type: 'PROPAGATION',
              line,
              function: currentScope !== 'global' ? currentScope : undefined,
              functionName: currentScope,
              symbol: varName,
              description: `Aliased variable '${varName}' inherits taint from '${init.name}'`,
            };

            taintedVars.set(targetKey, {
              name: varName,
              scope: currentScope,
              threat: sourceTaint.threat,
              sanitized: sourceTaint.sanitized,
              properties: sourceTaint.properties ? new Set(sourceTaint.properties) : undefined,
              history: [...sourceTaint.history, step],
            });
            changed = true;
          }
        }

        // Case: const { query } = data; (Destructuring from object)
        if (node.id?.type === 'ObjectPattern' && init?.type === 'Identifier') {
          const parentTaint = getVar(currentScope, init.name);
          if (parentTaint) {
            for (const prop of node.id.properties || []) {
              const propName = prop.key?.name || prop.value?.name;
              const targetKey = makeKey(currentScope, propName);

              if (propName && !taintedVars.has(targetKey)) {
                if (!parentTaint.properties || parentTaint.properties.has(propName)) {
                  const step: InterproceduralPathStep = {
                    stepNumber: parentTaint.history.length + 1,
                    type: 'PROPAGATION',
                    line,
                    function: currentScope !== 'global' ? currentScope : undefined,
                    functionName: currentScope,
                    symbol: propName,
                    description: `Destructured property '${propName}' inherits taint from '${init.name}'`,
                  };

                  taintedVars.set(targetKey, {
                    name: propName,
                    scope: currentScope,
                    threat: parentTaint.threat,
                    sanitized: parentTaint.sanitized,
                    history: [...parentTaint.history, step],
                  });
                  changed = true;
                }
              }
            }
          }
        }

        // Case: const query = `SELECT ... ${id}` or 'SELECT ...' + id;
        if (varName && (init?.type === 'TemplateLiteral' || init?.type === 'BinaryExpression')) {
          const evalRes = evaluateExpressionTaint(init, currentScope);
          const targetKey = makeKey(currentScope, varName);

          if (evalRes.isTainted && !taintedVars.has(targetKey)) {
            taintedVars.set(targetKey, {
              name: varName,
              scope: currentScope,
              threat: 'SQL_INJECTION',
              sanitized: evalRes.isSanitized,
              history: evalRes.history,
            });
            changed = true;
          }
        }

        // Case: const safeId = Number(id); / escapeHtml(id); (External sanitizers only)
        if (varName && init?.type === 'CallExpression') {
          const calleeName = extractCalleeName(init.callee);
          const isUserFn = calleeName ? callGraph.getFunction(calleeName) !== undefined : false;

          if (!isUserFn) {
            const evalRes = evaluateExpressionTaint(init, currentScope);
            const targetKey = makeKey(currentScope, varName);

            if (evalRes.isTainted && !taintedVars.has(targetKey)) {
              taintedVars.set(targetKey, {
                name: varName,
                scope: currentScope,
                threat: 'SQL_INJECTION',
                sanitized: evalRes.isSanitized,
                history: evalRes.history,
              });
              changed = true;
            }
          }
        }
      }

      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          scanLocalAliases(node[key], nextScope);
        }
      }
    }

    scanLocalAliases(ast, 'global');

    // Subpass B: Call Sites -> Arguments to Parameters & Return Values
    for (const callSite of callGraph.callSites) {
      const calleeFn = callGraph.getFunction(callSite.calleeName);

      if (calleeFn) {
        // 1. Argument -> Parameter Binding
        callSite.argumentNodes.forEach((argNode, argIndex) => {
          const paramName = calleeFn.paramNames[argIndex];
          if (!paramName) return;

          const argEval = evaluateExpressionTaint(argNode, callSite.callerFunctionName);

          if (argEval.isTainted) {
            const targetKey = makeKey(calleeFn.name, paramName);
            const existing = taintedVars.get(targetKey);

            if (!existing) {
              const stepArg: InterproceduralPathStep = {
                stepNumber: argEval.history.length + 1,
                type: 'ARGUMENT',
                line: callSite.line,
                function: calleeFn.name,
                functionName: callSite.callerFunctionName,
                symbol: paramName,
                description: `Passed as argument '${paramName}' into function '${calleeFn.name}()'`,
              };

              const stepParam: InterproceduralPathStep = {
                stepNumber: argEval.history.length + 2,
                type: 'PARAMETER',
                line: calleeFn.startLine,
                function: calleeFn.name,
                functionName: calleeFn.name,
                symbol: paramName,
                description: `Bound to parameter '${paramName}' in '${calleeFn.name}()'`,
              };

              // Check if argument passed is an object with properties
              let inheritedProps: Set<string> | undefined = undefined;
              if (argNode.type === 'Identifier') {
                const parentObj = getVar(callSite.callerFunctionName, argNode.name);
                if (parentObj?.properties) {
                  inheritedProps = new Set(parentObj.properties);
                }
              }

              taintedVars.set(targetKey, {
                name: paramName,
                scope: calleeFn.name,
                threat: 'SQL_INJECTION',
                sanitized: argEval.isSanitized,
                properties: inheritedProps,
                history: [...argEval.history, stepArg, stepParam],
              });
              changed = true;
            }
          }
        });

        // 2. Callee Return Nodes -> Caller Assignee
        for (const retNode of calleeFn.returnNodes) {
          const retEval = evaluateExpressionTaint(retNode, calleeFn.name);

          if (retEval.isTainted) {
            const callAssignee = findAssignmentTarget(ast, callSite.callNode);

            if (callAssignee) {
              const assigneeKey = makeKey(callSite.callerFunctionName, callAssignee);

              if (!taintedVars.has(assigneeKey)) {
                const stepReturn: InterproceduralPathStep = {
                  stepNumber: retEval.history.length + 1,
                  type: 'RETURN',
                  line: retNode.loc?.start?.line || calleeFn.endLine,
                  function: calleeFn.name,
                  functionName: calleeFn.name,
                  description: `Returned from function '${calleeFn.name}()'`,
                };

                const stepAssign: InterproceduralPathStep = {
                  stepNumber: retEval.history.length + 2,
                  type: 'PROPAGATION',
                  line: callSite.line,
                  function: callSite.callerFunctionName !== 'global' ? callSite.callerFunctionName : undefined,
                  functionName: callSite.callerFunctionName,
                  symbol: callAssignee,
                  description: `Assigned return value to variable '${callAssignee}'`,
                };

                taintedVars.set(assigneeKey, {
                  name: callAssignee,
                  scope: callSite.callerFunctionName,
                  threat: 'SQL_INJECTION',
                  sanitized: retEval.isSanitized,
                  history: [...retEval.history, stepReturn, stepAssign],
                });
                changed = true;
              }
            }
          }
        }
      }
    }
  }

  // 3. SINK DETECTION: Scan for sensitive SQL sinks reading tainted symbols
  function scanSinks(node: any, currentScope = 'global') {
    if (!node || typeof node !== 'object') return;

    let nextScope = currentScope;
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      nextScope = node.id.name;
    } else if (
      node.type === 'VariableDeclarator' &&
      node.id?.name &&
      (node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')
    ) {
      nextScope = node.id.name;
    }

    if (node.type === 'CallExpression') {
      const callee = node.callee;
      let methodName = '';
      let objectName = '';

      if (callee.type === 'MemberExpression') {
        methodName = (callee.property?.name || '').toLowerCase();
        objectName = (callee.object?.name || '').toLowerCase();
      } else if (callee.type === 'Identifier') {
        methodName = callee.name.toLowerCase();
      }

      const isQuerySink = (methodName === 'query' || methodName === 'execute' || methodName === 'raw') &&
        !['document', 'window', 'url', 'searchparams', 'router', 'graphql'].includes(objectName);

      if (isQuerySink && node.arguments?.length > 0) {
        const firstArg = node.arguments[0];
        const secondArg = node.arguments[1];

        // Check if safely parameterized
        const isParamSafe = isParameterizedCall(firstArg, secondArg);

        if (!isParamSafe) {
          const evalResult = evaluateExpressionTaint(firstArg, currentScope);

          if (evalResult.isTainted) {
            const line = node.loc?.start?.line || 1;
            const sinkSymbol = objectName ? `${objectName}.${methodName}` : `${methodName}`;

            const sinkStep: InterproceduralPathStep = {
              stepNumber: evalResult.history.length + 1,
              type: 'SINK',
              line,
              function: currentScope !== 'global' ? currentScope : undefined,
              functionName: currentScope,
              symbol: sinkSymbol,
              description: `Query executed in sensitive sink '${sinkSymbol}()'`,
            };

            const fullPath = [...evalResult.history, sinkStep];
            const sourceStep = fullPath[0];

            vulnerabilities.push({
              id: `ip-sqli-${vulnCount++}`,
              vulnerabilityType: 'SQL_INJECTION',
              source: {
                file: filename,
                line: sourceStep?.line || 1,
                symbol: sourceStep?.symbol || 'req.query.id',
              },
              sink: {
                file: filename,
                line,
                symbol: sinkSymbol,
              },
              sanitized: evalResult.isSanitized,
              path: fullPath,
            });
          }
        }
      }
    }

    for (const key in node) {
      if (key !== 'loc' && typeof node[key] === 'object') {
        scanSinks(node[key], nextScope);
      }
    }
  }

  scanSinks(ast, 'global');

  return vulnerabilities;
}

function findAssignmentTarget(rootAst: any, targetCallNode: any): string | null {
  let assignee: string | null = null;

  function traverse(node: any) {
    if (!node || typeof node !== 'object' || assignee) return;

    if (node.type === 'VariableDeclarator' && node.init === targetCallNode) {
      assignee = node.id?.name || null;
      return;
    }

    if (node.type === 'AssignmentExpression' && node.right === targetCallNode) {
      assignee = node.left?.name || null;
      return;
    }

    for (const key in node) {
      if (key !== 'loc' && typeof node[key] === 'object') traverse(node[key]);
    }
  }

  traverse(rootAst);
  return assignee;
}

function isParameterizedCall(firstArg: any, secondArg: any): boolean {
  if (!secondArg) return false;
  let queryStr = '';
  if (firstArg?.type === 'Literal' && typeof firstArg.value === 'string') {
    queryStr = firstArg.value;
  }
  const hasPlaceholders = /\?|\$\d+|:[a-zA-Z0-9_]+|@[a-zA-Z0-9_]+/.test(queryStr);
  const hasParams = secondArg.type === 'ArrayExpression' || secondArg.type === 'ObjectExpression' || secondArg.type === 'Identifier';
  return hasPlaceholders && hasParams;
}
