import { ASTNode } from '../ast/types';
import { CallGraph } from './callGraph';
import { doesNeutralizeThreat, isBuiltinSanitizer } from './sanitizerModel';
import { 
  InterproceduralTaintVulnerability, 
  InterproceduralPathStep, 
  TaintThreatType,
  InterproceduralAnalysisResult,
  AnalysisConvergenceStatus,
  FunctionSummary
} from './types';

// Flow-sensitive value representing taint state at a given program point
export interface TaintValue {
  isTainted: boolean;
  threat: TaintThreatType;
  sanitized: boolean;
  sanitizerStep?: {
    line: number;
    name: string;
    neutralizesThreat: boolean;
  };
  properties?: Set<string>; // If object, which specific properties are tainted
  history: InterproceduralPathStep[];
}

// Lexical scope representation supporting block scoping and variable shadowing
interface LexicalScope {
  id: string;
  name: string; // 'global', function name, or 'block_N'
  parent: LexicalScope | null;
  declarations: Set<string>;
}

export function performInterproceduralTaintAnalysis(
  ast: ASTNode | null,
  filename = 'source.js'
): InterproceduralTaintVulnerability[] {
  const result = runFlowSensitiveInterproceduralAnalysis(ast, filename);
  const vulns = result.vulnerabilities;
  (vulns as any).analysisResult = result;
  return vulns;
}

export function runFlowSensitiveInterproceduralAnalysis(
  ast: ASTNode | null,
  filename = 'source.js'
): InterproceduralAnalysisResult {
  if (!ast) {
    return {
      vulnerabilities: [],
      iterations: 0,
      converged: true,
      status: 'converged',
      unresolvedCallsCount: 0,
      flowSensitiveStepsEvaluated: 0,
    };
  }

  const callGraph = new CallGraph(ast);
  const vulnerabilities: InterproceduralTaintVulnerability[] = [];
  let vulnCount = 1;
  let unresolvedCallsCount = 0;
  let stepsEvaluated = 0;

  // Cache for function summaries: functionName -> { params: TaintValue[], returnVal: TaintValue | null }
  interface FunctionSummaryCache {
    paramSignatures: string;
    returnVal: TaintValue | null;
  }
  const functionCache = new Map<string, FunctionSummaryCache>();

  // Worklist of function names to re-evaluate when interprocedural flow changes
  const worklist = new Set<string>();
  let scopeCounter = 1;

  function createScope(name: string, parent: LexicalScope | null = null): LexicalScope {
    return {
      id: `scope_${scopeCounter++}_${name}`,
      name,
      parent,
      declarations: new Set<string>(),
    };
  }

  function resolveVarKey(scope: LexicalScope, varName: string): string {
    let curr: LexicalScope | null = scope;
    while (curr) {
      if (curr.declarations.has(varName)) {
        return `${curr.id}::${varName}`;
      }
      curr = curr.parent;
    }
    return `global::${varName}`;
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

  function extractCalleeName(callee: any): string | null {
    if (!callee) return null;
    if (callee.type === 'Identifier') return callee.name;
    if (callee.type === 'MemberExpression') {
      const obj = callee.object?.name || (callee.object?.type === 'ThisExpression' ? 'this' : '');
      const prop = callee.property?.name || callee.property?.value || '';
      return obj ? `${obj}.${prop}` : prop;
    }
    return null;
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

  // Evaluates an expression flow-sensitively against the current environment
  function evaluateExpression(
    expr: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[] = []
  ): TaintValue | null {
    stepsEvaluated++;
    if (!expr) return null;

    // 1. Literal -> Always safe (clean). Kills taint if assigned.
    if (expr.type === 'Literal') {
      return null;
    }

    // 2. Identifier: lookup in flow-sensitive environment
    if (expr.type === 'Identifier') {
      const key = resolveVarKey(scope, expr.name);
      return env.get(key) || null;
    }

    // 3. MemberExpression: source ingestion or object property access
    if (expr.type === 'MemberExpression') {
      const objStr = extractMemberString(expr);

      // 3A. Direct untrusted source: req.body, req.query, req.params, request.*
      if (/req\.(body|query|params|headers)|request\.|input/i.test(objStr)) {
        const line = expr.loc?.start?.line || 1;
        const step: InterproceduralPathStep = {
          stepNumber: 1,
          type: 'SOURCE',
          line,
          function: scope.name !== 'global' ? scope.name : undefined,
          functionName: scope.name,
          symbol: objStr,
          description: `Tainted input ingested from ${objStr}`,
        };

        return {
          isTainted: true,
          threat: 'SQL_INJECTION',
          sanitized: false,
          history: [step],
        };
      }

      // 3B. Property access on object: data.query
      const objName = expr.object?.name;
      const propName = expr.property?.name || expr.property?.value;
      if (objName) {
        const key = resolveVarKey(scope, objName);
        const objVal = env.get(key);
        if (objVal && objVal.isTainted) {
          // If properties are specified, check if this specific property is tainted
          if (!objVal.properties || objVal.properties.has(propName)) {
            const line = expr.loc?.start?.line || 1;
            const step: InterproceduralPathStep = {
              stepNumber: objVal.history.length + 1,
              type: 'PROPERTY_ACCESS',
              line,
              function: scope.name !== 'global' ? scope.name : undefined,
              functionName: scope.name,
              symbol: `${objName}.${propName}`,
              description: `Accessed object property '${objName}.${propName}'`,
            };

            return {
              isTainted: true,
              threat: objVal.threat,
              sanitized: objVal.sanitized,
              sanitizerStep: objVal.sanitizerStep,
              history: [...objVal.history, step],
            };
          }
        }
      }
      return null;
    }

    // 4. TemplateLiteral: `SELECT * FROM users WHERE id = ${id}`
    if (expr.type === 'TemplateLiteral') {
      for (const subExpr of expr.expressions || []) {
        const subVal = evaluateExpression(subExpr, env, scope, callStack);
        if (subVal && subVal.isTainted) {
          const line = expr.loc?.start?.line || 1;
          const step: InterproceduralPathStep = {
            stepNumber: subVal.history.length + 1,
            type: 'TEMPLATE',
            line,
            function: scope.name !== 'global' ? scope.name : undefined,
            functionName: scope.name,
            description: 'Interpolated into template literal string',
          };

          return {
            isTainted: true,
            threat: subVal.threat,
            sanitized: subVal.sanitized,
            sanitizerStep: subVal.sanitizerStep,
            history: [...subVal.history, step],
          };
        }
      }
      return null;
    }

    // 5. BinaryExpression (+): 'SELECT ...' + id
    if (expr.type === 'BinaryExpression' && expr.operator === '+') {
      const leftVal = evaluateExpression(expr.left, env, scope, callStack);
      if (leftVal && leftVal.isTainted) return leftVal;
      const rightVal = evaluateExpression(expr.right, env, scope, callStack);
      if (rightVal && rightVal.isTainted) return rightVal;
      return null;
    }

    // 6. ObjectExpression: { query: `... ${id}` }
    if (expr.type === 'ObjectExpression') {
      const taintedProps = new Set<string>();
      let combinedHistory: InterproceduralPathStep[] = [];
      let threat: TaintThreatType = 'SQL_INJECTION';
      let isSanitized = false;

      for (const prop of expr.properties || []) {
        const propName = prop.key?.name || prop.key?.value;
        if (propName && prop.value) {
          const propVal = evaluateExpression(prop.value, env, scope, callStack);
          if (propVal && propVal.isTainted) {
            taintedProps.add(propName);
            threat = propVal.threat;
            isSanitized = propVal.sanitized;
            combinedHistory = propVal.history;
          }
        }
      }

      if (taintedProps.size > 0) {
        const line = expr.loc?.start?.line || 1;
        const step: InterproceduralPathStep = {
          stepNumber: combinedHistory.length + 1,
          type: 'OBJECT_CREATION',
          line,
          function: scope.name !== 'global' ? scope.name : undefined,
          functionName: scope.name,
          description: `Object instantiated with tainted properties: ${Array.from(taintedProps).join(', ')}`,
        };

        return {
          isTainted: true,
          threat,
          sanitized: isSanitized,
          properties: taintedProps,
          history: [...combinedHistory, step],
        };
      }
      return null;
    }

    // 7. CallExpression: built-in sanitizers, user functions, or unresolved calls
    if (expr.type === 'CallExpression') {
      const calleeName = extractCalleeName(expr.callee);
      const args = expr.arguments || [];
      const evaluatedArgs = args.map((a: any) => evaluateExpression(a, env, scope, callStack));
      const firstTaintedArg = evaluatedArgs.find((a: any) => a && a.isTainted);

      if (!calleeName) {
        // Dynamic/computed call without static name -> handle conservatively if arg is tainted
        if (firstTaintedArg) {
          unresolvedCallsCount++;
          const line = expr.loc?.start?.line || 1;
          const step: InterproceduralPathStep = {
            stepNumber: firstTaintedArg.history.length + 1,
            type: 'PROPAGATION',
            line,
            function: scope.name !== 'global' ? scope.name : undefined,
            functionName: scope.name,
            description: 'Conservatively propagated taint through computed/dynamic call',
          };
          return {
            isTainted: true,
            threat: firstTaintedArg.threat,
            sanitized: firstTaintedArg.sanitized,
            history: [...firstTaintedArg.history, step],
          };
        }
        return null;
      }

      // Check if it is a verified built-in sanitizer: Number(), parseInt(), escapeHtml(), etc.
      // (CRITICAL: Do NOT treat functions named "sanitize..." as sanitizers unless built-in or verified)
      if (isBuiltinSanitizer(calleeName)) {
        if (firstTaintedArg) {
          const line = expr.loc?.start?.line || 1;
          const neutralizes = doesNeutralizeThreat(calleeName, firstTaintedArg.threat);

          const step: InterproceduralPathStep = {
            stepNumber: firstTaintedArg.history.length + 1,
            type: 'SANITIZER',
            line,
            function: scope.name !== 'global' ? scope.name : undefined,
            functionName: scope.name,
            symbol: calleeName,
            description: neutralizes
              ? `Passed through verified sanitizer '${calleeName}()' (Neutralizes ${firstTaintedArg.threat}: TAINT -> SANITIZER -> CLEAN)`
              : `Passed through '${calleeName}()' (Does NOT neutralize ${firstTaintedArg.threat}: REMAINS TAINTED)`,
          };

          return {
            isTainted: true,
            threat: firstTaintedArg.threat,
            sanitized: neutralizes ? true : firstTaintedArg.sanitized,
            sanitizerStep: {
              line,
              name: calleeName,
              neutralizesThreat: neutralizes,
            },
            history: [...firstTaintedArg.history, step],
          };
        }
        return null;
      }

      // Check if it is a user function resolved in the CallGraph
      const resolvedTarget = callGraph.resolveCallee(calleeName);
      if (resolvedTarget) {
        // Avoid infinite recursion in mutual/recursive calls
        const recursionDepth = callStack.filter(f => f === resolvedTarget.name).length;
        if (recursionDepth > 3) {
          // If recursion depth exceeded, return cached or conservative result
          return firstTaintedArg ? {
            isTainted: true,
            threat: firstTaintedArg.threat,
            sanitized: firstTaintedArg.sanitized,
            history: firstTaintedArg.history,
          } : null;
        }

        // Interprocedural step: pass arguments into callee
        const line = expr.loc?.start?.line || 1;
        const calleeScope = createScope(resolvedTarget.name, null);
        const calleeEnv = new Map<string, TaintValue | null>();

        let calleeFirstTaintedArg: TaintValue | null = null;

        resolvedTarget.paramNames.forEach((paramName, idx) => {
          calleeScope.declarations.add(paramName);
          const pKey = `${calleeScope.id}::${paramName}`;
          const argVal = evaluatedArgs[idx];

          if (argVal && argVal.isTainted) {
            const stepArg: InterproceduralPathStep = {
              stepNumber: argVal.history.length + 1,
              type: 'ARGUMENT',
              line,
              function: resolvedTarget.name,
              functionName: scope.name,
              symbol: paramName,
              description: `Passed as argument '${paramName}' into function '${resolvedTarget.name}()'`,
            };

            const stepParam: InterproceduralPathStep = {
              stepNumber: argVal.history.length + 2,
              type: 'PARAMETER',
              line: resolvedTarget.startLine,
              function: resolvedTarget.name,
              functionName: resolvedTarget.name,
              symbol: paramName,
              description: `Bound to parameter '${paramName}' in '${resolvedTarget.name}()'`,
            };

            const paramTaint: TaintValue = {
              isTainted: true,
              threat: argVal.threat,
              sanitized: argVal.sanitized,
              sanitizerStep: argVal.sanitizerStep,
              properties: argVal.properties ? new Set(argVal.properties) : undefined,
              history: [...argVal.history, stepArg, stepParam],
            };

            calleeEnv.set(pKey, paramTaint);
            if (!calleeFirstTaintedArg) calleeFirstTaintedArg = paramTaint;
          } else {
            calleeEnv.set(pKey, null);
          }
        });

        // Flow-sensitively analyze the body of the callee function
        const calleeResult = analyzeBlockStatements(
          resolvedTarget.declarationNode.body,
          calleeEnv,
          calleeScope,
          [...callStack, resolvedTarget.name]
        );

        // Check return statements
        if (calleeResult.returnValue && calleeResult.returnValue.isTainted) {
          const retStep: InterproceduralPathStep = {
            stepNumber: calleeResult.returnValue.history.length + 1,
            type: 'RETURN',
            line: resolvedTarget.declarationNode.loc?.end?.line || resolvedTarget.endLine,
            function: resolvedTarget.name,
            functionName: resolvedTarget.name,
            description: `Returned from function '${resolvedTarget.name}()'`,
          };

          return {
            isTainted: true,
            threat: calleeResult.returnValue.threat,
            sanitized: calleeResult.returnValue.sanitized,
            sanitizerStep: calleeResult.returnValue.sanitizerStep,
            properties: calleeResult.returnValue.properties,
            history: [...calleeResult.returnValue.history, retStep],
          };
        }

        return calleeResult.returnValue || null;
      }

      // Unresolved call: external library, module call, or unknown function
      // (HIGH 3: Handled CONSERVATIVELY — taint is preserved, not dropped)
      if (firstTaintedArg) {
        unresolvedCallsCount++;
        const line = expr.loc?.start?.line || 1;
        const step: InterproceduralPathStep = {
          stepNumber: firstTaintedArg.history.length + 1,
          type: 'PROPAGATION',
          line,
          function: scope.name !== 'global' ? scope.name : undefined,
          functionName: scope.name,
          symbol: calleeName,
          description: `Conservatively propagated taint through unresolved call '${calleeName}()'`,
        };

        return {
          isTainted: true,
          threat: firstTaintedArg.threat,
          sanitized: firstTaintedArg.sanitized,
          sanitizerStep: firstTaintedArg.sanitizerStep,
          history: [...firstTaintedArg.history, step],
        };
      }

      return null;
    }

    return null;
  }

  // Analyzes a statement or block of statements in strict sequential order
  function analyzeBlockStatements(
    bodyNode: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[]
  ): { env: Map<string, TaintValue | null>; returnValue: TaintValue | null } {
    if (!bodyNode) return { env, returnValue: null };

    // If arrow function with direct expression body: (x) => expr
    if (bodyNode.type !== 'BlockStatement' && bodyNode.type !== 'Program') {
      const retVal = evaluateExpression(bodyNode, env, scope, callStack);
      return { env, returnValue: retVal };
    }

    const statements = bodyNode.body || [];
    let currentEnv = new Map(env);
    let capturedReturn: TaintValue | null = null;

    for (const stmt of statements) {
      if (!stmt) continue;

      // 1. VariableDeclaration: const x = init, let y = init;
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations || []) {
          const varName = decl.id?.name;
          const init = decl.init;

          // Simple identifier declaration: const id = expr
          if (varName) {
            scope.declarations.add(varName);
            const varKey = `${scope.id}::${varName}`;
            const evalVal = evaluateExpression(init, currentEnv, scope, callStack);

            if (evalVal && evalVal.isTainted) {
              // Add a PROPAGATION step if aliased from another identifier: const localAlias = searchTerm;
              if (init?.type === 'Identifier') {
                const line = stmt.loc?.start?.line || 1;
                const propStep: InterproceduralPathStep = {
                  stepNumber: evalVal.history.length + 1,
                  type: 'PROPAGATION',
                  line,
                  function: scope.name !== 'global' ? scope.name : undefined,
                  functionName: scope.name,
                  symbol: varName,
                  description: `Aliased variable '${varName}' inherits taint from '${init.name}'`,
                };
                currentEnv.set(varKey, {
                  ...evalVal,
                  history: [...evalVal.history, propStep],
                });
              } else {
                currentEnv.set(varKey, evalVal);
              }
            } else {
              // Flow sensitivity: Variable initialized to clean value (kills any earlier taint)
              currentEnv.set(varKey, null);
            }
          }

          // Object destructuring: const { query } = data; or const { id } = req.body;
          if (decl.id?.type === 'ObjectPattern' && init) {
            const initVal = evaluateExpression(init, currentEnv, scope, callStack);

            for (const prop of decl.id.properties || []) {
              const propName = prop.key?.name || prop.value?.name;
              if (propName) {
                scope.declarations.add(propName);
                const propKey = `${scope.id}::${propName}`;

                if (initVal && initVal.isTainted) {
                  const line = stmt.loc?.start?.line || 1;
                  const step: InterproceduralPathStep = {
                    stepNumber: initVal.history.length + 1,
                    type: 'PROPAGATION',
                    line,
                    function: scope.name !== 'global' ? scope.name : undefined,
                    functionName: scope.name,
                    symbol: propName,
                    description: `Destructured property '${propName}' inherits taint`,
                  };

                  currentEnv.set(propKey, {
                    isTainted: true,
                    threat: initVal.threat,
                    sanitized: initVal.sanitized,
                    sanitizerStep: initVal.sanitizerStep,
                    history: [...initVal.history, step],
                  });
                } else {
                  currentEnv.set(propKey, null);
                }
              }
            }
          }
        }
      }

      // 2. ExpressionStatement: reassignments (x = expr) or sink invocations (db.query(sql))
      else if (stmt.type === 'ExpressionStatement') {
        const expr = stmt.expression;

        // 2A. AssignmentExpression: x = expr (FLOW-SENSITIVE REASSIGNMENT)
        if (expr?.type === 'AssignmentExpression') {
          const leftName = expr.left?.name;
          if (leftName) {
            const varKey = resolveVarKey(scope, leftName);
            const evalVal = evaluateExpression(expr.right, currentEnv, scope, callStack);

            if (evalVal && evalVal.isTainted) {
              const line = stmt.loc?.start?.line || 1;
              const propStep: InterproceduralPathStep = {
                stepNumber: evalVal.history.length + 1,
                type: 'PROPAGATION',
                line,
                function: scope.name !== 'global' ? scope.name : undefined,
                functionName: scope.name,
                symbol: leftName,
                description: `Reassigned variable '${leftName}' receives taint`,
              };
              currentEnv.set(varKey, {
                ...evalVal,
                history: [...evalVal.history, propStep],
              });
            } else {
              // CRITICAL 1 FIX: Reassignment to safe/clean value KILLS earlier taint!
              currentEnv.set(varKey, null);
            }
          }
        }

        // 2B. CallExpression at statement level: check sinks and step into call flow-sensitively
        let callExpr: any = null;
        if (expr?.type === 'CallExpression') callExpr = expr;
        else if (expr?.type === 'AwaitExpression' && expr.argument?.type === 'CallExpression') callExpr = expr.argument;

        if (callExpr) {
          checkSinkInvocation(callExpr, currentEnv, scope, callStack);
          evaluateExpression(callExpr, currentEnv, scope, callStack);
        }
      }

      // 3. ReturnStatement: return expr;
      else if (stmt.type === 'ReturnStatement') {
        if (stmt.argument) {
          // If return contains a call to sink (e.g. return db.query(sql))
          if (stmt.argument.type === 'CallExpression') {
            checkSinkInvocation(stmt.argument, currentEnv, scope, callStack);
          }
          capturedReturn = evaluateExpression(stmt.argument, currentEnv, scope, callStack);
        }
      }

      // 4. Nested BlockStatement: { ... } (variable shadowing in block scopes)
      else if (stmt.type === 'BlockStatement') {
        const blockScope = createScope('block', scope);
        const blockRes = analyzeBlockStatements(stmt, currentEnv, blockScope, callStack);
        currentEnv = blockRes.env;
        if (blockRes.returnValue) capturedReturn = blockRes.returnValue;
      }

      // 5. IfStatement: if (cond) { ... }
      else if (stmt.type === 'IfStatement') {
        if (stmt.consequent) {
          const ifScope = createScope('if_block', scope);
          const ifRes = analyzeBlockStatements(stmt.consequent, currentEnv, ifScope, callStack);
          if (ifRes.returnValue) capturedReturn = ifRes.returnValue;
        }
        if (stmt.alternate) {
          const elseScope = createScope('else_block', scope);
          const elseRes = analyzeBlockStatements(stmt.alternate, currentEnv, elseScope, callStack);
          if (elseRes.returnValue) capturedReturn = elseRes.returnValue;
        }
      }
    }

    return { env: currentEnv, returnValue: capturedReturn };
  }

  // Checks whether a CallExpression invokes a sensitive sink with tainted arguments
  function checkSinkInvocation(
    callNode: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[]
  ) {
    const callee = callNode.callee;
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

    if (isQuerySink && callNode.arguments?.length > 0) {
      const firstArg = callNode.arguments[0];
      const secondArg = callNode.arguments[1];

      // Safe parameterized query check (e.g. db.query('SELECT ... WHERE id = ?', [id]))
      const isParamSafe = isParameterizedCall(firstArg, secondArg);

      if (!isParamSafe) {
        const argEval = evaluateExpression(firstArg, env, scope, callStack);

        if (argEval && argEval.isTainted) {
          const line = callNode.loc?.start?.line || 1;
          const sinkSymbol = objectName ? `${objectName}.${methodName}` : `${methodName}`;

          const sinkStep: InterproceduralPathStep = {
            stepNumber: argEval.history.length + 1,
            type: 'SINK',
            line,
            function: scope.name !== 'global' ? scope.name : undefined,
            functionName: scope.name,
            symbol: sinkSymbol,
            description: `Query executed in sensitive sink '${sinkSymbol}()'`,
          };

          const fullPath = [...argEval.history, sinkStep];
          const sourceStep = fullPath[0];

          // Prevent duplicate recording of the exact same vulnerability line
          const isDuplicate = vulnerabilities.some(
            v => v.sink.line === line && v.source.line === sourceStep?.line && v.sanitized === argEval.sanitized
          );

          if (!isDuplicate) {
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
              sanitized: argEval.sanitized,
              sanitizerStep: argEval.sanitizerStep,
              path: fullPath,
            });
          }
        }
      }
    }
  }

  // Convergence-based Fixed-Point Algorithm (HIGH 5 FIX)
  const MAX_ITERATIONS = 150;
  let iterations = 0;
  let converged = true;
  let analysisStatus: AnalysisConvergenceStatus = 'converged';

  const globalScope = createScope('global', null);
  const initialEnv = new Map<string, TaintValue | null>();

  // Run the primary flow-sensitive analysis across the AST
  analyzeBlockStatements(ast, initialEnv, globalScope, []);
  iterations = 1;

  // If there are recursive / mutually calling functions in the CallGraph, iterate until fixed-point convergence
  const recursiveFunctions = Array.from(callGraph.functions.values()).filter(fn => fn.isRecursive);
  if (recursiveFunctions.length > 0) {
    let stateChanged = true;
    while (stateChanged && iterations < MAX_ITERATIONS) {
      stateChanged = false;
      iterations++;

      for (const recFn of recursiveFunctions) {
        const prevSummary = functionCache.get(recFn.name);
        const fnScope = createScope(recFn.name, null);
        const fnEnv = new Map<string, TaintValue | null>();

        // Re-evaluate recursive function
        const res = analyzeBlockStatements(recFn.declarationNode.body, fnEnv, fnScope, [recFn.name]);
        const newSig = res.returnValue ? `${res.returnValue.isTainted}:${res.returnValue.sanitized}` : 'null';

        if (!prevSummary || prevSummary.paramSignatures !== newSig) {
          functionCache.set(recFn.name, {
            paramSignatures: newSig,
            returnVal: res.returnValue,
          });
          stateChanged = true;
        }
      }
    }

    if (iterations >= MAX_ITERATIONS && stateChanged) {
      converged = false;
      analysisStatus = 'resource_limit_exceeded';
    }
  }

  return {
    vulnerabilities,
    iterations,
    converged,
    status: analysisStatus,
    unresolvedCallsCount,
    flowSensitiveStepsEvaluated: stepsEvaluated,
  };
}
