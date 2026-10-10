import { ASTNode } from '../ast/types';
import { CallGraph } from './callGraph';
import { 
  doesNeutralizeThreat, 
  doesNeutralizeThreatInContext, 
  isBuiltinSanitizer,
  isKnownSanitizer
} from './sanitizerModel';
import { 
  InterproceduralTaintVulnerability, 
  InterproceduralPathStep, 
  TaintThreatType,
  InterproceduralAnalysisResult,
  AnalysisConvergenceStatus,
  SinkContext,
  FinalVariableState,
  VulnerabilityConfidence
} from './types';

// Flow-sensitive value representing taint and abstract data-flow state
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
  isUnresolvedFlow?: boolean;
  unresolvedFunction?: string;
  stringValue?: string; // Statically tracked string literal / constant content
}

// Abstract State Equality comparison across all relevant analysis dimensions
export function isAbstractStateEqual(a: TaintValue | null, b: TaintValue | null): boolean {
  if (a === b) return true;
  if (!a && !b) return true;
  if (!a || !b) return false;

  if (a.isTainted !== b.isTainted) return false;
  if (a.threat !== b.threat) return false;
  if (a.sanitized !== b.sanitized) return false;
  if (!!a.isUnresolvedFlow !== !!b.isUnresolvedFlow) return false;
  if (a.unresolvedFunction !== b.unresolvedFunction) return false;

  // Compare object property taint sets
  const aProps = a.properties ? Array.from(a.properties).sort() : [];
  const bProps = b.properties ? Array.from(b.properties).sort() : [];
  if (aProps.length !== bProps.length) return false;
  for (let i = 0; i < aProps.length; i++) {
    if (aProps[i] !== bProps[i]) return false;
  }

  // Compare sanitizer metadata
  if (a.sanitizerStep?.name !== b.sanitizerStep?.name) return false;
  if (a.sanitizerStep?.neutralizesThreat !== b.sanitizerStep?.neutralizesThreat) return false;

  // Compare statically tracked string constant content (Finding 1)
  if (a.stringValue !== b.stringValue) return false;

  return true;
}

// Abstract State Join (Least Upper Bound in data-flow lattice)
export function joinAbstractValues(
  a: TaintValue | null,
  b: TaintValue | null,
  mergeStep?: InterproceduralPathStep
): TaintValue | null {
  if (!a && !b) return null;
  if (!a) {
    if (b && b.isTainted && mergeStep) {
      return { ...b, history: [...b.history, { ...mergeStep, stepNumber: b.history.length + 1 }] };
    }
    return b;
  }
  if (!b) {
    if (a && a.isTainted && mergeStep) {
      return { ...a, history: [...a.history, { ...mergeStep, stepNumber: a.history.length + 1 }] };
    }
    return a;
  }

  if (!a.isTainted && !b.isTainted) {
    const stringVal = (a.stringValue === b.stringValue) ? a.stringValue : (a.stringValue || b.stringValue);
    return {
      isTainted: false,
      threat: 'UNTRUSTED',
      sanitized: false,
      history: [],
      stringValue: stringVal,
    };
  }

  if (a.isTainted && !b.isTainted) {
    if (mergeStep) return { ...a, history: [...a.history, { ...mergeStep, stepNumber: a.history.length + 1 }] };
    return a;
  }
  if (!a.isTainted && b.isTainted) {
    if (mergeStep) return { ...b, history: [...b.history, { ...mergeStep, stepNumber: b.history.length + 1 }] };
    return b;
  }

  // Both branches are tainted!
  // Safety rule: Un-sanitized taint dominates over sanitized
  const isSanitized = a.sanitized && b.sanitized;
  const dominant = (!a.sanitized && b.sanitized) ? a : ((a.sanitized && !b.sanitized) ? b : a);
  const dominantThreat = (a.threat !== 'UNTRUSTED' ? a.threat : b.threat) || dominant.threat;

  // Union of tainted object properties
  let mergedProps: Set<string> | undefined = undefined;
  if (a.properties || b.properties) {
    mergedProps = new Set([...(a.properties || []), ...(b.properties || [])]);
  }

  const isUnres = !!a.isUnresolvedFlow || !!b.isUnresolvedFlow;
  const unresFn = a.unresolvedFunction || b.unresolvedFunction;
  const baseHistory = mergeStep 
    ? [...dominant.history, { ...mergeStep, stepNumber: dominant.history.length + 1 }] 
    : dominant.history;

  return {
    isTainted: true,
    threat: dominantThreat,
    sanitized: isSanitized,
    sanitizerStep: isSanitized ? dominant.sanitizerStep : undefined,
    properties: mergedProps,
    isUnresolvedFlow: isUnres,
    unresolvedFunction: unresFn,
    history: baseHistory,
  };
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
  filename = 'source.js',
  options?: { maxIterations?: number }
): InterproceduralAnalysisResult {
  if (!ast) {
    return {
      vulnerabilities: [],
      iterations: 0,
      converged: true,
      status: 'converged',
      unresolvedCallsCount: 0,
      flowSensitiveStepsEvaluated: 0,
      finalVariables: {},
    };
  }

  const callGraph = new CallGraph(ast);
  const vulnerabilities: InterproceduralTaintVulnerability[] = [];
  let vulnCount = 1;
  let unresolvedCallsCount = 0;
  let stepsEvaluated = 0;

  // Parameter-sensitive function summary cache: key -> return value
  interface FunctionSummaryRecord {
    returnVal: TaintValue | null;
    iterations: number;
    converged: boolean;
  }
  const summaryCache = new Map<string, FunctionSummaryRecord>();

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

  function getDeclarationScope(declScope: LexicalScope, kind?: string): LexicalScope {
    if (kind !== 'var') return declScope;
    let curr = declScope;
    while (
      curr.parent && 
      (curr.name === 'if_block' || curr.name === 'else_block' || curr.name === 'block' || curr.name === 'loop_block')
    ) {
      curr = curr.parent;
    }
    return curr;
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

  // Parameterized Query Verification (Medium 4):
  // Evaluates query expression flow-sensitively. If firstArg is tainted (e.g. interpolated string),
  // it is an unsafe query. If firstArg is a clean string with placeholders and secondArg contains parameters,
  // it is safe.
  function isParameterizedCall(
    firstArg: any,
    secondArg: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[]
  ): boolean {
    if (!firstArg || !secondArg) return false;

    // Check if the query expression itself was tainted by string interpolation
    const firstEval = evaluateExpression(firstArg, env, scope, callStack);
    if (firstEval && firstEval.isTainted) {
      // Unsafe query! The query itself was dynamically built with tainted values
      return false;
    }

    // Extract query string representation
    let queryStr = '';
    if (firstArg.type === 'Literal' && typeof firstArg.value === 'string') {
      queryStr = firstArg.value;
    } else if (firstArg.type === 'Identifier') {
      const key = resolveVarKey(scope, firstArg.name);
      const val = env.get(key);
      if (val && val.stringValue) {
        queryStr = val.stringValue;
      }
    } else if (firstArg.type === 'TemplateLiteral') {
      if (!firstArg.expressions || firstArg.expressions.length === 0) {
        queryStr = firstArg.quasis.map((q: any) => q.value.raw).join('');
      }
    }

    const hasPlaceholders = /\?|\$\d+|:[a-zA-Z0-9_]+|@[a-zA-Z0-9_]+/.test(queryStr);
    const hasParams = 
      secondArg.type === 'ArrayExpression' || 
      secondArg.type === 'ObjectExpression' || 
      secondArg.type === 'Identifier';

    return hasPlaceholders && hasParams;
  }

  // URL Destination vs Component Context Analysis (Finding 3):
  // Replaces syntactic binary '+' shortcut with semantic destination-versus-component analysis.
  // Determines if the assigned / passed expression forms a component of a fixed base URL
  // or a complete destination URL where protocol / host can be influenced.
  function analyzeUrlSinkContext(
    expr: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[]
  ): SinkContext {
    if (!expr) return 'URL_DESTINATION';

    // 1. Binary concatenation: inspect left prefix
    if (expr.type === 'BinaryExpression' && expr.operator === '+') {
      const leftEval = evaluateExpression(expr.left, env, scope, callStack);
      const prefixStr = leftEval?.stringValue;
      if (typeof prefixStr === 'string') {
        const trimmed = prefixStr.trim().toLowerCase();
        // Complete destination if the prefix contains scheme or is protocol-relative
        if (/^(https?:|\/\/|\/)/i.test(trimmed)) {
          // If prefix ends with query separator or path slash (e.g. '/search?q=', 'https://example.com/api?param='),
          // the concatenated suffix is a URL_COMPONENT
          if (trimmed.includes('?') || trimmed.includes('&') || trimmed.endsWith('/')) {
            return 'URL_COMPONENT';
          }
          // Concatenating directly to scheme without safe boundary (e.g. "javascript:" + code) is URL_DESTINATION
          return 'URL_DESTINATION';
        }
      }
      // If prefix is not a fixed safe base path/query, treat conservatively as complete destination
      return 'URL_DESTINATION';
    }

    // 2. Template literal: inspect initial quasi prefix
    if (expr.type === 'TemplateLiteral') {
      const firstQuasi = expr.quasis?.[0]?.value?.raw || '';
      const trimmed = firstQuasi.trim().toLowerCase();
      if ((trimmed.startsWith('/') || trimmed.startsWith('http://') || trimmed.startsWith('https://')) &&
          (trimmed.includes('?') || trimmed.includes('&') || trimmed.endsWith('/'))) {
        return 'URL_COMPONENT';
      }
      return 'URL_DESTINATION';
    }

    // 3. Direct identifier, member expression, or call expression without base prefix is a complete destination
    return 'URL_DESTINATION';
  }

  function buildParamSignature(args: (TaintValue | null)[]): string {
    return args
      .map(a => {
        if (!a || !a.isTainted) {
          if (a?.stringValue !== undefined) {
            // Encode string literal in bounded abstract domain
            const encodedStr = encodeURIComponent(a.stringValue.slice(0, 64));
            return `str:${encodedStr}`;
          }
          return 'safe';
        }
        const propsStr = a.properties && a.properties.size > 0 
          ? `[${Array.from(a.properties).sort().join(';')}]` 
          : '*';
        const unresStr = a.isUnresolvedFlow ? ':unres' : '';
        const strSuffix = a.stringValue !== undefined 
          ? `:str(${encodeURIComponent(a.stringValue.slice(0, 64))})` 
          : '';
        return `${a.threat}:${a.sanitized ? 'sanitized' : 'tainted'}:${propsStr}${unresStr}${strSuffix}`;
      })
      .join('|');
  }

  // Evaluates an expression flow-sensitively against current environment
  function evaluateExpression(
    expr: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[] = []
  ): TaintValue | null {
    stepsEvaluated++;
    if (!expr) return null;

    // 1. Literal -> Clean. Tracks stringValue if string.
    if (expr.type === 'Literal') {
      if (typeof expr.value === 'string') {
        return {
          isTainted: false,
          threat: 'UNTRUSTED',
          sanitized: false,
          history: [],
          stringValue: expr.value,
        };
      }
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

      // 3A. Untrusted Source: req.body, req.query, req.params, request.*
      // (HIGH 3: Represents untrusted input independently from a specific threat.
      // Threat is assigned based on sink context at invocation time.)
      if (/req\.(body|query|params|headers)|request\.|input/i.test(objStr)) {
        const line = expr.loc?.start?.line || 1;
        const step: InterproceduralPathStep = {
          stepNumber: 1,
          type: 'SOURCE',
          line,
          function: scope.name !== 'global' ? scope.name : undefined,
          functionName: scope.name,
          symbol: objStr,
          description: `Untrusted input ingested from ${objStr}`,
        };

        return {
          isTainted: true,
          threat: 'UNTRUSTED', // Independent from specific threat
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
              isUnresolvedFlow: objVal.isUnresolvedFlow,
              unresolvedFunction: objVal.unresolvedFunction,
              history: [...objVal.history, step],
            };
          }
        }
      }
      return null;
    }

    // 4. TemplateLiteral: `SELECT * FROM users WHERE id = ${id}`
    if (expr.type === 'TemplateLiteral') {
      let isAnyTainted = false;
      let firstTainted: TaintValue | null = null;

      for (const subExpr of expr.expressions || []) {
        const subVal = evaluateExpression(subExpr, env, scope, callStack);
        if (subVal && subVal.isTainted) {
          isAnyTainted = true;
          firstTainted = subVal;
          break;
        }
      }

      if (isAnyTainted && firstTainted) {
        const line = expr.loc?.start?.line || 1;
        const step: InterproceduralPathStep = {
          stepNumber: firstTainted.history.length + 1,
          type: 'TEMPLATE',
          line,
          function: scope.name !== 'global' ? scope.name : undefined,
          functionName: scope.name,
          description: 'Interpolated into template literal string',
        };

        return {
          isTainted: true,
          threat: firstTainted.threat,
          sanitized: firstTainted.sanitized,
          sanitizerStep: firstTainted.sanitizerStep,
          isUnresolvedFlow: firstTainted.isUnresolvedFlow,
          unresolvedFunction: firstTainted.unresolvedFunction,
          history: [...firstTainted.history, step],
        };
      }

      // Untainted template literal: extract raw string value
      const rawString = expr.quasis?.map((q: any) => q.value?.raw || '').join('');
      return {
        isTainted: false,
        threat: 'UNTRUSTED',
        sanitized: false,
        history: [],
        stringValue: rawString,
      };
    }

    // 5. BinaryExpression (+): 'SELECT ...' + id
    if (expr.type === 'BinaryExpression' && expr.operator === '+') {
      const leftVal = evaluateExpression(expr.left, env, scope, callStack);
      const rightVal = evaluateExpression(expr.right, env, scope, callStack);

      if (leftVal && leftVal.isTainted) return leftVal;
      if (rightVal && rightVal.isTainted) return rightVal;

      const leftStr = leftVal?.stringValue;
      const rightStr = rightVal?.stringValue;
      if (typeof leftStr === 'string' && typeof rightStr === 'string') {
        return {
          isTainted: false,
          threat: 'UNTRUSTED',
          sanitized: false,
          history: [],
          stringValue: leftStr + rightStr,
        };
      }
      return null;
    }

    // 6. ObjectExpression: { query: `... ${id}` }
    if (expr.type === 'ObjectExpression') {
      const taintedProps = new Set<string>();
      let combinedHistory: InterproceduralPathStep[] = [];
      let dominantThreat: TaintThreatType = 'UNTRUSTED';
      let isSanitized = false;
      let isUnres = false;
      let unresFn: string | undefined;

      for (const prop of expr.properties || []) {
        const propName = prop.key?.name || prop.key?.value;
        if (propName && prop.value) {
          const propVal = evaluateExpression(prop.value, env, scope, callStack);
          if (propVal && propVal.isTainted) {
            taintedProps.add(propName);
            dominantThreat = propVal.threat;
            isSanitized = propVal.sanitized;
            isUnres = !!propVal.isUnresolvedFlow;
            unresFn = propVal.unresolvedFunction;
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
          threat: dominantThreat,
          sanitized: isSanitized,
          properties: taintedProps,
          isUnresolvedFlow: isUnres,
          unresolvedFunction: unresFn,
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
        // Computed call -> unresolved flow finding
        if (firstTaintedArg) {
          unresolvedCallsCount++;
          const line = expr.loc?.start?.line || 1;
          const step: InterproceduralPathStep = {
            stepNumber: firstTaintedArg.history.length + 1,
            type: 'PROPAGATION',
            line,
            function: scope.name !== 'global' ? scope.name : undefined,
            functionName: scope.name,
            description: 'Conservatively propagated taint through computed call (unresolved flow)',
          };
          return {
            isTainted: true,
            threat: firstTaintedArg.threat,
            sanitized: firstTaintedArg.sanitized,
            isUnresolvedFlow: true,
            history: [...firstTaintedArg.history, step],
          };
        }
        return null;
      }

      // 1. Check if user function resolved in CallGraph (priority over name-matching)
      const resolvedTarget = callGraph.resolveCallee(calleeName);
      if (resolvedTarget) {
        const paramSig = buildParamSignature(evaluatedArgs);
        const cacheKey = `${resolvedTarget.name}::${paramSig}`;

        // Recursive cycle detection
        const isCurrentlyInCallStack = callStack.includes(resolvedTarget.name);
        if (isCurrentlyInCallStack) {
          const cached = summaryCache.get(cacheKey);
          if (cached) {
            return cached.returnVal;
          }
          // Bottom of lattice for initial approximation
          return null;
        }

        // Interprocedural step: bind arguments to callee parameters
        const line = expr.loc?.start?.line || 1;
        const calleeScope = createScope(resolvedTarget.name, null);
        const calleeEnv = new Map<string, TaintValue | null>();

        resolvedTarget.paramNames.forEach((paramName, idx) => {
          calleeScope.declarations.add(paramName);
          const pKey = `${calleeScope.id}::${paramName}`;
          const argVal = evaluatedArgs[idx];

          if (argVal && argVal.isTainted) {
            const stepArg: InterproceduralPathStep = {
              stepNumber: argVal.history.length + 1,
              line,
              type: 'ARGUMENT',
              function: resolvedTarget.name,
              functionName: scope.name,
              symbol: paramName,
              description: `Passed as argument '${paramName}' into function '${resolvedTarget.name}()'`,
            };

            const stepParam: InterproceduralPathStep = {
              stepNumber: argVal.history.length + 2,
              line: resolvedTarget.startLine,
              type: 'PARAMETER',
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
              isUnresolvedFlow: argVal.isUnresolvedFlow,
              unresolvedFunction: argVal.unresolvedFunction,
              stringValue: argVal.stringValue,
              history: [...argVal.history, stepArg, stepParam],
            };

            calleeEnv.set(pKey, paramTaint);
          } else {
            calleeEnv.set(pKey, argVal || null);
          }
        });

        // Flow-sensitively analyze callee body
        const calleeResult = analyzeBlockStatements(
          resolvedTarget.declarationNode.body,
          calleeEnv,
          calleeScope,
          [...callStack, resolvedTarget.name]
        );

        let finalRet: TaintValue | null = null;

        if (calleeResult.returnValue && calleeResult.returnValue.isTainted) {
          const retStep: InterproceduralPathStep = {
            stepNumber: calleeResult.returnValue.history.length + 1,
            type: 'RETURN',
            line: resolvedTarget.declarationNode.loc?.end?.line || resolvedTarget.endLine,
            function: resolvedTarget.name,
            functionName: resolvedTarget.name,
            description: `Returned from function '${resolvedTarget.name}()'`,
          };

          finalRet = {
            isTainted: true,
            threat: calleeResult.returnValue.threat,
            sanitized: calleeResult.returnValue.sanitized,
            sanitizerStep: calleeResult.returnValue.sanitizerStep,
            properties: calleeResult.returnValue.properties,
            isUnresolvedFlow: calleeResult.returnValue.isUnresolvedFlow,
            unresolvedFunction: calleeResult.returnValue.unresolvedFunction,
            stringValue: calleeResult.returnValue.stringValue,
            history: [...calleeResult.returnValue.history, retStep],
          };
        } else {
          finalRet = calleeResult.returnValue || null;
        }

        // Cache summary
        summaryCache.set(cacheKey, {
          returnVal: finalRet,
          iterations: 1,
          converged: true,
        });

        return finalRet;
      }

      // 2. Verified built-in or verified library sanitizer (NOT defined/overridden by user AST)
      if (isBuiltinSanitizer(calleeName) || isKnownSanitizer(calleeName)) {
        if (firstTaintedArg) {
          const line = expr.loc?.start?.line || 1;
          const step: InterproceduralPathStep = {
            stepNumber: firstTaintedArg.history.length + 1,
            type: 'SANITIZER',
            line,
            function: scope.name !== 'global' ? scope.name : undefined,
            functionName: scope.name,
            symbol: calleeName,
            description: `Passed through sanitizer '${calleeName}()'`,
          };

          return {
            isTainted: true,
            threat: firstTaintedArg.threat,
            sanitized: true,
            sanitizerStep: {
              line,
              name: calleeName,
              neutralizesThreat: true,
            },
            history: [...firstTaintedArg.history, step],
          };
        }
        return null;
      }

      // Unresolved call -> Conservative propagation as unresolved-flow finding
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
          isUnresolvedFlow: true,
          unresolvedFunction: calleeName,
          history: [...firstTaintedArg.history, step],
        };
      }

      return null;
    }

    return null;
  }

  // Analyzes statements in sequential order with branch join semantics
  function analyzeBlockStatements(
    bodyNode: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[]
  ): { env: Map<string, TaintValue | null>; returnValue: TaintValue | null } {
    if (!bodyNode) return { env, returnValue: null };

    let statements: any[] = [];
    if (bodyNode.type === 'BlockStatement' || bodyNode.type === 'Program') {
      statements = bodyNode.body || [];
    } else if (
      bodyNode.type?.endsWith('Statement') || 
      bodyNode.type?.endsWith('Declaration') ||
      bodyNode.type === 'IfStatement'
    ) {
      statements = [bodyNode];
    } else {
      // Arrow function with expression body (or bare expression)
      const retVal = evaluateExpression(bodyNode, env, scope, callStack);
      return { env, returnValue: retVal };
    }

    let currentEnv = new Map(env);
    let capturedReturn: TaintValue | null = null;

    for (const stmt of statements) {
      if (!stmt) continue;

      // 1. VariableDeclaration
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations || []) {
          const varName = decl.id?.name;
          const init = decl.init;

          if (varName) {
            const targetScope = getDeclarationScope(scope, stmt.kind);
            targetScope.declarations.add(varName);
            const varKey = `${targetScope.id}::${varName}`;
            const evalVal = evaluateExpression(init, currentEnv, scope, callStack);

            if (evalVal && evalVal.isTainted) {
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
              // Untainted variable initialization (retains stringValue if known for query resolution)
              if (evalVal && typeof evalVal.stringValue === 'string') {
                currentEnv.set(varKey, evalVal);
              } else {
                currentEnv.set(varKey, null);
              }
            }
          }

          // Destructuring: const { query } = data;
          if (decl.id?.type === 'ObjectPattern' && init) {
            const initVal = evaluateExpression(init, currentEnv, scope, callStack);

            for (const prop of decl.id.properties || []) {
              const propName = prop.key?.name || prop.value?.name;
              if (propName) {
                const targetScope = getDeclarationScope(scope, stmt.kind);
                targetScope.declarations.add(propName);
                const propKey = `${targetScope.id}::${propName}`;

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
                    isUnresolvedFlow: initVal.isUnresolvedFlow,
                    unresolvedFunction: initVal.unresolvedFunction,
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

      // 2. ExpressionStatement: reassignments and sinks
      else if (stmt.type === 'ExpressionStatement') {
        const expr = stmt.expression;

        // 2A. AssignmentExpression
        if (expr?.type === 'AssignmentExpression') {
          const leftName = expr.left?.name;
          if (leftName) {
            if (scope.name === 'global') {
              globalScope.declarations.add(leftName);
            }
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
              // Reassignment to safe/clean value KILLS earlier taint
              if (evalVal && typeof evalVal.stringValue === 'string') {
                currentEnv.set(varKey, evalVal);
              } else {
                currentEnv.set(varKey, null);
              }
            }
          } else if (expr.left?.type === 'MemberExpression') {
            checkPropertyAssignmentSink(expr, currentEnv, scope, callStack);
          }
        }

        // 2B. CallExpression at statement level
        let callExpr: any = null;
        if (expr?.type === 'CallExpression') callExpr = expr;
        else if (expr?.type === 'AwaitExpression' && expr.argument?.type === 'CallExpression') callExpr = expr.argument;

        if (callExpr) {
          checkSinkInvocation(callExpr, currentEnv, scope, callStack);
          evaluateExpression(callExpr, currentEnv, scope, callStack);
        }
      }

      // 3. ReturnStatement
      else if (stmt.type === 'ReturnStatement') {
        if (stmt.argument) {
          if (stmt.argument.type === 'CallExpression') {
            checkSinkInvocation(stmt.argument, currentEnv, scope, callStack);
          }
          const evalRet = evaluateExpression(stmt.argument, currentEnv, scope, callStack);
          capturedReturn = capturedReturn
            ? joinAbstractValues(capturedReturn, evalRet)
            : evalRet;
        }
      }

      // 4. Nested BlockStatement (lexical shadowing)
      else if (stmt.type === 'BlockStatement') {
        const blockScope = createScope('block', scope);
        const blockRes = analyzeBlockStatements(stmt, currentEnv, blockScope, callStack);
        currentEnv = blockRes.env;
        if (blockRes.returnValue) {
          capturedReturn = capturedReturn
            ? joinAbstractValues(capturedReturn, blockRes.returnValue)
            : blockRes.returnValue;
        }
      }

      // 5. IfStatement: Branch-Sensitive State Merging via Join Lattice
      else if (stmt.type === 'IfStatement') {
        if (stmt.test) {
          if (stmt.test.type === 'CallExpression') {
            checkSinkInvocation(stmt.test, currentEnv, scope, callStack);
          }
          evaluateExpression(stmt.test, currentEnv, scope, callStack);
        }

        const priorEnv = new Map(currentEnv);

        // Path 1: Consequent branch evaluated in isolated branch scope
        let ifEnv = new Map(priorEnv);
        if (stmt.consequent) {
          const ifScope = createScope('if_block', scope);
          const ifRes = analyzeBlockStatements(stmt.consequent, new Map(priorEnv), ifScope, callStack);
          ifEnv = ifRes.env;
          if (ifRes.returnValue) {
            capturedReturn = capturedReturn
              ? joinAbstractValues(capturedReturn, ifRes.returnValue)
              : ifRes.returnValue;
          }
        }

        // Path 2: Alternate branch evaluated in isolated branch scope
        // If alternate is omitted, unexecuted path retains prior environment
        let elseEnv = new Map(priorEnv);
        if (stmt.alternate) {
          const elseScope = createScope('else_block', scope);
          const elseRes = analyzeBlockStatements(stmt.alternate, new Map(priorEnv), elseScope, callStack);
          elseEnv = elseRes.env;
          if (elseRes.returnValue) {
            capturedReturn = capturedReturn
              ? joinAbstractValues(capturedReturn, elseRes.returnValue)
              : elseRes.returnValue;
          }
        }

        // Merge ifEnv and elseEnv back into currentEnv using join lattice
        // Calculating the union of tainted states from consequent and alternate branches
        const allKeys = new Set([...ifEnv.keys(), ...elseEnv.keys(), ...priorEnv.keys()]);

        for (const varKey of allKeys) {
          const valIf = ifEnv.get(varKey);
          const valElse = elseEnv.get(varKey);

          const branchStep: InterproceduralPathStep = {
            stepNumber: 1, // Offset dynamically in joinAbstractValues
            type: 'PROPAGATION',
            line: stmt.loc?.start?.line || 1,
            function: scope.name !== 'global' ? scope.name : undefined,
            functionName: scope.name,
            symbol: varKey.split('::')[1] || varKey,
            description: `Branch merge: variable '${varKey.split('::')[1]}' flow merged`,
          };

          const mergedVal = joinAbstractValues(valIf || null, valElse || null, branchStep);
          currentEnv.set(varKey, mergedVal);
        }
      }

      // 6. Loops: evaluate loop body in loop scope
      else if (
        stmt.type === 'ForStatement' ||
        stmt.type === 'ForInStatement' ||
        stmt.type === 'ForOfStatement' ||
        stmt.type === 'WhileStatement' ||
        stmt.type === 'DoWhileStatement'
      ) {
        if (stmt.body) {
          const loopScope = createScope('loop_block', scope);
          const loopRes = analyzeBlockStatements(stmt.body, currentEnv, loopScope, callStack);
          currentEnv = loopRes.env;
          if (loopRes.returnValue) {
            capturedReturn = capturedReturn
              ? joinAbstractValues(capturedReturn, loopRes.returnValue)
              : loopRes.returnValue;
          }
        }
      }
    }

    return { env: currentEnv, returnValue: capturedReturn };
  }

  // Checks assignment to property sinks (e.g. location.href, element.innerHTML)
  function checkPropertyAssignmentSink(
    assignNode: any,
    env: Map<string, TaintValue | null>,
    scope: LexicalScope,
    callStack: string[]
  ) {
    const left = assignNode.left;
    let objectName = '';
    let propName = '';

    if (left?.type === 'MemberExpression') {
      objectName = (left.object?.name || '').toLowerCase();
      propName = (left.property?.name || left.property?.value || '').toLowerCase();
    }

    let sinkContext: SinkContext | null = null;
    let sinkThreat: TaintThreatType | null = null;

    if (objectName === 'location' && propName === 'href') {
      // Determine if right-hand side is a full destination or query component
      sinkContext = analyzeUrlSinkContext(assignNode.right, env, scope, callStack);
      sinkThreat = 'XSS';
    } else if (propName === 'innerhtml' || propName === 'outerhtml') {
      sinkContext = 'HTML_BODY';
      sinkThreat = 'XSS';
    }

    if (sinkContext && sinkThreat && assignNode.right) {
      const argEval = evaluateExpression(assignNode.right, env, scope, callStack);
      if (argEval && argEval.isTainted) {
        const line = assignNode.loc?.start?.line || 1;
        const sinkSymbol = `${objectName}.${propName}`;

        const sinkStep: InterproceduralPathStep = {
          stepNumber: argEval.history.length + 1,
          type: 'SINK',
          line,
          function: scope.name !== 'global' ? scope.name : undefined,
          functionName: scope.name,
          symbol: sinkSymbol,
          description: `Taint assigned to sensitive sink '${sinkSymbol}' [Context: ${sinkContext}]`,
        };

        const fullPath = [...argEval.history, sinkStep];
        const sourceStep = fullPath[0];

        let effectiveSanitized = false;
        if (argEval.sanitizerStep) {
          effectiveSanitized = doesNeutralizeThreatInContext(
            argEval.sanitizerStep.name,
            sinkThreat,
            sinkContext
          );
        }

        const confidence: VulnerabilityConfidence = argEval.isUnresolvedFlow
          ? 'unresolved_flow'
          : 'confirmed';

        const isDuplicate = vulnerabilities.some(
          v => v.sink.line === line && v.source.line === sourceStep?.line && v.sanitized === effectiveSanitized
        );

        if (!isDuplicate) {
          vulnerabilities.push({
            id: `ip-vuln-${vulnCount++}`,
            vulnerabilityType: sinkThreat, // Correct threat associated at sink
            confidence,
            isUnresolvedFlow: argEval.isUnresolvedFlow,
            unresolvedFunction: argEval.unresolvedFunction,
            sinkContext,
            source: {
              file: filename,
              line: sourceStep?.line || 1,
              symbol: sourceStep?.symbol || 'input',
            },
            sink: {
              file: filename,
              line,
              symbol: sinkSymbol,
            },
            sanitized: effectiveSanitized,
            sanitizerStep: argEval.sanitizerStep,
            path: fullPath,
          });
        }
      }
    }
  }

  // Checks sensitive call sinks: query, exec, open, send, eval, etc.
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

    let sinkContext: SinkContext | null = null;
    let sinkThreat: TaintThreatType | null = null;

    // 1. SQL Query Sinks (query, execute, raw)
    if ((methodName === 'query' || methodName === 'execute' || methodName === 'raw') &&
        !['document', 'window', 'url', 'searchparams', 'router', 'graphql'].includes(objectName)) {
      sinkContext = 'SQL_QUERY';
      sinkThreat = 'SQL_INJECTION';
    }
    // 2. HTML Body Sinks (res.send, innerHTML, document.write)
    else if (methodName === 'send' || methodName === 'innerhtml' || methodName === 'write') {
      sinkContext = 'HTML_BODY';
      sinkThreat = 'XSS';
    }
    // 3. JavaScript Execution Sinks (eval, Function)
    else if (methodName === 'eval' || methodName === 'function') {
      sinkContext = 'JAVASCRIPT_CONTEXT';
      sinkThreat = 'XSS';
    }
    // 4. URL Sinks (window.open, location.href, setAttribute)
    else if (methodName === 'open' || (objectName === 'location' && methodName === 'href')) {
      const firstArg = callNode.arguments[0];
      sinkContext = analyzeUrlSinkContext(firstArg, env, scope, callStack);
      sinkThreat = 'XSS';
    }
    // 5. HTML Attribute Sink (element.setAttribute)
    else if (methodName === 'setattribute' && callNode.arguments?.length >= 2) {
      const attrNameArg = callNode.arguments[0];
      const attrName = (attrNameArg?.value || '').toLowerCase();
      if (attrName === 'href' || attrName === 'src') {
        sinkContext = 'URL_DESTINATION';
      } else {
        sinkContext = 'HTML_ATTRIBUTE';
      }
      sinkThreat = 'XSS';
    }
    // 6. Command Execution Sinks (exec, spawn, execSync)
    else if (methodName === 'exec' || methodName === 'spawn' || methodName === 'execsync') {
      sinkContext = 'COMMAND_EXEC';
      sinkThreat = 'COMMAND_INJECTION';
    }
    // 7. Path Traversal Sinks (readFile, readFileSync, createReadStream)
    else if (methodName === 'readfile' || methodName === 'readfilesync' || methodName === 'createreadstream') {
      sinkContext = 'PATH_RESOLVE';
      sinkThreat = 'PATH_TRAVERSAL';
    }

    if (sinkContext && sinkThreat && callNode.arguments?.length > 0) {
      const firstArg = callNode.arguments[0];
      const secondArg = callNode.arguments[1];

      // Safe Parameterized Query Verification (Medium 4)
      const isParamSafe = sinkContext === 'SQL_QUERY' && 
        isParameterizedCall(firstArg, secondArg, env, scope, callStack);

      if (!isParamSafe) {
        // For setAttribute, the tainted argument to check is the second argument (value)
        const targetArg = (methodName === 'setattribute' && callNode.arguments.length >= 2)
          ? callNode.arguments[1]
          : firstArg;

        const argEval = evaluateExpression(targetArg, env, scope, callStack);

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
            description: `Query executed in sensitive sink '${sinkSymbol}()' [Context: ${sinkContext}]`,
          };

          const fullPath = [...argEval.history, sinkStep];
          const sourceStep = fullPath[0];

          // Context-sensitive sanitization check
          let effectiveSanitized = argEval.sanitized;
          if (argEval.sanitizerStep) {
            const isNeutralizedInThisContext = doesNeutralizeThreatInContext(
              argEval.sanitizerStep.name,
              sinkThreat,
              sinkContext
            );
            effectiveSanitized = isNeutralizedInThisContext;
          }

          const confidence: VulnerabilityConfidence = argEval.isUnresolvedFlow
            ? 'unresolved_flow'
            : 'confirmed';

          const isDuplicate = vulnerabilities.some(
            v => v.sink.line === line && v.source.line === sourceStep?.line && v.sanitized === effectiveSanitized
          );

          if (!isDuplicate) {
            vulnerabilities.push({
              id: `ip-vuln-${vulnCount++}`,
              vulnerabilityType: sinkThreat, // Correct threat associated at sink!
              confidence,
              isUnresolvedFlow: argEval.isUnresolvedFlow,
              unresolvedFunction: argEval.unresolvedFunction,
              sinkContext,
              source: {
                file: filename,
                line: sourceStep?.line || 1,
                symbol: sourceStep?.symbol || 'input',
              },
              sink: {
                file: filename,
                line,
                symbol: sinkSymbol,
              },
              sanitized: effectiveSanitized,
              sanitizerStep: argEval.sanitizerStep,
              path: fullPath,
            });
          }
        }
      }
    }
  }

  // Worklist-Based Fixed-Point Algorithm with Explicit Abstract State Convergence (Critical 1)
  const MAX_ITERATIONS = options?.maxIterations ?? 50;
  let iterations = 0;
  let converged = true;
  let analysisStatus: AnalysisConvergenceStatus = 'converged';

  const globalScope = createScope('global', null);
  const initialEnv = new Map<string, TaintValue | null>();

  // Run the primary flow-sensitive analysis across the AST
  const rootResult = analyzeBlockStatements(ast, initialEnv, globalScope, []);
  iterations = 1;

  // Detect recursive/cyclic functions in the CallGraph
  const recursiveFunctions = Array.from(callGraph.functions.values()).filter(fn => fn.isRecursive);
  if (recursiveFunctions.length > 0) {
    let stateChanged = true;
    while (stateChanged && iterations < MAX_ITERATIONS) {
      stateChanged = false;
      iterations++;

      for (const recFn of recursiveFunctions) {
        for (const [cacheKey, recRecord] of Array.from(summaryCache.entries())) {
          if (!cacheKey.startsWith(`${recFn.name}::`)) continue;

          const paramSig = cacheKey.substring(`${recFn.name}::`.length);
          const fnScope = createScope(recFn.name, null);
          const fnEnv = new Map<string, TaintValue | null>();

          // Setup parameters from rich abstract signature
          const sigParts = paramSig.split('|');
          recFn.paramNames.forEach((pName, pIdx) => {
            fnScope.declarations.add(pName);
            const pKey = `${fnScope.id}::${pName}`;
            const sigVal = sigParts[pIdx] || 'safe';

            if (sigVal.startsWith('str:')) {
              const decodedStr = decodeURIComponent(sigVal.slice(4));
              fnEnv.set(pKey, {
                isTainted: false,
                threat: 'UNTRUSTED',
                sanitized: false,
                history: [],
                stringValue: decodedStr,
              });
            } else if (sigVal !== 'safe') {
              const segments = sigVal.split(':');
              const threat = (segments[0] || 'UNTRUSTED') as TaintThreatType;
              const isSanitized = segments[1] === 'sanitized';
              const isUnres = segments[3] === 'unres';
              let trackedStr: string | undefined = undefined;
              for (const seg of segments) {
                if (seg.startsWith('str(') && seg.endsWith(')')) {
                  trackedStr = decodeURIComponent(seg.slice(4, -1));
                }
              }

              fnEnv.set(pKey, {
                isTainted: true,
                threat,
                sanitized: isSanitized,
                isUnresolvedFlow: isUnres,
                stringValue: trackedStr,
                history: [{
                  stepNumber: 1,
                  type: 'PARAMETER',
                  line: recFn.startLine,
                  function: recFn.name,
                  symbol: pName,
                  description: `Parameter '${pName}' initialized for fixed-point iteration [${threat}]`,
                }],
              });
            } else {
              fnEnv.set(pKey, null);
            }
          });

          // Re-evaluate recursive function body with current approximation
          const res = analyzeBlockStatements(recFn.declarationNode.body, fnEnv, fnScope, []);
          const prevVal = recRecord.returnVal;
          const newVal = res.returnValue;

          // Abstract state equality check: compares taint, threat, sanitized, properties, unresolved
          if (!isAbstractStateEqual(prevVal, newVal)) {
            summaryCache.set(cacheKey, {
              returnVal: newVal,
              iterations: recRecord.iterations + 1,
              converged: true,
            });
            stateChanged = true;
          }
        }
      }
    }

    if (iterations >= MAX_ITERATIONS && stateChanged) {
      converged = false;
      analysisStatus = 'resource_limit_exceeded';
    }
  }

  // Final evaluation pass: If recursive functions converged, re-evaluate with stable summaryCache
  let finalEnvResult = rootResult;
  if (recursiveFunctions.length > 0 && converged) {
    vulnerabilities.length = 0;
    const finalEnv = new Map<string, TaintValue | null>();
    globalScope.declarations.clear();
    finalEnvResult = analyzeBlockStatements(ast, finalEnv, globalScope, []);
  }

  // Extract final variable states for verification assertions
  const finalVariables: Record<string, FinalVariableState> = {};
  for (const varName of globalScope.declarations) {
    const key = resolveVarKey(globalScope, varName);
    const val = finalEnvResult.env.get(key);
    if (val && val.isTainted) {
      finalVariables[varName] = {
        isTainted: true,
        sanitized: val.sanitized,
        threat: val.threat,
      };
    } else {
      finalVariables[varName] = {
        isTainted: false,
      };
    }
  }

  return {
    vulnerabilities,
    iterations,
    converged,
    status: analysisStatus,
    unresolvedCallsCount,
    flowSensitiveStepsEvaluated: stepsEvaluated,
    finalVariables,
  };
}
