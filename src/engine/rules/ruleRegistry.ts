import { ASTNode, StaticRuleResult, ControlFlowGraph } from '../ast/types';
import { analyzeRegexForReDoS } from './redosAnalyzer';

export function runStaticRules(
  ast: ASTNode | null, 
  code: string, 
  cfg: ControlFlowGraph
): StaticRuleResult[] {
  const results: StaticRuleResult[] = [];
  const lines = code.split('\n');

  function getSnippet(lineNum: number): string {
    return lines[lineNum - 1]?.trim() || '';
  }

  // 1. RULE: SEC-001 SQL Injection (AST Method & Argument Inspection)
  {
    const start = performance.now();
    let nodesInspected = 0;
    const violations: StaticRuleResult['violations'] = [];

    const DB_OBJECT_NAMES = new Set([
      'db', 'client', 'connection', 'conn', 'pool', 'sql', 'database',
      'knex', 'prisma', 'session', 'repository', 'sqlclient', 'model',
    ]);

    const NON_SQL_OBJECTS = new Set([
      'document', 'window', 'url', 'params', 'searchparams', 'router',
      'graphql', 'apollo', 'fs', 'path', 'array', 'element', 'domelement',
      'querystring', 'formdata', 'headers',
    ]);

    function expressionContainsDynamicVariables(exprNode: any): boolean {
      if (!exprNode) return false;
      if (exprNode.type === 'Literal') return false; // Pure constant string/number
      if (exprNode.type === 'Identifier') return true; // Dynamic variable!
      if (exprNode.type === 'TemplateLiteral') return Boolean(exprNode.expressions && exprNode.expressions.length > 0);
      if (exprNode.type === 'CallExpression') return true; // Dynamic function call!
      if (exprNode.type === 'BinaryExpression') {
        return expressionContainsDynamicVariables(exprNode.left) || expressionContainsDynamicVariables(exprNode.right);
      }
      return true;
    }

    function isSafeParameterizedQuery(firstArg: any, secondArg: any): boolean {
      if (!secondArg) return false;

      // Extract raw string of first argument
      let queryStr = '';
      if (firstArg.type === 'Literal' && typeof firstArg.value === 'string') {
        queryStr = firstArg.value;
      } else if (firstArg.type === 'TemplateLiteral' && (!firstArg.expressions || firstArg.expressions.length === 0)) {
        queryStr = firstArg.quasis.map((q: any) => q.value?.raw || '').join('');
      }

      // Check placeholder styles: ?, $1, :name, @name
      const hasPlaceholders = /\?|\$\d+|:[a-zA-Z0-9_]+|@[a-zA-Z0-9_]+/.test(queryStr);
      // Check that second argument provides parameters (Array, Object, or identifier)
      const hasParamContainer = secondArg.type === 'ArrayExpression' ||
        secondArg.type === 'ObjectExpression' ||
        secondArg.type === 'Identifier';

      return hasPlaceholders && hasParamContainer;
    }

    function checkSQL(node: any) {
      if (!node || typeof node !== 'object') return;
      nodesInspected++;

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

        const isQueryMethod = methodName === 'query' || methodName === 'execute' || methodName === 'raw' || methodName === 'querysync';
        const isNonSQL = NON_SQL_OBJECTS.has(objectName);

        if (isQueryMethod && !isNonSQL) {
          const firstArg = node.arguments?.[0];
          const secondArg = node.arguments?.[1];
          const line = node.loc?.start?.line || 1;

          if (firstArg) {
            // Check if parameterized with placeholder styles
            const isParamSafe = isSafeParameterizedQuery(firstArg, secondArg);

            if (!isParamSafe) {
              // 1. Template literal with expressions: `SELECT ... ${username}`
              if (firstArg.type === 'TemplateLiteral' && firstArg.expressions?.length > 0) {
                violations.push({
                  line,
                  nodeType: 'CallExpression:TemplateLiteral',
                  message: `Unparameterized database ${methodName}() call using template literal with dynamic expressions.`,
                  snippet: getSnippet(line),
                  fixSnippet: `const query = 'SELECT ... WHERE id = ?';\nawait ${callee.object?.name || 'db'}.${methodName}(query, [params]);`,
                });
              }

              // 2. String Concatenation via BinaryExpression (+): 'SELECT ...' + id
              if (firstArg.type === 'BinaryExpression' && firstArg.operator === '+' && expressionContainsDynamicVariables(firstArg)) {
                violations.push({
                  line,
                  nodeType: 'CallExpression:BinaryExpression',
                  message: `Unparameterized database ${methodName}() call using string concatenation with untrusted input.`,
                  snippet: getSnippet(line),
                  fixSnippet: `await ${callee.object?.name || 'db'}.${methodName}('SELECT ... WHERE id = ?', [id]);`,
                });
              }

              // 3. Nested parentheses / sequence expression with concatenation
              if (firstArg.type === 'SequenceExpression') {
                violations.push({
                  line,
                  nodeType: 'CallExpression:Sequence',
                  message: `Dynamic expression passed to database ${methodName}() without parameterization.`,
                  snippet: getSnippet(line),
                });
              }
            }
          }
        }
      }

      // Check top-level raw SQL template declaration or assignment if later passed to query
      if (node.type === 'VariableDeclarator' && node.init) {
        const line = node.loc?.start?.line || 1;

        function containsSqlDynamicTemplate(expr: any): boolean {
          if (!expr) return false;
          if (expr.type === 'TemplateLiteral') {
            const rawStr = expr.quasis?.map((q: any) => q.value?.raw || '').join(' ') || '';
            const fullSnippet = code.slice(expr.range?.[0] || 0, expr.range?.[1] || 0) || rawStr;
            return /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/i.test(fullSnippet || rawStr) && Boolean(expr.expressions?.length > 0);
          }
          if (expr.type === 'ConditionalExpression') {
            return containsSqlDynamicTemplate(expr.consequent) || containsSqlDynamicTemplate(expr.alternate);
          }
          if (expr.type === 'CallExpression') {
            if (expr.callee?.property?.name === 'join' && expr.callee.object?.type === 'ArrayExpression') {
              return expr.callee.object.elements?.some((el: any) => containsSqlDynamicTemplate(el) || expressionContainsDynamicVariables(el));
            }
          }
          if (expr.type === 'BinaryExpression' && expr.operator === '+') {
            const snippet = getSnippet(line);
            return /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/i.test(snippet) && expressionContainsDynamicVariables(expr);
          }
          return false;
        }

        if (containsSqlDynamicTemplate(node.init)) {
          violations.push({
            line,
            nodeType: 'VariableDeclarator:SQLTemplate',
            message: 'Raw SQL template literal incorporates unparameterized expressions.',
            snippet: getSnippet(line),
            fixSnippet: `const query = 'SELECT ... WHERE col = ?';`,
          });
        }
      }

      for (const k in node) {
        if (k !== 'loc' && typeof node[k] === 'object') checkSQL(node[k]);
      }
    }

    if (ast) checkSQL(ast);

    results.push({
      ruleId: 'SEC-001-SQLI',
      ruleName: 'AST SQL Parameterization Validator',
      category: 'security',
      severity: 'critical',
      passed: violations.length === 0,
      nodesInspectedCount: nodesInspected,
      executionTimeMs: Number((performance.now() - start).toFixed(2)),
      violations,
    });
  }

  // 2. RULE: PERF-001 Timer Leak in useEffect
  {
    const start = performance.now();
    let nodesInspected = 0;
    const violations: StaticRuleResult['violations'] = [];

    function checkTimers(node: any) {
      if (!node || typeof node !== 'object') return;
      nodesInspected++;

      if (node.type === 'CallExpression') {
        const callee = node.callee?.name;
        if (callee === 'useEffect' || callee === 'useLayoutEffect') {
          const effectFn = node.arguments?.[0];
          const line = node.loc?.start?.line || 1;

          let hasTimerOrListener = false;
          let hasCleanupReturn = false;
          let timerLine = line;

          function scanEffectBody(inner: any) {
            if (!inner || typeof inner !== 'object') return;
            if (inner.type === 'CallExpression') {
              const innerCallee = inner.callee?.name;
              if (innerCallee === 'setInterval' || innerCallee === 'setTimeout' || innerCallee === 'addEventListener') {
                hasTimerOrListener = true;
                timerLine = inner.loc?.start?.line || line;
              }
            }
            if (inner.type === 'ReturnStatement') {
              hasCleanupReturn = true;
            }
            for (const k in inner) {
              if (k !== 'loc' && typeof inner[k] === 'object') scanEffectBody(inner[k]);
            }
          }

          if (effectFn) scanEffectBody(effectFn);

          if (hasTimerOrListener && !hasCleanupReturn) {
            violations.push({
              line: timerLine,
              nodeType: 'CallExpression:useEffect',
              message: 'Timer or event listener allocated inside React Hook effect without teardown return function.',
              snippet: getSnippet(timerLine),
              fixSnippet: `const id = setInterval(...);\nreturn () => clearInterval(id);`,
            });
          }
        }
      }

      for (const k in node) {
        if (k !== 'loc' && typeof node[k] === 'object') checkTimers(node[k]);
      }
    }

    if (ast) checkTimers(ast);

    results.push({
      ruleId: 'PERF-001-TIMER-LEAK',
      ruleName: 'React Hook Lifecycle Cleanup Visitor',
      category: 'performance',
      severity: 'high',
      passed: violations.length === 0,
      nodesInspectedCount: nodesInspected,
      executionTimeMs: Number((performance.now() - start).toFixed(2)),
      violations,
    });
  }

  // 3. RULE: PERF-002 Synchronous Blocking Crypto / Exec on Event Loop
  {
    const start = performance.now();
    let nodesInspected = 0;
    const violations: StaticRuleResult['violations'] = [];

    function checkSyncBlock(node: any) {
      if (!node || typeof node !== 'object') return;
      nodesInspected++;

      if (node.type === 'CallExpression') {
        const calleeStr = node.callee?.property?.name || node.callee?.name || '';
        const line = node.loc?.start?.line || 1;

        if (/pbkdf2Sync|scryptSync|hashSync|execSync|spawnSync/i.test(calleeStr)) {
          violations.push({
            line,
            nodeType: 'CallExpression',
            message: `Synchronous heavy CPU blocking call \`${calleeStr}()\` freezes the main Node.js event loop thread.`,
            snippet: getSnippet(line),
            fixSnippet: `await new Promise((res, rej) => crypto.pbkdf2(..., (err, k) => ...));`,
          });
        }
      }

      for (const k in node) {
        if (k !== 'loc' && typeof node[k] === 'object') checkSyncBlock(node[k]);
      }
    }

    if (ast) checkSyncBlock(ast);

    results.push({
      ruleId: 'PERF-002-SYNC-BLOCK',
      ruleName: 'Non-Blocking Event Loop Concurrency Guard',
      category: 'performance',
      severity: 'critical',
      passed: violations.length === 0,
      nodesInspectedCount: nodesInspected,
      executionTimeMs: Number((performance.now() - start).toFixed(2)),
      violations,
    });
  }

  // 4. RULE: SEC-002 Catastrophic ReDoS (Structural Pattern Analysis)
  {
    const start = performance.now();
    let nodesInspected = 0;
    const violations: StaticRuleResult['violations'] = [];

    function checkRegex(node: any) {
      if (!node || typeof node !== 'object') return;
      nodesInspected++;

      // Pattern 1: RegExp Literal: /.../
      if (node.type === 'Literal' && node.regex) {
        const pattern = node.regex.pattern;
        const line = node.loc?.start?.line || 1;
        const analysis = analyzeRegexForReDoS(pattern);

        if (analysis.isVulnerable) {
          violations.push({
            line,
            nodeType: 'Literal:RegExp',
            message: `Catastrophic Backtracking detected in RegExp pattern /${pattern}/: ${analysis.reason}`,
            snippet: getSnippet(line),
            fixSnippet: `const SAFE_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;`,
          });
        }
      }

      // Pattern 2: RegExp Constructor: new RegExp(...)
      if (node.type === 'NewExpression' && node.callee?.name === 'RegExp') {
        const arg = node.arguments?.[0];
        if (arg?.type === 'Literal' && typeof arg.value === 'string') {
          const line = node.loc?.start?.line || 1;
          const analysis = analyzeRegexForReDoS(arg.value);
          if (analysis.isVulnerable) {
            violations.push({
              line,
              nodeType: 'NewExpression:RegExp',
              message: `Catastrophic Backtracking in dynamic RegExp /${arg.value}/: ${analysis.reason}`,
              snippet: getSnippet(line),
            });
          }
        }
      }

      for (const k in node) {
        if (k !== 'loc' && typeof node[k] === 'object') checkRegex(node[k]);
      }
    }

    if (ast) checkRegex(ast);

    results.push({
      ruleId: 'SEC-002-REDOS',
      ruleName: 'Exponential Backtracking Regex Analyzer',
      category: 'security',
      severity: 'high',
      passed: violations.length === 0,
      nodesInspectedCount: nodesInspected,
      executionTimeMs: Number((performance.now() - start).toFixed(2)),
      violations,
    });
  }

  // 5. RULE: SEC-003 Prototype Pollution (AST Control Flow & Dominance Inspection)
  {
    const start = performance.now();
    let nodesInspected = 0;
    const violations: StaticRuleResult['violations'] = [];

    // Helper: checks whether an AST loop body or enclosing block contains a prototype guard
    function loopHasPrototypeGuard(loopNode: any): boolean {
      let hasGuard = false;

      // Check if code contains prototype key filter
      if (/__proto__|constructor|prototype/.test(code) && /filter|includes|hasOwn|indexOf|!==|!=/.test(code)) {
        hasGuard = true;
        return true;
      }

      function inspectLoop(n: any) {
        if (!n || typeof n !== 'object' || hasGuard) return;

        // Check IfStatement checking '__proto__', 'constructor', or 'prototype'
        if (n.type === 'IfStatement') {
          const testNode = n.test;
          let mentionsProtoKey = false;

          function scanTest(expr: any) {
            if (!expr || typeof expr !== 'object') return;
            if (expr.type === 'Literal') {
              const val = String(expr.value || '');
              if (val === '__proto__' || val === 'constructor' || val === 'prototype') {
                mentionsProtoKey = true;
              }
            }
            for (const key in expr) {
              if (key !== 'loc' && typeof expr[key] === 'object') scanTest(expr[key]);
            }
          }

          scanTest(testNode);

          if (mentionsProtoKey) {
            hasGuard = true;
            return;
          }
        }

        for (const k in n) {
          if (k !== 'loc' && typeof n[k] === 'object') inspectLoop(n[k]);
        }
      }

      inspectLoop(loopNode);
      return hasGuard;
    }

    function checkProtoPollution(node: any) {
      if (!node || typeof node !== 'object') return;
      nodesInspected++;

      // Pattern 1: Nested computed path assignment outside loop: store[p1][p2] = payload;
      if (node.type === 'AssignmentExpression') {
        const left = node.left;
        if (left?.type === 'MemberExpression' && left.computed && left.object?.type === 'MemberExpression' && left.object.computed) {
          const line = node.loc?.start?.line || 1;
          violations.push({
            line,
            nodeType: 'AssignmentExpression:DeepPath',
            message: 'Unvalidated multi-level dynamic path property assignment allows prototype pollution.',
            snippet: getSnippet(line),
            fixSnippet: `if (p1 === '__proto__' || p2 === '__proto__') return;`,
          });
        }
      }

      // Pattern 2: forEach callback computed assignment: entries.forEach(([key, val]) => acc[key] = val)
      if (node.type === 'CallExpression' && node.callee?.property?.name === 'forEach') {
        const callback = node.arguments?.[0];
        if (callback && (callback.type === 'ArrowFunctionExpression' || callback.type === 'FunctionExpression')) {
          let hasComputed = false;
          let assignLine = node.loc?.start?.line || 1;

          function scanCb(inner: any) {
            if (!inner || typeof inner !== 'object') return;
            if (inner.type === 'AssignmentExpression' && inner.left?.type === 'MemberExpression' && inner.left.computed) {
              hasComputed = true;
              assignLine = inner.loc?.start?.line || assignLine;
            }
            for (const k in inner) {
              if (k !== 'loc' && typeof inner[k] === 'object') scanCb(inner[k]);
            }
          }

          scanCb(callback.body);

          if (hasComputed && !loopHasPrototypeGuard(callback.body)) {
            violations.push({
              line: assignLine,
              nodeType: 'CallExpression:forEach:ComputedProperty',
              message: 'Computed object assignment inside forEach loop without prototype key sanitization.',
              snippet: getSnippet(assignLine),
            });
          }
        }
      }

      // Pattern 3: Loops iterating over object properties: ForInStatement, ForOfStatement, ForStatement
      if (node.type === 'ForInStatement' || node.type === 'ForOfStatement' || node.type === 'ForStatement') {
        const loopBody = node.body;
        const line = node.loc?.start?.line || 1;

        // Check if there is a computed assignment inside this loop: target[key] = ...
        let hasComputedAssignment = false;
        let assignmentLine = line;

        function findComputedAssignment(inner: any) {
          if (!inner || typeof inner !== 'object') return;

          if (inner.type === 'AssignmentExpression') {
            const left = inner.left;
            if (left?.type === 'MemberExpression' && left.computed === true) {
              // Exclude numeric array index loops: arr[i] = ...
              const propName = left.property?.name;
              const objName = left.object?.name;
              const isNumericIndex = (propName === 'i' || propName === 'j' || propName === 'idx' || propName === 'index') &&
                (objName === 'arr' || objName === 'array' || node.type === 'ForStatement');

              if (!isNumericIndex) {
                hasComputedAssignment = true;
                assignmentLine = inner.loc?.start?.line || line;
              }
            }
          }

          for (const k in inner) {
            if (k !== 'loc' && typeof inner[k] === 'object') findComputedAssignment(inner[k]);
          }
        }

        findComputedAssignment(loopBody);

        if (hasComputedAssignment) {
          // Verify whether loop AST contains a dominating guard statement for __proto__ / prototype
          const isGuarded = loopHasPrototypeGuard(loopBody);

          if (!isGuarded) {
            violations.push({
              line: assignmentLine,
              nodeType: 'AssignmentExpression:ComputedProperty',
              message: 'Computed object property assignment inside loop without prototype key sanitization (__proto__ / constructor).',
              snippet: getSnippet(assignmentLine),
              fixSnippet: `if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;`,
            });
          }
        }
      }

      for (const k in node) {
        if (k !== 'loc' && typeof node[k] === 'object') checkProtoPollution(node[k]);
      }
    }

    if (ast) checkProtoPollution(ast);

    results.push({
      ruleId: 'SEC-003-PROTO-POLLUTION',
      ruleName: 'Prototype Key Sanitization AST Guard',
      category: 'security',
      severity: 'high',
      passed: violations.length === 0,
      nodesInspectedCount: nodesInspected,
      executionTimeMs: Number((performance.now() - start).toFixed(2)),
      violations,
    });
  }

  // 6. RULE: PERF-003 N+1 Query in Loops
  {
    const start = performance.now();
    let nodesInspected = 0;
    const violations: StaticRuleResult['violations'] = [];

    function checkNPlusOne(node: any) {
      if (!node || typeof node !== 'object') return;
      nodesInspected++;

      if (node.type === 'ForStatement' || node.type === 'ForOfStatement' || node.type === 'ForInStatement' || node.type === 'WhileStatement') {
        const line = node.loc?.start?.line || 1;

        let hasNestedQuery = false;
        let queryLine = line;

        function scanLoop(inner: any) {
          if (!inner || typeof inner !== 'object') return;
          if (inner.type === 'CallExpression') {
            const calleeStr = inner.callee?.property?.name || inner.callee?.name || '';
            if (/(query|filter_by|findUnique|findMany|execute)/i.test(calleeStr) || /db\.query|session\.query/i.test(getSnippet(inner.loc?.start?.line || line))) {
              hasNestedQuery = true;
              queryLine = inner.loc?.start?.line || line;
            }
          }
          for (const k in inner) {
            if (k !== 'loc' && typeof inner[k] === 'object') scanLoop(inner[k]);
          }
        }

        scanLoop(node.body);

        if (hasNestedQuery) {
          violations.push({
            line: queryLine,
            nodeType: 'LoopStatement:Query',
            message: 'Database I/O query executed inside loop iteration body (N+1 Query Anti-Pattern).',
            snippet: getSnippet(queryLine),
            fixSnippet: `// Use JOIN eager loading or batch IN (...) query ahead of loop`,
          });
        }
      }

      for (const k in node) {
        if (k !== 'loc' && typeof node[k] === 'object') checkNPlusOne(node[k]);
      }
    }

    if (ast) checkNPlusOne(ast);

    results.push({
      ruleId: 'PERF-003-N-PLUS-ONE',
      ruleName: 'Loop Database I/O Batched Query Visitor',
      category: 'performance',
      severity: 'high',
      passed: violations.length === 0,
      nodesInspectedCount: nodesInspected,
      executionTimeMs: Number((performance.now() - start).toFixed(2)),
      violations,
    });
  }

  // 7. RULE: REL-001 Unreachable / Dead Code from CFG
  {
    const start = performance.now();
    const violations = cfg.deadCodeBlocks.map(blk => ({
      line: blk.line || 1,
      nodeType: 'CFGNode:DeadBlock',
      message: `Unreachable statement block '${blk.label}' detected by Control Flow Graph traversal.`,
      snippet: blk.codeSnippet || getSnippet(blk.line || 1),
      fixSnippet: '// Remove dead code block',
    }));

    results.push({
      ruleId: 'REL-001-UNREACHABLE-CFG',
      ruleName: 'Control Flow Reachability & Dead Code Detector',
      category: 'reliability',
      severity: 'low',
      passed: violations.length === 0,
      nodesInspectedCount: cfg.nodes.length,
      executionTimeMs: Number((performance.now() - start).toFixed(2)),
      violations,
    });
  }

  return results;
}
