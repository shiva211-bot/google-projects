import { executeTrueStaticAnalysis } from '../staticEngine';

export interface CodeMutant {
  id: string;
  ruleId: string;
  name: string;
  category: 'adversarial_bypass' | 'placeholder_style' | 'aliased_client' | 'non_sql_method' | 'nested_expression' | 'redos_variation' | 'proto_pollution_trick';
  mutatedCode: string;
  expectedViolated: boolean;
  description: string;
}

export interface MutationResult {
  mutant: CodeMutant;
  actualViolated: boolean;
  killed: boolean; // Killed means analyzer behaved as expected (sensitive to the mutation)
  survived: boolean; // Survived means analyzer was fooled or missed the behavior change
  durationMs: number;
}

export interface MutationSuiteReport {
  timestamp: string;
  originalTestsCount: number;
  totalMutantsGenerated: number;
  mutantsKilled: number;
  mutantsSurvived: number;
  mutationScorePercent: number; // Killed / Total * 100
  durationMs: number;
  results: MutationResult[];
}

export interface PropertyTestResult {
  propertyName: string;
  description: string;
  samplesTested: number;
  passedCount: number;
  failedCount: number;
  invariantHolds: boolean;
  failures: string[];
}

export interface PropertyBasedReport {
  timestamp: string;
  totalProperties: number;
  passedProperties: number;
  totalSamplesTested: number;
  durationMs: number;
  results: PropertyTestResult[];
}

/**
 * Generates an adversarial mutation test corpus of 96 mutants across SEC-001, SEC-002, SEC-003, and PERF rules.
 */
export function generateAdversarialMutants(): CodeMutant[] {
  const mutants: CodeMutant[] = [];
  let id = 1;

  // =========================================================================
  // 1. SEC-001: SQL INJECTION ADVERSARIAL MUTATIONS (32 Mutants)
  // =========================================================================

  // 12 Aliased Database Clients
  const dbAliases = ['db', 'client', 'connection', 'conn', 'pool', 'sql', 'database', 'sqlClient', 'session', 'repository', 'model', 'knex'];
  for (const alias of dbAliases) {
    mutants.push({
      id: `MUT-SQLI-ALIAS-${id++}`,
      ruleId: 'SEC-001-SQLI',
      name: `Aliased DB Client: ${alias}.query() unparameterized`,
      category: 'aliased_client',
      expectedViolated: true,
      description: `Verifies ${alias}.query() unparameterized concatenation is flagged.`,
      mutatedCode: `const { id } = req.body;\nawait ${alias}.query('SELECT * FROM users WHERE id = ' + id);`,
    });
  }

  // 8 Parameterized Placeholder Styles
  const placeholderStyles = [
    { name: 'Positional Question Mark (?)', sql: 'SELECT * FROM users WHERE id = ?', params: '[id]' },
    { name: 'Postgres Indexed Dollar ($1)', sql: 'SELECT * FROM users WHERE id = $1', params: '[id]' },
    { name: 'Postgres Multi-Indexed ($1, $2)', sql: 'SELECT * FROM users WHERE id = $1 AND role = $2', params: '[id, role]' },
    { name: 'Postgres Multi-Indexed ($1, $2, $3)', sql: 'SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3', params: '[a, b, c]' },
    { name: 'Named Colon Parameter (:id)', sql: 'SELECT * FROM users WHERE id = :id', params: '{ id }' },
    { name: 'Named At Parameter (@id)', sql: 'SELECT * FROM users WHERE id = @id', params: '{ id }' },
    { name: 'Composite Named Params (:user, :tenant)', sql: 'SELECT * FROM users WHERE u = :user AND t = :tenant', params: '{ user, tenant }' },
    { name: 'Raw Safe Query with Prepared Array', sql: 'SELECT * FROM logs WHERE level = ?', params: '["error"]' },
  ];

  for (const p of placeholderStyles) {
    mutants.push({
      id: `MUT-SQLI-PARAM-${id++}`,
      ruleId: 'SEC-001-SQLI',
      name: `Parameterized Query: ${p.name}`,
      category: 'placeholder_style',
      expectedViolated: false,
      description: `Verifies that placeholder style ${p.name} is recognized as SAFE.`,
      mutatedCode: `const { id, role } = req.body;\nawait db.query('${p.sql}', ${p.params});`,
    });
  }

  // 6 Safe Non-SQL .query() / .execute() Methods
  const nonSqlMethods = [
    { name: 'document.querySelector', code: `const el = document.querySelector('div.' + className);` },
    { name: 'urlSearchParams.query', code: `const q = searchParams.query('term' + userInput);` },
    { name: 'graphqlClient.query', code: `await graphql.query('query { user(id: ' + id + ') }');` },
    { name: 'router.query', code: `const page = router.query.page;` },
    { name: 'domElement.query', code: `const child = element.query('span');` },
    { name: 'array.query (filter alias)', code: `const matches = items.query(x => x.id === id);` },
  ];

  for (const n of nonSqlMethods) {
    mutants.push({
      id: `MUT-SQLI-NONSQL-${id++}`,
      ruleId: 'SEC-001-SQLI',
      name: `Safe Non-SQL Call: ${n.name}`,
      category: 'non_sql_method',
      expectedViolated: false,
      description: `Ensures non-database query() call on ${n.name} is not falsely flagged.`,
      mutatedCode: n.code,
    });
  }

  // 6 Concatenation and Nested Expression Variations
  mutants.push({
    id: `MUT-SQLI-NESTED-${id++}`,
    ruleId: 'SEC-001-SQLI',
    name: 'Nested Parentheses in Query String',
    category: 'nested_expression',
    expectedViolated: true,
    description: 'Concatenation nested inside redundant parentheses.',
    mutatedCode: `await db.query(('SELECT * FROM accounts WHERE id = ' + (format(req.body.id))));`,
  });

  mutants.push({
    id: `MUT-SQLI-LITERAL-${id++}`,
    ruleId: 'SEC-001-SQLI',
    name: 'Constant String Concatenation Without User Variables',
    category: 'nested_expression',
    expectedViolated: false,
    description: 'Concatenation of two static string literals is safe.',
    mutatedCode: `await db.query('SELECT * FROM accounts ' + 'WHERE active = true');`,
  });

  mutants.push({
    id: `MUT-SQLI-TEMPLATE-INTERP-${id++}`,
    ruleId: 'SEC-001-SQLI',
    name: 'Template Literal String Interpolation',
    category: 'nested_expression',
    expectedViolated: true,
    description: 'Direct variable in backtick string without bindings.',
    mutatedCode: `await client.execute(\`SELECT * FROM users WHERE token = '\${req.query.token}'\`);`,
  });

  mutants.push({
    id: `MUT-SQLI-TEMPLATE-STATIC-${id++}`,
    ruleId: 'SEC-001-SQLI',
    name: 'Template Literal Pure Static String',
    category: 'nested_expression',
    expectedViolated: false,
    description: 'Backtick string with no expressions is static and safe.',
    mutatedCode: `await client.execute(\`SELECT COUNT(*) FROM users\`);`,
  });

  mutants.push({
    id: `MUT-SQLI-MULTI-CONCAT-${id++}`,
    ruleId: 'SEC-001-SQLI',
    name: 'Multi-part String Concatenation Chain',
    category: 'nested_expression',
    expectedViolated: true,
    description: 'Chain of 3+ string additions including user variable.',
    mutatedCode: `await pool.query('SELECT ' + '*' + ' FROM users WHERE email = ' + req.body.email);`,
  });

  mutants.push({
    id: `MUT-SQLI-PARAM-OBJ-${id++}`,
    ruleId: 'SEC-001-SQLI',
    name: 'Object Parameter Dictionary Bindings',
    category: 'placeholder_style',
    expectedViolated: false,
    description: 'Named parameters provided via key-value dictionary.',
    mutatedCode: `await knex.raw('SELECT * FROM accounts WHERE tenant_id = :tenant', { tenant: id });`,
  });

  // =========================================================================
  // 2. SEC-002: REDOS ADVERSARIAL MUTATIONS (24 Mutants)
  // =========================================================================

  // 12 Vulnerable ReDoS Variations
  const redosVulnerablePatterns = [
    { name: '(a+)+', pattern: '/(a+)+/' },
    { name: '(a*)*', pattern: '/(a*)*/' },
    { name: '(a+){2,}', pattern: '/(a+){2,}/' },
    { name: '(\\w+\\s?)+', pattern: '/(\\w+\\s?)+/' },
    { name: '(a|aa)+', pattern: '/(a|aa)+/' },
    { name: '(a+)+$', pattern: '/(a+)+$/' },
    { name: '([0-9]+)+', pattern: '/([0-9]+)+/' },
    { name: '((x+)+)+', pattern: '/((x+)+)+/' },
    { name: '(b|b+)+', pattern: '/(b|b+)+/' },
    { name: '(a|a?)+', pattern: '/(a|a?)+/' },
    { name: '([a-z]+)+', pattern: '/([a-z]+)+/' },
    { name: '(\\d+)+', pattern: '/(\\d+)+/' },
  ];

  for (const r of redosVulnerablePatterns) {
    mutants.push({
      id: `MUT-REDOS-VULN-${id++}`,
      ruleId: 'SEC-002-REDOS',
      name: `ReDoS Vulnerable: ${r.name}`,
      category: 'redos_variation',
      expectedViolated: true,
      description: `Adversarial pattern ${r.name} causing catastrophic exponential backtracking.`,
      mutatedCode: `const validator = ${r.pattern};\nvalidator.test(input);`,
    });
  }

  // 12 Safe ReDoS Variations
  const redosSafePatterns = [
    { name: '(abc)+ (Constant repeated sequence)', pattern: '/(abc)+/' },
    { name: '(a|b)+ (Disjoint alternation)', pattern: '/(a|b)+/' },
    { name: '^[a-zA-Z0-9]+$ (Single non-nested quantifier)', pattern: '/^[a-zA-Z0-9]+$/' },
    { name: '^[a-zA-Z0-9_-]{3,20}$ (Bounded linear quantifier)', pattern: '/^[a-zA-Z0-9_-]{3,20}$/' },
    { name: 'a+b+c+ (Sequential linear quantifiers)', pattern: '/a+b+c+/' },
    { name: '([a-z]+)@([a-z]+) (Non-nested group captures)', pattern: '/([a-z]+)@([a-z]+)/' },
    { name: '(x|y){2,4} (Fixed upper bounded repeat)', pattern: '/(x|y){2,4}/' },
    { name: '[0-9]{1,5} (Character class bounded range)', pattern: '/[0-9]{1,5}/' },
    { name: '(cat|dog)+ (Disjoint multi-character words)', pattern: '/(cat|dog)+/' },
    { name: '\\d{4}-\\d{2}-\\d{2} (ISO Date format)', pattern: '/^\\d{4}-\\d{2}-\\d{2}$/' },
    { name: '^[a-z]+$ (Simple lower-case word)', pattern: '/^[a-z]+$/' },
    { name: '(foo)+bar+ (Sequential repetition without overlap)', pattern: '/(foo)+bar+/' },
  ];

  for (const r of redosSafePatterns) {
    mutants.push({
      id: `MUT-REDOS-SAFE-${id++}`,
      ruleId: 'SEC-002-REDOS',
      name: `ReDoS Safe: ${r.name}`,
      category: 'redos_variation',
      expectedViolated: false,
      description: `Safe regex pattern ${r.name} that looks similar but evaluates in linear O(N) time.`,
      mutatedCode: `const safeRegex = ${r.pattern};\nsafeRegex.test(input);`,
    });
  }

  // =========================================================================
  // 3. SEC-003: PROTOTYPE POLLUTION ADVERSARIAL MUTATIONS (16 Mutants)
  // =========================================================================

  // 8 Guarded Merges (Safe)
  const guardedMergeVariations = [
    `function m1(t, s) { for (let k in s) { if (k === '__proto__') continue; t[k] = s[k]; } }`,
    `function m2(t, s) { for (let k of Object.keys(s)) { if (k === '__proto__' || k === 'constructor') continue; t[k] = s[k]; } }`,
    `function m3(t, s) { for (let k of Object.keys(s)) { if (k === 'prototype' || k === '__proto__') continue; t[k] = s[k]; } }`,
    `function m4(t, s) { for (let k in s) { if (k === 'constructor' || k === '__proto__' || k === 'prototype') continue; t[k] = s[k]; } }`,
    `function m5(t, s) { for (let k in s) { if (k === '__proto__') break; t[k] = s[k]; } }`,
    `function m6(t, s) { for (let k of Object.keys(s)) { if (k === '__proto__') { continue; } t[k] = s[k]; } }`,
    `function m7(t, s) { for (let k of Object.keys(s)) { if (k === 'constructor') continue; t[k] = s[k]; } }`,
    `function m8(t, s) { for (let k in s) { if (k === 'prototype') continue; t[k] = s[k]; } }`,
  ];

  for (let i = 0; i < guardedMergeVariations.length; i++) {
    mutants.push({
      id: `MUT-PROTO-GUARDED-${id++}`,
      ruleId: 'SEC-003-PROTO-POLLUTION',
      name: `Guarded Prototype Merge Variant #${i + 1}`,
      category: 'proto_pollution_trick',
      expectedViolated: false,
      description: 'Loop properly guarded with key filter prevents prototype pollution.',
      mutatedCode: guardedMergeVariations[i],
    });
  }

  // 8 Unguarded Merges (Vulnerable, including adversarial string trick variations)
  const unguardedMergeVariations = [
    `// String trick: mentions __proto__ in comments\nconst trick = "__proto__";\nfunction u1(t, s) { for (let k in s) { t[k] = s[k]; } }`,
    `// String trick: mentions constructor\nconst trick2 = "constructor";\nfunction u2(t, s) { for (let k in s) { t[k] = s[k]; } }`,
    `// String trick: mentions prototype\nconst trick3 = "prototype";\nfunction u3(t, s) { for (let k in s) { t[k] = s[k]; } }`,
    `function u4(target, source) { for (const key in source) { target[key] = source[key]; } }`,
    `function u5(t, s) { for (const prop of Object.keys(s)) { t[prop] = s[prop]; } }`,
    `function u6(a, b) { for (let i = 0; i < keys.length; i++) { const k = keys[i]; a[k] = b[k]; } }`,
    `function u7(obj, update) { for (const k in update) { obj[k] = update[k]; } }`,
    `function u8(dest, src) { for (const attr in src) { dest[attr] = src[attr]; } }`,
  ];

  for (let i = 0; i < unguardedMergeVariations.length; i++) {
    mutants.push({
      id: `MUT-PROTO-UNGUARDED-${id++}`,
      ruleId: 'SEC-003-PROTO-POLLUTION',
      name: `Unguarded Merge Variant #${i + 1}`,
      category: 'proto_pollution_trick',
      expectedViolated: true,
      description: 'Unguarded computed assignment in loop allows prototype pollution.',
      mutatedCode: unguardedMergeVariations[i],
    });
  }

  // =========================================================================
  // 4. PERF-001: TIMER LEAK MUTATIONS (12 Mutants)
  // =========================================================================

  // 6 Clean Timers
  for (let i = 1; i <= 6; i++) {
    mutants.push({
      id: `MUT-TIMER-CLEAN-${id++}`,
      ruleId: 'PERF-001-TIMER-LEAK',
      name: `Clean Timer Hook Variant #${i}`,
      category: 'adversarial_bypass',
      expectedViolated: false,
      description: 'Timer allocated with explicit clearInterval return teardown function.',
      mutatedCode: `useEffect(() => {\n  const timerId_${i} = setInterval(() => {}, ${i * 100});\n  return () => clearInterval(timerId_${i});\n}, []);`,
    });
  }

  // 6 Uncleaned Timers
  for (let i = 1; i <= 6; i++) {
    mutants.push({
      id: `MUT-TIMER-LEAK-${id++}`,
      ruleId: 'PERF-001-TIMER-LEAK',
      name: `Leaking Timer Hook Variant #${i}`,
      category: 'adversarial_bypass',
      expectedViolated: true,
      description: 'Timer allocated without return teardown callback.',
      mutatedCode: `useEffect(() => {\n  setInterval(() => { console.log('tick'); }, ${i * 200});\n}, []);`,
    });
  }

  // =========================================================================
  // 5. PERF-002: SYNC EVENT LOOP BLOCKING (12 Mutants)
  // =========================================================================

  // 6 Synchronous Blocking Calls
  const syncCalls = [
    { name: 'crypto.pbkdf2Sync', code: 'crypto.pbkdf2Sync(req.body.pwd, salt, 1000, 64, "sha512")' },
    { name: 'crypto.scryptSync', code: 'crypto.scryptSync(req.body.pwd, salt, 64)' },
    { name: 'bcrypt.hashSync', code: 'bcrypt.hashSync(req.body.pwd, 10)' },
    { name: 'child_process.execSync', code: 'child_process.execSync("whoami")' },
    { name: 'crypto.pbkdf2Sync (SHA-256)', code: 'crypto.pbkdf2Sync(key, salt, 10000, 32, "sha256")' },
    { name: 'crypto.scryptSync (Derived)', code: 'crypto.scryptSync(key, salt, 32)' },
  ];
  for (let i = 0; i < syncCalls.length; i++) {
    mutants.push({
      id: `MUT-SYNC-CALL-${id++}`,
      ruleId: 'PERF-002-SYNC-BLOCK',
      name: `Synchronous Blocking Call: ${syncCalls[i].name}`,
      category: 'adversarial_bypass',
      expectedViolated: true,
      description: `Synchronous call ${syncCalls[i].name} freezes the single Node.js event loop.`,
      mutatedCode: `app.post('/api/action_${i}', (req, res) => {\n  const result = ${syncCalls[i].code};\n  res.json({ result });\n});`,
    });
  }

  // 6 Asynchronous Non-blocking Equivalents
  for (let i = 1; i <= 6; i++) {
    mutants.push({
      id: `MUT-ASYNC-CALL-${id++}`,
      ruleId: 'PERF-002-SYNC-BLOCK',
      name: `Asynchronous Non-Blocking Call #${i}`,
      category: 'adversarial_bypass',
      expectedViolated: false,
      description: 'Asynchronous crypto execution via callback or worker promise.',
      mutatedCode: `app.post('/api/async_${i}', async (req, res) => {\n  crypto.pbkdf2(req.body.pwd, salt, 1000, 64, 'sha512', (err, key) => {\n    res.json({ key });\n  });\n});`,
    });
  }

  return mutants;
}

/**
 * Runs the full mutation test suite against the analyzer engine.
 */
export function runMutationTestSuite(): MutationSuiteReport {
  const suiteStart = performance.now();
  const mutants = generateAdversarialMutants();
  const results: MutationResult[] = [];

  let killedCount = 0;
  let survivedCount = 0;

  for (const m of mutants) {
    const start = performance.now();
    const { engineData } = executeTrueStaticAnalysis(m.mutatedCode, 'javascript', `${m.id}.js`);
    const duration = Number((performance.now() - start).toFixed(2));

    const ruleResult = engineData.ruleResults.find(r => r.ruleId === m.ruleId);
    const actualViolated = ruleResult ? !ruleResult.passed : false;

    // Mutant is killed if analyzer's detection matches expected outcome
    const killed = actualViolated === m.expectedViolated;
    const survived = !killed;

    if (killed) killedCount++;
    else survivedCount++;

    results.push({
      mutant: m,
      actualViolated,
      killed,
      survived,
      durationMs: duration,
    });
  }

  const mutationScore = Number(((killedCount / Math.max(1, mutants.length)) * 100).toFixed(1));
  const suiteDuration = Number((performance.now() - suiteStart).toFixed(2));

  return {
    timestamp: new Date().toISOString(),
    originalTestsCount: 16,
    totalMutantsGenerated: mutants.length,
    mutantsKilled: killedCount,
    mutantsSurvived: survivedCount,
    mutationScorePercent: mutationScore,
    durationMs: suiteDuration,
    results,
  };
}

/**
 * Property-Based Analysis Testing:
 * Evaluates formal invariant properties across generative code permutations.
 */
export function runPropertyBasedTests(): PropertyBasedReport {
  const startSuite = performance.now();
  const propertyResults: PropertyTestResult[] = [];

  // Property 1: Any database client calling query/execute with valid parameterized placeholders (? or $1) and parameters array is ALWAYS safe.
  {
    const clients = ['db', 'client', 'connection', 'conn', 'pool', 'sqlClient'];
    const methods = ['query', 'execute'];
    const placeholders = ['WHERE id = ?', 'WHERE id = $1', 'WHERE id = :id'];
    let passed = 0;
    let failed = 0;
    const failures: string[] = [];

    for (const c of clients) {
      for (const m of methods) {
        for (const p of placeholders) {
          const sample = `const { id } = req.body;\nawait ${c}.${m}('SELECT * FROM users ${p}', [id]);`;
          const { engineData } = executeTrueStaticAnalysis(sample, 'javascript', 'prop1.js');
          const rule = engineData.ruleResults.find(r => r.ruleId === 'SEC-001-SQLI');
          if (rule && rule.passed) {
            passed++;
          } else {
            failed++;
            failures.push(`Failed for ${c}.${m} with ${p}`);
          }
        }
      }
    }

    propertyResults.push({
      propertyName: 'PROP-01: Invariant Safety of Parameterized Queries',
      description: 'FOR ALL (dbClient, method, placeholder): client.method(sqlWithPlaceholder, [params]) is ALWAYS SAFE (Zero False Positives).',
      samplesTested: clients.length * methods.length * placeholders.length,
      passedCount: passed,
      failedCount: failed,
      invariantHolds: failed === 0,
      failures,
    });
  }

  // Property 2: Any database client calling query/execute with string concatenation of untrusted variables is ALWAYS flagged.
  {
    const clients = ['db', 'client', 'connection', 'conn', 'pool', 'sqlClient'];
    const methods = ['query', 'execute'];
    let passed = 0;
    let failed = 0;
    const failures: string[] = [];

    for (const c of clients) {
      for (const m of methods) {
        const sample = `const { id } = req.body;\nawait ${c}.${m}('SELECT * FROM users WHERE id = ' + id);`;
        const { engineData } = executeTrueStaticAnalysis(sample, 'javascript', 'prop2.js');
        const rule = engineData.ruleResults.find(r => r.ruleId === 'SEC-001-SQLI');
        if (rule && !rule.passed) {
          passed++;
        } else {
          failed++;
          failures.push(`Failed to detect unparameterized concat for ${c}.${m}`);
        }
      }
    }

    propertyResults.push({
      propertyName: 'PROP-02: Invariant Detection of Unparameterized Concatenation',
      description: 'FOR ALL (dbClient, method): client.method(sql + untrustedId) is ALWAYS FLAGGED as SQL Injection.',
      samplesTested: clients.length * methods.length,
      passedCount: passed,
      failedCount: failed,
      invariantHolds: failed === 0,
      failures,
    });
  }

  // Property 3: Non-SQL method calls on DOM or HTTP utilities are NEVER flagged as database SQL injection.
  {
    const nonSqlObjects = ['document', 'window', 'url', 'searchParams', 'router', 'graphql'];
    let passed = 0;
    let failed = 0;
    const failures: string[] = [];

    for (const obj of nonSqlObjects) {
      const sample = `const result = ${obj}.query('user' + id);`;
      const { engineData } = executeTrueStaticAnalysis(sample, 'javascript', 'prop3.js');
      const rule = engineData.ruleResults.find(r => r.ruleId === 'SEC-001-SQLI');
      if (rule && rule.passed) {
        passed++;
      } else {
        failed++;
        failures.push(`False positive on non-SQL object ${obj}.query()`);
      }
    }

    propertyResults.push({
      propertyName: 'PROP-03: Context Isolation for Non-SQL Objects',
      description: 'FOR ALL non-database objects: nonSqlObj.query() is NEVER falsely flagged as SQL Injection.',
      samplesTested: nonSqlObjects.length,
      passedCount: passed,
      failedCount: failed,
      invariantHolds: failed === 0,
      failures,
    });
  }

  const passedProps = propertyResults.filter(p => p.invariantHolds).length;
  const totalSamples = propertyResults.reduce((acc, p) => acc + p.samplesTested, 0);

  return {
    timestamp: new Date().toISOString(),
    totalProperties: propertyResults.length,
    passedProperties: passedProps,
    totalSamplesTested: totalSamples,
    durationMs: Number((performance.now() - startSuite).toFixed(2)),
    results: propertyResults,
  };
}
