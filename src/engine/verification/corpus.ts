export interface TestCase {
  id: string;
  name: string;
  category: 'security' | 'performance' | 'cfg' | 'taint' | 'halstead' | 'false_positive';
  expectedType: 'true_positive' | 'true_negative' | 'cfg_check' | 'metric_check';
  code: string;
  language: string;
  description: string;
  assertions: {
    ruleId?: string;
    shouldViolate?: boolean;
    expectedTaintType?: string;
    expectedTaintStepsCount?: number;
    expectedSourceLine?: number;
    expectedSinkLine?: number;
    expectedDeadBlocksCount?: number;
    expectedCyclomaticComplexity?: number;
    expectedDistinctOperators?: number;
    expectedDistinctOperands?: number;
    expectedVocabulary?: number;
    minMaintainabilityIndex?: number;
    maxMaintainabilityIndex?: number;
  };
}

export const BENCHMARK_CORPUS: TestCase[] = [
  // ==========================================
  // SECTION 1: TRUE POSITIVES (Vulnerabilities)
  // ==========================================
  {
    id: 'TP-SQLI-01',
    name: 'Multi-Step Taint-Tracked SQL Injection',
    category: 'taint',
    expectedType: 'true_positive',
    language: 'javascript',
    description: 'Verifies complete taint path: req.body ingestion -> variable assignment -> template literal -> db.query sink.',
    code: `const express = require('express');
const { username } = req.body;
const query = \`SELECT * FROM users WHERE username = '\${username}'\`;
await db.query(query);`,
    assertions: {
      ruleId: 'SEC-001-SQLI',
      shouldViolate: true,
      expectedTaintType: 'SQL_INJECTION',
      expectedTaintStepsCount: 3,
      expectedSourceLine: 2,
      expectedSinkLine: 4,
    },
  },
  {
    id: 'TP-TIMER-01',
    name: 'React useEffect Uncleaned Timer',
    category: 'performance',
    expectedType: 'true_positive',
    language: 'javascript',
    description: 'Detects setInterval inside useEffect hook without return teardown callback.',
    code: `useEffect(() => {
  setInterval(() => {
    console.log('tick');
  }, 1000);
}, []);`,
    assertions: {
      ruleId: 'PERF-001-TIMER-LEAK',
      shouldViolate: true,
    },
  },
  {
    id: 'TP-SYNC-01',
    name: 'Synchronous Crypto pbkdf2Sync Event Loop Block',
    category: 'performance',
    expectedType: 'true_positive',
    language: 'javascript',
    description: 'Detects pbkdf2Sync synchronous crypto operation on main thread.',
    code: `app.post('/auth', (req, res) => {
  const hash = crypto.pbkdf2Sync(req.body.pwd, salt, 100000, 64, 'sha512');
  res.json({ hash });
});`,
    assertions: {
      ruleId: 'PERF-002-SYNC-BLOCK',
      shouldViolate: true,
    },
  },
  {
    id: 'TP-REDOS-01',
    name: 'Catastrophic ReDoS Nested Quantifier',
    category: 'security',
    expectedType: 'true_positive',
    language: 'javascript',
    description: 'Detects exponential backtracking regex pattern /([a-z]+)+$/ with nested quantifiers.',
    code: `const evilRegex = /^([a-zA-Z0-9]+)+$/;
evilRegex.test(userInput);`,
    assertions: {
      ruleId: 'SEC-002-REDOS',
      shouldViolate: true,
    },
  },
  {
    id: 'TP-PROTO-01',
    name: 'Unchecked Recursive Object Merge Prototype Pollution',
    category: 'security',
    expectedType: 'true_positive',
    language: 'security',
    description: 'Detects recursive object traversal copying properties without __proto__ / prototype guard.',
    code: `function unsafeMerge(target, source) {
  for (const key of Object.keys(source)) {
    target[key] = source[key];
  }
  return target;
}`,
    assertions: {
      ruleId: 'SEC-003-PROTO-POLLUTION',
      shouldViolate: true,
    },
  },
  {
    id: 'TP-NPLUS1-01',
    name: 'Loop Nested Database Query (N+1 Anti-Pattern)',
    category: 'performance',
    expectedType: 'true_positive',
    language: 'javascript',
    description: 'Detects database query call executed inside for-loop iteration body.',
    code: `for (const order of orders) {
  const customer = await db.query('SELECT * FROM customers WHERE id = ' + order.customerId);
  results.push(customer);
}`,
    assertions: {
      ruleId: 'PERF-003-N-PLUS-ONE',
      shouldViolate: true,
    },
  },
  {
    id: 'TP-CFG-DEAD-01',
    name: 'Unreachable Dead Code After Return',
    category: 'cfg',
    expectedType: 'true_positive',
    language: 'javascript',
    description: 'Control flow graph traversal identifies statement block following unconditional return as unreachable.',
    code: `function compute() {
  const x = 10;
  return x;
  const deadVar = 20;
  console.log(deadVar);
}`,
    assertions: {
      ruleId: 'REL-001-UNREACHABLE-CFG',
      shouldViolate: true,
      expectedDeadBlocksCount: 2,
    },
  },

  // ==========================================
  // SECTION 2: TRUE NEGATIVES (False Positive Defense)
  // ==========================================
  {
    id: 'TN-SQLI-01',
    name: 'Safe Parameterized SQL Query (Must NOT Flag)',
    category: 'false_positive',
    expectedType: 'true_negative',
    language: 'javascript',
    description: 'Clean code: Uses parameterized SQL query bindings. Analyzer must NOT report SQL injection.',
    code: `const { username, tenantId } = req.body;
const query = 'SELECT * FROM users WHERE username = ? AND tenant_id = ?';
await db.query(query, [username, tenantId]);`,
    assertions: {
      ruleId: 'SEC-001-SQLI',
      shouldViolate: false,
    },
  },
  {
    id: 'TN-TIMER-01',
    name: 'Clean useEffect with Teardown Function (Must NOT Flag)',
    category: 'false_positive',
    expectedType: 'true_negative',
    language: 'javascript',
    description: 'Clean code: Returns clearInterval teardown. Analyzer must NOT report resource leak.',
    code: `useEffect(() => {
  const id = setInterval(() => {
    setCount(c => c + 1);
  }, 1000);
  return () => clearInterval(id);
}, []);`,
    assertions: {
      ruleId: 'PERF-001-TIMER-LEAK',
      shouldViolate: false,
    },
  },
  {
    id: 'TN-ASYNC-01',
    name: 'Asynchronous Non-Blocking Crypto (Must NOT Flag)',
    category: 'false_positive',
    expectedType: 'true_negative',
    language: 'javascript',
    description: 'Clean code: Uses asynchronous crypto.pbkdf2 with promise/callback. Must NOT flag event loop block.',
    code: `app.post('/auth', async (req, res) => {
  const key = await new Promise((resolve, reject) => {
    crypto.pbkdf2(req.body.pwd, salt, 100000, 64, 'sha512', (err, k) => {
      if (err) reject(err); else resolve(k);
    });
  });
  res.json({ key });
});`,
    assertions: {
      ruleId: 'PERF-002-SYNC-BLOCK',
      shouldViolate: false,
    },
  },
  {
    id: 'TN-REDOS-01',
    name: 'Linear O(N) Regex without Nested Quantifiers (Must NOT Flag)',
    category: 'false_positive',
    expectedType: 'true_negative',
    language: 'javascript',
    description: 'Clean code: Linear quantifier /^[a-zA-Z0-9_-]{3,20}$/ has no exponential backtracking.',
    code: `const safeUsername = /^[a-zA-Z0-9_-]{3,20}$/;
const isValid = safeUsername.test(input);`,
    assertions: {
      ruleId: 'SEC-002-REDOS',
      shouldViolate: false,
    },
  },
  {
    id: 'TN-PROTO-01',
    name: 'Guarded Object Merge with Prototype Filter (Must NOT Flag)',
    category: 'false_positive',
    expectedType: 'true_negative',
    language: 'javascript',
    description: 'Clean code: Explicitly filters __proto__, constructor, prototype before merging.',
    code: `function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    target[key] = source[key];
  }
  return target;
}`,
    assertions: {
      ruleId: 'SEC-003-PROTO-POLLUTION',
      shouldViolate: false,
    },
  },
  {
    id: 'TN-BATCH-01',
    name: 'Batched SQL Query Outside Loop (Must NOT Flag)',
    category: 'false_positive',
    expectedType: 'true_negative',
    language: 'javascript',
    description: 'Clean code: Fetches records in a single batch query ahead of processing.',
    code: `const customerIds = orders.map(o => o.customerId);
const customers = await db.query('SELECT * FROM customers WHERE id IN (?)', [customerIds]);
for (const order of orders) {
  results.push({ order, customer: customers.find(c => c.id === order.customerId) });
}`,
    assertions: {
      ruleId: 'PERF-003-N-PLUS-ONE',
      shouldViolate: false,
    },
  },
  {
    id: 'TN-CFG-ALL-REACHABLE-01',
    name: 'Clean If-Else Control Flow with All Paths Reachable (Must NOT Flag)',
    category: 'false_positive',
    expectedType: 'true_negative',
    language: 'javascript',
    description: 'Clean code: All branches and join nodes are reachable from entry. Must report 0 dead blocks.',
    code: `function route(status) {
  if (status === 200) {
    return 'ok';
  } else {
    return 'error';
  }
}`,
    assertions: {
      ruleId: 'REL-001-UNREACHABLE-CFG',
      shouldViolate: false,
      expectedDeadBlocksCount: 0,
    },
  },

  // ==========================================
  // SECTION 3: CFG STRUCTURAL CORRECTNESS
  // ==========================================
  {
    id: 'CFG-TEST-BRANCH-01',
    name: 'CFG Branch & Cyclomatic Complexity Verification',
    category: 'cfg',
    expectedType: 'cfg_check',
    language: 'javascript',
    description: 'Verifies McCabe Cyclomatic Complexity formula: M = E - N + 2P on an if-else decision structure.',
    code: `if (a > 0) {
  b = 1;
} else {
  b = 2;
}`,
    assertions: {
      expectedCyclomaticComplexity: 2,
    },
  },

  // ==========================================
  // SECTION 4: HALSTEAD METRICS DETERMINISTIC UNIT TEST
  // ==========================================
  {
    id: 'METRIC-HALSTEAD-ADD-01',
    name: 'Deterministic Halstead Software Science Math',
    category: 'halstead',
    expectedType: 'metric_check',
    language: 'javascript',
    description: 'Empirically checks token counts and deterministic Halstead volume for a standard add function.',
    code: `function add(a, b) {
  return a + b;
}`,
    assertions: {
      // function, (, ), ,, {, return, +, ;, } => 9 distinct operators
      // add, a, b => 3 distinct operands
      expectedDistinctOperators: 9,
      expectedDistinctOperands: 3,
      expectedVocabulary: 12,
      minMaintainabilityIndex: 60,
      maxMaintainabilityIndex: 100,
    },
  },
];
