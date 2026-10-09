import { InterproceduralStepType, VulnerabilityConfidence, AnalysisConvergenceStatus } from './types';

export interface InterproceduralTestCase {
  id: string;
  name: string;
  category: 
    | 'direct' 
    | 'function_boundary' 
    | 'return_flow' 
    | 'object_property' 
    | 'destructuring' 
    | 'aliasing' 
    | 'sanitizer' 
    | 'recursion' 
    | 'deep_chain' 
    | 'flow_sensitive'
    | 'branch_merging'
    | 'context_sanitization';
  description: string;
  code: string;
  options?: { maxIterations?: number };
  expectedVulnerable: boolean;
  expectedSanitized?: boolean;
  expectedConfidence?: VulnerabilityConfidence;
  expectedConvergenceStatus?: AnalysisConvergenceStatus;
  expectedMinSteps?: number;
  expectedPathSequence?: InterproceduralStepType[];
  expectedPostState?: Record<string, { isTainted: boolean; sanitized?: boolean }>;
}

export const INTERPROCEDURAL_CORPUS: InterproceduralTestCase[] = [
  // =========================================================================
  // IP-01: Direct Flow (Baseline intraprocedural sanity check)
  // =========================================================================
  {
    id: 'IP-01',
    name: 'Direct Local Taint Flow',
    category: 'direct',
    description: 'Direct ingestion of req.query.id concatenated into db.query sink.',
    code: `const id = req.query.id;
const query = \`SELECT * FROM users WHERE id = \${id}\`;
db.query(query);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 3,
    expectedPathSequence: ['SOURCE', 'TEMPLATE', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-02: One Function Boundary (Example 1 from specification)
  // =========================================================================
  {
    id: 'IP-02',
    name: 'Single Function Boundary (Argument -> Parameter -> Return)',
    category: 'function_boundary',
    description: 'Tracks id across buildQuery(id) boundary: argument binding, parameter, template return, sink.',
    code: `function buildQuery(id) {
  return \`SELECT * FROM users WHERE id = \${id}\`;
}

const id = req.query.id;
const query = buildQuery(id);
db.query(query);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 6,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'RETURN', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      query: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-03: Two Function Boundaries (Chained callers)
  // =========================================================================
  {
    id: 'IP-03',
    name: 'Two Function Boundaries (Format -> Execute)',
    category: 'function_boundary',
    description: 'Propagates through two function layers: formatQuery() and executeQuery().',
    code: `function formatQuery(userId) {
  return \`SELECT * FROM accounts WHERE user_id = \${userId}\`;
}

function executeQuery(uid) {
  const sql = formatQuery(uid);
  return db.query(sql);
}

const id = req.params.id;
executeQuery(id);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 8,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'RETURN', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-04: Return Propagation (Callee return assigned to caller variable)
  // =========================================================================
  {
    id: 'IP-04',
    name: 'Return-Value Propagation',
    category: 'return_flow',
    description: 'Verifies caller receives tainted return expression string from callee.',
    code: `function getSql(input) {
  return 'SELECT * FROM items WHERE name = ' + input;
}

const query = getSql(req.body.name);
db.query(query);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'RETURN', 'SINK'],
    expectedPostState: {
      query: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-05: Object Property Propagation (Example 2 from specification)
  // =========================================================================
  {
    id: 'IP-05',
    name: 'Object Property Propagation (data.query through function)',
    category: 'object_property',
    description: 'Traces req.query.id -> template -> input.query -> executeRequest(data) -> data.query -> db.query.',
    code: `function executeRequest(data) {
  db.query(data.query);
}

const input = {
  query: \`SELECT * FROM users WHERE id = \${req.query.id}\`
};

executeRequest(input);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 7,
    expectedPathSequence: ['SOURCE', 'TEMPLATE', 'OBJECT_CREATION', 'ARGUMENT', 'PARAMETER', 'PROPERTY_ACCESS', 'SINK'],
    expectedPostState: {
      input: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-06: Destructuring Propagation (Object destructuring across boundary)
  // =========================================================================
  {
    id: 'IP-06',
    name: 'Destructuring Propagation',
    category: 'destructuring',
    description: 'Destructures tainted property inside callee body: const { query } = data.',
    code: `function processRequest(data) {
  const { query } = data;
  db.query(query);
}

const payload = {
  query: \`SELECT * FROM audits WHERE tenant = \${req.query.tenant}\`
};

processRequest(payload);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 7,
    expectedPathSequence: ['SOURCE', 'TEMPLATE', 'OBJECT_CREATION', 'ARGUMENT', 'PARAMETER', 'PROPAGATION', 'SINK'],
    expectedPostState: {
      payload: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-07: Aliased Parameter (Variable re-assignment in callee)
  // =========================================================================
  {
    id: 'IP-07',
    name: 'Aliased Parameter in Function Body',
    category: 'aliasing',
    description: 'Traces parameter aliasing to a secondary local identifier before reaching sink.',
    code: `function runSearch(searchTerm) {
  const localAlias = searchTerm;
  const sql = \`SELECT * FROM products WHERE desc = '\${localAlias}'\`;
  db.query(sql);
}

const q = req.query.q;
runSearch(q);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 6,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'PROPAGATION', 'TEMPLATE', 'SINK'],
    expectedPostState: {
      q: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-08: Sanitizer Before Sink (Example 3 from specification - Number())
  // =========================================================================
  {
    id: 'IP-08',
    name: 'Sanitizer Before Sink (Number casting neutralizes SQL)',
    category: 'sanitizer',
    description: 'Proves TAINT -> SANITIZER -> CLEAN semantics. Number(id) casts input, rendering flow safe.',
    code: `function sanitizeId(id) {
  return Number(id);
}

const id = req.query.id;
const safeId = sanitizeId(id);

db.query(
  \`SELECT * FROM users WHERE id = \${safeId}\`
);`,
    expectedVulnerable: false, // Neutralized: marked sanitized/clean
    expectedSanitized: true,
    expectedMinSteps: 7,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'SANITIZER', 'RETURN', 'TEMPLATE', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      safeId: { isTainted: true, sanitized: true },
    },
  },

  // =========================================================================
  // IP-09: Threat-Specific Sanitizer Invariant (escapeHtml does NOT neutralize SQL)
  // =========================================================================
  {
    id: 'IP-09',
    name: 'Threat-Specific Sanitizer (escapeHtml does NOT neutralize SQLi)',
    category: 'sanitizer',
    description: 'escapeHtml() neutralizes XSS, but DOES NOT neutralize SQL Injection. Threat remains active!',
    code: `const id = req.query.id;
const pseudoSafe = escapeHtml(id);
const sql = \`SELECT * FROM users WHERE id = '\${pseudoSafe}'\`;
db.query(sql);`,
    expectedVulnerable: true, // escapeHtml does NOT neutralize SQL injection!
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 4,
    expectedPathSequence: ['SOURCE', 'SANITIZER', 'TEMPLATE', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      pseudoSafe: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-10: Safe Parameterized Query Across Function Boundary
  // =========================================================================
  {
    id: 'IP-10',
    name: 'Safe Parameterized Query Across Boundary',
    category: 'sanitizer',
    description: 'Tainted input passed as bound parameter array [userId] to parameterized prepared statement.',
    code: `function executeSafe(userId) {
  db.query('SELECT * FROM users WHERE id = ?', [userId]);
}

const id = req.query.id;
executeSafe(id);`,
    expectedVulnerable: false, // Parameterized query is clean
    expectedSanitized: false,
    expectedPathSequence: [],
    expectedPostState: {
      id: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-11: Recursive Function Reachability
  // =========================================================================
  {
    id: 'IP-11',
    name: 'Recursive Function Reachability',
    category: 'recursion',
    description: 'Propagates taint through recursive self-invoking function without infinite fixed-point loop.',
    code: `function recursiveFetch(filterKey, depth) {
  if (depth <= 0) {
    return db.query(\`SELECT * FROM hierarchy WHERE key = \${filterKey}\`);
  }
  return recursiveFetch(filterKey, depth - 1);
}

const k = req.query.key;
recursiveFetch(k, 3);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'SINK'],
    expectedPostState: {
      k: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-12: Mutually Calling Functions
  // =========================================================================
  {
    id: 'IP-12',
    name: 'Mutually Calling Functions Flow',
    category: 'recursion',
    description: 'Flow passes from dispatchAlpha() to dispatchBeta() across mutual function boundaries.',
    code: `function dispatchAlpha(val) {
  return dispatchBeta(val);
}

function dispatchBeta(val) {
  return db.query(\`SELECT * FROM nodes WHERE token = \${val}\`);
}

const token = req.query.token;
dispatchAlpha(token);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 7,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'SINK'],
    expectedPostState: {
      token: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-13: Deep Chain - 3 Functions Deep
  // =========================================================================
  {
    id: 'IP-13',
    name: 'Three Functions Deep Propagation Chain',
    category: 'deep_chain',
    description: 'Taint flows through 3 sequential functions: step1(x) -> step2(y) -> step3(z) -> db.query.',
    code: `function step3(z) {
  return \`SELECT * FROM accounts WHERE id = \${z}\`;
}

function step2(y) {
  return step3(y);
}

function step1(x) {
  return step2(x);
}

const inputId = req.query.id;
const query = step1(inputId);
db.query(query);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 8,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'RETURN', 'RETURN', 'RETURN', 'SINK'],
    expectedPostState: {
      inputId: { isTainted: true },
      query: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-14: Deep Chain - 4 Functions Deep
  // =========================================================================
  {
    id: 'IP-14',
    name: 'Four Functions Deep Propagation Chain',
    category: 'deep_chain',
    description: 'Taint flows across 4 nested calls: level1 -> level2 -> level3 -> level4 execution sink.',
    code: `function level4(v) {
  db.query(\`SELECT * FROM secure_data WHERE secret = \${v}\`);
}

function level3(c) {
  level4(c);
}

function level2(b) {
  level3(b);
}

function level1(a) {
  level2(a);
}

const secret = req.query.secret;
level1(secret);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 10,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'SINK'],
    expectedPostState: {
      secret: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-15: Flow-Sensitive Reassignment (Kills Taint)
  // =========================================================================
  {
    id: 'IP-15',
    name: 'Flow-Sensitive Reassignment Kills Taint',
    category: 'flow_sensitive',
    description: 'Variable is initially tainted from req.query.id, but subsequent safe reassignment overwrites and kills taint.',
    code: `let id = req.query.id;
id = 'safe_literal_id';
db.query('SELECT * FROM users WHERE id = ' + id);`,
    expectedVulnerable: false, // Taint killed by safe reassignment!
    expectedSanitized: false,
    expectedPathSequence: [],
    expectedPostState: {
      id: { isTainted: false },
    },
  },

  // =========================================================================
  // IP-16: Flow-Sensitive Variable Shadowing
  // =========================================================================
  {
    id: 'IP-16',
    name: 'Flow-Sensitive Block Scope Variable Shadowing',
    category: 'flow_sensitive',
    description: 'Inner block declares id = "safe_inner", shadowing outer tainted id without mutating outer scope.',
    code: `let id = req.query.id;
{
  let id = 'safe_inner';
  db.query('SELECT * FROM users WHERE id = ' + id);
}`,
    expectedVulnerable: false, // Inner id shadows outer id with safe value!
    expectedSanitized: false,
    expectedPathSequence: [],
    expectedPostState: {
      id: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-17: Fake Sanitizer Function (Behavior check)
  // =========================================================================
  {
    id: 'IP-17',
    name: 'Function Named "sanitizeId" With No-Op Body Does NOT Sanitize',
    category: 'sanitizer',
    description: 'Sanitization must depend on verified behavior, not function name containing sanitize. No-op returns taint.',
    code: `function sanitizeId(id) {
  return id;
}

const id = req.query.id;
const safeId = sanitizeId(id);
db.query('SELECT * FROM users WHERE id = ' + safeId);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'RETURN', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      safeId: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-18: Object Method Resolution
  // =========================================================================
  {
    id: 'IP-18',
    name: 'Object Method Resolution In Call Graph',
    category: 'function_boundary',
    description: 'Resolves object method queryService.build(id) across boundary and tracks return to sink.',
    code: `const queryService = {
  build(userId) {
    return \`SELECT * FROM users WHERE id = \${userId}\`;
  }
};

const id = req.query.id;
const query = queryService.build(id);
db.query(query);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedMinSteps: 6,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'RETURN', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      query: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-19: Conservative Handling of Unresolved Call (Unresolved-Flow Finding)
  // =========================================================================
  {
    id: 'IP-19',
    name: 'Conservative Taint Propagation On Unresolved Calls',
    category: 'function_boundary',
    description: 'Calls to unresolved external functions preserve taint conservatively as unresolved-flow findings.',
    code: `const id = req.query.id;
const processed = externalBlackboxTransform(id);
db.query('SELECT * FROM users WHERE id = ' + processed);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'unresolved_flow',
    expectedMinSteps: 3,
    expectedPathSequence: ['SOURCE', 'PROPAGATION', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      processed: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-20: Deep Convergence Fixed-Point
  // =========================================================================
  {
    id: 'IP-20',
    name: 'Convergence-Based Fixed-Point Deep Call Chain',
    category: 'deep_chain',
    description: 'Validates convergence of interprocedural analysis without reliance on arbitrary iteration cap.',
    code: `function chainA(x) {
  return chainB(x);
}

function chainB(y) {
  return \`SELECT * FROM deep WHERE val = \${y}\`;
}

const id = req.query.id;
const q = chainA(id);
db.query(q);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedConvergenceStatus: 'converged',
    expectedMinSteps: 8,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'RETURN', 'RETURN', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      q: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-21: Both Branches Safe (CRITICAL 1 Regression)
  // =========================================================================
  {
    id: 'IP-21',
    name: 'Branch-Sensitive State Merging: Both Branches Safe',
    category: 'branch_merging',
    description: 'A tainted value is overwritten with safe values in BOTH if and else branches. Post-branch value is clean.',
    code: `let id = req.query.id;
if (checkFlag()) {
  id = 'safe_value_a';
} else {
  id = 'safe_value_b';
}
db.query('SELECT * FROM users WHERE id = ' + id);`,
    expectedVulnerable: false, // Overwritten on all paths!
    expectedSanitized: false,
    expectedPathSequence: [],
    expectedPostState: {
      id: { isTainted: false },
    },
  },

  // =========================================================================
  // IP-22: One Branch Remains Tainted (CRITICAL 1 Regression)
  // =========================================================================
  {
    id: 'IP-22',
    name: 'Branch-Sensitive State Merging: One Branch Remains Tainted',
    category: 'branch_merging',
    description: 'One branch overwrites with a safe value, but the other branch preserves taint. Merged post-branch state remains tainted.',
    code: `let id = req.query.id;
if (checkFlag()) {
  id = 'safe_override';
} else {
  // un-sanitized: id retains req.query.id
}
db.query('SELECT * FROM users WHERE id = ' + id);`,
    expectedVulnerable: true, // One branch remains tainted -> must report vulnerability!
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedPathSequence: ['SOURCE', 'PROPAGATION', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-23: No Else Branch (CRITICAL 1 Regression)
  // =========================================================================
  {
    id: 'IP-23',
    name: 'Branch-Sensitive State Merging: No Else Branch',
    category: 'branch_merging',
    description: 'A safe overwrite occurs ONLY in the if branch; the unexecuted path retains prior taint. Merged post-state remains tainted.',
    code: `let id = req.query.id;
if (checkFlag()) {
  id = 'safe_override';
}
db.query('SELECT * FROM users WHERE id = ' + id);`,
    expectedVulnerable: true, // When condition is false, prior taint reaches sink!
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedPathSequence: ['SOURCE', 'PROPAGATION', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-24: Recursive Direct Propagation with Convergence (CRITICAL 2 Regression)
  // =========================================================================
  {
    id: 'IP-24',
    name: 'Recursive Propagation: Direct Self-Invoking Fixed-Point',
    category: 'recursion',
    description: 'Tainted parameters pass through recursive self-invoking function; demonstrates parameter summary convergence.',
    code: `function recWalk(nodeVal, depth) {
  if (depth <= 0) {
    return db.query('SELECT * FROM tree WHERE val = ' + nodeVal);
  }
  return recWalk(nodeVal, depth - 1);
}

const input = req.query.val;
recWalk(input, 5);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedConvergenceStatus: 'converged',
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'SINK'],
    expectedPostState: {
      input: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-25: Mutual Recursion Propagation with Convergence (CRITICAL 2 Regression)
  // =========================================================================
  {
    id: 'IP-25',
    name: 'Recursive Propagation: Mutual Recursion Fixed-Point',
    category: 'recursion',
    description: 'Tainted parameters flow through mutually recursive functions alpha <-> beta; stabilizes via parameter summary.',
    code: `function mutualA(v, d) {
  if (d <= 0) {
    return db.query('SELECT * FROM mutual_table WHERE key = ' + v);
  }
  return mutualB(v, d - 1);
}

function mutualB(v, d) {
  return mutualA(v, d);
}

const x = req.query.x;
mutualA(x, 2);`,
    expectedVulnerable: true,
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedConvergenceStatus: 'converged',
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'SINK'],
    expectedPostState: {
      x: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-26: Context-Sensitive Sanitization: HTML Body with escapeHtml (HIGH 3 Regression)
  // =========================================================================
  {
    id: 'IP-26',
    name: 'Context-Sensitive: HTML Text Sink with escapeHtml',
    category: 'context_sanitization',
    description: 'escapeHtml() is valid for HTML text context (res.send body), successfully neutralizing DOM XSS.',
    code: `const name = req.query.name;
const safeName = escapeHtml(name);
res.send('<div>Hello ' + safeName + '</div>');`,
    expectedVulnerable: false,
    expectedSanitized: true,
    expectedPathSequence: ['SOURCE', 'SANITIZER', 'SINK'],
    expectedPostState: {
      name: { isTainted: true },
      safeName: { isTainted: true, sanitized: true },
    },
  },

  // =========================================================================
  // IP-27: Context-Sensitive Sanitization: URL Sink with escapeHtml (HIGH 3 Regression)
  // =========================================================================
  {
    id: 'IP-27',
    name: 'Context-Sensitive: URL Context with escapeHtml (Vulnerable)',
    category: 'context_sanitization',
    description: 'escapeHtml() does NOT neutralize javascript: protocol injection in URL contexts. Threat remains active!',
    code: `const dest = req.query.url;
const pseudoSafe = escapeHtml(dest);
location.href = pseudoSafe;`,
    expectedVulnerable: true, // escapeHtml does NOT sanitize URL context!
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedPathSequence: ['SOURCE', 'SANITIZER', 'SINK'],
    expectedPostState: {
      dest: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-28: Context-Sensitive Sanitization: JavaScript Context with escapeHtml (HIGH 3 Regression)
  // =========================================================================
  {
    id: 'IP-28',
    name: 'Context-Sensitive: JavaScript Execution with escapeHtml (Vulnerable)',
    category: 'context_sanitization',
    description: 'escapeHtml() does NOT neutralize JavaScript execution context (eval). Threat remains active!',
    code: `const code = req.query.code;
const pseudoSafe = escapeHtml(code);
eval(pseudoSafe);`,
    expectedVulnerable: true, // escapeHtml does NOT sanitize JavaScript execution!
    expectedSanitized: false,
    expectedConfidence: 'confirmed',
    expectedPathSequence: ['SOURCE', 'SANITIZER', 'SINK'],
    expectedPostState: {
      code: { isTainted: true },
    },
  },

  // =========================================================================
  // IP-29: Context-Sensitive Sanitization: URL Sink with encodeURIComponent (HIGH 3 Regression)
  // =========================================================================
  {
    id: 'IP-29',
    name: 'Context-Sensitive: URL Query with encodeURIComponent (Safe)',
    category: 'context_sanitization',
    description: 'encodeURIComponent() is valid for URL query parameter context, neutralizing parameter breakout.',
    code: `const searchParam = req.query.q;
const safeParam = encodeURIComponent(searchParam);
location.href = safeParam;`,
    expectedVulnerable: false,
    expectedSanitized: true,
    expectedPathSequence: ['SOURCE', 'SANITIZER', 'SINK'],
    expectedPostState: {
      searchParam: { isTainted: true },
      safeParam: { isTainted: true, sanitized: true },
    },
  },

  // =========================================================================
  // IP-30: Context-Sensitive Sanitization: SQL Sink with Number() (HIGH 3 Regression)
  // =========================================================================
  {
    id: 'IP-30',
    name: 'Context-Sensitive: SQL Query with Number Casting (Safe)',
    category: 'context_sanitization',
    description: 'Number() casting converts input to a numeric primitive, neutralizing SQL syntax injection in query sink.',
    code: `const id = req.query.id;
const safeId = Number(id);
db.query('SELECT * FROM users WHERE id = ' + safeId);`,
    expectedVulnerable: false,
    expectedSanitized: true,
    expectedPathSequence: ['SOURCE', 'SANITIZER', 'SINK'],
    expectedPostState: {
      id: { isTainted: true },
      safeId: { isTainted: true, sanitized: true },
    },
  },

  // =========================================================================
  // IP-31: Incomplete Analysis Reporting (Acceptance Criterion)
  // =========================================================================
  {
    id: 'IP-31',
    name: 'Resource Limit Incomplete Analysis Reported As Incomplete',
    category: 'recursion',
    description: 'Any incomplete analysis exceeding fixed-point resource limits must be reported as incomplete (status: resource_limit_exceeded), never silently treated as safe.',
    code: `function loopA(v) { return loopB(v); }
function loopB(v) { return loopA(v); }
const x = req.query.x;
loopA(x);`,
    options: { maxIterations: 1 },
    expectedVulnerable: false,
    expectedConvergenceStatus: 'resource_limit_exceeded',
  },
];
