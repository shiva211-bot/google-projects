export interface InterproceduralTestCase {
  id: string;
  name: string;
  category: 'direct' | 'function_boundary' | 'return_flow' | 'object_property' | 'destructuring' | 'aliasing' | 'sanitizer' | 'recursion' | 'deep_chain';
  description: string;
  code: string;
  expectedVulnerable: boolean;
  expectedSanitized?: boolean;
  expectedMinSteps?: number;
  expectedPathSequence?: ('SOURCE' | 'ARGUMENT' | 'PARAMETER' | 'PROPAGATION' | 'TEMPLATE' | 'PROPERTY_ACCESS' | 'OBJECT_CREATION' | 'RETURN' | 'SANITIZER' | 'SINK')[];
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
    expectedMinSteps: 3,
    expectedPathSequence: ['SOURCE', 'TEMPLATE', 'SINK'],
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
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'TEMPLATE', 'RETURN', 'SINK'],
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
    expectedMinSteps: 6,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'SINK'],
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
    expectedMinSteps: 4,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'RETURN', 'SINK'],
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
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'TEMPLATE', 'OBJECT_CREATION', 'ARGUMENT', 'PARAMETER', 'PROPERTY_ACCESS', 'SINK'],
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
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'TEMPLATE', 'OBJECT_CREATION', 'ARGUMENT', 'PARAMETER', 'PROPAGATION', 'SINK'],
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
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'PROPAGATION', 'TEMPLATE', 'SINK'],
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
    expectedVulnerable: false, // Marked sanitized = CLEAN
    expectedSanitized: true,
    expectedMinSteps: 3,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'SANITIZER'],
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
    expectedMinSteps: 4,
    expectedPathSequence: ['SOURCE', 'SANITIZER', 'TEMPLATE', 'SINK'],
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
    expectedMinSteps: 4,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'SINK'],
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
    expectedMinSteps: 5,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'SINK'],
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
    expectedMinSteps: 6,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'RETURN', 'SINK'],
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
    expectedMinSteps: 8,
    expectedPathSequence: ['SOURCE', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'ARGUMENT', 'PARAMETER', 'SINK'],
  },
];
