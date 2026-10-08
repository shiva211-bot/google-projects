import { ChallengeItem } from '../types';

export const SENTINEL_CHALLENGES: ChallengeItem[] = [
  {
    id: 'ch-1',
    title: 'The Ghost Event Loop Lockup',
    difficulty: 'Intermediate',
    language: 'javascript',
    code: `app.post('/api/hash', (req, res) => {
  const { secretKey } = req.body;
  // Which line here causes a critical server freeze under 50 concurrent requests?
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(secretKey, salt, 350000, 64, 'sha512');
  res.json({ hash: hash.toString('hex') });
});`,
    question: 'Why does this endpoint degrade server response time to >10 seconds under concurrent load?',
    options: [
      { id: 'a', text: 'randomBytes(16) is cryptographically insecure and throws in Linux kernels.', isCorrect: false },
      { id: 'b', text: 'pbkdf2Sync is synchronous and blocks the single Node.js event loop thread for all requests.', isCorrect: true },
      { id: 'c', text: 'Express body parser does not support string keys longer than 16 bytes.', isCorrect: false },
      { id: 'd', text: 'hash.toString("hex") leaks heap memory because hex conversion is unmanaged.', isCorrect: false },
    ],
    explanation: 'crypto.pbkdf2Sync runs compute-heavy key derivation synchronously on Node.js main thread. With 350k iterations, each request blocks the CPU for ~250ms. 50 concurrent requests queue up, freezing the entire server for 12+ seconds. Use asynchronous crypto.pbkdf2() or worker threads instead.',
    performanceOrSecurityTip: 'Rule: Never run *Sync crypto or heavy regex in request handlers on the event loop thread.'
  },
  {
    id: 'ch-2',
    title: 'The React 19 Phantom Memory Leak',
    difficulty: 'Beginner',
    language: 'typescript',
    code: `function StockTicker({ symbol }: { symbol: string }) {
  const [price, setPrice] = useState(100);

  useEffect(() => {
    const ws = new WebSocket(\`wss://stream.market.com/\${symbol}\`);
    ws.onmessage = (e) => setPrice(JSON.parse(e.data).price);
  }, [symbol]);

  return <div>{symbol}: \${price}</div>;
}`,
    question: 'What is the primary bug when the user switches between 20 stock symbols quickly?',
    options: [
      { id: 'a', text: 'Missing cleanup return function to ws.close(), causing lingering WebSocket connections & memory leaks.', isCorrect: true },
      { id: 'b', text: 'symbol cannot be used inside useEffect dependency array.', isCorrect: false },
      { id: 'c', text: 'JSON.parse is not valid inside WebSocket onmessage callbacks.', isCorrect: false },
      { id: 'd', text: 'WebSocket only works inside useLayoutEffect in React 19.', isCorrect: false },
    ],
    explanation: 'Every time `symbol` changes, a new WebSocket connection is created without closing the prior one. The old WebSockets remain open in the background, receiving market data and attempting to update unmounted component state, causing memory bloat and bandwidth exhaustion.',
    performanceOrSecurityTip: 'Always return a teardown function `return () => ws.close();` inside useEffect.'
  },
  {
    id: 'ch-3',
    title: 'The Silent ORM N+1 Database Explosion',
    difficulty: 'Intermediate',
    language: 'python',
    code: `def get_user_reports(org_id):
    users = db.query(User).filter_by(org_id=org_id).all()
    payload = []
    for user in users:
        # What is the performance disaster here?
        roles = db.query(Role).filter_by(user_id=user.id).all()
        payload.append({"name": user.name, "roles": [r.name for r in roles]})
    return payload`,
    question: 'If an organization has 1,500 active users, how many database queries are issued?',
    options: [
      { id: 'a', text: 'Exactly 2 queries because ORMs automatically batch in-memory.', isCorrect: false },
      { id: 'b', text: '1,501 individual round-trip queries (1 query for users + 1 query per user for roles).', isCorrect: true },
      { id: 'c', text: '15 queries due to internal connection pooling limits.', isCorrect: false },
      { id: 'd', text: '0 queries because Python caches generator expressions.', isCorrect: false },
    ],
    explanation: 'This is the classic N+1 query disaster. Loading 1,500 users issues 1 query, then iterating through each user triggers an individual query for roles (1 + 1,500 = 1,501 queries). Network round-trips turn what could be a 15ms JOIN query into a 4,500ms server timeout.',
    performanceOrSecurityTip: 'Always use eager loading / JOIN (e.g. `options(joinedload(User.roles))` in SQLAlchemy or `include: [Role]` in Prisma).'
  },
  {
    id: 'ch-4',
    title: 'Catastrophic ReDoS (Regular Expression Denial of Service)',
    difficulty: 'Hard',
    language: 'typescript',
    code: `const usernamePattern = /^([a-zA-Z0-9]+)*$/;

app.post('/register', (req, res) => {
  const { username } = req.body;
  if (!usernamePattern.test(username)) {
    return res.status(400).send('Invalid');
  }
  res.send('Valid');
});`,
    question: 'Which test input payload will cause this regex engine to consume 100% CPU for several minutes?',
    options: [
      { id: 'a', text: '"admin@root.com"', isCorrect: false },
      { id: 'b', text: '"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" (28 "a" chars ending with non-matching char)', isCorrect: true },
      { id: 'c', text: 'Empty string ""', isCorrect: false },
      { id: 'd', text: '"user_123456789"', isCorrect: false },
    ],
    explanation: 'The nested quantifier `([a-zA-Z0-9]+)*` has ambiguous ways to match repeating "a" characters (exponential O(2^N) backtracking tree). When an invalid character like "!" appears at the end, the engine tries every permutation of grouping before failing, resulting in billions of iterations.',
    performanceOrSecurityTip: 'Simplify nested quantifiers: `^[a-zA-Z0-9]*$` evaluates in linear O(N) time.'
  },
  {
    id: 'ch-5',
    title: 'Prototype Pollution Privileges Escalation',
    difficulty: 'Guru',
    language: 'javascript',
    code: `function mergeDeep(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      mergeDeep(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}`,
    question: 'How can an attacker exploit this function with JSON input `{ "__proto__": { "isAdmin": true } }`?',
    options: [
      { id: 'a', text: 'It pollutes Object.prototype, making `isAdmin === true` for every object created across the entire Node process!', isCorrect: true },
      { id: 'b', text: 'It causes a StackOverflow exception but does not alter application state.', isCorrect: false },
      { id: 'c', text: 'JSON.parse strips keys starting with double underscores so nothing happens.', isCorrect: false },
      { id: 'd', text: 'It will only modify target, leaving other objects untouched.', isCorrect: false },
    ],
    explanation: 'Without filtering out "__proto__", "constructor", and "prototype", the recursion traverses into `target.__proto__` which references `Object.prototype`. Injecting properties into `Object.prototype` modifies all objects in the runtime, leading to authentication bypasses, denial of service, or remote code execution.',
    performanceOrSecurityTip: 'Always sanitize keys: `if (key === "__proto__" || key === "constructor" || key === "prototype") continue;`.'
  }
];
