import { CodePreset } from '../types';

export const CODE_PRESETS: CodePreset[] = [
  {
    id: 'react-memory-leak',
    title: 'React 19: Memory Leak & Thrashing',
    language: 'typescript',
    filename: 'LiveDashboard.tsx',
    category: 'performance',
    tags: ['React', 'Memory Leak', 'Re-renders', 'Frontend'],
    description: 'Uncleaned interval listener, massive unmemoized object filtering on every stroke, and stale closure bugs.',
    code: `import React, { useState, useEffect } from 'react';

export function LiveDashboard({ rawFeeds }: { rawFeeds: any[] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [metrics, setMetrics] = useState({ cpu: 10, memory: 512 });
  const [ticks, setTicks] = useState(0);

  // BUG 1: Uncleaned interval causes memory leak & ghost background timer execution!
  useEffect(() => {
    setInterval(() => {
      setTicks(ticks + 1); // BUG 2: Stale closure referencing ticks instead of prev => setTicks(t => t + 1)
      setMetrics({
        cpu: Math.random() * 100,
        memory: 500 + Math.random() * 200,
      });
    }, 1000);
    // Missing cleanup return () => clearInterval(id);
  }, []);

  // BUG 3: Catastrophic recalculation on every minor keystroke (O(N) search with regex inside render loop)
  const filteredFeeds = rawFeeds.filter(feed => {
    const regex = new RegExp(searchTerm, 'i');
    return regex.test(feed.title) || regex.test(feed.payload);
  });

  return (
    <div className="p-4 border">
      <h2>Live System Monitor (Tick: {ticks})</h2>
      <input 
        value={searchTerm} 
        onChange={(e) => setSearchTerm(e.target.value)} 
        placeholder="Filter feeds..." 
      />
      <div>CPU: {metrics.cpu.toFixed(1)}% | RAM: {metrics.memory.toFixed(0)}MB</div>
      <ul>
        {filteredFeeds.map((feed, idx) => (
          // BUG 4: Array index as key causes DOM thrashing on reorder
          <li key={idx}>{feed.title}</li>
        ))}
      </ul>
    </div>
  );
}`
  },
  {
    id: 'nodejs-sql-injection-eventloop',
    title: 'Node.js: SQL Injection & Loop Block',
    language: 'javascript',
    filename: 'userController.js',
    category: 'security',
    tags: ['Node.js', 'SQLi', 'Event Loop Block', 'Crypto'],
    description: 'Direct string interpolation in SQL query, synchronous pbkdf2Sync blocking the single Node thread, and unbounded cache leak.',
    code: `const express = require('express');
const crypto = require('crypto');
const db = require('./database');

const router = express.Router();
// BUG 1: Unbounded global cache without LRU eviction creates slow memory leak
const sessionCache = new Map();

router.post('/login', async (req, res) => {
  const { username, password, tenantId } = req.body;

  // BUG 2: CRITICAL SQL Injection vulnerability via raw template interpolation!
  // Attacker can pass: "' OR '1'='1' --" to bypass auth completely!
  const query = \`SELECT * FROM users WHERE username = '\${username}' AND tenant_id = \${tenantId}\`;
  const [user] = await db.query(query);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // BUG 3: Synchronous crypto PBKDF2 freezes the entire Node.js event loop for 200ms+!
  // Starves all other concurrent HTTP connections!
  const derivedKey = crypto.pbkdf2Sync(password, user.salt, 100000, 64, 'sha512');
  
  if (crypto.timingSafeEqual(Buffer.from(user.passwordHash, 'hex'), derivedKey)) {
    const token = crypto.randomBytes(32).toString('hex');
    // Leaking memory on every login:
    sessionCache.set(token, { user, loginTime: Date.now() });
    return res.json({ token, role: user.role });
  }

  return res.status(401).json({ error: 'Auth failed' });
});

module.exports = router;`
  },
  {
    id: 'python-nplusone-eval',
    title: 'Python: N+1 DB Queries & Insecure Eval',
    language: 'python',
    filename: 'order_service.py',
    category: 'fullstack',
    tags: ['Python', 'N+1 Query', 'Remote Code Execution', 'ORM'],
    description: 'Classic N+1 database queries inside serialization loop and dangerous eval() dynamic evaluation.',
    code: `import json
from models import Order, Customer, Item
from db import get_session

def process_batch_orders(customer_ids, filter_formula=None):
    session = get_session()
    results = []

    # BUG 1: Dangerous dynamic formula evaluation via eval() - RCE Vulnerability!
    # Malicious user input can trigger: __import__('os').system('rm -rf /')
    if filter_formula:
        is_valid = eval(filter_formula)
        if not is_valid:
            return []

    # BUG 2: N+1 Query Anti-Pattern:
    # Loads all orders first (1 query), then for EACH order makes 2 separate synchronous DB queries
    # 5,000 orders = 10,001 round-trips to the database! Latency spikes from 20ms to 4,800ms!
    orders = session.query(Order).filter(Order.customer_id.in_(customer_ids)).all()

    for order in orders:
        # DB round-trip 1 per item:
        customer = session.query(Customer).filter_by(id=order.customer_id).first()
        # DB round-trip 2 per item:
        items = session.query(Item).filter_by(order_id=order.id).all()
        
        results.append({
            "order_id": order.id,
            "total_amount": sum(item.price for item in items),
            "customer_email": customer.email if customer else None,
            "items_count": len(items)
        })

    return results`
  },
  {
    id: 'typescript-redos-pollution',
    title: 'TypeScript: ReDoS & Prototype Pollution',
    language: 'typescript',
    filename: 'sanitizer.ts',
    category: 'security',
    tags: ['TypeScript', 'ReDoS', 'Prototype Pollution', 'DOS'],
    description: 'Catastrophic backtracking regular expression and recursive object merge without prototype protection.',
    code: `// BUG 1: Catastrophic Backtracking Regular Expression (ReDoS)!
// Pattern ((a+)+)$ causes exponential O(2^N) backtracking on strings like "aaaaaaaaaaaaaaaaaaaaaaaa!"
// Causes 100% CPU lockup on server or browser tab freeze!
const EMAIL_OR_TAG_VALIDATOR = /^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+@([a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*)+$/;

export function validateInput(rawText: string): boolean {
  return EMAIL_OR_TAG_VALIDATOR.test(rawText);
}

// BUG 2: Unsafe recursive object deep merge allows __proto__ prototype pollution!
// Can lead to property spoofing, privilege escalation, or unexpected crashes.
export function unsafeMerge(target: any, source: any): any {
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      // Missing security check for '__proto__', 'constructor', 'prototype'
      unsafeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}`
  },
  {
    id: 'go-race-condition',
    title: 'Go: Goroutine Leak & Data Race',
    language: 'go',
    filename: 'worker_pool.go',
    category: 'performance',
    tags: ['Go', 'Concurrency', 'Goroutine Leak', 'Data Race'],
    description: 'Unbuffered channel deadlock, goroutine leak on context cancel, and concurrent unsynchronized map write.',
    code: `package main

import (
	"context"
	"fmt"
	"time"
)

type WorkerMetrics struct {
	// BUG 1: Shared map accessed concurrently by multiple goroutines without sync.RWMutex!
	// Will cause "fatal error: concurrent map writes" crash in production!
	cache map[string]int
}

func ProcessJobs(ctx context.Context, jobs []string) map[string]int {
	m := &WorkerMetrics{cache: make(map[string]int)}
	
	// BUG 2: Unbuffered channel!
	// If receiver exits early or context is cancelled, worker goroutines block forever!
	// Creates a silent Goroutine memory leak exhausting host RAM!
	doneCh := make(chan string)

	for _, job := range jobs {
		go func(j string) {
			time.Sleep(50 * time.Millisecond)
			// Unsafe concurrent write:
			m.cache[j] = len(j)
			doneCh <- j // Blocks forever if receiver stops reading!
		}(job)
	}

	for i := 0; i < len(jobs); i++ {
		select {
		case res := <-doneCh:
			fmt.Println("Completed:", res)
		case <-ctx.Done():
			// Exits early, abandoning remaining worker goroutines in deadlock!
			return m.cache
		}
	}

	return m.cache
}`
  }
];
