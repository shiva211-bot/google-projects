import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.json({ limit: '10mb' }));

// Initialize GoogleGenAI if key is present
const apiKey = process.env.GEMINI_API_KEY;
const ai = apiKey ? new GoogleGenAI({ apiKey }) : null;

// POST /api/analyze - AI & Rule-based code analysis
app.post('/api/analyze', async (req, res) => {
  const { code, language = 'typescript', filename = 'source.ts' } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Code content is required.' });
  }

  // If Gemini API is available, request deep reasoning audit
  if (ai) {
    try {
      const prompt = `You are a senior security researcher and high-performance software engineer.
Analyze the following ${language} code (${filename}) for:
1. Security vulnerabilities (OWASP, CWE, injection, ReDoS, memory leaks, authentication bypasses, prototype pollution).
2. Performance bottlenecks (Big-O scaling, event loop blocking, N+1 queries, memory churn, unmemoized re-renders, goroutine deadlocks).
3. Code reliability and clean architectural maintainability.

Provide your response as a valid JSON object matching this schema:
{
  "metrics": {
    "overallScore": number (0-100),
    "securityScore": number (0-100),
    "performanceScore": number (0-100),
    "maintainabilityScore": number (0-100),
    "efficiencyScore": number (0-100),
    "bigOTime": string (e.g. "O(N)", "O(2^N)"),
    "bigOSpace": string,
    "estimatedLatencyMs": number,
    "estimatedMemoryMb": number,
    "cyclomaticComplexity": number,
    "carbonGrams": number
  },
  "findings": [
    {
      "id": string,
      "title": string,
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "category": "security" | "performance" | "reliability" | "maintainability",
      "line": number,
      "impact": string,
      "description": string,
      "recommendation": string,
      "codeSnippet": string,
      "suggestedReplacement": string
    }
  ],
  "remediatedCode": string,
  "remediationSummary": string,
  "improvements": string[]
}

CODE TO ANALYZE:
\`\`\`${language}
${code}
\`\`\`
Return ONLY the raw JSON object.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.2
        }
      });

      const responseText = response.text?.trim() || '{}';
      const parsed = JSON.parse(responseText);

      return res.json({
        ...parsed,
        aiPowered: true,
        analyzedAt: new Date().toISOString()
      });
    } catch (err: any) {
      console.warn('Gemini API call failed, falling back to static analysis engine:', err.message);
      // Fallback gracefully to local static analysis engine
    }
  }

  // Fallback / standard engine
  return res.json({
    fallback: true,
    message: 'Processed via built-in static analysis engine.'
  });
});

// POST /api/benchmark-simulate - Simulate runtime telemetry
app.post('/api/benchmark-simulate', (req, res) => {
  const { iterations = 5000, codeCategory = 'general' } = req.body;
  const numIterations = Math.min(100000, Math.max(100, Number(iterations)));

  let originalLatency = 450;
  let remediatedLatency = 18;
  let originalMemory = 112;
  let remediatedMemory = 16;
  let originalThroughput = 980;
  let remediatedThroughput = 28400;

  if (codeCategory === 'database') {
    originalLatency = 3200;
    remediatedLatency = 34;
    originalMemory = 164;
    remediatedMemory = 28;
    originalThroughput = 310;
    remediatedThroughput = 18900;
  } else if (codeCategory === 'crypto') {
    originalLatency = 880;
    remediatedLatency = 42;
    originalThroughput = 1100;
    remediatedThroughput = 22000;
  }

  const speedupMultiplier = Number((originalLatency / Math.max(1, remediatedLatency)).toFixed(1));
  const memorySavedMb = originalMemory - remediatedMemory;
  const annualSavings = Math.round(speedupMultiplier * 240);

  res.json({
    iterations: numIterations,
    original: {
      avgLatencyMs: originalLatency,
      p95LatencyMs: Math.round(originalLatency * 1.6),
      p99LatencyMs: Math.round(originalLatency * 2.4),
      memoryMb: originalMemory,
      throughputOpsSec: originalThroughput,
      cpuUtilizationPercent: 88
    },
    remediated: {
      avgLatencyMs: remediatedLatency,
      p95LatencyMs: Math.round(remediatedLatency * 1.3),
      p99LatencyMs: Math.round(remediatedLatency * 1.8),
      memoryMb: remediatedMemory,
      throughputOpsSec: remediatedThroughput,
      cpuUtilizationPercent: 12
    },
    speedupMultiplier,
    memorySavedMb,
    estimatedAnnualCloudSavingsUsd: annualSavings
  });
});

// Vite middleware in dev or static files in production
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CodePulse server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
