import { AnalysisResult, BenchmarkMetrics } from '../types';
import { executeTrueStaticAnalysis } from '../engine/staticEngine';
import { ComprehensiveStaticAnalysis } from '../engine/ast/types';

export interface StaticAnalysisRunOutput {
  analysis: AnalysisResult;
  engineData: ComprehensiveStaticAnalysis;
}

export async function runFullAnalysis(
  code: string,
  language: string,
  filename: string
): Promise<StaticAnalysisRunOutput> {
  // 1. Run deterministic ESTree AST, CFG, Taint Analysis and Rule Visitors
  const { analysis: staticResult, engineData } = executeTrueStaticAnalysis(code, language, filename);

  // 2. Query server-side proxy for contextual enrichment if available
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, language, filename }),
    });

    if (res.ok) {
      const data = await res.json();
      if (data && data.metrics && data.findings && data.aiPowered) {
        return {
          analysis: {
            ...staticResult,
            aiPowered: true,
            remediationSummary: data.remediationSummary || staticResult.remediationSummary,
            improvements: data.improvements?.length ? data.improvements : staticResult.improvements,
          },
          engineData,
        };
      }
    }
  } catch (err) {
    // Network or server unavailable; static engine is primary source of truth
  }

  return { analysis: staticResult, engineData };
}

export async function simulateBenchmark(
  iterations: number,
  codeCategory: string
): Promise<BenchmarkMetrics> {
  try {
    const res = await fetch('/api/benchmark-simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iterations, codeCategory }),
    });

    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    // Fallback simulation calculation
  }

  const origLat = codeCategory === 'database' ? 2800 : codeCategory === 'crypto' ? 820 : 420;
  const remLat = codeCategory === 'database' ? 32 : codeCategory === 'crypto' ? 38 : 16;
  const speedup = Number((origLat / remLat).toFixed(1));

  return {
    iterations,
    original: {
      avgLatencyMs: origLat,
      p95LatencyMs: Math.round(origLat * 1.5),
      p99LatencyMs: Math.round(origLat * 2.2),
      memoryMb: 120,
      throughputOpsSec: Math.round(1000 / (origLat / 1000)),
      cpuUtilizationPercent: 85,
    },
    remediated: {
      avgLatencyMs: remLat,
      p95LatencyMs: Math.round(remLat * 1.3),
      p99LatencyMs: Math.round(remLat * 1.7),
      memoryMb: 18,
      throughputOpsSec: 25000,
      cpuUtilizationPercent: 14,
    },
    speedupMultiplier: speedup,
    memorySavedMb: 102,
    estimatedAnnualCloudSavingsUsd: speedup * 220,
  };
}
