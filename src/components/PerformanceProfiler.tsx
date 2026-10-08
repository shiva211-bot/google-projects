import React, { useState, useEffect } from 'react';
import { 
  Gauge, 
  Play, 
  TrendingDown, 
  TrendingUp, 
  DollarSign, 
  Layers, 
  Cpu, 
  Clock, 
  Zap, 
  CheckCircle2, 
  Loader2 
} from 'lucide-react';
import { BenchmarkMetrics } from '../types';
import { simulateBenchmark } from '../services/api';

interface PerformanceProfilerProps {
  currentCategory: string;
}

export const PerformanceProfiler: React.FC<PerformanceProfilerProps> = ({ currentCategory }) => {
  const [iterations, setIterations] = useState<number>(5000);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [metrics, setMetrics] = useState<BenchmarkMetrics | null>(null);

  // Initialize with simulated baseline
  useEffect(() => {
    simulateBenchmark(iterations, currentCategory).then(setMetrics);
  }, [currentCategory]);

  const handleRunBenchmark = async () => {
    setIsRunning(true);
    setProgress(0);

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 95) {
          clearInterval(interval);
          return 95;
        }
        return prev + 15;
      });
    }, 80);

    try {
      const result = await simulateBenchmark(iterations, currentCategory);
      clearInterval(interval);
      setProgress(100);
      setTimeout(() => {
        setMetrics(result);
        setIsRunning(false);
      }, 250);
    } catch (e) {
      clearInterval(interval);
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Simulation Controls Card */}
      <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Gauge className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-100 font-mono">
              Runtime Telemetry &amp; Load Simulator
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-lg leading-relaxed">
            Simulates high-concurrency requests and measures latency percentiles, heap memory allocation, and CPU event-loop blocking before and after remediation.
          </p>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          {/* Iteration Selector */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400">Load:</span>
            <select
              value={iterations}
              onChange={(e) => setIterations(Number(e.target.value))}
              disabled={isRunning}
              className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value={1000}>1,000 Ops</option>
              <option value={5000}>5,000 Ops</option>
              <option value={20000}>20,000 Ops</option>
              <option value={50000}>50,000 Ops</option>
            </select>
          </div>

          {/* Trigger button */}
          <button
            onClick={handleRunBenchmark}
            disabled={isRunning}
            className="px-4 py-1.5 text-xs font-medium rounded-md bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white transition-all flex items-center gap-1.5 shadow-sm font-mono disabled:opacity-50 cursor-pointer"
          >
            {isRunning ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Benchmarking...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Simulator</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Progress Bar when running */}
      {isRunning && (
        <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
          <div
            className="bg-cyan-400 h-full transition-all duration-100"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {/* Benchmark Results */}
      {metrics && (
        <div className="space-y-3">
          {/* Top Delta Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Speedup */}
            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Execution Speedup</span>
                <TrendingUp className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-1.5">
                <span className="text-2xl font-bold font-mono text-emerald-400">
                  {metrics.speedupMultiplier}x
                </span>
                <span className="text-xs text-slate-400">Faster Response</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                Reduced average latency from {metrics.original.avgLatencyMs}ms down to {metrics.remediated.avgLatencyMs}ms.
              </p>
            </div>

            {/* Memory Freed */}
            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Memory Saved</span>
                <Layers className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-1.5">
                <span className="text-2xl font-bold font-mono text-cyan-400">
                  {metrics.memorySavedMb} MB
                </span>
                <span className="text-xs text-slate-400">Heap Freed</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                Memory consumption trimmed from {metrics.original.memoryMb}MB down to {metrics.remediated.memoryMb}MB.
              </p>
            </div>

            {/* Estimated Cloud Cost Savings */}
            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Est. Cloud Savings</span>
                <DollarSign className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-1.5">
                <span className="text-2xl font-bold font-mono text-amber-400">
                  ${metrics.estimatedAnnualCloudSavingsUsd}
                </span>
                <span className="text-xs text-slate-400">/year/instance</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                Reduced CPU core-hours and lower horizontal autoscaling instances.
              </p>
            </div>
          </div>

          {/* Detailed Side-by-Side Comparison Table */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-200">
                Comparative Metrics Breakdown ({metrics.iterations.toLocaleString()} iterations)
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                p50 / p95 / p99 Percentile Distribution
              </span>
            </div>

            <div className="p-4 space-y-4">
              {/* Latency Comparison Bars */}
              <div>
                <div className="flex items-center justify-between text-xs text-slate-300 mb-1.5">
                  <span>Average Request Latency (Lower is better)</span>
                  <span className="font-mono text-emerald-400">
                    -{Math.round(((metrics.original.avgLatencyMs - metrics.remediated.avgLatencyMs) / metrics.original.avgLatencyMs) * 100)}% Latency Drop
                  </span>
                </div>
                {/* Original bar */}
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-[11px] text-slate-400 shrink-0">Original:</span>
                    <div className="flex-1 bg-slate-800 h-5 rounded overflow-hidden relative">
                      <div
                        className="bg-rose-500/80 h-full flex items-center px-2 text-[10px] text-white"
                        style={{ width: '100%' }}
                      >
                        {metrics.original.avgLatencyMs} ms
                      </div>
                    </div>
                  </div>
                  {/* Remediated bar */}
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-[11px] text-emerald-400 font-medium shrink-0">Optimized:</span>
                    <div className="flex-1 bg-slate-800 h-5 rounded overflow-hidden relative">
                      <div
                        className="bg-emerald-500 h-full flex items-center px-2 text-[10px] text-slate-950 font-bold"
                        style={{
                          width: `${Math.max(5, (metrics.remediated.avgLatencyMs / metrics.original.avgLatencyMs) * 100)}%`,
                        }}
                      >
                        {metrics.remediated.avgLatencyMs} ms
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Throughput comparison */}
              <div>
                <div className="flex items-center justify-between text-xs text-slate-300 mb-1.5">
                  <span>Throughput Capacity (Higher is better)</span>
                  <span className="font-mono text-cyan-400">
                    {Math.round(metrics.remediated.throughputOpsSec / metrics.original.throughputOpsSec)}x Concurrent Capacity
                  </span>
                </div>
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-[11px] text-slate-400 shrink-0">Original:</span>
                    <div className="flex-1 bg-slate-800 h-5 rounded overflow-hidden relative">
                      <div
                        className="bg-slate-600 h-full flex items-center px-2 text-[10px] text-white"
                        style={{
                          width: `${Math.max(4, (metrics.original.throughputOpsSec / metrics.remediated.throughputOpsSec) * 100)}%`,
                        }}
                      >
                        {metrics.original.throughputOpsSec.toLocaleString()} ops/s
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-[11px] text-cyan-400 font-medium shrink-0">Optimized:</span>
                    <div className="flex-1 bg-slate-800 h-5 rounded overflow-hidden relative">
                      <div
                        className="bg-cyan-500 h-full flex items-center px-2 text-[10px] text-slate-950 font-bold"
                        style={{ width: '100%' }}
                      >
                        {metrics.remediated.throughputOpsSec.toLocaleString()} ops/s
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Execution Profile Breakdown */}
              <div className="pt-2 border-t border-slate-800">
                <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block mb-2">
                  Simulated Execution Time Breakdown
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">p95 Spikes</div>
                    <div className="text-slate-200 mt-0.5">
                      <span className="line-through text-slate-500 mr-1.5">{metrics.original.p95LatencyMs}ms</span>
                      <span className="text-emerald-400 font-bold">{metrics.remediated.p95LatencyMs}ms</span>
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">p99 Outliers</div>
                    <div className="text-slate-200 mt-0.5">
                      <span className="line-through text-slate-500 mr-1.5">{metrics.original.p99LatencyMs}ms</span>
                      <span className="text-emerald-400 font-bold">{metrics.remediated.p99LatencyMs}ms</span>
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">CPU Busy Thread</div>
                    <div className="text-slate-200 mt-0.5">
                      <span className="line-through text-slate-500 mr-1.5">{metrics.original.cpuUtilizationPercent}%</span>
                      <span className="text-emerald-400 font-bold">{metrics.remediated.cpuUtilizationPercent}%</span>
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">Heap Allocation</div>
                    <div className="text-slate-200 mt-0.5">
                      <span className="line-through text-slate-500 mr-1.5">{metrics.original.memoryMb}MB</span>
                      <span className="text-emerald-400 font-bold">{metrics.remediated.memoryMb}MB</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
