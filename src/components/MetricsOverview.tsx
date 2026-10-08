import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck,
  Gauge, 
  Activity, 
  Leaf, 
  Zap, 
  ArrowRight, 
  Clock, 
  Layers, 
  Cpu, 
  AlertTriangle 
} from 'lucide-react';
import { CodeMetrics, CodeFinding } from '../types';

interface MetricsOverviewProps {
  metrics: CodeMetrics;
  findings: CodeFinding[];
  onAutoFixClick: () => void;
  onViewDiffClick: () => void;
}

export const MetricsOverview: React.FC<MetricsOverviewProps> = ({
  metrics,
  findings,
  onAutoFixClick,
  onViewDiffClick,
}) => {
  // Compute Letter Grade
  const getGrade = (score: number) => {
    if (score >= 90) return { grade: 'A+', color: 'text-emerald-400', desc: 'Production Ready' };
    if (score >= 80) return { grade: 'A', color: 'text-emerald-300', desc: 'Secure & Efficient' };
    if (score >= 70) return { grade: 'B', color: 'text-cyan-400', desc: 'Acceptable' };
    if (score >= 55) return { grade: 'C', color: 'text-amber-400', desc: 'Requires Optimization' };
    if (score >= 40) return { grade: 'D', color: 'text-orange-400', desc: 'High Risk Flaws' };
    return { grade: 'F', color: 'text-rose-400', desc: 'Critical Vulnerabilities' };
  };

  const gradeInfo = getGrade(metrics.overallScore);
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;

  // SVG circular gauge math
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (metrics.overallScore / 100) * circumference;

  return (
    <div className="space-y-4">
      {/* Top Banner: Health Score + High-level Summary */}
      <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-5">
        <div className="flex items-center gap-5 w-full sm:w-auto">
          {/* Circular SVG Gauge */}
          <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
            <svg className="w-24 h-24 transform -rotate-90">
              <circle
                cx="48"
                cy="48"
                r={radius}
                className="stroke-slate-800"
                strokeWidth="7"
                fill="transparent"
              />
              <circle
                cx="48"
                cy="48"
                r={radius}
                className="stroke-emerald-500 transition-all duration-1000 ease-out"
                strokeWidth="7"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className={`text-2xl font-bold font-mono tracking-tight ${gradeInfo.color}`}>
                {gradeInfo.grade}
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                {metrics.overallScore}/100
              </span>
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-slate-100 text-sm">
                System Code Health
              </h3>
              <span className="text-xs text-slate-500 font-mono">·</span>
              <span className={`text-xs font-medium ${gradeInfo.color}`}>
                {gradeInfo.desc}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-sm leading-relaxed">
              {criticalCount > 0
                ? `${criticalCount} critical and ${highCount} high risk flaws detected in current execution path.`
                : findings.length > 0
                ? `${findings.length} optimization opportunities identified to reduce latency and memory churn.`
                : 'Zero security or performance regressions detected in static trace.'}
            </p>
            <div className="flex items-center gap-3 mt-2 text-xs text-slate-400 font-mono">
              <span>Time: {metrics.bigOTime}</span>
              <span className="text-slate-700">·</span>
              <span>Complexity: M={metrics.cyclomaticComplexity}</span>
            </div>
          </div>
        </div>

        {/* 1-Click Fix CTA */}
        {findings.length > 0 && (
          <div className="w-full sm:w-auto flex sm:flex-col items-center sm:items-end justify-between gap-2 border-t sm:border-t-0 pt-3 sm:pt-0 border-slate-800">
            <button
              onClick={onAutoFixClick}
              className="w-full sm:w-auto px-4 py-2 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white text-xs font-medium rounded-md shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer font-mono"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>Auto-Remediate All</span>
            </button>
            <button
              onClick={onViewDiffClick}
              className="text-xs text-slate-400 hover:text-emerald-400 flex items-center gap-1 transition-colors cursor-pointer py-1"
            >
              <span>Inspect Diff</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        )}
      </div>

      {/* 4 Score Cards (Zero-Pill, Typographic Precision) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Security Score */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Security Index</span>
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics.securityScore}
            </span>
            <span className="text-xs text-slate-500 font-mono">/100</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1.5">
            <span className={metrics.securityScore >= 80 ? 'text-emerald-400' : 'text-rose-400'}>
              {metrics.securityScore >= 80 ? 'Protected' : `${criticalCount} High Vulnerabilities`}
            </span>
            <span className="text-slate-600">·</span>
            <span>OWASP Top 10</span>
          </div>
        </div>

        {/* Static Risk Estimate (Deterministic Heuristic, No Fake Telemetry) */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Static Risk</span>
            <Gauge className={`w-4 h-4 ${
              metrics.staticRiskEstimate === 'CRITICAL' ? 'text-rose-400' :
              metrics.staticRiskEstimate === 'HIGH' ? 'text-amber-400' :
              metrics.staticRiskEstimate === 'MODERATE' ? 'text-yellow-400' : 'text-emerald-400'
            }`} />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className={`text-2xl font-bold font-mono ${
              metrics.staticRiskEstimate === 'CRITICAL' ? 'text-rose-400' :
              metrics.staticRiskEstimate === 'HIGH' ? 'text-amber-400' :
              metrics.staticRiskEstimate === 'MODERATE' ? 'text-yellow-400' : 'text-emerald-400'
            }`}>
              {metrics.staticRiskEstimate}
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1.5">
            <span className="text-slate-300 font-mono">AST Heuristic</span>
            <span className="text-slate-600">·</span>
            <span>Static Risk Estimate</span>
          </div>
        </div>

        {/* Maintainability Index */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Maintainability</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics.maintainabilityScore}
            </span>
            <span className="text-xs text-slate-500 font-mono">/100</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1.5">
            <span className="text-indigo-400 font-mono">CC {metrics.cyclomaticComplexity}</span>
            <span className="text-slate-600">·</span>
            <span>Cognitive Depth</span>
          </div>
        </div>

        {/* AST Rule Compliance */}
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">AST Compliance</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics.rulesPassedPercent}
            </span>
            <span className="text-xs text-slate-500 font-mono">%</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1.5">
            <span className={metrics.rulesPassedPercent === 100 ? 'text-emerald-400' : 'text-amber-400 font-mono'}>
              {metrics.rulesPassedPercent === 100 ? 'All Rules Passed' : 'Active AST Violations'}
            </span>
            <span className="text-slate-600">·</span>
            <span>Deterministic</span>
          </div>
        </div>
      </div>

      {/* Deterministic Static Analysis Risk & Complexity Ratings */}
      <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800/70 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
        <div className="flex items-center gap-2 text-slate-400">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span>Static Risk: <strong className={
            metrics.staticRiskEstimate === 'CRITICAL' ? 'text-rose-400' :
            metrics.staticRiskEstimate === 'HIGH' ? 'text-amber-400' :
            metrics.staticRiskEstimate === 'MODERATE' ? 'text-yellow-400' : 'text-emerald-400'
          }>{metrics.staticRiskEstimate}</strong></span>
        </div>
        <div className="flex items-center gap-2 text-slate-400">
          <Layers className="w-3.5 h-3.5 text-slate-500" />
          <span>Rules Passed: <strong className={metrics.rulesPassedPercent === 100 ? 'text-emerald-400' : 'text-amber-400'}>{metrics.rulesPassedPercent}%</strong></span>
        </div>
        <div className="flex items-center gap-2 text-slate-400">
          <Cpu className="w-3.5 h-3.5 text-slate-500" />
          <span>Time Big-O: <strong className="text-slate-200">{metrics.bigOTime}</strong></span>
        </div>
        <div className="flex items-center gap-2 text-slate-400">
          <Activity className="w-3.5 h-3.5 text-slate-500" />
          <span>Space Big-O: <strong className="text-slate-200">{metrics.bigOSpace}</strong></span>
        </div>
      </div>
    </div>
  );
};
