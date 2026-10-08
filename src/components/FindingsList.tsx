import React, { useState } from 'react';
import { 
  AlertCircle, 
  AlertTriangle, 
  Info, 
  ShieldAlert, 
  Zap, 
  CheckCircle2, 
  Search, 
  ArrowUpRight,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { CodeFinding, Severity, Category } from '../types';

interface FindingsListProps {
  findings: CodeFinding[];
  highlightedLine: number | null;
  onLineClick: (lineNum: number) => void;
  onApplySingleFix?: (finding: CodeFinding) => void;
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  highlightedLine,
  onLineClick,
  onApplySingleFix,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredFindings = findings.filter(f => {
    if (selectedSeverity !== 'all' && f.severity !== selectedSeverity && f.category !== selectedSeverity) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.recommendation.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityColor = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return 'text-rose-400 border-rose-500/30 bg-rose-950/20';
      case 'high':
        return 'text-orange-400 border-orange-500/30 bg-orange-950/20';
      case 'medium':
        return 'text-amber-400 border-amber-500/30 bg-amber-950/20';
      case 'low':
        return 'text-sky-400 border-sky-500/30 bg-sky-950/20';
      default:
        return 'text-slate-400 border-slate-700 bg-slate-900/30';
    }
  };

  const counts = {
    all: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    security: findings.filter(f => f.category === 'security').length,
    performance: findings.filter(f => f.category === 'performance').length,
  };

  return (
    <div className="space-y-3">
      {/* Controls: Filter Segmented Buttons & Search */}
      <div className="flex flex-col sm:flex-row gap-2 items-stretch sm:items-center justify-between">
        {/* Interactive Filter Buttons */}
        <div className="flex flex-wrap items-center gap-1 bg-slate-900/90 p-1 rounded-md border border-slate-800 text-xs">
          <button
            onClick={() => setSelectedSeverity('all')}
            className={`px-2.5 py-1 rounded transition-colors ${
              selectedSeverity === 'all'
                ? 'bg-slate-800 text-white font-medium shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({counts.all})
          </button>
          <button
            onClick={() => setSelectedSeverity('critical')}
            className={`px-2.5 py-1 rounded transition-colors ${
              selectedSeverity === 'critical'
                ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60 font-medium shadow-sm'
                : 'text-slate-400 hover:text-rose-300'
            }`}
          >
            Critical ({counts.critical})
          </button>
          <button
            onClick={() => setSelectedSeverity('high')}
            className={`px-2.5 py-1 rounded transition-colors ${
              selectedSeverity === 'high'
                ? 'bg-orange-950/80 text-orange-300 border border-orange-800/60 font-medium shadow-sm'
                : 'text-slate-400 hover:text-orange-300'
            }`}
          >
            High ({counts.high})
          </button>
          <button
            onClick={() => setSelectedSeverity('security')}
            className={`px-2.5 py-1 rounded transition-colors ${
              selectedSeverity === 'security'
                ? 'bg-slate-800 text-emerald-300 font-medium shadow-sm'
                : 'text-slate-400 hover:text-emerald-300'
            }`}
          >
            Security ({counts.security})
          </button>
          <button
            onClick={() => setSelectedSeverity('performance')}
            className={`px-2.5 py-1 rounded transition-colors ${
              selectedSeverity === 'performance'
                ? 'bg-slate-800 text-cyan-300 font-medium shadow-sm'
                : 'text-slate-400 hover:text-cyan-300'
            }`}
          >
            Perf ({counts.performance})
          </button>
        </div>

        {/* Search */}
        <div className="relative min-w-[180px]">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search findings..."
            className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-md pl-8 pr-3 py-1.5 focus:outline-none focus:border-emerald-500/60 transition-colors"
          />
        </div>
      </div>

      {/* Findings List Items */}
      {filteredFindings.length === 0 ? (
        <div className="p-8 text-center border border-dashed border-slate-800 rounded-lg text-slate-500 text-xs">
          <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500/60 mb-2" />
          <p className="font-medium text-slate-300">No issues found matching criteria</p>
          <p className="mt-1">All scanned lines pass this category filter.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredFindings.map((finding) => {
            const isExpanded = expandedIds.has(finding.id);
            const isLineActive = highlightedLine === finding.line;

            return (
              <div
                key={finding.id}
                className={`border rounded-lg transition-all ${
                  isLineActive
                    ? 'border-amber-500/60 bg-amber-950/10 shadow-sm'
                    : 'border-slate-800/80 bg-slate-900/40 hover:border-slate-700/80'
                }`}
              >
                {/* Header Row */}
                <div
                  className="p-3 flex items-start justify-between gap-3 cursor-pointer select-none"
                  onClick={() => toggleExpand(finding.id)}
                >
                  <div className="flex items-start gap-2.5">
                    <span className="mt-0.5">
                      {finding.severity === 'critical' || finding.severity === 'high' ? (
                        <AlertCircle className="w-4 h-4 text-rose-400" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                      )}
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-200 text-xs">
                          {finding.title}
                        </span>
                      </div>
                      {/* Zero-Pill Unboxed Metadata with Typographic Separators */}
                      <div className="flex items-center gap-1.5 text-[11px] text-slate-400 mt-1">
                        <span className="capitalize font-mono font-medium text-slate-300">
                          {finding.severity}
                        </span>
                        <span className="text-slate-600">·</span>
                        <span className="capitalize text-slate-400">{finding.category}</span>
                        <span className="text-slate-600">·</span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onLineClick(finding.line);
                          }}
                          className="hover:text-emerald-400 text-slate-400 underline decoration-slate-700 underline-offset-2 flex items-center gap-0.5 font-mono"
                        >
                          Line {finding.line}
                          <ArrowUpRight className="w-2.5 h-2.5" />
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onLineClick(finding.line);
                      }}
                      className="text-xs px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors font-mono"
                      title="Jump to line in editor"
                    >
                      L{finding.line}
                    </button>
                    <button
                      type="button"
                      className="p-1 text-slate-500 hover:text-slate-300"
                    >
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-3 pb-3 pt-1 border-t border-slate-800/60 text-xs space-y-2.5">
                    {/* Description */}
                    <div>
                      <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block mb-0.5">
                        Cause
                      </span>
                      <p className="text-slate-300 leading-relaxed">
                        {finding.description}
                      </p>
                    </div>

                    {/* Impact */}
                    <div>
                      <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block mb-0.5">
                        Runtime Impact
                      </span>
                      <p className="text-rose-300/90 leading-relaxed font-mono text-[11px]">
                        {finding.impact}
                      </p>
                    </div>

                    {/* Recommendation & Code Snippet */}
                    <div>
                      <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block mb-0.5">
                        Remediation
                      </span>
                      <p className="text-emerald-300/90 leading-relaxed">
                        {finding.recommendation}
                      </p>
                      {finding.suggestedReplacement && (
                        <div className="mt-2 bg-slate-950 p-2.5 rounded border border-slate-800/80 font-mono text-[11px] text-emerald-400 overflow-x-auto">
                          <pre>{finding.suggestedReplacement}</pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
