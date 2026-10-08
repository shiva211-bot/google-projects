import React, { useState } from 'react';
import { 
  Check, 
  Copy, 
  Wand2, 
  Columns, 
  FileText, 
  ArrowRight, 
  Zap, 
  ShieldCheck 
} from 'lucide-react';

interface RemediationDiffViewProps {
  originalCode: string;
  remediatedCode: string;
  summary: string;
  improvements: string[];
  onApplyToEditor: () => void;
}

export const RemediationDiffView: React.FC<RemediationDiffViewProps> = ({
  originalCode,
  remediatedCode,
  summary,
  improvements,
  onApplyToEditor,
}) => {
  const [viewMode, setViewMode] = useState<'split' | 'unified'>('split');
  const [copied, setCopied] = useState(false);
  const [applied, setApplied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(remediatedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleApply = () => {
    onApplyToEditor();
    setApplied(true);
    setTimeout(() => setApplied(false), 2500);
  };

  const origLines = originalCode.split('\n');
  const remLines = remediatedCode.split('\n');

  return (
    <div className="space-y-3 flex flex-col h-full">
      {/* Top Banner: Improvements & Actions */}
      <div className="p-3.5 rounded-lg bg-emerald-950/30 border border-emerald-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h4 className="text-xs font-semibold text-emerald-300">
              Automated Code Remediation Ready
            </h4>
          </div>
          <p className="text-xs text-slate-300 mt-1 leading-relaxed max-w-xl">
            {summary}
          </p>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          <button
            onClick={handleCopy}
            className="px-3 py-1.5 text-xs rounded-md bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
            title="Copy clean code"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy</span>
          </button>
          <button
            onClick={handleApply}
            className="px-3.5 py-1.5 text-xs font-medium rounded-md bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white transition-all flex items-center gap-1.5 shadow-sm font-mono cursor-pointer"
          >
            {applied ? <Check className="w-3.5 h-3.5" /> : <Wand2 className="w-3.5 h-3.5" />}
            <span>{applied ? 'Applied to Editor!' : 'Apply to Editor'}</span>
          </button>
        </div>
      </div>

      {/* View Switcher Controls */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1">
        <div className="flex items-center gap-2">
          <span>Display:</span>
          <div className="flex items-center bg-slate-900 p-0.5 rounded border border-slate-800">
            <button
              onClick={() => setViewMode('split')}
              className={`px-2 py-1 rounded flex items-center gap-1 text-[11px] transition-colors ${
                viewMode === 'split' ? 'bg-slate-800 text-white' : 'hover:text-slate-200'
              }`}
            >
              <Columns className="w-3 h-3" />
              <span>Side-by-Side</span>
            </button>
            <button
              onClick={() => setViewMode('unified')}
              className={`px-2 py-1 rounded flex items-center gap-1 text-[11px] transition-colors ${
                viewMode === 'unified' ? 'bg-slate-800 text-white' : 'hover:text-slate-200'
              }`}
            >
              <FileText className="w-3 h-3" />
              <span>Unified</span>
            </button>
          </div>
        </div>
        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className="text-rose-400">− Vulnerable / Slow</span>
          <span className="text-emerald-400">+ Remediated / Optimized</span>
        </div>
      </div>

      {/* Diff Code Container */}
      <div className="flex-1 min-h-[360px] max-h-[500px] overflow-auto bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-xs leading-[20px]">
        {viewMode === 'split' ? (
          <div className="grid grid-cols-2 gap-3 min-w-[700px]">
            {/* Left: Original */}
            <div className="border-r border-slate-800/80 pr-2">
              <div className="sticky top-0 bg-slate-950/95 pb-1 mb-1 border-b border-slate-800 text-slate-400 text-[11px] flex items-center justify-between">
                <span>BEFORE (ORIGINAL)</span>
                <span className="text-rose-400">{origLines.length} lines</span>
              </div>
              {origLines.map((line, i) => {
                const isDifferent = remLines[i] !== line;
                return (
                  <div
                    key={`orig-${i}`}
                    className={`flex items-start gap-2 px-1 rounded ${
                      isDifferent ? 'bg-rose-950/20 text-rose-200' : 'text-slate-400'
                    }`}
                  >
                    <span className="w-6 text-slate-600 select-none text-right shrink-0 text-[10px]">
                      {i + 1}
                    </span>
                    <pre className="overflow-x-auto whitespace-pre">{line || ' '}</pre>
                  </div>
                );
              })}
            </div>

            {/* Right: Remediated */}
            <div className="pl-1">
              <div className="sticky top-0 bg-slate-950/95 pb-1 mb-1 border-b border-slate-800 text-slate-400 text-[11px] flex items-center justify-between">
                <span className="text-emerald-400">AFTER (OPTIMIZED)</span>
                <span className="text-emerald-400">{remLines.length} lines</span>
              </div>
              {remLines.map((line, i) => {
                const isDifferent = origLines[i] !== line;
                return (
                  <div
                    key={`rem-${i}`}
                    className={`flex items-start gap-2 px-1 rounded ${
                      isDifferent ? 'bg-emerald-950/25 text-emerald-200' : 'text-slate-300'
                    }`}
                  >
                    <span className="w-6 text-emerald-700/60 select-none text-right shrink-0 text-[10px]">
                      {i + 1}
                    </span>
                    <pre className="overflow-x-auto whitespace-pre">{line || ' '}</pre>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          /* Unified View */
          <div className="space-y-0.5">
            {remLines.map((line, i) => {
              const wasModified = origLines[i] !== line;
              return (
                <div
                  key={`uni-${i}`}
                  className={`flex items-start gap-2 px-1.5 py-0.5 rounded ${
                    wasModified ? 'bg-emerald-950/25 text-emerald-200 border-l-2 border-emerald-500' : 'text-slate-300'
                  }`}
                >
                  <span className="w-7 text-slate-600 select-none text-right shrink-0 text-[10px]">
                    {i + 1}
                  </span>
                  <span className="w-3 select-none text-slate-500">{wasModified ? '+' : ' '}</span>
                  <pre className="overflow-x-auto whitespace-pre">{line || ' '}</pre>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Applied Improvements list */}
      {improvements.length > 0 && (
        <div className="p-3 bg-slate-900/60 border border-slate-800/80 rounded-lg text-xs space-y-1.5">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
            Key Changes in this Patch
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
            {improvements.map((imp, idx) => (
              <div key={idx} className="flex items-start gap-2 text-slate-300 text-[11px]">
                <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span>{imp}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
