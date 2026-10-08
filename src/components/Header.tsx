import React from 'react';
import { 
  Zap, 
  ShieldCheck, 
  Play, 
  Wand2, 
  FileDown, 
  Trophy, 
  Code2, 
  Loader2, 
  Cpu
} from 'lucide-react';
import { CODE_PRESETS } from '../constants/presets';
import { CodePreset } from '../types';

interface HeaderProps {
  currentPreset: CodePreset;
  onSelectPreset: (preset: CodePreset) => void;
  onRunAudit: () => void;
  onAutoRemediate: () => void;
  onOpenReport: () => void;
  onToggleChallenge: () => void;
  isAnalyzing: boolean;
  isChallengeActive: boolean;
  activeLanguage: string;
  onLanguageChange: (lang: string) => void;
  aiPowered: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentPreset,
  onSelectPreset,
  onRunAudit,
  onAutoRemediate,
  onOpenReport,
  onToggleChallenge,
  isAnalyzing,
  isChallengeActive,
  activeLanguage,
  onLanguageChange,
  aiPowered,
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
        {/* Left: Brand & Status */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-sm shadow-emerald-950">
              <Zap className="w-5 h-5 fill-emerald-400/20" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-100 tracking-tight text-base font-mono">
                  CodePulse
                </span>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-1.5 py-0.5 rounded">
                  v3.8
                </span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span>AI Sentinel</span>
                <span aria-hidden="true" className="text-slate-600">·</span>
                <span>Static &amp; Runtime Optimization</span>
              </div>
            </div>
          </div>

          {/* Engine indicator */}
          <div className="hidden lg:flex items-center gap-2 text-xs text-slate-400 pl-4 border-l border-slate-800">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>{aiPowered ? 'Gemini 3.8 Flash Engine' : 'Hybrid AST Engine'}</span>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <span className="text-slate-500">Sub-10ms Static Lint</span>
          </div>
        </div>

        {/* Center: Preset Selector */}
        <div className="hidden md:flex items-center gap-2">
          <label htmlFor="preset-select" className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
            <Code2 className="w-3.5 h-3.5 text-slate-500" />
            <span>Preset:</span>
          </label>
          <select
            id="preset-select"
            value={currentPreset.id}
            onChange={(e) => {
              const selected = CODE_PRESETS.find((p) => p.id === e.target.value);
              if (selected) onSelectPreset(selected);
            }}
            className="bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-md px-2.5 py-1.5 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/50 transition-colors"
          >
            {CODE_PRESETS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.title} ({p.language})
              </option>
            ))}
          </select>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Challenge Toggle */}
          <button
            onClick={onToggleChallenge}
            className={`px-3 py-1.5 text-xs font-medium rounded-md border flex items-center gap-1.5 transition-all ${
              isChallengeActive
                ? 'bg-amber-950/60 border-amber-500/50 text-amber-300 shadow-sm'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700'
            }`}
            title="Interactive Code Sentinel Challenge"
          >
            <Trophy className="w-3.5 h-3.5 text-amber-400" />
            <span className="hidden sm:inline">Bug Challenge</span>
          </button>

          {/* Export Report */}
          <button
            onClick={onOpenReport}
            className="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 transition-colors flex items-center gap-1.5"
            title="Export Security & Performance Audit Report"
          >
            <FileDown className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Export</span>
          </button>

          {/* 1-Click Auto-Remediate */}
          <button
            onClick={onAutoRemediate}
            disabled={isAnalyzing}
            className="px-3.5 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-emerald-500/30 transition-all flex items-center gap-1.5 shadow-sm disabled:opacity-50"
            title="Auto-apply all optimizations and security fixes"
          >
            <Wand2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Auto-Fix</span>
          </button>

          {/* Run Audit */}
          <button
            onClick={onRunAudit}
            disabled={isAnalyzing}
            className="px-4 py-1.5 text-xs font-medium rounded-md bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white transition-all flex items-center gap-1.5 shadow-sm shadow-emerald-950 font-mono disabled:opacity-50 cursor-pointer"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Auditing...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Audit</span>
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
