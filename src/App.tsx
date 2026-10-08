import React, { useState, useEffect, useCallback } from 'react';
import { 
  BarChart3, 
  ShieldAlert, 
  GitCompare, 
  Gauge, 
  Trophy, 
  Check, 
  AlertCircle,
  Network,
  FileCheck2
} from 'lucide-react';
import { CODE_PRESETS } from './constants/presets';
import { CodePreset, AnalysisResult } from './types';
import { executeTrueStaticAnalysis } from './engine/staticEngine';
import { runFullAnalysis } from './services/api';
import { ComprehensiveStaticAnalysis } from './engine/ast/types';
import { Header } from './components/Header';
import { CodeEditor } from './components/CodeEditor';
import { MetricsOverview } from './components/MetricsOverview';
import { FindingsList } from './components/FindingsList';
import { RemediationDiffView } from './components/RemediationDiffView';
import { StaticEngineExplorer } from './components/StaticEngineExplorer';
import { QualityDashboard } from './components/QualityDashboard';
import { PerformanceProfiler } from './components/PerformanceProfiler';
import { ChallengeMode } from './components/ChallengeMode';
import { ReportModal } from './components/ReportModal';

export default function App() {
  const [currentPreset, setCurrentPreset] = useState<CodePreset>(CODE_PRESETS[0]);
  const [code, setCode] = useState<string>(CODE_PRESETS[0].code);
  const [language, setLanguage] = useState<string>(CODE_PRESETS[0].language);
  const [filename, setFilename] = useState<string>(CODE_PRESETS[0].filename);

  // Initialize with real static AST analysis
  const initialOutput = executeTrueStaticAnalysis(
    CODE_PRESETS[0].code,
    CODE_PRESETS[0].language,
    CODE_PRESETS[0].filename
  );

  const [analysis, setAnalysis] = useState<AnalysisResult>(initialOutput.analysis);
  const [engineData, setEngineData] = useState<ComprehensiveStaticAnalysis>(initialOutput.engineData);

  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'metrics' | 'findings' | 'diff' | 'engine' | 'quality' | 'profiler'>('metrics');
  const [isChallengeActive, setIsChallengeActive] = useState<boolean>(false);
  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 3000);
  };

  // Run audit handler
  const handleRunAudit = useCallback(async (sourceCode = code, srcLang = language, srcFile = filename) => {
    setIsAnalyzing(true);
    try {
      const result = await runFullAnalysis(sourceCode, srcLang, srcFile);
      setAnalysis(result.analysis);
      setEngineData(result.engineData);
      showNotification(`AST Scan passed: ${result.engineData.tokensCount} tokens analyzed in ${result.engineData.durationMs}ms`);
    } catch (err) {
      console.error('Audit failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  }, [code, language, filename]);

  // Initial audit
  useEffect(() => {
    handleRunAudit(currentPreset.code, currentPreset.language, currentPreset.filename);
  }, []);

  // Preset selection
  const handleSelectPreset = (preset: CodePreset) => {
    setCurrentPreset(preset);
    setCode(preset.code);
    setLanguage(preset.language);
    setFilename(preset.filename);
    setHighlightedLine(null);
    handleRunAudit(preset.code, preset.language, preset.filename);
  };

  // Reset current code to preset
  const handleResetToPreset = () => {
    setCode(currentPreset.code);
    setHighlightedLine(null);
    handleRunAudit(currentPreset.code, currentPreset.language, currentPreset.filename);
    showNotification('Restored to preset initial state');
  };

  // 1-Click Auto Remediate
  const handleAutoRemediate = () => {
    if (!analysis.remediatedCode || analysis.remediatedCode === code) {
      showNotification('No outstanding remediations needed');
      return;
    }
    setCode(analysis.remediatedCode);
    setHighlightedLine(null);
    setActiveTab('diff');
    handleRunAudit(analysis.remediatedCode, language, filename);
    showNotification('Applied AST-validated optimizations!');
  };

  const handleLineClick = (lineNum: number) => {
    setHighlightedLine(lineNum);
    if (activeTab !== 'findings' && activeTab !== 'engine') {
      setActiveTab('findings');
    }
  };

  // Keyboard shortcut: Cmd/Ctrl + Enter to trigger audit
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        handleRunAudit();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleRunAudit]);

  const findingsCount = analysis.findings.length;
  const criticalCount = analysis.findings.filter(f => f.severity === 'critical').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-900/40 selection:text-emerald-200">
      {/* App Header */}
      <Header
        currentPreset={currentPreset}
        onSelectPreset={handleSelectPreset}
        onRunAudit={() => handleRunAudit()}
        onAutoRemediate={handleAutoRemediate}
        onOpenReport={() => setIsReportOpen(true)}
        onToggleChallenge={() => setIsChallengeActive(!isChallengeActive)}
        isAnalyzing={isAnalyzing}
        isChallengeActive={isChallengeActive}
        activeLanguage={language}
        onLanguageChange={setLanguage}
        aiPowered={analysis.aiPowered}
      />

      {/* Floating Notification Toast */}
      {notification && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 border border-slate-700/80 text-slate-100 text-xs px-4 py-2.5 rounded-lg shadow-xl flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 duration-200 font-mono">
          <Check className="w-3.5 h-3.5 text-emerald-400" />
          <span>{notification}</span>
        </div>
      )}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 flex flex-col gap-4">
        {/* Challenge Mode Overlay or View */}
        {isChallengeActive ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-xs text-slate-400">
                <span>Interactive Learning Mode</span>
                <span className="mx-2 text-slate-600">·</span>
                <span>Test your vulnerability &amp; performance intuition</span>
              </div>
              <button
                onClick={() => setIsChallengeActive(false)}
                className="text-xs text-slate-400 hover:text-slate-200 underline cursor-pointer"
              >
                Return to Code Studio
              </button>
            </div>
            <ChallengeMode />
          </div>
        ) : (
          /* Normal Studio Workspace: Split Panes */
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[640px]">
            {/* Left Pane: Code Editor (5/12 cols on desktop) */}
            <div className="lg:col-span-5 h-[600px] lg:h-auto flex flex-col">
              <CodeEditor
                code={code}
                onChange={setCode}
                language={language}
                filename={filename}
                onFilenameChange={setFilename}
                findings={analysis.findings}
                highlightedLine={highlightedLine}
                onLineClick={handleLineClick}
                onReset={handleResetToPreset}
              />
            </div>

            {/* Right Pane: Analysis & Optimization Hub (7/12 cols on desktop) */}
            <div className="lg:col-span-7 flex flex-col bg-slate-950/70 border border-slate-800 rounded-lg overflow-hidden shadow-sm">
              {/* Tab Navigation (Interactive Segmented Buttons) */}
              <div className="h-11 bg-slate-900/90 border-b border-slate-800 px-3 flex items-center justify-between text-xs overflow-x-auto">
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    onClick={() => setActiveTab('metrics')}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer ${
                      activeTab === 'metrics'
                        ? 'bg-slate-800 text-white font-medium shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <BarChart3 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Metrics</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('findings')}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer ${
                      activeTab === 'findings'
                        ? 'bg-slate-800 text-white font-medium shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                    <span>Findings</span>
                    {findingsCount > 0 && (
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-950 text-slate-300 border border-slate-800">
                        {findingsCount}
                      </span>
                    )}
                  </button>

                  <button
                    onClick={() => setActiveTab('diff')}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer ${
                      activeTab === 'diff'
                        ? 'bg-slate-800 text-white font-medium shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <GitCompare className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Diff</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('engine')}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer ${
                      activeTab === 'engine'
                        ? 'bg-slate-800 text-white font-medium shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Network className="w-3.5 h-3.5 text-emerald-400" />
                    <span>AST &amp; Rules</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('quality')}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer ${
                      activeTab === 'quality'
                        ? 'bg-slate-800 text-white font-medium shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Verification Suite</span>
                  </button>

                  <button
                    onClick={() => setActiveTab('profiler')}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer ${
                      activeTab === 'profiler'
                        ? 'bg-slate-800 text-white font-medium shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Gauge className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Profiler Lab</span>
                  </button>
                </div>

                {/* Sub-status in tab bar */}
                <div className="hidden sm:flex items-center gap-2 text-[11px] text-slate-400 font-mono shrink-0 pl-2">
                  <span>AST: {engineData.durationMs}ms</span>
                  <span className="text-slate-700">·</span>
                  <span className={criticalCount > 0 ? 'text-rose-400' : 'text-emerald-400'}>
                    {criticalCount > 0 ? `${criticalCount} Critical` : 'Clean AST'}
                  </span>
                </div>
              </div>

              {/* Tab Contents */}
              <div className="p-4 flex-1 overflow-y-auto">
                {activeTab === 'metrics' && (
                  <MetricsOverview
                    metrics={analysis.metrics}
                    findings={analysis.findings}
                    onAutoFixClick={handleAutoRemediate}
                    onViewDiffClick={() => setActiveTab('diff')}
                  />
                )}

                {activeTab === 'findings' && (
                  <FindingsList
                    findings={analysis.findings}
                    highlightedLine={highlightedLine}
                    onLineClick={handleLineClick}
                  />
                )}

                {activeTab === 'diff' && (
                  <RemediationDiffView
                    originalCode={code}
                    remediatedCode={analysis.remediatedCode}
                    summary={analysis.remediationSummary}
                    improvements={analysis.improvements}
                    onApplyToEditor={handleAutoRemediate}
                  />
                )}

                {activeTab === 'engine' && (
                  <StaticEngineExplorer
                    engineData={engineData}
                    onLineClick={handleLineClick}
                  />
                )}

                {activeTab === 'quality' && (
                  <QualityDashboard />
                )}

                {activeTab === 'profiler' && (
                  <PerformanceProfiler currentCategory={currentPreset.category} />
                )}
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Export Report Modal */}
      <ReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        analysis={analysis}
      />
    </div>
  );
}
