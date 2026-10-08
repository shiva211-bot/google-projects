import React, { useState } from 'react';
import { 
  Network, 
  GitBranch, 
  Binary, 
  ShieldCheck, 
  AlertCircle, 
  CheckCircle2, 
  ChevronRight, 
  ChevronDown, 
  Clock, 
  Cpu, 
  Layers, 
  Search,
  Code2,
  FileCode2
} from 'lucide-react';
import { ComprehensiveStaticAnalysis, ASTNode, CFGNode, TaintVulnerability } from '../engine/ast/types';

interface StaticEngineExplorerProps {
  engineData: ComprehensiveStaticAnalysis;
  onLineClick: (line: number) => void;
}

export const StaticEngineExplorer: React.FC<StaticEngineExplorerProps> = ({
  engineData,
  onLineClick,
}) => {
  const [subTab, setSubTab] = useState<'ast' | 'cfg' | 'rules' | 'metrics'>('rules');
  const [astSearch, setAstSearch] = useState('');
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set(['root', 'body-0', 'body-1']));

  const toggleAstNode = (id: string) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      {/* Engine Overview Header */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-slate-100 font-mono">
              True Static Analysis &amp; AST Engine
            </h3>
            <span className="text-[10px] text-emerald-400 font-mono bg-emerald-950/70 border border-emerald-800/40 px-1.5 py-0.5 rounded">
              Native AST + CFG + Taint
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-xl leading-relaxed">
            Deterministic static analysis via ESTree Abstract Syntax Tree traversal, Control Flow Graph reachability, and Source-to-Sink Taint analysis. Zero AI dependency for core rule passes.
          </p>
        </div>

        {/* Engine Performance Telemetry */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="bg-slate-950 px-3 py-1.5 rounded border border-slate-800 text-slate-300">
            <span className="text-slate-500">Scan Time: </span>
            <span className="text-emerald-400 font-bold">{engineData.durationMs}ms</span>
          </div>
          <div className="bg-slate-950 px-3 py-1.5 rounded border border-slate-800 text-slate-300">
            <span className="text-slate-500">Tokens: </span>
            <span className="text-slate-200">{engineData.tokensCount}</span>
          </div>
        </div>
      </div>

      {/* Sub-navigation Controls (Zero-Pill Interactive Buttons) */}
      <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-md border border-slate-800 text-xs">
        <button
          onClick={() => setSubTab('rules')}
          className={`px-3 py-1.5 rounded transition-colors flex items-center gap-1.5 ${
            subTab === 'rules'
              ? 'bg-slate-800 text-white font-medium shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>AST Rule Passes ({engineData.ruleResults.length})</span>
        </button>

        <button
          onClick={() => setSubTab('cfg')}
          className={`px-3 py-1.5 rounded transition-colors flex items-center gap-1.5 ${
            subTab === 'cfg'
              ? 'bg-slate-800 text-white font-medium shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
          <span>CFG &amp; Taint Flow ({engineData.taintVulnerabilities.length} Taint)</span>
        </button>

        <button
          onClick={() => setSubTab('ast')}
          className={`px-3 py-1.5 rounded transition-colors flex items-center gap-1.5 ${
            subTab === 'ast'
              ? 'bg-slate-800 text-white font-medium shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Code2 className="w-3.5 h-3.5 text-indigo-400" />
          <span>AST Inspector</span>
        </button>

        <button
          onClick={() => setSubTab('metrics')}
          className={`px-3 py-1.5 rounded transition-colors flex items-center gap-1.5 ${
            subTab === 'metrics'
              ? 'bg-slate-800 text-white font-medium shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Binary className="w-3.5 h-3.5 text-amber-400" />
          <span>Halstead &amp; Complexity</span>
        </button>
      </div>

      {/* Sub Tab: AST Rule Passes */}
      {subTab === 'rules' && (
        <div className="space-y-2.5">
          <div className="grid grid-cols-1 gap-2">
            {engineData.ruleResults.map((rule) => {
              const isPassed = rule.passed;
              return (
                <div
                  key={rule.ruleId}
                  className={`p-3 rounded-lg border text-xs transition-colors ${
                    isPassed
                      ? 'bg-slate-900/40 border-slate-800/80 hover:border-slate-700'
                      : 'bg-rose-950/20 border-rose-500/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2.5">
                      {isPassed ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                      )}
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-200 font-mono">
                            {rule.ruleId}
                          </span>
                          <span className="text-slate-600">·</span>
                          <span className="text-slate-300 font-medium">{rule.ruleName}</span>
                        </div>
                        <div className="flex items-center gap-3 text-[11px] text-slate-400 mt-1 font-mono">
                          <span className="capitalize">{rule.category}</span>
                          <span className="text-slate-700">·</span>
                          <span>{rule.nodesInspectedCount} AST nodes traversed</span>
                          <span className="text-slate-700">·</span>
                          <span className="text-slate-500">{rule.executionTimeMs}ms</span>
                        </div>
                      </div>
                    </div>

                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                        isPassed
                          ? 'text-emerald-400 border-emerald-800/60 bg-emerald-950/40'
                          : 'text-rose-400 border-rose-800/60 bg-rose-950/40 font-bold'
                      }`}
                    >
                      {isPassed ? 'PASSED' : `${rule.violations.length} VIOLATION`}
                    </span>
                  </div>

                  {/* Violations if any */}
                  {!isPassed && rule.violations.length > 0 && (
                    <div className="mt-2.5 pt-2 border-t border-rose-900/40 space-y-1.5 pl-6">
                      {rule.violations.map((v, idx) => (
                        <div key={idx} className="text-[11px] space-y-1">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => onLineClick(v.line)}
                              className="text-amber-400 hover:underline font-mono"
                            >
                              Line {v.line}
                            </button>
                            <span className="text-slate-600">·</span>
                            <span className="text-slate-300">{v.message}</span>
                          </div>
                          {v.snippet && (
                            <div className="bg-slate-950 p-2 rounded font-mono text-[10px] text-rose-300 border border-slate-800/80 overflow-x-auto">
                              <code>{v.snippet}</code>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Sub Tab: CFG & Taint Flow */}
      {subTab === 'cfg' && (
        <div className="space-y-4">
          {/* Taint Data Flow Paths */}
          <div>
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5 text-rose-400" />
              <span>Taint Analysis: Source-to-Sink Data Flow Traces</span>
            </h4>

            {engineData.taintVulnerabilities.length === 0 ? (
              <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800 text-xs text-slate-400">
                No untrusted tainted inputs propagate to dangerous database or code execution sinks.
              </div>
            ) : (
              <div className="space-y-3">
                {engineData.taintVulnerabilities.map((tv) => (
                  <div key={tv.id} className="p-3.5 rounded-lg bg-rose-950/20 border border-rose-500/40 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-rose-300 font-mono">
                        {tv.vulnerabilityType} PATH TRACE
                      </span>
                      <span className="text-[11px] text-slate-400 font-mono">
                        Source L{tv.sourceLine} → Sink L{tv.sinkLine}
                      </span>
                    </div>

                    {/* Step by step taint flow */}
                    <div className="space-y-2">
                      {tv.taintPath.map((step) => (
                        <div key={step.stepNumber} className="flex items-start gap-2.5 font-mono text-[11px]">
                          <span className={`w-5 h-5 rounded flex items-center justify-center shrink-0 font-bold ${
                            step.type === 'source' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                            step.type === 'sink' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {step.stepNumber}
                          </span>
                          <div className="flex-1 bg-slate-950 p-2 rounded border border-slate-800/80">
                            <div className="flex items-center justify-between text-slate-400">
                              <span className="uppercase text-[10px] font-bold text-slate-300">{step.type}</span>
                              <button
                                onClick={() => onLineClick(step.line)}
                                className="text-amber-400 hover:underline text-[10px]"
                              >
                                Jump to Line {step.line}
                              </button>
                            </div>
                            <p className="text-slate-300 mt-1">{step.description}</p>
                            <code className="text-rose-300 mt-1 block font-mono text-[10px] bg-slate-900 p-1 rounded">
                              {step.expression}
                            </code>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Interprocedural Call-Flow Traces */}
          {engineData.interproceduralVulnerabilities && engineData.interproceduralVulnerabilities.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Network className="w-3.5 h-3.5 text-indigo-400" />
                <span>Interprocedural Taint: Cross-Function Call Graph Paths</span>
              </h4>

              <div className="space-y-3">
                {engineData.interproceduralVulnerabilities.map((ipv) => (
                  <div key={ipv.id} className="p-3.5 rounded-lg bg-indigo-950/20 border border-indigo-500/40 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-indigo-300 font-mono">
                        {ipv.vulnerabilityType} CROSS-FUNCTION TRACE ({ipv.path.length} HOPS)
                      </span>
                      <span className={`text-[11px] font-mono px-1.5 py-0.5 rounded border ${
                        ipv.sanitized
                          ? 'text-emerald-400 border-emerald-800 bg-emerald-950/40'
                          : 'text-rose-400 border-rose-800 bg-rose-950/40'
                      }`}>
                        {ipv.sanitized ? 'SANITIZED' : 'UNSANITIZED SINK'}
                      </span>
                    </div>

                    <div className="space-y-1.5">
                      {ipv.path.map((step) => (
                        <div key={step.stepNumber} className="flex items-start gap-2 bg-slate-950 p-2 rounded border border-slate-800/80 font-mono text-[11px]">
                          <span className={`w-5 h-5 rounded flex items-center justify-center shrink-0 font-bold text-[10px] ${
                            step.type === 'SOURCE' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                            step.type === 'SINK' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                            step.type === 'SANITIZER' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' :
                            step.type === 'RETURN' ? 'bg-indigo-950 text-indigo-400 border border-indigo-800' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {step.stepNumber}
                          </span>
                          <div className="flex-1 text-slate-300">
                            <div className="flex items-center justify-between">
                              <span className="uppercase text-[10px] font-bold text-slate-300">
                                {step.type} {step.function ? `(${step.function})` : ''}
                              </span>
                              <button
                                onClick={() => onLineClick(step.line)}
                                className="text-amber-400 hover:underline text-[10px]"
                              >
                                L{step.line}
                              </button>
                            </div>
                            <p className="text-slate-400 text-[10px] mt-0.5">{step.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Control Flow Graph Basic Blocks */}
          <div>
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
              <span>Control Flow Graph: Basic Blocks ({engineData.cfg.nodes.length} Blocks, {engineData.cfg.edges.length} Edges)</span>
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {engineData.cfg.nodes.map((node) => (
                <div
                  key={node.id}
                  className={`p-2.5 rounded border text-xs font-mono ${
                    !node.isReachable
                      ? 'bg-rose-950/30 border-rose-500/50 text-rose-200'
                      : node.type === 'entry' || node.type === 'exit'
                      ? 'bg-slate-900 border-slate-700 text-slate-200'
                      : 'bg-slate-950 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[11px]">{node.label}</span>
                    <span className="text-[10px] text-slate-500 uppercase">{node.type}</span>
                  </div>
                  <div className="mt-1 text-[10px] text-slate-400">
                    <span>In: {node.incomingEdges.length}</span>
                    <span className="mx-1 text-slate-700">·</span>
                    <span>Out: {node.outgoingEdges.length}</span>
                    <span className="mx-1 text-slate-700">·</span>
                    <span className={node.isReachable ? 'text-emerald-400' : 'text-rose-400 font-bold'}>
                      {node.isReachable ? 'Reachable' : 'DEAD CODE'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Sub Tab: AST Inspector */}
      {subTab === 'ast' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Root ESTree Program Node: {engineData.ast?.type || 'Program'}</span>
            <div className="relative min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                value={astSearch}
                onChange={(e) => setAstSearch(e.target.value)}
                placeholder="Filter AST nodes..."
                className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded pl-8 pr-2.5 py-1.5 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-[460px] overflow-auto font-mono text-xs">
            {engineData.ast && Array.isArray(engineData.ast.body) ? (
              <div className="space-y-1">
                <div className="text-emerald-400 font-bold">
                  Program ({engineData.ast.body.length} statements)
                </div>
                {engineData.ast.body.map((stmt: ASTNode, idx: number) => {
                  const id = `body-${idx}`;
                  const isExpanded = expandedNodes.has(id);
                  const line = stmt.loc?.start?.line;

                  return (
                    <div key={idx} className="pl-3 border-l border-slate-800">
                      <div
                        onClick={() => toggleAstNode(id)}
                        className="py-1 flex items-center justify-between hover:bg-slate-900/60 px-1.5 rounded cursor-pointer text-slate-300"
                      >
                        <div className="flex items-center gap-1.5">
                          {isExpanded ? (
                            <ChevronDown className="w-3 h-3 text-slate-500" />
                          ) : (
                            <ChevronRight className="w-3 h-3 text-slate-500" />
                          )}
                          <span className="text-indigo-400 font-semibold">{stmt.type}</span>
                          {stmt.id?.name && <span className="text-slate-400">({stmt.id.name})</span>}
                        </div>
                        {line && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onLineClick(line);
                            }}
                            className="text-amber-400 hover:underline text-[10px]"
                          >
                            L{line}
                          </button>
                        )}
                      </div>

                      {isExpanded && (
                        <div className="pl-4 py-1 text-[11px] text-slate-400 space-y-0.5">
                          <div>Range: [{stmt.start}, {stmt.end}]</div>
                          {stmt.declarations && (
                            <div className="text-slate-300">
                              Declarations: {stmt.declarations.map((d: any) => d.id?.name).filter(Boolean).join(', ')}
                            </div>
                          )}
                          {stmt.expression && (
                            <div className="text-slate-300">
                              Expression: {stmt.expression.type} ({stmt.expression.callee?.name || stmt.expression.callee?.property?.name || ''})
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <pre className="text-slate-400 text-xs">
                {JSON.stringify(engineData.ast, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}

      {/* Sub Tab: Halstead & Complexity Metrics */}
      {subTab === 'metrics' && (
        <div className="space-y-4">
          {/* Halstead Software Science Matrix */}
          <div>
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Binary className="w-3.5 h-3.5 text-amber-400" />
              <span>Halstead Software Science Parameters</span>
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs">
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <div className="text-slate-500 text-[10px]">Vocabulary (η = η1 + η2)</div>
                <div className="text-lg font-bold text-slate-100 mt-0.5">{engineData.halstead.vocabulary}</div>
                <div className="text-[10px] text-slate-400 mt-1">
                  η1={engineData.halstead.distinctOperators} ops · η2={engineData.halstead.distinctOperands} operands
                </div>
              </div>

              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <div className="text-slate-500 text-[10px]">Program Volume (V)</div>
                <div className="text-lg font-bold text-cyan-400 mt-0.5">{engineData.halstead.volume}</div>
                <div className="text-[10px] text-slate-400 mt-1">
                  N={engineData.halstead.length} total tokens
                </div>
              </div>

              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <div className="text-slate-500 text-[10px]">Program Difficulty (D)</div>
                <div className="text-lg font-bold text-amber-400 mt-0.5">{engineData.halstead.difficulty}</div>
                <div className="text-[10px] text-slate-400 mt-1">
                  Mental effort required
                </div>
              </div>

              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <div className="text-slate-500 text-[10px]">Implementation Effort (E)</div>
                <div className="text-lg font-bold text-indigo-400 mt-0.5">{Math.round(engineData.halstead.effort)}</div>
                <div className="text-[10px] text-slate-400 mt-1">
                  ~{engineData.halstead.timeSeconds}s dev time
                </div>
              </div>
            </div>
          </div>

          {/* Software Engineering Institute Maintainability Index Formula Breakdown */}
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs space-y-2">
            <h4 className="font-semibold text-slate-200">
              SEI Standard Maintainability Index (MI = {engineData.maintainabilityIndex}/100)
            </h4>
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-[11px] text-emerald-400">
              MI = max(0, (171 - 5.2 × ln({engineData.halstead.volume}) - 0.23 × {engineData.cyclomaticComplexity} - 16.2 × ln({engineData.linesOfCode.code})) × 100 / 171)
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono pt-1 text-slate-400">
              <div>Total Lines: <strong className="text-slate-200">{engineData.linesOfCode.total}</strong></div>
              <div>Source Code: <strong className="text-slate-200">{engineData.linesOfCode.code}</strong></div>
              <div>Comments: <strong className="text-slate-200">{engineData.linesOfCode.comments}</strong></div>
              <div>Blank Lines: <strong className="text-slate-200">{engineData.linesOfCode.blank}</strong></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
