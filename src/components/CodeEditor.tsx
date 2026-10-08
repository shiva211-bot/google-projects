import React, { useRef, useEffect } from 'react';
import { 
  Copy, 
  Check, 
  RotateCcw, 
  Upload, 
  AlertTriangle, 
  AlertCircle, 
  FileCode,
  Sparkles
} from 'lucide-react';
import { CodeFinding } from '../types';

interface CodeEditorProps {
  code: string;
  onChange: (value: string) => void;
  language: string;
  filename: string;
  onFilenameChange: (name: string) => void;
  findings: CodeFinding[];
  highlightedLine: number | null;
  onLineClick: (lineNum: number) => void;
  onReset: () => void;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  code,
  onChange,
  language,
  filename,
  onFilenameChange,
  findings,
  highlightedLine,
  onLineClick,
  onReset,
}) => {
  const [copied, setCopied] = React.useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineNumbersRef = useRef<HTMLDivElement>(null);

  const lines = code.split('\n');

  // Create a map of lines to findings
  const findingsByLine = React.useMemo(() => {
    const map = new Map<number, CodeFinding>();
    findings.forEach((f) => {
      if (!map.has(f.line) || f.severity === 'critical') {
        map.set(f.line, f);
      }
    });
    return map;
  }, [findings]);

  // Sync scrolling between textarea and line gutter
  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    if (lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = e.currentTarget.scrollTop;
    }
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    onFilenameChange(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        onChange(content);
      }
    };
    reader.readAsText(file);
  };

  // Scroll to highlighted line when requested
  useEffect(() => {
    if (highlightedLine && textareaRef.current) {
      const lineHeight = 21; // roughly 21px line height for text-xs/mono
      const scrollPos = Math.max(0, (highlightedLine - 3) * lineHeight);
      textareaRef.current.scrollTo({ top: scrollPos, behavior: 'smooth' });
    }
  }, [highlightedLine]);

  return (
    <div className="flex flex-col h-full bg-slate-950 border border-slate-800 rounded-lg overflow-hidden shadow-sm">
      {/* Editor Top Bar */}
      <div className="h-10 bg-slate-900/90 border-b border-slate-800 px-3 flex items-center justify-between text-xs text-slate-300">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-emerald-400" />
          <input
            type="text"
            value={filename}
            onChange={(e) => onFilenameChange(e.target.value)}
            className="bg-transparent border-b border-transparent hover:border-slate-700 focus:border-emerald-500 text-slate-200 font-mono text-xs focus:outline-none px-1 py-0.5 rounded transition-colors"
            title="Rename file"
          />
          <span className="text-slate-600">·</span>
          <span className="text-slate-400 font-mono text-[11px] uppercase tracking-wide">
            {language}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            className="hidden"
            accept=".js,.jsx,.ts,.tsx,.py,.go,.sql,.json,.html,.css"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="p-1.5 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition-colors"
            title="Upload source file"
          >
            <Upload className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleCopy}
            className="p-1.5 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition-colors"
            title="Copy source code"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={onReset}
            className="p-1.5 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition-colors"
            title="Reset to preset source"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Code Text Area with Line Numbers & Error Glyphs */}
      <div className="relative flex-1 flex overflow-hidden font-mono text-xs leading-[21px]">
        {/* Line Numbers Gutter */}
        <div
          ref={lineNumbersRef}
          className="w-12 py-3 bg-slate-900/50 border-r border-slate-800/80 text-slate-600 select-none overflow-hidden text-right font-mono text-[11px]"
        >
          {lines.map((_, i) => {
            const lineNum = i + 1;
            const finding = findingsByLine.get(lineNum);
            const isHighlighted = highlightedLine === lineNum;

            return (
              <div
                key={lineNum}
                onClick={() => onLineClick(lineNum)}
                className={`h-[21px] px-2 flex items-center justify-end gap-1 cursor-pointer transition-colors ${
                  isHighlighted ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'hover:text-slate-400'
                }`}
              >
                {finding && (
                  <span
                    title={`${finding.severity.toUpperCase()}: ${finding.title}`}
                    className="inline-block"
                  >
                    {finding.severity === 'critical' || finding.severity === 'high' ? (
                      <AlertCircle className="w-3 h-3 text-rose-400 inline" />
                    ) : (
                      <AlertTriangle className="w-3 h-3 text-amber-400 inline" />
                    )}
                  </span>
                )}
                <span>{lineNum}</span>
              </div>
            );
          })}
        </div>

        {/* Text Area */}
        <div className="relative flex-1 h-full">
          <textarea
            ref={textareaRef}
            value={code}
            onChange={(e) => onChange(e.target.value)}
            onScroll={handleScroll}
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            className="w-full h-full py-3 px-3.5 bg-slate-950 text-slate-200 resize-none focus:outline-none font-mono text-xs leading-[21px] whitespace-pre tab-4 selection:bg-emerald-900/40 selection:text-emerald-200"
            placeholder="Paste code to analyze or choose a preset above..."
          />
        </div>
      </div>

      {/* Editor Footer / Info Bar */}
      <div className="h-7 bg-slate-900/70 border-t border-slate-800/80 px-3 flex items-center justify-between text-[11px] text-slate-400 font-mono">
        <div className="flex items-center gap-3">
          <span>{lines.length} lines</span>
          <span className="text-slate-700">·</span>
          <span>{code.length} chars</span>
          <span className="text-slate-700">·</span>
          <span>~{Math.round(code.length / 4)} tokens</span>
        </div>
        <div className="flex items-center gap-2">
          {findings.length > 0 ? (
            <span className="text-rose-400 flex items-center gap-1">
              <AlertCircle className="w-3 h-3" />
              <span>{findings.length} findings detected</span>
            </span>
          ) : (
            <span className="text-emerald-400 flex items-center gap-1">
              <Check className="w-3 h-3" />
              <span>Clean baseline</span>
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
