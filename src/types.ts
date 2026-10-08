export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category = 'security' | 'performance' | 'reliability' | 'maintainability' | 'efficiency';

export interface CodeFinding {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
  line: number;
  endLine?: number;
  impact: string;
  description: string;
  recommendation: string;
  codeSnippet?: string;
  suggestedReplacement?: string;
}

export interface CodeMetrics {
  overallScore: number; // 0-100
  securityScore: number; // 0-100
  performanceScore: number; // 0-100
  maintainabilityScore: number; // 0-100
  efficiencyScore: number; // 0-100
  bigOTime: string;
  bigOSpace: string;
  estimatedLatencyMs: number;
  estimatedMemoryMb: number;
  cyclomaticComplexity: number;
  rulesPassedPercent: number;
}

export interface AnalysisResult {
  code: string;
  language: string;
  filename: string;
  analyzedAt: string;
  metrics: CodeMetrics;
  findings: CodeFinding[];
  remediatedCode: string;
  remediationSummary: string;
  improvements: string[];
  executionTimeMs: number;
  aiPowered: boolean;
}

export interface BenchmarkMetrics {
  iterations: number;
  original: {
    avgLatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    memoryMb: number;
    throughputOpsSec: number;
    cpuUtilizationPercent: number;
  };
  remediated: {
    avgLatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    memoryMb: number;
    throughputOpsSec: number;
    cpuUtilizationPercent: number;
  };
  speedupMultiplier: number;
  memorySavedMb: number;
  estimatedAnnualCloudSavingsUsd: number;
}

export interface CodePreset {
  id: string;
  title: string;
  language: string;
  filename: string;
  description: string;
  category: 'security' | 'performance' | 'fullstack';
  tags: string[];
  code: string;
}

export interface ChallengeItem {
  id: string;
  title: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Hard' | 'Guru';
  language: string;
  code: string;
  question: string;
  options: {
    id: string;
    text: string;
    isCorrect: boolean;
  }[];
  explanation: string;
  performanceOrSecurityTip: string;
}
