export interface SourceLocation {
  line: number;
  column: number;
}

export interface NodeLocation {
  start: SourceLocation;
  end: SourceLocation;
}

export interface ASTNode {
  type: string;
  start: number;
  end: number;
  loc?: NodeLocation;
  [key: string]: any;
}

export interface ASTToken {
  type: string;
  value: string;
  start: number;
  end: number;
  loc?: NodeLocation;
}

export interface CFGNode {
  id: string;
  label: string;
  type: 'entry' | 'statement' | 'branch' | 'loop' | 'exit';
  line?: number;
  codeSnippet?: string;
  incomingEdges: string[];
  outgoingEdges: string[];
  isReachable: boolean;
}

export interface CFGEdge {
  id: string;
  from: string;
  to: string;
  label?: 'true' | 'false' | 'always' | 'exception';
}

export interface ControlFlowGraph {
  nodes: CFGNode[];
  edges: CFGEdge[];
  cyclomaticComplexity: number;
  deadCodeBlocks: CFGNode[];
}

export interface TaintTraceStep {
  stepNumber: number;
  type: 'source' | 'propagation' | 'sink';
  line: number;
  variable?: string;
  expression: string;
  description: string;
}

export interface TaintVulnerability {
  id: string;
  vulnerabilityType: 'SQL_INJECTION' | 'COMMAND_INJECTION' | 'PATH_TRAVERSAL' | 'XSS' | 'PROTOTYPE_POLLUTION';
  sourceName: string;
  sinkName: string;
  sourceLine: number;
  sinkLine: number;
  taintPath: TaintTraceStep[];
}

export interface HalsteadMetrics {
  distinctOperators: number; // n1
  distinctOperands: number; // n2
  totalOperators: number; // N1
  totalOperands: number; // N2
  vocabulary: number; // n = n1 + n2
  length: number; // N = N1 + N2
  calculatedLength: number;
  volume: number; // V = N * log2(n)
  difficulty: number; // D = (n1/2) * (N2/n2)
  effort: number; // E = D * V
  timeSeconds: number; // T = E / 18
  bugsDelivered: number; // B = V / 3000
}

export interface StaticRuleResult {
  ruleId: string;
  ruleName: string;
  category: 'security' | 'performance' | 'reliability' | 'maintainability';
  severity: 'critical' | 'high' | 'medium' | 'low';
  passed: boolean;
  nodesInspectedCount: number;
  executionTimeMs: number;
  violations: {
    line: number;
    nodeType: string;
    message: string;
    snippet?: string;
    fixSnippet?: string;
  }[];
}

export interface ComprehensiveStaticAnalysis {
  ast: ASTNode | null;
  parseErrors: string[];
  tokensCount: number;
  cfg: ControlFlowGraph;
  taintVulnerabilities: TaintVulnerability[];
  halstead: HalsteadMetrics;
  cognitiveComplexity: number;
  cyclomaticComplexity: number;
  maintainabilityIndex: number; // 0-100 SEI index
  linesOfCode: {
    total: number;
    code: number;
    comments: number;
    blank: number;
  };
  ruleResults: StaticRuleResult[];
  analyzedAt: string;
  durationMs: number;
}
