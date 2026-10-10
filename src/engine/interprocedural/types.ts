import { ASTNode } from '../ast/types';

export type TaintThreatType = 
  | 'SQL_INJECTION' 
  | 'COMMAND_INJECTION' 
  | 'PATH_TRAVERSAL' 
  | 'XSS' 
  | 'UNTRUSTED';

export type SinkContext = 
  | 'SQL_QUERY'
  | 'HTML_BODY'
  | 'HTML_ATTRIBUTE'
  | 'JAVASCRIPT_CONTEXT'
  | 'URL_DESTINATION'
  | 'URL_COMPONENT'
  | 'URL_CONTEXT'
  | 'COMMAND_EXEC'
  | 'PATH_RESOLVE';

export type VulnerabilityConfidence = 'confirmed' | 'unresolved_flow';

export type InterproceduralStepType = 
  | 'SOURCE'
  | 'ARGUMENT'
  | 'PARAMETER'
  | 'PROPAGATION'
  | 'TEMPLATE'
  | 'PROPERTY_ACCESS'
  | 'OBJECT_CREATION'
  | 'RETURN'
  | 'SANITIZER'
  | 'SINK';

export interface InterproceduralPathStep {
  stepNumber: number;
  type: InterproceduralStepType;
  line: number;
  function?: string;
  functionName?: string;
  symbol?: string;
  expression?: string;
  description: string;
}

export interface InterproceduralTaintVulnerability {
  id: string;
  vulnerabilityType: TaintThreatType;
  confidence?: VulnerabilityConfidence;
  isUnresolvedFlow?: boolean;
  unresolvedFunction?: string;
  sinkContext?: SinkContext;
  source: {
    file: string;
    line: number;
    symbol: string;
  };
  sink: {
    file: string;
    line: number;
    symbol: string;
  };
  sanitized: boolean;
  sanitizerStep?: {
    line: number;
    name: string;
    neutralizesThreat: boolean;
  };
  path: InterproceduralPathStep[];
}

export interface CallSite {
  id: string;
  callerFunctionName: string; // 'global' or function name
  calleeName: string;
  callNode: ASTNode;
  line: number;
  argumentNodes: ASTNode[];
  isMethodCall?: boolean;
  objectName?: string;
  methodName?: string;
  isResolved?: boolean;
  isComputed?: boolean;
}

export interface FunctionSummary {
  name: string;
  declarationNode: ASTNode;
  startLine: number;
  endLine: number;
  paramNames: string[];
  calls: CallSite[];
  returnNodes: ASTNode[];
  isRecursive?: boolean;
  kind?: 'function' | 'method' | 'arrow';
  parentObjectOrClass?: string;
}

export type AnalysisConvergenceStatus = 'converged' | 'resource_limit_exceeded';

export interface FinalVariableState {
  isTainted: boolean;
  sanitized?: boolean;
  threat?: TaintThreatType;
  stringValue?: string;
}

export interface InterproceduralAnalysisResult {
  vulnerabilities: InterproceduralTaintVulnerability[];
  iterations: number;
  converged: boolean;
  status: AnalysisConvergenceStatus;
  unresolvedCallsCount: number;
  flowSensitiveStepsEvaluated: number;
  finalVariables: Record<string, FinalVariableState>;
}

export interface SanitizerDefinition {
  name: string;
  neutralizesThreats: TaintThreatType[];
  validContexts: SinkContext[];
  description: string;
}
