import { ASTNode } from '../ast/types';

export type TaintThreatType = 'SQL_INJECTION' | 'COMMAND_INJECTION' | 'PATH_TRAVERSAL' | 'XSS';

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
}

export interface SanitizerDefinition {
  name: string;
  neutralizesThreats: TaintThreatType[];
  description: string;
}
