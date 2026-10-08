import { ASTNode } from '../ast/types';
import { FunctionSummary, CallSite } from './types';

export class CallGraph {
  public functions = new Map<string, FunctionSummary>();
  public callSites: CallSite[] = [];

  constructor(ast: ASTNode | null) {
    if (ast) {
      this.buildSymbolTable(ast);
      this.detectRecursion();
    }
  }

  private buildSymbolTable(ast: ASTNode) {
    let callCounter = 1;

    // First pass: Index all function declarations and function expressions
    const indexFunctions = (node: any, currentFunctionName = 'global') => {
      if (!node || typeof node !== 'object') return;

      let fnName: string | null = null;
      let fnNode: any = null;

      if (node.type === 'FunctionDeclaration' && node.id?.name) {
        fnName = node.id.name;
        fnNode = node;
      } else if (
        node.type === 'VariableDeclarator' &&
        node.id?.name &&
        (node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')
      ) {
        fnName = node.id.name;
        fnNode = node.init;
      }

      if (fnName && fnNode) {
        const params: string[] = [];
        for (const p of fnNode.params || []) {
          if (p.type === 'Identifier') {
            params.push(p.name);
          } else if (p.type === 'ObjectPattern') {
            for (const prop of p.properties || []) {
              const k = prop.key?.name || prop.value?.name;
              if (k) params.push(k);
            }
          }
        }

        const returnNodes: ASTNode[] = [];
        const internalCalls: CallSite[] = [];

        // Scan function body for return statements and call expressions
        const scanBody = (inner: any) => {
          if (!inner || typeof inner !== 'object') return;

          // Don't descend into nested function declarations (they will be indexed separately)
          if (inner !== fnNode && (inner.type === 'FunctionDeclaration' || inner.type === 'ArrowFunctionExpression')) {
            return;
          }

          if (inner.type === 'ReturnStatement' && inner.argument) {
            returnNodes.push(inner.argument);
          }

          if (inner.type === 'CallExpression') {
            const calleeName = this.extractCalleeName(inner.callee);
            if (calleeName) {
              const cs: CallSite = {
                id: `call-${callCounter++}`,
                callerFunctionName: fnName!,
                calleeName,
                callNode: inner,
                line: inner.loc?.start?.line || 1,
                argumentNodes: inner.arguments || [],
              };
              internalCalls.push(cs);
              this.callSites.push(cs);
            }
          }

          for (const key in inner) {
            if (key !== 'loc' && typeof inner[key] === 'object') scanBody(inner[key]);
          }
        };

        // If arrow function with direct expression body: const f = (x) => expr
        if (fnNode.body?.type !== 'BlockStatement') {
          returnNodes.push(fnNode.body);
        } else {
          scanBody(fnNode.body);
        }

        this.functions.set(fnName, {
          name: fnName,
          declarationNode: fnNode,
          startLine: fnNode.loc?.start?.line || 1,
          endLine: fnNode.loc?.end?.line || 1,
          paramNames: params,
          calls: internalCalls,
          returnNodes,
        });

        // Continue indexing inside this function
        currentFunctionName = fnName;
      }

      // Record top-level (global) calls
      if (node.type === 'CallExpression' && currentFunctionName === 'global') {
        const calleeName = this.extractCalleeName(node.callee);
        if (calleeName) {
          this.callSites.push({
            id: `call-${callCounter++}`,
            callerFunctionName: 'global',
            calleeName,
            callNode: node,
            line: node.loc?.start?.line || 1,
            argumentNodes: node.arguments || [],
          });
        }
      }

      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          indexFunctions(node[key], currentFunctionName);
        }
      }
    };

    indexFunctions(ast);
  }

  private extractCalleeName(callee: any): string | null {
    if (!callee) return null;
    if (callee.type === 'Identifier') return callee.name;
    if (callee.type === 'MemberExpression') {
      const objName = callee.object?.name || '';
      const propName = callee.property?.name || '';
      return objName ? `${objName}.${propName}` : propName;
    }
    return null;
  }

  private detectRecursion() {
    for (const [name, fn] of this.functions.entries()) {
      const callsSelf = fn.calls.some(c => c.calleeName === name);
      if (callsSelf) fn.isRecursive = true;
    }
  }

  public getFunction(name: string): FunctionSummary | undefined {
    return this.functions.get(name);
  }
}
