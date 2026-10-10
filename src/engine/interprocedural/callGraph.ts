import { ASTNode } from '../ast/types';
import { FunctionSummary, CallSite } from './types';

export class CallGraph {
  public functions = new Map<string, FunctionSummary>();
  public callSites: CallSite[] = [];
  public aliases = new Map<string, string>(); // e.g. f -> buildQuery

  constructor(ast: ASTNode | null) {
    if (ast) {
      this.buildSymbolTable(ast);
      this.detectRecursion();
    }
  }

  private buildSymbolTable(ast: ASTNode) {
    let callCounter = 1;

    // Helper to register a function summary
    const registerFunction = (
      name: string,
      fnNode: any,
      kind: 'function' | 'method' | 'arrow' = 'function',
      parentName?: string
    ) => {
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
        if (inner !== fnNode && (
          inner.type === 'FunctionDeclaration' || 
          inner.type === 'ArrowFunctionExpression' || 
          inner.type === 'FunctionExpression'
        )) {
          return;
        }

        if (inner.type === 'ReturnStatement' && inner.argument) {
          returnNodes.push(inner.argument);
        }

        if (inner.type === 'CallExpression') {
          const { calleeName, isMethodCall, objectName, methodName, isComputed } = this.inspectCallee(inner.callee);
          if (calleeName) {
            const cs: CallSite = {
              id: `call-${callCounter++}`,
              callerFunctionName: name,
              calleeName,
              callNode: inner,
              line: inner.loc?.start?.line || 1,
              argumentNodes: inner.arguments || [],
              isMethodCall,
              objectName,
              methodName,
              isComputed,
              isResolved: false, // determined after indexing
            };
            internalCalls.push(cs);
            this.callSites.push(cs);
          }
        }

        for (const key in inner) {
          if (key !== 'loc' && typeof inner[key] === 'object') scanBody(inner[key]);
        }
      };

      // Arrow function with expression body: const f = (x) => expr
      if (fnNode.body?.type !== 'BlockStatement') {
        returnNodes.push(fnNode.body);
      } else {
        scanBody(fnNode.body);
      }

      const summary: FunctionSummary = {
        name,
        declarationNode: fnNode,
        startLine: fnNode.loc?.start?.line || 1,
        endLine: fnNode.loc?.end?.line || 1,
        paramNames: params,
        calls: internalCalls,
        returnNodes,
        kind,
        parentObjectOrClass: parentName,
      };

      this.functions.set(name, summary);
    };

    // First pass: Index function declarations, variable functions, object methods, class methods, and aliases
    const indexAst = (node: any, currentScope = 'global') => {
      if (!node || typeof node !== 'object') return;

      // 1. FunctionDeclaration: function foo() {}
      if (node.type === 'FunctionDeclaration' && node.id?.name) {
        registerFunction(node.id.name, node, 'function');
      }

      // 2. VariableDeclarator
      if (node.type === 'VariableDeclarator' && node.id?.name && node.init) {
        const varName = node.id.name;

        // 2A: Variable function: const foo = () => {} or const foo = function() {}
        if (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression') {
          registerFunction(varName, node.init, node.init.type === 'ArrowFunctionExpression' ? 'arrow' : 'function');
        }
        // 2B: Aliased function: const f = buildQuery;
        else if (node.init.type === 'Identifier') {
          this.aliases.set(varName, node.init.name);
        }
        // 2C: Object literal with methods: const obj = { build(id) { ... }, format: (x) => ... }
        else if (node.init.type === 'ObjectExpression') {
          for (const prop of node.init.properties || []) {
            const propName = prop.key?.name || prop.key?.value;
            if (propName && prop.value) {
              if (
                prop.value.type === 'FunctionExpression' ||
                prop.value.type === 'ArrowFunctionExpression' ||
                prop.method === true
              ) {
                const qualifiedMethodName = `${varName}.${propName}`;
                registerFunction(qualifiedMethodName, prop.value, 'method', varName);
                // Also index by method name as fallback if not ambiguous
                if (!this.functions.has(propName)) {
                  this.aliases.set(propName, qualifiedMethodName);
                }
              }
            }
          }
        }
      }

      // 3. ClassDeclaration: class Builder { build(id) { ... } }
      if (node.type === 'ClassDeclaration' && node.id?.name) {
        const className = node.id.name;
        for (const item of node.body?.body || []) {
          if (item.type === 'MethodDefinition' && item.key?.name && item.value) {
            const methodName = item.key.name;
            const qualifiedName = `${className}.${methodName}`;
            registerFunction(qualifiedName, item.value, 'method', className);
          }
        }
      }

      // 4. Global top-level calls
      if (node.type === 'CallExpression' && currentScope === 'global') {
        const { calleeName, isMethodCall, objectName, methodName, isComputed } = this.inspectCallee(node.callee);
        if (calleeName) {
          this.callSites.push({
            id: `call-${callCounter++}`,
            callerFunctionName: 'global',
            calleeName,
            callNode: node,
            line: node.loc?.start?.line || 1,
            argumentNodes: node.arguments || [],
            isMethodCall,
            objectName,
            methodName,
            isComputed,
            isResolved: false,
          });
        }
      }

      // Determine next scope for nested traversal
      let nextScope = currentScope;
      if (node.type === 'FunctionDeclaration' && node.id?.name) {
        nextScope = node.id.name;
      } else if (
        node.type === 'VariableDeclarator' &&
        node.id?.name &&
        (node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')
      ) {
        nextScope = node.id.name;
      }

      for (const key in node) {
        if (key !== 'loc' && typeof node[key] === 'object') {
          indexAst(node[key], nextScope);
        }
      }
    };

    indexAst(ast);

    // Resolve call sites
    for (const cs of this.callSites) {
      const resolved = this.resolveCallee(cs.calleeName);
      if (resolved) {
        cs.isResolved = true;
      } else {
        cs.isResolved = false;
      }
    }
  }

  private inspectCallee(callee: any): {
    calleeName: string | null;
    isMethodCall: boolean;
    objectName?: string;
    methodName?: string;
    isComputed: boolean;
  } {
    if (!callee) {
      return { calleeName: null, isMethodCall: false, isComputed: false };
    }

    if (callee.type === 'Identifier') {
      return { calleeName: callee.name, isMethodCall: false, isComputed: false };
    }

    if (callee.type === 'MemberExpression') {
      const isComputed = !!callee.computed;
      const objName = callee.object?.name || (callee.object?.type === 'ThisExpression' ? 'this' : '');
      const propName = callee.property?.name || callee.property?.value || '';
      const fullName = objName ? `${objName}.${propName}` : propName;
      return {
        calleeName: fullName || null,
        isMethodCall: true,
        objectName: objName || undefined,
        methodName: propName || undefined,
        isComputed,
      };
    }

    return { calleeName: null, isMethodCall: false, isComputed: false };
  }

  private detectRecursion() {
    // DFS cycle detection for both direct and mutual recursion
    const visited = new Set<string>();
    const recStack = new Set<string>();
    const cycleNodes = new Set<string>();

    const dfs = (fnName: string) => {
      visited.add(fnName);
      recStack.add(fnName);

      const fn = this.functions.get(fnName);
      if (fn) {
        for (const call of fn.calls) {
          const target = this.resolveCallee(call.calleeName);
          if (target) {
            const targetName = target.name;
            if (recStack.has(targetName)) {
              // Found cycle! All nodes currently on recStack from targetName onwards are recursive
              cycleNodes.add(fnName);
              cycleNodes.add(targetName);
            } else if (!visited.has(targetName)) {
              dfs(targetName);
            }
          }
        }
      }

      recStack.delete(fnName);
    };

    for (const name of this.functions.keys()) {
      if (!visited.has(name)) {
        dfs(name);
      }
    }

    for (const [name, fn] of this.functions.entries()) {
      if (cycleNodes.has(name)) {
        fn.isRecursive = true;
      }
    }
  }

  public resolveCallee(calleeName: string): FunctionSummary | undefined {
    if (!calleeName) return undefined;

    // 1. Direct function match or exact qualified method match ("obj.method" or "Class.method")
    const direct = this.functions.get(calleeName);
    if (direct) return direct;

    // 2. Check alias map
    const aliased = this.aliases.get(calleeName);
    if (aliased) {
      const target = this.functions.get(aliased);
      if (target) return target;
    }

    // 3. Qualified method call "receiver.method"
    if (calleeName.includes('.')) {
      const [obj, method] = calleeName.split('.');
      const qualified = `${obj}.${method}`;
      const exactQualified = this.functions.get(qualified);
      if (exactQualified) return exactQualified;

      // Check if method alone is unique across all registered functions (non-ambiguous check)
      const matchingFunctions: FunctionSummary[] = [];
      for (const [key, fn] of this.functions.entries()) {
        if (key === method || key.endsWith(`.${method}`)) {
          matchingFunctions.push(fn);
        }
      }

      // If exactly one function matches this method name globally, and it has no conflicting receiver, use it.
      // Otherwise, if ambiguous (multiple objects define the same method name), do NOT select arbitrarily.
      if (matchingFunctions.length === 1) {
        return matchingFunctions[0];
      }
      return undefined;
    }

    return undefined;
  }

  public getFunction(name: string): FunctionSummary | undefined {
    return this.resolveCallee(name);
  }
}
