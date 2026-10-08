import { ASTNode, CFGNode, CFGEdge, ControlFlowGraph } from '../ast/types';

export function buildControlFlowGraph(ast: ASTNode | null): ControlFlowGraph {
  const nodes: CFGNode[] = [];
  const edges: CFGEdge[] = [];
  let blockCounter = 1;
  let edgeCounter = 1;

  function addEdge(from: string, to: string, label?: 'true' | 'false' | 'always' | 'exception') {
    const edgeId = `e-${edgeCounter++}`;
    edges.push({ id: edgeId, from, to, label });

    const fromNode = nodes.find(n => n.id === from);
    const toNode = nodes.find(n => n.id === to);
    if (fromNode) fromNode.outgoingEdges.push(to);
    if (toNode) toNode.incomingEdges.push(from);
  }

  function createNode(
    label: string, 
    type: CFGNode['type'], 
    line?: number, 
    codeSnippet?: string
  ): CFGNode {
    const id = `blk-${blockCounter++}`;
    const node: CFGNode = {
      id,
      label,
      type,
      line,
      codeSnippet,
      incomingEdges: [],
      outgoingEdges: [],
      isReachable: false,
    };
    nodes.push(node);
    return node;
  }

  // 1. Entry Block
  const entryNode = createNode('ENTRY', 'entry');

  // Extract all statements across root Program and inner Function bodies
  function collectStatements(node: any): ASTNode[] {
    if (!node) return [];
    if (Array.isArray(node.body)) {
      const result: ASTNode[] = [];
      for (const stmt of node.body) {
        if (stmt.type === 'FunctionDeclaration' && stmt.body?.body) {
          result.push(stmt);
          result.push(...collectStatements(stmt.body));
        } else {
          result.push(stmt);
        }
      }
      return result;
    }
    return [];
  }

  const statements = collectStatements(ast);

  let currentBlockId = entryNode.id;
  let hasTerminated = false;

  for (let i = 0; i < statements.length; i++) {
    const stmt = statements[i];
    const line = stmt.loc?.start?.line;

    if (stmt.type === 'IfStatement') {
      const conditionNode = createNode(
        `IF (L${line || i + 1})`,
        'branch',
        line,
        'if condition'
      );
      if (!hasTerminated) {
        addEdge(currentBlockId, conditionNode.id, 'always');
      }

      const thenNode = createNode(`THEN (L${line})`, 'statement', line, 'consequent block');
      addEdge(conditionNode.id, thenNode.id, 'true');

      let elseNode: CFGNode | null = null;
      if (stmt.alternate) {
        elseNode = createNode(`ELSE (L${line})`, 'statement', line, 'alternate block');
        addEdge(conditionNode.id, elseNode.id, 'false');
      }

      const joinNode = createNode(`JOIN_IF (L${line})`, 'statement', line);
      addEdge(thenNode.id, joinNode.id, 'always');
      if (elseNode) {
        addEdge(elseNode.id, joinNode.id, 'always');
      } else {
        addEdge(conditionNode.id, joinNode.id, 'false');
      }

      currentBlockId = joinNode.id;
      hasTerminated = false;
    } else if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement' || stmt.type === 'ForOfStatement') {
      const loopHeader = createNode(`LOOP_HEADER (L${line})`, 'loop', line, 'loop condition');
      if (!hasTerminated) {
        addEdge(currentBlockId, loopHeader.id, 'always');
      }

      const loopBody = createNode(`LOOP_BODY (L${line})`, 'statement', line, 'loop body');
      addEdge(loopHeader.id, loopBody.id, 'true');
      addEdge(loopBody.id, loopHeader.id, 'always');

      const loopExit = createNode(`LOOP_EXIT (L${line})`, 'statement', line);
      addEdge(loopHeader.id, loopExit.id, 'false');

      currentBlockId = loopExit.id;
      hasTerminated = false;
    } else if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement') {
      const termNode = createNode(
        `${stmt.type === 'ReturnStatement' ? 'RETURN' : 'THROW'} (L${line})`,
        'statement',
        line,
        stmt.type === 'ReturnStatement' ? 'return' : 'throw'
      );
      if (!hasTerminated) {
        addEdge(currentBlockId, termNode.id, 'always');
      }
      currentBlockId = termNode.id;
      // Mark terminated: any next statements without a jump target are dead code!
      hasTerminated = true;
    } else {
      const name = stmt.type.replace('Statement', '').replace('Declaration', '');
      const stmtNode = createNode(`${name} (L${line || i + 1})`, 'statement', line);
      if (!hasTerminated) {
        addEdge(currentBlockId, stmtNode.id, 'always');
        currentBlockId = stmtNode.id;
      } else {
        // Unreachable statement! Not linked from current terminated block
        // It stays disconnected or orphaned
      }
    }
  }

  // Create Exit block
  const exitNode = createNode('EXIT', 'exit');
  if (!hasTerminated) {
    addEdge(currentBlockId, exitNode.id, 'always');
  }

  // Reachability Analysis (BFS from Entry)
  const reachableSet = new Set<string>();
  const queue: string[] = [entryNode.id];
  reachableSet.add(entryNode.id);

  while (queue.length > 0) {
    const currId = queue.shift()!;
    const currNode = nodes.find(n => n.id === currId);
    if (!currNode) continue;
    currNode.isReachable = true;

    for (const nextId of currNode.outgoingEdges) {
      if (!reachableSet.has(nextId)) {
        reachableSet.add(nextId);
        queue.push(nextId);
      }
    }
  }

  const deadCodeBlocks = nodes.filter(n => !n.isReachable && n.type !== 'exit');

  // McCabe Cyclomatic Complexity: M = E - N + 2P
  const E = edges.length;
  const N = nodes.length;
  const P = 1;
  const cyclomaticComplexity = Math.max(1, E - N + 2 * P);

  return {
    nodes,
    edges,
    cyclomaticComplexity,
    deadCodeBlocks,
  };
}
