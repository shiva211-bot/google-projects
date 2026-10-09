import { INTERPROCEDURAL_CORPUS, InterproceduralTestCase } from './interproceduralCorpus';
import { parseSourceCode } from '../ast/parser';
import { runFlowSensitiveInterproceduralAnalysis } from './interproceduralTaint';
import { 
  InterproceduralTaintVulnerability, 
  InterproceduralPathStep,
  AnalysisConvergenceStatus,
  InterproceduralStepType,
  VulnerabilityConfidence,
  FinalVariableState
} from './types';

export interface InterproceduralTestResult {
  testId: string;
  testName: string;
  category: InterproceduralTestCase['category'];
  description: string;
  passed: boolean;
  actualVulnerable: boolean;
  actualSanitized: boolean;
  actualConfidence?: VulnerabilityConfidence;
  verificationMode: 'EXACT_TRACE' | 'STATE_AND_ABSENCE';
  stepsCount: number;
  detectedVulnerabilities: InterproceduralTaintVulnerability[];
  tracePath: InterproceduralPathStep[];
  actualPathSequence: InterproceduralStepType[];
  expectedPathSequence?: InterproceduralStepType[];
  finalVariables: Record<string, FinalVariableState>;
  expectedPostState?: Record<string, { isTainted: boolean; sanitized?: boolean }>;
  dataFlowStateVerified: boolean;
  pathSequenceVerified: boolean;
  failureReason?: string;
  durationMs: number;
}

export interface InterproceduralReport {
  timestamp: string;
  totalCases: number;
  passedCases: number;
  failedCases: number;
  detectionScorePercent: number;
  status: AnalysisConvergenceStatus;
  converged: boolean;
  totalStepsEvaluated: number;
  unresolvedCallsTotal: number;
  durationMs: number;
  results: InterproceduralTestResult[];
}

export function runInterproceduralVerificationSuite(): InterproceduralReport {
  const startTime = performance.now();
  const results: InterproceduralTestResult[] = [];
  let passedCount = 0;
  let allConverged = true;
  let totalStepsEvaluated = 0;
  let unresolvedCallsTotal = 0;

  for (const testCase of INTERPROCEDURAL_CORPUS) {
    const testStart = performance.now();
    const parseRes = parseSourceCode(testCase.code, `${testCase.id}.js`);
    const analysisRes = runFlowSensitiveInterproceduralAnalysis(parseRes.ast, `${testCase.id}.js`, testCase.options);
    const testDuration = Number((performance.now() - testStart).toFixed(2));

    totalStepsEvaluated += analysisRes.flowSensitiveStepsEvaluated;
    unresolvedCallsTotal += analysisRes.unresolvedCallsCount;
    if (!analysisRes.converged) allConverged = false;

    const vulns = analysisRes.vulnerabilities;
    const activeVulns = vulns.filter(v => !v.sanitized);
    const sanitizedVulns = vulns.filter(v => v.sanitized);

    const actualVulnerable = activeVulns.length > 0;
    const actualSanitized = sanitizedVulns.length > 0;

    let testPassed = true;
    let failureReason: string | undefined = undefined;

    // Check 1: Vulnerability classification
    if (actualVulnerable !== testCase.expectedVulnerable) {
      testPassed = false;
      failureReason = `Classification mismatch: Expected vulnerable=${testCase.expectedVulnerable}, but got ${actualVulnerable} (active: ${activeVulns.length}, sanitized: ${sanitizedVulns.length})`;
    }

    // Check 2: Sanitizer expectation
    if (testPassed && testCase.expectedSanitized !== undefined) {
      if (actualSanitized !== testCase.expectedSanitized) {
        testPassed = false;
        failureReason = `Sanitizer status mismatch: Expected sanitized=${testCase.expectedSanitized}, but got ${actualSanitized}`;
      }
    }

    // Select primary trace
    const primaryVuln = activeVulns[0] || sanitizedVulns[0];
    const tracePath = primaryVuln ? primaryVuln.path : [];
    const actualPathSequence = tracePath.map(p => p.type);
    const actualConfidence = primaryVuln?.confidence;

    // Check 3: Confidence level matching (e.g. confirmed vs unresolved_flow)
    if (testPassed && testCase.expectedConfidence && primaryVuln) {
      if (primaryVuln.confidence !== testCase.expectedConfidence) {
        testPassed = false;
        failureReason = `Confidence level mismatch: Expected '${testCase.expectedConfidence}', but finding had '${primaryVuln.confidence}'`;
      }
    }

    // Check 4: Convergence status
    if (testPassed && testCase.expectedConvergenceStatus) {
      if (analysisRes.status !== testCase.expectedConvergenceStatus) {
        testPassed = false;
        failureReason = `Convergence status mismatch: Expected '${testCase.expectedConvergenceStatus}', but analysis returned '${analysisRes.status}'`;
      }
    }

    // Check 5: Minimum path step count
    if (testPassed && testCase.expectedMinSteps && primaryVuln) {
      if (tracePath.length < testCase.expectedMinSteps) {
        testPassed = false;
        failureReason = `Step count insufficient: Expected at least ${testCase.expectedMinSteps} path steps, but trace had ${tracePath.length}`;
      }
    }

    // Check 6: Rigorous Path Sequence Validation
    let pathSequenceVerified = true;
    if (testCase.expectedPathSequence !== undefined) {
      const expected = testCase.expectedPathSequence;
      if (expected.length === 0) {
        // Safe case expecting absence of trace
        if (actualPathSequence.length !== 0) {
          pathSequenceVerified = false;
          testPassed = false;
          failureReason = `Path trace expected to be empty for safe case, but trace had [${actualPathSequence.join(' → ')}]`;
        }
      } else {
        // Active or sanitized trace expected
        const sequenceMatches = actualPathSequence.length === expected.length &&
          actualPathSequence.every((val, idx) => val === expected[idx]);

        if (!sequenceMatches) {
          pathSequenceVerified = false;
          testPassed = false;
          failureReason = `Path sequence mismatch: Expected [${expected.join(' → ')}], but got [${actualPathSequence.join(' → ')}]`;
        }
      }
    }

    // Check 7: Post-Branch / Post-Execution Data-Flow State Assertion
    let dataFlowStateVerified = true;
    if (testPassed && testCase.expectedPostState) {
      for (const [varName, expectedState] of Object.entries(testCase.expectedPostState)) {
        const actualState = analysisRes.finalVariables[varName];

        if (!actualState) {
          // If expecting untainted and variable is not in finalVariables, it is untainted/clean
          if (expectedState.isTainted) {
            dataFlowStateVerified = false;
            testPassed = false;
            failureReason = `Post-state mismatch: Expected variable '${varName}' to be tainted=true, but variable was not found in environment`;
            break;
          }
        } else {
          if (actualState.isTainted !== expectedState.isTainted) {
            dataFlowStateVerified = false;
            testPassed = false;
            failureReason = `Post-state mismatch: Expected variable '${varName}' isTainted=${expectedState.isTainted}, but actual was ${actualState.isTainted}`;
            break;
          }

          if (expectedState.sanitized !== undefined && actualState.sanitized !== expectedState.sanitized) {
            dataFlowStateVerified = false;
            testPassed = false;
            failureReason = `Post-state mismatch: Expected variable '${varName}' sanitized=${expectedState.sanitized}, but actual was ${actualState.sanitized}`;
            break;
          }
        }
      }
    }

    if (testPassed) {
      passedCount++;
    }

    const verificationMode = primaryVuln ? 'EXACT_TRACE' : 'STATE_AND_ABSENCE';

    results.push({
      testId: testCase.id,
      testName: testCase.name,
      category: testCase.category,
      description: testCase.description,
      passed: testPassed,
      actualVulnerable,
      actualSanitized,
      actualConfidence,
      verificationMode,
      stepsCount: tracePath.length,
      detectedVulnerabilities: vulns,
      tracePath,
      actualPathSequence,
      expectedPathSequence: testCase.expectedPathSequence,
      finalVariables: analysisRes.finalVariables,
      expectedPostState: testCase.expectedPostState,
      dataFlowStateVerified,
      pathSequenceVerified,
      failureReason,
      durationMs: testDuration,
    });
  }

  const durationMs = Number((performance.now() - startTime).toFixed(2));
  const detectionScorePercent = Math.round((passedCount / Math.max(1, INTERPROCEDURAL_CORPUS.length)) * 100);

  return {
    timestamp: new Date().toISOString(),
    totalCases: INTERPROCEDURAL_CORPUS.length,
    passedCases: passedCount,
    failedCases: INTERPROCEDURAL_CORPUS.length - passedCount,
    detectionScorePercent,
    status: allConverged ? 'converged' : 'resource_limit_exceeded',
    converged: allConverged,
    totalStepsEvaluated,
    unresolvedCallsTotal,
    durationMs,
    results,
  };
}
