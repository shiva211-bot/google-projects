import { INTERPROCEDURAL_CORPUS, InterproceduralTestCase } from './interproceduralCorpus';
import { parseSourceCode } from '../ast/parser';
import { runFlowSensitiveInterproceduralAnalysis } from './interproceduralTaint';
import { 
  InterproceduralTaintVulnerability, 
  InterproceduralPathStep,
  AnalysisConvergenceStatus,
  InterproceduralStepType
} from './types';

export interface InterproceduralTestResult {
  testId: string;
  testName: string;
  category: InterproceduralTestCase['category'];
  description: string;
  passed: boolean;
  actualVulnerable: boolean;
  actualSanitized: boolean;
  stepsCount: number;
  detectedVulnerabilities: InterproceduralTaintVulnerability[];
  tracePath: InterproceduralPathStep[];
  actualPathSequence: InterproceduralStepType[];
  expectedPathSequence?: InterproceduralStepType[];
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
    const analysisRes = runFlowSensitiveInterproceduralAnalysis(parseRes.ast, `${testCase.id}.js`);
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

    // Check 3: Minimum path step count
    if (testPassed && testCase.expectedMinSteps && primaryVuln) {
      if (tracePath.length < testCase.expectedMinSteps) {
        testPassed = false;
        failureReason = `Step count insufficient: Expected at least ${testCase.expectedMinSteps} path steps, but trace had ${tracePath.length}`;
      }
    }

    // Check 4: Rigorous Path Sequence Validation (CRITICAL / HIGH 4 FIX)
    if (testPassed && testCase.expectedPathSequence && primaryVuln) {
      const expected = testCase.expectedPathSequence;
      const sequenceMatches = actualPathSequence.length === expected.length &&
        actualPathSequence.every((val, idx) => val === expected[idx]);

      if (!sequenceMatches) {
        testPassed = false;
        failureReason = `Path sequence mismatch: Expected [${expected.join(' → ')}], but got [${actualPathSequence.join(' → ')}]`;
      }
    }

    if (testPassed) {
      passedCount++;
    }

    results.push({
      testId: testCase.id,
      testName: testCase.name,
      category: testCase.category,
      description: testCase.description,
      passed: testPassed,
      actualVulnerable,
      actualSanitized,
      stepsCount: tracePath.length,
      detectedVulnerabilities: vulns,
      tracePath,
      actualPathSequence,
      expectedPathSequence: testCase.expectedPathSequence,
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
