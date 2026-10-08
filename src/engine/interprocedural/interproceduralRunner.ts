import { INTERPROCEDURAL_CORPUS, InterproceduralTestCase } from './interproceduralCorpus';
import { parseSourceCode } from '../ast/parser';
import { performInterproceduralTaintAnalysis } from './interproceduralTaint';
import { InterproceduralTaintVulnerability, InterproceduralPathStep } from './types';

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
  failureReason?: string;
  durationMs: number;
}

export interface InterproceduralReport {
  timestamp: string;
  totalCases: number;
  passedCases: number;
  failedCases: number;
  detectionScorePercent: number;
  durationMs: number;
  results: InterproceduralTestResult[];
}

export function runInterproceduralVerificationSuite(): InterproceduralReport {
  const startTime = performance.now();
  const results: InterproceduralTestResult[] = [];
  let passedCount = 0;

  for (const testCase of INTERPROCEDURAL_CORPUS) {
    const testStart = performance.now();
    const parseRes = parseSourceCode(testCase.code, `${testCase.id}.js`);
    const vulns = performInterproceduralTaintAnalysis(parseRes.ast, `${testCase.id}.js`);
    const testDuration = Number((performance.now() - testStart).toFixed(2));

    const activeVulns = vulns.filter(v => !v.sanitized);
    const sanitizedVulns = vulns.filter(v => v.sanitized);

    const actualVulnerable = activeVulns.length > 0;
    const actualSanitized = sanitizedVulns.length > 0;

    let testPassed = true;
    let failureReason: string | undefined = undefined;

    // Check 1: Vulnerability classification
    if (actualVulnerable !== testCase.expectedVulnerable) {
      testPassed = false;
      failureReason = `Expected vulnerable = ${testCase.expectedVulnerable}, but got ${actualVulnerable} (active vulns: ${activeVulns.length}, sanitized: ${sanitizedVulns.length})`;
    }

    // Check 2: Sanitizer expectation
    if (testPassed && testCase.expectedSanitized !== undefined) {
      if (actualSanitized !== testCase.expectedSanitized) {
        testPassed = false;
        failureReason = `Expected sanitized = ${testCase.expectedSanitized}, but got ${actualSanitized}`;
      }
    }

    // Check 3: Minimum path step count
    const primaryVuln = activeVulns[0] || sanitizedVulns[0];
    const tracePath = primaryVuln ? primaryVuln.path : [];

    if (testPassed && testCase.expectedMinSteps && primaryVuln) {
      if (tracePath.length < testCase.expectedMinSteps) {
        testPassed = false;
        failureReason = `Expected at least ${testCase.expectedMinSteps} path steps, but trace had ${tracePath.length}`;
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
    durationMs,
    results,
  };
}
