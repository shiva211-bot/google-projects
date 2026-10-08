import { BENCHMARK_CORPUS, TestCase } from './corpus';
import { executeTrueStaticAnalysis } from '../staticEngine';
import { TaintVulnerability } from '../ast/types';

export interface TestExecutionResult {
  testId: string;
  testName: string;
  category: TestCase['category'];
  expectedType: TestCase['expectedType'];
  passed: boolean;
  durationMs: number;
  assertionResults: {
    name: string;
    expected: string;
    actual: string;
    passed: boolean;
  }[];
  taintTraceVerified?: {
    sourceLine: number;
    sinkLine: number;
    stepsCount: number;
    stepsDescription: string[];
  };
  failureReason?: string;
}

export interface CorpusVerificationReport {
  timestamp: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  overallPassed: boolean;
  durationMs: number;
  metrics: {
    truePositives: number;
    trueNegatives: number;
    falsePositives: number;
    falseNegatives: number;
    precisionPercent: number;
    recallPercent: number;
    falsePositiveRatePercent: number;
    f1Score: number;
  };
  results: TestExecutionResult[];
}

export function runBenchmarkVerificationSuite(): CorpusVerificationReport {
  const suiteStartTime = performance.now();
  const results: TestExecutionResult[] = [];

  let tpCount = 0;
  let tnCount = 0;
  let fpCount = 0;
  let fnCount = 0;

  for (const test of BENCHMARK_CORPUS) {
    const testStart = performance.now();
    const { analysis, engineData } = executeTrueStaticAnalysis(test.code, test.language, `${test.id}.js`);
    const testDuration = Number((performance.now() - testStart).toFixed(2));

    const assertions: TestExecutionResult['assertionResults'] = [];
    let testPassed = true;
    let failureReason: string | undefined = undefined;
    let taintTraceVerified: TestExecutionResult['taintTraceVerified'] = undefined;

    // 1. RULE VIOLATION CHECK (True Positive vs True Negative)
    if (test.assertions.ruleId) {
      const targetRule = engineData.ruleResults.find(r => r.ruleId === test.assertions.ruleId);
      const isViolated = targetRule ? !targetRule.passed : false;
      const expectedViolated = Boolean(test.assertions.shouldViolate);

      const ruleAssertPassed = isViolated === expectedViolated;
      assertions.push({
        name: `Rule ${test.assertions.ruleId} violation status`,
        expected: expectedViolated ? 'VIOLATED' : 'PASSED (Clean)',
        actual: isViolated ? 'VIOLATED' : 'PASSED (Clean)',
        passed: ruleAssertPassed,
      });

      if (!ruleAssertPassed) {
        testPassed = false;
        failureReason = `Expected rule ${test.assertions.ruleId} to be ${expectedViolated ? 'violated' : 'clean'}, but got ${isViolated ? 'violated' : 'clean'}`;
      }

      // Track Confusion Matrix
      if (test.expectedType === 'true_positive') {
        if (isViolated) tpCount++;
        else fnCount++;
      } else if (test.expectedType === 'true_negative') {
        if (!isViolated) tnCount++;
        else fpCount++;
      }
    }

    // 2. COMPLETE TAINT PATH VERIFICATION
    if (test.assertions.expectedTaintType) {
      const matchTaint = engineData.taintVulnerabilities.find(
        tv => tv.vulnerabilityType === test.assertions.expectedTaintType
      );

      const taintFound = Boolean(matchTaint);
      assertions.push({
        name: `Taint type: ${test.assertions.expectedTaintType}`,
        expected: 'FOUND',
        actual: taintFound ? 'FOUND' : 'MISSING',
        passed: taintFound,
      });

      if (!matchTaint) {
        testPassed = false;
        failureReason = `Expected taint vulnerability ${test.assertions.expectedTaintType} not found in AST.`;
      } else {
        // Verify Complete Path (Source line, Sink line, Steps count)
        if (test.assertions.expectedSourceLine) {
          const srcLinePassed = matchTaint.sourceLine === test.assertions.expectedSourceLine;
          assertions.push({
            name: 'Taint Source Line',
            expected: `Line ${test.assertions.expectedSourceLine}`,
            actual: `Line ${matchTaint.sourceLine}`,
            passed: srcLinePassed,
          });
          if (!srcLinePassed) testPassed = false;
        }

        if (test.assertions.expectedSinkLine) {
          const sinkLinePassed = matchTaint.sinkLine === test.assertions.expectedSinkLine;
          assertions.push({
            name: 'Taint Sink Line',
            expected: `Line ${test.assertions.expectedSinkLine}`,
            actual: `Line ${matchTaint.sinkLine}`,
            passed: sinkLinePassed,
          });
          if (!sinkLinePassed) testPassed = false;
        }

        if (test.assertions.expectedTaintStepsCount) {
          const stepsCountPassed = matchTaint.taintPath.length === test.assertions.expectedTaintStepsCount;
          assertions.push({
            name: 'Complete Path Steps Count',
            expected: `${test.assertions.expectedTaintStepsCount} steps (source -> prop -> sink)`,
            actual: `${matchTaint.taintPath.length} steps`,
            passed: stepsCountPassed,
          });
          if (!stepsCountPassed) testPassed = false;
        }

        taintTraceVerified = {
          sourceLine: matchTaint.sourceLine,
          sinkLine: matchTaint.sinkLine,
          stepsCount: matchTaint.taintPath.length,
          stepsDescription: matchTaint.taintPath.map(p => `[L${p.line} ${p.type.toUpperCase()}]: ${p.description}`),
        };
      }
    }

    // 3. CFG CORRECTNESS VERIFICATION
    if (test.assertions.expectedCyclomaticComplexity !== undefined) {
      const actualComplexity = engineData.cfg.cyclomaticComplexity;
      const complexityPassed = actualComplexity === test.assertions.expectedCyclomaticComplexity;

      assertions.push({
        name: 'CFG Cyclomatic Complexity (M = E - N + 2P)',
        expected: `M = ${test.assertions.expectedCyclomaticComplexity}`,
        actual: `M = ${actualComplexity}`,
        passed: complexityPassed,
      });

      if (!complexityPassed) {
        testPassed = false;
        failureReason = `Expected CFG complexity ${test.assertions.expectedCyclomaticComplexity}, got ${actualComplexity}`;
      }
    }

    if (test.assertions.expectedDeadBlocksCount !== undefined) {
      const actualDead = engineData.cfg.deadCodeBlocks.length;
      const deadPassed = actualDead === test.assertions.expectedDeadBlocksCount;

      assertions.push({
        name: 'CFG Reachability Dead Blocks Count',
        expected: `${test.assertions.expectedDeadBlocksCount} dead blocks`,
        actual: `${actualDead} dead blocks`,
        passed: deadPassed,
      });

      if (!deadPassed) {
        testPassed = false;
        failureReason = `Expected ${test.assertions.expectedDeadBlocksCount} unreachable blocks, got ${actualDead}`;
      }
    }

    // 4. DETERMINISTIC HALSTEAD METRIC VERIFICATION
    if (test.assertions.expectedDistinctOperands !== undefined) {
      const actualOperands = engineData.halstead.distinctOperands;
      const opPassed = actualOperands === test.assertions.expectedDistinctOperands;

      assertions.push({
        name: 'Halstead Distinct Operands (η2)',
        expected: `η2 = ${test.assertions.expectedDistinctOperands}`,
        actual: `η2 = ${actualOperands}`,
        passed: opPassed,
      });
      if (!opPassed) testPassed = false;
    }

    if (test.assertions.expectedVocabulary !== undefined) {
      const actualVocab = engineData.halstead.vocabulary;
      const vocabPassed = actualVocab === test.assertions.expectedVocabulary;

      assertions.push({
        name: 'Halstead Total Vocabulary (η = η1 + η2)',
        expected: `η = ${test.assertions.expectedVocabulary}`,
        actual: `η = ${actualVocab}`,
        passed: vocabPassed,
      });
      if (!vocabPassed) testPassed = false;
    }

    if (test.assertions.minMaintainabilityIndex !== undefined) {
      const actualMI = engineData.maintainabilityIndex;
      const miPassed = actualMI >= test.assertions.minMaintainabilityIndex && actualMI <= (test.assertions.maxMaintainabilityIndex || 100);

      assertions.push({
        name: 'Deterministic SEI Maintainability Index Bounds',
        expected: `${test.assertions.minMaintainabilityIndex} <= MI <= ${test.assertions.maxMaintainabilityIndex || 100}`,
        actual: `MI = ${actualMI}`,
        passed: miPassed,
      });
      if (!miPassed) testPassed = false;
    }

    results.push({
      testId: test.id,
      testName: test.name,
      category: test.category,
      expectedType: test.expectedType,
      passed: testPassed,
      durationMs: testDuration,
      assertionResults: assertions,
      taintTraceVerified,
      failureReason,
    });
  }

  const passedCount = results.filter(r => r.passed).length;
  const failedCount = results.length - passedCount;

  // Calculate Precision, Recall, False Positive Rate, F1
  const precision = tpCount + fpCount > 0 ? (tpCount / (tpCount + fpCount)) * 100 : 100;
  const recall = tpCount + fnCount > 0 ? (tpCount / (tpCount + fnCount)) * 100 : 100;
  const fpr = tnCount + fpCount > 0 ? (fpCount / (tnCount + fpCount)) * 100 : 0;
  const f1 = (precision + recall) > 0 ? 2 * ((precision * recall) / (precision + recall)) / 100 : 1;

  const suiteDuration = Number((performance.now() - suiteStartTime).toFixed(2));

  return {
    timestamp: new Date().toISOString(),
    totalTests: results.length,
    passedTests: passedCount,
    failedTests: failedCount,
    overallPassed: failedCount === 0,
    durationMs: suiteDuration,
    metrics: {
      truePositives: tpCount,
      trueNegatives: tnCount,
      falsePositives: fpCount,
      falseNegatives: fnCount,
      precisionPercent: Number(precision.toFixed(1)),
      recallPercent: Number(recall.toFixed(1)),
      falsePositiveRatePercent: Number(fpr.toFixed(1)),
      f1Score: Number(f1.toFixed(2)),
    },
    results,
  };
}
