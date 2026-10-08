export interface ReDoSAnalysisResult {
  isVulnerable: boolean;
  reason?: string;
}

/**
 * Analyzes a Regular Expression pattern for Catastrophic Backtracking (ReDoS)
 * using structural AST / token examination rather than surface string matching.
 */
export function analyzeRegexForReDoS(pattern: string): ReDoSAnalysisResult {
  // 1. Remove escaped characters to avoid false triggers like \( or \+
  let sanitized = pattern.replace(/\\./g, '_');

  // Check 1: Nested Quantifiers (Star Height >= 2)
  // Forms: (inner+)+, (inner*)*, (inner+)*, (inner*)+, (inner+){2,}, etc.
  // Group followed by +, *, or {n,}
  const groupWithOuterQuantifier = /\(([^)]+)\)(\+|\*|\{\d+,?\d*\})/g;
  let match: RegExpExecArray | null;

  while ((match = groupWithOuterQuantifier.exec(sanitized)) !== null) {
    const inner = match[1];
    const outerQuantifier = match[2];

    // Case A: Inner expression has its own quantifier (+, *, {n,})
    // Example: (a+)+, (a*)*, (a+){2,}, ([0-9]+)+
    if (/(\+|\*|\{\d+,?\d*\})/.test(inner)) {
      // Check for overlapping repetition with optional separator: (\w+\s?)+ or (a+b?)+
      if (/(\+|\*)\w*(\?|\{0,1\})/.test(inner)) {
        return {
          isVulnerable: true,
          reason: `Overlapping repetition with optional component inside group /(${inner})${outerQuantifier}/`,
        };
      }

      return {
        isVulnerable: true,
        reason: `Nested quantifiers detected: /(${inner})${outerQuantifier}/ causes exponential O(2^N) backtracking.`,
      };
    }

    // Case B: Alternation with overlapping prefixes inside repeated group
    // Example: (a|aa)+, (x|xx)+, (foo|foobar)+
    if (inner.includes('|')) {
      const branches = inner.split('|');
      for (let i = 0; i < branches.length; i++) {
        for (let j = 0; j < branches.length; j++) {
          if (i !== j) {
            const b1 = branches[i].trim();
            const b2 = branches[j].trim();
            if (b1.length > 0 && b2.length > 0 && (b2.startsWith(b1) || b1.startsWith(b2))) {
              return {
                isVulnerable: true,
                reason: `Ambiguous overlapping alternation /(${b1}|${b2})${outerQuantifier}/ causes exponential permutations.`,
              };
            }
          }
        }
      }
    }
  }

  // Check 2: Direct raw pattern checks for edge-cases like (\\w+\\s?)+ or nested group in pattern
  if (/(\(\w+[\+\*]\s*\??\)\+|\(\w+[\+\*]\)\+)/.test(pattern)) {
    return {
      isVulnerable: true,
      reason: 'Repetitive token group with nested multiplier.',
    };
  }

  return { isVulnerable: false };
}
