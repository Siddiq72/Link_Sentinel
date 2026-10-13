/**
 * LINK SENTINEL - SYNCHRONOUS BENCHMARK & REGRESSION RUNNER
 * 
 * Executes full 40-case comparative audit between Link Sentinel's deterministic
 * structural engine and the naive regex baseline.
 * 
 * Strict constraints:
 * - 100% synchronous client memory execution
 * - Zero network requests or background workers
 * - Sub-50ms execution profile
 */

import { analyze } from '../index.js';
import { BENCHMARK_CORPUS } from './corpus.js';
import { runNaiveCheck } from './naiveChecker.js';

/**
 * Runs the complete regression corpus benchmark synchronously.
 * 
 * @param {Array} [corpus=BENCHMARK_CORPUS] - Optional custom corpus array
 * @returns {object} Comparative evaluation metrics and detailed item results
 */
export function runBenchmarkSuite(corpus = BENCHMARK_CORPUS) {
  const t0 = performance.now();

  let sentinelCorrect = 0;
  let sentinelFalseAlarms = 0;
  let sentinelAttacksMissed = 0;
  let sentinelAttacksCaught = 0;

  let naiveCorrect = 0;
  let naiveFalseAlarms = 0;
  let naiveAttacksMissed = 0;
  let naiveAttacksCaught = 0;

  const testResults = [];

  for (const item of corpus) {
    // 1. Evaluate Link Sentinel
    const sentinelStart = performance.now();
    let sentinelVerdict = 'error';
    let sentinelReason = '';
    try {
      const res = analyze(item.input);
      sentinelVerdict = res.verdict;
      sentinelReason = res.primaryReason?.text || res.rules?.[0]?.reason || '';
    } catch (err) {
      sentinelVerdict = 'error';
      sentinelReason = err.message;
    }
    const sentinelDuration = performance.now() - sentinelStart;

    // 2. Evaluate Naive Baseline
    const naiveStart = performance.now();
    const naiveRes = runNaiveCheck(item.input);
    const naiveVerdict = naiveRes.verdict;
    const naiveReason = naiveRes.triggerReason;
    const naiveDuration = performance.now() - naiveStart;

    // Compare with expectedVerdict
    const isSentinelMatch = sentinelVerdict === item.expectedVerdict;
    if (isSentinelMatch) {
      sentinelCorrect++;
    }

    // False alarms: Benign input flagged as suspicious
    if (item.expectedVerdict === 'safe' && sentinelVerdict === 'suspicious') {
      sentinelFalseAlarms++;
    }
    if (item.expectedVerdict === 'safe' && naiveVerdict === 'suspicious') {
      naiveFalseAlarms++;
    }

    // Attacks missed / caught (Structural Attack category)
    const isAttack = item.category === 'Structural Attack' || item.expectedVerdict === 'suspicious';
    if (isAttack) {
      if (sentinelVerdict === 'suspicious') {
        sentinelAttacksCaught++;
      } else {
        sentinelAttacksMissed++;
      }

      if (naiveVerdict === 'suspicious') {
        naiveAttacksCaught++;
      } else {
        naiveAttacksMissed++;
      }
    }

    // Naive correctness: exact match with expectedVerdict
    const isNaiveMatch = naiveVerdict === item.expectedVerdict;
    if (isNaiveMatch) {
      naiveCorrect++;
    }

    testResults.push({
      id: item.id,
      input: item.input,
      category: item.category,
      label: item.label,
      expectedVerdict: item.expectedVerdict,
      isKnownLimit: Boolean(item.isKnownLimit),
      explanation: item.explanation,
      sentinelVerdict,
      sentinelReason,
      sentinelDuration,
      sentinelCorrect: isSentinelMatch,
      naiveVerdict,
      naiveReason,
      naiveDuration,
      naiveCorrect: isNaiveMatch
    });
  }

  const elapsedMs = Math.round((performance.now() - t0) * 10) / 10;
  const total = corpus.length;

  const totalAttacks = corpus.filter(
    (c) => c.category === 'Structural Attack' || c.expectedVerdict === 'suspicious'
  ).length;

  const sentinelStats = {
    total,
    correct: sentinelCorrect,
    accuracyPct: Math.round((sentinelCorrect / total) * 100),
    falseAlarms: sentinelFalseAlarms,
    attacksCaught: sentinelAttacksCaught,
    totalAttacks,
    attacksMissed: sentinelAttacksMissed,
    elapsedMs
  };

  const naiveStats = {
    total,
    correct: naiveCorrect,
    accuracyPct: Math.round((naiveCorrect / total) * 100),
    falseAlarms: naiveFalseAlarms,
    attacksCaught: naiveAttacksCaught,
    totalAttacks,
    attacksMissed: naiveAttacksMissed,
    elapsedMs
  };

  return {
    sentinelStats,
    naiveStats,
    testResults,
    elapsedMs
  };
}

export default runBenchmarkSuite;
