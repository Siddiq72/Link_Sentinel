import { describe, it, expect } from 'vitest';
import { BENCHMARK_CORPUS } from '../src/engine/benchmark/corpus.js';
import { runNaiveCheck } from '../src/engine/benchmark/naiveChecker.js';
import { runBenchmarkSuite } from '../src/engine/benchmark/runner.js';
import { analyze } from '../src/engine/index.js';

describe('Evidence & Regression Benchmark Corpus Integrity', () => {
  it('contains exactly 40 categorized test items', () => {
    expect(BENCHMARK_CORPUS).toHaveLength(40);
  });

  it('validates schema requirements for all 40 items', () => {
    const validVerdicts = ['safe', 'review', 'suspicious'];
    const validCategories = [
      'Benign Complex',
      'Structural Attack',
      'Review Class',
      'Non-URL Payload',
      'Known Limit'
    ];

    for (const item of BENCHMARK_CORPUS) {
      expect(item.id).toBeDefined();
      expect(typeof item.id).toBe('string');

      expect(item.input).toBeDefined();
      expect(typeof item.input).toBe('string');
      expect(item.input.trim().length).toBeGreaterThan(0);

      expect(validVerdicts).toContain(item.expectedVerdict);
      expect(validCategories).toContain(item.category);

      expect(item.label).toBeDefined();
      expect(typeof item.label).toBe('string');

      expect(item.explanation).toBeDefined();
      expect(typeof item.explanation).toBe('string');
      expect(item.explanation.length).toBeGreaterThan(10);
    }
  });

  it('verifies exact category breakdown', () => {
    const counts = {};
    for (const item of BENCHMARK_CORPUS) {
      counts[item.category] = (counts[item.category] || 0) + 1;
    }

    expect(counts['Benign Complex']).toBe(12);
    expect(counts['Structural Attack']).toBe(10);
    expect(counts['Review Class']).toBe(8);
    expect(counts['Non-URL Payload']).toBe(6);
    expect(counts['Known Limit']).toBe(4);
  });

  it('identifies exactly 4 documented known limits with isKnownLimit: true', () => {
    const limits = BENCHMARK_CORPUS.filter((item) => item.isKnownLimit);
    expect(limits).toHaveLength(4);
    for (const limit of limits) {
      expect(limit.category).toBe('Known Limit');
      expect(limit.explanation).toContain('reputation');
    }
  });
});

describe('Naive Baseline Screener Simulation', () => {
  it('flags occurrence of @ in query parameters as a false alarm', () => {
    const benignWithAt = 'https://portal.campus.example:8443/forms?contact=lab@campus.example';
    const naiveRes = runNaiveCheck(benignWithAt);
    expect(naiveRes.verdict).toBe('suspicious');
    expect(naiveRes.triggerReason).toContain('@');

    // Sentinel correctly evaluates as safe
    const sentinelRes = analyze(benignWithAt);
    expect(sentinelRes.verdict).toBe('safe');
  });

  it('flags keyword "security" or "canteen" as suspicious', () => {
    const res = runNaiveCheck('https://search.campus.example/results?q=security+seminar');
    expect(res.verdict).toBe('suspicious');
  });

  it('safely evaluates clean input without triggers', () => {
    const res = runNaiveCheck('https://campus.example/notices/lab-3');
    expect(res.verdict).toBe('safe');
  });
});

describe('Benchmark Suite Execution & Comparative Performance', () => {
  it('executes all 40 cases synchronously in < 50ms without throwing', () => {
    const res = runBenchmarkSuite();

    expect(res).toBeDefined();
    expect(res.testResults).toHaveLength(40);
    expect(res.elapsedMs).toBeLessThan(50);
  });

  it('asserts Link Sentinel produces 0 false alarms on all benign inputs', () => {
    const res = runBenchmarkSuite();
    expect(res.sentinelStats.falseAlarms).toBe(0);
  });

  it('asserts Link Sentinel catches 100% of structural attacks (10/10)', () => {
    const res = runBenchmarkSuite();
    expect(res.sentinelStats.attacksCaught).toBe(10);
    expect(res.sentinelStats.attacksMissed).toBe(0);
  });

  it('confirms Link Sentinel achieves 100% accuracy on structural expectations vs naive baseline', () => {
    const res = runBenchmarkSuite();
    expect(res.sentinelStats.accuracyPct).toBe(100);
    expect(res.naiveStats.falseAlarms).toBeGreaterThan(0);
    expect(res.sentinelStats.accuracyPct).toBeGreaterThan(res.naiveStats.accuracyPct);
  });
});
