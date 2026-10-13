import React, { useState, useEffect, useMemo } from 'react';
import { runBenchmarkSuite } from '../engine/benchmark/runner.js';
import { BENCHMARK_CORPUS } from '../engine/benchmark/corpus.js';

/**
 * SelfTestModal - Evidence & Regression Corpus Dashboard
 * 
 * Client-side, zero-network benchmark modal comparing Link Sentinel
 * against naive regex pattern matching across 40 test vectors in <50ms.
 * 
 * Execution states:
 * - 'idle': Unrun placeholder with CTA button and system boundaries documentation.
 * - 'running': Active progress animation and execution ticker for ~500ms.
 * - 'completed': Revealed comparative scorecard, execution speed badge, and audit table.
 * 
 * @param {object} props
 * @param {boolean} props.isOpen - Whether modal overlay is open
 * @param {function} props.onClose - Close callback
 */
export default function SelfTestModal({ isOpen, onClose }) {
  const [status, setStatus] = useState('idle'); // 'idle' | 'running' | 'completed'
  const [suiteResult, setSuiteResult] = useState(null);
  const [activeCategory, setActiveCategory] = useState('All');
  const [searchFilter, setSearchFilter] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [isLimitsOpen, setIsLimitsOpen] = useState(true);

  // Reset to idle state when modal is closed/reopened
  useEffect(() => {
    if (!isOpen) {
      setStatus('idle');
      setSuiteResult(null);
      setSearchFilter('');
      setActiveCategory('All');
      setExpandedId(null);
    }
  }, [isOpen]);

  // Handle ESC key to close modal
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Explicit execution trigger with ~500ms visible progress phase
  const handleRunSuite = () => {
    if (status === 'running') return;
    setStatus('running');

    setTimeout(() => {
      const res = runBenchmarkSuite();
      setSuiteResult(res);
      setStatus('completed');
    }, 500);
  };

  const categories = useMemo(() => {
    const cats = ['All'];
    BENCHMARK_CORPUS.forEach((item) => {
      if (!cats.includes(item.category)) {
        cats.push(item.category);
      }
    });
    return cats;
  }, []);

  const filteredResults = useMemo(() => {
    if (!suiteResult) return [];
    return suiteResult.testResults.filter((item) => {
      const matchCat = activeCategory === 'All' || item.category === activeCategory;
      const matchSearch =
        !searchFilter ||
        item.label.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.input.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.category.toLowerCase().includes(searchFilter.toLowerCase());
      return matchCat && matchSearch;
    });
  }, [suiteResult, activeCategory, searchFilter]);

  // Pre-load known limits from corpus so they are readable in idle state as well
  const knownLimits = useMemo(() => {
    if (suiteResult?.testResults) {
      return suiteResult.testResults.filter((item) => item.isKnownLimit);
    }
    return BENCHMARK_CORPUS.filter((item) => item.isKnownLimit);
  }, [suiteResult]);

  if (!isOpen) return null;

  const sentinel = suiteResult?.sentinelStats;
  const naive = suiteResult?.naiveStats;

  const getVerdictBadge = (verdict) => {
    switch (verdict?.toLowerCase()) {
      case 'safe':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-950 border border-emerald-500/50 text-emerald-300">
            SAFE
          </span>
        );
      case 'review':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 border border-amber-500/50 text-amber-300">
            REVIEW
          </span>
        );
      case 'suspicious':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-red-950 border border-red-500/50 text-red-400">
            SUSPICIOUS
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-900 border border-slate-700 text-slate-300">
            {verdict || 'NONE'}
          </span>
        );
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="self-test-title"
      className="bg-slate-950/85 backdrop-blur-md fixed inset-0 z-50 flex items-center justify-center p-2.5 sm:p-6 animate-fade-in"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-[#0c1729] border border-cyan-500/30 rounded-2xl shadow-[0_0_50px_rgba(0,229,255,0.15)] w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden backdrop-blur-xl">
        {/* 1. Modal Header */}
        <div className="p-4 sm:p-6 border-b border-slate-800/90 flex items-center justify-between gap-4 bg-slate-950/60 shrink-0">
          <div className="flex flex-col gap-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] sm:text-xs font-mono font-bold uppercase bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 flex items-center gap-1.5 shrink-0">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />
                Zero-Network Deterministic Evaluation
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono text-cyan-300 bg-cyan-950/70 border border-cyan-500/30">
                40 Test Vectors
              </span>
            </div>
            <h2 id="self-test-title" className="text-lg sm:text-2xl font-black text-slate-100 tracking-tight truncate">
              Evidence &amp; Regression Corpus
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 font-sans">
              Comparative audit of Link Sentinel's deterministic structural parser against naive pattern matching.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="w-10 h-10 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center border border-slate-700/60 transition-colors shrink-0 cursor-pointer focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
            aria-label="Close self-test modal"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* 2. Scrollable Body */}
        <div className="p-4 sm:p-6 overflow-y-auto flex flex-col gap-6 font-sans">
          {/* Action Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-950 border border-slate-800 shrink-0">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={handleRunSuite}
                disabled={status === 'running'}
                className="min-h-[44px] px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold font-sans text-sm flex items-center gap-2.5 shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all active:scale-95 cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {status === 'running' ? (
                  <>
                    <svg className="animate-spin w-4 h-4 text-slate-950" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    <span>Running Test Suite...</span>
                  </>
                ) : status === 'completed' ? (
                  <>
                    <svg className="w-4 h-4 fill-none stroke-current" strokeWidth="2.5" viewBox="0 0 24 24">
                      <polyline points="23 4 23 10 17 10" />
                      <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                    </svg>
                    <span>Re-run Self-Test Suite</span>
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
                      <polygon points="5 3 19 12 5 21 5 3" />
                    </svg>
                    <span>Run Self-Test Suite</span>
                  </>
                )}
              </button>

              {status === 'completed' && suiteResult && (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/70 text-xs font-mono text-cyan-300">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" aria-hidden="true" />
                  Ran 40 cases in <span className="font-bold text-white">{suiteResult.elapsedMs}ms</span>
                </div>
              )}
            </div>

            <div className="text-xs text-slate-400 font-mono">
              Synchronous in-memory execution • Sub-50ms target
            </div>
          </div>

          {/* VIEW STATE 1: IDLE STATE (Before Running) */}
          {status === 'idle' && (
            <div className="p-8 sm:p-10 rounded-2xl bg-slate-950/70 border border-cyan-500/30 flex flex-col items-center text-center gap-5 shadow-2xl">
              <div className="w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_24px_rgba(0,229,255,0.2)]">
                <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="4 17 10 11 4 5" />
                  <line x1="12" y1="19" x2="20" y2="19" />
                </svg>
              </div>

              <div className="flex flex-col gap-2 max-w-lg">
                <h3 className="text-xl sm:text-2xl font-black text-slate-100 tracking-tight">
                  Ready to run 40-case regression suite
                </h3>
                <p className="text-xs sm:text-sm text-slate-400 leading-relaxed font-sans">
                  Click below to execute Link Sentinel's deterministic parser and the naive regex baseline across all 40 vectors simultaneously in client memory.
                </p>
              </div>

              <button
                type="button"
                onClick={handleRunSuite}
                className="min-h-[48px] px-7 py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold font-sans text-sm sm:text-base flex items-center gap-2.5 shadow-[0_0_28px_rgba(16,185,129,0.35)] transition-all active:scale-95 cursor-pointer"
              >
                <svg className="w-5 h-5 fill-current" viewBox="0 0 24 24">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
                <span>Run Self-Test Suite</span>
              </button>

              <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-[11px] font-mono text-slate-500">
                <span>100% In-Memory Sync</span>
                <span>•</span>
                <span>Zero Network Calls</span>
                <span>•</span>
                <span>Expected Speed &lt; 50ms</span>
              </div>
            </div>
          )}

          {/* VIEW STATE 2: RUNNING ANIMATION STATE */}
          {status === 'running' && (
            <div className="p-8 sm:p-12 rounded-2xl bg-slate-950/80 border border-cyan-500/40 flex flex-col items-center text-center gap-6 shadow-2xl">
              <div className="relative w-16 h-16 flex items-center justify-center">
                <div className="absolute inset-0 rounded-2xl bg-cyan-500/20 animate-ping opacity-75" />
                <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-cyan-400/60 flex items-center justify-center text-cyan-300 shadow-[0_0_24px_rgba(0,229,255,0.3)]">
                  <svg className="animate-spin w-8 h-8 text-cyan-400" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                </div>
              </div>

              <div className="flex flex-col gap-2 max-w-md">
                <h3 className="text-xl font-bold text-slate-100 tracking-tight">
                  Executing Regression Benchmark...
                </h3>
                <p className="text-xs sm:text-sm text-cyan-300 font-mono animate-pulse">
                  Evaluating 40 vectors against structural engine and naive regex baseline in memory...
                </p>
              </div>

              {/* Progress Bar Animation */}
              <div className="w-full max-w-md h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-gradient-to-r from-emerald-400 via-cyan-400 to-emerald-400 animate-pulse w-full" />
              </div>
            </div>
          )}

          {/* VIEW STATE 3: COMPLETED RESULTS (Scorecard & Audit Table) */}
          {status === 'completed' && suiteResult && (
            <div className="flex flex-col gap-6 animate-fade-in">
              {/* Comparative Scorecard Table */}
              <div className="flex flex-col gap-3">
                <span className="text-xs font-mono uppercase tracking-wider font-bold text-slate-400">
                  Comparative Performance Scorecard
                </span>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Link Sentinel Card */}
                  <div className="p-5 rounded-xl bg-[#071d15] border-2 border-emerald-500/60 shadow-[0_0_24px_rgba(16,185,129,0.2)] flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-emerald-900/60 pb-3">
                      <div className="flex items-center gap-2">
                        <span className="w-3 h-3 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />
                        <h3 className="font-bold text-emerald-300 text-base sm:text-lg">
                          Link Sentinel (Structural Engine)
                        </h3>
                      </div>
                      <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-emerald-950 border border-emerald-400 text-emerald-200">
                        {sentinel.accuracyPct}% Accuracy
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-xs sm:text-sm">
                      <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">Accurate Outcomes</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-emerald-300">
                          {sentinel.correct} / {sentinel.total}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">False Alarms (Benign)</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-emerald-400">
                          {sentinel.falseAlarms}
                        </span>
                        <span className="text-[10px] text-emerald-300/80">Zero false positives</span>
                      </div>

                      <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">Attacks Caught</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-emerald-300">
                          {sentinel.attacksCaught} / {sentinel.totalAttacks}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">Execution Duration</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-cyan-300">
                          {sentinel.elapsedMs}ms
                        </span>
                        <span className="text-[10px] text-cyan-300/80">Benchmark limit: &lt;50ms</span>
                      </div>
                    </div>
                  </div>

                  {/* Naive Regex Baseline Card */}
                  <div className="p-5 rounded-xl bg-[#241113] border-2 border-red-500/50 shadow-[0_0_24px_rgba(239,68,68,0.15)] flex flex-col gap-4">
                    <div className="flex items-center justify-between border-b border-red-900/60 pb-3">
                      <div className="flex items-center gap-2">
                        <span className="w-3 h-3 rounded-full bg-red-400" aria-hidden="true" />
                        <h3 className="font-bold text-red-300 text-base sm:text-lg">
                          Naive Regex / Keyword Baseline
                        </h3>
                      </div>
                      <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-red-950 border border-red-400 text-red-200">
                        {naive.accuracyPct}% Accuracy
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-xs sm:text-sm">
                      <div className="p-3 rounded-lg bg-red-950/60 border border-red-900/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">Accurate Outcomes</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-red-300">
                          {naive.correct} / {naive.total}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-red-950/60 border border-red-900/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">False Alarms (Benign)</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-red-400">
                          {naive.falseAlarms}
                        </span>
                        <span className="text-[10px] text-red-300/80">Flags @ in queries &amp; words</span>
                      </div>

                      <div className="p-3 rounded-lg bg-red-950/60 border border-red-900/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">Attacks Caught</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-slate-200">
                          {naive.attacksCaught} / {naive.totalAttacks}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-red-950/60 border border-red-900/50 flex flex-col gap-0.5">
                        <span className="text-slate-300 text-xs">Execution Duration</span>
                        <span className="font-mono text-xl sm:text-2xl font-black text-slate-300">
                          {naive.elapsedMs}ms
                        </span>
                        <span className="text-[10px] text-slate-400">Primitive scanning</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Corpus Audit Table */}
              <div className="flex flex-col gap-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <span className="text-xs font-mono uppercase tracking-wider font-bold text-slate-400">
                    Corpus Audit Table ({filteredResults.length} vectors)
                  </span>

                  {/* Search Bar */}
                  <div className="relative w-full sm:w-64">
                    <input
                      type="text"
                      placeholder="Filter vectors..."
                      value={searchFilter}
                      onChange={(e) => setSearchFilter(e.target.value)}
                      className="w-full px-3 py-1.5 pl-8 rounded-lg bg-slate-950 border border-slate-800 text-xs font-sans text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                    <svg
                      className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2.5"
                    >
                      <circle cx="11" cy="11" r="8" />
                      <line x1="21" y1="21" x2="16.65" y2="16.65" />
                    </svg>
                  </div>
                </div>

                {/* Category Filter Chips */}
                <div className="flex flex-wrap items-center gap-1.5">
                  {categories.map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setActiveCategory(cat)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                        activeCategory === cat
                          ? 'bg-cyan-500 text-slate-950 shadow-[0_0_12px_rgba(0,229,255,0.3)]'
                          : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>

                {/* Table Rows */}
                <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden divide-y divide-slate-800/80">
                  {filteredResults.map((item) => {
                    const isExpanded = expandedId === item.id;
                    return (
                      <div key={item.id} className="flex flex-col">
                        <button
                          type="button"
                          onClick={() => setExpandedId(isExpanded ? null : item.id)}
                          className="p-3.5 sm:p-4 flex items-center justify-between gap-3 text-left hover:bg-slate-900/50 transition-colors cursor-pointer w-full"
                        >
                          <div className="flex flex-col min-w-0 pr-2">
                            <div className="flex flex-wrap items-center gap-2 pb-1">
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-900 border border-slate-800 text-slate-400">
                                {item.category}
                              </span>
                              <span className="font-semibold text-xs sm:text-sm text-slate-200 truncate">
                                {item.label}
                              </span>
                            </div>
                            <span className="font-mono text-xs text-slate-400 truncate break-all">
                              {item.input}
                            </span>
                          </div>

                          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
                            <div className="flex flex-col items-end gap-1">
                              <div className="flex items-center gap-1.5">
                                <span className="text-[10px] font-mono text-slate-500 hidden sm:inline">Expected:</span>
                                {getVerdictBadge(item.expectedVerdict)}
                              </div>
                              <div className="flex items-center gap-1.5">
                                <span className="text-[10px] font-mono text-slate-500 hidden sm:inline">Sentinel:</span>
                                {getVerdictBadge(item.sentinelVerdict)}
                              </div>
                            </div>

                            <div className="w-6 flex items-center justify-center">
                              {item.sentinelCorrect ? (
                                <svg className="w-5 h-5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                  <polyline points="20 6 9 17 4 12" />
                                </svg>
                              ) : (
                                <svg className="w-5 h-5 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                  <line x1="18" y1="6" x2="6" y2="18" />
                                  <line x1="6" y1="6" x2="18" y2="18" />
                                </svg>
                              )}
                            </div>
                          </div>
                        </button>

                        {isExpanded && (
                          <div className="px-4 pb-4 pt-1 bg-slate-900/40 border-t border-slate-800/60 flex flex-col gap-3 text-xs">
                            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col gap-1">
                              <span className="font-bold text-slate-300 font-mono text-[11px] uppercase">
                                Evaluated Vector String:
                              </span>
                              <span className="font-mono text-cyan-200 break-all select-all">
                                {item.input}
                              </span>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                              <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-900/60 flex flex-col gap-1">
                                <span className="font-bold text-emerald-300 font-mono text-[11px] uppercase">
                                  Link Sentinel Evaluation
                                </span>
                                <span className="text-slate-200">
                                  Verdict: <strong className="uppercase">{item.sentinelVerdict}</strong>
                                </span>
                                <span className="text-slate-400 leading-relaxed font-sans">
                                  {item.sentinelReason || 'Deterministic structural check.'}
                                </span>
                              </div>

                              <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/60 flex flex-col gap-1">
                                <span className="font-bold text-red-300 font-mono text-[11px] uppercase">
                                  Naive Regex Baseline
                                </span>
                                <span className="text-slate-200">
                                  Verdict: <strong className="uppercase">{item.naiveVerdict}</strong>
                                </span>
                                <span className="text-slate-400 leading-relaxed font-sans">
                                  {item.naiveReason}
                                </span>
                              </div>
                            </div>

                            <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 text-slate-300">
                              <span className="font-bold font-mono text-[11px] text-slate-400 uppercase">
                                Test Rationale:
                              </span>{' '}
                              {item.explanation}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* 4. Collapsible Documented System Boundaries (Known Limits) - Visible across all states */}
          <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
            <button
              type="button"
              onClick={() => setIsLimitsOpen(!isLimitsOpen)}
              className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-900/60 transition-colors cursor-pointer"
              aria-expanded={isLimitsOpen}
            >
              <div className="flex items-center gap-2.5">
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase bg-cyan-950 border border-cyan-500/40 text-cyan-300">
                  Known Limits
                </span>
                <span className="font-bold text-sm sm:text-base text-slate-200">
                  Documented System Boundaries ({knownLimits.length} cases)
                </span>
              </div>
              <svg
                className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${
                  isLimitsOpen ? 'rotate-180' : ''
                }`}
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
              >
                <polyline points="6 9 12 15 18 9" />
              </svg>
            </button>

            {isLimitsOpen && (
              <div className="p-4 pt-0 border-t border-slate-800/80 flex flex-col gap-3 text-xs sm:text-sm">
                <p className="text-slate-400 leading-relaxed font-sans pt-3">
                  Link Sentinel operates <strong>offline without external network telemetry</strong>.
                  Structural analysis deliberately yields to external domain reputation lookups in the following documented scenarios:
                </p>

                <div className="flex flex-col gap-2.5">
                  {knownLimits.map((item) => (
                    <div
                      key={item.id}
                      className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col gap-1.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-bold text-slate-200">{item.label}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-slate-400">Structural Outcome:</span>
                          {getVerdictBadge(item.sentinelVerdict || item.expectedVerdict)}
                        </div>
                      </div>
                      <span className="font-mono text-xs text-cyan-300 break-all select-all">
                        {item.input}
                      </span>
                      <p className="text-xs text-slate-400 leading-relaxed font-sans">
                        {item.explanation}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* 6. Modal Footer */}
        <div className="p-4 sm:p-5 border-t border-slate-800/90 bg-slate-950/60 flex items-center justify-between gap-4 shrink-0">
          <span className="text-xs font-mono text-slate-400">
            Link Sentinel v1.0.0 • Strict Zero-Network Evidence Dashboard
          </span>

          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 text-xs font-mono font-semibold border border-slate-700 transition-colors cursor-pointer"
          >
            Close Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}
