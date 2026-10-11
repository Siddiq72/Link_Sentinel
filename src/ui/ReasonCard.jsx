import React, { useState } from 'react';
import { ChevronDownIcon, CheckIcon } from './icons';

export default function ReasonCard({ rules = [], passedRules = [] }) {
  const [passedOpen, setPassedOpen] = useState(false);

  const getSeverityChip = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'suspicious':
        return (
          <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-red-950 border border-red-500/50 text-red-400">
            Suspicious
          </span>
        );
      case 'review':
        return (
          <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 border border-amber-500/50 text-amber-300">
            Review
          </span>
        );
      case 'note':
      default:
        return (
          <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950 border border-cyan-500/40 text-cyan-300">
            Note
          </span>
        );
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* One card per fired rule */}
      {rules.map((rule) => {
        const ruleName = rule.name || rule.id.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
        return (
          <div
            key={rule.id || ruleName}
            className="bg-[#0c1729] border border-cyan-500/20 shadow-xl rounded-2xl p-5 sm:p-6 flex flex-col gap-3"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-bold text-on-surface">
                {ruleName}
              </span>
              {getSeverityChip(rule.severity)}
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              {rule.reason}
            </p>
          </div>
        );
      })}

      {/* Collapsible section for rules that passed */}
      {passedRules && passedRules.length > 0 && (
        <div className="rounded-xl bg-slate-950/70 border border-slate-800 overflow-hidden">
          <button
            type="button"
            onClick={() => setPassedOpen(!passedOpen)}
            className="w-full min-h-[44px] px-4 py-3 flex items-center justify-between text-left hover:bg-slate-900 transition-colors cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary-container/40"
            aria-expanded={passedOpen}
          >
            <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold">
              <CheckIcon className="w-4 h-4" />
              <span>Passed Checks ({passedRules.length} rules satisfied)</span>
            </div>
            <ChevronDownIcon
              className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${
                passedOpen ? 'rotate-180' : ''
              }`}
            />
          </button>

          {passedOpen && (
            <div className="px-4 pb-4 pt-1 flex flex-col gap-2.5 text-xs text-slate-400 border-t border-slate-800/80">
              {passedRules.map((check, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
                  <span>{check}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
