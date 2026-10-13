import React from 'react';

export const SAMPLES = [
  {
    label: 'Ordinary',
    url: 'https://campus.example/notices/lab-3'
  },
  {
    label: '@ trick',
    url: 'https://campus.example@other.example/login'
  },
  {
    label: 'Lookalike',
    url: 'https://сampus.example/login' // Cyrillic 'с' (U+0441)
  },
  {
    label: 'Public IP',
    url: 'http://192.0.2.45/signin'
  },
  {
    label: 'Private IP',
    url: 'http://192.168.1.10/'
  },
  {
    label: 'Shortener',
    url: 'https://bit.ly/3abcXYZ'
  },
  {
    label: 'Safe: @ in query',
    url: 'https://portal.campus.example:8443/forms?contact=lab@campus.example'
  }
];

export default function ExampleChips({ onSelectSample }) {
  return (
    <div className="flex flex-col gap-2 pt-1">
      <span className="text-sm font-sans uppercase text-slate-400 font-semibold tracking-wider">
        Example Templates:
      </span>
      <div className="flex flex-wrap items-center gap-2" role="toolbar" aria-label="Sample link templates">
        {SAMPLES.map((sample) => (
          <button
            key={sample.label}
            type="button"
            onClick={() => onSelectSample(sample.url)}
            className="min-h-[44px] px-3.5 py-2 rounded-lg bg-surface-container text-on-surface hover:bg-surface-container-high hover:text-primary transition-all text-sm font-sans shrink-0 border border-slate-700/60 active:scale-95 cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary-container/40"
          >
            {sample.label}
          </button>
        ))}
      </div>
    </div>
  );
}
