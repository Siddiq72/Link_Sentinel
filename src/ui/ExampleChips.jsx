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

export const PAYLOAD_SAMPLES = [
  {
    label: 'UPI Pay',
    url: 'upi://pay?pa=campus-canteen@oksbi&pn=Campus%20Canteen&am=250&cu=INR'
  },
  {
    label: 'Wi-Fi QR',
    url: 'WIFI:T:WPA;S:Campus_Guest_WiFi;P:Welcome2026;H:false;;'
  }
];

export const ALL_SAMPLES = [...SAMPLES, ...PAYLOAD_SAMPLES];

function getChipTheme(label) {
  if (['@ trick', 'Lookalike', 'Public IP'].includes(label)) {
    return {
      classes: 'border-rose-500/30 hover:border-rose-400 hover:bg-rose-950/30 text-rose-200',
      dot: 'bg-rose-400 shadow-[0_0_6px_rgba(251,113,133,0.5)]'
    };
  }
  if (['Ordinary', 'Safe: @ in query'].includes(label)) {
    return {
      classes: 'border-emerald-500/30 hover:border-emerald-400 hover:bg-emerald-950/30 text-emerald-200',
      dot: 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.5)]'
    };
  }
  return {
    classes: 'border-cyan-500/30 hover:border-cyan-400 hover:bg-cyan-950/30 text-cyan-200',
    dot: 'bg-cyan-400 shadow-[0_0_6px_rgba(34,211,238,0.5)]'
  };
}

export default function ExampleChips({ onSelectSample }) {
  return (
    <div className="flex flex-col gap-2 pt-1">
      <span className="text-sm font-sans uppercase text-slate-400 font-semibold tracking-wider">
        Example Templates:
      </span>
      <div className="flex flex-wrap items-center gap-2" role="toolbar" aria-label="Sample link templates">
        {ALL_SAMPLES.map((sample) => {
          const theme = getChipTheme(sample.label);
          return (
            <button
              key={sample.label}
              type="button"
              onClick={() => onSelectSample(sample.url)}
              className={`min-h-[44px] px-3.5 py-1.5 rounded-full bg-slate-900/80 border ${theme.classes} transition-all duration-150 text-xs sm:text-sm font-sans shrink-0 active:scale-95 cursor-pointer focus:outline-none focus:ring-2 focus:ring-cyan-500/30 flex items-center gap-2 shadow-sm`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${theme.dot} shrink-0`} aria-hidden="true" />
              <span>{sample.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

