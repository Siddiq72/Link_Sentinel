import React from 'react';

export default function Footer() {
  return (
    <footer className="w-full border-t border-slate-800/80 bg-[#060b14] py-6 px-4 sm:px-6 mt-12 text-center">
      <p className="max-w-[1140px] mx-auto text-xs sm:text-sm text-slate-400 font-normal leading-relaxed">
        Detects structural deception in the link text. It does not judge domain reputation, compromised sites or where a shortened link leads.
      </p>
    </footer>
  );
}
