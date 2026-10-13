import React, { useState } from 'react';
import { ChevronDownIcon, CheckIcon } from './icons';

const SEVERITY_ORDER = {
  suspicious: 1,
  review: 2,
  note: 3
};

function formatRuleReason(rule) {
  if (rule.id === 'standard-route') {
    return 'This link uses https. No deception signals were found in its structure.';
  }
  if (rule.id === 'insecure-scheme') {
    return 'This link uses http, not https, so data sent to it is not encrypted.';
  }
  return rule.reason;
}

function getSeverityChip(severity) {
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
}

export function getRuleBreakdown(rule) {
  const id = rule.id || '';
  const reason = rule.reason || '';

  // 1. Standard institutional safe route
  if (id === 'standard-route') {
    return {
      mechanism: 'Standard institutional domain route parsed with valid HTTPS protocol.',
      securityImpact: 'Connection is encrypted in transit and no deceptive structural anomalies were detected.'
    };
  }

  // 2. Insecure http
  if (id === 'insecure-scheme') {
    return {
      mechanism: 'Unencrypted HTTP scheme (http://) parsed instead of secure HTTPS.',
      securityImpact: 'Data sent to this link is not encrypted and can be intercepted or tampered with on public networks (Man-in-the-Middle).'
    };
  }

  // 3. Authority Routing Trap (@ trick)
  if (id === 'authority-routing-trap') {
    return {
      mechanism: 'URL authority contains userinfo text formatted like a domain name prior to the "@" delimiter.',
      securityImpact: 'Deceives users into believing they are visiting the domain before "@", while browsers secretly route to the host after "@".'
    };
  }

  // 4. Character substitution / Homoglyph / Lookalike
  if (id === 'character-substitution' || id === 'mixed-script-detection') {
    return {
      mechanism: 'Hostname contains visually confusing characters (homoglyphs) or mixed scripts imitating a protected domain.',
      securityImpact: 'Attackers register lookalike domains to mislead users into entering credentials on a spoofed destination.'
    };
  }

  // 5. Direct IP Host
  if (id === 'ip-host-detection') {
    return {
      mechanism: 'Host is a raw numerical public IP address rather than a registered, authenticated domain name.',
      securityImpact: 'Frequently used by attackers to host malicious payloads and evade domain-based reputation blocklists.'
    };
  }

  // 6. Obfuscated IP Host
  if (id === 'obfuscated-ip-host') {
    return {
      mechanism: 'Host uses hexadecimal, octal, or integer encoding to disguise an IP address.',
      securityImpact: 'Disguises destination address from basic URL filters while browsers decode and navigate to the numeric host.'
    };
  }

  // 7. Private IP Host
  if (id === 'private-ip-host') {
    return {
      mechanism: 'Host address falls within private RFC 1918 subnets, loopback, or link-local ranges.',
      securityImpact: 'Only accessible on internal local area networks; external links targeting private IPs may probe local intranet services.'
    };
  }

  // 8. URL Shortener
  if (id === 'destination-obfuscation') {
    return {
      mechanism: 'Hostname belongs to a known public URL shortening or redirection service.',
      securityImpact: 'Conceals the final destination URL and prevents offline structural risk analysis without opening the link.'
    };
  }

  // 9. Dangerous schemes (javascript, vbscript, data:html)
  if (id === 'dangerous-scheme-javascript' || id === 'dangerous-scheme-vbscript') {
    return {
      mechanism: 'Pseudo-protocol executes client-side script code directly in browser context.',
      securityImpact: 'Can execute arbitrary malicious scripts or steal local session tokens without standard cross-origin restrictions.'
    };
  }
  if (id === 'dangerous-scheme-data-html') {
    return {
      mechanism: 'Data URI embeds raw HTML and executable script payloads directly within the link string.',
      securityImpact: 'Can render phishing pages or exploit client vulnerabilities without connecting to an external server.'
    };
  }
  if (id === 'data-scheme') {
    return {
      mechanism: 'Data URI protocol packaging inline media or data payload without standard origin.',
      securityImpact: 'Payload cannot be verified against remote host reputation and origin identity is opaque.'
    };
  }

  // 10. External application schemes & Payloads
  if (id === 'local-file-scheme') {
    return {
      mechanism: 'Local file scheme (file://) targeting host device filesystem.',
      securityImpact: 'Attempts to read or trigger files on the local operating system rather than navigating the web.'
    };
  }
  if (id === 'payment-intent-scheme') {
    return {
      mechanism: 'Payment intent protocol (upi://) configured to launch external payment applications.',
      securityImpact: 'Directs the device to initiate financial transactions or fund transfers.'
    };
  }
  if (id === 'upi-claimed-name') {
    return {
      mechanism: 'Claimed display name parameter (pn) encoded within payment intent URI.',
      securityImpact: 'Display names in UPI QR codes are unverified creator-supplied strings. Banking systems route payments strictly by the Payee VPA address.'
    };
  }
  if (id === 'upi-prefilled-amount') {
    return {
      mechanism: 'Pre-populated transaction debit amount (am) declared in payment intent URI.',
      securityImpact: 'Attackers frequently pre-fill specific debit amounts on counterfeit posters to extract immediate unauthorized funds.'
    };
  }
  if (id === 'upi-transaction-note') {
    return {
      mechanism: 'Transaction note parameter (tn) embedded in UPI URI parameters.',
      securityImpact: 'Informational note supplied by requester to provide context or influence payer trust.'
    };
  }
  if (id === 'wifi-config-payload') {
    return {
      mechanism: 'MECARD-formatted string encoding network SSID and Wi-Fi connection credentials.',
      securityImpact: 'Prompts the device to associate with a local wireless network. Connecting to untrusted access points can expose device traffic.'
    };
  }
  if (id === 'wifi-open-network') {
    return {
      mechanism: 'Wi-Fi configuration specifies no encryption (nopass / open).',
      securityImpact: 'Data transmitted across open wireless networks is unencrypted and vulnerable to local eavesdropping and Evil Twin attacks.'
    };
  }
  if (id === 'wifi-security-protocol') {
    return {
      mechanism: 'Encrypted wireless authentication standard specified in configuration.',
      securityImpact: 'Device will negotiate encrypted over-the-air communication with the access point using pre-shared credentials.'
    };
  }
  if (id === 'wifi-hidden-network') {
    return {
      mechanism: 'Network SSID is flagged as hidden / non-broadcast.',
      securityImpact: 'Connecting to a hidden network causes client devices to broadcast probe requests revealing the network name.'
    };
  }
  if (id === 'non-executable-text') {
    return {
      mechanism: 'Plain UTF-8 text string without URLs, executable protocols, or system deep links.',
      securityImpact: 'Safe for local viewing and copying; cannot trigger browser navigation or execute device actions.'
    };
  }
  if (id === 'mail-handler-scheme') {
    return {
      mechanism: 'Mail handler scheme (mailto:) configured to launch local email client.',
      securityImpact: 'Opens pre-populated draft messages in external email applications rather than navigating.'
    };
  }

  // 11. Malformed link
  if (id === 'malformed-link') {
    return {
      mechanism: 'URI structure violates WHATWG/RFC specifications (invalid brackets, corrupt port, or illegal authority syntax).',
      securityImpact: 'Exploits discrepancies between security parsers and browser navigation engines, or indicates a broken attack payload.'
    };
  }

  // 12. Obfuscation flags (bidi, backslash, zero-width)
  if (id === 'bidi-override') {
    return {
      mechanism: 'Unicode bidirectional override characters (U+202E, etc.) reverse visual rendering of text.',
      securityImpact: 'Visually disguises malicious domains or extensions (e.g. making an executable appear like an image or safe link).'
    };
  }
  if (id === 'backslash-obfuscation') {
    return {
      mechanism: 'Backslash characters ("\\") used as delimiters within the link authority or path.',
      securityImpact: 'Exploits parser discrepancies where backend scanners and web browsers interpret path boundaries differently.'
    };
  }
  if (id === 'zero-width-character') {
    return {
      mechanism: 'Invisible zero-width characters (e.g. U+200B, U+FEFF) embedded within host or path text.',
      securityImpact: 'Used by attackers to defeat keyword filters and pattern-matching security scanners.'
    };
  }

  // 13. Authority Credentials
  if (id === 'userinfo-credentials') {
    return {
      mechanism: 'URL authority embeds user credentials prior to the host without domain syntax.',
      securityImpact: 'Transmits credentials in plaintext authority or obscures the actual hostname from casual inspection.'
    };
  }

  // 14. Parameter context check
  if (id === 'parameter-context-check') {
    return {
      mechanism: '"@" character is located inside the query parameters (?key=val@...) rather than the URL authority.',
      securityImpact: 'Browsers treat this as data rather than login credentials; no authority spoofing occurs.'
    };
  }

  // Default fallback for any unrecognized rule
  return {
    mechanism: reason || 'Pattern parsed during deterministic link structure evaluation.',
    securityImpact: rule.severity === 'suspicious'
      ? 'Deceptive structural pattern commonly associated with credential theft, spoofing, or filter evasion.'
      : rule.severity === 'review'
      ? 'Non-standard routing pattern requiring manual review or external network resolution.'
      : 'Structural attribute noted during link evaluation.'
  };
}

function SingleReasonCard({ rule }) {
  const [expanded, setExpanded] = useState(true);
  const ruleName = rule.name || rule.id.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  const { mechanism, securityImpact } = getRuleBreakdown(rule);

  return (
    <div className="bg-[#0c1729] border border-cyan-500/20 shadow-xl rounded-2xl overflow-hidden flex flex-col">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="p-5 sm:p-6 flex items-center justify-between gap-2 w-full text-left cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary-container/40 hover:bg-slate-900/40 transition-colors"
        aria-expanded={expanded}
      >
        <span className="text-sm font-bold text-on-surface">
          {ruleName}
        </span>
        <div className="flex items-center gap-3 shrink-0">
          {getSeverityChip(rule.severity)}
          <ChevronDownIcon
            className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${
              expanded ? 'rotate-180' : ''
            }`}
          />
        </div>
      </button>
      {expanded && (
        <div className="px-5 pb-5 sm:px-6 sm:pb-6 pt-0 flex flex-col gap-3.5 border-t border-slate-800/80 pt-3.5">
          <div className="flex flex-col gap-1">
            <span className="text-[11px] uppercase tracking-wider font-bold text-cyan-400 font-mono flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" aria-hidden="true" />
              Mechanism
            </span>
            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed break-words font-sans">
              {mechanism}
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <span className="text-[11px] uppercase tracking-wider font-bold font-mono flex items-center gap-1.5 text-slate-300">
              <span
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                  rule.severity?.toLowerCase() === 'suspicious'
                    ? 'bg-red-400'
                    : rule.severity?.toLowerCase() === 'review'
                    ? 'bg-amber-400'
                    : 'bg-emerald-400'
                }`}
                aria-hidden="true"
              />
              Security Impact
            </span>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed break-words font-sans">
              {securityImpact}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ReasonCard({ rules = [], passedRules = [] }) {
  const [passedOpen, setPassedOpen] = useState(false);

  const sortedRules = [...rules].sort((a, b) => {
    const rankA = SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 4;
    const rankB = SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 4;
    return rankA - rankB;
  });

  return (
    <div className="flex flex-col gap-4">
      {/* One card per fired rule, sorted most severe first, expanded by default */}
      {sortedRules.map((rule) => (
        <SingleReasonCard key={rule.id || rule.name} rule={rule} />
      ))}

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
