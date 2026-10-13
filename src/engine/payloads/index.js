/**
 * LINK SENTINEL - NON-URL PAYLOAD CLASSIFICATION MODULE
 * 
 * Offline, synchronous inspection and deconstruction of non-web QR codes:
 * - UPI payment intent strings (upi://pay?...)
 * - Wi-Fi network configuration barcodes (WIFI:...)
 * - Plain descriptive text payloads
 * 
 * Strict safety guarantees:
 * - Client-side only; zero network requests
 * - Does not route through WHATWG URL parser or heuristic URL guessing
 * - Returns null for standard web URLs so link screening proceeds unaffected
 */

import psl from 'psl';

/**
 * Checks whether an input contains any token that is a valid PSL domain or IP authority.
 * 
 * @param {string} text - Raw input string
 * @returns {boolean} True if any word token appears to be a web host or valid PSL domain
 */
function containsValidDomainOrIp(text) {
  const words = text.split(/\s+/);
  for (const rawWord of words) {
    const word = rawWord.replace(/^[^\w@/]+|[^\w@/]+$/g, '');
    if (!word || !word.includes('.')) continue;

    // IPv4 check
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?(\/.*)?$/.test(word)) {
      return true;
    }

    // Host candidate extraction
    const candidate = word.split(/[/?#:]/)[0].toLowerCase();
    if (candidate.includes('.')) {
      if (psl.isValid(candidate)) {
        return true;
      }
      const parsed = psl.parse(candidate);
      if (parsed && parsed.listed && parsed.tld) {
        return true;
      }
      if (candidate.endsWith('.example')) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Parses Wi-Fi MECARD barcode string format.
 * Format: WIFI:T:WPA;S:Network_SSID;P:password;H:false;;
 * 
 * @param {string} raw - Raw Wi-Fi string starting with WIFI:
 * @returns {object} Parsed fields { ssid, security, password, hidden }
 */
export function parseWifiMecard(raw) {
  const payload = raw.slice(5); // strip leading 'WIFI:'
  let current = '';
  let isEscaped = false;
  const tokens = [];

  for (let i = 0; i < payload.length; i++) {
    const char = payload[i];
    if (isEscaped) {
      current += char;
      isEscaped = false;
    } else if (char === '\\') {
      current += char;
      isEscaped = true;
    } else if (char === ';') {
      if (current.trim()) {
        tokens.push(current);
      }
      current = '';
    } else {
      current += char;
    }
  }
  if (current.trim()) {
    tokens.push(current);
  }

  const fields = {};
  for (const token of tokens) {
    const colonIdx = token.indexOf(':');
    if (colonIdx > 0) {
      const key = token.slice(0, colonIdx).trim().toUpperCase();
      let val = token.slice(colonIdx + 1);
      // Unescape escaped characters (\;, \:, \\, \", \,)
      val = val.replace(/\\([\\;,:"])/g, '$1');
      fields[key] = val;
    }
  }

  const ssid = fields.S || '';
  const security = fields.T || 'nopass';
  const password = fields.P || '';
  const hidden = fields.H === 'true' || fields.H === 'TRUE' || fields.H === '1';

  return { ssid, security, password, hidden };
}

/**
 * Parses UPI payment intent string.
 * Format: upi://pay?pa=...&pn=...&am=...&tn=...&cu=...
 * 
 * @param {string} raw - Raw UPI URI string
 * @returns {object} Parsed query parameters
 */
export function parseUpiPayload(raw) {
  const queryIndex = raw.indexOf('?');
  const queryString = queryIndex !== -1 ? raw.slice(queryIndex + 1) : '';
  const params = new URLSearchParams(queryString);

  return {
    pa: params.get('pa') || '',
    pn: params.get('pn') || '',
    am: params.get('am') || '',
    tn: params.get('tn') || '',
    cu: params.get('cu') || ''
  };
}

/**
 * Detects and parses non-URL payloads before URL normalization.
 * 
 * @param {string} rawInput - Raw input string from input field or QR decoder
 * @returns {object|null} Structured payload analysis, or null if it should be handled by standard URL engine
 */
export function detectAndParsePayload(rawInput) {
  if (rawInput === null || rawInput === undefined || typeof rawInput !== 'string') {
    return null;
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return null;
  }

  // 1. UPI Payment Check (upi://pay?...)
  if (/^upi:\/\/pay([/?].*)?$/i.test(trimmed)) {
    const { pa, pn, am, tn, cu } = parseUpiPayload(trimmed);

    const rules = [
      {
        id: 'payment-intent-scheme',
        name: 'Payment Intent Protocol',
        severity: 'review',
        reason: 'Deep link triggers external payment application (UPI intent).'
      }
    ];

    const anomalies = ['payment_intent_scheme'];

    if (pn) {
      rules.push({
        id: 'upi-claimed-name',
        name: 'Claimed Display Name (Untrusted, set by creator)',
        severity: 'review',
        reason: `Claimed Display Name (Untrusted, set by creator): "${pn}". Display names are set arbitrarily by the QR creator. Verify payee VPA before authorizing.`
      });
    }

    if (am) {
      anomalies.push('upi_prefilled_amount');
      rules.push({
        id: 'upi-prefilled-amount',
        name: 'Prefilled Transaction Amount',
        severity: 'review',
        reason: `Prefilled Amount: ${am} ${cu || 'INR'}. Attackers often pre-populate amounts on campus poster scams.`
      });
    }

    if (tn) {
      rules.push({
        id: 'upi-transaction-note',
        name: 'Transaction Note',
        severity: 'note',
        reason: `Transaction Note: "${tn}". Creator-specified note intended to influence payee context.`
      });
    }

    const passedRules = [
      'Zero hidden background web execution or silent browser redirection'
    ];
    if (!am) {
      passedRules.push('No pre-filled transaction amount locked into request');
    }
    passedRules.push('Requires explicit PIN authorization within personal banking application');

    const queryIndex = trimmed.indexOf('?');
    const parts = {
      protocol: 'upi:',
      userinfo: '',
      host: 'pay',
      registrableDomain: 'UPI Mobile Payment',
      port: '',
      path: '',
      query: queryIndex !== -1 ? trimmed.slice(queryIndex) : ''
    };

    return {
      type: 'UPI',
      verdict: 'review',
      tag: 'UPI PAYMENT',
      data: { pa, pn, am, tn, cu },
      rules,
      passedRules,
      anomalies,
      primaryReason: {
        label: 'Why review is required:',
        text: 'UPI Payment Request — Verify the payee address and transaction details before authorizing payment in a banking app.'
      },
      parts
    };
  }

  // 2. Wi-Fi Configuration Check (Starts with WIFI:)
  if (trimmed.toUpperCase().startsWith('WIFI:')) {
    const { ssid, security, password, hidden } = parseWifiMecard(trimmed);
    const isOpen = !security || security.toLowerCase() === 'nopass' || security.toLowerCase() === 'none';

    const anomalies = ['wifi_config_payload'];
    if (isOpen) {
      anomalies.push('wifi_open_network');
    }

    const rules = [
      {
        id: 'wifi-config-payload',
        name: 'Local Network Configuration',
        severity: 'review',
        reason: 'Barcode configures local device Wi-Fi connectivity and access point credentials.'
      }
    ];

    if (isOpen) {
      rules.push({
        id: 'wifi-open-network',
        name: 'Unencrypted Wi-Fi Network',
        severity: 'review',
        reason: 'Flagged: Network specifies no encryption (open Wi-Fi); wireless traffic can be monitored on local airwaves.'
      });
    } else {
      rules.push({
        id: 'wifi-security-protocol',
        name: 'Wireless Security Standard',
        severity: 'note',
        reason: `Protected network configuration using ${security} authentication.`
      });
    }

    if (hidden) {
      rules.push({
        id: 'wifi-hidden-network',
        name: 'Hidden Network SSID',
        severity: 'note',
        reason: 'SSID is configured as hidden; client device will actively broadcast probe requests searching for this network.'
      });
    }

    const passedRules = [
      'Zero executable web payload or browser redirection route',
      'Requires manual user confirmation before associating device to wireless network'
    ];
    if (!isOpen) {
      passedRules.push('Pre-shared wireless encryption credentials configured');
    }

    const parts = {
      protocol: 'wifi:',
      userinfo: '',
      host: ssid || 'Local Wi-Fi',
      registrableDomain: 'Local Wi-Fi Configuration',
      port: '',
      path: '',
      query: ''
    };

    return {
      type: 'WIFI',
      verdict: 'review',
      tag: 'WI-FI CONFIG',
      data: { ssid, security, password, hidden },
      rules,
      passedRules,
      anomalies,
      primaryReason: {
        label: 'Why review is required:',
        text: 'Local Network Configuration — Connecting to unverified or open Wi-Fi access points can expose traffic to interception.'
      },
      parts
    };
  }

  // 3. Plain Text Check
  // If the raw text does not contain ://, does not start with WIFI:,
  // has no known application protocol scheme, has no valid top-level domain from PSL,
  // and contains spaces or plain language:
  const hasHierarchicalScheme = trimmed.includes('://');
  const isKnownScheme = /^(javascript|vbscript|data|file|mailto|tel|sms|blob|upi|wifi):/i.test(trimmed);

  if (!hasHierarchicalScheme && !isKnownScheme && /\s/.test(trimmed)) {
    if (!containsValidDomainOrIp(trimmed)) {
      const rules = [
        {
          id: 'non-executable-text',
          name: 'Non-Executable Plain Text',
          severity: 'note',
          reason: 'Payload contains descriptive text without active links, protocols, or commands.'
        }
      ];

      const passedRules = [
        'Zero executable script or protocol triggers',
        'No network authority destination requested',
        'Safe for local display and inspection'
      ];

      const parts = {
        protocol: '',
        userinfo: '',
        host: '',
        registrableDomain: 'Non-Executable Plain Text',
        port: '',
        path: '',
        query: ''
      };

      return {
        type: 'TEXT',
        verdict: 'safe',
        tag: 'PLAIN TEXT',
        data: { text: rawInput },
        rules,
        passedRules,
        anomalies: [],
        primaryReason: {
          label: 'Classification basis:',
          text: 'Non-Executable Text — This QR contains plain descriptive text, not a web link, executable script, or system intent.'
        },
        parts
      };
    }
  }

  // Fallback: null for standard web links
  return null;
}

export default detectAndParsePayload;
