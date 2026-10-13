import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/index.js';
import { detectAndParsePayload, parseWifiMecard, parseUpiPayload } from '../src/engine/payloads/index.js';

describe('UPI Payment Intent Payload Parser', () => {
  it('extracts all query parameters, flags prefilled amount anomaly and untrusted name', () => {
    const raw = 'upi://pay?pa=campus-canteen@oksbi&pn=Campus%20Canteen&am=250&cu=INR&tn=Lunch%20Combo';
    const parsed = detectAndParsePayload(raw);

    expect(parsed).not.toBeNull();
    expect(parsed.type).toBe('UPI');
    expect(parsed.verdict).toBe('review');
    expect(parsed.tag).toBe('UPI PAYMENT');

    expect(parsed.data.pa).toBe('campus-canteen@oksbi');
    expect(parsed.data.pn).toBe('Campus Canteen');
    expect(parsed.data.am).toBe('250');
    expect(parsed.data.cu).toBe('INR');
    expect(parsed.data.tn).toBe('Lunch Combo');

    expect(parsed.anomalies).toContain('upi_prefilled_amount');
    expect(parsed.anomalies).toContain('payment_intent_scheme');

    const amountRule = parsed.rules.find((r) => r.id === 'upi-prefilled-amount');
    expect(amountRule).toBeDefined();
    expect(amountRule.reason).toContain('Prefilled Amount: 250 INR');

    const pnRule = parsed.rules.find((r) => r.id === 'upi-claimed-name');
    expect(pnRule).toBeDefined();
    expect(pnRule.name).toContain('Claimed Display Name');

    expect(parsed.primaryReason.text).toBe(
      'UPI Payment Request — Verify the payee address and transaction details before authorizing payment in a banking app.'
    );
  });

  it('handles UPI without prefilled amount safely and does not flag upi_prefilled_amount', () => {
    const raw = 'upi://pay?pa=library-fines@sbi&pn=Central%20Library';
    const res = analyze(raw);

    expect(res.payloadType).toBe('UPI');
    expect(res.verdict).toBe('review');
    expect(res.data.pa).toBe('library-fines@sbi');
    expect(res.data.am).toBe('');
    expect(res.anomalies).not.toContain('upi_prefilled_amount');
    expect(res.passedRules).toContain('No pre-filled transaction amount locked into request');
  });

  it('decodes plus-encoded spaces in URL query parameters', () => {
    const raw = 'upi://pay?pa=vendor@okhdfcbank&pn=Book+Store&am=100';
    const { pn, am } = parseUpiPayload(raw);

    expect(pn).toBe('Book Store');
    expect(am).toBe('100');
  });
});

describe('Wi-Fi MECARD String Parser', () => {
  it('correctly parses standard WPA Wi-Fi parameters', () => {
    const raw = 'WIFI:T:WPA;S:Campus_Guest_WiFi;P:Welcome2026;H:false;;';
    const parsed = detectAndParsePayload(raw);

    expect(parsed).not.toBeNull();
    expect(parsed.type).toBe('WIFI');
    expect(parsed.verdict).toBe('review');
    expect(parsed.tag).toBe('WI-FI CONFIG');

    expect(parsed.data.ssid).toBe('Campus_Guest_WiFi');
    expect(parsed.data.security).toBe('WPA');
    expect(parsed.data.password).toBe('Welcome2026');
    expect(parsed.data.hidden).toBe(false);

    expect(parsed.primaryReason.text).toBe(
      'Local Network Configuration — Connecting to unverified or open Wi-Fi access points can expose traffic to interception.'
    );
  });

  it('detects unencrypted open Wi-Fi network and flags anomaly', () => {
    const raw = 'WIFI:S:University_Free_WiFi;T:nopass;;';
    const res = analyze(raw);

    expect(res.payloadType).toBe('WIFI');
    expect(res.verdict).toBe('review');
    expect(res.data.security).toBe('nopass');
    expect(res.anomalies).toContain('wifi_open_network');

    const openRule = res.rules.find((r) => r.id === 'wifi-open-network');
    expect(openRule).toBeDefined();
    expect(openRule.severity).toBe('review');
  });

  it('handles hidden networks and unescapes semicolons and backslashes in credentials', () => {
    const raw = 'WIFI:S:Staff\\;Network;T:WPA2;P:p\\;ss123;H:true;;';
    const parsed = parseWifiMecard(raw);

    expect(parsed.ssid).toBe('Staff;Network');
    expect(parsed.security).toBe('WPA2');
    expect(parsed.password).toBe('p;ss123');
    expect(parsed.hidden).toBe(true);

    const fullRes = analyze(raw);
    const hiddenRule = fullRes.rules.find((r) => r.id === 'wifi-hidden-network');
    expect(hiddenRule).toBeDefined();
  });
});

describe('Plain Text Classification', () => {
  it('classifies non-web natural descriptive text as Safe with PLAIN TEXT tag', () => {
    const raw = 'Welcome to CS101. Lab 3 will be held on Thursday at 2 PM in Room 304.';
    const res = analyze(raw);

    expect(res.payloadType).toBe('TEXT');
    expect(res.verdict).toBe('safe');
    expect(res.tag).toBe('PLAIN TEXT');
    expect(res.data.text).toBe(raw);
    expect(res.primaryReason.label).toBe('Classification basis:');
    expect(res.primaryReason.text).toBe(
      'Non-Executable Text — This QR contains plain descriptive text, not a web link, executable script, or system intent.'
    );
  });

  it('classifies item notices and locker keys as safe plain text', () => {
    const raw = 'Physics Department Locker #42 - Assigned to Alice Smith';
    const parsed = detectAndParsePayload(raw);

    expect(parsed).not.toBeNull();
    expect(parsed.type).toBe('TEXT');
    expect(parsed.verdict).toBe('safe');
  });
});

describe('Standard URL Parity and Fallback', () => {
  it('returns null from payload classifier for standard HTTPS URLs', () => {
    expect(detectAndParsePayload('https://campus.example/notices/lab-3')).toBeNull();
    expect(detectAndParsePayload('https://campus.example@other.example/login')).toBeNull();
    expect(detectAndParsePayload('http://192.168.1.10/')).toBeNull();
    expect(detectAndParsePayload('campus.example/notices')).toBeNull();
    expect(detectAndParsePayload('https://bit.ly/3abcXYZ')).toBeNull();
  });

  it('returns null for texts containing valid domain names or schemes', () => {
    expect(detectAndParsePayload('Visit https://campus.example for details')).toBeNull();
    expect(detectAndParsePayload('Check out google.com today')).toBeNull();
    expect(detectAndParsePayload('javascript:alert(1)')).toBeNull();
  });

  it('evaluates all 7 original demo links identically through analyze()', () => {
    // 1. Ordinary
    const v1 = analyze('https://campus.example/notices/lab-3');
    expect(v1.verdict).toBe('safe');
    expect(v1.parts.host).toBe('campus.example');
    expect(v1.payloadType).toBeUndefined();

    // 2. @ trick
    const v2 = analyze('https://campus.example@other.example/login');
    expect(v2.verdict).toBe('suspicious');
    expect(v2.anomalies).toContain('userinfo_decoy');
    expect(v2.payloadType).toBeUndefined();

    // 3. Lookalike
    const v3 = analyze('https://\u0441ampus.example/login');
    expect(v3.verdict).toBe('suspicious');
    expect(v3.anomalies).toContain('homoglyph_cyrillic');
    expect(v3.payloadType).toBeUndefined();

    // 4. Public IP
    const v4 = analyze('http://192.0.2.45/signin');
    expect(v4.verdict).toBe('suspicious');
    expect(v4.anomalies).toContain('raw_ip_host');
    expect(v4.payloadType).toBeUndefined();

    // 5. Private IP
    const v5 = analyze('http://192.168.1.10/');
    expect(v5.verdict).toBe('review');
    expect(v5.anomalies).toContain('private_ip_host');
    expect(v5.payloadType).toBeUndefined();

    // 6. Shortener
    const v6 = analyze('https://bit.ly/3abcXYZ');
    expect(v6.verdict).toBe('review');
    expect(v6.anomalies).toContain('url_shortener');
    expect(v6.payloadType).toBeUndefined();

    // 7. Safe: @ in query
    const v7 = analyze('https://portal.campus.example:8443/forms?contact=lab@campus.example');
    expect(v7.verdict).toBe('safe');
    expect(v7.parts.port).toBe(':8443');
    expect(v7.payloadType).toBeUndefined();
  });
});

describe('ResultPanel Data Contract & Safety Constraints', () => {
  it('UPI payloads must strictly resolve to review, never safe', () => {
    const payloads = [
      'upi://pay?pa=trusted-org@sbi',
      'upi://pay?pa=campus-canteen@oksbi&pn=Campus%20Canteen&am=250&cu=INR',
      'upi://pay?pa=test@bank'
    ];
    for (const p of payloads) {
      const res = analyze(p);
      expect(res.verdict).toBe('review');
      expect(res.payloadType).toBe('UPI');
    }
  });

  it('verifies ResultPanel data contract shape for all payload types', () => {
    const upiRes = analyze('upi://pay?pa=canteen@bank&am=50');
    expect(upiRes).toHaveProperty('verdict', 'review');
    expect(upiRes).toHaveProperty('payloadType', 'UPI');
    expect(upiRes).toHaveProperty('primaryReason');
    expect(upiRes).toHaveProperty('reasons');
    expect(Array.isArray(upiRes.reasons)).toBe(true);
    expect(upiRes).toHaveProperty('rules');
    expect(upiRes).toHaveProperty('passedRules');
    expect(upiRes).toHaveProperty('anomalies');
    expect(upiRes).toHaveProperty('parts');

    const wifiRes = analyze('WIFI:T:WPA;S:LabNet;P:pass;;');
    expect(wifiRes).toHaveProperty('verdict', 'review');
    expect(wifiRes).toHaveProperty('payloadType', 'WIFI');
    expect(wifiRes).toHaveProperty('primaryReason');
    expect(wifiRes).toHaveProperty('reasons');

    const textRes = analyze('Notice: System upgrade scheduled for 10 PM tonight');
    expect(textRes).toHaveProperty('verdict', 'safe');
    expect(textRes).toHaveProperty('payloadType', 'TEXT');
    expect(textRes).toHaveProperty('primaryReason');
    expect(textRes).toHaveProperty('reasons');
  });
});

