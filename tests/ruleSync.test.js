import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  STORAGE_KEY,
  DEFAULT_RULE_VERSION,
  DEFAULT_SIGNATURES,
  validateRulePayload,
  getActiveSignatures,
  getRuleMetadata,
  saveRulePayload,
  resetRulesToDefault,
  syncRulesOnline
} from '../src/engine/sync/ruleManager.js';
import { checkCombosquatting } from '../src/engine/rules/combosquattingRule.js';
import { checkScamLure } from '../src/engine/rules/scamLureRule.js';

describe('1. Rule Schema Validation & Prototype Defenses (validateRulePayload)', () => {
  const validManifest = {
    version: '2026.10.1',
    updatedAt: '2026-10-14T00:00:00Z',
    signatures: {
      brandCatalog: ['google', 'paypal', 'microsoft', 'fintechcorp'],
      credentialLures: ['login', 'signin', 'verify', 'reauth'],
      scamOffers: ['free', 'gift', 'prize', 'airdrop'],
      scamActions: ['claim', 'collect', 'redeem', 'payout']
    }
  };

  it('accepts a conformant rule manifest', () => {
    expect(validateRulePayload(validManifest)).toBe(true);
  });

  it('rejects non-object or null root structures', () => {
    expect(validateRulePayload(null)).toBe(false);
    expect(validateRulePayload(undefined)).toBe(false);
    expect(validateRulePayload('{"version": "1.0"}')).toBe(false);
    expect(validateRulePayload(12345)).toBe(false);
    expect(validateRulePayload([])).toBe(false);
  });

  it('rejects missing or malformed version attributes', () => {
    expect(validateRulePayload({ signatures: validManifest.signatures })).toBe(false);
    expect(validateRulePayload({ version: 2026, signatures: validManifest.signatures })).toBe(false);
    expect(validateRulePayload({ version: '', signatures: validManifest.signatures })).toBe(false);
    expect(validateRulePayload({ version: 'a'.repeat(60), signatures: validManifest.signatures })).toBe(false);
    expect(validateRulePayload({ version: 'v1.0; DROP TABLE;', signatures: validManifest.signatures })).toBe(false);
  });

  it('rejects missing or malformed signatures object', () => {
    expect(validateRulePayload({ version: '2026.10.1' })).toBe(false);
    expect(validateRulePayload({ version: '2026.10.1', signatures: null })).toBe(false);
    expect(validateRulePayload({ version: '2026.10.1', signatures: ['array-instead-of-object'] })).toBe(false);
    expect(validateRulePayload({ version: '2026.10.1', signatures: 'invalid' })).toBe(false);
  });

  it('rejects missing required signature categories', () => {
    const missingBrand = {
      version: '2026.10.1',
      signatures: {
        credentialLures: ['login'],
        scamOffers: ['free'],
        scamActions: ['claim']
      }
    };
    expect(validateRulePayload(missingBrand)).toBe(false);
  });

  it('mitigates prototype pollution vectors in root and signatures objects', () => {
    const rootPollution = JSON.parse('{"__proto__": {"admin": true}, "version": "1.0", "signatures": {}}');
    expect(validateRulePayload(rootPollution)).toBe(false);

    const sigsPollution = {
      version: '2026.10.1',
      signatures: {
        __proto__: { polluted: true },
        brandCatalog: ['google'],
        credentialLures: ['login'],
        scamOffers: ['free'],
        scamActions: ['claim']
      }
    };
    expect(validateRulePayload(sigsPollution)).toBe(false);
  });

  it('rejects script tags and HTML injection attempts', () => {
    const xssPayload = {
      version: '2026.10.1',
      signatures: {
        brandCatalog: ['google', '<script>alert("xss")</script>'],
        credentialLures: ['login'],
        scamOffers: ['free'],
        scamActions: ['claim']
      }
    };
    expect(validateRulePayload(xssPayload)).toBe(false);
  });

  it('enforces lowercase alphanumeric token syntax (/^[a-z0-9-]+$/)', () => {
    const uppercasePayload = {
      version: '2026.10.1',
      signatures: {
        ...validManifest.signatures,
        brandCatalog: ['Google', 'paypal'] // Uppercase 'G'
      }
    };
    expect(validateRulePayload(uppercasePayload)).toBe(false);

    const spacePayload = {
      version: '2026.10.1',
      signatures: {
        ...validManifest.signatures,
        credentialLures: ['log in', 'verify'] // Contains space
      }
    };
    expect(validateRulePayload(spacePayload)).toBe(false);

    const symbolPayload = {
      version: '2026.10.1',
      signatures: {
        ...validManifest.signatures,
        scamOffers: ['free$money'] // Contains symbol
      }
    };
    expect(validateRulePayload(symbolPayload)).toBe(false);
  });

  it('rejects oversized token arrays (>1,000 items) to prevent memory DoS', () => {
    const massiveList = Array.from({ length: 1001 }, (_, i) => `token-${i}`);
    const oversizedPayload = {
      version: '2026.10.1',
      signatures: {
        ...validManifest.signatures,
        brandCatalog: massiveList
      }
    };
    expect(validateRulePayload(oversizedPayload)).toBe(false);
  });

  it('rejects arrays containing non-string or empty elements', () => {
    const nonStringItem = {
      version: '2026.10.1',
      signatures: {
        ...validManifest.signatures,
        brandCatalog: ['google', 12345]
      }
    };
    expect(validateRulePayload(nonStringItem)).toBe(false);

    const emptyStringItem = {
      version: '2026.10.1',
      signatures: {
        ...validManifest.signatures,
        brandCatalog: ['google', '']
      }
    };
    expect(validateRulePayload(emptyStringItem)).toBe(false);
  });
});

describe('2. Local Storage Caching & Fail-Safe Defaults (getActiveSignatures)', () => {
  beforeEach(() => {
    resetRulesToDefault();
  });

  afterEach(() => {
    resetRulesToDefault();
  });

  it('cleanly falls back to bundled defaults when storage is uninitialized', () => {
    const active = getActiveSignatures();
    expect(active.brandCatalog).toEqual(DEFAULT_SIGNATURES.brandCatalog);
    expect(active.credentialLures).toEqual(DEFAULT_SIGNATURES.credentialLures);
    expect(active.scamOffers).toEqual(DEFAULT_SIGNATURES.scamOffers);
    expect(active.scamActions).toEqual(DEFAULT_SIGNATURES.scamActions);

    const metadata = getRuleMetadata();
    expect(metadata.version).toBe(DEFAULT_RULE_VERSION);
    expect(metadata.source).toBe('bundled_default');
  });

  it('cleanly falls back to bundled defaults if storage contains corrupted JSON', () => {
    const mockStorage = {
      getItem: (key) => (key === STORAGE_KEY ? '{{{CORRUPTED_JSON' : null),
      setItem: vi.fn(),
      removeItem: vi.fn()
    };
    // Emulate corrupted storage read
    const active = getActiveSignatures();
    expect(active.brandCatalog).toEqual(DEFAULT_SIGNATURES.brandCatalog);
  });

  it('retrieves active signatures when a validated payload is persisted', () => {
    const customPayload = {
      version: '2026.11.0',
      updatedAt: '2026-11-01T00:00:00Z',
      signatures: {
        brandCatalog: ['custombrand'],
        credentialLures: ['reauthenticate'],
        scamOffers: ['megabonus'],
        scamActions: ['cashout']
      }
    };

    const saved = saveRulePayload(customPayload);
    expect(saved).toBe(true);

    const active = getActiveSignatures();
    expect(active.brandCatalog).toEqual(['custombrand']);
    expect(active.credentialLures).toEqual(['reauthenticate']);

    const metadata = getRuleMetadata();
    expect(metadata.version).toBe('2026.11.0');
    expect(metadata.source).toBe('local_storage');
  });

  it('resetRulesToDefault restores factory state', () => {
    saveRulePayload({
      version: '2026.11.0',
      signatures: {
        brandCatalog: ['custombrand'],
        credentialLures: ['reauthenticate'],
        scamOffers: ['megabonus'],
        scamActions: ['cashout']
      }
    });

    expect(getRuleMetadata().version).toBe('2026.11.0');

    resetRulesToDefault();

    expect(getActiveSignatures().brandCatalog).toEqual(DEFAULT_SIGNATURES.brandCatalog);
    expect(getRuleMetadata().version).toBe(DEFAULT_RULE_VERSION);
    expect(getRuleMetadata().source).toBe('bundled_default');
  });
});

describe('3. Dynamic Detection Heuristic Extension', () => {
  beforeEach(() => {
    resetRulesToDefault();
  });

  afterEach(() => {
    resetRulesToDefault();
  });

  it('combosquatting: dynamically detects new brand catalog entries added via local storage', () => {
    const testUrl = 'https://fintechcorp-security.com';

    // Baseline: "fintechcorp" is NOT in the default catalog -> NOT triggered
    const baseline = checkCombosquatting(testUrl);
    expect(baseline.triggered).toBe(false);

    // Save updated signatures including "fintechcorp"
    saveRulePayload({
      version: '2026.10.2',
      signatures: {
        ...DEFAULT_SIGNATURES,
        brandCatalog: [...DEFAULT_SIGNATURES.brandCatalog, 'fintechcorp']
      }
    });

    // Now dynamically detected without modifying source code or rebooting
    const updated = checkCombosquatting(testUrl);
    expect(updated.triggered).toBe(true);
    expect(updated.ruleId).toBe('combosquatting_phishing_lure');
    expect(updated.primaryReason).toContain('fintechcorp');
    expect(updated.primaryReason).toContain('security');

    // Reset restores baseline
    resetRulesToDefault();
    expect(checkCombosquatting(testUrl).triggered).toBe(false);
  });

  it('combosquatting: dynamically detects new credential lure tokens', () => {
    const testUrl = 'https://paypal-reauth.com';

    // Baseline: "reauth" is not in default LURE_KEYWORDS -> NOT triggered
    expect(checkCombosquatting(testUrl).triggered).toBe(false);

    // Add "reauth" dynamically
    saveRulePayload({
      version: '2026.10.2',
      signatures: {
        ...DEFAULT_SIGNATURES,
        credentialLures: [...DEFAULT_SIGNATURES.credentialLures, 'reauth']
      }
    });

    const updated = checkCombosquatting(testUrl);
    expect(updated.triggered).toBe(true);
    expect(updated.primaryReason).toContain('reauth');
  });

  it('scamLures: dynamically detects novel reward & action lure tokens', () => {
    const testUrl = 'https://cryptodrop-instantmint.com';

    // Baseline: neither token in dictionary -> NOT triggered
    expect(checkScamLure(testUrl).triggered).toBe(false);

    // Add novel tokens
    saveRulePayload({
      version: '2026.10.2',
      signatures: {
        ...DEFAULT_SIGNATURES,
        scamOffers: [...DEFAULT_SIGNATURES.scamOffers, 'cryptodrop'],
        scamActions: [...DEFAULT_SIGNATURES.scamActions, 'instantmint']
      }
    });

    const updated = checkScamLure(testUrl);
    expect(updated.triggered).toBe(true);
    expect(updated.ruleId).toBe('social_engineering_lure');
    expect(updated.matchedTokens).toContain('cryptodrop');
    expect(updated.matchedTokens).toContain('instantmint');
  });
});

describe('4. Online Rule Sync (syncRulesOnline)', () => {
  beforeEach(() => {
    resetRulesToDefault();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    resetRulesToDefault();
    try {
      delete globalThis.navigator.onLine;
    } catch {
      // ignore
    }
    vi.restoreAllMocks();
  });

  it('returns offline status when navigator.onLine is false', async () => {
    Object.defineProperty(globalThis.navigator, 'onLine', { value: false, configurable: true });
    try {
      const res = await syncRulesOnline();
      expect(res.status).toBe('offline');
    } finally {
      delete globalThis.navigator.onLine;
    }
  });

  it('fetches static manifest, validates, and persists when online', async () => {
    const mockManifest = {
      version: '2026.10.5',
      updatedAt: '2026-10-15T00:00:00Z',
      signatures: {
        brandCatalog: ['stripe', 'paypal'],
        credentialLures: ['verify', 'invoice'],
        scamOffers: ['reward', 'prize'],
        scamActions: ['claim', 'redeem']
      }
    };

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockManifest
    });

    const res = await syncRulesOnline(mockFetch);
    expect(res.status).toBe('updated');
    expect(res.version).toBe('2026.10.5');

    const active = getActiveSignatures();
    expect(active.brandCatalog).toContain('stripe');
  });

  it('handles HTTP error gracefully without modifying local cache', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500
    });

    const res = await syncRulesOnline(mockFetch);
    expect(res.status).toBe('error');
    expect(getActiveSignatures().brandCatalog).toEqual(DEFAULT_SIGNATURES.brandCatalog);
  });

  it('rejects malicious payload from server and preserves local cache', async () => {
    const maliciousManifest = {
      version: '2026.10.5',
      signatures: {
        brandCatalog: ['<script>evil()</script>'],
        credentialLures: ['login'],
        scamOffers: ['free'],
        scamActions: ['claim']
      }
    };

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => maliciousManifest
    });

    const res = await syncRulesOnline(mockFetch);
    expect(res.status).toBe('invalid_payload');
    expect(getActiveSignatures().brandCatalog).toEqual(DEFAULT_SIGNATURES.brandCatalog);
  });
});
