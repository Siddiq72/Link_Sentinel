/**
 * RULE MANAGER & STORAGE SUBSYSTEM
 *
 * Implements online rule synchronization and offline-first persistent caching.
 *
 * Security & Architectural Guarantees:
 * 1. DATA, NOT CODE: Exclusively ingests static threat signature JSON; zero executable JS.
 * 2. PROTOTYPE DEFENSE: Rejects __proto__, constructor, and prototype pollution attempts.
 * 3. STRICT SCHEMA: Enforces lowercase alphanumeric token validation (/^[a-z0-9-]+$/)
 *    and strict array length bounds (<= 1,000 items).
 * 4. FAIL-SAFE FALLBACK: Transparently falls back to bundled baseline constants
 *    if storage is corrupt, uninitialized, or empty.
 */

export const STORAGE_KEY = 'link_sentinel_threat_rules_v1';
export const DEFAULT_RULE_VERSION = '2026.10.2';

export const DEFAULT_SIGNATURES = Object.freeze({
  brandCatalog: Object.freeze([
    'google',
    'paypal',
    'microsoft',
    'apple',
    'amazon',
    'netflix',
    'chase',
    'wellsfargo',
    'sbi',
    'fampay',
    'binance',
    'coinbase',
    'facebook',
    'instagram',
    'dropbox',
    'adobe',
    'steam'
  ]),
  credentialLures: Object.freeze([
    'login',
    'signin',
    'verify',
    'verification',
    'security',
    'secure',
    'account',
    'portal',
    'update',
    'billing',
    'support',
    'auth',
    'service',
    'kyc',
    'otp',
    'wallet',
    'helpdesk',
    'claim',
    'recover'
  ]),
  scamOffers: Object.freeze([
    'free',
    'gift',
    'prize',
    'reward',
    'bonus',
    'airdrop',
    'claim',
    'winner',
    'giveaway',
    'lottery',
    'crypto',
    'cash'
  ]),
  scamActions: Object.freeze([
    'claim',
    'collect',
    'redeem',
    'payout',
    'jackpot',
    'winner',
    'survey',
    'instant',
    'reward'
  ])
});

const TOKEN_REGEX = /^[a-z0-9-]+$/;
const VERSION_REGEX = /^[a-zA-Z0-9.\-_]{1,50}$/;
const REQUIRED_SIGNATURE_KEYS = ['brandCatalog', 'credentialLures', 'scamOffers', 'scamActions'];

let customStorage = null;
const inMemoryFallback = new Map();
let cachedMetadata = null;

/**
 * Configure a custom or mocked storage implementation (primarily for unit tests).
 */
export function setCustomStorage(storage) {
  customStorage = storage;
}

/**
 * Resolves the active key-value storage engine (window.localStorage -> global localStorage -> in-memory Map).
 */
export function getStorage() {
  if (customStorage) return customStorage;
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
    if (typeof localStorage !== 'undefined' && localStorage.getItem) {
      return localStorage;
    }
  } catch {
    // Restricted environment (e.g. security sandbox)
  }
  return {
    getItem: (key) => inMemoryFallback.get(key) || null,
    setItem: (key, val) => inMemoryFallback.set(key, String(val)),
    removeItem: (key) => inMemoryFallback.delete(key),
    clear: () => inMemoryFallback.clear()
  };
}

function isCleanPlainObject(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return false;
  }
  const proto = Object.getPrototypeOf(obj);
  if (proto !== Object.prototype && proto !== null) {
    return false;
  }
  if (
    Object.prototype.hasOwnProperty.call(obj, '__proto__') ||
    Object.prototype.hasOwnProperty.call(obj, 'constructor') ||
    Object.prototype.hasOwnProperty.call(obj, 'prototype')
  ) {
    return false;
  }
  const names = Object.getOwnPropertyNames(obj);
  if (names.includes('__proto__') || names.includes('constructor') || names.includes('prototype')) {
    return false;
  }
  return true;
}

/**
 * Validates incoming rule payload against strict security schema and limits.
 *
 * @param {unknown} data - Untrusted incoming JSON payload.
 * @returns {boolean} True if payload strictly conforms to the rule schema.
 */
export function validateRulePayload(data) {
  if (!isCleanPlainObject(data)) {
    return false;
  }

  // Validate version
  if (typeof data.version !== 'string' || !VERSION_REGEX.test(data.version)) {
    return false;
  }

  // Validate signatures container
  if (!isCleanPlainObject(data.signatures)) {
    return false;
  }

  // Verify all required signature lists are present
  for (const requiredKey of REQUIRED_SIGNATURE_KEYS) {
    if (!Array.isArray(data.signatures[requiredKey])) {
      return false;
    }
  }

  // Inspect each signature collection
  for (const key of Object.keys(data.signatures)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return false;
    }

    const list = data.signatures[key];
    if (!Array.isArray(list)) {
      return false;
    }

    // Upper limit on rule count to prevent memory exhaustion / DoS
    if (list.length > 1000) {
      return false;
    }

    for (let i = 0; i < list.length; i++) {
      const item = list[i];
      if (
        typeof item !== 'string' ||
        item.length < 1 ||
        item.length > 100 ||
        !TOKEN_REGEX.test(item)
      ) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Retrieves the currently active threat signatures.
 * Seamlessly returns bundled baseline signatures if storage is uninitialized or invalid.
 *
 * @returns {typeof DEFAULT_SIGNATURES}
 */
export function getActiveSignatures() {
  const storage = getStorage();
  if (!storage) {
    return DEFAULT_SIGNATURES;
  }

  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (!raw) {
      return DEFAULT_SIGNATURES;
    }

    const parsed = JSON.parse(raw);
    if (!validateRulePayload(parsed)) {
      return DEFAULT_SIGNATURES;
    }

    return parsed.signatures;
  } catch {
    return DEFAULT_SIGNATURES;
  }
}

/**
 * Retrieves metadata for currently loaded rule set (version, update timestamp, source).
 */
export function getRuleMetadata() {
  if (cachedMetadata) {
    return cachedMetadata;
  }

  const storage = getStorage();
  if (storage) {
    try {
      const raw = storage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (validateRulePayload(parsed)) {
          cachedMetadata = {
            version: parsed.version,
            updatedAt: parsed.updatedAt || null,
            source: 'local_storage'
          };
          return cachedMetadata;
        }
      }
    } catch {
      // Fall through to default
    }
  }

  return {
    version: DEFAULT_RULE_VERSION,
    updatedAt: '2026-10-14T12:35:00Z',
    source: 'bundled_default'
  };
}

function notifyRulesUpdated(payload) {
  if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
    try {
      window.dispatchEvent(new CustomEvent('link-sentinel-rules-updated', { detail: payload }));
    } catch {
      // ignore
    }
  }
}

/**
 * Manually saves an updated rule payload into local storage after verification.
 *
 * @param {object} payload
 * @returns {boolean} True if saved successfully.
 */
export function saveRulePayload(payload) {
  if (!validateRulePayload(payload)) {
    return false;
  }

  const storage = getStorage();
  if (storage) {
    try {
      storage.setItem(STORAGE_KEY, JSON.stringify(payload));
      cachedMetadata = {
        version: payload.version,
        updatedAt: payload.updatedAt || null,
        source: 'local_storage'
      };
      notifyRulesUpdated(payload);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Resets local storage rule cache back to default factory baseline.
 */
export function resetRulesToDefault() {
  const storage = getStorage();
  if (storage && typeof storage.removeItem === 'function') {
    try {
      storage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }
  inMemoryFallback.delete(STORAGE_KEY);
  cachedMetadata = null;
  notifyRulesUpdated(null);
}

/**
 * Synchronizes rule signatures from static manifest endpoint when online.
 * Never executes code. Strictly validates static JSON before storage.
 *
 * @param {Function} [fetchFn] - Optional fetch injection for testing.
 * @returns {Promise<{ status: string, version?: string, updatedAt?: string, error?: string, message?: string }>}
 */
export async function syncRulesOnline(fetchFn = (typeof fetch !== 'undefined' ? fetch : null)) {
  const isOnline = typeof navigator !== 'undefined' && typeof navigator.onLine === 'boolean'
    ? navigator.onLine
    : true;
  if (!isOnline) {
    return { status: 'offline', message: 'Network offline. Using local signatures.' };
  }

  if (!fetchFn) {
    return { status: 'error', error: 'Fetch API unavailable' };
  }

  try {
    const res = await fetchFn('/rules/manifest.json', { cache: 'no-cache' });
    if (!res.ok) {
      return { status: 'error', error: `HTTP ${res.status}` };
    }

    const payload = await res.json();
    if (!validateRulePayload(payload)) {
      return { status: 'invalid_payload', error: 'Payload failed schema validation' };
    }

    const storage = getStorage();
    if (storage) {
      storage.setItem(STORAGE_KEY, JSON.stringify(payload));
    }

    cachedMetadata = {
      version: payload.version,
      updatedAt: payload.updatedAt || null,
      source: 'local_storage'
    };
    notifyRulesUpdated(payload);

    return {
      status: 'updated',
      version: payload.version,
      updatedAt: payload.updatedAt
    };
  } catch (err) {
    return { status: 'error', error: err?.message || 'Sync failed' };
  }
}

export default {
  STORAGE_KEY,
  DEFAULT_RULE_VERSION,
  DEFAULT_SIGNATURES,
  setCustomStorage,
  getStorage,
  validateRulePayload,
  getActiveSignatures,
  getRuleMetadata,
  saveRulePayload,
  resetRulesToDefault,
  syncRulesOnline
};
