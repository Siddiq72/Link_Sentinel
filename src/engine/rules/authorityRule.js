/**
 * Authority & Userinfo Deception Evaluation Rule.
 * Hardens Link Sentinel against double-encoded and percent-encoded '@' (%40 and %2540)
 * and authority routing decoys.
 */

export { evaluateUserinfoRule as evaluateAuthorityRule, evaluateUserinfoRule, default } from './userinfoRule.js';
