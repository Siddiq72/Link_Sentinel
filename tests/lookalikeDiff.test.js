import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/index.js';
import { computeLookalikeDiff, CONFUSABLE_METADATA } from '../src/engine/data/confusables.js';
import LookalikeDiffCard from '../src/ui/LookalikeDiffCard.jsx';
import ResultPanel from '../src/ui/ResultPanel.jsx';
import UrlTokens from '../src/ui/UrlTokens.jsx';

describe('Look-alike Visual Diff Feature', () => {
  it('analyzing https://\u0441ampus.example/login generates a valid lookalikeDiff object', () => {
    const fakeUrl = 'https://\u0441ampus.example/login';
    const result = analyze(fakeUrl);

    expect(result).toHaveProperty('lookalikeDiff');
    expect(result.lookalikeDiff).not.toBeNull();
    expect(result.lookalikeDiff).toHaveProperty('genuineDomain', 'campus.example');
    expect(result.lookalikeDiff).toHaveProperty('fakeHost', '\u0441ampus.example');
    expect(result.lookalikeDiff).toHaveProperty('punycode');
    expect(result.lookalikeDiff.punycode).toMatch(/^xn--/);
    expect(Array.isArray(result.lookalikeDiff.characters)).toBe(true);
  });

  it('identifies confusable \\u0441 with codePoint U+0441 and targets campus.example', () => {
    const fakeUrl = 'https://\u0441ampus.example/login';
    const result = analyze(fakeUrl);
    const diff = result.lookalikeDiff;

    expect(diff.genuineDomain).toBe('campus.example');

    // First character should be Cyrillic 'с' (U+0441)
    const firstChar = diff.characters[0];
    expect(firstChar.char).toBe('\u0441');
    expect(firstChar.isConfusable).toBe(true);
    expect(firstChar.metadata).toBeDefined();
    expect(firstChar.metadata.codePoint).toBe('U+0441');
    expect(firstChar.metadata.name).toBe('CYRILLIC SMALL LETTER ES');
    expect(firstChar.metadata.latinMatch).toBe('c');

    // Subsequent characters should be normal Latin
    const secondChar = diff.characters[1];
    expect(secondChar.char).toBe('a');
    expect(secondChar.isConfusable).toBe(false);
    expect(secondChar.metadata).toBeNull();
  });

  it('clean link like https://campus.example/notices/lab-3 has lookalikeDiff: null', () => {
    const cleanUrl = 'https://campus.example/notices/lab-3';
    const result = analyze(cleanUrl);

    expect(result).toHaveProperty('lookalikeDiff');
    expect(result.lookalikeDiff).toBeNull();
  });

  it('non-lookalike suspicious link (@ trick) has lookalikeDiff: null', () => {
    const atTrickUrl = 'https://campus.example@other.example/login';
    const result = analyze(atTrickUrl);

    expect(result).toHaveProperty('lookalikeDiff');
    expect(result.lookalikeDiff).toBeNull();
  });

  it('computeLookalikeDiff provides graceful fallback for unmapped non-ASCII characters', () => {
    // Test with a non-ASCII character not explicitly in CONFUSABLE_METADATA
    const unmappedChar = '\u2000'; // EN QUAD
    const diff = computeLookalikeDiff(`${unmappedChar}ampus.example`, 'campus.example');

    expect(diff).not.toBeNull();
    expect(diff.genuineDomain).toBe('campus.example');
    const firstChar = diff.characters[0];
    expect(firstChar.char).toBe(unmappedChar);
    expect(firstChar.isConfusable).toBe(true);
    expect(firstChar.metadata.codePoint).toBe('U+2000');
    expect(firstChar.metadata.name).toContain('NON-ASCII');
  });

  it('exports CONFUSABLE_METADATA for Cyrillic and Greek homoglyphs', () => {
    expect(CONFUSABLE_METADATA['\u0441']).toEqual({
      char: 'с',
      codePoint: 'U+0441',
      name: 'CYRILLIC SMALL LETTER ES',
      latinMatch: 'c'
    });
    expect(CONFUSABLE_METADATA['\u0430']).toEqual({
      char: 'а',
      codePoint: 'U+0430',
      name: 'CYRILLIC SMALL LETTER A',
      latinMatch: 'a'
    });
    expect(CONFUSABLE_METADATA['\u03B1']).toEqual({
      char: 'α',
      codePoint: 'U+03B1',
      name: 'GREEK SMALL LETTER ALPHA',
      latinMatch: 'a'
    });
  });

  it('handles Greek homoglyph imitation against protected domain', () => {
    // Replace 'a' in campus with Greek alpha \u03B1
    const greekUrl = 'https://c\u03B1mpus.example/login';
    const result = analyze(greekUrl);

    expect(result.lookalikeDiff).not.toBeNull();
    expect(result.lookalikeDiff.genuineDomain).toBe('campus.example');
    const alphaChar = result.lookalikeDiff.characters[1];
    expect(alphaChar.char).toBe('\u03B1');
    expect(alphaChar.isConfusable).toBe(true);
    expect(alphaChar.metadata.codePoint).toBe('U+03B1');
    expect(alphaChar.metadata.name).toBe('GREEK SMALL LETTER ALPHA');
  });

  describe('UI Component Rendering', () => {
    it('LookalikeDiffCard returns null when diff is null or undefined', () => {
      expect(renderToStaticMarkup(React.createElement(LookalikeDiffCard, { diff: null }))).toBe('');
      expect(renderToStaticMarkup(React.createElement(LookalikeDiffCard, { diff: undefined }))).toBe('');
      expect(renderToStaticMarkup(React.createElement(LookalikeDiffCard, { diff: {} }))).toBe('');
    });

    it('LookalikeDiffCard renders visual stacked diff and explainer rows correctly', () => {
      const result = analyze('https://\u0441ampus.example/login');
      const html = renderToStaticMarkup(React.createElement(LookalikeDiffCard, { diff: result.lookalikeDiff }));

      expect(html).toContain('LOOK-ALIKE CHARACTER COMPARISON');
      expect(html).toContain('Genuine target:');
      expect(html).toContain('campus.example');
      expect(html).toContain('Analyzed host:');
      expect(html).toContain('CYRILLIC SMALL LETTER ES');
      expect(html).toContain('U+0441');
      expect(html).toContain('visually imitates Latin');
      expect(html).toContain('Host as the browser resolves it:');
      expect(html).toContain(result.lookalikeDiff.punycode);
      // Confusable character has red pill styling
      expect(html).toContain('bg-red-500/20 text-red-300 ring-1 ring-red-500');
    });

    it('UrlTokens strips duplicate (Punycode: ...) when hasLookalikeDiff is true', () => {
      const result = analyze('https://\u0441ampus.example/login');
      const html = renderToStaticMarkup(
        React.createElement(UrlTokens, {
          parts: result.parts,
          anomalies: result.anomalies,
          verdict: result.verdict,
          hasLookalikeDiff: true
        })
      );

      expect(html).not.toContain('(Punycode:');
      expect(html).toContain('сampus.example');
    });

    it('ResultPanel integrates LookalikeDiffCard between UrlTokens and ReasonCard', () => {
      const result = analyze('https://\u0441ampus.example/login');
      const html = renderToStaticMarkup(React.createElement(ResultPanel, { result }));

      expect(html).toContain('LOOK-ALIKE CHARACTER COMPARISON');
      expect(html).toContain('URL Anatomy Breakdown');
      expect(html).toContain('Genuine target:');

      // Check relative ordering in rendered markup
      const anatomyPos = html.indexOf('URL Anatomy Breakdown');
      const lookalikePos = html.indexOf('LOOK-ALIKE CHARACTER COMPARISON');
      const reasonsPos = html.indexOf('Character Substitution');

      expect(anatomyPos).toBeGreaterThan(-1);
      expect(lookalikePos).toBeGreaterThan(anatomyPos);
      expect(reasonsPos).toBeGreaterThan(lookalikePos);
    });
  });
});
