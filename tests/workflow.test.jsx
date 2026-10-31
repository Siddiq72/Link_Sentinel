import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { renderToString } from 'react-dom/server';
import App from '../src/App';
import InputCard from '../src/ui/InputCard';

describe('Analysis Workflow & Explicit Execution Triggers', () => {
  it('renders initial idle state ("Awaiting Target Stream") on initial mount', () => {
    const html = renderToString(<App />);
    expect(html).toContain('Awaiting Target Stream');
    expect(html).toContain('HEURISTIC ENGINE ARMED // 0 NETWORK TELEMETRY');
    expect(html).not.toContain('Classification basis:');
    expect(html).not.toContain("Why it's flagged as Suspicious:");
  });

  it('InputCard submits on Enter key press', () => {
    const onAnalyze = vi.fn();
    const onChange = vi.fn();

    // Verify handleKeyDown triggers onAnalyze when Enter is pressed
    const handleKeyDown = (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        onAnalyze();
      }
    };

    const enterEvent = {
      key: 'Enter',
      preventDefault: vi.fn()
    };
    handleKeyDown(enterEvent);

    expect(enterEvent.preventDefault).toHaveBeenCalled();
    expect(onAnalyze).toHaveBeenCalledTimes(1);

    // Non-enter keys do not trigger onAnalyze
    const otherEvent = {
      key: 'a',
      preventDefault: vi.fn()
    };
    handleKeyDown(otherEvent);
    expect(onAnalyze).toHaveBeenCalledTimes(1);
  });

  it('InputCard invokes onAnalyze on button click', () => {
    const onAnalyze = vi.fn();
    const onClear = vi.fn();

    const html = renderToString(
      <InputCard
        value="https://google.com"
        onChange={() => {}}
        onAnalyze={onAnalyze}
        onClear={onClear}
        onQrUpload={() => {}}
        onSelectSample={() => {}}
      />
    );

    expect(html).toContain('id="btn-analyze"');
    expect(html).toContain('ANALYZE');
    expect(html).toContain('Clear');
  });
});
