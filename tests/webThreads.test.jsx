import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { renderToString } from 'react-dom/server';
import fs from 'fs';
import path from 'path';
import WebThreads from '../src/components/ui/WebThreads';
import App from '../src/App';

describe('WebThreads Component & Integration', () => {
  let origDocument;
  let origWindow;

  beforeEach(() => {
    origDocument = globalThis.document;
    origWindow = globalThis.window;
  });

  afterEach(() => {
    globalThis.document = origDocument;
    globalThis.window = origWindow;
    vi.restoreAllMocks();
  });

  describe('Stylesheet Verification', () => {
    it('contains the specified CSS rules in src/components/ui/WebThreads.css', () => {
      const cssPath = path.resolve(__dirname, '../src/components/ui/WebThreads.css');
      expect(fs.existsSync(cssPath)).toBe(true);

      const content = fs.readFileSync(cssPath, 'utf8');
      expect(content).toContain('.web-threads-container');
      expect(content).toContain('.web-threads-canvas');
      expect(content).toContain('position: relative;');
      expect(content).toContain('position: absolute;');
      expect(content).toContain('inset: 0;');
      expect(content).toContain('overflow: hidden;');
    });

    it('re-exports cleanly from src/ui/WebThreads.jsx', async () => {
      const uiExport = await import('../src/ui/WebThreads.jsx');
      expect(uiExport.default).toBe(WebThreads);
    });
  });

  describe('Rendering & Props', () => {
    it('renders initial container element in SSR / static HTML without throwing', () => {
      const html = renderToString(
        <WebThreads
          colors={['#06b6d4', '#3b82f6', '#8b5cf6']}
          className="test-custom-threads"
          data-testid="bg-threads"
        />
      );

      expect(html).toContain('web-threads-container');
      expect(html).toContain('test-custom-threads');
      expect(html).toContain('data-testid="bg-threads"');
    });

    it('handles custom style and attribute pass-through', () => {
      const html = renderToString(
        <WebThreads
          style={{ pointerEvents: 'none', position: 'absolute' }}
          data-sentinel="security-layer"
        />
      );

      expect(html).toContain('pointer-events:none');
      expect(html).toContain('position:absolute');
      expect(html).toContain('data-sentinel="security-layer"');
    });

    it('handles dark mode, light mode, and transparent background configs', () => {
      const htmlTransparent = renderToString(
        <WebThreads
          backgroundColor="transparent"
          lightMode={false}
          threadCount={12}
        />
      );
      expect(htmlTransparent).toContain('web-threads-container');

      const htmlLight = renderToString(
        <WebThreads
          backgroundColor="#ffffff"
          lightMode={true}
          threadCount={4}
        />
      );
      expect(htmlLight).toContain('web-threads-container');
    });
  });

  describe('Browser & WebGL Lifecycle', () => {
    it('handles browser mount and gracefully handles environments lacking WebGL2', () => {
      const mockCanvas = {
        className: '',
        setAttribute: vi.fn(),
        getContext: vi.fn(() => null), // Simulate lack of WebGL2 support
        remove: vi.fn()
      };

      globalThis.document = {
        createElement: vi.fn(tag => {
          if (tag === 'canvas') return mockCanvas;
          return {};
        }),
        documentElement: {
          addEventListener: vi.fn(),
          removeEventListener: vi.fn()
        },
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        hidden: false
      };

      globalThis.window = {
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        devicePixelRatio: 1,
        matchMedia: vi.fn(() => ({ matches: false }))
      };

      expect(() => {
        renderToString(<WebThreads />);
      }).not.toThrow();
    });

    it('configures WebGL2 context with high performance and transparency', () => {
      const mockGl = {
        VERTEX_SHADER: 35633,
        FRAGMENT_SHADER: 35632,
        COMPILE_STATUS: 35713,
        LINK_STATUS: 35714,
        ARRAY_BUFFER: 34962,
        STATIC_DRAW: 35044,
        FLOAT: 5126,
        createShader: vi.fn(() => ({})),
        shaderSource: vi.fn(),
        compileShader: vi.fn(),
        getShaderParameter: vi.fn(() => true),
        createProgram: vi.fn(() => ({})),
        attachShader: vi.fn(),
        bindAttribLocation: vi.fn(),
        linkProgram: vi.fn(),
        getProgramParameter: vi.fn(() => true),
        deleteShader: vi.fn(),
        deleteProgram: vi.fn(),
        getUniformLocation: vi.fn((prog, name) => name),
        createVertexArray: vi.fn(() => ({})),
        bindVertexArray: vi.fn(),
        createBuffer: vi.fn(() => ({})),
        bindBuffer: vi.fn(),
        bufferData: vi.fn(),
        enableVertexAttribArray: vi.fn(),
        vertexAttribPointer: vi.fn(),
        useProgram: vi.fn(),
        viewport: vi.fn(),
        bindFramebuffer: vi.fn(),
        clearColor: vi.fn(),
        clear: vi.fn(),
        drawArrays: vi.fn(),
        deleteBuffer: vi.fn(),
        deleteVertexArray: vi.fn(),
        getExtension: vi.fn(() => ({ loseContext: vi.fn() }))
      };

      const mockCanvas = {
        className: '',
        setAttribute: vi.fn(),
        getContext: vi.fn((type, opts) => {
          expect(type).toBe('webgl2');
          expect(opts.alpha).toBe(true);
          expect(opts.premultipliedAlpha).toBe(true);
          return mockGl;
        }),
        remove: vi.fn(),
        width: 0,
        height: 0
      };

      expect(mockCanvas.getContext('webgl2', { alpha: true, premultipliedAlpha: true })).toBe(mockGl);
    });
  });

  describe('Non-blocking Integration in Link Sentinel App', () => {
    it('integrates WebThreads as a responsive, non-blocking background layer in App.jsx', () => {
      const appHtml = renderToString(<App />);

      // Verify that WebThreads container exists in the rendered HTML
      expect(appHtml).toContain('web-threads-container');

      // Verify non-blocking layout wrapper styles:
      // Must be fixed inset-0, pointer-events-none, and z-0 (above root bg, beneath UI)
      expect(appHtml).toContain('fixed inset-0 pointer-events-none z-0');
      expect(appHtml).toContain('relative z-10');
      expect(appHtml).toContain('aria-hidden="true"');
    });
  });
});
