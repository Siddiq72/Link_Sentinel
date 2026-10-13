import { describe, it, expect, vi } from 'vitest';
import { decodeQrImage } from '../src/qr/decodeQr.js';

describe('QR Code Decoder (Client-Side)', () => {
  it('rejects on null or non-Blob input', async () => {
    await expect(decodeQrImage(null)).rejects.toThrow('Please select a valid image file.');
    await expect(decodeQrImage('not-a-file')).rejects.toThrow('Please select a valid image file.');
  });

  it('rejects with "No readable QR code found" when jsQR detects no matrix', async () => {
    // Setup mock browser globals
    const origFileReader = globalThis.FileReader;
    const origImage = globalThis.Image;
    const origDocument = globalThis.document;

    try {
      class MockFileReader {
        readAsDataURL() {
          setTimeout(() => {
            this.result = 'data:image/png;base64,mock';
            if (this.onload) this.onload();
          }, 0);
        }
      }

      class MockImage {
        constructor() {
          this.naturalWidth = 200;
          this.naturalHeight = 200;
        }
        set src(val) {
          this._src = val;
          if (val) {
            setTimeout(() => {
              if (this.onload) this.onload();
            }, 0);
          }
        }
        get src() {
          return this._src;
        }
      }

      const mockCtx = {
        drawImage: vi.fn(),
        getImageData: vi.fn(() => ({
          data: new Uint8ClampedArray(200 * 200 * 4),
          width: 200,
          height: 200
        }))
      };

      const mockCanvas = {
        width: 0,
        height: 0,
        getContext: vi.fn(() => mockCtx)
      };

      globalThis.FileReader = MockFileReader;
      globalThis.Image = MockImage;
      globalThis.document = {
        createElement: vi.fn((tag) => (tag === 'canvas' ? mockCanvas : {}))
      };

      const fakeBlob = new Blob([''], { type: 'image/png' });
      await expect(decodeQrImage(fakeBlob)).rejects.toThrow('No readable QR code found');
    } finally {
      globalThis.FileReader = origFileReader;
      globalThis.Image = origImage;
      globalThis.document = origDocument;
    }
  });

  it('downscales images exceeding 1000px dimension maintaining aspect ratio', async () => {
    const origFileReader = globalThis.FileReader;
    const origImage = globalThis.Image;
    const origDocument = globalThis.document;

    try {
      class MockFileReader {
        readAsDataURL() {
          setTimeout(() => {
            this.result = 'data:image/jpeg;base64,mock';
            if (this.onload) this.onload();
          }, 0);
        }
      }

      class MockImage {
        constructor() {
          // Large 2000 x 1500 image
          this.naturalWidth = 2000;
          this.naturalHeight = 1500;
        }
        set src(val) {
          this._src = val;
          if (val) {
            setTimeout(() => {
              if (this.onload) this.onload();
            }, 0);
          }
        }
        get src() {
          return this._src;
        }
      }

      let assignedWidth = 0;
      let assignedHeight = 0;

      const mockCtx = {
        drawImage: vi.fn(),
        getImageData: vi.fn(() => ({
          data: new Uint8ClampedArray(1000 * 750 * 4),
          width: 1000,
          height: 750
        }))
      };

      const mockCanvas = {
        set width(w) {
          if (w > 0) assignedWidth = w;
        },
        set height(h) {
          if (h > 0) assignedHeight = h;
        },
        getContext: vi.fn(() => mockCtx)
      };

      globalThis.FileReader = MockFileReader;
      globalThis.Image = MockImage;
      globalThis.document = {
        createElement: vi.fn(() => mockCanvas)
      };

      const fakeBlob = new Blob([''], { type: 'image/jpeg' });
      try {
        await decodeQrImage(fakeBlob);
      } catch {
        // Expected "No readable QR code found"
      }

      // 2000x1500 scaled down with max 1000 should be 1000x750
      expect(assignedWidth).toBe(1000);
      expect(assignedHeight).toBe(750);
    } finally {
      globalThis.FileReader = origFileReader;
      globalThis.Image = origImage;
      globalThis.document = origDocument;
    }
  });

  it('runs multi-pass contrast and threshold fallback passes when initial pass fails', async () => {
    const origFileReader = globalThis.FileReader;
    const origImage = globalThis.Image;
    const origDocument = globalThis.document;

    try {
      class MockFileReader {
        readAsDataURL() {
          setTimeout(() => {
            this.result = 'data:image/jpeg;base64,mock';
            if (this.onload) this.onload();
          }, 0);
        }
      }

      class MockImage {
        constructor() {
          this.naturalWidth = 800;
          this.naturalHeight = 600;
        }
        set src(val) {
          this._src = val;
          if (val) {
            setTimeout(() => {
              if (this.onload) this.onload();
            }, 0);
          }
        }
        get src() {
          return this._src;
        }
      }

      // Track that canvas was read
      const getImageDataMock = vi.fn(() => ({
        data: new Uint8ClampedArray(800 * 600 * 4).fill(120),
        width: 800,
        height: 600
      }));

      const mockCtx = {
        drawImage: vi.fn(),
        getImageData: getImageDataMock
      };

      const mockCanvas = {
        width: 800,
        height: 600,
        getContext: vi.fn(() => mockCtx)
      };

      globalThis.FileReader = MockFileReader;
      globalThis.Image = MockImage;
      globalThis.document = {
        createElement: vi.fn(() => mockCanvas)
      };

      const fakeBlob = new Blob(['mock'], { type: 'image/jpeg' });
      await expect(decodeQrImage(fakeBlob)).rejects.toThrow('No readable QR code found');
      expect(getImageDataMock).toHaveBeenCalled();
    } finally {
      globalThis.FileReader = origFileReader;
      globalThis.Image = origImage;
      globalThis.document = origDocument;
    }
  });
});
