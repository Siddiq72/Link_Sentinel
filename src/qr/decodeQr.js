/**
 * LINK SENTINEL - CLIENT-SIDE QR DECODER
 * 
 * Synchronous/client-side barcode detection using HTML5 off-screen canvas and jsQR.
 * Purely local execution without server uploads or telemetry.
 */

import jsQR from 'jsqr';

const MAX_CANVAS_DIMENSION = 1000;

/**
 * Enhances contrast and stretches luminance histogram for low-contrast camera captures.
 */
function enhanceContrast(data) {
  const output = new Uint8ClampedArray(data.length);
  let minLum = 255;
  let maxLum = 0;

  for (let i = 0; i < data.length; i += 4) {
    const lum = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
    if (lum < minLum) minLum = lum;
    if (lum > maxLum) maxLum = lum;
  }

  const range = maxLum - minLum || 1;
  for (let i = 0; i < data.length; i += 4) {
    const lum = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
    const normalized = Math.round(((lum - minLum) / range) * 255);
    output[i] = normalized;
    output[i + 1] = normalized;
    output[i + 2] = normalized;
    output[i + 3] = data[i + 3];
  }
  return output;
}

/**
 * High-contrast binarization thresholding pass for camera photos with glare or shadows.
 */
function binarizeThreshold(data) {
  const output = new Uint8ClampedArray(data.length);
  let sum = 0;
  const count = data.length / 4;

  for (let i = 0; i < data.length; i += 4) {
    sum += (0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
  }
  const threshold = sum / count;

  for (let i = 0; i < data.length; i += 4) {
    const lum = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
    const val = lum > threshold ? 255 : 0;
    output[i] = val;
    output[i + 1] = val;
    output[i + 2] = val;
    output[i + 3] = 255;
  }
  return output;
}

/**
 * Decodes a QR code from a File or Blob client-side.
 * 
 * @param {File|Blob} file - The image file (png, jpg, jpeg, webp) containing a QR code.
 * @returns {Promise<string>} The decoded payload text.
 * @throws {Error} If the image cannot be read or no valid QR code is detected.
 */
export async function decodeQrImage(file) {
  if (!file || !(file instanceof Blob)) {
    throw new Error('Please select a valid image file.');
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = () => {
      const img = new Image();

      img.onload = () => {
        let canvas = null;
        try {
          let width = img.naturalWidth || img.width;
          let height = img.naturalHeight || img.height;

          if (!width || !height) {
            img.src = '';
            reject(new Error('Invalid image dimensions.'));
            return;
          }

          // Downscale to prevent main-thread UI jank if width or height exceeds 1000px
          if (width > MAX_CANVAS_DIMENSION || height > MAX_CANVAS_DIMENSION) {
            const scale = Math.min(MAX_CANVAS_DIMENSION / width, MAX_CANVAS_DIMENSION / height);
            width = Math.max(1, Math.round(width * scale));
            height = Math.max(1, Math.round(height * scale));
          }

          canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;

          const ctx = canvas.getContext('2d', { willReadFrequently: true });
          if (!ctx) {
            img.src = '';
            canvas.width = 0;
            canvas.height = 0;
            reject(new Error('Unable to initialize canvas context.'));
            return;
          }

          ctx.drawImage(img, 0, 0, width, height);
          const imageData = ctx.getImageData(0, 0, width, height);

          // Release image memory
          img.src = '';

          // Scan QR code with multi-pass strategy for robust camera photo decoding
          // Pass 1: Standard raw RGB scan with both inversion attempts
          let code = jsQR(imageData.data, width, height, {
            inversionAttempts: 'attemptBoth'
          });

          // Pass 2: Contrast and grayscale stretch fallback for low-contrast camera photos
          if (!code) {
            const contrastData = enhanceContrast(imageData.data);
            code = jsQR(contrastData, width, height, {
              inversionAttempts: 'attemptBoth'
            });
          }

          // Pass 3: Grayscale threshold / binarization fallback for shadowed or uneven camera lighting
          if (!code) {
            const thresholdData = binarizeThreshold(imageData.data);
            code = jsQR(thresholdData, width, height, {
              inversionAttempts: 'attemptBoth'
            });
          }

          // Release canvas backing buffer
          canvas.width = 0;
          canvas.height = 0;
          canvas = null;

          if (code && typeof code.data === 'string' && code.data.trim()) {
            resolve(code.data.trim());
          } else {
            reject(new Error('No readable QR code found'));
          }
        } catch (err) {
          if (img) img.src = '';
          if (canvas) {
            canvas.width = 0;
            canvas.height = 0;
          }
          reject(err instanceof Error ? err : new Error('No readable QR code found'));
        }
      };

      img.onerror = () => {
        img.src = '';
        reject(new Error('Unable to load image file.'));
      };

      img.src = reader.result;
    };

    reader.onerror = () => {
      reject(new Error('Failed to read image file.'));
    };

    reader.readAsDataURL(file);
  });
}

export default decodeQrImage;
