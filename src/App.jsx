import React, { useState } from 'react';
import Header from './ui/Header';
import InputCard from './ui/InputCard';
import ResultPanel from './ui/ResultPanel';
import EmptyState from './ui/EmptyState';
import ErrorState from './ui/ErrorState';
import Footer from './ui/Footer';
import { analyze } from './engine';

export default function App() {
  const [inputVal, setInputVal] = useState('');
  const [status, setStatus] = useState('idle'); // 'idle' | 'result' | 'error'
  const [resultData, setResultData] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [errorType, setErrorType] = useState('link'); // 'link' | 'qr' | 'both'
  const [qrPlaceholderNotice, setQrPlaceholderNotice] = useState('');

  // Handles typing and pasting: immediately runs link analysis when valid
  const handleInputChange = (newVal) => {
    setInputVal(newVal);
    setQrPlaceholderNotice('');
    const targetUrl = typeof newVal === 'string' ? newVal.trim() : '';

    if (!targetUrl) {
      setStatus('idle');
      setResultData(null);
      setErrorMessage('');
      return;
    }

    try {
      const result = analyze(targetUrl);
      setResultData(result);
      setStatus('result');
      setErrorMessage('');
    } catch {
      // While typing an incomplete URL, keep current view without interrupting
    }
  };

  // Executes link analysis through the single analyze() integration point
  const handleAnalyze = (urlToAnalyze = inputVal) => {
    setQrPlaceholderNotice('');
    const targetUrl = typeof urlToAnalyze === 'string' ? urlToAnalyze.trim() : inputVal.trim();

    if (!targetUrl) {
      setErrorMessage('Please enter a valid link.');
      setErrorType('link');
      setStatus('error');
      setResultData(null);
      return;
    }

    try {
      const result = analyze(targetUrl);
      setResultData(result);
      setStatus('result');
      setErrorMessage('');
    } catch (err) {
      setErrorMessage(err.message || 'Please enter a valid link.');
      setErrorType('link');
      setStatus('error');
      setResultData(null);
    }
  };

  // Handles clicking any example chip
  const handleSelectSample = (sampleUrl) => {
    setInputVal(sampleUrl);
    handleAnalyze(sampleUrl);
  };

  // Clears input and returns UI to idle empty state
  const handleClear = () => {
    setInputVal('');
    setStatus('idle');
    setResultData(null);
    setErrorMessage('');
    setQrPlaceholderNotice('');
  };

  // Handles QR image file upload
  const handleQrUpload = (file) => {
    if (!file) return;

    // Read the image file client-side as ArrayBuffer / DataURL
    const reader = new FileReader();

    reader.onload = () => {
      // TODO: Connect jsQR barcode decoder here.
      // Once integrated, pass the image imageData to jsQR(imageData.data, width, height),
      // extract the decoded URL string, setInputVal(decodedUrl), and call handleAnalyze(decodedUrl).
      // If decoding fails, setErrorType('qr') and setErrorMessage('No QR code found in this image.').

      setQrPlaceholderNotice(
        `QR decoding will be connected here (Read ${file.name}, ${Math.round(file.size / 1024)} KB)`
      );
    };

    reader.onerror = () => {
      setErrorType('qr');
      setErrorMessage('No QR code found in this image.');
      setStatus('error');
    };

    reader.readAsDataURL(file);
  };

  return (
    <div className="bg-[#070d18] text-on-surface min-h-screen flex flex-col justify-between selection:bg-primary-container selection:text-on-primary-container">
      {/* 1. Header */}
      <Header />

      {/* 2. Main 2-Column Application Layout */}
      <main className="w-full flex-1 max-w-[1280px] mx-auto px-4 sm:px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* LEFT COLUMN: Input Section (Mobile-first, 12 cols on mobile, 5 cols on lg) */}
          <section className="lg:col-span-5 flex flex-col gap-6" aria-label="Input Section">
            <InputCard
              value={inputVal}
              onChange={handleInputChange}
              onAnalyze={() => handleAnalyze()}
              onClear={handleClear}
              onQrUpload={handleQrUpload}
              onSelectSample={handleSelectSample}
            />

            {/* QR Notice banner when file is read */}
            {qrPlaceholderNotice && (
              <div
                role="status"
                className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/40 text-cyan-200 text-sm flex items-center justify-between gap-3 shadow-lg"
              >
                <div className="flex items-center gap-2.5">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shrink-0" aria-hidden="true" />
                  <span>{qrPlaceholderNotice}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setQrPlaceholderNotice('')}
                  className="text-xs font-mono text-cyan-400 hover:text-white px-2 py-1 rounded border border-cyan-500/30 min-h-[36px]"
                >
                  Dismiss
                </button>
              </div>
            )}
          </section>

          {/* RIGHT COLUMN: Result Section (12 cols on mobile, 7 cols on lg) */}
          <section
            className="lg:col-span-7 flex flex-col gap-4"
            aria-label="Inspection Results"
            aria-live="polite"
          >
            {status === 'idle' && <EmptyState />}
            {status === 'error' && (
              <ErrorState errorType={errorType} message={errorMessage} />
            )}
            {status === 'result' && resultData && (
              <ResultPanel result={resultData} />
            )}
          </section>
        </div>
      </main>

      {/* 3. Footer */}
      <Footer />
    </div>
  );
}
