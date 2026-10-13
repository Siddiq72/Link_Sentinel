import React, { useState } from 'react';
import Header from './ui/Header';
import InputCard from './ui/InputCard';
import ResultPanel from './ui/ResultPanel';
import EmptyState from './ui/EmptyState';
import ErrorState from './ui/ErrorState';
import Footer from './ui/Footer';
import SelfTestModal from './ui/SelfTestModal';
import { analyze } from './engine';
import { decodeQrImage } from './qr/decodeQr';
import { AlertCircleIcon } from './ui/icons';

export default function App() {
  const [inputVal, setInputVal] = useState('');
  const [status, setStatus] = useState('idle'); // 'idle' | 'result' | 'error'
  const [resultData, setResultData] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [errorType, setErrorType] = useState('link'); // 'link' | 'qr' | 'both'
  const [isQrLoading, setIsQrLoading] = useState(false);
  const [qrError, setQrError] = useState('');
  const [qrSuccessNotice, setQrSuccessNotice] = useState('');
  const [isSelfTestOpen, setIsSelfTestOpen] = useState(false);

  // Handles typing and pasting: immediately runs link analysis when valid
  const handleInputChange = (newVal) => {
    setInputVal(newVal);
    setQrError('');
    setQrSuccessNotice('');
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
    setQrError('');
    const targetUrl = typeof urlToAnalyze === 'string' ? urlToAnalyze.trim() : inputVal.trim();

    if (!targetUrl) {
      handleClear();
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
    setQrError('');
    setQrSuccessNotice('');
    handleAnalyze(sampleUrl);
  };

  // Clears input and returns UI to idle empty state
  const handleClear = () => {
    setInputVal('');
    setStatus('idle');
    setResultData(null);
    setErrorMessage('');
    setQrError('');
    setQrSuccessNotice('');
  };

  // Handles QR image file upload and client-side barcode decoding
  const handleQrUpload = async (file) => {
    if (!file) return;

    setQrError('');
    setQrSuccessNotice('');
    setIsQrLoading(true);

    try {
      const decodedText = await decodeQrImage(file);
      setInputVal(decodedText);
      handleAnalyze(decodedText);
      setQrSuccessNotice(`QR code decoded successfully: ${decodedText}`);
    } catch (err) {
      const msg = err?.message || 'No readable QR code found';
      setQrError(msg);
    } finally {
      setIsQrLoading(false);
    }
  };

  return (
    <div className="bg-[#070d18] text-on-surface min-h-screen flex flex-col justify-between selection:bg-primary-container selection:text-on-primary-container">
      {/* 1. Header */}
      <Header onOpenSelfTest={() => setIsSelfTestOpen(true)} />

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
              isQrLoading={isQrLoading}
            />

            {/* Dismissible QR Scan Error banner */}
            {qrError && (
              <div
                role="alert"
                className="p-4 rounded-xl bg-red-950/60 border border-red-500/50 text-red-200 text-sm flex items-center justify-between gap-3 shadow-lg"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <AlertCircleIcon className="w-5 h-5 text-red-400 shrink-0" />
                  <div className="flex flex-col min-w-0">
                    <span className="font-bold text-red-300">QR Scan Failed</span>
                    <span className="text-xs text-red-200/90 truncate">{qrError}</span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setQrError('')}
                  className="text-xs font-mono text-red-300 hover:text-white px-2.5 py-1.5 rounded-lg border border-red-500/40 bg-red-900/40 hover:bg-red-900/70 min-h-[36px] cursor-pointer shrink-0 transition-colors"
                >
                  Dismiss
                </button>
              </div>
            )}

            {/* Dismissible QR Success banner */}
            {qrSuccessNotice && (
              <div
                role="status"
                className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/40 text-cyan-200 text-sm flex items-center justify-between gap-3 shadow-lg"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shrink-0" aria-hidden="true" />
                  <span className="text-xs sm:text-sm font-mono truncate">{qrSuccessNotice}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setQrSuccessNotice('')}
                  className="text-xs font-mono text-cyan-400 hover:text-white px-2 py-1 rounded border border-cyan-500/30 min-h-[36px] cursor-pointer shrink-0"
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

      {/* 4. Evidence & Regression Self-Test Modal */}
      <SelfTestModal
        isOpen={isSelfTestOpen}
        onClose={() => setIsSelfTestOpen(false)}
      />
    </div>
  );
}
