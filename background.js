// background.js - Updated: Listen for setupDetails message from setup.html
// Validates downloads using DownloadValidator and PkiHelper

const baseUrl = "http://192.168.43.129:80/";

importScripts('pki_utils.js'); 
importScripts('PkiHelper.js');
importScripts('DownloadValidator.js');

const trackedDownloads = new Set();
const SIGNATURE_SIZE = 256;
const MIN_BYTES_FOR_BASIC_CHECK = SIGNATURE_SIZE;

let pkiHelper;
let downloadValidator;

// Initialize after DOM ready (service worker style)
chrome.runtime.onStartup.addListener(() => {
  pkiHelper = new PkiHelper();
  downloadValidator = new DownloadValidator();
});

// Listen for download creation
chrome.downloads.onCreated.addListener((downloadItem) => {
  const { id, url, filename, state } = downloadItem;
  if (state !== 'in_progress') return;

  trackedDownloads.add(id);

  // Pause download for validation
  chrome.downloads.pause(id, async () => {
    try {
      // Wait for validator to be ready (with timeout fallback)
      while (!downloadValidator.isReady && !pkiHelper.#certificate) {
        await new Promise(resolve => setTimeout(resolve, 500));
        if (Date.now() - startTime > 10000) { // 10s timeout
          chrome.downloads.resume(id);
          return;
        }
      }

      // Domain check
      if (!downloadValidator.domainPermitted(url)) {
        chrome.downloads.cancel(id);
        trackedDownloads.delete(id);
        return;
      }

      // Get file extension
      let fileExtension = '';
      if (filename) {
        const parts = filename.split('.');
        if (parts.length > 1) fileExtension = parts[parts.length - 1].toLowerCase();
      } else {
        const urlParts = new URL(url).pathname.split('.');
        if (urlParts.length > 1) fileExtension = urlParts[urlParts.length - 1].toLowerCase();
      }

      // Format check
      if (downloadValidator.formatPermitted(fileExtension)) {
        chrome.downloads.resume(id);
        trackedDownloads.delete(id);
        return;
      }

      // Fetch file for signature validation
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const buffer = await response.arrayBuffer();
      const fileBuffer = new Uint8Array(buffer);

      if (fileBuffer.length < MIN_BYTES_FOR_BASIC_CHECK) {
        throw new Error('File too small for signature');
      }

      const signature = fileBuffer.slice(0, SIGNATURE_SIZE);
      const originalContent = fileBuffer.slice(SIGNATURE_SIZE);
      const checksum = await crypto.subtle.digest('SHA-256', originalContent);

      // Client-side basic signature check using PkiHelper
      const sigValid = await downloadValidator.basicSignatureCheck(originalContent, signature, new Uint8Array(checksum));
      if (!sigValid) {
        throw new Error('Basic signature invalid');
      }

      // Server-side CA validation
      // Note: Access to private #certificate; in production, add public getter to PkiHelper
      const certPem = pkiHelper.#certificate;
      if (!certPem) throw new Error('Certificate not loaded');

      // Adjusted call: pass originalContent, signature, certPem
      // Assumes validateWithServer updated to accept/handle these (see note below)
      const caResult = await downloadValidator.validateWithServer(originalContent, signature, certPem);
      if (!caResult.valid) {
        throw new Error(`CA validation failed: ${caResult.reasons.join(', ')}`);
      }

      // All checks passed
      chrome.downloads.resume(id);
    } catch (error) {
      console.error('Download validation failed:', error);
      chrome.downloads.cancel(id);
    } finally {
      trackedDownloads.delete(id);
    }
  });
});

// Optional: Clean up on download changed
chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state && delta.state.current === 'complete') {
    const id = delta.id;
    if (trackedDownloads.has(id)) {
      trackedDownloads.delete(id);
    }
  }
});

// Note: To fully integrate, update DownloadValidator.validateWithServer to:
// async validateWithServer(originalContent, sigBuffer, certPem) {
//   ...
//   formData.append('fileToUpload', new Blob([originalContent]), 'file.dat');
//   formData.append('fileToUploadSig', new Blob([sigBuffer]), 'file.sig');
//   formData.append('fileToUploadX509', new Blob([certPem], { type: 'text/plain' }), 'cert.pem');
//   ...
// }
// And add to PkiHelper: getCertificate() { return this.#certificate; } then use pkiHelper.getCertificate()
// Also, fix this.baseURL in DownloadValidator by setting this.baseURL = baseUrl; in constructor.