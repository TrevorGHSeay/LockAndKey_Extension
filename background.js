// background.js - Fixed: Simplified offscreen messaging to avoid hanging on clean download

// Polyfill window for libraries expecting browser globals
if (typeof window === 'undefined') {
  self.window = self;
  self.document = {}; // Empty stub if DOM refs needed (Forge doesn't use it much)
  self.navigator = {
    userAgent: 'Mozilla/5.0 (compatible; Chrome Extension Service Worker)'
  };
  // Expose crypto if not already (available in workers, but shim for window.crypto)
  if (!self.window.crypto) {
    self.window.crypto = self.crypto;
  }
}

const baseUrl = "http://192.168.234.128:80/";

importScripts('pki_utils.js');
importScripts('PkiHelper.js');
importScripts('DownloadValidator.js');

const trackedDownloads = new Map();  // id -> {url, filename}
const SIGNATURE_SIZE = 256;

// Initialize sidePanel behaviour for file signing 
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch((error) => console.error(error));

var pkiHelper = new PkiHelper();
var downloadValidator = new DownloadValidator(baseUrl);

// Listen for messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'signFile') {

    let fileContent;
    try {
      fileContent = new Uint8Array(base64ToArrayBuffer(message.fileBase64));
    }
    catch (error) {
      sendResponse({success: false, error: 'Failed to decode file content: ' + error.message});
      return true;
    }

    try {
      pkiHelper.sign(message.fileName, fileContent, message.password, message.fileSize).then((result) => {
        sendResponse(result);
      }).catch((error) => {
        sendResponse({success: false, error: 'Signing failed: ' + error.message});
      });
    }
    catch (error) {
      sendResponse({success: false, error: 'Signing failed: ' + error.message});
    }
    return true; // Keep channel open for async

  }
  return true;
});

// Listen for download creation
chrome.downloads.onCreated.addListener((downloadItem) => {

  const { id, url, state } = downloadItem;
  if (state !== 'in_progress' || url.startsWith("blob:") )
    return;
  
  const filename = downloadItem.filename || url.substring(url.lastIndexOf("/") + 1);


  // Pause immediately
  chrome.downloads.pause(id, async () => {
    const startTime = Date.now();
    try {

      // Wait for validator to be ready
      while (!downloadValidator.isReady) {
        await new Promise(resolve => setTimeout(resolve, 500));
        if (Date.now() - startTime > 10000) { // 10s timeout
          chrome.downloads.resume(id);
          return;
        }
      }

      // Check if file identifies as signed
      const safeFile = filename && filename.endsWith('.safe');

      if(safeFile)
      {
        trackedDownloads.set(id, {url, filename});
        chrome.downloads.resume(id);
        return;
      }


      // Get the extention
      let fileExtension = '';
      if (filename) {
        const parts = filename.split('.');
        if (parts.length > 1)
          fileExtension = parts[parts.length - 1].toLowerCase();
      }
      else {
        const urlParts = new URL(url).pathname.split('.');
        if (urlParts.length > 1)
          fileExtension = urlParts[urlParts.length - 1].toLowerCase();
      }


      // Determine if we should be downloading
      var isDomain = downloadValidator.domainPermitted(url);
      var isFormat = downloadValidator.formatPermitted(fileExtension);

      if(!isDomain && !isFormat){
          if (!isDomain)
            throw new Error('Domain not permitted');
          if (!isFormat)
            throw new Error('Format not permitted');
      }

      trackedDownloads.set(id, {url, filename});
      chrome.downloads.resume(id);
    }
    catch (error) {
      console.error('Download validation failed:', error);
      chrome.downloads.cancel(id);
    }
  });
});

let offscreenCreated = false;

async function ensureOffscreen() {

  if(offscreenCreated)
    return;
  
  try {
    await chrome.offscreen.createDocument({
      url: 'offscreen.html',
      reasons: ['BLOBS'],
      justification: 'Generate blob URLs for secure file cleaning'
    });
    offscreenCreated = true;
  }
  catch (error) {
    console.error('Failed to create offscreen document:', error);
    throw error;
  }
}

async function initiateCleanDownload(originalContent, cleanPath) {

  await ensureOffscreen();

  // Normalize pathing (machine-agnostic) and get file with format at end
  const normPath = cleanPath.replaceAll('\\', '/');
  const fileName = normPath.split('/').pop();
  
  return new Promise((resolve, reject) => {

    // Convert incoming originalContent to a Uint8Array (handle ArrayBuffer or Uint8Array)
    let byteView;
    if (originalContent instanceof ArrayBuffer) 
      byteView = new Uint8Array(originalContent);
    
    else if (originalContent instanceof Uint8Array) 
      byteView = originalContent;
    
    else if (originalContent && originalContent.buffer instanceof ArrayBuffer)
      byteView = new Uint8Array(originalContent.buffer, originalContent.byteOffset, originalContent.byteLength);
    
    else // Fallback: try to coerce
      byteView = new Uint8Array(originalContent);
  

    chrome.runtime.sendMessage({
        type: 'create-clean-download',
        originalContentBytes: Array.from(byteView),
        cleanPath: fileName
      }, 
    
      (response) => {
        
        // Any errors? Reject
        var error = chrome.runtime.lastError || (response.error ? new Error(response.error) : null);
        if (error) {
          console.error('Offscreen error:', error);
          reject(error);
          return;
        }
        
        // Get url and download from it
        const objectUrl = response.objectUrl;
        
        chrome.downloads.download({
          url: objectUrl,
          filename: fileName,
          conflictAction: 'overwrite',
          saveAs: false
        },
        
        (newDownloadId) => {

          // Error? Reject
          if (chrome.runtime.lastError) {
            console.error('Download initiation failed:', chrome.runtime.lastError);
            reject(chrome.runtime.lastError);
          }
          else
            resolve(newDownloadId);

        });
    });
  });
}

// Handle download changes
chrome.downloads.onChanged.addListener((delta) => {

  if (delta.state && delta.state.current === 'complete' && trackedDownloads.has(delta.id)) {
    const id = delta.id;
    const info = trackedDownloads.get(id);
    trackedDownloads.delete(id);

    // Unsigned approved download: leave as is
    if (!info.filename.endsWith('.safe'))
      return;

    // Get local filename
    chrome.downloads.search({id}, async (items) => {

      // Skip if not found - just in case
      if (items.length === 0 || !items[0].exists) {
        console.error('Downloaded file not found:', id);
        return;
      }

      const localPath = items[0].filename;
      try {
        // Fetch local file content
        const response = await fetch(`file://${localPath}`);
        if (!response.ok)
          throw new Error(`Failed to fetch local file: ${response.status}`);
        
        const buffer = await response.arrayBuffer();
        const fileBuffer = new Uint8Array(buffer);

        // Validate
        const result = await downloadValidator.fullValidate(fileBuffer, info.filename);
        if (!result.valid) 
          throw new Error(`Validation failed: ${result.reasons.join(', ')}`);

        // Delete original file
        chrome.downloads.removeFile(id, () => {
          if (chrome.runtime.lastError)
            console.error('Failed to remove original file:', chrome.runtime.lastError);
        });

        // Hide from download history (like we were never even here)
        chrome.downloads.erase({id});

        // Save clean content to same directory without .safe
        const dir = localPath.replaceAll('\\', '/').split('/').pop();
        const cleanPath = dir + result.cleanFilename;

        await initiateCleanDownload(result.originalContent, cleanPath);

      }
      catch (error) {
        console.error('Post-download validation failed:', error);
        // Clean up on failure
        chrome.downloads.removeFile(id);
        chrome.downloads.erase({id});
      }
    });
  } else if (delta.state && (delta.state.current === 'interrupted' || delta.state.current === 'complete')) {
    // Remove from tracked if not handled
    trackedDownloads.delete(delta.id);
  }
});