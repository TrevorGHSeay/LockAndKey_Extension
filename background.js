// background.js - Updated to handle sync errors in sign for proper sendResponse.

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


const baseUrl = "http://192.168.43.129:80/";

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
    } catch (error) {
      sendResponse({success: false, error: 'Failed to decode file content: ' + error.message});
      return true;
    }
    try {
      pkiHelper.sign(message.fileName, fileContent, message.password, message.fileSize).then((result) => {
        sendResponse(result);
      }).catch((error) => {
        sendResponse({success: false, error: 'Signing failed: ' + error.message});
      });
    } catch (error) {
      sendResponse({success: false, error: 'Signing failed: ' + error.message});
    }
    return true; // Keep channel open for async
  }
  // Existing code for other messages...
  return true;
});




// Listen for download creation
chrome.downloads.onCreated.addListener((downloadItem) => {
  console.log("Download started: " + downloadItem.fileName);
  const { id, url, state } = downloadItem;
  if (state !== 'in_progress') return;
  
  const filename = downloadItem.filename || url.substring(url.lastIndexOf("/") + 1);

  // Pause immediately
  chrome.downloads.pause(id, async () => {
    console.log("Download paused: " + downloadItem.fileName);
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

      // Domain check
      if (!downloadValidator.domainPermitted(url))
        throw new Error('Domain not permitted');

      console.log("Domain permitted");

      const isSigned = filename && filename.endsWith('.safe');

      if (!isSigned) {
        // Check format for non-.safe
        let fileExtension = '';
        if (filename) {
          const parts = filename.split('.');
          if (parts.length > 1) fileExtension = parts[parts.length - 1].toLowerCase();
        }
        else {
          const urlParts = new URL(url).pathname.split('.');
          if (urlParts.length > 1) fileExtension = urlParts[urlParts.length - 1].toLowerCase();
        }
        if (!downloadValidator.formatPermitted(fileExtension)) {
          throw new Error('Format not permitted');
        }
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

// Handle download changes
chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state && delta.state.current === 'complete' && trackedDownloads.has(delta.id)) {
    const id = delta.id;
    const info = trackedDownloads.get(id);
    trackedDownloads.delete(id);

    if (!info.filename.endsWith('.safe')) {
      // Unsigned approved download: leave as is
      return;
    }

    // Get local filename
    chrome.downloads.search({id}, async (items) => {
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
          if (chrome.runtime.lastError) {
            console.error('Failed to remove original file:', chrome.runtime.lastError);
          }
        });

        // Hide from download history (optional)
        chrome.downloads.erase({id});

        // Save clean content to same directory without .safe
        const dir = localPath.substring(0, localPath.lastIndexOf('/') + 1);
        const cleanPath = dir + result.cleanFilename;

        const blob = new Blob([result.originalContent]);
        const objectUrl = URL.createObjectURL(blob);

        chrome.downloads.download({
          url: objectUrl,
          filename: cleanPath,
          conflictAction: 'overwrite',
          saveAs: false
        }, (newDownloadId) => {
          if (chrome.runtime.lastError) {
            console.error('Failed to initiate clean download:', chrome.runtime.lastError);
          } else {
            console.log('Clean download started:', newDownloadId);
            // Immediately erase from history to hide the download entry
            chrome.downloads.erase({id: newDownloadId}, () => {
              if (chrome.runtime.lastError) {
                console.error('Failed to erase clean download from history:', chrome.runtime.lastError);
              }
            });
          }
          URL.revokeObjectURL(objectUrl);
        });
      } catch (error) {
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