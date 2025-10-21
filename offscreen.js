chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type !== 'create-clean-download')
    return true;

  try {

    // Only allow bytes to pass
    if (!Array.isArray(message.originalContentBytes))
      throw new Error('Expected originalContentBytes as Array of numbers');
  
    const bytes = new Uint8Array(message.originalContentBytes);
    const blob = new Blob([bytes.buffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);

    sendResponse({ objectUrl: url });

    // Revoke after 1 hour to free memory
    setTimeout(() => URL.revokeObjectURL(url), 60_000 * 60);
  }
  catch (err) {
    sendResponse({ error: err.message || String(err) });
  }

  return true;

});
