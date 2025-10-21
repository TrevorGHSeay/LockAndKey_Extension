
let signedData = null;
let safeName = null;
const button = document.getElementById('selectFile');
const statusDiv = document.getElementById('status');

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  const binary = [];
  for (let i = 0; i < len; i++) {
    binary.push(String.fromCharCode(bytes[i]));
  }
  return btoa(binary.join(''));
}

function base64ToUint8Array(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function resetUI() {
  button.textContent = 'Select File to Sign';
  button.onclick = handleSelectFile;
  signedData = null;
  safeName = null;
  statusDiv.textContent = '';
}

async function handleSaveFile() {
  if (!signedData || !safeName) {
    statusDiv.textContent = 'No signed data available.';
    return;
  }

  try {
    const saveOptions = {
      suggestedName: safeName,
      types: [
        {
          description: 'Safe File',
          accept: {'application/octet-stream': ['.safe']}
        }
      ]
    };
    const saveHandle = await window.showSaveFilePicker(saveOptions);
    const writable = await saveHandle.createWritable();
    await writable.write(new Blob([signedData]));
    await writable.close();

    statusDiv.textContent = `File signed and saved as ${safeName}.`;
    resetUI();
  } catch (error) {
    console.error('Save failed:', error);
    statusDiv.textContent = 'Save failed: ' + error.message;
    // Don't reset on error, allow retry
  }
}

async function handleSelectFile() {
  try {
    const [fileHandle] = await window.showOpenFilePicker({
      multiple: false,
      types: [
        {
          description: 'All Files',
          accept: {'*/*': []}
        }
      ]
    });

    const file = await fileHandle.getFile();
    const fileContent = await file.arrayBuffer();
    const fileName = file.name;
    const fileSize = file.size;

    // Prompt for password
    const password = prompt('Enter password to decrypt private key:');
    if (!password) {
      statusDiv.textContent = 'Password required.';
      return;
    }

    const fileBase64 = arrayBufferToBase64(fileContent);

    // Send to background.js for signing using pkiHelper
    chrome.runtime.sendMessage({
      type: 'signFile',
      fileBase64,
      fileName,
      password,
      fileSize
    }, (response) => {

      if (chrome.runtime.lastError) {
        statusDiv.textContent = 'Error: ' + chrome.runtime.lastError.message;
        return;
      }

      else if (response.success) {
        signedData = base64ToUint8Array(response.signedContent);
        safeName = response.safeName;
        button.textContent = 'Save Signed File As...';
        button.onclick = handleSaveFile;
        statusDiv.textContent = 'Signing complete. Click the button to save the file.';
      }

      else
        statusDiv.textContent = 'Error: ' + response.error;
      
    });
  } catch (error) {
    console.error('File selection failed:', error);
    statusDiv.textContent = 'File selection failed: ' + error.message;
  }
}

// Initial setup
button.onclick = handleSelectFile;