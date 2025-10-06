// pki_utils.js - Fixed: Derive publicKey explicitly from private key components to ensure 'n' is set

if (typeof window === 'undefined') {
  self.window = self;
  self.document = {};
  self.navigator = {
    userAgent: 'Mozilla/5.0 (compatible; Chrome Extension Service Worker)'
  };
  if (!self.window.crypto) {
    self.window.crypto = self.crypto;
  }
}

importScripts('forge.min.js');

// Utility Functions (retained but not critical for core ops)
function pemToArrayBuffer(pem) {
  const binaryString = atob(pem.replace(/-----BEGIN [A-Z0-9\s-]+-----|-----END [A-Z0-9\s-]+-----|\n|\r/g, ''));
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function stringToArrayBuffer(str) {
  return new TextEncoder().encode(str);
}

// Generate Encrypted Private Key (uses built-in encryptRsaPrivateKey for AES-128-CBC + PBKDF2)
function generateEncryptedPrivateKey(passphrase) {  // Sync
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  
  // Encrypt using built-in (default: AES-128, 1000 iterations PBKDF2)
  const encryptedPrivatePem = forge.pki.encryptRsaPrivateKey(keys.privateKey, passphrase, {
    algorithm: 'aes128'
  });

  const publicPem = forge.pki.publicKeyToPem(keys.publicKey);
  return { encryptedPrivatePem, publicPem };
}

// Decrypt Encrypted Private Key (uses built-in; returns key object, not PEM)
function decryptEncryptedPrivateKey(encryptedPem, passphrase) {
  return forge.pki.decryptRsaPrivateKey(encryptedPem, passphrase);
}

// Create CSR (derives publicKey explicitly from private key's n/e to ensure properties are set)
function createCSR(encryptedPrivatePem, passphrase, subjectDetails) {
  const privateKey = decryptEncryptedPrivateKey(encryptedPrivatePem, passphrase);

  // Explicitly derive public key from private key components (ensures 'n' and 'e' are accessible)
  const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);

  const attrs = [
    { name: 'commonName', value: subjectDetails.CN || 'Client' },
    { name: 'organizationName', value: subjectDetails.O || 'YourOrg' },
    { name: 'stateOrProvinceName', value: subjectDetails.SP || 'New York' },
    { shortName: 'C', value: subjectDetails.C || 'US' }
  ];

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = publicKey;
  csr.setSubject(attrs);
  csr.sign(privateKey, forge.md.sha256.create());

  return forge.pki.certificationRequestToPem(csr);
}