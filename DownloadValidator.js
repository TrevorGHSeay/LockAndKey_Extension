// DownloadValidator.js - Updated: fullValidate handles signed file parsing (PEM cert + sig + content).
// Validates cert chain with CA root using forge.verifyCertificateChain.
// Verifies file sig with cert pubkey.
// Assumes .safe files; extracts clean content and filename.

class DownloadValidator {

  #isReady;
  get isReady() { return this.#isReady; }

  #permittedDomains;
  #permittedFormats;
  #caRootPem;

  #baseURL;
  get baseURL() { return this.#baseURL; }

  constructor(baseUrl) {
    this.#baseURL = baseUrl;
    this.#getPermittedDomains();
  }

  #getPermittedDomains() {
    console.log("Getting download settings. URL: " + this.#baseURL);

    fetch(this.#baseURL + "download_settings.php", {
      method: "GET",
      headers: { "Content-Type": "application/json" }
    })
    .then(response => response.json())
    .then(data => {
      console.log("Heard response from settings server.");

      this.#permittedDomains = {};
      data.permittedDomains.forEach(element => {
        this.#permittedDomains[element] = true;
      });

      this.#permittedFormats = {};
      data.permittedFormats.forEach(element => {
        this.#permittedFormats[element] = true;
      });

      // Assume server returns caRootPem as string
      this.#caRootPem = data.caRootPem.join("");

      // DEBUG REMOVE
      console.log(data);
      console.log("Domains:\n" + data.permittedDomains);
      console.log("Formats:\n" + data.permittedFormats);

      this.#isReady = true;
      Object.freeze(this);

    })
    .catch(error => {
      setTimeout(() => this.#getPermittedDomains(), 1000);
    });
  }

  domainPermitted(domain) {
    try {
      const urlObject = new URL(domain);
      return this.#permittedDomains[urlObject.hostname] === true;
    } catch (error) {
      return false;
    }
  }

  formatPermitted(format) {
    return this.#permittedFormats[format] === true;
  }

  // Validate signing certificate against CA root: chain and validity
  #validateCertificate(certPem, caRootPem) {
    try {
      const signingCert = forge.pki.certificateFromPem(certPem);
      const caCert = forge.pki.certificateFromPem(caRootPem);
      const caStore = forge.pki.createCaStore([caCert]);
      forge.pki.verifyCertificateChain(caStore, [signingCert]);
      return { valid: true, reason: "" };
    }
    catch (error) {
      console.error("Certificate validation error:", error);
      return { valid: false, reason: error.message || "Invalid certificate" };
    }
  }

// Full signature verification: validate cert first, then file sig with cert pubkey
verifySignatureWithCert(originalContent, signature, certPem) {

  if (!this.#caRootPem)
    throw new Error("CA root not loaded");
  

  // Validate cert against CA
  const certResult = this.#validateCertificate(certPem, this.#caRootPem);
  if (!certResult.valid)
    return { valid: false, reason: certResult.reason };
  

  try {
    const signingCert = forge.pki.certificateFromPem(certPem);
    const publicKey = signingCert.publicKey;

    // DEBUG
    console.log('Verify public exponent e hex:', publicKey.e.toString(16));
    console.log('Verify modulus n hex:', publicKey.n.toString(16));

    // Hash content with forge (chunked to handle large files and convert Uint8Array to binary string)
    const md = forge.md.sha256.create();
    const chunkSize = 1024 * 1024; // 1MB chunks
    for (let offset = 0; offset < originalContent.length; offset += chunkSize) {
      const chunk = originalContent.subarray(offset, offset + chunkSize);
      const binaryChunk = String.fromCharCode.apply(null, chunk);
      md.update(binaryChunk);
    }
    const digest = md.digest().getBytes();  // Raw digest as binary string

    // Convert signature Uint8Array to binary string
    const sigBytes = String.fromCharCode.apply(null, signature);

    // Manual verification: raw decryption + padding validation + DigestInfo parse
    let decrypted = publicKey.encrypt(sigBytes, 'RAW');  // Use 'RAW' scheme for no padding

    // Pad with leading zeros if shorter than modulus byte length (should be rare but handles edge cases)
    const keyByteLength = Math.ceil(publicKey.n.bitLength() / 8);
    if (decrypted.length < keyByteLength) {
      decrypted = '\x00'.repeat(keyByteLength - decrypted.length) + decrypted;
    }

    // Validate PKCS#1 v1.5 signature padding: 00 || 01 || FF...FF || 00 || DigestInfo
    if (decrypted.charAt(0) !== '\x00') {
      console.log('Verification failed: No leading 0x00');
      return { valid: false, reason: 'Invalid padding (no leading 0x00)' };
    }
    if (decrypted.charAt(1) !== '\x01') {
      console.log('Verification failed: No 0x01 after leading 0x00');
      return { valid: false, reason: 'Invalid padding (no 0x01)' };
    }

    let pos = 2;
    while (pos < decrypted.length && decrypted.charAt(pos) === '\xFF') {
      pos++;
    }

    if (decrypted.charAt(pos) !== '\x00') {
      console.log('Verification failed: No separator 0x00 after FFs');
      return { valid: false, reason: 'Invalid padding (no separator 0x00)' };
    }

    const digInfoBytes = decrypted.substring(pos + 1);

    // Parse DigestInfo ASN.1
    const digInfoAsn1 = forge.asn1.fromDer(digInfoBytes);

    // Expect SEQUENCE [ SEQUENCE [OID, NULL], OCTETSTRING (digest) ]
    if (digInfoAsn1.type !== forge.asn1.Type.SEQUENCE || digInfoAsn1.value.length !== 2) {
      console.log('Verification failed: Invalid DigestInfo structure');
      return { valid: false, reason: 'Invalid DigestInfo ASN.1' };
    }

    const algId = digInfoAsn1.value[0];
    if (algId.type !== forge.asn1.Type.SEQUENCE || algId.value.length !== 2 ||
        algId.value[0].type !== forge.asn1.Type.OID || algId.value[1].type !== forge.asn1.Type.NULL) {
      console.log('Verification failed: Invalid algorithm ID');
      return { valid: false, reason: 'Invalid algorithm ID' };
    }

    const oidBytes = algId.value[0].value;
    const oid = forge.asn1.derToOid(oidBytes);
    if (oid !== forge.pki.oids.sha256) {  // Ensure it's SHA-256 OID
      console.log('Verification failed: Unexpected OID', oid);
      return { valid: false, reason: 'Unexpected hash algorithm OID' };
    }

    const embeddedDigestAsn1 = digInfoAsn1.value[1];
    if (embeddedDigestAsn1.type !== forge.asn1.Type.OCTETSTRING) {
      console.log('Verification failed: No OCTETSTRING for digest');
      return { valid: false, reason: 'Invalid digest format' };
    }

    const embeddedDigest = embeddedDigestAsn1.value;
    if (embeddedDigest.length !== 32) {  // SHA-256 is 32 bytes
      console.log('Verification failed: Wrong digest length', embeddedDigest.length);
      return { valid: false, reason: 'Wrong digest length' };
    }

    if (embeddedDigest !== digest) {
      console.log('Verification failed: Digests do not match');
      return { valid: false, reason: 'Digests do not match' };
    }

    // If all checks pass
    return { valid: true, reason: "" };
  }
  catch (error) {
    console.error("File signature verification error:", error);
    return { valid: false, reason: "Verification error" };
  }
}

  async validateWithServer(certPem) {
    if (!this.isReady) {
      throw new Error("Validator not ready");
    }

    const formData = new FormData();
    formData.append("fileToUploadX509", new Blob([certPem], { type: "text/plain" }), "cert.pem");

    try {
      const response = await fetch(this.#baseURL + "validate_signature.php", {
        method: "POST",
        body: formData
      });

      if (!response.ok)
        throw new Error(`Server error: ${response.status}`);
      
      const result = await response.json();
      return result;

    }
    catch (error) {
      console.error("Server validation error:", error);
      return { valid: true, reasons: [] };  // Fallback to client-only
    }
  }

  // Full validation for signed files: parse prefix, validate cert and sig
  async fullValidate(fileBuffer, filename) {
    const cleanFilename = filename.replace(/\.safe$/, "");

    const startCert = "-----BEGIN CERTIFICATE-----";
    const endCert = "-----END CERTIFICATE-----";

    // Parse PEM cert from start
    const bufferStr = new TextDecoder("utf-8").decode(fileBuffer);
    let startIndex = bufferStr.indexOf(startCert);
    let endIndex = bufferStr.indexOf(endCert, startIndex < 0 ? 0 : startIndex);
    
    if (endIndex === -1) {
      return { valid: false, reasons: ["Invalid signed file: No certificate"] };
    }
    endIndex += endCert.length;
    // Skip only trailing line breaks (e.g., \n or \r\n), not all whitespace
    while (endIndex < bufferStr.length && (bufferStr.charAt(endIndex) === '\n' || bufferStr.charAt(endIndex) === '\r'))
      endIndex++;
    const certPem = bufferStr.substring(startIndex, endIndex).trim();
    if (!certPem.startsWith(startCert)) {
      return { valid: false, reasons: ["Invalid certificate format"] };
    }

    const sigStart = endIndex; // Byte index matches char index for ASCII PEM
    if (sigStart + SIGNATURE_SIZE > fileBuffer.length) {
      return { valid: false, reasons: ["File too small for signature"] };
    }

    // DEBUG
    console.log('Sig start byte (hex):', fileBuffer[sigStart].toString(16));

    const signature = fileBuffer.slice(sigStart, sigStart + SIGNATURE_SIZE);
    const originalContent = fileBuffer.slice(sigStart + SIGNATURE_SIZE);

    // Verify signature including cert
    const sigResult = this.verifySignatureWithCert(originalContent, signature, certPem);
    if (!sigResult.valid) 
      return { valid: false, reasons: [sigResult.reason] };
    
    // Server revocation check
    const caResult = await this.validateWithServer(certPem);
    if (!caResult.valid) 
      return { valid: false, reasons: caResult.reasons };
    
    return { valid: true, reasons: [], originalContent, cleanFilename };
  }
}