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

      // Hash content with forge
      const md = forge.md.sha256.create();
      md.update(forge.util.createBuffer(originalContent));
      const digest = md.digest();

      // Signature buffer
      const sigBuffer = forge.util.createBuffer(signature);

      const isValid = publicKey.verify(digest, sigBuffer);

      return { valid: isValid, reason: isValid ? "" : "File signature invalid" };
    }
    catch (error) {
      console.error("File signature verification error:", error);
      return { valid: false, reason: "Verification error" };
    }
  }

  // Server validation for issuance and revocation
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
    // Skip whitespace
    while (endIndex < bufferStr.length && /\s/.test(bufferStr.charAt(endIndex))) {
      endIndex++;
    }
    const certPem = bufferStr.substring(startIndex, endIndex).trim();
    if (!certPem.startsWith(startCert)) {
      return { valid: false, reasons: ["Invalid certificate format"] };
    }

    const sigStart = endIndex; // Byte index matches char index for ASCII PEM
    if (sigStart + SIGNATURE_SIZE > fileBuffer.length) {
      return { valid: false, reasons: ["File too small for signature"] };
    }

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