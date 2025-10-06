// DownloadValidator.js - Updated for client-side basic checks + server CA validation

class DownloadValidator {

  #isReady;
  get isReady() { return this.#isReady; }

  #permittedDomains;
  #permittedFormats;

  constructor() {
    this.#getPermittedDomains();
  }

  #getPermittedDomains() {
    console.log("Getting download settings. URL: " + baseUrl);

    fetch(baseUrl + "download_settings.php", {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
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

      // DEBUG REMOVE
      console.log(data);
      console.log("Domains:\n"+data.permittedDomains);
      console.log("Formats:\n"+data.permittedFormats);

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

  // New: Client-side basic signature verification (using PkiHelper's validateSignature)
  async basicSignatureCheck(originalContent, signature, checksum) {
    // Assume pkiHelper is available (import or global from background)
    // Compute SHA-256 checksum if not provided
    if (!checksum) {
      checksum = await crypto.subtle.digest('SHA-256', originalContent);
    }
    return pkiHelper.validateSignature(signature, new Uint8Array(checksum));
  }

  // New: Send to server for CA checks (cert validity, revocation)
  async validateWithServer(fileBuffer, sigBuffer, certPem) {
    if (!this.isReady) {
      throw new Error('Validator not ready');
    }

    const formData = new FormData();
    formData.append('fileToUpload', new Blob([fileBuffer]), 'file.dat');
    formData.append('fileToUploadSig', new Blob([sigBuffer]), 'file.sig');
    formData.append('fileToUploadX509', new Blob([certPem], { type: 'text/plain' }), 'cert.pem');

    try {
      const response = await fetch(this.baseURL + 'validate_signature.php', {
        method: 'POST',
        body: formData
      });

      if (!response.ok)
        throw new Error(`Server error: ${response.status}`);
      
      const result = await response.json();  // Expect JSON from updated PHP
      return result;  // { valid: true/false, reasons: [...] }

    }
    catch (error) {
      console.error('Server validation error:', error);
      return { valid: false, reasons: ['Server unreachable'] };
    }
  }

  
  async fullValidate(fileBuffer, sigBuffer, certPem, downloadUrl) {
    // Client-side checks
    if (!this.domainPermitted(downloadUrl)) {
      return { valid: false, reasons: ['Domain not permitted'] };
    }

    const fileExtension = fileBuffer.name ? fileBuffer.name.split('.').pop().toLowerCase() : '';
    if (this.formatPermitted(fileExtension)) {
      return { valid: true, reasons: [] };  // Whitelisted formats skip sig checks
    }

    // Basic signature (local)
    const originalContent = fileBuffer.slice(SIGNATURE_SIZE);  // Assume sig prefixed
    const signature = fileBuffer.slice(0, SIGNATURE_SIZE);
    const checksum = await crypto.subtle.digest('SHA-256', originalContent);
    const sigValid = await this.basicSignatureCheck(originalContent, signature, checksum);
    if (!sigValid) {
      return { valid: false, reasons: ['Signature invalid'] };
    }

    // Server CA checks
    const caResult = await this.validateWithServer(fileBuffer, sigBuffer, certPem);
    if (!caResult.valid) {
      return { valid: false, reasons: caResult.reasons };
    }

    return { valid: true, reasons: [] };
  }
}