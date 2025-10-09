class PkiHelper {

  #privateKeyEnc;
  #publicKey;
  #certificate;

  constructor() {
    this.#loadKeys();
  }

  async validateSignature(signature, checksum) { // signature and checksum as Uint8Array
    if (!this.#publicKey) throw new Error("Public key not loaded");
    const publicKey = forge.pki.publicKeyFromPem(this.#publicKey);
    
    // Verify RSA-PSS signature over SHA-256 checksum
    const md = forge.md.sha256.create();
    md.update(forge.util.createBuffer(checksum));
    const hash = md.digest().getBytes();
    
    const verifier = publicKey.verify(forge.util.createBuffer(hash), forge.util.createBuffer(signature));
    return verifier;
  }

  async sign(fileName, fileContent, password, fileSize) {
  if (!this.#privateKeyEnc || !this.#certificate)
    throw new Error("PKI setup incomplete. Await authentication or sign up.");

  try {
    const privateKey = decryptEncryptedPrivateKey(this.#privateKeyEnc, password);

    const md = forge.md.sha256.create();

    const chunkSize = 1024 * 1024; // 1MB chunks to avoid large strings
    for (let offset = 0; offset < fileContent.length; offset += chunkSize) {
      const chunk = fileContent.subarray(offset, offset + chunkSize);
      
      let binaryChunk = "";
      for (let j = 0; j < chunk.length; j++)
        binaryChunk += String.fromCharCode(chunk[j]);
      
      md.update(binaryChunk);
    }

    const signature = privateKey.sign(md);
    const signatureBytes = forge.util.binary.raw.decode(signature);

    if (signatureBytes.length !== SIGNATURE_SIZE) {
      throw new Error("Invalid signature length");
    }

    let certPem = this.#certificate.trim();
    if (!certPem.endsWith("\n")) {
      certPem += "\n";
    }
    const certBytes = new TextEncoder().encode(certPem);

    const totalLength = certBytes.length + SIGNATURE_SIZE + fileSize;
    const signedContent = new Uint8Array(totalLength);
    signedContent.set(certBytes, 0);
    signedContent.set(signatureBytes, certBytes.length);
    signedContent.set(fileContent, certBytes.length + SIGNATURE_SIZE);

    const safeName = fileName.endsWith(".safe") ? fileName : fileName + ".safe";
    const signedBase64 = this.#arrayBufferToBase64(signedContent.buffer);

    return { success: true, signedContent: signedBase64, safeName };
  }
  catch (error) {
    console.error("Signing error:", error);
    throw error;
  }
}

 #arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

  #loadKeys() {
    chrome.storage.local.get(["pki_keys_safe"]).then(result => {
      if (!result.pki_keys_safe) {
        this.#generateKeys();
        return;
      } 

      this.#publicKey = result.pki_keys_safe.publicKey;
      this.#privateKeyEnc = result.pki_keys_safe.privateKeyEnc;
      this.#certificate = result.pki_keys_safe.certificate;
    });
  }

  async #getSetupDetails() {
      return new Promise((resolve) => {
          // Temporary listener for setup response
          const messageListener = (request, sender, sendResponse) => {
              if (request.type === "setupDetails") {
                resolve(request.details);
                sendResponse({});  // Acknowledge to close port cleanly (prevents error)
              }
          };

          chrome.runtime.onMessage.addListener(messageListener);

          // Create temporary popup window loading setup.html
          chrome.windows.create({
              url: "setup.html",
              type: "popup",
              width: 600,
              height: 450
          }, (win) => { });
      });
  }

  // In #generateKeys() - Remove await if function is sync now; await the CSR
  async #generateKeys() {

    console.log("Beginning key setup");

    const details = await this.#getSetupDetails();
    if (!details) {
      console.error("Setup cancelled. Please reload the extension and start again.");
      return;
    }

    console.log("Generating keys");

    const { encryptedPrivatePem, publicPem } = generateEncryptedPrivateKey(details.password);

    console.log("Key generation complete. Saving keys");
 
    this.#publicKey = publicPem;
    this.#privateKeyEnc = encryptedPrivatePem;

    console.log("Generating CSR.");
    const csr = this.#generateCsr(details);

    console.log("CSR generated; requesting approval.");

    var csrResponse = await this.#getCsrResponse(csr);

    if(!csrResponse.success)
    {
        console.log(csrResponse);
        console.error("Certificate registration failed. Reason:\n" + csrResponse.error);
        return;
    }

    console.log("Certificate request approved. Saving details to disk.");

    const certificate = csrResponse.certificate; 
    this.#certificate = certificate;
    
    await chrome.storage.local.set({ pki_keys_safe: { publicKey: publicPem, privateKeyEnc: encryptedPrivatePem, certificate: certificate } });

    console.log("Keys and certificate saved to disk.");
  }

  // In #generateCsr() - Accept passphrase param to ensure match
  #generateCsr(setupDetails) {  // Relative to dir
    const subjectDetails = { CN: setupDetails.CN, O: setupDetails.organization, C: setupDetails.country, SP: setupDetails.stateOrProvince };
    // Remove this.#getPassphrase() - use passed param
    return createCSR(this.#privateKeyEnc, setupDetails.password, subjectDetails);
  }

  #getCsrResponse(csr) {
        return new Promise((resolve) => {
            fetch(baseUrl + "/csr_handler.php", {  // Replace with your server URL
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ csr: csr })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success)
                    resolve({ success: true, certificate: data.certificate });
                else
                    resolve({ success: false, error: data.error });
            })
            .catch(error => {
                resolve({ success: false, error: `Network error: ${error.message}` });
            });
        });
    }
}