const crypto = require("crypto");
const forge = require("node-forge");

class DigitalSignature {
  constructor() {
    this.supportedAlgorithms = {
      "RSA-SHA256": "RSA-SHA256",
      "RSA-SHA512": "RSA-SHA512",
      "ECDSA-SHA256": "ECDSA-SHA256",
      Ed25519: "Ed25519",
    };
  }

  /**
   * Create digital signature
   */
  sign(data, privateKey, algorithm = "RSA-SHA256") {
    if (!this.supportedAlgorithms[algorithm]) {
      throw new Error(
        `Unsupported algorithm. Use: ${Object.keys(
          this.supportedAlgorithms
        ).join(", ")}`
      );
    }

    const sign = crypto.createSign(algorithm);
    sign.update(typeof data === "string" ? data : JSON.stringify(data));
    sign.end();

    const signature = sign.sign(privateKey, "base64");

    return {
      algorithm: algorithm,
      signature: signature,
      data: data,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Verify digital signature
   */
  verify(data, signature, publicKey, algorithm = "RSA-SHA256") {
    try {
      const verify = crypto.createVerify(algorithm);
      verify.update(typeof data === "string" ? data : JSON.stringify(data));
      verify.end();

      const isValid = verify.verify(publicKey, signature, "base64");

      return {
        valid: isValid,
        algorithm: algorithm,
        verifiedAt: new Date().toISOString(),
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message,
        verifiedAt: new Date().toISOString(),
      };
    }
  }

  /**
   * Create detached signature (signature separate from data)
   */
  createDetachedSignature(data, privateKey, algorithm = "RSA-SHA256") {
    const signature = this.sign(data, privateKey, algorithm);

    return {
      data: data,
      signature: signature.signature,
      algorithm: signature.algorithm,
      timestamp: signature.timestamp,
      format: "DETACHED",
    };
  }

  /**
   * Create attached signature (signature embedded in data)
   */
  createAttachedSignature(data, privateKey, algorithm = "RSA-SHA256") {
    const signature = this.sign(data, privateKey, algorithm);

    return {
      version: "1.0",
      payload: {
        data: data,
        timestamp: signature.timestamp,
      },
      signature: signature.signature,
      algorithm: signature.algorithm,
      format: "ATTACHED",
    };
  }

  /**
   * Sign file content
   */
  signFile(filePath, privateKey, algorithm = "RSA-SHA256") {
    const fs = require("fs");
    const data = fs.readFileSync(filePath, "utf8");

    return this.sign(data, privateKey, algorithm);
  }

  /**
   * Create PKCS#7 signature
   */
  createPKCS7Signature(data, certificate, privateKey) {
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(
      typeof data === "string" ? data : JSON.stringify(data),
      "utf8"
    );

    // Add certificate
    p7.addCertificate(forge.pki.certificateFromPem(certificate));

    // Add signer
    p7.addSigner({
      key: forge.pki.privateKeyFromPem(privateKey),
      certificate: forge.pki.certificateFromPem(certificate),
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        {
          type: forge.pki.oids.contentType,
          value: forge.pki.oids.data,
        },
        {
          type: forge.pki.oids.messageDigest,
        },
        {
          type: forge.pki.oids.signingTime,
        },
      ],
    });

    p7.sign();

    return forge.pkcs7.messageToPem(p7);
  }

  /**
   * Verify PKCS#7 signature
   */
  verifyPKCS7Signature(p7Pem, trustedCertificates = []) {
    try {
      const p7 = forge.pkcs7.messageFromPem(p7Pem);

      // Convert trusted certificates
      const trustedCerts = trustedCertificates.map((cert) =>
        forge.pki.certificateFromPem(cert)
      );

      // Verify signature
      const verified = p7.verify({
        certificates: trustedCerts,
        // Additional verification options
      });

      return {
        valid: verified,
        signers: p7.signers,
        content: p7.content ? p7.content.toString("utf8") : null,
        certificates: p7.certificates,
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message,
      };
    }
  }
}

module.exports = DigitalSignature;
