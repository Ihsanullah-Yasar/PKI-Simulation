const forge = require("node-forge");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

class CRLManager {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs/crl",
      crlNumber: config.crlNumber || 1,
      validityDays: config.validityDays || 7,
      nextUpdateDays: config.nextUpdateDays || 7,
      ...config,
    };

    this.forge = forge;
    forge.options.usePureJavaScript = true;

    this.revokedCertificates = new Map(); // serialNumber -> revocation info
    this.crl = null;

    this.ensureDirectory();
  }

  /**
   * Ensure directory exists
   */
  ensureDirectory() {
    if (!fs.existsSync(this.config.basePath)) {
      fs.mkdirSync(this.config.basePath, { recursive: true });
    }
  }

  /**
   * Initialize CRL with issuer certificate
   */
  initialize(issuerCert, issuerPrivateKey) {
    this.issuerCert = issuerCert;
    this.issuerPrivateKey = issuerPrivateKey;

    // Create initial CRL
    this.crl = forge.pkix.createCrl();
    this.crl.issuer = issuerCert.subject;
    this.crl.thisUpdate = new Date();
    this.crl.nextUpdate = new Date();
    this.crl.nextUpdate.setDate(
      this.crl.nextUpdate.getDate() + this.config.nextUpdateDays
    );

    // Set CRL number extension
    this.crl.setExtensions([
      {
        name: "cRLNumber",
        cRLNumber: this.config.crlNumber,
      },
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: this.getAuthorityKeyIdentifier(issuerCert),
      },
    ]);

    // Sign the CRL
    this.signCRL();

    console.log(`✅ CRL initialized with number ${this.config.crlNumber}`);
    console.log(`   Issuer: ${this.formatName(issuerCert.subject)}`);
    console.log(`   Valid until: ${this.crl.nextUpdate.toDateString()}`);

    return this.crl;
  }

  /**
   * Revoke a certificate
   */
  revokeCertificate(
    cert,
    issuerCert,
    issuerPrivateKey,
    reason = "unspecified"
  ) {
    if (!this.crl) {
      this.initialize(issuerCert, issuerPrivateKey);
    }

    const serialNumber = cert.serialNumber;
    const revocationDate = new Date();

    // Add to revoked list
    this.revokedCertificates.set(serialNumber, {
      certificate: cert,
      serialNumber: serialNumber,
      revocationDate: revocationDate,
      reason: reason,
      addedAt: new Date(),
    });

    // Add to CRL
    this.crl.addRevokedCertificate({
      serialNumber: serialNumber,
      revocationDate: revocationDate,
      reason: this.getRevocationReasonCode(reason),
    });

    // Increment CRL number
    this.config.crlNumber++;
    this.updateCRLNumber();

    // Re-sign CRL
    this.signCRL();

    console.log(`❌ Certificate revoked in CRL: ${serialNumber}`);
    console.log(`   Reason: ${reason}`);
    console.log(`   CRL number: ${this.config.crlNumber}`);

    return {
      serialNumber: serialNumber,
      crlNumber: this.config.crlNumber,
      revocationDate: revocationDate,
      reason: reason,
    };
  }

  /**
   * Check if certificate is revoked
   */
  isCertificateRevoked(serialNumber) {
    return this.revokedCertificates.has(serialNumber);
  }

  /**
   * Get revocation information
   */
  getRevocationInfo(serialNumber) {
    return this.revokedCertificates.get(serialNumber);
  }

  /**
   * Remove certificate from CRL (un-revoke)
   */
  unrevokeCertificate(serialNumber, issuerCert, issuerPrivateKey) {
    if (!this.revokedCertificates.has(serialNumber)) {
      return false;
    }

    // Remove from revoked list
    this.revokedCertificates.delete(serialNumber);

    // Recreate CRL without this certificate
    this.recreateCRL(issuerCert, issuerPrivateKey);

    console.log(`✅ Certificate removed from CRL: ${serialNumber}`);

    return true;
  }

  /**
   * Recreate CRL with current revoked certificates
   */
  recreateCRL(issuerCert, issuerPrivateKey) {
    this.issuerCert = issuerCert;
    this.issuerPrivateKey = issuerPrivateKey;

    // Create new CRL
    this.crl = forge.pkix.createCrl();
    this.crl.issuer = issuerCert.subject;
    this.crl.thisUpdate = new Date();
    this.crl.nextUpdate = new Date();
    this.crl.nextUpdate.setDate(
      this.crl.nextUpdate.getDate() + this.config.nextUpdateDays
    );

    // Add all revoked certificates
    for (const [serialNumber, info] of this.revokedCertificates) {
      this.crl.addRevokedCertificate({
        serialNumber: serialNumber,
        revocationDate: info.revocationDate,
        reason: this.getRevocationReasonCode(info.reason),
      });
    }

    // Update extensions
    this.crl.setExtensions([
      {
        name: "cRLNumber",
        cRLNumber: this.config.crlNumber,
      },
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: this.getAuthorityKeyIdentifier(issuerCert),
      },
    ]);

    // Sign the CRL
    this.signCRL();

    return this.crl;
  }

  /**
   * Sign the CRL
   */
  signCRL() {
    if (!this.crl || !this.issuerPrivateKey) {
      throw new Error("CRL or issuer private key not set");
    }

    this.crl.sign(
      forge.pki.privateKeyFromPem(this.issuerPrivateKey),
      forge.md.sha256.create()
    );
  }

  /**
   * Update CRL number extension
   */
  updateCRLNumber() {
    if (!this.crl) return;

    const extensions = this.crl.extensions || [];
    const crlNumberIndex = extensions.findIndex(
      (ext) => ext.name === "cRLNumber"
    );

    if (crlNumberIndex !== -1) {
      extensions[crlNumberIndex].cRLNumber = this.config.crlNumber;
    } else {
      extensions.push({
        name: "cRLNumber",
        cRLNumber: this.config.crlNumber,
      });
    }

    this.crl.setExtensions(extensions);
  }

  /**
   * Get revocation reason code
   */
  getRevocationReasonCode(reason) {
    const reasonCodes = {
      unspecified: 0,
      keyCompromise: 1,
      cACompromise: 2,
      affiliationChanged: 3,
      superseded: 4,
      cessationOfOperation: 5,
      certificateHold: 6,
      removeFromCRL: 8,
      privilegeWithdrawn: 9,
      aACompromise: 10,
    };

    return reasonCodes[reason] || 0;
  }

  /**
   * Get revocation reason text
   */
  getRevocationReasonText(code) {
    const reasons = {
      0: "unspecified",
      1: "keyCompromise",
      2: "cACompromise",
      3: "affiliationChanged",
      4: "superseded",
      5: "cessationOfOperation",
      6: "certificateHold",
      8: "removeFromCRL",
      9: "privilegeWithdrawn",
      10: "aACompromise",
    };

    return reasons[code] || "unknown";
  }

  /**
   * Get authority key identifier
   */
  getAuthorityKeyIdentifier(cert) {
    const md = forge.md.sha1.create();
    md.update(
      forge.asn1.toDer(forge.pki.getPublicKeyInfo(cert.publicKey)).getBytes()
    );
    return md.digest().getBytes();
  }

  /**
   * Get CRL in PEM format
   */
  getCRLPem() {
    if (!this.crl) {
      throw new Error("CRL not initialized");
    }

    return forge.pkix.crlToPem(this.crl);
  }

  /**
   * Get CRL in DER format
   */
  getCRLDer() {
    if (!this.crl) {
      throw new Error("CRL not initialized");
    }

    return forge.asn1.toDer(forge.pkix.crlToAsn1(this.crl)).getBytes();
  }

  /**
   * Get CRL number
   */
  getCRLNumber() {
    return this.config.crlNumber;
  }

  /**
   * Get revoked certificates count
   */
  getRevokedCount() {
    return this.revokedCertificates.size;
  }

  /**
   * List all revoked certificates
   */
  listRevokedCertificates() {
    const list = [];

    for (const [serialNumber, info] of this.revokedCertificates) {
      list.push({
        serialNumber: serialNumber,
        subject: this.formatName(info.certificate.subject),
        revocationDate: info.revocationDate,
        reason: info.reason,
        daysRevoked: Math.floor(
          (new Date() - info.revocationDate) / (1000 * 60 * 60 * 24)
        ),
      });
    }

    return list.sort((a, b) => b.revocationDate - a.revocationDate);
  }

  /**
   * Validate CRL signature
   */
  validateCRLSignature(crlPem, issuerCert) {
    try {
      const crl = forge.pkix.crlFromPem(crlPem);
      const verified = crl.verify(issuerCert);

      return {
        valid: verified,
        crl: crl,
        issuer: this.formatName(crl.issuer),
        thisUpdate: crl.thisUpdate,
        nextUpdate: crl.nextUpdate,
        revokedCount: crl.revokedCertificates
          ? crl.revokedCertificates.length
          : 0,
      };
    } catch (error) {
      return {
        valid: false,
        error: `CRL signature validation failed: ${error.message}`,
      };
    }
  }

  /**
   * Check certificate against CRL
   */
  checkCertificateAgainstCRL(cert, crlPem) {
    try {
      const crl = forge.pkix.crlFromPem(crlPem);
      const isRevoked = crl.isRevoked(cert);

      let revocationInfo = null;
      if (isRevoked && crl.revokedCertificates) {
        const revokedCert = crl.revokedCertificates.find(
          (rc) => rc.serialNumber === cert.serialNumber
        );
        if (revokedCert) {
          revocationInfo = {
            revocationDate: revokedCert.revocationDate,
            reason: this.getRevocationReasonText(revokedCert.reasonCode),
          };
        }
      }

      return {
        revoked: isRevoked,
        revocationInfo: revocationInfo,
        crlInfo: {
          issuer: this.formatName(crl.issuer),
          thisUpdate: crl.thisUpdate,
          nextUpdate: crl.nextUpdate,
          isExpired: new Date() > crl.nextUpdate,
        },
      };
    } catch (error) {
      return {
        revoked: false,
        error: `CRL check failed: ${error.message}`,
      };
    }
  }

  /**
   * Save CRL to file
   */
  saveCRLToFile(filename = null) {
    if (!this.crl) {
      throw new Error("CRL not initialized");
    }

    const crlPem = this.getCRLPem();
    const crlDer = this.getCRLDer();

    const baseName =
      filename || `crl-${new Date().toISOString().replace(/[:.]/g, "-")}`;
    const pemPath = path.join(this.config.basePath, `${baseName}.pem`);
    const derPath = path.join(this.config.basePath, `${baseName}.der`);
    const jsonPath = path.join(this.config.basePath, `${baseName}.json`);

    // Save PEM
    fs.writeFileSync(pemPath, crlPem, "utf8");

    // Save DER
    fs.writeFileSync(derPath, crlDer);

    // Save metadata
    const metadata = {
      crlNumber: this.config.crlNumber,
      issuer: this.formatName(this.crl.issuer),
      thisUpdate: this.crl.thisUpdate.toISOString(),
      nextUpdate: this.crl.nextUpdate.toISOString(),
      revokedCertificates: this.getRevokedCount(),
      generatedAt: new Date().toISOString(),
    };

    fs.writeFileSync(jsonPath, JSON.stringify(metadata, null, 2), "utf8");

    console.log(`💾 CRL saved to:`);
    console.log(`   PEM: ${pemPath}`);
    console.log(`   DER: ${derPath}`);
    console.log(`   JSON: ${jsonPath}`);

    return {
      pem: pemPath,
      der: derPath,
      json: jsonPath,
    };
  }

  /**
   * Load CRL from file
   */
  loadCRLFromFile(filePath) {
    try {
      const crlPem = fs.readFileSync(filePath, "utf8");
      const crl = forge.pkix.crlFromPem(crlPem);

      this.crl = crl;

      // Extract CRL number from extensions
      const crlNumberExt = crl.extensions.find(
        (ext) => ext.name === "cRLNumber"
      );
      if (crlNumberExt) {
        this.config.crlNumber = crlNumberExt.cRLNumber;
      }

      // Build revoked certificates map
      this.revokedCertificates.clear();
      if (crl.revokedCertificates) {
        // Note: We don't have the actual certificate objects here
        // In a real implementation, you'd look them up by serial number
        crl.revokedCertificates.forEach((revoked) => {
          this.revokedCertificates.set(revoked.serialNumber, {
            serialNumber: revoked.serialNumber,
            revocationDate: revoked.revocationDate,
            reason: this.getRevocationReasonText(revoked.reasonCode),
          });
        });
      }

      console.log(`📂 CRL loaded from ${filePath}`);
      console.log(`   CRL number: ${this.config.crlNumber}`);
      console.log(`   Revoked certificates: ${this.getRevokedCount()}`);
      console.log(`   Valid until: ${crl.nextUpdate.toDateString()}`);

      return true;
    } catch (error) {
      console.error(`Failed to load CRL: ${error.message}`);
      return false;
    }
  }

  /**
   * Export CRL in different formats
   */
  exportCRL(format = "pem") {
    if (!this.crl) {
      throw new Error("CRL not initialized");
    }

    switch (format.toLowerCase()) {
      case "pem":
        return {
          format: "PEM",
          data: this.getCRLPem(),
        };

      case "der":
        return {
          format: "DER",
          data: this.getCRLDer(),
        };

      case "base64":
        return {
          format: "BASE64",
          data: Buffer.from(this.getCRLDer()).toString("base64"),
        };

      case "json":
        return {
          format: "JSON",
          data: {
            crlNumber: this.config.crlNumber,
            issuer: this.formatName(this.crl.issuer),
            thisUpdate: this.crl.thisUpdate,
            nextUpdate: this.crl.nextUpdate,
            revokedCertificates: this.listRevokedCertificates(),
          },
        };

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Get CRL statistics
   */
  getStatistics() {
    const now = new Date();
    const revokedList = this.listRevokedCertificates();

    const recentRevocations = revokedList.filter(
      (revoked) => now - revoked.revocationDate < 7 * 24 * 60 * 60 * 1000 // Last 7 days
    );

    const reasonStats = {};
    revokedList.forEach((revoked) => {
      reasonStats[revoked.reason] = (reasonStats[revoked.reason] || 0) + 1;
    });

    return {
      crlNumber: this.config.crlNumber,
      revokedCertificates: this.getRevokedCount(),
      recentRevocations: recentRevocations.length,
      thisUpdate: this.crl ? this.crl.thisUpdate : null,
      nextUpdate: this.crl ? this.crl.nextUpdate : null,
      isExpired: this.crl ? now > this.crl.nextUpdate : true,
      reasonStatistics: reasonStats,
      issuer: this.crl ? this.formatName(this.crl.issuer) : "Not set",
    };
  }

  /**
   * Format name for display
   */
  formatName(name) {
    return name.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  /**
   * Generate test CRL
   */
  generateTestCRL(issuerCert, issuerPrivateKey, testCertificates = []) {
    this.initialize(issuerCert, issuerPrivateKey);

    // Revoke some test certificates
    testCertificates.forEach((cert, index) => {
      if (index % 3 === 0) {
        // Revoke every 3rd certificate
        this.revokeCertificate(
          cert,
          issuerCert,
          issuerPrivateKey,
          "keyCompromise"
        );
      }
    });

    return this.crl;
  }

  /**
   * Get root CA CRL (for demo purposes)
   */
  getRootCRLPem() {
    if (!this.crl) {
      // Create a dummy CRL for demo
      const dummyCRL = forge.pkix.createCrl();
      dummyCRL.issuer = forge.pki.createCertificate().subject;
      dummyCRL.thisUpdate = new Date();
      dummyCRL.nextUpdate = new Date();
      dummyCRL.nextUpdate.setDate(dummyCRL.nextUpdate.getDate() + 30);

      // Sign with a dummy key
      const dummyKey = forge.pki.privateKeyFromPem(
        "-----BEGIN PRIVATE KEY-----\n" +
          "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCz7...\n" +
          "-----END PRIVATE KEY-----"
      );
      dummyCRL.sign(dummyKey, forge.md.sha256.create());

      return forge.pkix.crlToPem(dummyCRL);
    }

    return this.getCRLPem();
  }
}

module.exports = CRLManager;
