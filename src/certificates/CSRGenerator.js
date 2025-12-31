const forge = require("node-forge");

class CSRGenerator {
  constructor() {
    this.forge = forge;
    forge.options.usePureJavaScript = true;
  }

  /**
   * Generate Certificate Signing Request
   */
  generateCSR(keyPair, subject, options = {}) {
    const csr = forge.pki.createCertificationRequest();

    // Set public key
    csr.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);

    // Parse subject
    const subjectAttrs = this.parseSubject(subject);
    csr.setSubject(subjectAttrs);

    // Set attributes and extensions
    const attributes = [];

    // Add basic extensions if requested
    if (options.extensions) {
      const extensions = [];

      if (
        options.extensions.subjectAltName &&
        options.extensions.subjectAltName.length > 0
      ) {
        extensions.push({
          name: "subjectAltName",
          altNames: options.extensions.subjectAltName.map((name) => ({
            type: 2, // DNS
            value: name,
          })),
        });
      }

      if (options.extensions.keyUsage) {
        extensions.push({
          name: "keyUsage",
          digitalSignature:
            options.extensions.keyUsage.includes("digitalSignature"),
          keyEncipherment:
            options.extensions.keyUsage.includes("keyEncipherment"),
          keyAgreement: options.extensions.keyUsage.includes("keyAgreement"),
          dataEncipherment:
            options.extensions.keyUsage.includes("dataEncipherment"),
          critical: true,
        });
      }

      if (extensions.length > 0) {
        attributes.push({
          name: "extensionRequest",
          extensions: extensions,
        });
      }
    }

    if (attributes.length > 0) {
      csr.setAttributes(attributes);
    }

    // Sign CSR with private key
    const privateKey = forge.pki.privateKeyFromPem(keyPair.privateKey);
    csr.sign(privateKey, forge.md.sha256.create());

    // Verify CSR
    const verified = csr.verify();
    if (!verified) {
      throw new Error("CSR signature verification failed");
    }

    return {
      csr: csr,
      pem: forge.pki.certificationRequestToPem(csr),
      der: forge.asn1
        .toDer(forge.pki.certificationRequestToAsn1(csr))
        .getBytes(),
      publicKey: keyPair.publicKey,
      subject: this.formatSubject(csr.subject),
      signatureAlgorithm: csr.signatureOid,
      attributes:
        csr.getAttribute({ name: "extensionRequest" })?.extensions || [],
    };
  }

  /**
   * Parse CSR from PEM
   */
  parseCSR(csrPem) {
    try {
      const csr = forge.pki.certificationRequestFromPem(csrPem);

      // Verify signature
      const verified = csr.verify();

      return {
        csr: csr,
        verified: verified,
        subject: this.formatSubject(csr.subject),
        publicKey: forge.pki.publicKeyToPem(csr.publicKey),
        signatureAlgorithm: csr.signatureOid,
        attributes: csr.attributes,
        extensions: this.extractExtensions(csr),
      };
    } catch (error) {
      throw new Error(`Failed to parse CSR: ${error.message}`);
    }
  }

  /**
   * Extract extensions from CSR
   */
  extractExtensions(csr) {
    const extensions = {};
    const extensionRequest = csr.getAttribute({ name: "extensionRequest" });

    if (extensionRequest && extensionRequest.extensions) {
      extensionRequest.extensions.forEach((ext) => {
        extensions[ext.name] = ext;
      });
    }

    return extensions;
  }

  /**
   * Parse subject string to attributes
   */
  parseSubject(subjectString) {
    const attributes = [];

    // Support both /C=US/ST=CA and comma-separated formats
    let parts;
    if (subjectString.includes("/")) {
      parts = subjectString.split("/").filter((part) => part.trim());
    } else {
      parts = subjectString.split(",").filter((part) => part.trim());
    }

    parts.forEach((part) => {
      const [key, ...valueParts] = part.split("=");
      const value = valueParts.join("=").trim();

      if (key && value) {
        const attr = this.getAttributeDefinition(key.trim());
        if (attr) {
          attributes.push({
            name: attr.name,
            shortName: attr.shortName,
            value: value,
          });
        }
      }
    });

    return attributes;
  }

  /**
   * Get attribute definition
   */
  getAttributeDefinition(key) {
    const definitions = {
      C: { name: "countryName", shortName: "C" },
      ST: { name: "stateOrProvinceName", shortName: "ST" },
      L: { name: "localityName", shortName: "L" },
      O: { name: "organizationName", shortName: "O" },
      OU: { name: "organizationalUnitName", shortName: "OU" },
      CN: { name: "commonName", shortName: "CN" },
      EMAIL: { name: "emailAddress", shortName: "EMAIL" },
      E: { name: "emailAddress", shortName: "E" },
    };

    return definitions[key.toUpperCase()] || { name: key, shortName: key };
  }

  /**
   * Format subject to string
   */
  formatSubject(subject) {
    return subject.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  /**
   * Create CSR for web server
   */
  createWebServerCSR(domain, keyPair, organization = null) {
    const subject = organization
      ? `/C=US/ST=California/L=San Francisco/O=${organization}/CN=${domain}`
      : `/CN=${domain}`;

    const options = {
      extensions: {
        subjectAltName: [domain],
        keyUsage: ["digitalSignature", "keyEncipherment"],
      },
    };

    return this.generateCSR(keyPair, subject, options);
  }

  /**
   * Create CSR for code signing
   */
  createCodeSigningCSR(developerName, keyPair, organization) {
    const subject = `/C=US/O=${organization}/CN=${developerName}`;

    const options = {
      extensions: {
        keyUsage: ["digitalSignature"],
        extendedKeyUsage: ["codeSigning"],
      },
    };

    return this.generateCSR(keyPair, subject, options);
  }

  /**
   * Create CSR for email protection
   */
  createEmailCSR(email, keyPair, organization = null) {
    const subject = organization
      ? `/C=US/O=${organization}/EMAIL=${email}`
      : `/EMAIL=${email}`;

    const options = {
      extensions: {
        keyUsage: ["digitalSignature", "keyEncipherment"],
        extendedKeyUsage: ["emailProtection"],
      },
    };

    return this.generateCSR(keyPair, subject, options);
  }

  /**
   * Validate CSR against requirements
   */
  validateCSR(csrPem, requirements = {}) {
    const csrInfo = this.parseCSR(csrPem);

    const issues = [];

    // Check subject
    if (requirements.minSubjectFields) {
      const fieldCount = csrInfo.csr.subject.attributes.length;
      if (fieldCount < requirements.minSubjectFields) {
        issues.push(
          `Insufficient subject fields: ${fieldCount} found, ${requirements.minSubjectFields} required`
        );
      }
    }

    // Check CN if required
    if (requirements.requireCN) {
      const cn = csrInfo.csr.subject.getField("CN");
      if (!cn) {
        issues.push("Common Name (CN) is required but missing");
      }
    }

    // Check key strength if public key is available
    if (csrInfo.publicKey && requirements.minKeySize) {
      // This is a simplified check - in reality, you'd need to parse the key
      const keySize = this.estimateKeySize(csrInfo.publicKey);
      if (keySize < requirements.minKeySize) {
        issues.push(
          `Key size ${keySize} bits is less than required ${requirements.minKeySize} bits`
        );
      }
    }

    // Check signature algorithm
    if (
      requirements.allowedAlgorithms &&
      !requirements.allowedAlgorithms.includes(csrInfo.signatureAlgorithm)
    ) {
      issues.push(
        `Signature algorithm ${csrInfo.signatureAlgorithm} not allowed`
      );
    }

    return {
      valid: issues.length === 0,
      verified: csrInfo.verified,
      issues: issues,
      csrInfo: csrInfo,
    };
  }

  /**
   * Estimate key size from PEM (simplified)
   */
  estimateKeySize(publicKeyPem) {
    // Very basic estimation
    const lines = publicKeyPem
      .split("\n")
      .filter((line) => !line.includes("-----"));
    const base64 = lines.join("");
    const binary = Buffer.from(base64, "base64");

    // Rough estimation: RSA keys are larger
    if (publicKeyPem.includes("RSA")) {
      return binary.length > 400 ? 4096 : binary.length > 250 ? 2048 : 1024;
    }

    // ECDSA estimation
    return binary.length > 100 ? 256 : 128;
  }

  /**
   * Export CSR in different formats
   */
  exportCSR(csrInfo, format = "pem") {
    switch (format.toLowerCase()) {
      case "der":
        return {
          format: "DER",
          data:
            csrInfo.der ||
            forge.asn1
              .toDer(forge.pki.certificationRequestToAsn1(csrInfo.csr))
              .getBytes(),
        };
      case "base64":
        const der =
          csrInfo.der ||
          forge.asn1
            .toDer(forge.pki.certificationRequestToAsn1(csrInfo.csr))
            .getBytes();
        return {
          format: "BASE64",
          data: Buffer.from(der).toString("base64"),
        };
      case "json":
        return {
          format: "JSON",
          data: {
            subject: csrInfo.subject,
            publicKey: csrInfo.publicKey.substring(0, 100) + "...",
            signatureAlgorithm: csrInfo.signatureAlgorithm,
            verified: csrInfo.verified,
          },
        };
      default:
        return {
          format: "PEM",
          data: csrInfo.pem || forge.pki.certificationRequestToPem(csrInfo.csr),
        };
    }
  }
}

module.exports = CSRGenerator;
