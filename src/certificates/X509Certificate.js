const crypto = require("crypto");
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");

class X509Certificate {
  constructor() {
    this.forge = forge;
    forge.options.usePureJavaScript = true;
  }

  /**
   * Generate certificate serial number
   */
  generateSerialNumber() {
    return "0x" + crypto.randomBytes(20).toString("hex");
  }

  /**
   * Create a self-signed Root CA certificate
   */
  createRootCA(subject, keyPair, validityYears = 10) {
    const cert = forge.pki.createCertificate();

    // Set certificate fields
    cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);
    cert.serialNumber = this.generateSerialNumber();

    // Validity period
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + validityYears
    );

    // Subject and Issuer are the same for Root CA
    const subjectAttrs = this.parseSubjectString(subject);
    cert.setSubject(subjectAttrs);
    cert.setIssuer(subjectAttrs);

    // Root CA extensions
    cert.setExtensions([
      {
        name: "basicConstraints",
        cA: true,
        critical: true,
      },
      {
        name: "keyUsage",
        keyCertSign: true,
        cRLSign: true,
        critical: true,
      },
      {
        name: "subjectKeyIdentifier",
        critical: false,
      },
    ]);

    // Sign the certificate
    const privateKey = forge.pki.privateKeyFromPem(keyPair.privateKey);
    cert.sign(privateKey, forge.md.sha256.create());

    // Generate subject key identifier
    this.addSubjectKeyIdentifier(cert);

    return {
      certificate: cert,
      pem: forge.pki.certificateToPem(cert),
      der: forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(),
      serialNumber: cert.serialNumber,
      subject: this.formatName(cert.subject),
      issuer: this.formatName(cert.issuer),
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
    };
  }

  /**
   * Create Intermediate CA certificate
   */
  createIntermediateCA(
    subject,
    keyPair,
    issuerCert,
    issuerPrivateKey,
    validityYears = 5
  ) {
    const cert = forge.pki.createCertificate();

    cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);
    cert.serialNumber = this.generateSerialNumber();

    // Validity period
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + validityYears
    );

    // Subject
    const subjectAttrs = this.parseSubjectString(subject);
    cert.setSubject(subjectAttrs);

    // Issuer is the parent CA
    cert.setIssuer(issuerCert.certificate.subject.attributes);

    // Intermediate CA extensions
    cert.setExtensions([
      {
        name: "basicConstraints",
        cA: true,
        pathLenConstraint: 0, // Cannot issue more CAs
        critical: true,
      },
      {
        name: "keyUsage",
        keyCertSign: true,
        cRLSign: true,
        critical: true,
      },
      {
        name: "subjectKeyIdentifier",
        critical: false,
      },
      {
        name: "authorityKeyIdentifier",
        critical: false,
      },
    ]);

    // Sign with issuer's private key
    const privateKey = forge.pki.privateKeyFromPem(issuerPrivateKey);
    cert.sign(privateKey, forge.md.sha256.create());

    // Add key identifiers
    this.addSubjectKeyIdentifier(cert);
    this.addAuthorityKeyIdentifier(cert, issuerCert.certificate);

    return {
      certificate: cert,
      pem: forge.pki.certificateToPem(cert),
      serialNumber: cert.serialNumber,
      subject: this.formatName(cert.subject),
      issuer: this.formatName(cert.issuer),
    };
  }

  /**
   * Create End-Entity certificate
   */
  createEndEntityCertificate(
    subject,
    keyPair,
    issuerCert,
    issuerPrivateKey,
    options = {}
  ) {
    const {
      validityDays = 365,
      keyUsage = ["digitalSignature", "keyEncipherment"],
      extendedKeyUsage = ["serverAuth", "clientAuth"],
      san = [],
      isCA = false,
    } = options;

    const cert = forge.pki.createCertificate();

    cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);
    cert.serialNumber = this.generateSerialNumber();

    // Validity period
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setDate(
      cert.validity.notBefore.getDate() + validityDays
    );

    // Subject
    const subjectAttrs = this.parseSubjectString(subject);
    cert.setSubject(subjectAttrs);

    // Issuer
    cert.setIssuer(issuerCert.certificate.subject.attributes);

    // Build extensions
    const extensions = [
      {
        name: "basicConstraints",
        cA: isCA,
        critical: true,
      },
      {
        name: "keyUsage",
        critical: true,
      },
    ];

    // Add key usage flags
    const keyUsageExt = extensions.find((ext) => ext.name === "keyUsage");
    keyUsage.forEach((usage) => {
      keyUsageExt[usage] = true;
    });

    // Add extended key usage if specified
    if (extendedKeyUsage && extendedKeyUsage.length > 0) {
      extensions.push({
        name: "extKeyUsage",
        serverAuth: extendedKeyUsage.includes("serverAuth"),
        clientAuth: extendedKeyUsage.includes("clientAuth"),
        codeSigning: extendedKeyUsage.includes("codeSigning"),
        emailProtection: extendedKeyUsage.includes("emailProtection"),
        timeStamping: extendedKeyUsage.includes("timeStamping"),
        critical: false,
      });
    }

    // Add Subject Alternative Names if specified
    if (san && san.length > 0) {
      const altNames = san.map((name) => {
        if (name.startsWith("DNS:")) {
          return {
            type: 2, // DNS
            value: name.substring(4),
          };
        } else if (name.startsWith("IP:")) {
          return {
            type: 7, // IP
            ip: name.substring(3),
          };
        } else if (name.includes("@")) {
          return {
            type: 1, // Email
            value: name,
          };
        } else {
          return {
            type: 2, // DNS
            value: name,
          };
        }
      });

      extensions.push({
        name: "subjectAltName",
        altNames: altNames,
        critical: false,
      });
    }

    // Add key identifiers
    extensions.push({
      name: "subjectKeyIdentifier",
      critical: false,
    });

    extensions.push({
      name: "authorityKeyIdentifier",
      critical: false,
    });

    cert.setExtensions(extensions);

    // Sign with issuer's private key
    const privateKey = forge.pki.privateKeyFromPem(issuerPrivateKey);
    cert.sign(privateKey, forge.md.sha256.create());

    // Add key identifiers
    this.addSubjectKeyIdentifier(cert);
    this.addAuthorityKeyIdentifier(cert, issuerCert.certificate);

    return {
      certificate: cert,
      pem: forge.pki.certificateToPem(cert),
      serialNumber: cert.serialNumber,
      subject: this.formatName(cert.subject),
      issuer: this.formatName(cert.issuer),
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
      san: san,
    };
  }

  /**
   * Create Certificate Signing Request (CSR)
   */
  createCSR(subject, keyPair) {
    const csr = forge.pki.createCertificationRequest();

    csr.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);

    // Set subject
    const subjectAttrs = this.parseSubjectString(subject);
    csr.setSubject(subjectAttrs);

    // Add attributes
    csr.setAttributes([
      {
        name: "extensionRequest",
        extensions: [
          {
            name: "subjectAltName",
            altNames: [
              {
                type: 2, // DNS
                value: "example.com",
              },
            ],
          },
        ],
      },
    ]);

    // Sign CSR
    const privateKey = forge.pki.privateKeyFromPem(keyPair.privateKey);
    csr.sign(privateKey, forge.md.sha256.create());

    // Verify CSR
    const verified = csr.verify();

    if (!verified) {
      throw new Error("Failed to verify CSR signature");
    }

    return {
      csr: csr,
      pem: forge.pki.certificationRequestToPem(csr),
      subject: this.formatName(csr.subject),
      publicKey: keyPair.publicKey,
    };
  }

  /**
   * Parse subject string to attributes
   */
  parseSubjectString(subjectString) {
    const attributes = [];
    const parts = subjectString.split("/").filter((part) => part.trim());

    parts.forEach((part) => {
      const [key, value] = part.split("=");
      if (key && value) {
        const attr = this.getAttributeForShortName(key.trim());
        if (attr) {
          attributes.push({
            name: attr.name,
            shortName: attr.shortName,
            value: value.trim(),
          });
        }
      }
    });

    return attributes;
  }

  /**
   * Get attribute details for short name
   */
  getAttributeForShortName(shortName) {
    const attributes = {
      C: { name: "countryName", shortName: "C" },
      ST: { name: "stateOrProvinceName", shortName: "ST" },
      L: { name: "localityName", shortName: "L" },
      O: { name: "organizationName", shortName: "O" },
      OU: { name: "organizationalUnitName", shortName: "OU" },
      CN: { name: "commonName", shortName: "CN" },
      E: { name: "emailAddress", shortName: "E" },
    };

    return attributes[shortName.toUpperCase()];
  }

  /**
   * Format name object to string
   */
  formatName(name) {
    return name.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  /**
   * Add Subject Key Identifier extension
   */
  addSubjectKeyIdentifier(cert) {
    const ski = forge.pki.getPublicKeyFingerprint(cert.publicKey, {
      type: "SubjectKeyIdentifier",
    });

    // Find and update existing extension
    const extIndex = cert.extensions.findIndex(
      (ext) => ext.name === "subjectKeyIdentifier"
    );
    if (extIndex !== -1) {
      cert.extensions[extIndex].subjectKeyIdentifier = ski;
    }
  }

  /**
   * Add Authority Key Identifier extension
   */
  addAuthorityKeyIdentifier(cert, issuerCert) {
    const aki = forge.pki.getPublicKeyFingerprint(issuerCert.publicKey, {
      type: "AuthorityKeyIdentifier",
    });

    // Find and update existing extension
    const extIndex = cert.extensions.findIndex(
      (ext) => ext.name === "authorityKeyIdentifier"
    );
    if (extIndex !== -1) {
      cert.extensions[extIndex].authorityKeyIdentifier = aki;
    }
  }

  /**
   * Validate certificate
   */
  validateCertificate(certPem, trustedCerts = []) {
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const now = new Date();

      // Check validity period
      if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
        return {
          valid: false,
          reason: "Certificate expired or not yet valid",
          notBefore: cert.validity.notBefore,
          notAfter: cert.validity.notAfter,
          currentTime: now,
        };
      }

      // Check if any trusted cert can verify this cert
      let verified = false;
      let verifiedBy = null;

      for (const trustedCertPem of trustedCerts) {
        const trustedCert = forge.pki.certificateFromPem(trustedCertPem);
        try {
          if (trustedCert.verify(cert)) {
            verified = true;
            verifiedBy = this.formatName(trustedCert.subject);
            break;
          }
        } catch (error) {
          // Continue to next certificate
        }
      }

      if (!verified) {
        return {
          valid: false,
          reason: "Certificate not signed by trusted authority",
        };
      }

      // Check basic constraints if present
      const basicConstraints = cert.extensions.find(
        (ext) => ext.name === "basicConstraints"
      );
      if (basicConstraints && basicConstraints.cA) {
        return {
          valid: true,
          isCA: true,
          verifiedBy: verifiedBy,
          subject: this.formatName(cert.subject),
          issuer: this.formatName(cert.issuer),
        };
      }

      return {
        valid: true,
        isCA: false,
        verifiedBy: verifiedBy,
        subject: this.formatName(cert.subject),
        issuer: this.formatName(cert.issuer),
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
      };
    } catch (error) {
      return {
        valid: false,
        reason: `Validation error: ${error.message}`,
      };
    }
  }

  /**
   * Inspect certificate details
   */
  inspectCertificate(certPem) {
    try {
      const cert = forge.pki.certificateFromPem(certPem);

      const extensions = {};
      cert.extensions.forEach((ext) => {
        extensions[ext.name] = {
          value: ext.value,
          critical: ext.critical,
        };
      });

      return {
        subject: this.formatName(cert.subject),
        issuer: this.formatName(cert.issuer),
        serialNumber: cert.serialNumber,
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
        signatureAlgorithm: cert.siginfo.algorithmOid,
        publicKey: {
          algorithm: cert.publicKey.constructor.name,
          n: cert.publicKey.n
            ? cert.publicKey.n.toString(16).substring(0, 64) + "..."
            : "N/A",
          e: cert.publicKey.e || "N/A",
        },
        extensions: extensions,
        isCA:
          extensions.basicConstraints &&
          extensions.basicConstraints.value &&
          extensions.basicConstraints.value.cA,
      };
    } catch (error) {
      return {
        error: `Failed to parse certificate: ${error.message}`,
      };
    }
  }

  /**
   * Convert certificate to different formats
   */
  convertCertificate(certPem, format) {
    const cert = forge.pki.certificateFromPem(certPem);

    switch (format.toLowerCase()) {
      case "der":
        return {
          format: "DER",
          data: forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(),
        };
      case "base64":
        return {
          format: "BASE64",
          data: Buffer.from(
            forge.pki.certificateToDer(cert).getBytes()
          ).toString("base64"),
        };
      case "json":
        return {
          format: "JSON",
          data: this.inspectCertificate(certPem),
        };
      default:
        return {
          format: "PEM",
          data: certPem,
        };
    }
  }
}

module.exports = X509Certificate;
