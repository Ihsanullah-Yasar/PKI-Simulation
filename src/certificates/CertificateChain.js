const forge = require("node-forge");

class CertificateChain {
  constructor() {
    this.forge = forge;
    forge.options.usePureJavaScript = true;
  }

  /**
   * Build certificate chain from leaf to root
   */
  buildChain(leafCertPem, intermediateCertsPem = [], rootCertPem = null) {
    const leafCert = forge.pki.certificateFromPem(leafCertPem);

    const chain = {
      leaf: leafCert,
      intermediates: [],
      root: null,
      valid: false,
      validationResult: null,
    };

    // Parse intermediate certificates
    const intermediateCerts = intermediateCertsPem.map((pem) =>
      forge.pki.certificateFromPem(pem)
    );
    chain.intermediates = intermediateCerts;

    // Parse root certificate if provided
    if (rootCertPem) {
      chain.root = forge.pki.certificateFromPem(rootCertPem);
    }

    // Validate the chain
    chain.validationResult = this.validateChain(chain);
    chain.valid = chain.validationResult.valid;

    return chain;
  }

  /**
   * Validate certificate chain
   */
  validateChain(chain) {
    const issues = [];
    const warnings = [];
    const certificates = [];

    // Start with leaf certificate
    let currentCert = chain.leaf;
    certificates.push({
      certificate: currentCert,
      type: "LEAF",
      subject: this.formatName(currentCert.subject),
      issuer: this.formatName(currentCert.issuer),
    });

    // Check leaf certificate validity
    const leafValidation = this.validateCertificate(currentCert, null);
    if (!leafValidation.valid) {
      issues.push(`Leaf certificate: ${leafValidation.reason}`);
    }

    // Try to build chain through intermediates
    let remainingIntermediates = [...chain.intermediates];
    let issuerCert = null;

    while (remainingIntermediates.length > 0) {
      // Find intermediate that issued current certificate
      const issuerIndex = remainingIntermediates.findIndex((intermediate) =>
        this.namesMatch(intermediate.subject, currentCert.issuer)
      );

      if (issuerIndex === -1) {
        warnings.push(
          `No intermediate found for issuer: ${this.formatName(
            currentCert.issuer
          )}`
        );
        break;
      }

      issuerCert = remainingIntermediates[issuerIndex];

      // Validate intermediate
      const intermediateValidation = this.validateCertificate(
        issuerCert,
        currentCert
      );
      if (!intermediateValidation.valid) {
        issues.push(
          `Intermediate certificate: ${intermediateValidation.reason}`
        );
      }

      certificates.push({
        certificate: issuerCert,
        type: "INTERMEDIATE",
        subject: this.formatName(issuerCert.subject),
        issuer: this.formatName(issuerCert.issuer),
      });

      // Remove used intermediate
      remainingIntermediates.splice(issuerIndex, 1);
      currentCert = issuerCert;
    }

    // Check if we reached a root certificate
    if (chain.root) {
      // Validate root certificate
      const rootValidation = this.validateCertificate(chain.root, null, true);
      if (!rootValidation.valid) {
        issues.push(`Root certificate: ${rootValidation.reason}`);
      }

      // Check if last certificate in chain is issued by root
      if (
        currentCert &&
        !this.namesMatch(chain.root.subject, currentCert.issuer)
      ) {
        issues.push("Chain does not link to root certificate");
      }

      certificates.push({
        certificate: chain.root,
        type: "ROOT",
        subject: this.formatName(chain.root.subject),
        issuer: this.formatName(chain.root.issuer),
      });
    } else {
      warnings.push(
        "No root certificate provided for complete chain validation"
      );
    }

    // Check for self-signed certificates in chain (except root)
    certificates.forEach((cert, index) => {
      if (cert.type !== "ROOT" && this.isSelfSigned(cert.certificate)) {
        warnings.push(
          `Self-signed certificate found in chain: ${cert.subject}`
        );
      }
    });

    // Check for circular references
    const circularRef = this.findCircularReference(certificates);
    if (circularRef) {
      issues.push(`Circular reference detected: ${circularRef}`);
    }

    return {
      valid: issues.length === 0,
      issues: issues,
      warnings: warnings,
      certificates: certificates.map((cert) => ({
        type: cert.type,
        subject: cert.subject,
        issuer: cert.issuer,
        validity: this.getValidityPeriod(cert.certificate),
      })),
      chainLength: certificates.length,
      complete: chain.root !== null && issues.length === 0,
    };
  }

  /**
   * Validate individual certificate
   */
  validateCertificate(cert, issuerCert = null, isRoot = false) {
    const now = new Date();

    // Check validity period
    if (now < cert.validity.notBefore) {
      return {
        valid: false,
        reason: `Certificate not valid until ${cert.validity.notBefore.toISOString()}`,
      };
    }

    if (now > cert.validity.notAfter) {
      return {
        valid: false,
        reason: `Certificate expired on ${cert.validity.notAfter.toISOString()}`,
      };
    }

    // Check signature if issuer is provided
    if (issuerCert) {
      try {
        const verified = issuerCert.verify(cert);
        if (!verified) {
          return {
            valid: false,
            reason: "Invalid signature",
          };
        }
      } catch (error) {
        return {
          valid: false,
          reason: `Signature verification failed: ${error.message}`,
        };
      }
    }

    // Check basic constraints
    const basicConstraints = cert.extensions.find(
      (ext) => ext.name === "basicConstraints"
    );
    if (basicConstraints) {
      if (isRoot && !basicConstraints.cA) {
        return {
          valid: false,
          reason: "Root certificate must have CA basic constraint",
        };
      }

      if (
        basicConstraints.pathLenConstraint !== undefined &&
        basicConstraints.pathLenConstraint < 0
      ) {
        return {
          valid: false,
          reason: "Path length constraint violation",
        };
      }
    }

    // Check key usage
    const keyUsage = cert.extensions.find((ext) => ext.name === "keyUsage");
    if (keyUsage) {
      if (isRoot && (!keyUsage.keyCertSign || !keyUsage.cRLSign)) {
        return {
          valid: false,
          reason:
            "Root certificate must have keyCertSign and cRLSign key usage",
        };
      }
    }

    return {
      valid: true,
      reason: "Certificate is valid",
    };
  }

  /**
   * Check if two names match
   */
  namesMatch(name1, name2) {
    const formatName = (name) => {
      return name.attributes
        .map((attr) => `${attr.type || attr.name}=${attr.value}`)
        .sort()
        .join(",");
    };

    return formatName(name1) === formatName(name2);
  }

  /**
   * Check if certificate is self-signed
   */
  isSelfSigned(cert) {
    return this.namesMatch(cert.subject, cert.issuer);
  }

  /**
   * Find circular references in chain
   */
  findCircularReference(certificates) {
    const visited = new Set();

    for (let i = 0; i < certificates.length; i++) {
      const cert = certificates[i];
      const certId = this.formatName(cert.certificate.subject);

      if (visited.has(certId)) {
        return certId;
      }

      visited.add(certId);

      // Check if this certificate's issuer is also in the chain (except for self-signed)
      const issuerId = this.formatName(cert.certificate.issuer);
      if (
        issuerId !== certId &&
        certificates.some(
          (c) => this.formatName(c.certificate.subject) === issuerId
        )
      ) {
        // Follow the issuer chain
        let currentIssuerId = issuerId;
        const chain = [certId];

        while (currentIssuerId && !chain.includes(currentIssuerId)) {
          chain.push(currentIssuerId);
          const issuerCert = certificates.find(
            (c) => this.formatName(c.certificate.subject) === currentIssuerId
          );

          if (!issuerCert) break;

          currentIssuerId = this.formatName(issuerCert.certificate.issuer);
          if (
            currentIssuerId === this.formatName(issuerCert.certificate.subject)
          ) {
            break; // Self-signed
          }
        }

        if (chain.includes(currentIssuerId)) {
          return chain.join(" -> ");
        }
      }
    }

    return null;
  }

  /**
   * Get validity period of certificate
   */
  getValidityPeriod(cert) {
    return {
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
      daysRemaining: Math.floor(
        (cert.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24)
      ),
    };
  }

  /**
   * Format name to string
   */
  formatName(name) {
    return name.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  /**
   * Export chain in different formats
   */
  exportChain(chain, format = "pem") {
    const certificates = [];

    // Collect all certificates
    certificates.push(chain.leaf);
    chain.intermediates.forEach((cert) => certificates.push(cert));
    if (chain.root) certificates.push(chain.root);

    switch (format.toLowerCase()) {
      case "pem":
        return {
          format: "PEM",
          data: certificates
            .map((cert) => forge.pki.certificateToPem(cert))
            .join("\n"),
        };

      case "pem-chain":
        // Leaf first, then intermediates, then root
        const orderedCerts = [chain.leaf, ...chain.intermediates];
        if (chain.root) orderedCerts.push(chain.root);

        return {
          format: "PEM_CHAIN",
          data: orderedCerts
            .map((cert) => forge.pki.certificateToPem(cert))
            .join("\n"),
        };

      case "pem-bundle":
        // All certificates in a bundle
        return {
          format: "PEM_BUNDLE",
          data: certificates
            .map((cert) => forge.pki.certificateToPem(cert))
            .join("\n"),
        };

      case "json":
        return {
          format: "JSON",
          data: {
            validation: chain.validationResult,
            certificates: certificates.map((cert) => ({
              subject: this.formatName(cert.subject),
              issuer: this.formatName(cert.issuer),
              serialNumber: cert.serialNumber,
              validity: this.getValidityPeriod(cert),
              isCA: cert.extensions.some(
                (ext) => ext.name === "basicConstraints" && ext.cA
              ),
            })),
          },
        };

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Find missing certificates in chain
   */
  findMissingCertificates(chain) {
    const missing = [];
    const certificates = [chain.leaf, ...chain.intermediates];

    // Check each certificate's issuer
    certificates.forEach((cert) => {
      const issuerName = this.formatName(cert.issuer);
      const issuerFound = certificates.some(
        (c) => this.formatName(c.subject) === issuerName
      );

      if (!issuerFound && !this.isSelfSigned(cert)) {
        missing.push({
          certificate: this.formatName(cert.subject),
          missingIssuer: issuerName,
        });
      }
    });

    return missing;
  }

  /**
   * Sort certificates in proper chain order
   */
  sortCertificates(certificatesPem) {
    const certificates = certificatesPem.map((pem) =>
      forge.pki.certificateFromPem(pem)
    );

    // Find leaf certificate (not an issuer of any other certificate)
    const leafCerts = certificates.filter(
      (cert) =>
        !certificates.some(
          (otherCert) =>
            this.namesMatch(cert.subject, otherCert.issuer) &&
            !this.namesMatch(cert.subject, otherCert.subject)
        )
    );

    if (leafCerts.length !== 1) {
      throw new Error(`Expected 1 leaf certificate, found ${leafCerts.length}`);
    }

    const leafCert = leafCerts[0];
    const sorted = [leafCert];
    const remaining = certificates.filter((cert) => cert !== leafCert);

    // Build chain by finding issuers
    let currentCert = leafCert;
    while (remaining.length > 0) {
      const issuerIndex = remaining.findIndex((cert) =>
        this.namesMatch(cert.subject, currentCert.issuer)
      );

      if (issuerIndex === -1) {
        // No more issuers found
        break;
      }

      const issuerCert = remaining[issuerIndex];
      sorted.push(issuerCert);
      remaining.splice(issuerIndex, 1);
      currentCert = issuerCert;
    }

    // Add any remaining certificates (likely root or unrelated)
    sorted.push(...remaining);

    return sorted.map((cert) => forge.pki.certificateToPem(cert));
  }

  /**
   * Verify chain against a trust store
   */
  verifyChainAgainstTrustStore(chain, trustStorePems) {
    const trustStore = trustStorePems.map((pem) =>
      forge.pki.certificateFromPem(pem)
    );

    const results = [];

    // Check each certificate in trust store
    trustStore.forEach((trustedCert, index) => {
      // Check if trusted cert is in our chain
      const inChain = [chain.leaf, ...chain.intermediates, chain.root].some(
        (cert) => cert && this.namesMatch(cert.subject, trustedCert.subject)
      );

      if (inChain) {
        results.push({
          trustedCert: this.formatName(trustedCert.subject),
          status: "IN_CHAIN",
          message: "Trusted certificate found in chain",
        });
      } else {
        // Check if trusted cert can validate any certificate in chain
        const canValidate = [chain.leaf, ...chain.intermediates].some(
          (cert) => {
            try {
              return trustedCert.verify(cert);
            } catch {
              return false;
            }
          }
        );

        if (canValidate) {
          results.push({
            trustedCert: this.formatName(trustedCert.subject),
            status: "CAN_VALIDATE",
            message: "Trusted certificate can validate chain",
          });
        }
      }
    });

    return {
      verified: results.some(
        (r) => r.status === "CAN_VALIDATE" || r.status === "IN_CHAIN"
      ),
      results: results,
      trustStoreSize: trustStore.length,
    };
  }
}

module.exports = CertificateChain;
