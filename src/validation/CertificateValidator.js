const forge = require("node-forge");
const crypto = require("crypto");

class CertificateValidator {
  constructor() {
    this.forge = forge;
    forge.options.usePureJavaScript = true;
  }

  /**
   * Comprehensive certificate validation
   */
  validateCertificate(certPem, options = {}) {
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const now = new Date();

      const results = {
        valid: true,
        errors: [],
        warnings: [],
        details: {},
        timestamp: now.toISOString(),
      };

      // 1. Check validity period
      if (now < cert.validity.notBefore) {
        results.valid = false;
        results.errors.push(
          `Certificate not valid until ${cert.validity.notBefore.toISOString()}`
        );
      }

      if (now > cert.validity.notAfter) {
        results.valid = false;
        results.errors.push(
          `Certificate expired on ${cert.validity.notAfter.toISOString()}`
        );
      }

      results.details.validity = {
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
        currentTime: now,
        daysRemaining: Math.floor(
          (cert.validity.notAfter - now) / (1000 * 60 * 60 * 24)
        ),
      };

      // 2. Check basic constraints
      const basicConstraints = cert.extensions.find(
        (ext) => ext.name === "basicConstraints"
      );
      if (basicConstraints) {
        results.details.basicConstraints = {
          cA: basicConstraints.cA,
          pathLenConstraint: basicConstraints.pathLenConstraint,
          critical: basicConstraints.critical,
        };

        if (options.requireCA && !basicConstraints.cA) {
          results.valid = false;
          results.errors.push("Certificate missing CA basic constraint");
        }

        if (options.rejectCA && basicConstraints.cA) {
          results.valid = false;
          results.errors.push("CA certificates are not allowed");
        }
      } else if (options.requireCA) {
        results.valid = false;
        results.errors.push("Basic constraints extension missing");
      }

      // 3. Check key usage
      const keyUsage = cert.extensions.find((ext) => ext.name === "keyUsage");
      if (keyUsage) {
        results.details.keyUsage = {
          digitalSignature: keyUsage.digitalSignature,
          nonRepudiation: keyUsage.nonRepudiation,
          keyEncipherment: keyUsage.keyEncipherment,
          dataEncipherment: keyUsage.dataEncipherment,
          keyAgreement: keyUsage.keyAgreement,
          keyCertSign: keyUsage.keyCertSign,
          cRLSign: keyUsage.cRLSign,
          encipherOnly: keyUsage.encipherOnly,
          decipherOnly: keyUsage.decipherOnly,
          critical: keyUsage.critical,
        };

        // Validate against required key usage
        if (options.requiredKeyUsage) {
          for (const usage of options.requiredKeyUsage) {
            if (!keyUsage[usage]) {
              results.valid = false;
              results.errors.push(`Missing required key usage: ${usage}`);
            }
          }
        }

        // Warn about inappropriate key usage
        if (basicConstraints && basicConstraints.cA && !keyUsage.keyCertSign) {
          results.warnings.push("CA certificate missing keyCertSign key usage");
        }
      }

      // 4. Check extended key usage
      const extKeyUsage = cert.extensions.find(
        (ext) => ext.name === "extKeyUsage"
      );
      if (extKeyUsage) {
        results.details.extendedKeyUsage = {
          serverAuth: extKeyUsage.serverAuth,
          clientAuth: extKeyUsage.clientAuth,
          codeSigning: extKeyUsage.codeSigning,
          emailProtection: extKeyUsage.emailProtection,
          timeStamping: extKeyUsage.timeStamping,
          OCSPSigning: extKeyUsage.OCSPSigning,
        };

        // Validate against required extended key usage
        if (options.requiredExtendedKeyUsage) {
          for (const usage of options.requiredExtendedKeyUsage) {
            if (!extKeyUsage[usage]) {
              results.valid = false;
              results.errors.push(
                `Missing required extended key usage: ${usage}`
              );
            }
          }
        }
      }

      // 5. Check subject alternative names
      const san = cert.extensions.find((ext) => ext.name === "subjectAltName");
      if (san) {
        results.details.subjectAltNames = san.altNames.map((altName) => ({
          type: this.getAltNameType(altName.type),
          value: altName.value || altName.ip,
        }));
      }

      // 6. Check subject and issuer
      results.details.subject = this.formatName(cert.subject);
      results.details.issuer = this.formatName(cert.issuer);
      results.details.serialNumber = cert.serialNumber;
      results.details.signatureAlgorithm = cert.siginfo.algorithmOid;

      // 7. Check public key
      results.details.publicKey = {
        algorithm: cert.publicKey.constructor.name,
        keySize: this.getKeySize(cert.publicKey),
        fingerprint: this.getPublicKeyFingerprint(cert.publicKey),
      };

      // Validate key size
      if (
        options.minKeySize &&
        results.details.publicKey.keySize < options.minKeySize
      ) {
        results.valid = false;
        results.errors.push(
          `Key size ${results.details.publicKey.keySize} bits is less than minimum ${options.minKeySize} bits`
        );
      }

      // 8. Check for weak algorithms
      if (this.isWeakAlgorithm(cert.siginfo.algorithmOid)) {
        results.warnings.push(
          `Weak signature algorithm: ${cert.siginfo.algorithmOid}`
        );
      }

      // 9. Check for self-signed certificate
      const isSelfSigned = this.isSelfSigned(cert);
      results.details.selfSigned = isSelfSigned;

      if (isSelfSigned && options.rejectSelfSigned) {
        results.valid = false;
        results.errors.push("Self-signed certificates are not allowed");
      }

      // 10. Check certificate policies if required
      if (options.checkPolicies) {
        const policies = this.checkCertificatePolicies(cert);
        if (policies.length > 0) {
          results.details.policies = policies;
        }
      }

      return results;
    } catch (error) {
      return {
        valid: false,
        errors: [`Failed to parse certificate: ${error.message}`],
        warnings: [],
        details: {},
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Validate certificate chain
   */
  validateChain(
    leafCertPem,
    chainCertsPem = [],
    trustedRootsPem = [],
    options = {}
  ) {
    const results = {
      valid: true,
      errors: [],
      warnings: [],
      chain: [],
      timestamp: new Date().toISOString(),
    };

    try {
      const leafCert = forge.pki.certificateFromPem(leafCertPem);
      const chainCerts = chainCertsPem.map((pem) =>
        forge.pki.certificateFromPem(pem)
      );
      const trustedRoots = trustedRootsPem.map((pem) =>
        forge.pki.certificateFromPem(pem)
      );

      // Start with leaf certificate
      let currentCert = leafCert;
      results.chain.push({
        certificate: this.formatName(currentCert.subject),
        type: "LEAF",
        validation: this.validateCertificate(leafCertPem, options),
      });

      // Build chain
      let remainingChainCerts = [...chainCerts];
      let chainBuilt = false;

      while (remainingChainCerts.length > 0 && !chainBuilt) {
        // Find issuer in chain
        const issuerIndex = remainingChainCerts.findIndex((candidate) =>
          this.namesMatch(candidate.subject, currentCert.issuer)
        );

        if (issuerIndex === -1) {
          break; // No more issuers in chain
        }

        const issuerCert = remainingChainCerts[issuerIndex];

        // Validate issuer certificate
        const issuerPem = forge.pki.certificateToPem(issuerCert);
        const issuerValidation = this.validateCertificate(issuerPem, {
          ...options,
          requireCA: true,
        });

        // Verify signature
        let signatureValid = false;
        try {
          signatureValid = issuerCert.verify(currentCert);
        } catch (error) {
          signatureValid = false;
        }

        if (!signatureValid) {
          results.valid = false;
          results.errors.push(
            `Invalid signature for ${this.formatName(currentCert.subject)}`
          );
        }

        results.chain.push({
          certificate: this.formatName(issuerCert.subject),
          type: "INTERMEDIATE",
          validation: issuerValidation,
          signatureValid: signatureValid,
        });

        // Remove used certificate
        remainingChainCerts.splice(issuerIndex, 1);
        currentCert = issuerCert;

        // Check if we reached a trusted root
        const isTrustedRoot = trustedRoots.some((root) =>
          this.namesMatch(root.subject, currentCert.subject)
        );

        if (isTrustedRoot) {
          chainBuilt = true;
          results.chain[results.chain.length - 1].type = "TRUSTED_ROOT";
        }
      }

      // Check if chain is complete
      if (!chainBuilt) {
        // Check if current certificate is self-signed (root)
        if (this.isSelfSigned(currentCert)) {
          // Check if this root is trusted
          const isTrusted = trustedRoots.some((root) =>
            this.namesMatch(root.subject, currentCert.subject)
          );

          if (isTrusted) {
            results.chain[results.chain.length - 1].type = "TRUSTED_ROOT";
            chainBuilt = true;
          } else {
            results.valid = false;
            results.errors.push(
              "Chain ends with untrusted self-signed certificate"
            );
          }
        } else {
          results.valid = false;
          results.errors.push("Incomplete certificate chain");
        }
      }

      // Check for unused certificates
      if (remainingChainCerts.length > 0) {
        results.warnings.push(
          `${remainingChainCerts.length} unused certificates in chain`
        );
      }

      // Validate entire chain
      for (const link of results.chain) {
        if (!link.validation.valid) {
          results.valid = false;
          results.errors.push(
            ...link.validation.errors.map(
              (err) => `${link.certificate}: ${err}`
            )
          );
        }

        if (link.validation.warnings.length > 0) {
          results.warnings.push(
            ...link.validation.warnings.map(
              (warn) => `${link.certificate}: ${warn}`
            )
          );
        }
      }

      // Check chain length
      if (
        options.maxChainLength &&
        results.chain.length > options.maxChainLength
      ) {
        results.warnings.push(
          `Chain length ${results.chain.length} exceeds maximum ${options.maxChainLength}`
        );
      }

      results.chainLength = results.chain.length;
      results.complete = chainBuilt;
    } catch (error) {
      results.valid = false;
      results.errors.push(`Chain validation failed: ${error.message}`);
    }

    return results;
  }

  /**
   * Check certificate against Certificate Revocation List (CRL)
   */
  checkCRL(certPem, crlPem) {
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const crl = forge.pki.crlFromPem(crlPem);

      // Check if certificate is revoked
      const isRevoked = crl.isRevoked(cert);

      return {
        revoked: isRevoked,
        crlInfo: {
          issuer: this.formatName(crl.issuer),
          thisUpdate: crl.thisUpdate,
          nextUpdate: crl.nextUpdate,
          revokedCerts: crl.revokedCertificates
            ? crl.revokedCertificates.length
            : 0,
        },
        certificate: {
          serialNumber: cert.serialNumber,
          subject: this.formatName(cert.subject),
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
   * Validate certificate for specific purpose
   */
  validateForPurpose(certPem, purpose, options = {}) {
    const purposeConfigs = {
      webserver: {
        requiredExtendedKeyUsage: ["serverAuth"],
        requiredKeyUsage: ["digitalSignature", "keyEncipherment"],
        minKeySize: 2048,
        rejectCA: true,
        checkPolicies: true,
      },
      client: {
        requiredExtendedKeyUsage: ["clientAuth"],
        requiredKeyUsage: ["digitalSignature"],
        minKeySize: 2048,
        rejectCA: true,
      },
      codesigning: {
        requiredExtendedKeyUsage: ["codeSigning"],
        requiredKeyUsage: ["digitalSignature"],
        minKeySize: 2048,
        rejectCA: true,
      },
      email: {
        requiredExtendedKeyUsage: ["emailProtection"],
        requiredKeyUsage: ["digitalSignature", "keyEncipherment"],
        minKeySize: 2048,
        rejectCA: true,
      },
      ca: {
        requiredKeyUsage: ["keyCertSign", "cRLSign"],
        requireCA: true,
        minKeySize: 4096,
      },
    };

    const config = purposeConfigs[purpose] || purposeConfigs.webserver;
    const mergedOptions = { ...config, ...options };

    return this.validateCertificate(certPem, mergedOptions);
  }

  /**
   * Verify certificate signature
   */
  verifySignature(certPem, issuerCertPem) {
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const issuerCert = forge.pki.certificateFromPem(issuerCertPem);

      const verified = issuerCert.verify(cert);

      return {
        verified: verified,
        certificate: this.formatName(cert.subject),
        issuer: this.formatName(issuerCert.subject),
      };
    } catch (error) {
      return {
        verified: false,
        error: error.message,
      };
    }
  }

  /**
   * Get certificate expiration status
   */
  getExpirationStatus(certPem, warningDays = 30) {
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const now = new Date();
      const notAfter = cert.validity.notAfter;

      const daysRemaining = Math.floor(
        (notAfter - now) / (1000 * 60 * 60 * 24)
      );

      let status = "VALID";
      if (now < cert.validity.notBefore) {
        status = "NOT_YET_VALID";
      } else if (daysRemaining < 0) {
        status = "EXPIRED";
      } else if (daysRemaining <= warningDays) {
        status = "EXPIRING_SOON";
      }

      return {
        status: status,
        daysRemaining: daysRemaining,
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
        currentTime: now,
      };
    } catch (error) {
      return {
        status: "ERROR",
        error: error.message,
      };
    }
  }

  /**
   * Helper methods
   */
  formatName(name) {
    return name.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  namesMatch(name1, name2) {
    const format = (name) =>
      name.attributes
        .map((attr) => `${attr.type || attr.name}=${attr.value}`)
        .sort()
        .join(",");

    return format(name1) === format(name2);
  }

  isSelfSigned(cert) {
    return this.namesMatch(cert.subject, cert.issuer);
  }

  getKeySize(publicKey) {
    if (publicKey.n) {
      // RSA key
      return publicKey.n.bitLength();
    } else if (publicKey.q) {
      // DSA key
      return publicKey.q.bitLength();
    } else {
      // ECDSA or other
      return 0;
    }
  }

  getPublicKeyFingerprint(publicKey) {
    const md = forge.md.sha256.create();
    md.update(forge.pki.publicKeyToPem(publicKey));
    return md.digest().toHex();
  }

  getAltNameType(type) {
    const types = {
      0: "otherName",
      1: "rfc822Name",
      2: "dNSName",
      3: "x400Address",
      4: "directoryName",
      5: "ediPartyName",
      6: "uniformResourceIdentifier",
      7: "iPAddress",
      8: "registeredID",
    };
    return types[type] || `unknown(${type})`;
  }

  isWeakAlgorithm(algorithmOid) {
    const weakAlgorithms = [
      forge.pki.oids.md2WithRSAEncryption,
      forge.pki.oids.md5WithRSAEncryption,
      forge.pki.oids.sha1WithRSAEncryption,
    ];
    return weakAlgorithms.includes(algorithmOid);
  }

  checkCertificatePolicies(cert) {
    const policies = [];
    const certPolicies = cert.extensions.find(
      (ext) => ext.name === "certificatePolicies"
    );

    if (certPolicies && certPolicies.certificatePolicies) {
      certPolicies.certificatePolicies.forEach((policy) => {
        policies.push({
          policyIdentifier: policy.policyIdentifier,
          policyQualifiers: policy.policyQualifiers || [],
        });
      });
    }

    return policies;
  }

  /**
   * Validate certificate against name constraints
   */
  validateNameConstraints(certPem, allowedDomains = [], allowedIPs = []) {
    const cert = forge.pki.certificateFromPem(certPem);
    const errors = [];
    const warnings = [];

    // Check Subject CN
    const cn = cert.subject.getField("CN");
    if (cn) {
      const domainMatch = allowedDomains.some(
        (domain) => cn.value === domain || cn.value.endsWith("." + domain)
      );

      if (!domainMatch && allowedDomains.length > 0) {
        errors.push(`Subject CN '${cn.value}' not in allowed domains`);
      }
    }

    // Check Subject Alternative Names
    const san = cert.extensions.find((ext) => ext.name === "subjectAltName");
    if (san && san.altNames) {
      for (const altName of san.altNames) {
        if (altName.type === 2) {
          // DNS
          const dnsMatch = allowedDomains.some(
            (domain) =>
              altName.value === domain || altName.value.endsWith("." + domain)
          );

          if (!dnsMatch && allowedDomains.length > 0) {
            errors.push(`SAN DNS '${altName.value}' not in allowed domains`);
          }
        } else if (altName.type === 7) {
          // IP
          const ipMatch = allowedIPs.some((ip) => altName.ip === ip);

          if (!ipMatch && allowedIPs.length > 0) {
            warnings.push(`SAN IP '${altName.ip}' not in allowed IPs`);
          }
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors,
      warnings: warnings,
      subject: this.formatName(cert.subject),
      san: san ? san.altNames.length : 0,
    };
  }
}

module.exports = CertificateValidator;
