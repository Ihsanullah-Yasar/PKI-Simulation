const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const forge = require("node-forge");

const KeyPairGenerator = require("../crypto/KeyPairGenerator");
const X509Certificate = require("../certificates/X509Certificate");
const CertificateChain = require("../certificates/CertificateChain");
const CRLManager = require("../validation/CRLManager");

class CertificateAuthority {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs",
      keySize: config.keySize || 2048,
      rootValidityYears: config.rootValidityYears || 10,
      intermediateValidityYears: config.intermediateValidityYears || 5,
      serverValidityDays: config.serverValidityDays || 365,
      defaultCountry: config.defaultCountry || "US",
      defaultOrganization: config.defaultOrganization || "Classroom PKI Inc.",
      ...config,
    };

    this.keyGen = new KeyPairGenerator();
    this.x509 = new X509Certificate();
    this.chainValidator = new CertificateChain();
    this.crlManager = new CRLManager();

    this.certificates = new Map(); // serialNumber -> cert info
    this.revokedCertificates = new Set();

    this.ensureDirectories();
    this.loadExistingCertificates();
  }

  /**
   * Ensure all required directories exist
   */
  ensureDirectories() {
    const dirs = [
      this.config.basePath,
      path.join(this.config.basePath, "root"),
      path.join(this.config.basePath, "intermediate"),
      path.join(this.config.basePath, "server"),
      path.join(this.config.basePath, "client"),
      path.join(this.config.basePath, "email"),
      path.join(this.config.basePath, "code"),
      path.join(this.config.basePath, "crl"),
      path.join(this.config.basePath, "csr"),
      path.join(this.config.basePath, "archive"),
    ];

    dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Load existing certificates from filesystem
   */
  loadExistingCertificates() {
    const certTypes = [
      "root",
      "intermediate",
      "server",
      "client",
      "email",
      "code",
    ];

    certTypes.forEach((type) => {
      const typePath = path.join(this.config.basePath, type);
      if (fs.existsSync(typePath)) {
        const files = fs
          .readdirSync(typePath)
          .filter((f) => f.endsWith(".crt"));

        files.forEach((file) => {
          try {
            const certPath = path.join(typePath, file);
            const certPem = fs.readFileSync(certPath, "utf8");
            const cert = forge.pki.certificateFromPem(certPem);

            this.certificates.set(cert.serialNumber, {
              type: type,
              path: certPath,
              certificate: cert,
              pem: certPem,
              subject: this.x509.formatName(cert.subject),
              issuer: this.x509.formatName(cert.issuer),
              notBefore: cert.validity.notBefore,
              notAfter: cert.validity.notAfter,
              serialNumber: cert.serialNumber,
            });
          } catch (error) {
            console.warn(
              `Failed to load certificate ${file}: ${error.message}`
            );
          }
        });
      }
    });

    console.log(`Loaded ${this.certificates.size} existing certificates`);
  }

  /**
   * Initialize a complete PKI hierarchy
   */
  async initializePKI(options = {}) {
    console.log("🔐 Initializing PKI Hierarchy...\n");

    const {
      organization = this.config.defaultOrganization,
      country = this.config.defaultCountry,
      state = "California",
      locality = "San Francisco",
    } = options;

    // 1. Create Root CA
    console.log("📜 Step 1: Creating Root Certificate Authority");
    const rootKeys = this.keyGen.generateRSAKeyPair(4096);
    const rootSubject = `/C=${country}/ST=${state}/L=${locality}/O=${organization}/OU=Certificate Authority/CN=${organization} Root CA`;

    const rootCA = this.x509.createRootCA(
      rootSubject,
      rootKeys,
      this.config.rootValidityYears
    );

    this.saveCertificate("root", "root-ca", rootCA);
    this.saveKeyPair("root", "root-ca", rootKeys);

    console.log(`✅ Root CA created: ${rootCA.subject}`);
    console.log(
      `   Valid: ${rootCA.notBefore.toDateString()} to ${rootCA.notAfter.toDateString()}\n`
    );

    // 2. Create Intermediate CA
    console.log("📜 Step 2: Creating Intermediate CA");
    const intermediateKeys = this.keyGen.generateRSAKeyPair(
      this.config.keySize
    );
    const intermediateSubject = `/C=${country}/ST=${state}/L=${locality}/O=${organization}/OU=Intermediate Authority/CN=${organization} Intermediate CA`;

    const intermediateCA = this.x509.createIntermediateCA(
      intermediateSubject,
      intermediateKeys,
      rootCA,
      rootKeys.privateKey,
      this.config.intermediateValidityYears
    );

    this.saveCertificate("intermediate", "intermediate-ca", intermediateCA);
    this.saveKeyPair("intermediate", "intermediate-ca", intermediateKeys);

    console.log(`✅ Intermediate CA created: ${intermediateCA.subject}\n`);

    // 3. Create default server certificate
    console.log("📜 Step 3: Creating default server certificate");
    const serverKeys = this.keyGen.generateRSAKeyPair(this.config.keySize);
    const serverCert = this.x509.createEndEntityCertificate(
      `/CN=localhost`,
      serverKeys,
      intermediateCA,
      intermediateKeys.privateKey,
      {
        validityDays: 365,
        san: ["DNS:localhost", "IP:127.0.0.1", "IP:::1"],
        keyUsage: ["digitalSignature", "keyEncipherment"],
        extendedKeyUsage: ["serverAuth", "clientAuth"],
      }
    );

    this.saveCertificate("server", "localhost", serverCert);
    this.saveKeyPair("server", "localhost", serverKeys);

    // Create certificate chain file
    const chainPem =
      rootCA.pem + "\n" + intermediateCA.pem + "\n" + serverCert.pem;
    this.saveFile("server", "localhost-chain.pem", chainPem);

    console.log(`✅ Server certificate created: localhost`);
    console.log(`   SAN: localhost, 127.0.0.1, ::1\n`);

    // 4. Initialize CRL
    console.log("📜 Step 4: Initializing Certificate Revocation Lists");
    await this.crlManager.initialize(rootCA.certificate, rootKeys.privateKey);

    this.saveFile("root", "root-ca.crl", this.crlManager.getRootCRLPem());

    console.log("✅ CRL initialized\n");

    return {
      rootCA,
      intermediateCA,
      serverCert,
      certificates: {
        root: this.getCertificatePath("root", "root-ca.crt"),
        intermediate: this.getCertificatePath(
          "intermediate",
          "intermediate-ca.crt"
        ),
        server: this.getCertificatePath("server", "localhost.crt"),
        chain: this.getCertificatePath("server", "localhost-chain.pem"),
        crl: this.getCertificatePath("root", "root-ca.crl"),
      },
      keys: {
        root: this.getKeyPath("root", "root-ca_private.pem"),
        intermediate: this.getKeyPath(
          "intermediate",
          "intermediate-ca_private.pem"
        ),
        server: this.getKeyPath("server", "localhost_private.pem"),
      },
    };
  }

  /**
   * Issue a new certificate
   */
  issueCertificate(csrPem, certType = "server", options = {}) {
    // Load intermediate CA
    const intermediateCert = this.loadCertificate(
      "intermediate",
      "intermediate-ca.crt"
    );
    const intermediateKey = this.loadPrivateKey(
      "intermediate",
      "intermediate-ca_private.pem"
    );

    if (!intermediateCert || !intermediateKey) {
      throw new Error("Intermediate CA not found. Initialize PKI first.");
    }

    // Parse CSR
    const forge = require("node-forge");
    const csr = forge.pki.certificationRequestFromPem(csrPem);

    if (!csr.verify()) {
      throw new Error("Invalid CSR signature");
    }

    // Determine certificate options based on type
    const certOptions = this.getCertificateOptions(certType, options);

    // Create certificate from CSR
    const keyPair = {
      publicKey: forge.pki.publicKeyToPem(csr.publicKey),
      privateKey: null, // CSR doesn't include private key
    };

    const subject = this.x509.formatName(csr.subject);
    const cert = this.x509.createEndEntityCertificate(
      subject,
      keyPair,
      intermediateCert,
      intermediateKey,
      certOptions
    );

    // Generate unique filename
    const commonName = csr.subject.getField("CN")?.value || "unknown";
    const safeName = commonName.replace(/[^a-zA-Z0-9.-]/g, "_");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const fileName = `${safeName}_${timestamp}`;

    // Save certificate
    this.saveCertificate(certType, fileName, cert);

    // Store in registry
    this.certificates.set(cert.serialNumber, {
      type: certType,
      path: this.getCertificatePath(certType, `${fileName}.crt`),
      certificate: cert.certificate,
      pem: cert.pem,
      subject: cert.subject,
      issuer: cert.issuer,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      serialNumber: cert.serialNumber,
      csr: csrPem,
    });

    console.log(`✅ Certificate issued: ${cert.subject}`);
    console.log(`   Type: ${certType}`);
    console.log(`   Serial: ${cert.serialNumber}`);
    console.log(`   Valid until: ${cert.notAfter.toDateString()}`);

    return {
      certificate: cert,
      serialNumber: cert.serialNumber,
      filePath: this.getCertificatePath(certType, `${fileName}.crt`),
    };
  }

  /**
   * Get certificate options based on type
   */
  getCertificateOptions(certType, userOptions = {}) {
    const defaultOptions = {
      server: {
        validityDays: this.config.serverValidityDays,
        keyUsage: ["digitalSignature", "keyEncipherment"],
        extendedKeyUsage: ["serverAuth", "clientAuth"],
        san: userOptions.san || [],
      },
      client: {
        validityDays: 365,
        keyUsage: ["digitalSignature", "keyEncipherment"],
        extendedKeyUsage: ["clientAuth"],
        san: userOptions.san || [],
      },
      email: {
        validityDays: 365,
        keyUsage: ["digitalSignature", "keyEncipherment"],
        extendedKeyUsage: ["emailProtection"],
      },
      code: {
        validityDays: 1095, // 3 years for code signing
        keyUsage: ["digitalSignature"],
        extendedKeyUsage: ["codeSigning"],
      },
      ocsp: {
        validityDays: 365,
        keyUsage: ["digitalSignature"],
        extendedKeyUsage: ["OCSPSigning"],
      },
    };

    return {
      ...(defaultOptions[certType] || defaultOptions.server),
      ...userOptions,
    };
  }

  /**
   * Revoke a certificate
   */
  async revokeCertificate(serialNumber, reason = "unspecified") {
    const certInfo = this.certificates.get(serialNumber);

    if (!certInfo) {
      throw new Error(`Certificate with serial ${serialNumber} not found`);
    }

    // Load root CA for CRL signing
    const rootCert = this.loadCertificate("root", "root-ca.crt");
    const rootKey = this.loadPrivateKey("root", "root-ca_private.pem");

    if (!rootCert || !rootKey) {
      throw new Error("Root CA not found");
    }

    // Add to revoked list
    this.revokedCertificates.add(serialNumber);

    // Update CRL
    await this.crlManager.revokeCertificate(
      certInfo.certificate,
      rootCert.certificate,
      rootKey,
      reason
    );

    // Save updated CRL
    this.saveFile("root", "root-ca.crl", this.crlManager.getRootCRLPem());

    console.log(`❌ Certificate revoked: ${serialNumber}`);
    console.log(`   Subject: ${certInfo.subject}`);
    console.log(`   Reason: ${reason}`);

    return {
      serialNumber,
      revoked: true,
      reason,
      revocationDate: new Date().toISOString(),
      crlNumber: this.crlManager.getCRLNumber(),
    };
  }

  /**
   * Check if certificate is revoked
   */
  isRevoked(serialNumber) {
    return (
      this.revokedCertificates.has(serialNumber) ||
      this.crlManager.isCertificateRevoked(serialNumber)
    );
  }

  /**
   * Validate certificate
   */
  validateCertificate(certPem) {
    // Load trust chain
    const rootCert = this.loadCertificate("root", "root-ca.crt");
    const intermediateCert = this.loadCertificate(
      "intermediate",
      "intermediate-ca.crt"
    );

    if (!rootCert || !intermediateCert) {
      throw new Error("Trust chain not found");
    }

    // Build certificate chain
    const chain = this.chainValidator.buildChain(
      certPem,
      [intermediateCert.pem],
      rootCert.pem
    );

    // Check revocation
    const cert = forge.pki.certificateFromPem(certPem);
    const isRevoked = this.isRevoked(cert.serialNumber);

    return {
      chainValidation: chain.validationResult,
      revoked: isRevoked,
      valid: chain.valid && !isRevoked,
      certificate: this.x509.inspectCertificate(certPem),
    };
  }

  /**
   * List all issued certificates
   */
  listCertificates(filter = {}) {
    const certs = Array.from(this.certificates.values());

    let filtered = certs;

    if (filter.type) {
      filtered = filtered.filter((cert) => cert.type === filter.type);
    }

    if (filter.valid === true) {
      const now = new Date();
      filtered = filtered.filter(
        (cert) => now >= cert.notBefore && now <= cert.notAfter
      );
    }

    if (filter.revoked === true) {
      filtered = filtered.filter((cert) =>
        this.revokedCertificates.has(cert.serialNumber)
      );
    }

    return filtered.map((cert) => ({
      type: cert.type,
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      validFrom: cert.notBefore,
      validTo: cert.notAfter,
      revoked: this.revokedCertificates.has(cert.serialNumber),
      path: cert.path,
    }));
  }

  /**
   * Get certificate by serial number
   */
  getCertificate(serialNumber) {
    return this.certificates.get(serialNumber);
  }

  /**
   * Export certificate in different formats
   */
  exportCertificate(serialNumber, format = "pem") {
    const certInfo = this.certificates.get(serialNumber);

    if (!certInfo) {
      throw new Error(`Certificate ${serialNumber} not found`);
    }

    return this.x509.convertCertificate(certInfo.pem, format);
  }

  /**
   * Save certificate to file
   */
  saveCertificate(type, name, certData) {
    const dirPath = path.join(this.config.basePath, type);
    const certPath = path.join(dirPath, `${name}.crt`);

    fs.writeFileSync(certPath, certData.pem, "utf8");

    // Also save as JSON for metadata
    const metaPath = path.join(dirPath, `${name}.json`);
    const metadata = {
      type: type,
      name: name,
      subject: certData.subject,
      issuer: certData.issuer,
      serialNumber: certData.serialNumber,
      notBefore: certData.notBefore?.toISOString(),
      notAfter: certData.notAfter?.toISOString(),
      created: new Date().toISOString(),
    };

    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2), "utf8");

    return certPath;
  }

  /**
   * Save key pair
   */
  saveKeyPair(type, name, keyPair) {
    const dirPath = path.join(this.config.basePath, type);

    // Save private key
    const privKeyPath = path.join(dirPath, `${name}_private.pem`);
    fs.writeFileSync(privKeyPath, keyPair.privateKey, "utf8");

    // Save public key
    const pubKeyPath = path.join(dirPath, `${name}_public.pem`);
    fs.writeFileSync(pubKeyPath, keyPair.publicKey, "utf8");

    return { privateKey: privKeyPath, publicKey: pubKeyPath };
  }

  /**
   * Save any file
   */
  saveFile(type, filename, content) {
    const filePath = path.join(this.config.basePath, type, filename);
    fs.writeFileSync(filePath, content, "utf8");
    return filePath;
  }

  /**
   * Load certificate from file
   */
  loadCertificate(type, filename) {
    const certPath = path.join(this.config.basePath, type, filename);

    if (!fs.existsSync(certPath)) {
      return null;
    }

    try {
      const certPem = fs.readFileSync(certPath, "utf8");
      const cert = forge.pki.certificateFromPem(certPem);

      return {
        certificate: cert,
        pem: certPem,
        subject: this.x509.formatName(cert.subject),
        issuer: this.x509.formatName(cert.issuer),
      };
    } catch (error) {
      console.warn(`Failed to load certificate ${certPath}: ${error.message}`);
      return null;
    }
  }

  /**
   * Load private key from file
   */
  loadPrivateKey(type, filename) {
    const keyPath = path.join(this.config.basePath, type, filename);

    if (!fs.existsSync(keyPath)) {
      return null;
    }

    return fs.readFileSync(keyPath, "utf8");
  }

  /**
   * Get certificate path
   */
  getCertificatePath(type, filename) {
    return path.join(this.config.basePath, type, filename);
  }

  /**
   * Get key path
   */
  getKeyPath(type, filename) {
    return path.join(this.config.basePath, type, filename);
  }

  /**
   * Display PKI hierarchy
   */
  displayHierarchy() {
    console.log("\n🌳 PKI Hierarchy");
    console.log("=".repeat(60));

    // Root CA
    const rootCert = this.loadCertificate("root", "root-ca.crt");
    if (rootCert) {
      console.log("📜 Root Certificate Authority:");
      console.log(`   Subject: ${rootCert.subject}`);
      console.log(`   Issuer: ${rootCert.issuer} (self-signed)`);
      console.log(`   Path: ${this.getCertificatePath("root", "root-ca.crt")}`);
    }

    // Intermediate CA
    const intermediateCert = this.loadCertificate(
      "intermediate",
      "intermediate-ca.crt"
    );
    if (intermediateCert) {
      console.log("\n📜 Intermediate Certificate Authority:");
      console.log(`   Subject: ${intermediateCert.subject}`);
      console.log(`   Issuer: ${intermediateCert.issuer}`);
      console.log(
        `   Path: ${this.getCertificatePath(
          "intermediate",
          "intermediate-ca.crt"
        )}`
      );
    }

    // Issued certificates by type
    const certTypes = ["server", "client", "email", "code"];

    certTypes.forEach((type) => {
      const certs = this.listCertificates({ type: type });
      if (certs.length > 0) {
        console.log(
          `\n📜 ${type.toUpperCase()} Certificates (${certs.length}):`
        );
        certs.forEach((cert) => {
          const status = cert.revoked ? "❌ REVOKED" : "✅ VALID";
          const daysLeft = Math.floor(
            (cert.validTo - new Date()) / (1000 * 60 * 60 * 24)
          );
          console.log(`   ${status} ${cert.subject}`);
          console.log(`      Serial: ${cert.serialNumber}`);
          console.log(
            `      Valid to: ${cert.validTo.toDateString()} (${daysLeft} days left)`
          );
        });
      }
    });

    // CRL info
    console.log("\n📋 Certificate Revocation List:");
    const revokedCount = this.revokedCertificates.size;
    console.log(`   Revoked certificates: ${revokedCount}`);
    console.log(
      `   CRL Path: ${this.getCertificatePath("root", "root-ca.crl")}`
    );

    console.log("=".repeat(60));
  }

  /**
   * Generate statistics
   */
  getStatistics() {
    const certs = Array.from(this.certificates.values());
    const now = new Date();

    const stats = {
      total: certs.length,
      byType: {},
      valid: 0,
      expired: 0,
      revoked: this.revokedCertificates.size,
      rootCA: this.loadCertificate("root", "root-ca.crt") ? true : false,
      intermediateCA: this.loadCertificate(
        "intermediate",
        "intermediate-ca.crt"
      )
        ? true
        : false,
    };

    certs.forEach((cert) => {
      // Count by type
      stats.byType[cert.type] = (stats.byType[cert.type] || 0) + 1;

      // Count valid/expired
      if (now >= cert.notBefore && now <= cert.notAfter) {
        stats.valid++;
      } else {
        stats.expired++;
      }
    });

    return stats;
  }
}

module.exports = CertificateAuthority;
