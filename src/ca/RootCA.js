const crypto = require("crypto");
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");

const KeyPairGenerator = require("../crypto/KeyPairGenerator");
const X509Certificate = require("../certificates/X509Certificate");

class RootCA {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs/root",
      keySize: config.keySize || 4096,
      validityYears: config.validityYears || 10,
      country: config.country || "US",
      organization: config.organization || "Classroom Root CA",
      ...config,
    };

    this.keyGen = new KeyPairGenerator();
    this.x509 = new X509Certificate();

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
   * Create Root Certificate Authority
   */
  create() {
    console.log("🔐 Creating Root Certificate Authority...");

    // Generate key pair
    const keyPair = this.keyGen.generateRSAKeyPair(this.config.keySize);

    // Create subject
    const subject = this.buildSubject();

    // Create Root CA certificate
    const rootCA = this.x509.createRootCA(
      subject,
      keyPair,
      this.config.validityYears
    );

    // Save everything
    this.saveRootCA(rootCA, keyPair);

    console.log(`✅ Root CA created successfully!`);
    console.log(`   Subject: ${rootCA.subject}`);
    console.log(
      `   Valid: ${rootCA.notBefore.toDateString()} to ${rootCA.notAfter.toDateString()}`
    );
    console.log(`   Key size: ${this.config.keySize} bits`);
    console.log(`   Saved to: ${this.config.basePath}`);

    return {
      rootCA,
      keyPair,
      config: this.config,
      files: this.getFilePaths(),
    };
  }

  /**
   * Build subject string
   */
  buildSubject() {
    const { country, organization } = this.config;

    return `/C=${country}/O=${organization}/OU=Certificate Authority/CN=${organization} Root CA`;
  }

  /**
   * Save Root CA files
   */
  saveRootCA(rootCA, keyPair) {
    // Save certificate
    const certPath = path.join(this.config.basePath, "root-ca.crt");
    fs.writeFileSync(certPath, rootCA.pem, "utf8");

    // Save private key
    const keyPath = path.join(this.config.basePath, "root-ca.key");
    fs.writeFileSync(keyPath, keyPair.privateKey, "utf8");

    // Save public key
    const pubKeyPath = path.join(this.config.basePath, "root-ca.pub");
    fs.writeFileSync(pubKeyPath, keyPair.publicKey, "utf8");

    // Save metadata
    const metaPath = path.join(this.config.basePath, "root-ca.json");
    const metadata = {
      created: new Date().toISOString(),
      config: this.config,
      subject: rootCA.subject,
      issuer: rootCA.issuer,
      serialNumber: rootCA.serialNumber,
      notBefore: rootCA.notBefore.toISOString(),
      notAfter: rootCA.notAfter.toISOString(),
      keySize: this.config.keySize,
      algorithm: "RSA",
    };

    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2), "utf8");

    // Save in DER format
    const derPath = path.join(this.config.basePath, "root-ca.der");
    fs.writeFileSync(derPath, rootCA.der);
  }

  /**
   * Get file paths
   */
  getFilePaths() {
    return {
      certificate: path.join(this.config.basePath, "root-ca.crt"),
      privateKey: path.join(this.config.basePath, "root-ca.key"),
      publicKey: path.join(this.config.basePath, "root-ca.pub"),
      metadata: path.join(this.config.basePath, "root-ca.json"),
      der: path.join(this.config.basePath, "root-ca.der"),
    };
  }

  /**
   * Load existing Root CA
   */
  load() {
    const certPath = path.join(this.config.basePath, "root-ca.crt");
    const keyPath = path.join(this.config.basePath, "root-ca.key");

    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      return null;
    }

    try {
      const certPem = fs.readFileSync(certPath, "utf8");
      const keyPem = fs.readFileSync(keyPath, "utf8");
      const cert = forge.pki.certificateFromPem(certPem);

      return {
        certificate: cert,
        pem: certPem,
        privateKey: keyPem,
        subject: this.x509.formatName(cert.subject),
        issuer: this.x509.formatName(cert.issuer),
        serialNumber: cert.serialNumber,
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
      };
    } catch (error) {
      console.error(`Failed to load Root CA: ${error.message}`);
      return null;
    }
  }

  /**
   * Validate Root CA certificate
   */
  validate() {
    const rootCA = this.load();

    if (!rootCA) {
      return {
        valid: false,
        reason: "Root CA not found",
      };
    }

    const now = new Date();
    const cert = rootCA.certificate;

    // Check validity period
    if (now < cert.validity.notBefore) {
      return {
        valid: false,
        reason: `Root CA not valid until ${cert.validity.notBefore.toISOString()}`,
      };
    }

    if (now > cert.validity.notAfter) {
      return {
        valid: false,
        reason: `Root CA expired on ${cert.validity.notAfter.toISOString()}`,
      };
    }

    // Check basic constraints
    const basicConstraints = cert.extensions.find(
      (ext) => ext.name === "basicConstraints"
    );
    if (!basicConstraints || !basicConstraints.cA) {
      return {
        valid: false,
        reason: "Root CA missing CA basic constraint",
      };
    }

    // Check key usage
    const keyUsage = cert.extensions.find((ext) => ext.name === "keyUsage");
    if (!keyUsage || !keyUsage.keyCertSign || !keyUsage.cRLSign) {
      return {
        valid: false,
        reason: "Root CA missing required key usage",
      };
    }

    // Check self-signed
    if (
      !this.x509.formatName(cert.subject) === this.x509.formatName(cert.issuer)
    ) {
      return {
        valid: false,
        reason: "Root CA is not self-signed",
      };
    }

    return {
      valid: true,
      rootCA: rootCA,
      daysRemaining: Math.floor(
        (cert.validity.notAfter - now) / (1000 * 60 * 60 * 24)
      ),
    };
  }

  /**
   * Export Root CA in different formats
   */
  export(format = "pem") {
    const rootCA = this.load();

    if (!rootCA) {
      throw new Error("Root CA not found");
    }

    switch (format.toLowerCase()) {
      case "pem":
        return {
          format: "PEM",
          certificate: rootCA.pem,
          privateKey: rootCA.privateKey,
        };

      case "der":
        const der = forge.asn1
          .toDer(forge.pki.certificateToAsn1(rootCA.certificate))
          .getBytes();
        return {
          format: "DER",
          data: der,
        };

      case "base64":
        const derData = forge.asn1
          .toDer(forge.pki.certificateToAsn1(rootCA.certificate))
          .getBytes();
        return {
          format: "BASE64",
          data: Buffer.from(derData).toString("base64"),
        };

      case "json":
        return {
          format: "JSON",
          data: {
            subject: rootCA.subject,
            issuer: rootCA.issuer,
            serialNumber: rootCA.serialNumber,
            notBefore: rootCA.notBefore.toISOString(),
            notAfter: rootCA.notAfter.toISOString(),
            keySize: this.config.keySize,
          },
        };

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Generate certificate for Intermediate CA
   */
  issueIntermediateCA(subject, intermediateKeyPair, validityYears = 5) {
    const rootCA = this.load();

    if (!rootCA) {
      throw new Error("Root CA not found. Create Root CA first.");
    }

    const intermediateCA = this.x509.createIntermediateCA(
      subject,
      intermediateKeyPair,
      { certificate: rootCA.certificate, pem: rootCA.pem },
      rootCA.privateKey,
      validityYears
    );

    return intermediateCA;
  }

  /**
   * Sign Certificate Signing Request (CSR)
   */
  signCSR(csrPem, options = {}) {
    const rootCA = this.load();

    if (!rootCA) {
      throw new Error("Root CA not found");
    }

    const csr = forge.pki.certificationRequestFromPem(csrPem);

    if (!csr.verify()) {
      throw new Error("Invalid CSR signature");
    }

    const cert = forge.pki.createCertificate();
    cert.publicKey = csr.publicKey;
    cert.serialNumber = "0x" + crypto.randomBytes(20).toString("hex");

    // Validity period
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + (options.validityYears || 1)
    );

    // Subject from CSR
    cert.setSubject(csr.subject.attributes);

    // Issuer is Root CA
    cert.setIssuer(rootCA.certificate.subject.attributes);

    // Set extensions
    const extensions = [
      {
        name: "basicConstraints",
        cA: options.isCA || false,
        critical: true,
      },
      {
        name: "keyUsage",
        digitalSignature:
          options.keyUsage?.includes("digitalSignature") || true,
        keyEncipherment: options.keyUsage?.includes("keyEncipherment") || false,
        keyCertSign: options.keyUsage?.includes("keyCertSign") || false,
        cRLSign: options.keyUsage?.includes("cRLSign") || false,
        critical: true,
      },
    ];

    if (options.extendedKeyUsage) {
      extensions.push({
        name: "extKeyUsage",
        serverAuth: options.extendedKeyUsage.includes("serverAuth"),
        clientAuth: options.extendedKeyUsage.includes("clientAuth"),
        codeSigning: options.extendedKeyUsage.includes("codeSigning"),
        emailProtection: options.extendedKeyUsage.includes("emailProtection"),
        critical: false,
      });
    }

    cert.setExtensions(extensions);

    // Sign certificate
    cert.sign(
      forge.pki.privateKeyFromPem(rootCA.privateKey),
      forge.md.sha256.create()
    );

    return {
      certificate: cert,
      pem: forge.pki.certificateToPem(cert),
      subject: this.x509.formatName(cert.subject),
      issuer: this.x509.formatName(cert.issuer),
      serialNumber: cert.serialNumber,
    };
  }

  /**
   * Get Root CA information
   */
  getInfo() {
    const rootCA = this.load();

    if (!rootCA) {
      return {
        exists: false,
        message: "Root CA not created yet",
      };
    }

    const validation = this.validate();

    return {
      exists: true,
      valid: validation.valid,
      subject: rootCA.subject,
      issuer: rootCA.issuer,
      serialNumber: rootCA.serialNumber,
      notBefore: rootCA.notBefore,
      notAfter: rootCA.notAfter,
      keySize: this.config.keySize,
      files: this.getFilePaths(),
      validation: validation,
    };
  }
}

module.exports = RootCA;
