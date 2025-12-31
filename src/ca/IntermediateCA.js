const crypto = require("crypto");
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");

const KeyPairGenerator = require("../crypto/KeyPairGenerator");
const X509Certificate = require("../certificates/X509Certificate");

class IntermediateCA {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs/intermediate",
      keySize: config.keySize || 2048,
      validityYears: config.validityYears || 5,
      country: config.country || "US",
      organization: config.organization || "Classroom Intermediate CA",
      pathLenConstraint: config.pathLenConstraint || 0,
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
   * Create Intermediate Certificate Authority
   */
  create(rootCA, rootPrivateKey) {
    console.log("🔐 Creating Intermediate Certificate Authority...");

    if (!rootCA || !rootPrivateKey) {
      throw new Error("Root CA certificate and private key are required");
    }

    // Generate key pair for intermediate CA
    const keyPair = this.keyGen.generateRSAKeyPair(this.config.keySize);

    // Create subject
    const subject = this.buildSubject();

    // Create Intermediate CA certificate
    const intermediateCA = this.x509.createIntermediateCA(
      subject,
      keyPair,
      rootCA,
      rootPrivateKey,
      this.config.validityYears
    );

    // Save everything
    this.saveIntermediateCA(intermediateCA, keyPair);

    console.log(`✅ Intermediate CA created successfully!`);
    console.log(`   Subject: ${intermediateCA.subject}`);
    console.log(`   Issuer: ${intermediateCA.issuer}`);
    console.log(
      `   Valid: ${intermediateCA.notBefore.toDateString()} to ${intermediateCA.notAfter.toDateString()}`
    );
    console.log(`   Key size: ${this.config.keySize} bits`);
    console.log(`   Path length constraint: ${this.config.pathLenConstraint}`);
    console.log(`   Saved to: ${this.config.basePath}`);

    return {
      intermediateCA,
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

    return `/C=${country}/O=${organization}/OU=Intermediate Authority/CN=${organization} Intermediate CA`;
  }

  /**
   * Save Intermediate CA files
   */
  saveIntermediateCA(intermediateCA, keyPair) {
    // Save certificate
    const certPath = path.join(this.config.basePath, "intermediate-ca.crt");
    fs.writeFileSync(certPath, intermediateCA.pem, "utf8");

    // Save private key
    const keyPath = path.join(this.config.basePath, "intermediate-ca.key");
    fs.writeFileSync(keyPath, keyPair.privateKey, "utf8");

    // Save public key
    const pubKeyPath = path.join(this.config.basePath, "intermediate-ca.pub");
    fs.writeFileSync(pubKeyPath, keyPair.publicKey, "utf8");

    // Save metadata
    const metaPath = path.join(this.config.basePath, "intermediate-ca.json");
    const metadata = {
      created: new Date().toISOString(),
      config: this.config,
      subject: intermediateCA.subject,
      issuer: intermediateCA.issuer,
      serialNumber: intermediateCA.serialNumber,
      notBefore: intermediateCA.notBefore.toISOString(),
      notAfter: intermediateCA.notAfter.toISOString(),
      keySize: this.config.keySize,
      algorithm: "RSA",
      pathLenConstraint: this.config.pathLenConstraint,
    };

    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2), "utf8");

    // Save chain file (intermediate + root)
    const chainPath = path.join(this.config.basePath, "ca-chain.crt");
    // Note: Root CA certificate needs to be loaded separately
  }

  /**
   * Get file paths
   */
  getFilePaths() {
    return {
      certificate: path.join(this.config.basePath, "intermediate-ca.crt"),
      privateKey: path.join(this.config.basePath, "intermediate-ca.key"),
      publicKey: path.join(this.config.basePath, "intermediate-ca.pub"),
      metadata: path.join(this.config.basePath, "intermediate-ca.json"),
    };
  }

  /**
   * Load existing Intermediate CA
   */
  load() {
    const certPath = path.join(this.config.basePath, "intermediate-ca.crt");
    const keyPath = path.join(this.config.basePath, "intermediate-ca.key");

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
      console.error(`Failed to load Intermediate CA: ${error.message}`);
      return null;
    }
  }

  /**
   * Validate Intermediate CA certificate
   */
  validate(rootCA) {
    const intermediateCA = this.load();

    if (!intermediateCA) {
      return {
        valid: false,
        reason: "Intermediate CA not found",
      };
    }

    if (!rootCA) {
      return {
        valid: false,
        reason: "Root CA required for validation",
      };
    }

    const now = new Date();
    const cert = intermediateCA.certificate;

    // Check validity period
    if (now < cert.validity.notBefore) {
      return {
        valid: false,
        reason: `Intermediate CA not valid until ${cert.validity.notBefore.toISOString()}`,
      };
    }

    if (now > cert.validity.notAfter) {
      return {
        valid: false,
        reason: `Intermediate CA expired on ${cert.validity.notAfter.toISOString()}`,
      };
    }

    // Verify signature with Root CA
    try {
      const verified = rootCA.certificate.verify(cert);
      if (!verified) {
        return {
          valid: false,
          reason: "Invalid signature (not signed by Root CA)",
        };
      }
    } catch (error) {
      return {
        valid: false,
        reason: `Signature verification failed: ${error.message}`,
      };
    }

    // Check basic constraints
    const basicConstraints = cert.extensions.find(
      (ext) => ext.name === "basicConstraints"
    );
    if (!basicConstraints || !basicConstraints.cA) {
      return {
        valid: false,
        reason: "Intermediate CA missing CA basic constraint",
      };
    }

    // Check path length constraint
    if (
      basicConstraints.pathLenConstraint !== undefined &&
      basicConstraints.pathLenConstraint < this.config.pathLenConstraint
    ) {
      return {
        valid: false,
        reason: `Path length constraint violation: ${basicConstraints.pathLenConstraint} < ${this.config.pathLenConstraint}`,
      };
    }

    // Check key usage
    const keyUsage = cert.extensions.find((ext) => ext.name === "keyUsage");
    if (!keyUsage || !keyUsage.keyCertSign) {
      return {
        valid: false,
        reason: "Intermediate CA missing keyCertSign key usage",
      };
    }

    return {
      valid: true,
      intermediateCA: intermediateCA,
      daysRemaining: Math.floor(
        (cert.validity.notAfter - now) / (1000 * 60 * 60 * 24)
      ),
    };
  }

  /**
   * Issue end-entity certificate
   */
  issueCertificate(subject, keyPair, options = {}) {
    const intermediateCA = this.load();

    if (!intermediateCA) {
      throw new Error(
        "Intermediate CA not found. Create Intermediate CA first."
      );
    }

    const defaultOptions = {
      validityDays: options.validityDays || 365,
      keyUsage: options.keyUsage || ["digitalSignature", "keyEncipherment"],
      extendedKeyUsage: options.extendedKeyUsage || [
        "serverAuth",
        "clientAuth",
      ],
      san: options.san || [],
      isCA: false,
    };

    const certificate = this.x509.createEndEntityCertificate(
      subject,
      keyPair,
      { certificate: intermediateCA.certificate, pem: intermediateCA.pem },
      intermediateCA.privateKey,
      defaultOptions
    );

    return certificate;
  }

  /**
   * Issue server certificate
   */
  issueServerCertificate(domain, keyPair, san = []) {
    const subject = `/CN=${domain}`;
    const allSAN = ["DNS:" + domain, ...san];

    return this.issueCertificate(subject, keyPair, {
      validityDays: 365,
      keyUsage: ["digitalSignature", "keyEncipherment"],
      extendedKeyUsage: ["serverAuth", "clientAuth"],
      san: allSAN,
      isCA: false,
    });
  }

  /**
   * Issue client certificate
   */
  issueClientCertificate(username, keyPair, email = null) {
    const subject = email
      ? `/CN=${username}/emailAddress=${email}`
      : `/CN=${username}`;

    const san = email ? [`email:${email}`] : [];

    return this.issueCertificate(subject, keyPair, {
      validityDays: 365,
      keyUsage: ["digitalSignature", "keyEncipherment"],
      extendedKeyUsage: ["clientAuth"],
      san: san,
      isCA: false,
    });
  }

  /**
   * Issue code signing certificate
   */
  issueCodeSigningCertificate(developerName, keyPair, organization) {
    const subject = `/O=${organization}/CN=${developerName}`;

    return this.issueCertificate(subject, keyPair, {
      validityDays: 1095, // 3 years
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["codeSigning"],
      san: [],
      isCA: false,
    });
  }

  /**
   * Issue email certificate
   */
  issueEmailCertificate(email, keyPair, organization = null) {
    const subject = organization
      ? `/O=${organization}/emailAddress=${email}`
      : `/emailAddress=${email}`;

    return this.issueCertificate(subject, keyPair, {
      validityDays: 365,
      keyUsage: ["digitalSignature", "keyEncipherment"],
      extendedKeyUsage: ["emailProtection"],
      san: [`email:${email}`],
      isCA: false,
    });
  }

  /**
   * Sign Certificate Signing Request (CSR)
   */
  signCSR(csrPem, options = {}) {
    const intermediateCA = this.load();

    if (!intermediateCA) {
      throw new Error("Intermediate CA not found");
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
    cert.validity.notAfter.setDate(
      cert.validity.notBefore.getDate() + (options.validityDays || 365)
    );

    // Subject from CSR
    cert.setSubject(csr.subject.attributes);

    // Issuer is Intermediate CA
    cert.setIssuer(intermediateCA.certificate.subject.attributes);

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
        critical: true,
      },
    ];

    // Add extended key usage if specified
    if (options.extendedKeyUsage && options.extendedKeyUsage.length > 0) {
      extensions.push({
        name: "extKeyUsage",
        serverAuth: options.extendedKeyUsage.includes("serverAuth"),
        clientAuth: options.extendedKeyUsage.includes("clientAuth"),
        codeSigning: options.extendedKeyUsage.includes("codeSigning"),
        emailProtection: options.extendedKeyUsage.includes("emailProtection"),
        timeStamping: options.extendedKeyUsage.includes("timeStamping"),
        critical: false,
      });
    }

    // Add subject alternative names if specified
    if (options.san && options.san.length > 0) {
      const altNames = options.san.map((name) => {
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
        } else if (name.startsWith("email:")) {
          return {
            type: 1, // Email
            value: name.substring(6),
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

    cert.setExtensions(extensions);

    // Sign certificate
    cert.sign(
      forge.pki.privateKeyFromPem(intermediateCA.privateKey),
      forge.md.sha256.create()
    );

    return {
      certificate: cert,
      pem: forge.pki.certificateToPem(cert),
      subject: this.x509.formatName(cert.subject),
      issuer: this.x509.formatName(cert.issuer),
      serialNumber: cert.serialNumber,
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
    };
  }

  /**
   * Create certificate chain
   */
  createChain(rootCertPem) {
    const intermediateCert = this.load();

    if (!intermediateCert) {
      throw new Error("Intermediate CA not found");
    }

    if (!rootCertPem) {
      throw new Error("Root CA certificate is required");
    }

    return {
      chain: rootCertPem + "\n" + intermediateCert.pem,
      certificates: [
        { type: "root", pem: rootCertPem },
        { type: "intermediate", pem: intermediateCert.pem },
      ],
    };
  }

  /**
   * Get Intermediate CA information
   */
  getInfo(rootCA = null) {
    const intermediateCA = this.load();

    if (!intermediateCA) {
      return {
        exists: false,
        message: "Intermediate CA not created yet",
      };
    }

    const validation = rootCA
      ? this.validate(rootCA)
      : { valid: false, reason: "Root CA not provided for validation" };

    return {
      exists: true,
      valid: validation.valid,
      subject: intermediateCA.subject,
      issuer: intermediateCA.issuer,
      serialNumber: intermediateCA.serialNumber,
      notBefore: intermediateCA.notBefore,
      notAfter: intermediateCA.notAfter,
      keySize: this.config.keySize,
      pathLenConstraint: this.config.pathLenConstraint,
      files: this.getFilePaths(),
      validation: validation,
    };
  }

  /**
   * Export Intermediate CA in different formats
   */
  export(format = "pem") {
    const intermediateCA = this.load();

    if (!intermediateCA) {
      throw new Error("Intermediate CA not found");
    }

    switch (format.toLowerCase()) {
      case "pem":
        return {
          format: "PEM",
          certificate: intermediateCA.pem,
          privateKey: intermediateCA.privateKey,
        };

      case "der":
        const der = forge.asn1
          .toDer(forge.pki.certificateToAsn1(intermediateCA.certificate))
          .getBytes();
        return {
          format: "DER",
          data: der,
        };

      case "json":
        return {
          format: "JSON",
          data: {
            subject: intermediateCA.subject,
            issuer: intermediateCA.issuer,
            serialNumber: intermediateCA.serialNumber,
            notBefore: intermediateCA.notBefore.toISOString(),
            notAfter: intermediateCA.notAfter.toISOString(),
            keySize: this.config.keySize,
            pathLenConstraint: this.config.pathLenConstraint,
          },
        };

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }
}

module.exports = IntermediateCA;
