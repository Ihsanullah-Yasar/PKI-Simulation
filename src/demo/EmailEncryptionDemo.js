const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const forge = require("node-forge");

class EmailEncryptionDemo {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs",
      emailsPath: config.emailsPath || "./emails",
      ...config,
    };

    this.forge = forge;
    forge.options.usePureJavaScript = true;

    this.ensureDirectories();
    this.loadEmailCertificates();
  }

  /**
   * Ensure directories exist
   */
  ensureDirectories() {
    const dirs = [
      this.config.basePath,
      this.config.emailsPath,
      path.join(this.config.emailsPath, "encrypted"),
      path.join(this.config.emailsPath, "decrypted"),
      path.join(this.config.emailsPath, "signed"),
      path.join(this.config.emailsPath, "keypairs"),
    ];

    dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Load email certificates
   */
  loadEmailCertificates() {
    this.certificates = {};
    this.privateKeys = {};

    // Load email certificates
    const emailCertPath = path.join(this.config.basePath, "email");
    if (fs.existsSync(emailCertPath)) {
      const certFiles = fs
        .readdirSync(emailCertPath)
        .filter((f) => f.endsWith(".crt"));

      certFiles.forEach((certFile) => {
        try {
          const certPem = fs.readFileSync(
            path.join(emailCertPath, certFile),
            "utf8"
          );
          const cert = forge.pki.certificateFromPem(certPem);

          // Extract email from subject
          const email = this.extractEmailFromCertificate(cert);
          if (email) {
            this.certificates[email] = cert;

            // Try to load corresponding private key
            const keyFile = certFile.replace(".crt", "_private.pem");
            const keyPath = path.join(emailCertPath, keyFile);
            if (fs.existsSync(keyPath)) {
              this.privateKeys[email] = fs.readFileSync(keyPath, "utf8");
            }
          }
        } catch (error) {
          console.warn(
            `Failed to load certificate ${certFile}: ${error.message}`
          );
        }
      });
    }

    // Load CA certificates for verification
    const rootCertPath = path.join(this.config.basePath, "root", "root-ca.crt");
    const intermediateCertPath = path.join(
      this.config.basePath,
      "intermediate",
      "intermediate-ca.crt"
    );

    if (fs.existsSync(rootCertPath)) {
      this.certificates.rootCA = forge.pki.certificateFromPem(
        fs.readFileSync(rootCertPath, "utf8")
      );
    }

    if (fs.existsSync(intermediateCertPath)) {
      this.certificates.intermediateCA = forge.pki.certificateFromPem(
        fs.readFileSync(intermediateCertPath, "utf8")
      );
    }

    console.log(
      `📧 Loaded ${
        Object.keys(this.certificates).length - 2
      } email certificates`
    );
  }

  /**
   * Extract email from certificate
   */
  extractEmailFromCertificate(cert) {
    // Check emailAddress in subject
    const emailAttr = cert.subject.getField("emailAddress");
    if (emailAttr) {
      return emailAttr.value;
    }

    // Check subjectAltName extension
    const san = cert.extensions.find((ext) => ext.name === "subjectAltName");
    if (san && san.altNames) {
      const emailAlt = san.altNames.find((alt) => alt.type === 1); // rfc822Name
      if (emailAlt) {
        return emailAlt.value;
      }
    }

    // Check CN for email pattern
    const cn = cert.subject.getField("CN");
    if (cn && cn.value.includes("@")) {
      return cn.value;
    }

    return null;
  }

  /**
   * Generate email key pair for a user
   */
  generateEmailKeyPair(email, options = {}) {
    const keyGen = require("../crypto/KeyPairGenerator");
    const keyGenerator = new keyGen();

    // Generate RSA key pair
    const keyPair = keyGenerator.generateRSAKeyPair(2048, options.passphrase);

    // Save key pair
    const keyDir = path.join(this.config.emailsPath, "keypairs");
    const safeEmail = email.replace(/[^a-zA-Z0-9]/g, "_");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    const keyPaths = keyGenerator.saveKeyPair(
      keyPair,
      `${safeEmail}_${timestamp}`,
      keyDir
    );

    console.log(`🔑 Generated key pair for: ${email}`);
    console.log(`   Public key: ${keyPaths.publicKeyPath}`);
    console.log(`   Private key: ${keyPaths.privateKeyPath}`);

    return {
      email: email,
      keyPair: keyPair,
      paths: keyPaths,
    };
  }

  /**
   * Encrypt email for recipient
   */
  encryptEmail(recipientEmail, message, options = {}) {
    const recipientCert = this.certificates[recipientEmail];

    if (!recipientCert) {
      throw new Error(`No certificate found for recipient: ${recipientEmail}`);
    }

    // Check if certificate is valid for email protection
    if (!this.isValidForEmailProtection(recipientCert)) {
      throw new Error(
        `Certificate for ${recipientEmail} is not valid for email protection`
      );
    }

    const senderEmail = options.sender || "unknown@sender.com";
    const subject = options.subject || "Encrypted Email";
    const timestamp = new Date().toISOString();

    // Create email structure
    const emailData = {
      version: "1.0",
      sender: senderEmail,
      recipient: recipientEmail,
      subject: subject,
      body: message,
      timestamp: timestamp,
      headers: {
        "Content-Type": "text/plain",
        "X-Encrypted": "true",
        "X-Encryption-Algorithm": "RSA-OAEP",
        "X-Signature-Algorithm": options.sign ? "RSA-SHA256" : "none",
      },
    };

    // Convert to string for encryption
    const emailString = JSON.stringify(emailData);

    // Encrypt with recipient's public key
    const encrypted = this.encryptWithPublicKey(
      emailString,
      recipientCert.publicKey
    );

    // Sign if sender private key is provided
    let signature = null;
    if (options.senderPrivateKey) {
      signature = this.signMessage(emailString, options.senderPrivateKey);
    }

    // Create encrypted email package
    const encryptedEmail = {
      version: "1.0",
      recipient: recipientEmail,
      algorithm: "RSA-OAEP",
      encryptionTimestamp: timestamp,
      encryptedData: encrypted,
      signature: signature,
      certificateInfo: {
        subject: this.formatName(recipientCert.subject),
        issuer: this.formatName(recipientCert.issuer),
        serialNumber: recipientCert.serialNumber,
        validForEmail: this.isValidForEmailProtection(recipientCert),
      },
    };

    // Save encrypted email
    const safeEmail = recipientEmail.replace(/[^a-zA-Z0-9]/g, "_");
    const emailFileName = `encrypted_${safeEmail}_${timestamp.replace(
      /[:.]/g,
      "-"
    )}.json`;
    const emailPath = path.join(
      this.config.emailsPath,
      "encrypted",
      emailFileName
    );

    fs.writeFileSync(
      emailPath,
      JSON.stringify(encryptedEmail, null, 2),
      "utf8"
    );

    console.log(`📧 Email encrypted for: ${recipientEmail}`);
    console.log(`   Saved to: ${emailPath}`);
    console.log(`   Sender: ${senderEmail}`);
    console.log(`   Subject: ${subject}`);
    console.log(`   Signed: ${signature ? "Yes" : "No"}`);

    return {
      encryptedEmail: encryptedEmail,
      filePath: emailPath,
      recipient: recipientEmail,
      timestamp: timestamp,
    };
  }

  /**
   * Decrypt email with recipient's private key
   */
  decryptEmail(encryptedEmailPath, recipientPrivateKey, passphrase = "") {
    if (!fs.existsSync(encryptedEmailPath)) {
      throw new Error(`Encrypted email not found: ${encryptedEmailPath}`);
    }

    const encryptedEmail = JSON.parse(
      fs.readFileSync(encryptedEmailPath, "utf8")
    );

    // Decrypt the data
    const decryptedString = this.decryptWithPrivateKey(
      encryptedEmail.encryptedData,
      recipientPrivateKey,
      passphrase
    );

    const emailData = JSON.parse(decryptedString);

    // Verify signature if present
    let signatureValid = false;
    if (encryptedEmail.signature) {
      const senderCert = this.certificates[emailData.sender];
      if (senderCert) {
        signatureValid = this.verifySignature(
          decryptedString,
          encryptedEmail.signature,
          senderCert.publicKey
        );
      }
    }

    // Validate certificate chain
    const recipientCert = this.certificates[emailData.recipient];
    const chainValid = recipientCert
      ? this.validateCertificateChain(recipientCert)
      : false;

    // Create decryption result
    const decryptionResult = {
      email: emailData,
      metadata: {
        decryptedAt: new Date().toISOString(),
        signatureValid: signatureValid,
        certificateChainValid: chainValid,
        recipientMatches:
          emailData.recipient ===
          this.extractEmailFromCertificate(recipientCert),
        algorithm: encryptedEmail.algorithm,
      },
      warnings: [],
    };

    // Check for warnings
    if (!signatureValid && encryptedEmail.signature) {
      decryptionResult.warnings.push("Signature verification failed");
    }

    if (!chainValid) {
      decryptionResult.warnings.push("Certificate chain validation failed");
    }

    if (!recipientCert) {
      decryptionResult.warnings.push("Recipient certificate not found locally");
    }

    // Save decrypted email
    const safeEmail = emailData.recipient.replace(/[^a-zA-Z0-9]/g, "_");
    const decryptedFileName = `decrypted_${safeEmail}_${new Date()
      .toISOString()
      .replace(/[:.]/g, "-")}.json`;
    const decryptedPath = path.join(
      this.config.emailsPath,
      "decrypted",
      decryptedFileName
    );

    fs.writeFileSync(
      decryptedPath,
      JSON.stringify(decryptionResult, null, 2),
      "utf8"
    );

    // Display results
    console.log(`📨 Email decrypted successfully!`);
    console.log(`   From: ${emailData.sender}`);
    console.log(`   To: ${emailData.recipient}`);
    console.log(`   Subject: ${emailData.subject}`);
    console.log(`   Time: ${emailData.timestamp}`);
    console.log(
      `   Signature: ${
        signatureValid
          ? "✅ VALID"
          : encryptedEmail.signature
          ? "❌ INVALID"
          : "N/A"
      }`
    );
    console.log(
      `   Certificate chain: ${chainValid ? "✅ VALID" : "❌ INVALID"}`
    );
    console.log(`   Saved to: ${decryptedPath}`);

    if (decryptionResult.warnings.length > 0) {
      console.log(`\n⚠️  Warnings:`);
      decryptionResult.warnings.forEach((warning) =>
        console.log(`   • ${warning}`)
      );
    }

    return decryptionResult;
  }

  /**
   * Sign email message
   */
  signEmail(senderEmail, message, options = {}) {
    const senderPrivateKey = this.privateKeys[senderEmail];

    if (!senderPrivateKey) {
      throw new Error(`No private key found for sender: ${senderEmail}`);
    }

    const emailData = {
      sender: senderEmail,
      recipient: options.recipient || "unknown@recipient.com",
      subject: options.subject || "Signed Email",
      body: message,
      timestamp: new Date().toISOString(),
    };

    const emailString = JSON.stringify(emailData);
    const signature = this.signMessage(emailString, senderPrivateKey);

    const senderCert = this.certificates[senderEmail];
    const chainValid = senderCert
      ? this.validateCertificateChain(senderCert)
      : false;

    const signedEmail = {
      email: emailData,
      signature: signature,
      certificate: senderCert ? this.formatCertificateInfo(senderCert) : null,
      chainValid: chainValid,
      signedAt: new Date().toISOString(),
    };

    // Save signed email
    const safeEmail = senderEmail.replace(/[^a-zA-Z0-9]/g, "_");
    const signedFileName = `signed_${safeEmail}_${new Date()
      .toISOString()
      .replace(/[:.]/g, "-")}.json`;
    const signedPath = path.join(
      this.config.emailsPath,
      "signed",
      signedFileName
    );

    fs.writeFileSync(signedPath, JSON.stringify(signedEmail, null, 2), "utf8");

    console.log(`✍️  Email signed by: ${senderEmail}`);
    console.log(`   Subject: ${emailData.subject}`);
    console.log(`   Signature algorithm: RSA-SHA256`);
    console.log(
      `   Certificate chain: ${chainValid ? "✅ VALID" : "❌ INVALID"}`
    );
    console.log(`   Saved to: ${signedPath}`);

    return {
      signedEmail: signedEmail,
      filePath: signedPath,
      sender: senderEmail,
      timestamp: emailData.timestamp,
    };
  }

  /**
   * Verify signed email
   */
  verifySignedEmail(signedEmailPath) {
    if (!fs.existsSync(signedEmailPath)) {
      throw new Error(`Signed email not found: ${signedEmailPath}`);
    }

    const signedEmail = JSON.parse(fs.readFileSync(signedEmailPath, "utf8"));
    const emailString = JSON.stringify(signedEmail.email);

    let signatureValid = false;
    if (signedEmail.certificate) {
      // Try to find certificate by subject
      const senderEmail = signedEmail.email.sender;
      const senderCert = this.certificates[senderEmail];

      if (senderCert) {
        signatureValid = this.verifySignature(
          emailString,
          signedEmail.signature,
          senderCert.publicKey
        );
      }
    }

    const verificationResult = {
      email: signedEmail.email,
      signatureValid: signatureValid,
      certificateFound: !!signedEmail.certificate,
      chainValid: signedEmail.chainValid,
      verifiedAt: new Date().toISOString(),
      overallValid: signatureValid && signedEmail.chainValid,
    };

    console.log(`🔍 Signed email verification:`);
    console.log(`   From: ${signedEmail.email.sender}`);
    console.log(`   Subject: ${signedEmail.email.subject}`);
    console.log(`   Signature: ${signatureValid ? "✅ VALID" : "❌ INVALID"}`);
    console.log(
      `   Certificate chain: ${
        signedEmail.chainValid ? "✅ VALID" : "❌ INVALID"
      }`
    );
    console.log(
      `   Overall: ${
        verificationResult.overallValid ? "✅ TRUSTED" : "❌ UNTRUSTED"
      }`
    );

    if (!verificationResult.overallValid) {
      console.log(`\n⚠️  This email should not be trusted!`);
    }

    return verificationResult;
  }

  /**
   * Crypto helper methods
   */
  encryptWithPublicKey(data, publicKey) {
    const buffer = Buffer.from(data, "utf8");

    // Using Node.js crypto for RSA encryption
    const encrypted = crypto.publicEncrypt(
      {
        key: forge.pki.publicKeyToPem(publicKey),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      buffer
    );

    return encrypted.toString("base64");
  }

  decryptWithPrivateKey(encryptedData, privateKeyPem, passphrase = "") {
    const buffer = Buffer.from(encryptedData, "base64");

    const decrypted = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
        passphrase: passphrase || undefined,
      },
      buffer
    );

    return decrypted.toString("utf8");
  }

  signMessage(data, privateKeyPem) {
    const sign = crypto.createSign("RSA-SHA256");
    sign.update(data);
    sign.end();

    const signature = sign.sign(privateKeyPem, "base64");

    return {
      algorithm: "RSA-SHA256",
      value: signature,
      timestamp: new Date().toISOString(),
    };
  }

  verifySignature(data, signatureInfo, publicKey) {
    try {
      const verify = crypto.createVerify("RSA-SHA256");
      verify.update(data);
      verify.end();

      return verify.verify(
        forge.pki.publicKeyToPem(publicKey),
        signatureInfo.value,
        "base64"
      );
    } catch (error) {
      console.error(`Signature verification failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Certificate validation methods
   */
  isValidForEmailProtection(cert) {
    if (!cert) return false;

    // Check extended key usage for email protection
    const extKeyUsage = cert.extensions.find(
      (ext) => ext.name === "extKeyUsage"
    );
    if (extKeyUsage && extKeyUsage.emailProtection) {
      return true;
    }

    // Check validity period
    const now = new Date();
    if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
      return false;
    }

    return false;
  }

  validateCertificateChain(cert) {
    if (
      !cert ||
      !this.certificates.intermediateCA ||
      !this.certificates.rootCA
    ) {
      return false;
    }

    try {
      // Verify intermediate signs the certificate
      const intermediateValidatesCert =
        this.certificates.intermediateCA.verify(cert);

      // Verify root signs intermediate
      const rootValidatesIntermediate = this.certificates.rootCA.verify(
        this.certificates.intermediateCA
      );

      // Verify root is self-signed
      const rootSelfSigned =
        this.formatName(this.certificates.rootCA.subject) ===
        this.formatName(this.certificates.rootCA.issuer);

      return (
        intermediateValidatesCert && rootValidatesIntermediate && rootSelfSigned
      );
    } catch (error) {
      console.error(`Chain validation failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Run complete demo
   */
  async runDemo() {
    console.log("\n📧 EMAIL ENCRYPTION DEMO");
    console.log("=".repeat(60));

    // Check if we have email certificates
    const emailCerts = Object.keys(this.certificates).filter(
      (key) => key !== "rootCA" && key !== "intermediateCA"
    );

    if (emailCerts.length < 2) {
      console.log("⚠️  Need at least 2 email certificates for demo.");
      console.log("   Please issue email certificates first:");
      console.log(
        '   > node src/cli.js issue --type email --email "alice@example.com"'
      );
      console.log(
        '   > node src/cli.js issue --type email --email "bob@example.com"'
      );
      return;
    }

    const [aliceEmail, bobEmail] = emailCerts.slice(0, 2);
    const alicePrivateKey = this.privateKeys[aliceEmail];
    const bobPrivateKey = this.privateKeys[bobEmail];

    console.log(`\n👥 Participants:`);
    console.log(
      `   Alice: ${aliceEmail} ${
        alicePrivateKey ? "(has private key)" : "(no private key)"
      }`
    );
    console.log(
      `   Bob: ${bobEmail} ${
        bobPrivateKey ? "(has private key)" : "(no private key)"
      }`
    );

    // Step 1: Alice signs an email
    console.log("\n📝 Step 1: Alice signs an email...");
    let signedEmail;
    if (alicePrivateKey) {
      signedEmail = this.signEmail(
        aliceEmail,
        "Hello Bob, this is a signed message from Alice.",
        {
          recipient: bobEmail,
          subject: "Signed Message",
        }
      );

      // Verify the signature
      this.verifySignedEmail(signedEmail.filePath);
    } else {
      console.log(`   Skipping - no private key for Alice`);
    }

    // Step 2: Bob encrypts email for Alice
    console.log("\n🔐 Step 2: Bob encrypts email for Alice...");
    let encryptedEmail;
    if (this.certificates[aliceEmail]) {
      encryptedEmail = this.encryptEmail(
        aliceEmail,
        "Hi Alice,\n\nThis is a confidential message encrypted for you.\n\nBest regards,\nBob",
        {
          sender: bobEmail,
          subject: "Confidential Report",
          sign: !!bobPrivateKey,
        }
      );
    } else {
      console.log(`   Skipping - no certificate for Alice`);
    }

    // Step 3: Alice decrypts the email
    console.log("\n🔓 Step 3: Alice decrypts the email...");
    if (encryptedEmail && alicePrivateKey) {
      this.decryptEmail(encryptedEmail.filePath, alicePrivateKey);
    } else {
      console.log(`   Skipping - missing encrypted email or private key`);
    }

    // Step 4: Demonstrate tampering detection
    console.log("\n⚠️  Step 4: Demonstrating tampering detection...");
    if (encryptedEmail) {
      const tamperedPath = this.createTamperedEmail(encryptedEmail.filePath);
      console.log(`   Created tampered email: ${tamperedPath}`);
      console.log(`   Try to decrypt it to see detection in action.`);
    }

    // Display summary
    console.log("\n📊 DEMO SUMMARY:");
    console.log("=".repeat(60));
    console.log(`   Email certificates: ${emailCerts.length}`);
    console.log(
      `   Private keys available: ${Object.keys(this.privateKeys).length}`
    );

    console.log("\n🎯 Key Points Demonstrated:");
    console.log("   1. Email encryption using recipient's public key");
    console.log("   2. Digital signatures for sender authentication");
    console.log("   3. Certificate-based trust establishment");
    console.log("   4. Tamper detection through encryption");

    console.log("\n🔗 Try these commands:");
    console.log(
      '   • Encrypt email: node src/cli.js encrypt-email <recipient> "message"'
    );
    console.log(
      "   • Decrypt email: node src/cli.js decrypt-email <file> <private-key>"
    );
    console.log(
      '   • Sign email: node src/cli.js sign-email <sender> "message"'
    );

    console.log("=".repeat(60));

    return {
      participants: { alice: aliceEmail, bob: bobEmail },
      signedEmail: signedEmail,
      encryptedEmail: encryptedEmail,
    };
  }

  /**
   * Create tampered email for demonstration
   */
  createTamperedEmail(originalPath) {
    const original = JSON.parse(fs.readFileSync(originalPath, "utf8"));

    // Modify the encrypted data
    const tamperedData = Buffer.from(original.encryptedData, "base64");
    tamperedData[tamperedData.length - 1] ^= 0xff; // Flip last byte

    const tamperedEmail = {
      ...original,
      encryptedData: tamperedData.toString("base64"),
      tampered: true,
      tamperedAt: new Date().toISOString(),
    };

    const tamperedFileName = `tampered_${path.basename(originalPath)}`;
    const tamperedPath = path.join(
      this.config.emailsPath,
      "encrypted",
      tamperedFileName
    );

    fs.writeFileSync(
      tamperedPath,
      JSON.stringify(tamperedEmail, null, 2),
      "utf8"
    );

    return tamperedPath;
  }

  /**
   * Format certificate information
   */
  formatCertificateInfo(cert) {
    return {
      subject: this.formatName(cert.subject),
      issuer: this.formatName(cert.issuer),
      serialNumber: cert.serialNumber,
      notBefore: cert.validity.notBefore.toISOString(),
      notAfter: cert.validity.notAfter.toISOString(),
      email: this.extractEmailFromCertificate(cert),
      validForEmail: this.isValidForEmailProtection(cert),
    };
  }

  /**
   * Format name
   */
  formatName(name) {
    return name.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  /**
   * Get demo statistics
   */
  getStatistics() {
    const encryptedDir = path.join(this.config.emailsPath, "encrypted");
    const decryptedDir = path.join(this.config.emailsPath, "decrypted");
    const signedDir = path.join(this.config.emailsPath, "signed");

    const encryptedCount = fs.existsSync(encryptedDir)
      ? fs.readdirSync(encryptedDir).filter((f) => f.startsWith("encrypted_"))
          .length
      : 0;

    const decryptedCount = fs.existsSync(decryptedDir)
      ? fs.readdirSync(decryptedDir).filter((f) => f.startsWith("decrypted_"))
          .length
      : 0;

    const signedCount = fs.existsSync(signedDir)
      ? fs.readdirSync(signedDir).filter((f) => f.startsWith("signed_")).length
      : 0;

    return {
      certificates: {
        total: Object.keys(this.certificates).length - 2, // Exclude CAs
        withPrivateKeys: Object.keys(this.privateKeys).length,
        rootCA: !!this.certificates.rootCA,
        intermediateCA: !!this.certificates.intermediateCA,
      },
      emails: {
        encrypted: encryptedCount,
        decrypted: decryptedCount,
        signed: signedCount,
      },
    };
  }
}

module.exports = EmailEncryptionDemo;
