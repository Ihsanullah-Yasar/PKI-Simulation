const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const forge = require("node-forge");

class CodeSigningDemo {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs",
      signaturesPath: config.signaturesPath || "./signatures",
      ...config,
    };

    this.forge = forge;
    forge.options.usePureJavaScript = true;

    this.ensureDirectories();
    this.loadSigningCertificates();
  }

  /**
   * Ensure directories exist
   */
  ensureDirectories() {
    const dirs = [
      this.config.basePath,
      this.config.signaturesPath,
      path.join(this.config.signaturesPath, "signed"),
      path.join(this.config.signaturesPath, "verified"),
      path.join(this.config.signaturesPath, "tampered"),
    ];

    dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Load code signing certificates
   */
  loadSigningCertificates() {
    this.certificates = {};

    // Try to load code signing certificate
    const codeCertPath = path.join(this.config.basePath, "code");
    if (fs.existsSync(codeCertPath)) {
      const certFiles = fs
        .readdirSync(codeCertPath)
        .filter((f) => f.endsWith(".crt"));
      if (certFiles.length > 0) {
        const certPem = fs.readFileSync(
          path.join(codeCertPath, certFiles[0]),
          "utf8"
        );
        this.certificates.codeSigning = forge.pki.certificateFromPem(certPem);

        // Try to load private key
        const keyFiles = fs
          .readdirSync(codeCertPath)
          .filter((f) => f.includes("_private.pem"));
        if (keyFiles.length > 0) {
          this.certificates.codeSigningKey = fs.readFileSync(
            path.join(codeCertPath, keyFiles[0]),
            "utf8"
          );
        }
      }
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
  }

  /**
   * Sign a file with code signing certificate
   */
  signFile(filePath, options = {}) {
    if (!this.certificates.codeSigning || !this.certificates.codeSigningKey) {
      throw new Error("Code signing certificate or private key not found");
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    // Read file content
    const fileContent = fs.readFileSync(filePath);
    const fileName = path.basename(filePath);
    const fileHash = crypto
      .createHash("sha256")
      .update(fileContent)
      .digest("hex");

    // Create signature
    const signature = this.createSignature(fileContent, options);

    // Create signature package
    const signaturePackage = {
      version: "1.0",
      file: {
        name: fileName,
        size: fileContent.length,
        hash: fileHash,
        hashAlgorithm: "SHA256",
        timestamp: new Date().toISOString(),
      },
      signature: signature,
      certificate: this.formatCertificateInfo(this.certificates.codeSigning),
      verification: {
        chainValid: this.validateCertificateChain(),
        signatureValid: true,
      },
    };

    // Save signature
    const signatureFileName = `${fileName}.sig.json`;
    const signaturePath = path.join(
      this.config.signaturesPath,
      "signed",
      signatureFileName
    );

    fs.writeFileSync(
      signaturePath,
      JSON.stringify(signaturePackage, null, 2),
      "utf8"
    );

    // Create signed file package
    const signedPackage = {
      file: fileContent.toString("base64"),
      signature: signaturePackage,
    };

    const signedFileName = `${fileName}.signed`;
    const signedPath = path.join(
      this.config.signaturesPath,
      "signed",
      signedFileName
    );

    fs.writeFileSync(
      signedPath,
      JSON.stringify(signedPackage, null, 2),
      "utf8"
    );

    console.log(`✅ File signed: ${fileName}`);
    console.log(`   Signature saved: ${signaturePath}`);
    console.log(`   Signed package: ${signedPath}`);
    console.log(
      `   Signer: ${this.formatName(this.certificates.codeSigning.subject)}`
    );
    console.log(`   Timestamp: ${signaturePackage.file.timestamp}`);

    return {
      signature: signaturePackage,
      signaturePath: signaturePath,
      signedPath: signedPath,
      fileInfo: {
        name: fileName,
        size: fileContent.length,
        hash: fileHash,
      },
    };
  }

  /**
   * Create digital signature
   */
  createSignature(data, options = {}) {
    const privateKey = forge.pki.privateKeyFromPem(
      this.certificates.codeSigningKey
    );
    const md = forge.md.sha256.create();

    md.update(typeof data === "string" ? data : data.toString("binary"));

    const signature = privateKey.sign(md);

    return {
      algorithm: "RSA-SHA256",
      value: forge.util.encode64(signature),
      timestamp: new Date().toISOString(),
      signingTime: options.signingTime || new Date().toISOString(),
      purpose: "codeSigning",
    };
  }

  /**
   * Verify file signature
   */
  verifySignature(filePath, signaturePath = null) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const fileContent = fs.readFileSync(filePath);
    const fileName = path.basename(filePath);

    // Try to find signature file
    let signaturePackage;
    if (signaturePath && fs.existsSync(signaturePath)) {
      signaturePackage = JSON.parse(fs.readFileSync(signaturePath, "utf8"));
    } else {
      // Look for signature in signed directory
      const signatureFileName = `${fileName}.sig.json`;
      const defaultSignaturePath = path.join(
        this.config.signaturesPath,
        "signed",
        signatureFileName
      );

      if (fs.existsSync(defaultSignaturePath)) {
        signaturePackage = JSON.parse(
          fs.readFileSync(defaultSignaturePath, "utf8")
        );
      } else {
        throw new Error(`Signature not found for file: ${fileName}`);
      }
    }

    // Verify file hash
    const fileHash = crypto
      .createHash("sha256")
      .update(fileContent)
      .digest("hex");
    const hashMatch = fileHash === signaturePackage.file.hash;

    if (!hashMatch) {
      console.warn(`⚠️  File hash mismatch! File may have been modified.`);
    }

    // Verify signature
    const signatureValid = this.verifyDigitalSignature(
      fileContent,
      signaturePackage.signature,
      this.certificates.codeSigning
    );

    // Verify certificate chain
    const chainValid = this.validateCertificateChain();

    // Check certificate validity for code signing
    const certValidForCodeSigning = this.isValidForCodeSigning(
      this.certificates.codeSigning
    );

    const verificationResult = {
      file: fileName,
      hashValid: hashMatch,
      signatureValid: signatureValid,
      certificateValid: chainValid,
      certValidForCodeSigning: certValidForCodeSigning,
      signer: signaturePackage.certificate.subject,
      signingTime: signaturePackage.signature.signingTime,
      timestamp: new Date().toISOString(),
      overallValid:
        hashMatch && signatureValid && chainValid && certValidForCodeSigning,
    };

    // Save verification result
    const resultFileName = `${fileName}.verification.json`;
    const resultPath = path.join(
      this.config.signaturesPath,
      "verified",
      resultFileName
    );

    fs.writeFileSync(
      resultPath,
      JSON.stringify(verificationResult, null, 2),
      "utf8"
    );

    // Display results
    console.log(`🔍 Verification results for: ${fileName}`);
    console.log(`   File integrity: ${hashMatch ? "✅ PASS" : "❌ FAIL"}`);
    console.log(`   Signature: ${signatureValid ? "✅ VALID" : "❌ INVALID"}`);
    console.log(
      `   Certificate chain: ${chainValid ? "✅ VALID" : "❌ INVALID"}`
    );
    console.log(
      `   Code signing purpose: ${
        certValidForCodeSigning ? "✅ ALLOWED" : "❌ NOT ALLOWED"
      }`
    );
    console.log(
      `   Overall: ${
        verificationResult.overallValid ? "✅ TRUSTED" : "❌ UNTRUSTED"
      }`
    );
    console.log(`   Signer: ${signaturePackage.certificate.subject}`);
    console.log(`   Signed: ${signaturePackage.signature.signingTime}`);

    if (!verificationResult.overallValid) {
      console.log(`\n⚠️  WARNING: This file should not be trusted!`);

      // Create tampered example
      if (!hashMatch) {
        this.createTamperedExample(filePath, fileContent);
      }
    }

    return verificationResult;
  }

  /**
   * Verify digital signature
   */
  verifyDigitalSignature(data, signatureInfo, certificate) {
    try {
      const publicKey = certificate.publicKey;
      const md = forge.md.sha256.create();

      md.update(typeof data === "string" ? data : data.toString("binary"));

      const signature = forge.util.decode64(signatureInfo.value);
      const verified = publicKey.verify(md.digest().bytes(), signature);

      return verified;
    } catch (error) {
      console.error(`Signature verification failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Validate certificate chain for code signing
   */
  validateCertificateChain() {
    if (
      !this.certificates.codeSigning ||
      !this.certificates.intermediateCA ||
      !this.certificates.rootCA
    ) {
      return false;
    }

    try {
      // Verify intermediate signs code signing cert
      const intermediateValidatesCode = this.certificates.intermediateCA.verify(
        this.certificates.codeSigning
      );

      // Verify root signs intermediate
      const rootValidatesIntermediate = this.certificates.rootCA.verify(
        this.certificates.intermediateCA
      );

      // Verify root is self-signed
      const rootSelfSigned =
        this.formatName(this.certificates.rootCA.subject) ===
        this.formatName(this.certificates.rootCA.issuer);

      return (
        intermediateValidatesCode && rootValidatesIntermediate && rootSelfSigned
      );
    } catch (error) {
      console.error(`Chain validation failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Check if certificate is valid for code signing
   */
  isValidForCodeSigning(cert) {
    if (!cert) return false;

    // Check extended key usage for code signing
    const extKeyUsage = cert.extensions.find(
      (ext) => ext.name === "extKeyUsage"
    );
    if (extKeyUsage && extKeyUsage.codeSigning) {
      return true;
    }

    // Check validity period
    const now = new Date();
    if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
      return false;
    }

    return false;
  }

  /**
   * Create tampered file example
   */
  createTamperedExample(originalPath, originalContent) {
    const fileName = path.basename(originalPath);
    const tamperedContent = Buffer.from(
      originalContent.toString() +
        "\n// TAMPERED: This file has been modified!\n"
    );

    const tamperedPath = path.join(
      this.config.signaturesPath,
      "tampered",
      fileName
    );
    fs.writeFileSync(tamperedPath, tamperedContent);

    // Try to verify the tampered file
    console.log(`\n🧪 Demonstration: Created tampered file at ${tamperedPath}`);
    console.log(`   Try verifying it to see the failure:`);
    console.log(
      `   > node -e "require('./src/demo/CodeSigningDemo').verifySignature('${tamperedPath}')"`
    );

    return tamperedPath;
  }

  /**
   * Generate test files for signing
   */
  generateTestFiles() {
    const testFiles = [
      {
        name: "app.js",
        content: `
// Sample Application
console.log('Hello from signed application!');

function calculateSum(a, b) {
    return a + b;
}

module.exports = {
    calculateSum,
    version: '1.0.0',
    author: 'Secure Software Inc.',
    license: 'MIT'
};
                `.trim(),
      },
      {
        name: "config.json",
        content: JSON.stringify(
          {
            appName: "SecureApp",
            version: "1.0.0",
            features: ["authentication", "encryption", "signing"],
            requireSignature: true,
            allowedSigners: ["Secure Software Inc."],
          },
          null,
          2
        ),
      },
      {
        name: "README.md",
        content: `# Secure Application

This application has been digitally signed to ensure integrity.

## Verification

To verify the signature:

\`\`\`bash
npm run verify-signature app.js
\`\`\`

## Features

- Digital signatures
- Certificate-based verification
- Tamper detection

## Security

Always verify signatures before executing code.
`,
      },
    ];

    const generatedFiles = [];

    testFiles.forEach((file) => {
      const filePath = path.join(this.config.signaturesPath, file.name);
      fs.writeFileSync(filePath, file.content, "utf8");
      generatedFiles.push(filePath);

      console.log(`📄 Created test file: ${file.name}`);
    });

    return generatedFiles;
  }

  /**
   * Run complete demo
   */
  async runDemo() {
    console.log("\n🔐 CODE SIGNING DEMO");
    console.log("=".repeat(60));

    // Check if we have code signing certificate
    if (!this.certificates.codeSigning) {
      console.log("⚠️  No code signing certificate found.");
      console.log("   Please issue a code signing certificate first:");
      console.log(
        '   > node src/cli.js issue --type code --developer "Your Name" --organization "Your Company"'
      );
      return;
    }

    // Generate test files
    console.log("\n📁 Step 1: Generating test files...");
    const testFiles = this.generateTestFiles();

    // Sign files
    console.log("\n📝 Step 2: Signing files...");
    const signatures = [];

    for (const filePath of testFiles) {
      try {
        const signature = this.signFile(filePath);
        signatures.push(signature);
      } catch (error) {
        console.error(`Failed to sign ${filePath}: ${error.message}`);
      }
    }

    // Verify signatures
    console.log("\n🔍 Step 3: Verifying signatures...");
    const verificationResults = [];

    for (const filePath of testFiles) {
      try {
        const result = this.verifySignature(filePath);
        verificationResults.push(result);
      } catch (error) {
        console.error(`Failed to verify ${filePath}: ${error.message}`);
      }
    }

    // Demonstrate tampering
    console.log("\n⚠️  Step 4: Demonstrating tamper detection...");
    if (testFiles.length > 0) {
      const firstFile = testFiles[0];
      const content = fs.readFileSync(firstFile, "utf8");
      const tamperedContent = content + "\n// Malicious code injected here!\n";
      const tamperedPath = path.join(
        this.config.signaturesPath,
        "tampered",
        path.basename(firstFile)
      );

      fs.writeFileSync(tamperedPath, tamperedContent, "utf8");

      console.log(`   Created tampered file: ${tamperedPath}`);
      console.log(`   Try to verify it to see detection in action.`);
    }

    // Display summary
    console.log("\n📊 DEMO SUMMARY:");
    console.log("=".repeat(60));
    console.log(`   Files signed: ${signatures.length}`);
    console.log(`   Files verified: ${verificationResults.length}`);

    const validCount = verificationResults.filter((r) => r.overallValid).length;
    console.log(
      `   Valid signatures: ${validCount}/${verificationResults.length}`
    );

    console.log("\n🎯 Key Points Demonstrated:");
    console.log("   1. Digital signatures ensure file integrity");
    console.log("   2. Certificate chains establish trust");
    console.log("   3. Tampered files are detected");
    console.log("   4. Code signing certificates have specific purposes");

    console.log("\n🔗 Try these commands:");
    console.log("   • Sign a file: node src/cli.js sign-file <filepath>");
    console.log(
      "   • Verify signature: node src/cli.js verify-file <filepath>"
    );
    console.log("   • View certificates: node src/cli.js list --type code");

    console.log("=".repeat(60));

    return {
      files: testFiles,
      signatures: signatures,
      verifications: verificationResults,
    };
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
      keyUsage: this.getKeyUsage(cert),
      extendedKeyUsage: this.getExtendedKeyUsage(cert),
    };
  }

  /**
   * Get key usage from certificate
   */
  getKeyUsage(cert) {
    const keyUsage = cert.extensions.find((ext) => ext.name === "keyUsage");
    if (!keyUsage) return [];

    const usages = [];
    if (keyUsage.digitalSignature) usages.push("digitalSignature");
    if (keyUsage.nonRepudiation) usages.push("nonRepudiation");
    if (keyUsage.keyEncipherment) usages.push("keyEncipherment");
    if (keyUsage.dataEncipherment) usages.push("dataEncipherment");
    if (keyUsage.keyAgreement) usages.push("keyAgreement");
    if (keyUsage.keyCertSign) usages.push("keyCertSign");
    if (keyUsage.cRLSign) usages.push("cRLSign");

    return usages;
  }

  /**
   * Get extended key usage
   */
  getExtendedKeyUsage(cert) {
    const extKeyUsage = cert.extensions.find(
      (ext) => ext.name === "extKeyUsage"
    );
    if (!extKeyUsage) return [];

    const usages = [];
    if (extKeyUsage.serverAuth) usages.push("serverAuth");
    if (extKeyUsage.clientAuth) usages.push("clientAuth");
    if (extKeyUsage.codeSigning) usages.push("codeSigning");
    if (extKeyUsage.emailProtection) usages.push("emailProtection");
    if (extKeyUsage.timeStamping) usages.push("timeStamping");
    if (extKeyUsage.OCSPSigning) usages.push("OCSPSigning");

    return usages;
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
    const signedDir = path.join(this.config.signaturesPath, "signed");
    const verifiedDir = path.join(this.config.signaturesPath, "verified");
    const tamperedDir = path.join(this.config.signaturesPath, "tampered");

    const signedCount = fs.existsSync(signedDir)
      ? fs.readdirSync(signedDir).filter((f) => f.endsWith(".sig.json")).length
      : 0;

    const verifiedCount = fs.existsSync(verifiedDir)
      ? fs
          .readdirSync(verifiedDir)
          .filter((f) => f.endsWith(".verification.json")).length
      : 0;

    const tamperedCount = fs.existsSync(tamperedDir)
      ? fs.readdirSync(tamperedDir).length
      : 0;

    return {
      certificates: {
        codeSigning: !!this.certificates.codeSigning,
        privateKey: !!this.certificates.codeSigningKey,
        rootCA: !!this.certificates.rootCA,
        intermediateCA: !!this.certificates.intermediateCA,
      },
      files: {
        signed: signedCount,
        verified: verifiedCount,
        tampered: tamperedCount,
      },
    };
  }
}

module.exports = CodeSigningDemo;
