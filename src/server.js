const express = require("express");
const fs = require("fs");
const path = require("path");

// Import all modules
const CertificateAuthority = require("./ca/CertificateAuthority");
const HTTPSDemo = require("./demo/HTTPSDemo");
const CodeSigningDemo = require("./demo/CodeSigningDemo");
const EmailEncryptionDemo = require("./demo/EmailEncryptionDemo");

const app = express();
app.use(express.json());
app.use(express.static("public"));

// Initialize components
const caConfig = {
  basePath: "./certs",
  keySize: 2048,
  defaultOrganization: "PKI Demo Academy",
};

const ca = new CertificateAuthority(caConfig);
const httpsDemo = new HTTPSDemo({
  basePath: "./certs",
  port: 8443,
  httpPort: 8080,
});
const codeSigningDemo = new CodeSigningDemo({ basePath: "./certs" });
const emailDemo = new EmailEncryptionDemo({ basePath: "./certs" });

let demoServer = null;
let httpsServer = null;

/**
 * Welcome Route
 */
app.get("/", (req, res) => {
  res.json({
    message: "🔐 PKI Simulation Server",
    version: "1.0.0",
    endpoints: {
      // PKI Management
      "GET /api/pki/status": "Get PKI status",
      "POST /api/pki/initialize": "Initialize PKI hierarchy",
      "GET /api/pki/hierarchy": "Display PKI hierarchy",
      "POST /api/pki/issue": "Issue new certificate",
      "POST /api/pki/revoke": "Revoke certificate",
      "POST /api/pki/validate": "Validate certificate",

      // HTTPS Demo
      "GET /api/https/start": "Start HTTPS demo server",
      "GET /api/https/stop": "Stop HTTPS demo server",
      "GET /api/https/status": "Get HTTPS demo status",

      // Code Signing Demo
      "GET /api/codesign/status": "Get code signing status",
      "POST /api/codesign/sign": "Sign a file",
      "POST /api/codesign/verify": "Verify file signature",
      "GET /api/codesign/demo": "Run code signing demo",

      // Email Encryption Demo
      "GET /api/email/status": "Get email encryption status",
      "POST /api/email/encrypt": "Encrypt email",
      "POST /api/email/decrypt": "Decrypt email",
      "POST /api/email/sign": "Sign email",
      "GET /api/email/demo": "Run email encryption demo",

      // System
      "GET /api/system/cleanup": "Clean up demo files",
      "GET /api/system/stats": "Get system statistics",
    },
    description:
      "A complete Public Key Infrastructure simulation for educational purposes",
  });
});

/**
 * PKI Status
 */
app.get("/api/pki/status", (req, res) => {
  try {
    const stats = ca.getStatistics();

    res.json({
      success: true,
      pki: {
        initialized: stats.rootCA && stats.intermediateCA,
        statistics: stats,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Initialize PKI
 */
app.post("/api/pki/initialize", async (req, res) => {
  try {
    const { organization, country } = req.body;

    const result = await ca.initializePKI({
      organization: organization || "PKI Demo Academy",
      country: country || "US",
    });

    res.json({
      success: true,
      message: "PKI hierarchy initialized successfully",
      certificates: result.certificates,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Display PKI Hierarchy
 */
app.get("/api/pki/hierarchy", (req, res) => {
  try {
    ca.displayHierarchy();

    const certificates = ca.listCertificates();
    const stats = ca.getStatistics();

    res.json({
      success: true,
      hierarchy: {
        rootCA: stats.rootCA,
        intermediateCA: stats.intermediateCA,
        certificates: certificates,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Issue Certificate
 */
app.post("/api/pki/issue", (req, res) => {
  try {
    const { csr, type, options } = req.body;

    if (!csr) {
      return res.status(400).json({ error: "CSR is required" });
    }

    const result = ca.issueCertificate(csr, type || "server", options || {});

    res.json({
      success: true,
      message: "Certificate issued successfully",
      certificate: {
        serialNumber: result.serialNumber,
        filePath: result.filePath,
        subject: result.certificate.subject,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Validate Certificate
 */
app.post("/api/pki/validate", (req, res) => {
  try {
    const { certificate } = req.body;

    if (!certificate) {
      return res.status(400).json({ error: "Certificate is required" });
    }

    const result = ca.validateCertificate(certificate);

    res.json({
      success: true,
      validation: result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * HTTPS Demo Start
 */
app.get("/api/https/start", (req, res) => {
  try {
    if (httpsServer) {
      return res.json({
        success: false,
        message: "HTTPS server already running",
        info: httpsDemo.getServerInfo(),
      });
    }

    httpsServer = httpsDemo.startAll();

    res.json({
      success: true,
      message: "HTTPS demo servers started",
      info: httpsDemo.getServerInfo(),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * HTTPS Demo Stop
 */
app.get("/api/https/stop", (req, res) => {
  try {
    if (!httpsServer) {
      return res.json({
        success: false,
        message: "No HTTPS server running",
      });
    }

    httpsDemo.stopAll();
    httpsServer = null;

    res.json({
      success: true,
      message: "HTTPS demo servers stopped",
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * HTTPS Demo Status
 */
app.get("/api/https/status", (req, res) => {
  try {
    res.json({
      success: true,
      servers: httpsDemo.getServerInfo(),
      certificates: httpsDemo.certificates
        ? Object.keys(httpsDemo.certificates)
        : [],
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Code Signing Status
 */
app.get("/api/codesign/status", (req, res) => {
  try {
    const stats = codeSigningDemo.getStatistics();

    res.json({
      success: true,
      codeSigning: stats,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Sign File
 */
app.post("/api/codesign/sign", async (req, res) => {
  try {
    const { filePath, options } = req.body;

    if (!filePath) {
      return res.status(400).json({ error: "File path is required" });
    }

    const result = await codeSigningDemo.signFile(filePath, options || {});

    res.json({
      success: true,
      message: "File signed successfully",
      result: result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Verify File Signature
 */
app.post("/api/codesign/verify", async (req, res) => {
  try {
    const { filePath, signaturePath } = req.body;

    if (!filePath) {
      return res.status(400).json({ error: "File path is required" });
    }

    const result = await codeSigningDemo.verifySignature(
      filePath,
      signaturePath
    );

    res.json({
      success: true,
      verification: result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Run Code Signing Demo
 */
app.get("/api/codesign/demo", async (req, res) => {
  try {
    const result = await codeSigningDemo.runDemo();

    res.json({
      success: true,
      message: "Code signing demo completed",
      demo: result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Email Encryption Status
 */
app.get("/api/email/status", (req, res) => {
  try {
    const stats = emailDemo.getStatistics();

    res.json({
      success: true,
      emailEncryption: stats,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Encrypt Email
 */
app.post("/api/email/encrypt", async (req, res) => {
  try {
    const { recipient, message, options } = req.body;

    if (!recipient || !message) {
      return res.status(400).json({
        error: "Recipient and message are required",
      });
    }

    const result = await emailDemo.encryptEmail(
      recipient,
      message,
      options || {}
    );

    res.json({
      success: true,
      message: "Email encrypted successfully",
      result: result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Decrypt Email
 */
app.post("/api/email/decrypt", async (req, res) => {
  try {
    const { filePath, privateKey, passphrase } = req.body;

    if (!filePath || !privateKey) {
      return res.status(400).json({
        error: "File path and private key are required",
      });
    }

    const result = await emailDemo.decryptEmail(
      filePath,
      privateKey,
      passphrase
    );

    res.json({
      success: true,
      message: "Email decrypted successfully",
      result: result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Run Email Encryption Demo
 */
app.get("/api/email/demo", async (req, res) => {
  try {
    const result = await emailDemo.runDemo();

    res.json({
      success: true,
      message: "Email encryption demo completed",
      demo: result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * System Cleanup
 */
app.get("/api/system/cleanup", (req, res) => {
  try {
    // Clean up demo directories
    const dirs = ["./emails", "./signatures", "./public/demo"];

    let cleaned = 0;
    dirs.forEach((dir) => {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        cleaned++;
        console.log(`Cleaned: ${dir}`);
      }
    });

    res.json({
      success: true,
      message: `Cleaned ${cleaned} directories`,
      cleaned: cleaned,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * System Statistics
 */
app.get("/api/system/stats", (req, res) => {
  try {
    const pkiStats = ca.getStatistics();
    const codeSigningStats = codeSigningDemo.getStatistics();
    const emailStats = emailDemo.getStatistics();

    res.json({
      success: true,
      statistics: {
        pki: pkiStats,
        codeSigning: codeSigningStats,
        email: emailStats,
        https: httpsServer ? "running" : "stopped",
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Error handling middleware
 */
app.use((err, req, res, next) => {
  console.error("Server error:", err.stack);
  res.status(500).json({
    success: false,
    error: err.message,
    timestamp: new Date().toISOString(),
  });
});

/**
 * 404 handler
 */
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found",
    path: req.url,
    timestamp: new Date().toISOString(),
  });
});

/**
 * Start server
 */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("\n" + "=".repeat(60));
  console.log("🚀 PKI Simulation Server");
  console.log("=".repeat(60));
  console.log(`📡 API Server running on http://localhost:${PORT}`);
  console.log("\n📋 Available Endpoints:");
  console.log(`   • http://localhost:${PORT}/ - API documentation`);
  console.log(`   • http://localhost:${PORT}/api/pki/status - PKI status`);
  console.log(
    `   • http://localhost:${PORT}/api/https/start - Start HTTPS demo`
  );
  console.log(
    `   • http://localhost:${PORT}/api/codesign/demo - Run code signing demo`
  );
  console.log(
    `   • http://localhost:${PORT}/api/email/demo - Run email encryption demo`
  );
  console.log("\n🔐 To get started:");
  console.log("   1. Initialize PKI: POST /api/pki/initialize");
  console.log("   2. Start HTTPS demo: GET /api/https/start");
  console.log("   3. Visit https://localhost:8443 (accept security warning)");
  console.log("\n💡 Check the browser console for more instructions!");
  console.log("=".repeat(60) + "\n");
});

/**
 * Graceful shutdown
 */
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully...");

  if (httpsServer) {
    httpsDemo.stopAll();
  }

  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully...");

  if (httpsServer) {
    httpsDemo.stopAll();
  }

  process.exit(0);
});

module.exports = app;
