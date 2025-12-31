const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const forge = require("node-forge");

class HTTPSDemo {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs",
      port: config.port || 8443,
      httpPort: config.httpPort || 8080,
      enableHTTP: config.enableHTTP !== false,
      enableHTTPS: config.enableHTTPS !== false,
      ...config,
    };

    this.servers = {};
    this.certificates = {};

    this.loadCertificates();
  }

  /**
   * Load certificates for demo
   */
  loadCertificates() {
    try {
      // Try to load root CA
      const rootCertPath = path.join(
        this.config.basePath,
        "root",
        "root-ca.crt"
      );
      if (fs.existsSync(rootCertPath)) {
        this.certificates.rootCA = fs.readFileSync(rootCertPath, "utf8");
      }

      // Try to load intermediate CA
      const intermediateCertPath = path.join(
        this.config.basePath,
        "intermediate",
        "intermediate-ca.crt"
      );
      if (fs.existsSync(intermediateCertPath)) {
        this.certificates.intermediateCA = fs.readFileSync(
          intermediateCertPath,
          "utf8"
        );
      }

      // Try to load server certificate
      const serverCertPath = path.join(
        this.config.basePath,
        "server",
        "localhost.crt"
      );
      if (fs.existsSync(serverCertPath)) {
        this.certificates.serverCert = fs.readFileSync(serverCertPath, "utf8");
      }

      // Try to load server private key
      const serverKeyPath = path.join(
        this.config.basePath,
        "server",
        "localhost_private.pem"
      );
      if (fs.existsSync(serverKeyPath)) {
        this.certificates.serverKey = fs.readFileSync(serverKeyPath, "utf8");
      }

      // Try to load certificate chain
      const chainPath = path.join(
        this.config.basePath,
        "server",
        "localhost-chain.pem"
      );
      if (fs.existsSync(chainPath)) {
        this.certificates.chain = fs.readFileSync(chainPath, "utf8");
      }
    } catch (error) {
      console.warn(`Failed to load certificates: ${error.message}`);
    }
  }

  /**
   * Create HTTPS server
   */
  createHTTPServer(port = null) {
    const serverPort = port || this.config.port;

    if (!this.certificates.serverCert || !this.certificates.serverKey) {
      console.error("❌ Server certificate or key not found");
      console.log("   Please initialize PKI first: npm run init");
      return null;
    }

    const options = {
      key: this.certificates.serverKey,
      cert: this.certificates.serverCert,
      ca: this.certificates.intermediateCA
        ? [this.certificates.intermediateCA]
        : [],
      requestCert: true,
      rejectUnauthorized: false,
      secureProtocol: "TLSv1_2_method",
      ciphers: [
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-DSS-AES128-GCM-SHA256",
        "kEDH+AESGCM",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-ECDSA-AES256-SHA",
        "DHE-RSA-AES128-SHA256",
        "DHE-RSA-AES128-SHA",
        "DHE-DSS-AES128-SHA256",
        "DHE-RSA-AES256-SHA256",
        "DHE-DSS-AES256-SHA",
        "DHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA256",
        "AES256-SHA256",
        "AES128-SHA",
        "AES256-SHA",
        "AES",
        "!3DES",
      ].join(":"),
      honorCipherOrder: true,
    };

    const server = https.createServer(options, (req, res) => {
      this.handleRequest(req, res, "HTTPS");
    });

    server.on("tlsClientError", (error, socket) => {
      console.error(`🔐 TLS Client Error: ${error.message}`);
    });

    server.on("secureConnection", (tlsSocket) => {
      const clientCert = tlsSocket.getPeerCertificate();
      console.log(`🔐 Secure connection established:`);
      console.log(`   Protocol: ${tlsSocket.getProtocol()}`);
      console.log(`   Cipher: ${tlsSocket.getCipher().name}`);
      console.log(`   Client authorized: ${tlsSocket.authorized}`);

      if (clientCert && Object.keys(clientCert).length > 0) {
        console.log(`   Client certificate: ${clientCert.subject.CN}`);
      }
    });

    server.listen(serverPort, () => {
      console.log(
        `🔐 HTTPS Demo Server running on https://localhost:${serverPort}`
      );
      console.log(`📋 Note: Your browser will show a security warning`);
      console.log(
        `   This is expected - you're using a custom Certificate Authority`
      );
      console.log(`\n🔗 Try these URLs:`);
      console.log(`   • https://localhost:${serverPort}/ - Demo homepage`);
      console.log(
        `   • https://localhost:${serverPort}/api/certificate - Certificate info`
      );
      console.log(
        `   • https://localhost:${serverPort}/api/validate - Chain validation`
      );
      console.log(
        `   • https://localhost:${serverPort}/secure - Secure area demo`
      );
      console.log(
        `\n💡 To fix the security warning, import the Root CA certificate:`
      );
      console.log(
        `   ${path.join(this.config.basePath, "root", "root-ca.crt")}`
      );
    });

    this.servers.https = server;
    return server;
  }

  /**
   * Create HTTP server (for redirecting to HTTPS)
   */
  createHTTPServerRedirect(port = null) {
    const serverPort = port || this.config.httpPort;

    const server = http.createServer((req, res) => {
      const httpsPort = this.config.port;
      const redirectUrl = `https://${
        req.headers.host.split(":")[0]
      }:${httpsPort}${req.url}`;

      res.writeHead(301, {
        Location: redirectUrl,
        "Content-Type": "text/html",
      });

      res.end(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Redirecting to HTTPS</title>
                    <meta http-equiv="refresh" content="3;url=${redirectUrl}">
                </head>
                <body>
                    <h1>Redirecting to HTTPS...</h1>
                    <p>For security, this site requires HTTPS.</p>
                    <p>If you are not redirected automatically, <a href="${redirectUrl}">click here</a>.</p>
                </body>
                </html>
            `);
    });

    server.listen(serverPort, () => {
      console.log(
        `🔗 HTTP Redirect Server running on http://localhost:${serverPort}`
      );
      console.log(
        `   Redirects all traffic to HTTPS on port ${this.config.port}`
      );
    });

    this.servers.http = server;
    return server;
  }

  /**
   * Handle HTTP/HTTPS requests
   */
  handleRequest(req, res, protocol) {
    const url = req.url;
    const method = req.method;

    console.log(`${protocol} ${method} ${url}`);

    // Set common headers
    res.setHeader("X-Powered-By", "PKI-Demo-Server");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");

    // Add security headers for HTTPS
    if (protocol === "HTTPS") {
      res.setHeader(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains"
      );
    }

    // Route requests
    if (url === "/" || url === "/index.html") {
      this.serveHomepage(req, res, protocol);
    } else if (url === "/api/certificate") {
      this.serveCertificateInfo(req, res, protocol);
    } else if (url === "/api/validate") {
      this.serveValidationInfo(req, res, protocol);
    } else if (url === "/secure") {
      this.serveSecureArea(req, res, protocol);
    } else if (url === "/api/chain") {
      this.serveCertificateChain(req, res);
    } else if (url === "/api/tls-info") {
      this.serveTLSInfo(req, res);
    } else if (url === "/insecure") {
      this.serveInsecureWarning(req, res, protocol);
    } else if (url.startsWith("/download/")) {
      this.serveDownload(req, res, url);
    } else {
      this.serveNotFound(req, res);
    }
  }

  /**
   * Serve homepage
   */
  serveHomepage(req, res, protocol) {
    const clientCert = req.socket.getPeerCertificate();
    const tlsInfo = req.socket.getCipher();

    let clientInfo = "";
    if (clientCert && Object.keys(clientCert).length > 0) {
      clientInfo = `
                <div class="client-info">
                    <h3>🔐 Your Client Certificate:</h3>
                    <pre>${JSON.stringify(clientCert, null, 2)}</pre>
                </div>
            `;
    }

    const html = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>🔐 PKI HTTPS Demo</title>
                <style>
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
                    
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        padding: 20px;
                    }
                    
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                        background: white;
                        border-radius: 20px;
                        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                        overflow: hidden;
                    }
                    
                    .header {
                        background: linear-gradient(135deg, #2c3e50 0%, #4ca1af 100%);
                        color: white;
                        padding: 40px;
                        text-align: center;
                    }
                    
                    .header h1 {
                        font-size: 2.8rem;
                        margin-bottom: 10px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 15px;
                    }
                    
                    .protocol-badge {
                        display: inline-block;
                        padding: 8px 16px;
                        background: ${
                          protocol === "HTTPS" ? "#10b981" : "#ef4444"
                        };
                        color: white;
                        border-radius: 20px;
                        font-size: 0.9rem;
                        font-weight: bold;
                        text-transform: uppercase;
                    }
                    
                    .content {
                        padding: 40px;
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 40px;
                    }
                    
                    .card {
                        background: #f8fafc;
                        border-radius: 15px;
                        padding: 25px;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                        transition: transform 0.3s ease;
                    }
                    
                    .card:hover {
                        transform: translateY(-5px);
                    }
                    
                    .card h2 {
                        color: #2c3e50;
                        margin-bottom: 20px;
                        padding-bottom: 10px;
                        border-bottom: 3px solid #667eea;
                    }
                    
                    .info-grid {
                        display: grid;
                        gap: 15px;
                    }
                    
                    .info-item {
                        display: flex;
                        justify-content: space-between;
                        padding: 10px;
                        background: white;
                        border-radius: 8px;
                        border-left: 4px solid #667eea;
                    }
                    
                    .info-label {
                        font-weight: 600;
                        color: #4a5568;
                    }
                    
                    .info-value {
                        color: #2d3748;
                        font-family: 'Courier New', monospace;
                    }
                    
                    .actions {
                        display: grid;
                        gap: 15px;
                        margin-top: 30px;
                    }
                    
                    .btn {
                        display: inline-block;
                        padding: 12px 24px;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                        text-decoration: none;
                        border-radius: 8px;
                        text-align: center;
                        font-weight: 600;
                        transition: all 0.3s ease;
                        border: none;
                        cursor: pointer;
                        font-size: 1rem;
                    }
                    
                    .btn:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
                    }
                    
                    .btn-secondary {
                        background: linear-gradient(135deg, #4ca1af 0%, #2c3e50 100%);
                    }
                    
                    .btn-danger {
                        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                    }
                    
                    .client-info {
                        grid-column: 1 / -1;
                        background: #fff3cd;
                        border: 2px solid #ffc107;
                        border-radius: 10px;
                        padding: 20px;
                        margin-top: 20px;
                    }
                    
                    pre {
                        background: #2d3748;
                        color: #e2e8f0;
                        padding: 20px;
                        border-radius: 8px;
                        overflow-x: auto;
                        font-size: 0.9rem;
                        margin-top: 10px;
                    }
                    
                    .security-status {
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        margin: 20px 0;
                        padding: 15px;
                        background: ${
                          protocol === "HTTPS" ? "#d1fae5" : "#fee2e2"
                        };
                        border-radius: 10px;
                        border-left: 4px solid ${
                          protocol === "HTTPS" ? "#10b981" : "#ef4444"
                        };
                    }
                    
                    .status-icon {
                        font-size: 1.5rem;
                    }
                    
                    .footer {
                        text-align: center;
                        padding: 20px;
                        color: #6b7280;
                        font-size: 0.9rem;
                        border-top: 1px solid #e5e7eb;
                        background: #f9fafb;
                    }
                    
                    @media (max-width: 768px) {
                        .content {
                            grid-template-columns: 1fr;
                        }
                        
                        .header h1 {
                            font-size: 2rem;
                            flex-direction: column;
                            gap: 10px;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>
                            🔐 PKI HTTPS Demo
                            <span class="protocol-badge">${protocol}</span>
                        </h1>
                        <p>Real-time demonstration of Public Key Infrastructure in action</p>
                    </div>
                    
                    <div class="content">
                        <div class="security-status">
                            <span class="status-icon">${
                              protocol === "HTTPS" ? "🔒" : "⚠️"
                            }</span>
                            <div>
                                <strong>${
                                  protocol === "HTTPS"
                                    ? "Secure Connection Established"
                                    : "Insecure Connection"
                                }</strong>
                                <p>${
                                  protocol === "HTTPS"
                                    ? "Your connection is encrypted using TLS and your custom PKI certificates."
                                    : "This connection is not secure. Please use HTTPS."
                                }</p>
                            </div>
                        </div>
                        
                        <div class="card">
                            <h2>🔗 Connection Details</h2>
                            <div class="info-grid">
                                <div class="info-item">
                                    <span class="info-label">Protocol:</span>
                                    <span class="info-value">${protocol}</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">TLS Version:</span>
                                    <span class="info-value">${
                                      req.socket.getProtocol() || "N/A"
                                    }</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">Cipher Suite:</span>
                                    <span class="info-value">${
                                      tlsInfo ? tlsInfo.name : "N/A"
                                    }</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">Key Size:</span>
                                    <span class="info-value">${
                                      tlsInfo ? tlsInfo.bits : "N/A"
                                    } bits</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <h2>⚡ Quick Actions</h2>
                            <div class="actions">
                                <a href="/api/certificate" class="btn">View Certificate Details</a>
                                <a href="/api/validate" class="btn">Validate Certificate Chain</a>
                                <a href="/secure" class="btn">Access Secure Area</a>
                                ${
                                  protocol === "HTTPS"
                                    ? '<a href="/insecure" class="btn btn-danger">Try HTTP (Insecure)</a>'
                                    : '<a href="/" class="btn btn-secondary">Back to HTTPS</a>'
                                }
                            </div>
                        </div>
                        
                        ${clientInfo}
                    </div>
                    
                    <div class="footer">
                        <p>PKI Simulation Demo • Created for Educational Purposes • ${new Date().getFullYear()}</p>
                        <p>This server is secured with certificates from your own Certificate Authority</p>
                    </div>
                </div>
                
                <script>
                    // Auto-refresh TLS info every 10 seconds
                    setInterval(() => {
                        fetch('/api/tls-info')
                            .then(res => res.json())
                            .then(data => {
                                // Update TLS info if available
                                if (data.protocol) {
                                    const protocolBadge = document.querySelector('.protocol-badge');
                                    if (protocolBadge) {
                                        protocolBadge.textContent = data.protocol;
                                        protocolBadge.style.background = data.protocol === 'HTTPS' ? '#10b981' : '#ef4444';
                                    }
                                }
                            });
                    }, 10000);
                </script>
            </body>
            </html>
        `;

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  }

  /**
   * Serve certificate information
   */
  serveCertificateInfo(req, res, protocol) {
    if (!this.certificates.serverCert) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Certificate not found" }, null, 2));
      return;
    }

    try {
      const cert = forge.pki.certificateFromPem(this.certificates.serverCert);

      const extensions = {};
      cert.extensions.forEach((ext) => {
        extensions[ext.name] = {
          value: ext.value,
          critical: ext.critical,
        };
      });

      const certInfo = {
        subject: this.formatName(cert.subject),
        issuer: this.formatName(cert.issuer),
        serialNumber: cert.serialNumber,
        notBefore: cert.validity.notBefore.toISOString(),
        notAfter: cert.validity.notAfter.toISOString(),
        signatureAlgorithm: cert.siginfo.algorithmOid,
        publicKey: {
          algorithm: cert.publicKey.constructor.name,
          keySize: cert.publicKey.n ? cert.publicKey.n.bitLength() : "N/A",
        },
        extensions: extensions,
        isCA:
          extensions.basicConstraints &&
          extensions.basicConstraints.value &&
          extensions.basicConstraints.value.cA,
        protocol: protocol,
      };

      const html = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Certificate Details</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
                        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
                        .info { margin: 20px 0; }
                        .info h3 { color: #555; margin-bottom: 10px; }
                        pre { background: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; }
                        .nav { margin-top: 30px; }
                        .btn { display: inline-block; padding: 10px 20px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔐 Server Certificate Details</h1>
                        <div class="info">
                            <h3>Basic Information</h3>
                            <pre>${JSON.stringify(
                              {
                                subject: certInfo.subject,
                                issuer: certInfo.issuer,
                                validity: {
                                  notBefore: certInfo.notBefore,
                                  notAfter: certInfo.notAfter,
                                },
                                serialNumber: certInfo.serialNumber,
                              },
                              null,
                              2
                            )}</pre>
                        </div>
                        <div class="info">
                            <h3>Public Key Information</h3>
                            <pre>${JSON.stringify(
                              certInfo.publicKey,
                              null,
                              2
                            )}</pre>
                        </div>
                        <div class="info">
                            <h3>Extensions</h3>
                            <pre>${JSON.stringify(
                              certInfo.extensions,
                              null,
                              2
                            )}</pre>
                        </div>
                        <div class="nav">
                            <a href="/" class="btn">← Back to Home</a>
                            <a href="/api/validate" class="btn">Validate Chain →</a>
                            <a href="/download/certificate" class="btn">Download Certificate</a>
                        </div>
                    </div>
                </body>
                </html>
            `;

      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(html);
    } catch (error) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: error.message }, null, 2));
    }
  }

  /**
   * Serve validation information
   */
  serveValidationInfo(req, res, protocol) {
    if (
      !this.certificates.serverCert ||
      !this.certificates.intermediateCA ||
      !this.certificates.rootCA
    ) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({ error: "Required certificates not found" }, null, 2)
      );
      return;
    }

    try {
      const serverCert = forge.pki.certificateFromPem(
        this.certificates.serverCert
      );
      const intermediateCert = forge.pki.certificateFromPem(
        this.certificates.intermediateCA
      );
      const rootCert = forge.pki.certificateFromPem(this.certificates.rootCA);

      // Validate signatures
      const intermediateValidatesServer = intermediateCert.verify(serverCert);
      const rootValidatesIntermediate = rootCert.verify(intermediateCert);
      const rootIsSelfSigned =
        this.formatName(rootCert.subject) === this.formatName(rootCert.issuer);

      // Check validity periods
      const now = new Date();
      const serverValid =
        now >= serverCert.validity.notBefore &&
        now <= serverCert.validity.notAfter;
      const intermediateValid =
        now >= intermediateCert.validity.notBefore &&
        now <= intermediateCert.validity.notAfter;
      const rootValid =
        now >= rootCert.validity.notBefore && now <= rootCert.validity.notAfter;

      const validationResult = {
        chain: [
          {
            type: "Leaf",
            subject: this.formatName(serverCert.subject),
            issuer: this.formatName(serverCert.issuer),
            signatureValid: intermediateValidatesServer,
            validityPeriodValid: serverValid,
            daysRemaining: Math.floor(
              (serverCert.validity.notAfter - now) / (1000 * 60 * 60 * 24)
            ),
          },
          {
            type: "Intermediate",
            subject: this.formatName(intermediateCert.subject),
            issuer: this.formatName(intermediateCert.issuer),
            signatureValid: rootValidatesIntermediate,
            validityPeriodValid: intermediateValid,
            daysRemaining: Math.floor(
              (intermediateCert.validity.notAfter - now) / (1000 * 60 * 60 * 24)
            ),
          },
          {
            type: "Root",
            subject: this.formatName(rootCert.subject),
            issuer: this.formatName(rootCert.issuer),
            selfSigned: rootIsSelfSigned,
            validityPeriodValid: rootValid,
            daysRemaining: Math.floor(
              (rootCert.validity.notAfter - now) / (1000 * 60 * 60 * 24)
            ),
          },
        ],
        overallValid:
          intermediateValidatesServer &&
          rootValidatesIntermediate &&
          serverValid &&
          intermediateValid &&
          rootValid,
        timestamp: now.toISOString(),
      };

      const html = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Certificate Chain Validation</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
                        h1 { color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }
                        .chain { margin: 30px 0; }
                        .cert { padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 5px solid #ccc; }
                        .cert.root { border-left-color: #4CAF50; background: #f1f8e9; }
                        .cert.intermediate { border-left-color: #2196F3; background: #e3f2fd; }
                        .cert.leaf { border-left-color: #FF9800; background: #fff3e0; }
                        .status { display: inline-block; padding: 5px 15px; border-radius: 15px; color: white; font-weight: bold; margin-left: 10px; }
                        .status.valid { background: #4CAF50; }
                        .status.invalid { background: #f44336; }
                        .details { margin-top: 10px; padding: 10px; background: #f8f8f8; border-radius: 5px; }
                        .nav { margin-top: 30px; }
                        .btn { display: inline-block; padding: 10px 20px; background: #2196F3; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }
                        .overall { padding: 20px; background: ${
                          validationResult.overallValid ? "#d4edda" : "#f8d7da"
                        }; 
                                  border: 2px solid ${
                                    validationResult.overallValid
                                      ? "#c3e6cb"
                                      : "#f5c6cb"
                                  };
                                  border-radius: 8px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔗 Certificate Chain Validation</h1>
                        
                        <div class="overall">
                            <h2>${
                              validationResult.overallValid
                                ? "✅ Chain is VALID"
                                : "❌ Chain is INVALID"
                            }</h2>
                            <p>All certificates in the chain are properly signed and within their validity periods.</p>
                        </div>
                        
                        <div class="chain">
                            ${validationResult.chain
                              .map(
                                (cert) => `
                                <div class="cert ${cert.type.toLowerCase()}">
                                    <h3>${cert.type} Certificate</h3>
                                    <p><strong>Subject:</strong> ${
                                      cert.subject
                                    }</p>
                                    <p><strong>Issuer:</strong> ${
                                      cert.issuer
                                    }</p>
                                    <div class="details">
                                        <p><strong>Signature:</strong> 
                                            <span class="status ${
                                              cert.signatureValid
                                                ? "valid"
                                                : "invalid"
                                            }">
                                                ${
                                                  cert.signatureValid
                                                    ? "VALID"
                                                    : "INVALID"
                                                }
                                            </span>
                                        </p>
                                        <p><strong>Validity Period:</strong> 
                                            <span class="status ${
                                              cert.validityPeriodValid
                                                ? "valid"
                                                : "invalid"
                                            }">
                                                ${
                                                  cert.validityPeriodValid
                                                    ? "VALID"
                                                    : "EXPIRED"
                                                }
                                            </span>
                                        </p>
                                        ${
                                          cert.daysRemaining !== undefined
                                            ? `
                                            <p><strong>Days Remaining:</strong> ${cert.daysRemaining}</p>
                                        `
                                            : ""
                                        }
                                        ${
                                          cert.selfSigned !== undefined
                                            ? `
                                            <p><strong>Self-signed:</strong> ${
                                              cert.selfSigned ? "Yes" : "No"
                                            }</p>
                                        `
                                            : ""
                                        }
                                    </div>
                                </div>
                            `
                              )
                              .join("")}
                        </div>
                        
                        <div class="nav">
                            <a href="/" class="btn">← Back to Home</a>
                            <a href="/api/certificate" class="btn">View Certificate Details →</a>
                            <a href="/api/chain" class="btn">Download Full Chain</a>
                        </div>
                    </div>
                </body>
                </html>
            `;

      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(html);
    } catch (error) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: error.message }, null, 2));
    }
  }

  /**
   * Serve secure area
   */
  serveSecureArea(req, res, protocol) {
    if (protocol !== "HTTPS") {
      res.writeHead(403, { "Content-Type": "text/html" });
      res.end(`
                <!DOCTYPE html>
                <html>
                <head><title>Access Denied</title></head>
                <body>
                    <h1>⛔ Access Denied</h1>
                    <p>This area requires a secure HTTPS connection.</p>
                    <p><a href="/">Return to homepage</a></p>
                </body>
                </html>
            `);
      return;
    }

    const clientCert = req.socket.getPeerCertificate();
    const hasClientCert = clientCert && Object.keys(clientCert).length > 0;

    const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Secure Area</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
                    .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
                    h1 { color: #333; text-align: center; margin-bottom: 30px; }
                    .secure-badge { display: inline-block; padding: 10px 20px; background: #4CAF50; color: white; border-radius: 20px; font-weight: bold; }
                    .info-card { background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 5px solid #4CAF50; }
                    .nav { text-align: center; margin-top: 30px; }
                    .btn { display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 8px; margin: 0 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🔐 Secure Area</h1>
                    <div style="text-align: center; margin-bottom: 30px;">
                        <span class="secure-badge">HTTPS SECURE CONNECTION</span>
                    </div>
                    
                    <div class="info-card">
                        <h2>Welcome to the Secure Area!</h2>
                        <p>This content is only accessible over a secure HTTPS connection.</p>
                        <p>Your connection is encrypted using TLS and validated with your custom PKI.</p>
                    </div>
                    
                    ${
                      hasClientCert
                        ? `
                        <div class="info-card">
                            <h2>🔑 Client Certificate Detected</h2>
                            <p>You have provided a client certificate for mutual TLS authentication.</p>
                            <p><strong>Subject:</strong> ${
                              clientCert.subject.CN || "Unknown"
                            }</p>
                        </div>
                    `
                        : `
                        <div class="info-card">
                            <h2>⚠️ No Client Certificate</h2>
                            <p>This server supports mutual TLS authentication, but you didn't provide a client certificate.</p>
                            <p>For enhanced security, consider configuring a client certificate.</p>
                        </div>
                    `
                    }
                    
                    <div class="nav">
                        <a href="/" class="btn">← Back to Home</a>
                        ${
                          hasClientCert
                            ? '<a href="/api/certificate" class="btn">View Your Certificate</a>'
                            : ""
                        }
                    </div>
                </div>
            </body>
            </html>
        `;

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  }

  /**
   * Serve insecure warning
   */
  serveInsecureWarning(req, res, protocol) {
    const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Insecure Connection Warning</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #fff3cd; }
                    .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); border: 3px solid #ffc107; }
                    h1 { color: #856404; }
                    .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 5px; margin: 20px 0; }
                    .btn { display: inline-block; padding: 10px 20px; background: #856404; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>⚠️ Insecure Connection Detected</h1>
                    <div class="warning">
                        <p><strong>Warning:</strong> You are accessing this page over ${protocol}.</p>
                        <p>For security reasons, sensitive information should only be transmitted over HTTPS.</p>
                        <p>Your connection is not encrypted and could be intercepted by attackers.</p>
                    </div>
                    <p>Please use HTTPS for secure communication:</p>
                    <p>
                        <a href="https://localhost:${this.config.port}/" class="btn">Switch to HTTPS</a>
                        <a href="/" class="btn">I understand the risks</a>
                    </p>
                </div>
            </body>
            </html>
        `;

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  }

  /**
   * Serve certificate chain download
   */
  serveCertificateChain(req, res) {
    if (!this.certificates.chain) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Certificate chain not found");
      return;
    }

    res.writeHead(200, {
      "Content-Type": "application/x-pem-file",
      "Content-Disposition": 'attachment; filename="certificate-chain.pem"',
      "Content-Length": this.certificates.chain.length,
    });
    res.end(this.certificates.chain);
  }

  /**
   * Serve TLS information as JSON
   */
  serveTLSInfo(req, res) {
    const tlsInfo = req.socket.getCipher();
    const protocol = req.socket.encrypted ? "HTTPS" : "HTTP";

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify(
        {
          protocol: protocol,
          tlsVersion: req.socket.getProtocol(),
          cipher: tlsInfo ? tlsInfo.name : null,
          keySize: tlsInfo ? tlsInfo.bits : null,
          timestamp: new Date().toISOString(),
        },
        null,
        2
      )
    );
  }

  /**
   * Serve file downloads
   */
  serveDownload(req, res, url) {
    const filename = url.split("/download/")[1];

    if (filename === "certificate" && this.certificates.serverCert) {
      res.writeHead(200, {
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": 'attachment; filename="server-certificate.pem"',
        "Content-Length": this.certificates.serverCert.length,
      });
      res.end(this.certificates.serverCert);
    } else if (filename === "root-ca" && this.certificates.rootCA) {
      res.writeHead(200, {
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": 'attachment; filename="root-ca.crt"',
        "Content-Length": this.certificates.rootCA.length,
      });
      res.end(this.certificates.rootCA);
    } else if (filename === "chain" && this.certificates.chain) {
      res.writeHead(200, {
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": 'attachment; filename="certificate-chain.pem"',
        "Content-Length": this.certificates.chain.length,
      });
      res.end(this.certificates.chain);
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("File not found");
    }
  }

  /**
   * Serve 404 page
   */
  serveNotFound(req, res) {
    res.writeHead(404, { "Content-Type": "text/html" });
    res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>404 Not Found</title></head>
            <body>
                <h1>404 - Page Not Found</h1>
                <p>The requested URL ${req.url} was not found on this server.</p>
                <p><a href="/">Return to homepage</a></p>
            </body>
            </html>
        `);
  }

  /**
   * Format certificate name
   */
  formatName(name) {
    return name.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  /**
   * Start all demo servers
   */
  startAll() {
    if (this.config.enableHTTPS) {
      this.createHTTPServer();
    }

    if (this.config.enableHTTP) {
      this.createHTTPServerRedirect();
    }

    return this.servers;
  }

  /**
   * Stop all servers
   */
  stopAll() {
    Object.values(this.servers).forEach((server) => {
      if (server && server.close) {
        server.close();
      }
    });

    this.servers = {};
    console.log("All demo servers stopped");
  }

  /**
   * Get server information
   */
  getServerInfo() {
    return {
      https: this.servers.https
        ? {
            port: this.config.port,
            protocol: "HTTPS",
            certificates: {
              server: !!this.certificates.serverCert,
              intermediate: !!this.certificates.intermediateCA,
              root: !!this.certificates.rootCA,
              chain: !!this.certificates.chain,
            },
          }
        : null,
      http: this.servers.http
        ? {
            port: this.config.httpPort,
            protocol: "HTTP",
            redirectsTo: this.config.port,
          }
        : null,
    };
  }
}

module.exports = HTTPSDemo;
