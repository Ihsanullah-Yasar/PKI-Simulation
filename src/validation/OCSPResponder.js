const crypto = require("crypto");
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");

class OCSPResponder {
  constructor(config = {}) {
    this.config = {
      basePath: config.basePath || "./certs",
      port: config.port || 8080,
      responseLifetime: config.responseLifetime || 3600, // 1 hour in seconds
      nextUpdateOffset: config.nextUpdateOffset || 86400, // 24 hours in seconds
      ...config,
    };

    this.forge = forge;
    forge.options.usePureJavaScript = true;

    this.revokedCertificates = new Map(); // serialNumber -> revocation info
    this.responseCache = new Map(); // cache key -> OCSP response
    this.responderCert = null;
    this.responderKey = null;

    this.ensureDirectory();
  }

  /**
   * Ensure directory exists
   */
  ensureDirectory() {
    const ocspDir = path.join(this.config.basePath, "ocsp");
    if (!fs.existsSync(ocspDir)) {
      fs.mkdirSync(ocspDir, { recursive: true });
    }
  }

  /**
   * Initialize OCSP responder with certificate
   */
  initialize(responderCert, responderKey) {
    this.responderCert = responderCert;
    this.responderKey = responderKey;

    console.log("🔐 OCSP Responder initialized");
    console.log(`   Responder: ${this.formatName(responderCert.subject)}`);
    console.log(
      `   Response lifetime: ${this.config.responseLifetime} seconds`
    );

    return true;
  }

  /**
   * Load OCSP responder from files
   */
  loadFromFiles(certPath, keyPath) {
    try {
      const certPem = fs.readFileSync(certPath, "utf8");
      const keyPem = fs.readFileSync(keyPath, "utf8");

      this.responderCert = forge.pki.certificateFromPem(certPem);
      this.responderKey = forge.pki.privateKeyFromPem(keyPem);

      console.log(`✅ OCSP Responder loaded from ${certPath}`);
      return true;
    } catch (error) {
      console.error(`Failed to load OCSP responder: ${error.message}`);
      return false;
    }
  }

  /**
   * Add revoked certificate to OCSP database
   */
  revokeCertificate(cert, revocationDate = new Date(), reason = "unspecified") {
    const serialNumber = cert.serialNumber;

    this.revokedCertificates.set(serialNumber, {
      cert: cert,
      serialNumber: serialNumber,
      revocationDate: revocationDate,
      reason: reason,
      addedAt: new Date(),
    });

    console.log(
      `❌ Added to OCSP: ${serialNumber} (${this.formatName(cert.subject)})`
    );

    // Clear cache for this certificate
    this.clearCacheForCertificate(serialNumber);

    return true;
  }

  /**
   * Remove certificate from revoked list (un-revoke)
   */
  unrevokeCertificate(serialNumber) {
    const removed = this.revokedCertificates.delete(serialNumber);

    if (removed) {
      console.log(`✅ Removed from OCSP: ${serialNumber}`);
      this.clearCacheForCertificate(serialNumber);
    }

    return removed;
  }

  /**
   * Process OCSP request
   */
  processRequest(ocspRequestDer) {
    try {
      const request = forge.ocsp.decodeRequest(ocspRequestDer);

      const responses = [];

      // Process each certificate ID in the request
      for (const certId of request.certIDs) {
        const response = this.createResponseForCertId(certId);
        responses.push(response);
      }

      // Create OCSP response
      const ocspResponse = forge.ocsp.createResponse(
        this.responderCert,
        this.responderKey,
        responses,
        {
          producedAt: new Date(),
          responseLifetime: this.config.responseLifetime,
          nextUpdateOffset: this.config.nextUpdateOffset,
        }
      );

      const responseDer = forge.ocsp.encodeResponse(ocspResponse);

      // Cache the response
      const cacheKey = this.generateCacheKey(request);
      this.responseCache.set(cacheKey, {
        response: ocspResponse,
        der: responseDer,
        cachedAt: new Date(),
        expiresAt: new Date(Date.now() + this.config.responseLifetime * 1000),
      });

      return {
        success: true,
        response: ocspResponse,
        der: responseDer,
        requestId: this.getRequestId(request),
      };
    } catch (error) {
      console.error(`OCSP request processing failed: ${error.message}`);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Create response for a single certificate ID
   */
  createResponseForCertId(certId) {
    const serialNumber = certId.serialNumber;
    const revocationInfo = this.revokedCertificates.get(serialNumber);

    if (revocationInfo) {
      // Certificate is revoked
      return {
        certID: certId,
        status: forge.ocsp.CertificateStatus.REVOKED,
        revocationTime: revocationInfo.revocationDate,
        revocationReason: this.getRevocationReasonCode(revocationInfo.reason),
      };
    } else {
      // Certificate is good (not revoked)
      return {
        certID: certId,
        status: forge.ocsp.CertificateStatus.GOOD,
      };
    }
  }

  /**
   * Get revocation reason code
   */
  getRevocationReasonCode(reason) {
    const reasonCodes = {
      unspecified: 0,
      keyCompromise: 1,
      cACompromise: 2,
      affiliationChanged: 3,
      superseded: 4,
      cessationOfOperation: 5,
      certificateHold: 6,
      removeFromCRL: 8,
      privilegeWithdrawn: 9,
      aACompromise: 10,
    };

    return reasonCodes[reason] || 0;
  }

  /**
   * Generate cache key for request
   */
  generateCacheKey(request) {
    const certIds = request.certIDs
      .map(
        (certId) =>
          `${certId.serialNumber}-${certId.issuerNameHash}-${certId.issuerKeyHash}`
      )
      .join("|");

    return crypto.createHash("sha256").update(certIds).digest("hex");
  }

  /**
   * Get request ID for logging
   */
  getRequestId(request) {
    const firstCertId = request.certIDs[0];
    return firstCertId ? firstCertId.serialNumber.substring(0, 16) : "unknown";
  }

  /**
   * Clear cache for specific certificate
   */
  clearCacheForCertificate(serialNumber) {
    for (const [key, value] of this.responseCache.entries()) {
      if (key.includes(serialNumber)) {
        this.responseCache.delete(key);
      }
    }
  }

  /**
   * Clear entire response cache
   */
  clearCache() {
    const cleared = this.responseCache.size;
    this.responseCache.clear();
    return cleared;
  }

  /**
   * Get cached response for request
   */
  getCachedResponse(request) {
    const cacheKey = this.generateCacheKey(request);
    const cached = this.responseCache.get(cacheKey);

    if (cached && cached.expiresAt > new Date()) {
      return cached;
    }

    if (cached) {
      this.responseCache.delete(cacheKey);
    }

    return null;
  }

  /**
   * Validate OCSP request
   */
  validateRequest(ocspRequestDer) {
    try {
      const request = forge.ocsp.decodeRequest(ocspRequestDer);

      if (!request.certIDs || request.certIDs.length === 0) {
        return {
          valid: false,
          error: "No certificate IDs in request",
        };
      }

      // Check request signature if present
      if (request.signature) {
        // TODO: Implement signature validation
        console.log("OCSP request has signature (not validated in this demo)");
      }

      return {
        valid: true,
        request: request,
        certCount: request.certIDs.length,
      };
    } catch (error) {
      return {
        valid: false,
        error: `Invalid OCSP request: ${error.message}`,
      };
    }
  }

  /**
   * Create OCSP response for testing
   */
  createTestResponse(serialNumber, status = "good") {
    const certId = {
      hashAlgorithm: forge.pki.oids.sha1,
      issuerNameHash: "test-hash",
      issuerKeyHash: "test-key-hash",
      serialNumber: serialNumber,
    };

    let response;

    if (status === "revoked") {
      response = {
        certID: certId,
        status: forge.ocsp.CertificateStatus.REVOKED,
        revocationTime: new Date(),
        revocationReason: 0,
      };
    } else {
      response = {
        certID: certId,
        status: forge.ocsp.CertificateStatus.GOOD,
      };
    }

    const ocspResponse = forge.ocsp.createResponse(
      this.responderCert,
      this.responderKey,
      [response],
      {
        producedAt: new Date(),
        responseLifetime: this.config.responseLifetime,
      }
    );

    return {
      response: ocspResponse,
      der: forge.ocsp.encodeResponse(ocspResponse),
    };
  }

  /**
   * Get responder statistics
   */
  getStatistics() {
    const now = new Date();
    const cacheEntries = Array.from(this.responseCache.values());

    const validCache = cacheEntries.filter((entry) => entry.expiresAt > now);
    const expiredCache = cacheEntries.filter((entry) => entry.expiresAt <= now);

    return {
      revokedCertificates: this.revokedCertificates.size,
      cacheEntries: {
        total: cacheEntries.length,
        valid: validCache.length,
        expired: expiredCache.length,
      },
      responderCert: this.responderCert
        ? this.formatName(this.responderCert.subject)
        : "Not set",
      config: {
        responseLifetime: this.config.responseLifetime,
        nextUpdateOffset: this.config.nextUpdateOffset,
      },
    };
  }

  /**
   * Save responder state to file
   */
  saveState(filePath = null) {
    const statePath =
      filePath ||
      path.join(this.config.basePath, "ocsp", "responder-state.json");

    const state = {
      revokedCertificates: Array.from(this.revokedCertificates.entries()).map(
        ([serial, info]) => ({
          serialNumber: serial,
          revocationDate: info.revocationDate.toISOString(),
          reason: info.reason,
          subject: this.formatName(info.cert.subject),
        })
      ),
      savedAt: new Date().toISOString(),
      config: this.config,
    };

    fs.writeFileSync(statePath, JSON.stringify(state, null, 2), "utf8");

    console.log(`💾 OCSP responder state saved to ${statePath}`);

    return statePath;
  }

  /**
   * Load responder state from file
   */
  loadState(filePath = null) {
    const statePath =
      filePath ||
      path.join(this.config.basePath, "ocsp", "responder-state.json");

    if (!fs.existsSync(statePath)) {
      console.log(`No saved state found at ${statePath}`);
      return false;
    }

    try {
      const stateData = fs.readFileSync(statePath, "utf8");
      const state = JSON.parse(stateData);

      // Clear current state
      this.revokedCertificates.clear();
      this.responseCache.clear();

      // Load revoked certificates
      // Note: We need the actual certificate objects, not just serial numbers
      // In a real implementation, you'd load certificates from a database

      console.log(`📂 Loaded OCSP responder state from ${statePath}`);
      console.log(
        `   Revoked certificates: ${state.revokedCertificates.length}`
      );
      console.log(`   State saved: ${state.savedAt}`);

      return true;
    } catch (error) {
      console.error(`Failed to load OCSP responder state: ${error.message}`);
      return false;
    }
  }

  /**
   * Format name for display
   */
  formatName(name) {
    return name.attributes
      .map((attr) => `${attr.shortName || attr.name}=${attr.value}`)
      .join(", ");
  }

  /**
   * Create HTTP server for OCSP responses
   */
  createHTTPServer(port = null) {
    const http = require("http");
    const url = require("url");

    const serverPort = port || this.config.port;

    const server = http.createServer((req, res) => {
      const parsedUrl = url.parse(req.url, true);

      // Handle OCSP requests
      if (req.method === "POST" && parsedUrl.pathname === "/ocsp") {
        let body = [];

        req
          .on("data", (chunk) => {
            body.push(chunk);
          })
          .on("end", () => {
            const requestData = Buffer.concat(body);

            // Process OCSP request
            const result = this.processRequest(requestData);

            if (result.success) {
              res.writeHead(200, {
                "Content-Type": "application/ocsp-response",
                "Content-Length": result.der.length,
              });
              res.end(result.der);

              console.log(
                `🌐 OCSP response sent for request ${result.requestId}`
              );
            } else {
              res.writeHead(400, { "Content-Type": "text/plain" });
              res.end(`OCSP Error: ${result.error}`);
            }
          });
      } else if (req.method === "GET" && parsedUrl.pathname === "/status") {
        // Status page
        const stats = this.getStatistics();

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(stats, null, 2));
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not Found");
      }
    });

    server.listen(serverPort, () => {
      console.log(
        `🌐 OCSP Responder HTTP server listening on port ${serverPort}`
      );
      console.log(`   Endpoints:`);
      console.log(`   POST /ocsp    - Process OCSP requests`);
      console.log(`   GET  /status  - Get responder status`);
    });

    return server;
  }

  /**
   * Generate OCSP request for testing
   */
  generateTestRequest(cert, issuerCert) {
    const certId = forge.ocsp.createCertID(cert, issuerCert);
    const request = forge.ocsp.createRequest([certId]);

    return {
      request: request,
      der: forge.ocsp.encodeRequest(request),
    };
  }

  /**
   * Decode and display OCSP response
   */
  decodeResponse(responseDer) {
    try {
      const response = forge.ocsp.decodeResponse(responseDer);

      const decoded = {
        responseStatus: response.responseStatus,
        responseType: response.responseType,
        producedAt: response.producedAt,
        responses: [],
      };

      if (response.responses) {
        response.responses.forEach((resp) => {
          decoded.responses.push({
            certID: {
              serialNumber: resp.certID.serialNumber,
              issuerNameHash: resp.certID.issuerNameHash,
              issuerKeyHash: resp.certID.issuerKeyHash,
            },
            status: resp.status,
            revocationTime: resp.revocationTime,
            revocationReason: resp.revocationReason,
            thisUpdate: resp.thisUpdate,
            nextUpdate: resp.nextUpdate,
          });
        });
      }

      return decoded;
    } catch (error) {
      return {
        error: `Failed to decode OCSP response: ${error.message}`,
      };
    }
  }
}

module.exports = OCSPResponder;
