const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

class KeyPairGenerator {
  constructor() {
    this.supportedAlgorithms = {
      RSA: ["2048", "3072", "4096"],
      ECDSA: ["P-256", "P-384", "P-521"],
      Ed25519: ["Ed25519"],
    };
  }

  /**
   * Generate RSA key pair
   */
  generateRSAKeyPair(keySize = 2048, passphrase = "") {
    if (![2048, 3072, 4096].includes(keySize)) {
      throw new Error("Invalid key size. Use 2048, 3072, or 4096");
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: keySize,
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: passphrase ? "aes-256-cbc" : undefined,
        passphrase: passphrase || undefined,
      },
    });

    return {
      algorithm: "RSA",
      keySize: keySize,
      publicKey: publicKey,
      privateKey: privateKey,
      passphrase: passphrase,
    };
  }

  /**
   * Generate ECDSA key pair
   */
  generateECDSAKeyPair(curve = "P-256", passphrase = "") {
    const curves = {
      "P-256": "prime256v1",
      "P-384": "secp384r1",
      "P-521": "secp521r1",
    };

    if (!curves[curve]) {
      throw new Error(
        `Unsupported curve. Use: ${Object.keys(curves).join(", ")}`
      );
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: curves[curve],
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: passphrase ? "aes-256-cbc" : undefined,
        passphrase: passphrase || undefined,
      },
    });

    return {
      algorithm: "ECDSA",
      curve: curve,
      publicKey: publicKey,
      privateKey: privateKey,
      passphrase: passphrase,
    };
  }

  /**
   * Generate Ed25519 key pair (for modern certificates)
   */
  generateEd25519KeyPair(passphrase = "") {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: passphrase ? "aes-256-cbc" : undefined,
        passphrase: passphrase || undefined,
      },
    });

    return {
      algorithm: "Ed25519",
      publicKey: publicKey,
      privateKey: privateKey,
      passphrase: passphrase,
    };
  }

  /**
   * Save key pair to files
   */
  saveKeyPair(keyPair, name, outputDir = "./keys") {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const baseName = `${name}_${timestamp}`;

    // Save public key
    const pubKeyPath = path.join(outputDir, `${baseName}_public.pem`);
    fs.writeFileSync(pubKeyPath, keyPair.publicKey);

    // Save private key
    const privKeyPath = path.join(outputDir, `${baseName}_private.pem`);
    fs.writeFileSync(privKeyPath, keyPair.privateKey);

    // Save metadata
    const metadata = {
      ...keyPair,
      publicKey: undefined,
      privateKey: undefined,
    };
    const metaPath = path.join(outputDir, `${baseName}_metadata.json`);
    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

    return {
      publicKeyPath: pubKeyPath,
      privateKeyPath: privKeyPath,
      metadataPath: metaPath,
    };
  }

  /**
   * Load key pair from files
   */
  loadKeyPair(publicKeyPath, privateKeyPath) {
    if (!fs.existsSync(publicKeyPath) || !fs.existsSync(privateKeyPath)) {
      throw new Error("Key files not found");
    }

    const publicKey = fs.readFileSync(publicKeyPath, "utf8");
    const privateKey = fs.readFileSync(privateKeyPath, "utf8");

    return {
      publicKey: publicKey,
      privateKey: privateKey,
    };
  }

  /**
   * Get key information
   */
  getKeyInfo(keyPem) {
    try {
      const key = crypto.createPublicKey(keyPem);
      return {
        type: key.type,
        asymmetricKeyType: key.asymmetricKeyType,
        asymmetricKeyDetails: key.asymmetricKeyDetails,
      };
    } catch (error) {
      try {
        const key = crypto.createPrivateKey(keyPem);
        return {
          type: key.type,
          asymmetricKeyType: key.asymmetricKeyType,
          asymmetricKeyDetails: key.asymmetricKeyDetails,
        };
      } catch (err) {
        throw new Error("Invalid key format");
      }
    }
  }
}

module.exports = KeyPairGenerator;
