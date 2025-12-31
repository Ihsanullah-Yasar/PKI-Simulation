const crypto = require("crypto");

class Encryption {
  constructor() {
    this.supportedAlgorithms = {
      "AES-256-GCM": "aes-256-gcm",
      "AES-256-CBC": "aes-256-cbc",
      "RSA-OAEP": "RSA-OAEP",
    };
  }

  /**
   * Generate random initialization vector
   */
  generateIV(length = 16) {
    return crypto.randomBytes(length);
  }

  /**
   * Generate random symmetric key
   */
  generateSymmetricKey(algorithm = "AES-256-GCM") {
    let keyLength;

    switch (algorithm) {
      case "AES-256-GCM":
      case "AES-256-CBC":
        keyLength = 32; // 256 bits
        break;
      case "AES-128-GCM":
        keyLength = 16; // 128 bits
        break;
      default:
        keyLength = 32;
    }

    return {
      key: crypto.randomBytes(keyLength),
      algorithm: algorithm,
      created: new Date().toISOString(),
    };
  }

  /**
   * Encrypt with symmetric key
   */
  encryptSymmetric(data, key, algorithm = "AES-256-GCM") {
    const iv = this.generateIV();
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    let encrypted = cipher.update(
      typeof data === "string" ? data : JSON.stringify(data),
      "utf8",
      "base64"
    );
    encrypted += cipher.final("base64");

    const authTag = algorithm.includes("GCM") ? cipher.getAuthTag() : null;

    return {
      algorithm: algorithm,
      encryptedData: encrypted,
      iv: iv.toString("base64"),
      authTag: authTag ? authTag.toString("base64") : null,
      keyId: crypto
        .createHash("sha256")
        .update(key)
        .digest("hex")
        .substring(0, 16),
    };
  }

  /**
   * Decrypt with symmetric key
   */
  decryptSymmetric(
    encryptedData,
    key,
    iv,
    authTag = null,
    algorithm = "AES-256-GCM"
  ) {
    const decipher = crypto.createDecipheriv(
      algorithm,
      key,
      Buffer.from(iv, "base64")
    );

    if (authTag && algorithm.includes("GCM")) {
      decipher.setAuthTag(Buffer.from(authTag, "base64"));
    }

    let decrypted = decipher.update(encryptedData, "base64", "utf8");
    decrypted += decipher.final("utf8");

    // Try to parse as JSON, otherwise return as string
    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  }

  /**
   * Encrypt with public key (asymmetric)
   */
  encryptAsymmetric(data, publicKey, algorithm = "RSA-OAEP") {
    const buffer =
      typeof data === "string"
        ? Buffer.from(data, "utf8")
        : Buffer.from(JSON.stringify(data));

    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      buffer
    );

    return {
      algorithm: algorithm,
      encryptedData: encrypted.toString("base64"),
      keyAlgorithm: "RSA",
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Decrypt with private key (asymmetric)
   */
  decryptAsymmetric(encryptedData, privateKey, passphrase = "") {
    const buffer = Buffer.from(encryptedData, "base64");

    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
        passphrase: passphrase || undefined,
      },
      buffer
    );

    // Try to parse as JSON, otherwise return as string
    try {
      return JSON.parse(decrypted.toString("utf8"));
    } catch {
      return decrypted.toString("utf8");
    }
  }

  /**
   * Hybrid encryption: Use symmetric key for data, RSA for key
   */
  hybridEncrypt(data, recipientPublicKey) {
    // Generate symmetric key
    const symKey = this.generateSymmetricKey("AES-256-GCM");

    // Encrypt data with symmetric key
    const encryptedData = this.encryptSymmetric(
      data,
      symKey.key,
      symKey.algorithm
    );

    // Encrypt symmetric key with recipient's public key
    const encryptedKey = this.encryptAsymmetric(
      symKey.key.toString("base64"),
      recipientPublicKey
    );

    return {
      version: "1.0",
      algorithm: "HYBRID",
      symmetricAlgorithm: symKey.algorithm,
      asymmetricAlgorithm: encryptedKey.algorithm,
      encryptedKey: encryptedKey.encryptedData,
      encryptedData: encryptedData.encryptedData,
      iv: encryptedData.iv,
      authTag: encryptedData.authTag,
      keyId: encryptedData.keyId,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Hybrid decryption
   */
  hybridDecrypt(encryptedPackage, recipientPrivateKey, passphrase = "") {
    // Decrypt symmetric key
    const symKeyBase64 = this.decryptAsymmetric(
      encryptedPackage.encryptedKey,
      recipientPrivateKey,
      passphrase
    );

    const symKey = Buffer.from(symKeyBase64, "base64");

    // Decrypt data with symmetric key
    return this.decryptSymmetric(
      encryptedPackage.encryptedData,
      symKey,
      encryptedPackage.iv,
      encryptedPackage.authTag,
      encryptedPackage.symmetricAlgorithm
    );
  }

  /**
   * Calculate hash of data
   */
  calculateHash(data, algorithm = "sha256") {
    const hash = crypto.createHash(algorithm);
    hash.update(typeof data === "string" ? data : JSON.stringify(data));

    return {
      algorithm: algorithm,
      hash: hash.digest("hex"),
      dataLength: (typeof data === "string" ? data : JSON.stringify(data))
        .length,
    };
  }
}

module.exports = Encryption;
