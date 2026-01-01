# PKI Simulation Toolkit

A complete Public Key Infrastructure (PKI) simulation system built in Node.js for educational demonstrations, testing, and learning PKI concepts. This toolkit provides a fully functional PKI environment with certificate authorities, certificate management, validation, revocation, and real-world use case demonstrations.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Running the Server](#running-the-server)
- [API Endpoints](#api-endpoints)
- [Usage Examples](#usage-examples)
- [Core Components](#core-components)
- [Demo Applications](#demo-applications)
- [Certificate Types](#certificate-types)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This PKI Simulation Toolkit provides a complete implementation of Public Key Infrastructure concepts including:

- **Certificate Authority (CA) Hierarchy**: Root CA and Intermediate CA
- **Certificate Management**: Generation, signing, validation, and revocation
- **Certificate Signing Requests (CSR)**: Generate and process CSRs
- **Certificate Revocation Lists (CRL)**: Manage revoked certificates
- **OCSP Responder**: Online Certificate Status Protocol implementation
- **Real-world Demos**: HTTPS, Code Signing, and Email Encryption

## ✨ Features

### Core PKI Features

- ✅ **Root Certificate Authority**: Self-signed root CA with configurable validity
- ✅ **Intermediate Certificate Authority**: Intermediate CA signed by root CA
- ✅ **End-Entity Certificates**: Server, client, email, and code signing certificates
- ✅ **Certificate Chain Validation**: Complete chain validation from leaf to root
- ✅ **Certificate Revocation**: CRL-based certificate revocation
- ✅ **OCSP Support**: Online Certificate Status Protocol responder
- ✅ **CSR Generation**: Certificate Signing Request creation and processing
- ✅ **Multiple Key Algorithms**: RSA (2048, 3072, 4096 bits), ECDSA, Ed25519
- ✅ **X.509 Certificate Support**: Full X.509 v3 certificate implementation

### Demo Applications

- 🔐 **HTTPS Demo**: Live HTTPS server with certificate chain demonstration
- ✍️ **Code Signing Demo**: Digital signature creation and verification
- 📧 **Email Encryption Demo**: Email encryption and signing with S/MIME-like functionality

### API Server

- 🌐 **RESTful API**: Complete REST API for PKI operations
- 📊 **Statistics & Monitoring**: System statistics and certificate tracking
- 🔍 **Certificate Inspection**: Detailed certificate information and validation

## 🚀 Installation

### Prerequisites

- **Node.js**: Version 16.x or higher
- **npm**: Version 7.x or higher
- **Operating System**: Windows, macOS, or Linux

### Setup Instructions

1. **Clone the repository:**
```bash
git clone https://github.com/Ihsanullah-Yasar/PKI-Simulation.git
cd PKI-Simulation
```

2. **Install dependencies:**
```bash
npm install
```

3. **Create required directories:**
```bash
# Windows
mkdir certs keys crl

# Linux/macOS
mkdir -p certs keys crl
```

The directories will be automatically created when you initialize the PKI.

## 📁 Project Structure

```
PKI-Simulation/
├── src/
│   ├── ca/
│   │   ├── RootCA.js              # Root Certificate Authority
│   │   ├── IntermediateCA.js       # Intermediate Certificate Authority
│   │   └── CertificateAuthority.js # Main CA management class
│   ├── certificates/
│   │   ├── X509Certificate.js     # X.509 certificate creation and management
│   │   ├── CSRGenerator.js        # Certificate Signing Request generator
│   │   └── CertificateChain.js    # Certificate chain validation
│   ├── crypto/
│   │   ├── KeyPairGenerator.js    # RSA, ECDSA, Ed25519 key generation
│   │   ├── DigitalSignature.js    # Digital signature creation/verification
│   │   └── Encryption.js          # Encryption/decryption utilities
│   ├── validation/
│   │   ├── CertificateValidator.js # Certificate validation engine
│   │   ├── CRLManager.js          # Certificate Revocation List manager
│   │   └── OCSPResponder.js       # OCSP responder implementation
│   ├── demo/
│   │   ├── HTTPSDemo.js           # HTTPS server demo
│   │   ├── CodeSigningDemo.js     # Code signing demonstration
│   │   └── EmailEncryptionDemo.js # Email encryption demo
│   └── server.js                  # Main API server
├── certs/                          # Generated certificates (auto-created)
│   ├── root/                       # Root CA certificates
│   ├── intermediate/               # Intermediate CA certificates
│   ├── server/                     # Server certificates
│   ├── client/                     # Client certificates
│   ├── email/                      # Email certificates
│   ├── code/                       # Code signing certificates
│   └── crl/                        # Certificate Revocation Lists
├── keys/                           # Private keys (auto-created)
├── crl/                            # CRL files (auto-created)
├── package.json                    # Project dependencies
├── start.bat                       # Windows quick start script
└── README.md                       # This file
```

## ⚡ Quick Start

### Windows Users

Simply run the provided batch file:
```bash
start.bat
```

This will:
1. Install dependencies
2. Initialize the PKI hierarchy
3. Start the API server
4. Launch the HTTPS demo server

### Manual Start

1. **Initialize PKI:**
```bash
npm start
# Then visit http://localhost:3000 and use POST /api/pki/initialize
```

Or programmatically:
```javascript
const { CertificateAuthority } = require('./src/ca/CertificateAuthority');

const ca = new CertificateAuthority({
  basePath: './certs',
  defaultOrganization: 'My Organization'
});

await ca.initializePKI({
  organization: 'My Organization',
  country: 'US'
});
```

2. **Start the API Server:**
```bash
npm start
# Server runs on http://localhost:3000
```

3. **Start HTTPS Demo:**
Visit `http://localhost:3000/api/https/start` or use the API to start the HTTPS demo server.

## 🖥️ Running the Server

### Start API Server

```bash
npm start
```

The server will start on port 3000 (configurable via `PORT` environment variable).

### Server Endpoints

Once started, the server provides:
- **API Server**: `http://localhost:3000`
- **HTTPS Demo**: `https://localhost:8443` (after initialization)
- **HTTP Redirect**: `http://localhost:8080` (redirects to HTTPS)

## 📡 API Endpoints

### Root Endpoint

**GET /** - API Documentation
- Returns list of all available endpoints

### PKI Management Endpoints

#### Initialize PKI
**POST /api/pki/initialize**
- Initializes complete PKI hierarchy (Root CA, Intermediate CA, default server certificate)
- **Body:**
```json
{
  "organization": "My Organization",
  "country": "US"
}
```
- **Response:**
```json
{
  "success": true,
  "message": "PKI hierarchy initialized successfully",
  "certificates": {
    "root": "./certs/root/root-ca.crt",
    "intermediate": "./certs/intermediate/intermediate-ca.crt",
    "server": "./certs/server/localhost.crt",
    "chain": "./certs/server/localhost-chain.pem",
    "crl": "./certs/root/root-ca.crl"
  }
}
```

#### Get PKI Status
**GET /api/pki/status**
- Returns current PKI status and statistics
- **Response:**
```json
{
  "success": true,
  "pki": {
    "initialized": true,
    "statistics": {
      "total": 3,
      "byType": {
        "root": 1,
        "intermediate": 1,
        "server": 1
      },
      "valid": 3,
      "expired": 0,
      "revoked": 0
    }
  }
}
```

#### Display PKI Hierarchy
**GET /api/pki/hierarchy**
- Displays complete PKI hierarchy structure
- **Response:**
```json
{
  "success": true,
  "hierarchy": {
    "rootCA": {
      "subject": "CN=My Organization Root CA",
      "issuer": "CN=My Organization Root CA"
    },
    "intermediateCA": {
      "subject": "CN=My Organization Intermediate CA",
      "issuer": "CN=My Organization Root CA"
    },
    "certificates": [...]
  }
}
```

#### Issue Certificate
**POST /api/pki/issue**
- Issues a new certificate from a CSR
- **Body:**
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "type": "server",
  "options": {
    "validityDays": 365,
    "san": ["DNS:example.com", "DNS:www.example.com"]
  }
}
```
- **Response:**
```json
{
  "success": true,
  "message": "Certificate issued successfully",
  "certificate": {
    "serialNumber": "0x...",
    "filePath": "./certs/server/example.com_...crt",
    "subject": "CN=example.com"
  }
}
```

#### Validate Certificate
**POST /api/pki/validate**
- Validates a certificate and its chain
- **Body:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----..."
}
```
- **Response:**
```json
{
  "success": true,
  "validation": {
    "chainValidation": {
      "valid": true,
      "chainLength": 3
    },
    "revoked": false,
    "valid": true,
    "certificate": {...}
  }
}
```

### HTTPS Demo Endpoints

#### Start HTTPS Demo
**GET /api/https/start**
- Starts HTTPS demo server on port 8443
- **Response:**
```json
{
  "success": true,
  "message": "HTTPS demo servers started",
  "info": {
    "https": {
      "port": 8443,
      "protocol": "HTTPS"
    },
    "http": {
      "port": 8080,
      "protocol": "HTTP"
    }
  }
}
```

#### Stop HTTPS Demo
**GET /api/https/stop**
- Stops the HTTPS demo servers

#### Get HTTPS Status
**GET /api/https/status**
- Returns HTTPS demo server status

### Code Signing Endpoints

#### Get Code Signing Status
**GET /api/codesign/status**
- Returns code signing demo status

#### Sign File
**POST /api/codesign/sign**
- Signs a file with code signing certificate
- **Body:**
```json
{
  "filePath": "./path/to/file.js",
  "options": {}
}
```

#### Verify File Signature
**POST /api/codesign/verify**
- Verifies file signature
- **Body:**
```json
{
  "filePath": "./path/to/file.js",
  "signaturePath": "./signatures/signed/file.js.sig.json"
}
```

#### Run Code Signing Demo
**GET /api/codesign/demo**
- Runs complete code signing demonstration

### Email Encryption Endpoints

#### Get Email Encryption Status
**GET /api/email/status**
- Returns email encryption demo status

#### Encrypt Email
**POST /api/email/encrypt**
- Encrypts email for recipient
- **Body:**
```json
{
  "recipient": "alice@example.com",
  "message": "Secret message",
  "options": {
    "sender": "bob@example.com",
    "subject": "Confidential"
  }
}
```

#### Decrypt Email
**POST /api/email/decrypt**
- Decrypts encrypted email
- **Body:**
```json
{
  "filePath": "./emails/encrypted/encrypted_alice_...json",
  "privateKey": "-----BEGIN PRIVATE KEY-----...",
  "passphrase": ""
}
```

#### Sign Email
**POST /api/email/sign**
- Signs email message
- **Body:**
```json
{
  "sender": "alice@example.com",
  "message": "Message content",
  "options": {
    "recipient": "bob@example.com",
    "subject": "Signed Message"
  }
}
```

#### Run Email Encryption Demo
**GET /api/email/demo**
- Runs complete email encryption demonstration

### System Endpoints

#### System Statistics
**GET /api/system/stats**
- Returns comprehensive system statistics

#### Cleanup Demo Files
**GET /api/system/cleanup**
- Cleans up demo directories (emails, signatures, etc.)

## 💻 Usage Examples

### Programmatic Usage

#### Initialize PKI Hierarchy

```javascript
const { CertificateAuthority } = require('./src/ca/CertificateAuthority');

const ca = new CertificateAuthority({
  basePath: './certs',
  defaultOrganization: 'My Company',
  defaultCountry: 'US'
});

// Initialize complete PKI
const result = await ca.initializePKI({
  organization: 'My Company',
  country: 'US',
  state: 'California',
  locality: 'San Francisco'
});

console.log('PKI initialized:', result.certificates);
```

#### Generate Key Pair and CSR

```javascript
const KeyPairGenerator = require('./src/crypto/KeyPairGenerator');
const CSRGenerator = require('./src/certificates/CSRGenerator');

// Generate key pair
const keyGen = new KeyPairGenerator();
const keyPair = keyGen.generateRSAKeyPair(2048);

// Generate CSR
const csrGen = new CSRGenerator();
const csr = csrGen.generateCSR(keyPair, '/CN=example.com', {
  extensions: {
    subjectAltName: ['DNS:example.com', 'DNS:www.example.com'],
    keyUsage: ['digitalSignature', 'keyEncipherment']
  }
});

console.log('CSR:', csr.pem);
```

#### Issue Server Certificate

```javascript
const ca = new CertificateAuthority();

// Issue certificate from CSR
const result = ca.issueCertificate(csr.pem, 'server', {
  validityDays: 365,
  san: ['DNS:example.com', 'DNS:www.example.com']
});

console.log('Certificate issued:', result.serialNumber);
```

#### Validate Certificate

```javascript
const { CertificateValidator } = require('./src/validation/CertificateValidator');

const validator = new CertificateValidator();
const certPem = fs.readFileSync('./certs/server/example.com.crt', 'utf8');

const result = validator.validateCertificate(certPem, {
  requiredExtendedKeyUsage: ['serverAuth'],
  minKeySize: 2048
});

console.log('Valid:', result.valid);
console.log('Errors:', result.errors);
```

#### Revoke Certificate

```javascript
const ca = new CertificateAuthority();

// Revoke certificate
const revocation = await ca.revokeCertificate(
  '0x1234567890abcdef...',
  'keyCompromise'
);

console.log('Revoked:', revocation);
```

### Command Line Usage (via API)

#### Using cURL

```bash
# Initialize PKI
curl -X POST http://localhost:3000/api/pki/initialize \
  -H "Content-Type: application/json" \
  -d '{"organization": "My Org", "country": "US"}'

# Get PKI status
curl http://localhost:3000/api/pki/status

# Start HTTPS demo
curl http://localhost:3000/api/https/start

# Issue certificate
curl -X POST http://localhost:3000/api/pki/issue \
  -H "Content-Type: application/json" \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "type": "server"
  }'
```

## 🔧 Core Components

### Certificate Authority Classes

#### RootCA
- Creates self-signed root certificate authority
- Configurable validity period (default: 10 years)
- Supports key sizes: 2048, 3072, 4096 bits
- Methods: `create()`, `load()`, `validate()`, `export()`, `signCSR()`

#### IntermediateCA
- Creates intermediate CA signed by root CA
- Configurable path length constraints
- Methods: `create()`, `load()`, `validate()`, `issueCertificate()`, `signCSR()`

#### CertificateAuthority
- Main CA management class
- Handles complete PKI hierarchy
- Certificate lifecycle management
- CRL integration
- Methods: `initializePKI()`, `issueCertificate()`, `revokeCertificate()`, `validateCertificate()`, `listCertificates()`

### Certificate Classes

#### X509Certificate
- X.509 v3 certificate creation
- Supports Root CA, Intermediate CA, and End-Entity certificates
- Extension management (keyUsage, extendedKeyUsage, subjectAltName, etc.)
- Certificate inspection and validation

#### CSRGenerator
- Certificate Signing Request generation
- Subject Alternative Names support
- Extension request handling
- CSR validation

#### CertificateChain
- Certificate chain building and validation
- Chain verification against trust store
- Missing certificate detection
- Chain sorting

### Crypto Classes

#### KeyPairGenerator
- RSA key generation (2048, 3072, 4096 bits)
- ECDSA key generation (P-256, P-384, P-521)
- Ed25519 key generation
- Key pair export/import

#### DigitalSignature
- Digital signature creation (RSA-SHA256, RSA-SHA512, ECDSA-SHA256)
- Signature verification
- PKCS#7 signature support
- Detached and attached signatures

#### Encryption
- Symmetric encryption (AES-256-GCM, AES-256-CBC)
- Asymmetric encryption (RSA-OAEP)
- Hybrid encryption (symmetric + asymmetric)
- Hash calculation

### Validation Classes

#### CertificateValidator
- Comprehensive certificate validation
- Chain validation
- CRL checking
- Purpose-specific validation (webserver, client, codesigning, email, ca)
- Expiration status checking

#### CRLManager
- Certificate Revocation List creation and management
- Certificate revocation tracking
- CRL signing and validation
- Revocation reason codes
- CRL export (PEM, DER, JSON)

#### OCSPResponder
- OCSP request processing
- Certificate status responses (good, revoked, unknown)
- Response caching
- HTTP server for OCSP
- State persistence

## 🎬 Demo Applications

### HTTPS Demo

The HTTPS demo provides a live HTTPS server demonstrating:
- TLS/SSL certificate usage
- Certificate chain validation
- Client certificate authentication (optional)
- Secure connection establishment

**Access:**
- HTTPS: `https://localhost:8443`
- HTTP Redirect: `http://localhost:8080`

**Features:**
- Interactive certificate inspection
- Chain validation display
- TLS information display
- Secure area demonstration

### Code Signing Demo

Demonstrates digital code signing:
- File signing with code signing certificate
- Signature verification
- Tamper detection
- Certificate chain validation

**Usage:**
```javascript
const CodeSigningDemo = require('./src/demo/CodeSigningDemo');

const demo = new CodeSigningDemo({ basePath: './certs' });

// Sign a file
await demo.signFile('./app.js');

// Verify signature
await demo.verifySignature('./app.js');

// Run complete demo
await demo.runDemo();
```

### Email Encryption Demo

Demonstrates email encryption and signing:
- Email encryption using recipient's public key
- Email signing with sender's private key
- Signature verification
- Certificate-based trust

**Usage:**
```javascript
const EmailEncryptionDemo = require('./src/demo/EmailEncryptionDemo');

const demo = new EmailEncryptionDemo({ basePath: './certs' });

// Encrypt email
await demo.encryptEmail('alice@example.com', 'Secret message', {
  sender: 'bob@example.com',
  subject: 'Confidential'
});

// Decrypt email
await demo.decryptEmail('./emails/encrypted/...json', privateKey);

// Run complete demo
await demo.runDemo();
```

## 📜 Certificate Types

### Server Certificates
- **Purpose**: HTTPS/TLS server authentication
- **Key Usage**: digitalSignature, keyEncipherment
- **Extended Key Usage**: serverAuth, clientAuth
- **Validity**: Typically 1 year
- **SAN Support**: DNS names, IP addresses

### Client Certificates
- **Purpose**: Client authentication
- **Key Usage**: digitalSignature
- **Extended Key Usage**: clientAuth
- **Validity**: Typically 1 year

### Email Certificates
- **Purpose**: Email encryption and signing
- **Key Usage**: digitalSignature, keyEncipherment
- **Extended Key Usage**: emailProtection
- **Validity**: Typically 1 year
- **Email in Subject**: emailAddress attribute

### Code Signing Certificates
- **Purpose**: Software code signing
- **Key Usage**: digitalSignature
- **Extended Key Usage**: codeSigning
- **Validity**: Typically 3 years
- **Organization Required**: Usually requires organization name

## ⚠️ Security Notes

### IMPORTANT WARNINGS

**🚨 THIS IS SIMULATION SOFTWARE FOR EDUCATIONAL PURPOSES ONLY**

**NOT FOR PRODUCTION USE** - This toolkit lacks essential security features required for real-world PKI:

1. **Unencrypted Key Storage**: Private keys are stored in plain text for demonstration purposes
2. **No Hardware Security Module (HSM)**: No HSM or secure element support
3. **Limited Algorithm Support**: Uses basic cryptographic algorithms
4. **No Key Escrow**: No key recovery mechanisms
5. **Simplified Validation**: Some validation checks are simplified for educational purposes
6. **No Certificate Policy**: No Certificate Policy or Certification Practice Statement
7. **No Audit Logging**: Limited audit trail capabilities
8. **No Network Security**: No protection against network-based attacks

### Best Practices for Educational Use

- Use only in isolated, non-production environments
- Never use generated certificates for real applications
- Do not expose private keys
- Regularly rotate certificates in test environments
- Understand the security implications before using in any real scenario

## 🔍 Troubleshooting

### Common Issues

#### "Error: digital envelope routines::unsupported"
**Solution:**
```bash
# Set Node.js option
export NODE_OPTIONS="--openssl-legacy-provider"

# Or on Windows
set NODE_OPTIONS=--openssl-legacy-provider
```

#### "Cannot find module"
**Solution:**
```bash
rm -rf node_modules package-lock.json
npm install
```

#### Certificate validation fails
**Check:**
- Certificate expiration dates
- Certificate chains are complete
- CRLs are not expired
- Root CA is trusted

#### Key generation errors
**Check:**
- System entropy: `cat /proc/sys/kernel/random/entropy_avail` (Linux)
- Try smaller key sizes (2048 instead of 4096)
- Ensure sufficient disk space

#### HTTPS server shows security warning
**This is expected!** You're using a custom Certificate Authority. To fix:
1. Export the Root CA certificate: `./certs/root/root-ca.crt`
2. Import it into your browser's trusted root store
3. Restart your browser

#### Port already in use
**Solution:**
```bash
# Change port via environment variable
PORT=3001 npm start

# Or modify server.js
const PORT = process.env.PORT || 3001;
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

- Follow existing code style
- Add comments for complex logic
- Update documentation for new features
- Test thoroughly before submitting

## 📄 License

MIT License - See LICENSE file for details.

## 📚 Resources

- [X.509 Certificate Specification (RFC 5280)](https://tools.ietf.org/html/rfc5280)
- [PKI Basics Tutorial](https://en.wikipedia.org/wiki/Public_key_infrastructure)
- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

## 🙏 Acknowledgments

- Built with [node-forge](https://github.com/digitalbazaar/forge) for cryptographic operations
- Built with [Express.js](https://expressjs.com/) for the API server
- Inspired by real-world PKI implementations

## 📞 Support

For issues, questions, or contributions:
- **GitHub Issues**: [Create an issue](https://github.com/Ihsanullah-Yasar/PKI-Simulation/issues)
- **Repository**: [PKI-Simulation](https://github.com/Ihsanullah-Yasar/PKI-Simulation)

---

**Remember**: This is educational software. Always use production-grade PKI solutions for real-world applications!
