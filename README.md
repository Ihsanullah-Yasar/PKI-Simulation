# PKI Simulation Toolkit

A complete Public Key Infrastructure (PKI) simulation system for educational demonstrations, testing, and learning PKI concepts.

## 📋 Table of Contents

- [Installation](#installation)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## 🚀 Installation

### Prerequisites

- **Node.js 16.x or higher**
- **npm 7.x or higher**
- Basic understanding of PKI concepts (recommended)

### Setup Instructions

1. **Clone the repository:**

```bash
git clone https://github.com/yourusername/pki-simulation.git
cd pki-simulation
Install dependencies:

bash
npm install
Create required directories:

bash
mkdir -p certs keys crl logs
📁 Project Structure
text
pki-simulation/
├── src/
│   ├── ca/
│   │   ├── RootCA.js
│   │   ├── IntermediateCA.js
│   │   └── CertificateAuthority.js
│   ├── certificates/
│   │   ├── X509Certificate.js
│   │   ├── CSRGenerator.js
│   │   └── CertificateBuilder.js
│   ├── crypto/
│   │   ├── KeyGenerator.js
│   │   ├── Signer.js
│   │   └── Encryption.js
│   ├── validation/
│   │   ├── CertificateValidator.js
│   │   ├── OCSPResponder.js
│   │   └── CRLManager.js
│   └── demo/
│       ├── setup-basic-pki.js
│       ├── https-flow.js
│       ├── code-signing.js
│       └── email-encryption.js
├── certs/          # Generated certificates
├── keys/           # Private keys
├── crl/            # Certificate Revocation Lists
├── tests/          # Test files
├── package.json
├── README.md
└── .gitignore
⚡ Quick Start
Initialize a basic PKI hierarchy:

bash
node src/demo/setup-basic-pki.js
Generate a root CA certificate:

javascript
const { RootCA } = require('./src/ca/RootCA');
const rootCA = new RootCA({
  commonName: 'My Root CA',
  organization: 'Test Company',
  country: 'US'
});
rootCA.generate();
Create an intermediate CA:

javascript
const { IntermediateCA } = require('./src/ca/IntermediateCA');
const intermediateCA = new IntermediateCA(rootCA, {
  commonName: 'My Intermediate CA'
});
intermediateCA.generate();
📚 Usage Examples
Generating a Server Certificate
javascript
const { CSRGenerator } = require('./src/certificates/CSRGenerator');
const csr = new CSRGenerator({
  commonName: 'example.com',
  altNames: ['www.example.com', '*.example.com']
});

const serverCert = intermediateCA.issueCertificate(csr, {
  keyUsage: ['digitalSignature', 'keyEncipherment'],
  extendedKeyUsage: ['serverAuth'],
  validityDays: 365
});
Validating Certificate Chain
javascript
const { CertificateValidator } = require('./src/validation/CertificateValidator');
const validator = new CertificateValidator(rootCA.certificate);
const isValid = validator.validateChain([intermediateCA.certificate, serverCert]);
console.log('Certificate valid:', isValid);
Creating CRL
javascript
const { CRLManager } = require('./src/validation/CRLManager');
const crlManager = new CRLManager(rootCA);
crlManager.revokeCertificate(serverCert.serialNumber);
crlManager.publishCRL();
🔧 API Reference
RootCA Class
javascript
new RootCA(config)
.generate()
.saveToFiles(certPath, keyPath)
.loadFromFiles(certPath, keyPath)
IntermediateCA Class
javascript
new IntermediateCA(parentCA, config)
.generate()
.issueCertificate(csr, options)
X509Certificate Class
javascript
new X509Certificate(pemString)
.getSubject()
.getIssuer()
.getSerialNumber()
.getValidity()
.verifySignature(parentCert)
🧪 Testing
Run the test suite:

bash
npm test

# Run with coverage
npm run test:coverage

# Run specific tests
npm run test:ca
npm run test:certificates
npm run test:validation
⚠️ Security Notes
IMPORTANT: This is simulation software for educational purposes only.

NOT FOR PRODUCTION USE - This toolkit lacks essential security features required for real-world PKI.

Keys are stored unencrypted - Private keys are saved in plain text for demonstration.

No hardware security - No HSM or secure element support.

Limited algorithm support - Uses basic cryptographic algorithms.

Educational focus - Simplified for learning, not security.

🔍 Troubleshooting
Common Issues
"Error: digital envelope routines::unsupported"

bash
export NODE_OPTIONS="--openssl-legacy-provider"
"Cannot find module"

bash
rm -rf node_modules package-lock.json
npm install
Certificate validation fails

Check certificate expiration dates

Verify certificate chains are complete

Ensure CRLs are not expired

Key generation errors

Check system entropy: cat /proc/sys/kernel/random/entropy_avail

Try smaller key sizes (2048 instead of 4096)

📄 License
MIT License - See LICENSE file for details.

🤝 Contributing
Fork the repository

Create a feature branch

Make your changes

Add tests

Submit a pull request

📚 Resources
X.509 Certificate Specification

PKI Basics Tutorial

Node.js Crypto Documentation
```
