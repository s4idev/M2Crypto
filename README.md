# M2Crypto

[![Python](https://img.shields.io/badge/python-2.6%2B%2C%203.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-BSD--style-green.svg)](https://github.com/s4idev/M2Crypto/blob/master/LICENCE)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-0.9.8%2B-orange.svg)](https://www.openssl.org/)

**M2Crypto** is a comprehensive Python crypto and SSL toolkit that provides a Python interface to OpenSSL.

*M2 stands for "me, too!"* — providing Python developers with powerful cryptographic capabilities.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [SSL Client Example](#ssl-client-example)
  - [Encryption Example](#encryption-example)
  - [Digital Signatures Example](#digital-signatures-example)
- [Documentation](#documentation)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## Features

M2Crypto provides a comprehensive set of cryptographic and SSL/TLS capabilities:

### Cryptographic Algorithms
- **RSA** - Public key encryption and digital signatures
- **DSA** - Digital Signature Algorithm
- **DH** - Diffie-Hellman key exchange
- **EC** - Elliptic Curve cryptography (ECDH, ECDSA)
- **AES** - Advanced Encryption Standard and other symmetric ciphers
- **Message Digests** - MD5, SHA-1, SHA-2 family (SHA-256, SHA-384, SHA-512)
- **HMACs** - Hash-based Message Authentication Codes

### SSL/TLS Support
- **SSL/TLS Clients and Servers** - Full support for SSL/TLS protocols
- **Threading and Forking** - Multi-threaded and multi-process servers
- **Non-blocking I/O** - Asynchronous socket operations
- **Protocol Support** - SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2+

### High-Level Features
- **S/MIME v2** - Secure email message encryption and signing
- **X.509 Certificates** - Certificate creation, parsing, and validation
- **FTP/TLS** - Secure FTP client and server
- **HTTPS Extensions** - Enhanced httplib, urllib, and xmlrpclib
- **AuthCookies** - HMAC-based unforgeable cookies for web session management
- **ZServerSSL** - HTTPS server for Zope
- **ZSmime** - S/MIME messenger for Zope

---

## Requirements

- **Python**: 2.6, 2.7, or 3.x
- **OpenSSL**: 0.9.8 or newer (1.0.1+ recommended)
- **SWIG**: 2.0 or newer (for building from source)
- **Platform**: Linux, macOS, Windows (with appropriate build tools)

---

## Installation

### Using pip (Recommended)

```bash
pip install M2Crypto
```

### From Source

```bash
# Clone the repository
git clone https://github.com/s4idev/M2Crypto.git
cd M2Crypto

# Install dependencies
pip install setuptools

# Build and install
python setup.py build
python setup.py install
```

### Platform-Specific Notes

**Linux:**
```bash
# Install OpenSSL development headers (Debian/Ubuntu)
sudo apt-get install python-dev libssl-dev swig

# Install OpenSSL development headers (RHEL/CentOS/Fedora)
sudo yum install python-devel openssl-devel swig
```

**macOS:**
```bash
# Using Homebrew
brew install openssl swig
```

**Windows:**
- Install OpenSSL from [slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)
- Install SWIG from [swig.org](http://www.swig.org/)
- Use Visual Studio or MinGW for building

---

## Quick Start

### SSL Client Example

```python
from M2Crypto import SSL, httpslib

# Create an SSL context
ctx = SSL.Context('sslv23')

# Connect to an HTTPS server
conn = httpslib.HTTPSConnection('www.example.com', ssl_context=ctx)
conn.request('GET', '/')
response = conn.getresponse()
print(response.read())
conn.close()
```

### Encryption Example

```python
from M2Crypto import EVP

# Create a cipher for AES encryption
cipher = EVP.Cipher(alg='aes_256_cbc', key='a'*32, iv='b'*16, op=1)  # 1 = encrypt

# Encrypt data
plaintext = b'Secret message to encrypt'
ciphertext = cipher.update(plaintext)
ciphertext += cipher.final()

print("Encrypted:", ciphertext.encode('hex'))

# Decrypt data
decipher = EVP.Cipher(alg='aes_256_cbc', key='a'*32, iv='b'*16, op=0)  # 0 = decrypt
decrypted = decipher.update(ciphertext)
decrypted += decipher.final()

print("Decrypted:", decrypted)
```

### Digital Signatures Example

```python
from M2Crypto import RSA, EVP

# Generate RSA key pair
rsa = RSA.gen_key(2048, 65537)

# Create a message digest
message = b'Message to sign'
md = EVP.MessageDigest('sha256')
md.update(message)
digest = md.final()

# Sign the digest
signature = rsa.sign(digest, 'sha256')

# Verify the signature
pub_key = rsa.pub()
verified = pub_key.verify(digest, signature, 'sha256')
print("Signature valid:", verified == 1)
```

---

## Documentation

- **README**: [README](README) (this file)
- **Installation Guide**: [INSTALL](INSTALL)
- **API Examples**: See the `demo/` and `tests/` directories for comprehensive examples
- **Recommended Reading**: "Network Security with OpenSSL" by John Viega, Matt Messier, and Pravir Chandra (ISBN 059600270X)

### Example Code

The repository includes extensive examples:

- **SSL/TLS Examples**: `demo/ssl/`
- **S/MIME Examples**: `demo/smime/`
- **Medusa Integration**: `demo/medusa/`
- **Zope Integration**: `demo/Zope/`

---

## Testing

M2Crypto includes a comprehensive test suite using Python's `unittest` framework.

### Run All Tests

```bash
python setup.py test
```

### Run Specific Test Module

```bash
python setup.py test --test-suite=tests.test_ssl
```

### Run Tests Directly

```bash
cd tests
python alltests.py
```

### Test Coverage

The test suite includes tests for:
- BN (BigNum operations)
- EC (Elliptic Curve cryptography)
- EVP (Message digests, HMACs, ciphers)
- RSA, DSA, DH key operations
- S/MIME functionality
- SSL/TLS connections
- X.509 certificates
- BIO (I/O operations)
- And more...

---

## Contributing

We welcome contributions to M2Crypto! Here's how you can help:

### Reporting Issues

- **Bug Reports**: Open an issue on [GitHub Issues](https://github.com/s4idev/M2Crypto/issues)
- Include Python version, OpenSSL version, and platform details
- Provide a minimal reproducible example

### Submitting Changes

1. **Fork the Repository**
   ```bash
   git clone https://github.com/YOUR-USERNAME/M2Crypto.git
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Run Tests**
   ```bash
   python setup.py test
   ```

5. **Submit a Pull Request**
   - Describe your changes clearly
   - Reference any related issues

### Code Style

- Follow PEP 8 style guidelines for Python code
- Maintain compatibility with Python 2.6+ and 3.x
- Include docstrings for new functions and classes
- Add unit tests for new features

---

## License

M2Crypto is released under a **BSD-style license**. See [LICENCE](LICENCE) for full details.

### Copyright Notice

- Copyright (c) 1999-2004 Ng Pheng Siong
- Portions Copyright (c) 2004-2006 Open Source Applications Foundation
- Portions Copyright (c) 2005-2006 Vrije Universiteit Amsterdam
- Copyright (c) 2008-2010 Heikki Toivonen

Permission to use, copy, modify, and distribute this software and its documentation for any purpose and without fee is hereby granted under the terms described in the LICENCE file.

---

## Support

### Getting Help

- **Documentation**: Check the `demo/` and `tests/` directories for examples
- **GitHub Issues**: [Report bugs or ask questions](https://github.com/s4idev/M2Crypto/issues)
- **Mailing List**: [Chandler Project Mailing List](http://chandlerproject.org/Projects/MeTooCrypto)

### Important Security Notes

⚠️ **Caveats**:

- **Memory Management**: Possible memory leaks due to differences in Python vs. C object lifecycle. While multiple frees are caught quickly, some objects may not be properly freed.

- **Memory Clearing**: No memory locking/clearing for keys and passphrases on the Python side (Python doesn't provide these features). However, C-side (OpenSSL) memory is cleared when Python objects are deleted.

- **Production Deployment**: Read "Network Security with OpenSSL" before deploying in production environments.

### Maintainer

- **Current Maintainer**: Heikki Toivonen
- **Original Author**: Ng Pheng Siong
- **Website**: [http://chandlerproject.org/Projects/MeTooCrypto](http://chandlerproject.org/Projects/MeTooCrypto)

---

**Have fun! Your feedback is welcome.** 🎉
