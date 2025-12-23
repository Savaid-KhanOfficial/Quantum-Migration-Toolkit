# Quantum-Migration-Toolkit

**Your Complete Solution for Post-Quantum Cryptography Migration**

> Protect your data from quantum computing threats with battle-tested tools for auditing, encrypting, and securing your applications.

---

## 🛡️ Why Quantum-Safe Cryptography?

The quantum computing revolution is approaching. When large-scale quantum computers arrive, current cryptographic algorithms (RSA, ECC, DES, MD5, SHA-1) will be broken in minutes. Organizations must act now to protect their data against **"harvest now, decrypt later"** attacks.

**Quantum-Migration-Toolkit** provides enterprise-grade tools to:
- **Audit** your codebase for vulnerable cryptographic patterns
- **Encrypt** files with NIST-approved post-quantum algorithms
- **Migrate** seamlessly to quantum-safe infrastructure

---

## 📦 What's Inside?

### 🔍 `/Scanner` - The Auditor
**Quantum-safe security scanner** that detects vulnerable cryptographic patterns in your codebase.

**Features:**
- Scans C++, Python, JavaScript, Java, and more
- Detects 15+ vulnerable algorithms (RSA, MD5, DES, SHA-1, AES-128, etc.)
- Recursive directory analysis
- Zero false positives with regex-powered word boundary detection
- Detailed line-by-line vulnerability reports

**Use Cases:**
- Pre-migration security audits
- Continuous integration checks
- Compliance scanning for quantum-safe standards

```bash
cd Scanner
cmake -S . -B build
cmake --build build
./build/QuantumScanner /path/to/your/code
```

---

### 🔐 `/Locker` - The Fix
**Quantum-safe file encryption tool** powered by NIST-approved Kyber-512 and AES-256.

**Features:**
- **Kyber-512**: NIST-selected post-quantum key encapsulation mechanism
- **AES-256-CBC**: Industry-standard symmetric encryption
- **Hybrid encryption**: Combines quantum-safe key exchange with high-speed symmetric cipher
- **Key management**: Save/load public and private keys (.pub/.priv files)
- **CLI interface**: Simple commands for key generation, encryption, and decryption

**Use Cases:**
- Secure file transmission
- Long-term data archival
- Quantum-resistant backup systems

```bash
cd Locker
cmake -S . -B build -DOQS_DIR=/path/to/liboqs/install
cmake --build build

# Generate quantum-safe keypair
./build/QuantumLocker genkeys

# Encrypt a file
./build/QuantumLocker encrypt secret.txt encrypted.bin

# Decrypt a file
./build/QuantumLocker decrypt encrypted.bin decrypted.txt
```

---

## 🚀 Quick Start

### Prerequisites
- **C++17 compiler** (GCC 7+, Clang 5+, MSVC 2017+)
- **CMake 3.10+**
- **liboqs** (Open Quantum Safe library)

### Installation

1. **Install liboqs**
   ```bash
   git clone https://github.com/open-quantum-safe/liboqs.git
   cd liboqs
   cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/path/to/install
   cmake --build build
   cmake --install build
   ```

2. **Clone this repository**
   ```bash
   git clone https://github.com/Savaid-KhanOfficial/Quantum-Migration-Toolkit.git
   cd Quantum-Migration-Toolkit
   ```

3. **Build Scanner**
   ```bash
   cd Scanner
   cmake -S . -B build
   cmake --build build
   ```

4. **Build Locker**
   ```bash
   cd ../Locker
   cmake -S . -B build -DOQS_DIR=/path/to/liboqs/install
   cmake --build build
   ```

---

## 📊 Real-World Example

### Scenario: Migrating a Legacy Authentication System

**Step 1: Audit**
```bash
./Scanner/build/QuantumScanner /path/to/legacy/auth/system
```

**Output:**
```
[WARNING] Found RSA in auth.cpp at line 15
[WARNING] Found MD5 in password_hash.cpp at line 42
[WARNING] Found DES in config.cpp at line 8

SUMMARY: 3 vulnerabilities detected
```

**Step 2: Encrypt Sensitive Data**
```bash
./Locker/build/QuantumLocker genkeys
./Locker/build/QuantumLocker encrypt user_passwords.db encrypted_passwords.bin
```

**Result:** Your data is now protected with quantum-safe Kyber-512 + AES-256 encryption!

---

## 🔬 Technical Details

### Cryptographic Algorithms

| Component | Algorithm | Status | Key Size |
|-----------|-----------|--------|----------|
| Key Exchange | **Kyber-512** | NIST Selected (PQC) | 1632 bytes (public) |
| Symmetric Cipher | **AES-256-CBC** | NIST Approved | 256 bits |
| Hashing | SHA-256 | Quantum-resistant | 256 bits |

### Security Guarantees
- **Kyber-512**: IND-CCA2 secure against quantum adversaries
- **AES-256**: 256-bit security level (quantum-resistant with Grover's algorithm)
- **Hybrid Design**: Defense-in-depth approach combining post-quantum and classical algorithms

---

## 📖 Documentation

Each tool includes detailed documentation:
- [Scanner README](Scanner/README.md)
- [Locker README](Locker/README.md)

---

## 🤝 Contributing

We welcome contributions! Whether you're:
- Adding new vulnerability patterns to Scanner
- Implementing additional post-quantum algorithms in Locker
- Improving documentation
- Reporting bugs

Please open an issue or submit a pull request.

---

## 📜 License

This project is open-source and available under the MIT License.

---

## 🌟 Why Choose Quantum-Migration-Toolkit?

| Feature | This Toolkit | Traditional Tools |
|---------|--------------|-------------------|
| Post-Quantum Ready | ✅ Yes | ❌ No |
| NIST-Approved Algorithms | ✅ Kyber-512 | ❌ RSA/ECC |
| Automated Vulnerability Scanning | ✅ Yes | ⚠️ Manual Review |
| Production-Ready | ✅ C++17, No Dependencies | ⚠️ Experimental |
| Easy Integration | ✅ CLI + CMake | ⚠️ Complex Setup |

---

## 🎯 Roadmap

- [ ] Support for additional NIST PQC algorithms (Dilithium, SPHINCS+)
- [ ] Python bindings for Scanner and Locker
- [ ] CI/CD integration plugins (GitHub Actions, Jenkins)
- [ ] Web dashboard for vulnerability tracking
- [ ] Windows native builds

---

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/Savaid-KhanOfficial/Quantum-Migration-Toolkit/issues)
- **Email**: savaid.khan@example.com
- **Documentation**: [Wiki](https://github.com/Savaid-KhanOfficial/Quantum-Migration-Toolkit/wiki)

---

## 🔗 Related Projects

- [liboqs](https://github.com/open-quantum-safe/liboqs) - Open Quantum Safe cryptographic library
- [NIST PQC Competition](https://csrc.nist.gov/projects/post-quantum-cryptography) - Official NIST post-quantum cryptography standards

---

**⚡ Start your quantum-safe migration today with Quantum-Migration-Toolkit!**

*Built with ❤️ for a quantum-secure future*
