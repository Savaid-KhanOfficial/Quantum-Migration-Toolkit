# QuantumScanner - Cryptographic Vulnerability Scanner

A command-line tool that scans codebases for outdated and quantum-vulnerable cryptographic algorithms.

## Features

- 🔍 **Recursive Directory Scanning**: Automatically scans all code files in a directory tree
- 🎯 **Multi-Language Support**: Scans C/C++, Python, Java, JavaScript/TypeScript files
- 🚨 **Detects Vulnerable Patterns**:
  - RSA (vulnerable to quantum attacks)
  - AES-128 (weak variant of AES)
  - MD5 (broken hash function)
  - DES (obsolete encryption)
  - SHA1/SHA-1 (weak hash function)
- 📊 **Detailed Reports**: Outputs to console and saves to `audit_report.txt`
- 📍 **Line-Level Accuracy**: Shows exact file, line number, and code snippet

## Build Instructions

### Prerequisites

- CMake 3.20 or higher
- C++17 compatible compiler
  - Windows: Visual Studio 2022 Build Tools
  - Linux: GCC 7+ or Clang 5+
  - macOS: Xcode Command Line Tools

### Building on Windows

```bash
# Navigate to QuantumScanner directory
cd D:\Quantum\QuantumScanner

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
cmake --build .
```

### Building on Linux/macOS

```bash
cd QuantumScanner

mkdir build && cd build
cmake ..
make
```

## Usage

```bash
# Show help
QuantumScanner help

# Scan a directory
QuantumScanner <directory_path>

# Examples
QuantumScanner C:\Projects\MyApp
QuantumScanner /home/user/code
QuantumScanner .
```

## Output

The scanner provides:

1. **Console Output**: Real-time scanning progress and warnings
2. **audit_report.txt**: Complete detailed report with:
   - Scan date
   - List of all vulnerabilities found
   - File paths and line numbers
   - Code snippets showing vulnerable patterns
   - Summary statistics

## Example Output

```
==========================================================
  QUANTUM SCANNER - Starting Analysis
  Target: D:\Projects\MyApp
==========================================================

[SCANNING] auth.cpp
[SCANNING] crypto_utils.py
[SCANNING] hash_service.java

[INFO] Total files scanned: 3

[WARNINGS] Found 8 potential vulnerabilities:

[WARNING] Found RSA in auth.cpp at line 15
  > RSA_PKCS1_PADDING

[WARNING] Found MD5 in crypto_utils.py at line 42
  > hashlib.md5(password).hexdigest()

...

==========================================================
SUMMARY:
  Total Vulnerabilities: 8
  Action Required: Review and upgrade to quantum-safe algorithms
==========================================================
```

## Test the Scanner

A test directory with sample vulnerable code is included:

```bash
cd D:\Quantum\QuantumScanner
.\build\Debug\QuantumScanner.exe test_code
```

## Recommendations

When vulnerabilities are found:

1. **RSA** → Upgrade to Kyber-512/768/1024 (NIST-approved post-quantum KEM)
2. **AES-128** → Upgrade to AES-256
3. **MD5** → Use SHA-256, SHA-3, or BLAKE2
4. **DES** → Use AES-256 or ChaCha20
5. **SHA1** → Use SHA-256, SHA-3, or BLAKE2

## Note on False Positives

The scanner performs case-insensitive keyword matching. Some false positives may occur (e.g., "Destructor" contains "DES"). Review flagged instances manually for context.

## License

This tool is provided for educational and security auditing purposes.

## Related Projects

- **QuantumLocker**: Quantum-safe file encryption tool using Kyber-512 + AES-256
- **liboqs**: Open Quantum Safe library for post-quantum cryptography
