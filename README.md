# 🔐 AES Encryption/Decryption System

[![Java](https://img.shields.io/badge/Java-17+-orange.svg)](https://www.oracle.com/java/)
[![License](https://img.shields.io/badge/License-Educational-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-35%2F35%20Passing-brightgreen.svg)](docs/TESTING.md)

Educational implementation of AES (Advanced Encryption Standard) with multiple modes of operation, built from scratch without using external cryptographic libraries.

## ⚠️ Important Notice

**This is an educational project.** Do NOT use in production systems. For real-world applications, always use established, audited cryptographic libraries like Java Cryptography Extension (JCE).

## 📋 Table of Contents

- [Features](#-features)
- [Modes of Operation](#-modes-of-operation)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Project Structure](#-project-structure)
- [Documentation](#-documentation)
- [Testing](#-testing)
- [Performance](#-performance)
- [Contributing](#-contributing)
- [Team](#-team)
- [License](#-license)

## ✨ Features

- **4 Cipher Modes**: ECB, CBC, CTR, GCM (AEAD)
- **3 Key Sizes**: AES-128, AES-192, AES-256
- **Pure Java Implementation**: No external crypto libraries
- **NIST Test Vectors**: Built-in validation
- **Console Interface**: User-friendly CLI
- **Complete Testing Suite**: 35 tests, 100% pass rate
- **Educational Focus**: Demonstrates ECB weakness

## 🔄 Modes of Operation

| Mode | Security | Authentication | Padding | Use Case |
|------|----------|----------------|---------|----------|
| **ECB** | ❌ Low | ❌ No | ✓ Yes | Educational only |
| **CBC** | ✓ Good | ❌ No | ✓ Yes | Legacy systems |
| **CTR** | ✓ Good | ❌ No | ❌ No | High performance |
| **GCM** | ✓✓ Excellent | ✓✓ Yes | ❌ No | **Recommended** |

### Mode Details

- **ECB (Electronic Codebook)**: Simple but insecure - identical plaintext blocks produce identical ciphertext blocks
- **CBC (Cipher Block Chaining)**: Chains blocks together using IV, secure with random IV
- **CTR (Counter)**: Stream cipher mode, parallelizable, no padding needed
- **GCM (Galois/Counter Mode)**: Authenticated encryption, provides both confidentiality and authenticity

## 💻 Requirements

### Software Requirements
- **Java Development Kit (JDK)**: 11 or higher
- **Build Tool**: Maven or Gradle (optional)
- **IDE** (recommended): IntelliJ IDEA, Eclipse, or VS Code

### Hardware Requirements
- **RAM**: Minimum 512 MB
- **Storage**: ~50 MB for project files
- **CPU**: Any modern processor

## 📦 Installation

### Option 1: Clone Repository

```bash
# Clone the repository
git clone https://github.com/keletos/Applied-Cryptography-SIS1.git

# Navigate to project directory
cd Applied-Cryptography.git

# Compile the project
javac -d bin -sourcepath src src/**/*.java

# Run the application
java -cp bin test.AESConsoleApp
```

### Option 2: Download ZIP

1. Click **Code** → **Download ZIP** on GitHub
2. Extract the archive
3. Open terminal in the extracted folder
4. Follow compilation steps above

### Option 3: Import into IDE

#### IntelliJ IDEA
1. **File** → **New** → **Project from Version Control**
2. Enter repository URL: `https://github.com/YOUR_USERNAME/mycrypto.git`
3. Click **Clone**
4. Right-click `Main.java` → **Run 'Main.main()'**

#### Eclipse
1. **File** → **Import** → **Git** → **Projects from Git**
2. Select **Clone URI**
3. Enter repository URL
4. Right-click project → **Run As** → **Java Application**

#### VS Code
1. Open Command Palette (`Ctrl+Shift+P`)
2. Type: `Git: Clone`
3. Enter repository URL
4. Open `Main.java` and click **Run** above `main` method

## 🚀 Quick Start

### Running the Application

```bash
# Compile
javac -d bin -sourcepath src src/**/*.java

# Run
java -cp bin Main
```

### First Encryption

1. **Select Key Size** (Option 1)
   - Choose: `1` for AES-128

2. **Select Cipher Mode** (Option 2)
   - Choose: `4` for GCM (recommended)

3. **Generate Key** (Option 3)
   - Choose: `1` to generate random key

4. **Encrypt** (Option 4)
   - Choose: `1` to enter text
   - Type your message
   - View encrypted output in HEX and Base64

5. **Decrypt** (Option 5)
   - Paste the encrypted output
   - View decrypted plaintext

## 📖 Usage Examples

### Example 1: Encrypt Text with GCM Mode

```
MAIN MENU
════════════════════════════════════════
Current Settings:
  Key Size: K128
  Mode:     GCM
  Key:      SET

Enter choice: 4

ENCRYPTION
──────────
1. Enter Text (UTF-8)
2. Enter Hex
3. Load from File

Enter choice: 1
Enter text: Hello, World!

Encrypting...
✓ Encryption successful!
Time: 2.36 ms

OUTPUT
──────
Original length: 13 bytes
Output length:   41 bytes (12-byte IV + 13-byte ciphertext + 16-byte tag)

[HEX]
4f2a1b8e3c5d9a7f2e6b8c3a5d9f1e4c2a7b3f...

[BASE64]
Tyobfjxdmn8ua4w6XZ8eLCp7Pw==...

Save to file? (y/n): n
```

### Example 2: Run Test Vectors

```
Enter choice: 6

NIST TEST VECTORS
══════════════════════════════════════════

--- AES-128 Test Vector ---
✓ PASS

--- AES-192 Test Vector ---
✓ PASS

--- AES-256 Test Vector ---
✓ PASS

All tests passed!
```

### Example 3: Programmatic Usage

```java
import core.AESCoreImpl;
import random.SecureRandomImpl;
import modes.*;

public class Example {
    public static void main(String[] args) {
        // Initialize dependencies
        AESCore aes = new AESCoreImpl();
        SecureRandomGenerator rng = new SecureRandomImpl();
        
        // Create GCM mode instance
        GCMMode gcm = new GCMMode(aes, rng);
        
        // Prepare data
        byte[] plaintext = "Secret message".getBytes();
        byte[] key = rng.generateBytes(16); // 128-bit key
        
        // Encrypt
        byte[] encrypted = gcm.encrypt(plaintext, key);
        
        // Decrypt
        byte[] decrypted = gcm.decrypt(encrypted, key);
        
        System.out.println(new String(decrypted)); // "Secret message"
    }
}
```

## 📁 Project Structure

```
mycrypto/
├── src/
│   ├── core/                    # AES core implementation
│   │   ├── AESCore.java         # Interface
│   │   ├── AESCoreImpl.java     # Implementation
│   │   └── KeySize.java
│   │
│   ├── random/                  # Random number generation
│   │   └── RNG.java
│   │   
│   │
│   ├── modes/                   # Cipher modes
│   │   ├── CipherMode.java      # Interface
│   │   ├── ECBMode.java         # ECB mode
│   │   ├── CBCMode.java         # CBC mode
│   │   ├── CTRMode.java         # CTR mode
│   │   └── GCMMode.java         # GCM mode
│   │   
│   └──test/
│       ├── TestRunner.java     # Unit tests
│       └── AESConsoleApp.java  # Main app
│       
│                
│   
│   
│ 
│
├── docs/                        # Documentation
│   ├── MODES.md                 # Detailed mode descriptions
│   ├── TESTING.md               # Test documentation
│   ├── PERFORMANCE.md           # Benchmarks
│   └── AES_Technical_Report.docx
│
├── .gitignore                   # Git ignore file
├── README.md                    # This file
└── LICENSE                      # License file
```

## 📚 Documentation

- **[Modes of Operation](docs/MODES.md)**: Detailed explanation of each cipher mode
- **[Testing Guide](docs/TESTING.md)**: Test suite documentation
- **[Performance Benchmarks](docs/PERFORMANCE.md)**: Speed and efficiency analysis
- **[Technical Report](docs/AES_Technical_Report.docx)**: Complete technical documentation

## 🧪 Testing

### Run All Tests

```bash
# Compile tests
javac -d bin -sourcepath src:test src/**/*.java test/**/*.java

# Run test suite
java -cp bin TestRunner
```

### Test Results

```
Total tests:    35
Passed:         35 ✓
Failed:         0 ✗
Success rate:   100%
Execution time: 3527 ms
```

### Test Categories

1. **NIST Test Vectors** (3 tests)
   - AES-128, AES-192, AES-256 validation

2. **Round-Trip Tests** (12 tests)
   - All modes with various data sizes

3. **PKCS#7 Padding** (16 tests)
   - All padding lengths (1-16 bytes)

4. **GCM Authentication** (2 tests)
   - Valid decryption + tamper detection

5. **Large Data** (2 tests)
   - 1 MB and 2 MB file handling

## ⚡ Performance

### Throughput Benchmarks

| Mode | Small (13 bytes) | Medium (1 KB) | Large (1 MB) | Throughput |
|------|------------------|---------------|--------------|------------|
| CTR  | ~2.3 ms         | ~14 ms        | ~1240 ms     | ~0.81 MB/s |
| ECB  | ~2.5 ms         | ~15 ms        | ~1278 ms     | ~0.78 MB/s |
| CBC  | ~2.4 ms         | ~16 ms        | ~1310 ms     | ~0.76 MB/s |
| GCM  | ~2.8 ms         | ~18 ms        | ~1450 ms     | ~0.69 MB/s |

**Test Environment**: Pure Java implementation (no hardware acceleration)

> **Note**: Production libraries with AES-NI hardware acceleration achieve 1000+ MB/s

## 🤝 Contributing

This is an educational project. Contributions for learning purposes are welcome!

### How to Contribute

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create Pull Request

### Code Style

- Follow Java naming conventions
- Add JavaDoc comments for public methods
- Include unit tests for new features
- Keep methods under 50 lines when possible

## 👥 Team

### Core Team
- **[Your Name]** - Modes of Operation Implementation
- **[Team Member 1]** - AES Core Implementation
- **[Team Member 2]** - Random Number Generation

### Acknowledgments
- NIST for AES specification and test vectors
- Course instructor for guidance
- Community for feedback and testing

## 📄 License

This project is licensed under the Educational License - see the [LICENSE](LICENSE) file for details.

### Educational Use Only

This implementation is intended for:
- ✓ Learning cryptography concepts
- ✓ Understanding AES algorithms
- ✓ Academic research and study
- ✗ Production systems
- ✗ Commercial applications
- ✗ Protecting sensitive data

**For production use, always use established libraries like:**
- Java Cryptography Extension (JCE)
- Bouncy Castle
- Google Tink

## 🔗 Resources

- [AES Specification (FIPS 197)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [NIST Test Vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- [GCM Specification (NIST SP 800-38D)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/mycrypto/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR_USERNAME/mycrypto/discussions)

---

<p align="center">
  Made with ❤️ for learning cryptography
</p>

<p align="center">
  <sub>⚠️ Educational Project - Not for Production Use</sub>
</p>
