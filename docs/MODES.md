# 🔄 Cipher Modes of Operation - Detailed Guide

Complete reference for all implemented AES cipher modes.

## Table of Contents

- [Overview](#overview)
- [ECB Mode](#ecb-mode)
- [CBC Mode](#cbc-mode)
- [CTR Mode](#ctr-mode)
- [GCM Mode](#gcm-mode)
- [Comparison](#mode-comparison)
- [Security Recommendations](#security-recommendations)

---

## Overview

Block cipher modes of operation define how to repeatedly apply a cipher's single-block operation to securely transform larger amounts of data. Our implementation provides four distinct modes, each with different security properties and use cases.

### Key Concepts

- **Block Cipher**: Operates on fixed-size blocks (AES = 128 bits = 16 bytes)
- **Padding**: Used when plaintext isn't a multiple of block size
- **IV (Initialization Vector)**: Random value to ensure different ciphertexts
- **Nonce**: Number used once - similar to IV but may have different requirements
- **AEAD**: Authenticated Encryption with Associated Data

---

## ECB Mode

**Electronic Codebook Mode**

### Description

ECB is the simplest mode where each block is encrypted independently with the same key.

### How It Works

```
Encryption:
Block 1 → AES(Key) → Ciphertext Block 1
Block 2 → AES(Key) → Ciphertext Block 2
Block 3 → AES(Key) → Ciphertext Block 3

Decryption:
Ciphertext Block 1 → AES⁻¹(Key) → Block 1
Ciphertext Block 2 → AES⁻¹(Key) → Block 2
Ciphertext Block 3 → AES⁻¹(Key) → Block 3
```

### Formulas

- **Encryption**: C[i] = E(K, P[i])
- **Decryption**: P[i] = D(K, C[i])

Where:
- C = Ciphertext block
- P = Plaintext block
- E = Encryption function
- D = Decryption function
- K = Key
- i = Block index

### Implementation Details

```java
public byte[] encrypt(byte[] plaintext, byte[] key) {
    byte[] padded = addPKCS7Padding(plaintext);
    byte[] ciphertext = new byte[padded.length];
    
    for (int i = 0; i < padded.length; i += 16) {
        byte[] block = extractBlock(padded, i);
        byte[] encrypted = aesCore.encryptBlock(block, key);
        copyToOutput(encrypted, ciphertext, i);
    }
    return ciphertext;
}
```

### Padding: PKCS#7

Adds N bytes with value N:
- 1 byte short → add `0x01`
- 2 bytes short → add `0x02 0x02`
- 15 bytes short → add `0x0F 0x0F ... 0x0F` (15 times)
- Full block → add entire block `0x10 0x10 ... 0x10` (16 times)

### Security Analysis

**❌ NOT SECURE - DO NOT USE IN PRODUCTION**

**Vulnerabilities:**
1. **Pattern Leakage**: Identical plaintext blocks → identical ciphertext blocks
2. **No Semantic Security**: Attacker can see structure of data
3. **Malleable**: Blocks can be rearranged without detection
4. **Deterministic**: Same plaintext always produces same ciphertext

**Famous Example**: ECB Penguin
- Original image clearly visible even when encrypted
- Demonstrates why ECB fails for real data

### Use Cases

- ❌ **NEVER** for production
- ✅ Educational demonstrations only
- ✅ Understanding why proper modes are needed

---

## CBC Mode

**Cipher Block Chaining Mode**

### Description

CBC chains blocks together by XORing each plaintext block with the previous ciphertext block before encryption.

### How It Works

```
Encryption:
IV  ⊕ Block 1 → AES(Key) → Ciphertext 1
C1  ⊕ Block 2 → AES(Key) → Ciphertext 2
C2  ⊕ Block 3 → AES(Key) → Ciphertext 3

Decryption:
Ciphertext 1 → AES⁻¹(Key) ⊕ IV  → Block 1
Ciphertext 2 → AES⁻¹(Key) ⊕ C1  → Block 2
Ciphertext 3 → AES⁻¹(Key) ⊕ C2  → Block 3
```

### Formulas

- **Encryption**: C[i] = E(K, P[i] ⊕ C[i-1]), where C[0] = IV
- **Decryption**: P[i] = D(K, C[i]) ⊕ C[i-1]

### Implementation Details

```java
public byte[] encrypt(byte[] plaintext, byte[] key) {
    byte[] iv = randomGenerator.generateBytes(16);
    byte[] padded = addPKCS7Padding(plaintext);
    byte[] result = new byte[16 + padded.length];
    
    // Prepend IV
    System.arraycopy(iv, 0, result, 0, 16);
    
    byte[] previousCiphertext = iv;
    for (int i = 0; i < padded.length; i += 16) {
        byte[] block = extractBlock(padded, i);
        byte[] xored = xor(block, previousCiphertext);
        byte[] encrypted = aesCore.encryptBlock(xored, key);
        copyToOutput(encrypted, result, 16 + i);
        previousCiphertext = encrypted;
    }
    return result;
}
```

### Output Format

```
[IV: 16 bytes][Ciphertext: variable][Padding: 1-16 bytes]
```

### Security Analysis

**✅ Secure when used correctly**

**Strengths:**
- Random IV ensures different ciphertext for same plaintext
- Cannot see patterns in data
- Widely supported and tested

**Weaknesses:**
- Vulnerable to padding oracle attacks if error messages reveal padding validity
- Sequential encryption (not parallelizable)
- Decryption parallelizable

**Error Propagation:**
- 1 bit error in ciphertext affects 2 blocks:
  - Current block: completely garbled
  - Next block: 1 bit flipped

### Best Practices

1. **Generate random IV** for each encryption
2. **Never reuse IV** with same key
3. **IV doesn't need to be secret** but must be unpredictable
4. **Hide padding errors** - don't reveal if padding is invalid
5. **Use authenticated encryption** (like GCM) when possible

### Use Cases

- ✅ Legacy systems compatibility
- ✅ General-purpose encryption
- ⚠️ Consider GCM for new applications

---

## CTR Mode

**Counter Mode**

### Description

CTR mode turns a block cipher into a stream cipher by encrypting sequential counter values to create a keystream.

### How It Works

```
Keystream Generation:
Nonce||Counter=0 → AES(Key) → Keystream 1
Nonce||Counter=1 → AES(Key) → Keystream 2
Nonce||Counter=2 → AES(Key) → Keystream 3

Encryption:
Plaintext 1 ⊕ Keystream 1 → Ciphertext 1
Plaintext 2 ⊕ Keystream 2 → Ciphertext 2
Plaintext 3 ⊕ Keystream 3 → Ciphertext 3

Decryption (identical to encryption):
Ciphertext 1 ⊕ Keystream 1 → Plaintext 1
Ciphertext 2 ⊕ Keystream 2 → Plaintext 2
```

### Formulas

- **Keystream**: K[i] = E(K, Nonce || Counter[i])
- **Encryption**: C[i] = P[i] ⊕ K[i]
- **Decryption**: P[i] = C[i] ⊕ K[i]

### Implementation Details

```java
public byte[] encrypt(byte[] plaintext, byte[] key) {
    byte[] nonce = randomGenerator.generateBytes(12);
    byte[] result = new byte[12 + plaintext.length];
    
    // Prepend nonce
    System.arraycopy(nonce, 0, result, 0, 12);
    
    for (int i = 0; i < plaintext.length; i += 16) {
        byte[] counterBlock = buildCounterBlock(nonce, i / 16);
        byte[] keystream = aesCore.encryptBlock(counterBlock, key);
        
        int len = Math.min(16, plaintext.length - i);
        for (int j = 0; j < len; j++) {
            result[12 + i + j] = (byte)(plaintext[i + j] ^ keystream[j]);
        }
    }
    return result;
}
```

### Counter Block Format

```
[Nonce: 96 bits][Counter: 32 bits]
```

Counter starts at 2 (1 reserved for GCM).

### Output Format

```
[Nonce: 12 bytes][Ciphertext: same length as plaintext]
```

### Security Analysis

**✅ Secure when used correctly**

**Strengths:**
- No padding required
- Fully parallelizable (encryption and decryption)
- Random access: can decrypt any block independently
- Keystream can be precomputed
- Simple error propagation: 1 bit error affects only that bit

**Weaknesses:**
- **CRITICAL**: Never reuse nonce with same key → catastrophic failure
- No authentication (use GCM instead)

**Nonce Reuse Attack:**
```
If Nonce₁ = Nonce₂:
C₁ ⊕ C₂ = (P₁ ⊕ K) ⊕ (P₂ ⊕ K) = P₁ ⊕ P₂
→ Attacker gets XOR of plaintexts (often enough to recover both)
```

### Best Practices

1. **NEVER reuse nonce** - this is critical
2. Use random nonce or counter (if counter, ensure no wraparound)
3. Consider GCM instead (adds authentication)
4. Limit data encrypted with single key (2³² blocks max)

### Use Cases

- ✅ High-performance encryption
- ✅ Random access scenarios
- ✅ Parallelizable applications
- ✅ When padding overhead is unacceptable

---

## GCM Mode

**Galois/Counter Mode - Authenticated Encryption with Associated Data (AEAD)**

### Description

GCM combines CTR mode encryption with GMAC authentication, providing both confidentiality and authenticity in a single operation.

### How It Works

```
1. Compute Hash Subkey:
   H = AES(Key, 0¹²⁸)

2. CTR Encryption:
   (same as CTR mode, counter starts at 2)

3. Authentication (GHASH):
   Process AAD blocks through GHASH(H, ...)
   Process Ciphertext blocks through GHASH(H, ...)
   Process length block: len(AAD)||len(C)
   
4. Generate Tag:
   Tag = GHASH_result ⊕ AES(Key, IV||0x00000001)

5. Output:
   IV || Ciphertext || Tag
```

### Formulas

- **Encryption**: Same as CTR mode
- **GHASH**: Polynomial evaluation in GF(2¹²⁸)
- **Tag**: T = GHASH(H, AAD, C, len) ⊕ E(K, IV||1)

### GF(2¹²⁸) Multiplication

Uses reduction polynomial: R = x¹²⁸ + x⁷ + x² + x + 1

```java
private byte[] gfMultiply(byte[] x, byte[] y) {
    byte[] result = new byte[16];
    byte[] v = y.clone();
    
    for (int i = 0; i < 128; i++) {
        if (getBit(x, i) == 1) {
            result = xor(result, v);
        }
        
        boolean lsb = (v[15] & 1) == 1;
        rightShift(v);  // v >>= 1
        
        if (lsb) {
            v[0] ^= 0xE1;  // XOR with R
        }
    }
    return result;
}
```

### Output Format

```
[IV: 12 bytes][Ciphertext: same as plaintext][Tag: 16 bytes]
```

### Authentication Process

1. **Hash Subkey**: H = E(K, 0¹²⁸)
2. **Process AAD**: Feed AAD blocks into GHASH
3. **Process Ciphertext**: Feed ciphertext blocks into GHASH
4. **Length Block**: Append len(AAD) || len(Ciphertext) in bits
5. **Generate Tag**: XOR GHASH result with encrypted counter 1

### Security Analysis

**✅✅ Highly Secure - RECOMMENDED**

**Strengths:**
- Provides confidentiality AND authenticity
- Detects any tampering
- Supports AAD (authenticated but not encrypted data)
- Parallelizable
- NIST approved
- Widely used (TLS 1.3, IPsec, etc.)

**Authentication Guarantee:**
- Any modification to ciphertext, IV, or AAD detected
- Probability of forging valid tag: 2⁻¹²⁸ (negligible)

**Weaknesses:**
- Slightly slower than pure CTR (~10-20% overhead)
- Still requires unique IV (but easier than CTR since includes auth)

### Additional Authenticated Data (AAD)

Data that is authenticated but not encrypted:
- Headers, metadata, routing information
- User IDs, timestamps, version numbers

Example:
```java
byte[] plaintext = "secret message".getBytes();
byte[] aad = "user_id:12345,timestamp:1707555600".getBytes();
byte[] encrypted = gcm.encryptWithAAD(plaintext, key, aad);

// Attacker cannot change user_id or timestamp without detection
```

### Best Practices

1. **Use GCM for new applications** - it's the modern standard
2. Generate random 96-bit IV (recommended length)
3. Include relevant metadata in AAD
4. Verify tag BEFORE processing plaintext
5. Use constant-time tag comparison (prevents timing attacks)

### Use Cases

- ✅✅ **Recommended for all new applications**
- ✅ TLS connections
- ✅ Disk encryption with authentication
- ✅ Network protocols
- ✅ Any scenario requiring both encryption and authentication

---

## Mode Comparison

### Security Comparison

| Feature | ECB | CBC | CTR | GCM |
|---------|-----|-----|-----|-----|
| Pattern Hiding | ❌ | ✅ | ✅ | ✅ |
| Semantic Security | ❌ | ✅ | ✅ | ✅ |
| Authentication | ❌ | ❌ | ❌ | ✅✅ |
| IV/Nonce Required | ❌ | ✅ | ✅ | ✅ |
| Padding Oracles | N/A | ⚠️ | N/A | N/A |
| Nonce Reuse Impact | N/A | Medium | Critical | Critical |
| Overall Security | ❌ Low | ✅ Good | ✅ Good | ✅✅ Excellent |

### Performance Comparison

| Feature | ECB | CBC | CTR | GCM |
|---------|-----|-----|-----|-----|
| Encryption Speed | Fast | Medium | Fast | Fast |
| Parallelizable Encryption | ✅ | ❌ | ✅ | ✅ |
| Parallelizable Decryption | ✅ | ✅ | ✅ | ✅ |
| Padding Overhead | 1-16 bytes | 1-16 bytes | None | None |
| Authentication Overhead | None | None | None | ~10-20% |
| Random Access | ✅ | ❌ | ✅ | ✅ |

### Implementation Complexity

| Aspect | ECB | CBC | CTR | GCM |
|--------|-----|-----|-----|-----|
| Algorithm Complexity | Simple | Medium | Medium | Complex |
| Implementation Lines | ~100 | ~150 | ~120 | ~300 |
| Padding Logic | Required | Required | Not needed | Not needed |
| Special Math | None | XOR only | XOR only | GF(2¹²⁸) |

---

## Security Recommendations

### For New Applications

**✅ USE: GCM Mode**
- Provides both encryption and authentication
- Modern standard
- Fast and secure

### For Legacy Compatibility

**✅ USE: CBC Mode**
- Only if GCM not available
- Ensure proper padding error handling
- Consider adding HMAC for authentication

### For High Performance

**✅ USE: CTR Mode**
- Only if authentication handled separately
- CRITICAL: ensure unique nonces
- Consider parallelization benefits

### NEVER USE

**❌ AVOID: ECB Mode**
- Fundamentally insecure
- Only for educational purposes
- Will leak data patterns

---

## References

- [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) - Block Cipher Modes
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) - GCM Specification
- [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) - AES Specification

---
