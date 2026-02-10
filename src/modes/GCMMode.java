package modes;
import core.AESBlockCipher;
import random.RNG;
/**
 * GCM (Galois/Counter Mode) - Authenticated Encryption with Associated Data (AEAD)
 * Combines CTR mode encryption with GMAC authentication
 * Uses Galois Field GF(2^128) arithmetic for authentication
 * Output format: IV (96 bits) || Ciphertext || Tag (128 bits)
 */
public class GCMMode implements CipherMode {

    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int IV_SIZE = 12; // 96 bits
    private static final int TAG_SIZE = 16; // 128 bits

    private AESBlockCipher aes;
    private RNG randomGenerator;

    /**
     * Constructor
     * @param aes The AES block cipher
     * @param randomGenerator The random number generator
     */
    public GCMMode(AESBlockCipher aes, RNG randomGenerator) {
        this.aes = aes;
        this.randomGenerator = randomGenerator;
    }

    /**
     * Encrypts plaintext with optional additional authenticated data (AAD)
     * @param plaintext The data to encrypt
     * @param key The encryption key
     * @param aad Additional authenticated data (can be null or empty)
     * @return IV || Ciphertext || Tag
     */
    public byte[] encryptWithAAD(byte[] plaintext, byte[] key, byte[] aad) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        // Generate random 96-bit IV
        byte[] iv = randomGenerator.randomBytes(IV_SIZE);

        // Compute H = E(K, 0^128) - the hash subkey
        byte[] h = computeHashSubkey(key);

        // Perform CTR mode encryption
        byte[] ciphertext = ctrEncrypt(plaintext, key, iv);

        // Compute authentication tag
        byte[] tag = computeTag(h, iv, ciphertext, aad, key);

        // Combine: IV || Ciphertext || Tag
        byte[] result = new byte[IV_SIZE + ciphertext.length + TAG_SIZE];
        System.arraycopy(iv, 0, result, 0, IV_SIZE);
        System.arraycopy(ciphertext, 0, result, IV_SIZE, ciphertext.length);
        System.arraycopy(tag, 0, result, IV_SIZE + ciphertext.length, TAG_SIZE);

        return result;
    }

    /**
     * Decrypts ciphertext and verifies authentication tag
     * @param ciphertext IV || Ciphertext || Tag
     * @param key The decryption key
     * @param aad Additional authenticated data (must match encryption)
     * @return Decrypted plaintext
     * @throws IllegalArgumentException if authentication fails
     */
    public byte[] decryptWithAAD(byte[] ciphertext, byte[] key, byte[] aad) {
        if (ciphertext == null || ciphertext.length < IV_SIZE + TAG_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        // Extract IV
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(ciphertext, 0, iv, 0, IV_SIZE);

        // Extract tag
        byte[] receivedTag = new byte[TAG_SIZE];
        System.arraycopy(ciphertext, ciphertext.length - TAG_SIZE, receivedTag, 0, TAG_SIZE);

        // Extract encrypted data
        int encryptedLength = ciphertext.length - IV_SIZE - TAG_SIZE;
        byte[] encryptedData = new byte[encryptedLength];
        System.arraycopy(ciphertext, IV_SIZE, encryptedData, 0, encryptedLength);

        // Compute H = E(K, 0^128)
        byte[] h = computeHashSubkey(key);

        // Compute expected tag
        byte[] computedTag = computeTag(h, iv, encryptedData, aad, key);

        // Verify tag (constant-time comparison)
        if (!constantTimeEqual(receivedTag, computedTag)) {
            throw new IllegalArgumentException("Authentication failed: tag mismatch");
        }

        // Decrypt using CTR mode
        return ctrDecrypt(encryptedData, key, iv);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] key) {
        return encryptWithAAD(plaintext, key, null);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        return decryptWithAAD(ciphertext, key, null);
    }

    @Override
    public String getModeName() {
        return "GCM";
    }

    /**
     * Computes the hash subkey H = E(K, 0^128)
     */
    private byte[] computeHashSubkey(byte[] key) {
        byte[] zeroBlock = new byte[BLOCK_SIZE];
        return aes.encryptBlock(zeroBlock, key);
    }

    /**
     * CTR mode encryption for GCM
     */
    private byte[] ctrEncrypt(byte[] plaintext, byte[] key, byte[] iv) {
        byte[] ciphertext = new byte[plaintext.length];
        int numBlocks = (plaintext.length + BLOCK_SIZE - 1) / BLOCK_SIZE;

        for (int i = 0; i < numBlocks; i++) {
            // Counter starts at 2 (1 is reserved for tag generation)
            byte[] counterBlock = buildCounterBlock(iv, i + 2);
            byte[] keystream = aes.encryptBlock(counterBlock, key);

            int offset = i * BLOCK_SIZE;
            int bytesToProcess = Math.min(BLOCK_SIZE, plaintext.length - offset);

            for (int j = 0; j < bytesToProcess; j++) {
                ciphertext[offset + j] = (byte) (plaintext[offset + j] ^ keystream[j]);
            }
        }

        return ciphertext;
    }

    /**
     * CTR mode decryption for GCM (same as encryption)
     */
    private byte[] ctrDecrypt(byte[] ciphertext, byte[] key, byte[] iv) {
        return ctrEncrypt(ciphertext, key, iv);
    }

    /**
     * Builds counter block: IV (96 bits) || Counter (32 bits, big-endian)
     */
    private byte[] buildCounterBlock(byte[] iv, int counter) {
        byte[] block = new byte[BLOCK_SIZE];
        System.arraycopy(iv, 0, block, 0, IV_SIZE);

        block[12] = (byte) (counter >>> 24);
        block[13] = (byte) (counter >>> 16);
        block[14] = (byte) (counter >>> 8);
        block[15] = (byte) counter;

        return block;
    }

    /**
     * Computes GMAC authentication tag
     */
    private byte[] computeTag(byte[] h, byte[] iv, byte[] ciphertext, byte[] aad, byte[] key) {
        // Initialize GHASH with zero
        byte[] ghash = new byte[BLOCK_SIZE];

        // Process AAD if present
        if (aad != null && aad.length > 0) {
            ghash = ghashUpdate(ghash, h, aad);
        }

        // Process ciphertext
        ghash = ghashUpdate(ghash, h, ciphertext);

        // Process lengths: len(AAD) || len(C) in bits
        byte[] lengths = new byte[BLOCK_SIZE];
        long aadBitLength = (aad != null) ? (long) aad.length * 8 : 0;
        long ciphertextBitLength = (long) ciphertext.length * 8;

        // AAD length (bits 0-63, big-endian)
        for (int i = 0; i < 8; i++) {
            lengths[7 - i] = (byte) (aadBitLength >>> (i * 8));
        }

        // Ciphertext length (bits 64-127, big-endian)
        for (int i = 0; i < 8; i++) {
            lengths[15 - i] = (byte) (ciphertextBitLength >>> (i * 8));
        }

        ghash = gfMultiply(xor(ghash, lengths), h);

        // Encrypt counter block 1: IV || 0x00000001
        byte[] j0 = buildCounterBlock(iv, 1);
        byte[] encryptedJ0 = aes.encryptBlock(j0, key);

        // Final tag = GHASH XOR E(K, J0)
        return xor(ghash, encryptedJ0);
    }

    /**
     * GHASH update function - processes data blocks
     */
    private byte[] ghashUpdate(byte[] ghash, byte[] h, byte[] data) {
        int numBlocks = (data.length + BLOCK_SIZE - 1) / BLOCK_SIZE;

        for (int i = 0; i < numBlocks; i++) {
            byte[] block = new byte[BLOCK_SIZE];
            int offset = i * BLOCK_SIZE;
            int bytesToCopy = Math.min(BLOCK_SIZE, data.length - offset);
            System.arraycopy(data, offset, block, 0, bytesToCopy);

            // GHASH: ghash = (ghash XOR block) * H in GF(2^128)
            ghash = gfMultiply(xor(ghash, block), h);
        }

        return ghash;
    }

    /**
     * Multiplication in GF(2^128) using the reduction polynomial
     * R = 11100001 || 0^120 (i.e., x^128 + x^7 + x^2 + x + 1)
     */
    private byte[] gfMultiply(byte[] x, byte[] y) {
        byte[] result = new byte[BLOCK_SIZE];
        byte[] v = y.clone();

        // For each bit in x
        for (int i = 0; i < BLOCK_SIZE * 8; i++) {
            // If bit is set, XOR result with v
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);

            if (((x[byteIndex] >> bitIndex) & 1) == 1) {
                result = xor(result, v);
            }

            // Right shift v by 1 bit
            boolean lsb = (v[BLOCK_SIZE - 1] & 1) == 1;

            for (int j = BLOCK_SIZE - 1; j > 0; j--) {
                v[j] = (byte) ((v[j] >>> 1) | ((v[j - 1] & 1) << 7));
            }
            v[0] = (byte) (v[0] >>> 1);

            // If LSB was 1, XOR with R
            if (lsb) {
                v[0] ^= (byte) 0xE1; // 11100001
            }
        }

        return result;
    }

    /**
     * XOR two byte arrays
     */
    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Constant-time comparison to prevent timing attacks
     */
    private boolean constantTimeEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }
}