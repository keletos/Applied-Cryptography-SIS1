package modes;
import core.AESBlockCipher;
import random.RNG;

/**
 * CBC (Cipher Block Chaining) Mode Implementation
 * Each plaintext block is XORed with the previous ciphertext block before encryption
 * Uses random IV which is prepended to the ciphertext
 */
public class CBCMode implements CipherMode {

    private static final int BLOCK_SIZE = 16; // AES block size in bytes

    private AESBlockCipher aes;
    private RNG randomGenerator;

    /**
     * Constructor
     * @param aes The AES block cipher
     * @param randomGenerator The random number generator
     */
    public CBCMode(AESBlockCipher aes, RNG randomGenerator) {
        this.aes = aes;
        this.randomGenerator = randomGenerator;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] key) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        // Generate random IV
        byte[] iv = randomGenerator.randomBytes(BLOCK_SIZE);

        // Apply PKCS#7 padding
        byte[] paddedPlaintext = addPKCS7Padding(plaintext);

        // Number of blocks
        int numBlocks = paddedPlaintext.length / BLOCK_SIZE;

        // Result: IV || Ciphertext
        byte[] result = new byte[BLOCK_SIZE + paddedPlaintext.length];

        // Copy IV to result
        System.arraycopy(iv, 0, result, 0, BLOCK_SIZE);

        // Previous ciphertext block (initially the IV)
        byte[] previousCiphertext = iv;

        // Encrypt each block with chaining
        for (int i = 0; i < numBlocks; i++) {
            int plaintextOffset = i * BLOCK_SIZE;
            int ciphertextOffset = BLOCK_SIZE + i * BLOCK_SIZE; // Skip IV

            // Extract current plaintext block
            byte[] block = new byte[BLOCK_SIZE];
            System.arraycopy(paddedPlaintext, plaintextOffset, block, 0, BLOCK_SIZE);

            // XOR with previous ciphertext block
            byte[] xoredBlock = xor(block, previousCiphertext);

            // Encrypt the XORed block
            byte[] encryptedBlock = aes.encryptBlock(xoredBlock, key);

            // Copy to result
            System.arraycopy(encryptedBlock, 0, result, ciphertextOffset, BLOCK_SIZE);

            // Update previous ciphertext for next iteration
            previousCiphertext = encryptedBlock;
        }

        return result;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        if (ciphertext == null || ciphertext.length < BLOCK_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short (must include IV)");
        }
        if ((ciphertext.length - BLOCK_SIZE) % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Invalid ciphertext length");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        // Extract IV from beginning
        byte[] iv = new byte[BLOCK_SIZE];
        System.arraycopy(ciphertext, 0, iv, 0, BLOCK_SIZE);

        // Calculate number of encrypted blocks
        int encryptedLength = ciphertext.length - BLOCK_SIZE;
        int numBlocks = encryptedLength / BLOCK_SIZE;

        byte[] paddedPlaintext = new byte[encryptedLength];

        // Previous ciphertext block (initially the IV)
        byte[] previousCiphertext = iv;

        // Decrypt each block with chaining
        for (int i = 0; i < numBlocks; i++) {
            int ciphertextOffset = BLOCK_SIZE + i * BLOCK_SIZE; // Skip IV
            int plaintextOffset = i * BLOCK_SIZE;

            // Extract current ciphertext block
            byte[] block = new byte[BLOCK_SIZE];
            System.arraycopy(ciphertext, ciphertextOffset, block, 0, BLOCK_SIZE);

            // Decrypt the block
            byte[] decryptedBlock = aes.decryptBlock(block, key);

            // XOR with previous ciphertext block
            byte[] plaintextBlock = xor(decryptedBlock, previousCiphertext);

            // Copy to result
            System.arraycopy(plaintextBlock, 0, paddedPlaintext, plaintextOffset, BLOCK_SIZE);

            // Update previous ciphertext for next iteration
            previousCiphertext = block;
        }

        // Remove PKCS#7 padding
        return removePKCS7Padding(paddedPlaintext);
    }

    @Override
    public String getModeName() {
        return "CBC";
    }

    /**
     * XOR two byte arrays of equal length
     */
    private byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("Arrays must have equal length for XOR");
        }

        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Adds PKCS#7 padding to the data
     */
    private byte[] addPKCS7Padding(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = new byte[data.length + paddingLength];

        System.arraycopy(data, 0, padded, 0, data.length);

        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }

        return padded;
    }

    /**
     * Removes PKCS#7 padding from the data
     */
    private byte[] removePKCS7Padding(byte[] paddedData) {
        if (paddedData == null || paddedData.length == 0) {
            throw new IllegalArgumentException("Padded data cannot be null or empty");
        }

        int paddingLength = paddedData[paddedData.length - 1] & 0xFF;

        if (paddingLength < 1 || paddingLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid padding length: " + paddingLength);
        }

        if (paddingLength > paddedData.length) {
            throw new IllegalArgumentException("Padding length exceeds data length");
        }

        // Verify padding
        for (int i = paddedData.length - paddingLength; i < paddedData.length; i++) {
            if ((paddedData[i] & 0xFF) != paddingLength) {
                throw new IllegalArgumentException("Invalid padding bytes");
            }
        }

        byte[] data = new byte[paddedData.length - paddingLength];
        System.arraycopy(paddedData, 0, data, 0, data.length);

        return data;
    }
}