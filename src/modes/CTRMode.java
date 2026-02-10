package modes;
import core.AESBlockCipher;
import random.RNG;
/**
 * CTR (Counter) Mode Implementation
 * Stream cipher mode that generates keystream by encrypting counter values
 * Uses 96-bit nonce + 32-bit counter
 * No padding required
 */
public class CTRMode implements CipherMode {

    private static final int BLOCK_SIZE = 16; // AES block size in bytes
    private static final int NONCE_SIZE = 12; // 96 bits
    private static final int COUNTER_SIZE = 4; // 32 bits

    private AESBlockCipher aes;
    private RNG randomGenerator;

    /**
     * Constructor
     * @param aes The AES block cipher
     * @param randomGenerator The random number generator
     */
    public CTRMode(AESBlockCipher aes, RNG randomGenerator) {
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

        // Generate random 96-bit nonce
        byte[] nonce = randomGenerator.randomBytes(NONCE_SIZE);

        // Encrypt the plaintext
        byte[] ciphertext = ctrProcess(plaintext, key, nonce);

        // Result: Nonce || Ciphertext
        byte[] result = new byte[NONCE_SIZE + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, result, NONCE_SIZE, ciphertext.length);

        return result;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        if (ciphertext == null || ciphertext.length < NONCE_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short (must include nonce)");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        // Extract nonce from beginning
        byte[] nonce = new byte[NONCE_SIZE];
        System.arraycopy(ciphertext, 0, nonce, 0, NONCE_SIZE);

        // Extract actual ciphertext
        int encryptedLength = ciphertext.length - NONCE_SIZE;
        byte[] encryptedData = new byte[encryptedLength];
        System.arraycopy(ciphertext, NONCE_SIZE, encryptedData, 0, encryptedLength);

        // Decrypt (CTR mode: encryption and decryption are the same operation)
        return ctrProcess(encryptedData, key, nonce);
    }

    @Override
    public String getModeName() {
        return "CTR";
    }

    /**
     * Core CTR mode processing (same for encryption and decryption)
     * @param input Input data (plaintext or ciphertext)
     * @param key Encryption key
     * @param nonce 96-bit nonce
     * @return Output data (ciphertext or plaintext)
     */
    private byte[] ctrProcess(byte[] input, byte[] key, byte[] nonce) {
        byte[] output = new byte[input.length];

        // Calculate number of blocks needed (round up)
        int numBlocks = (input.length + BLOCK_SIZE - 1) / BLOCK_SIZE;

        // Process each block
        for (int i = 0; i < numBlocks; i++) {
            // Build counter block: Nonce (96 bits) || Counter (32 bits)
            byte[] counterBlock = buildCounterBlock(nonce, i);

            // Encrypt counter block to generate keystream
            byte[] keystream = aes.encryptBlock(counterBlock, key);

            // Calculate how many bytes to process in this block
            int inputOffset = i * BLOCK_SIZE;
            int remainingBytes = input.length - inputOffset;
            int bytesToProcess = Math.min(BLOCK_SIZE, remainingBytes);

            // XOR input with keystream
            for (int j = 0; j < bytesToProcess; j++) {
                output[inputOffset + j] = (byte) (input[inputOffset + j] ^ keystream[j]);
            }
        }

        return output;
    }

    /**
     * Builds a counter block: Nonce (96 bits) || Counter (32 bits, big-endian)
     * @param nonce The 96-bit nonce
     * @param counter The counter value
     * @return 128-bit counter block
     */
    private byte[] buildCounterBlock(byte[] nonce, int counter) {
        byte[] block = new byte[BLOCK_SIZE];

        // Copy nonce (first 12 bytes)
        System.arraycopy(nonce, 0, block, 0, NONCE_SIZE);

        // Add counter (last 4 bytes, big-endian)
        block[12] = (byte) (counter >>> 24);
        block[13] = (byte) (counter >>> 16);
        block[14] = (byte) (counter >>> 8);
        block[15] = (byte) counter;

        return block;
    }
}