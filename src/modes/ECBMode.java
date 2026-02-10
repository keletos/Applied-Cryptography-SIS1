package modes;
import core.AESBlockCipher;
/**
 * ECB (Electronic Codebook) Mode Implementation
 * WARNING: ECB is not secure for most use cases as it doesn't hide data patterns
 * This implementation is for educational purposes to demonstrate ECB weaknesses
 */
public class ECBMode implements CipherMode {

    private static final int BLOCK_SIZE = 16; // AES block size in bytes

    private AESBlockCipher aes;

    /**
     * Constructor
     * @param aes The AES block cipher
     */
    public ECBMode(AESBlockCipher aes) {
        this.aes = aes;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] key) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        // Apply PKCS#7 padding
        byte[] paddedPlaintext = addPKCS7Padding(plaintext);

        // Number of blocks
        int numBlocks = paddedPlaintext.length / BLOCK_SIZE;
        byte[] ciphertext = new byte[paddedPlaintext.length];

        // Encrypt each block independently
        for (int i = 0; i < numBlocks; i++) {
            int offset = i * BLOCK_SIZE;
            byte[] block = new byte[BLOCK_SIZE];
            System.arraycopy(paddedPlaintext, offset, block, 0, BLOCK_SIZE);

            // Encrypt block using AES core
            byte[] encryptedBlock = aes.encryptBlock(block, key);
            System.arraycopy(encryptedBlock, 0, ciphertext, offset, BLOCK_SIZE);
        }

        return ciphertext;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be null or empty");
        }
        if (ciphertext.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Ciphertext length must be multiple of block size");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("Invalid AES key length");
        }


        // Number of blocks
        int numBlocks = ciphertext.length / BLOCK_SIZE;
        byte[] paddedPlaintext = new byte[ciphertext.length];

        // Decrypt each block independently
        for (int i = 0; i < numBlocks; i++) {
            int offset = i * BLOCK_SIZE;
            byte[] block = new byte[BLOCK_SIZE];
            System.arraycopy(ciphertext, offset, block, 0, BLOCK_SIZE);

            // Decrypt block using AES core
            byte[] decryptedBlock = aes.decryptBlock(block, key);
            System.arraycopy(decryptedBlock, 0, paddedPlaintext, offset, BLOCK_SIZE);
        }

        // Remove PKCS#7 padding
        return removePKCS7Padding(paddedPlaintext);
    }

    @Override
    public String getModeName() {
        return "ECB";
    }

    /**
     * Adds PKCS#7 padding to the data
     * PKCS#7: If data needs n bytes of padding, add n bytes each with value n
     * @param data The data to pad
     * @return Padded data
     */
    private byte[] addPKCS7Padding(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = new byte[data.length + paddingLength];

        // Copy original data
        System.arraycopy(data, 0, padded, 0, data.length);

        // Add padding bytes
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }

        return padded;
    }

    /**
     * Removes PKCS#7 padding from the data
     * @param paddedData The padded data
     * @return Original data without padding
     * @throws IllegalArgumentException if padding is invalid
     */
    private byte[] removePKCS7Padding(byte[] paddedData) {
        if (paddedData == null || paddedData.length == 0) {
            throw new IllegalArgumentException("Padded data cannot be null or empty");
        }

        // Get padding length from last byte
        int paddingLength = paddedData[paddedData.length - 1] & 0xFF;

        // Validate padding length
        if (paddingLength < 1 || paddingLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid padding length: " + paddingLength);
        }

        if (paddingLength > paddedData.length) {
            throw new IllegalArgumentException("Padding length exceeds data length");
        }

        // Verify all padding bytes have correct value
        for (int i = paddedData.length - paddingLength; i < paddedData.length; i++) {
            if ((paddedData[i] & 0xFF) != paddingLength) {
                throw new IllegalArgumentException("Invalid padding bytes");
            }
        }

        // Remove padding
        byte[] data = new byte[paddedData.length - paddingLength];
        System.arraycopy(paddedData, 0, data, 0, data.length);

        return data;
    }
}