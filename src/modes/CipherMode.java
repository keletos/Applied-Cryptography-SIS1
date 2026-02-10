package modes;

/**
 * Base interface for AES cipher modes of operation
 * All modes must implement encryption and decryption operations
 */
public interface CipherMode {

    /**
     * Encrypts plaintext using the specified mode
     * @param plaintext The data to encrypt
     * @param key The encryption key (128, 192, or 256 bits)
     * @return Encrypted ciphertext (may include IV/nonce prepended)
     */
    byte[] encrypt(byte[] plaintext, byte[] key);

    /**
     * Decrypts ciphertext using the specified mode
     * @param ciphertext The data to decrypt (may include IV/nonce)
     * @param key The decryption key
     * @return Decrypted plaintext
     * @throws IllegalArgumentException if decryption fails or authentication fails
     */
    byte[] decrypt(byte[] ciphertext, byte[] key) throws IllegalArgumentException;

    /**
     * Gets the name of this cipher mode
     * @return Mode name (e.g., "ECB", "CBC", "CTR", "GCM")
     */
    String getModeName();
}