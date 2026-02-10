package core;

/**
 * Adapter для совместимости режимов шифрования с AES
 * Предоставляет методы encryptBlock/decryptBlock с параметром key
 */
public class AESBlockCipher {

    /**
     * Шифрование одного блока с указанным ключом
     */
    public byte[] encryptBlock(byte[] block, byte[] key) {
        if (block.length != 16) {
            throw new IllegalArgumentException("Block must be 16 bytes");
        }

        KeySize keySize = determineKeySize(key);
        AES aes = new AES(key, keySize);
        return aes.encrypt(block);
    }

    /**
     * Дешифрование одного блока с указанным ключом
     */
    public byte[] decryptBlock(byte[] block, byte[] key) {
        if (block.length != 16) {
            throw new IllegalArgumentException("Block must be 16 bytes");
        }

        KeySize keySize = determineKeySize(key);
        AES aes = new AES(key, keySize);
        return aes.decrypt(block);
    }

    /**
     * Определение размера ключа
     */
    private KeySize determineKeySize(byte[] key) {
        return switch (key.length) {
            case 16 -> KeySize.K128;
            case 24 -> KeySize.K192;
            case 32 -> KeySize.K256;
            default -> throw new IllegalArgumentException("Invalid key length: " + key.length +
                    ". Must be 16, 24, or 32 bytes.");
        };
    }
}