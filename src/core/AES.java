package core;

public class AES {

    //S-box
    private static final int[] SBOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // Inverse S-box for decryption
    private static final int[] INV_SBOX = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // Round constants
    private static final int[] RCON = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
    };

    private byte[] expandedKey;
    private int rounds;

    /**
     * Initializes AES with a key
     */
    public AES(byte[] key, KeySize keySize)
    {
        if (key.length != keySize.getBytesAmount()) throw new IllegalArgumentException("Incorrect key size");

        this.expandedKey = expandKey(key, keySize);
        this.rounds = keySize.getRounds();
    }

    /**
     * Encrypt a 16-byte block
     */
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext.length != 16) {
            throw new IllegalArgumentException("Block must be 16 bytes");
        }

        // Copy plaintext to state (column-major order)
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = plaintext[i * 4 + j];
            }
        }

        // Initial round - just AddRoundKey
        addRoundKey(state, 0);

        // Main rounds (rounds - 1)
        for (int round = 1; round < rounds; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }

        // Final round (no MixColumns)
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, rounds);

        // Convert state back to byte array
        byte[] ciphertext = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ciphertext[i * 4 + j] = state[j][i];
            }
        }

        return ciphertext;
    }

    /**
     * Decrypt a 16-byte block
     */
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext.length != 16) {
            throw new IllegalArgumentException("Block must be 16 bytes");
        }

        // Copy ciphertext to state
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = ciphertext[i * 4 + j];
            }
        }

        // Initial round
        addRoundKey(state, rounds);

        // Main rounds (in reverse)
        for (int round = rounds - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }

        // Final round
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        // Convert state back to byte array
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                plaintext[i * 4 + j] = state[j][i];
            }
        }

        return plaintext;
    }

    // ==================== ENCRYPTION OPERATIONS ====================

    /**
     * SubBytes - substitute each byte using S-box
     */
    private void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = (byte) SBOX[state[i][j] & 0xFF];
            }
        }
    }

    /**
     * Row 0: no shift
     * Row 1: shift left by 1
     * Row 2: shift left by 2
     * Row 3: shift left by 3
     */

    //Yeah, its hardcoded, why not?
    private void shiftRows(byte[][] state) {
        byte temp;

        // Row 1: shift left by 1
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        // Row 2: shift left by 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Row 3: shift left by 3 (right by 1)
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
    }

    /**
     * MixColumns - mix data within each column
     */
    private void mixColumns(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            byte[] col = new byte[4];
            col[0] = state[0][i];
            col[1] = state[1][i];
            col[2] = state[2][i];
            col[3] = state[3][i];

            state[0][i] = (byte) (gfMul(0x02, col[0]) ^ gfMul(0x03, col[1]) ^ col[2] ^ col[3]);
            state[1][i] = (byte) (col[0] ^ gfMul(0x02, col[1]) ^ gfMul(0x03, col[2]) ^ col[3]);
            state[2][i] = (byte) (col[0] ^ col[1] ^ gfMul(0x02, col[2]) ^ gfMul(0x03, col[3]));
            state[3][i] = (byte) (gfMul(0x03, col[0]) ^ col[1] ^ col[2] ^ gfMul(0x02, col[3]));
        }
    }

    /**
     * AddRoundKey - XOR state with round key
     */
    private void addRoundKey(byte[][] state, int round) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] ^= expandedKey[round * 16 + i * 4 + j];
            }
        }
    }

    // ==================== DECRYPTION OPERATIONS ====================

    /**
     * Inverse SubBytes
     */
    private void invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = (byte) INV_SBOX[state[i][j] & 0xFF];
            }
        }
    }

    /**
     * Inverse ShiftRows
     */
    private void invShiftRows(byte[][] state) {
        byte temp;

        // Row 1: shift right by 1 (or left by 3)
        temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // Row 2: shift right by 2
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Row 3: shift right by 3 (or left by 1)
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    /**
     * Inverse MixColumns
     */
    private void invMixColumns(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            byte[] col = new byte[4];
            col[0] = state[0][i];
            col[1] = state[1][i];
            col[2] = state[2][i];
            col[3] = state[3][i];

            state[0][i] = (byte) (gfMul(0x0e, col[0]) ^ gfMul(0x0b, col[1]) ^
                    gfMul(0x0d, col[2]) ^ gfMul(0x09, col[3]));
            state[1][i] = (byte) (gfMul(0x09, col[0]) ^ gfMul(0x0e, col[1]) ^
                    gfMul(0x0b, col[2]) ^ gfMul(0x0d, col[3]));
            state[2][i] = (byte) (gfMul(0x0d, col[0]) ^ gfMul(0x09, col[1]) ^
                    gfMul(0x0e, col[2]) ^ gfMul(0x0b, col[3]));
            state[3][i] = (byte) (gfMul(0x0b, col[0]) ^ gfMul(0x0d, col[1]) ^
                    gfMul(0x09, col[2]) ^ gfMul(0x0e, col[3]));
        }
    }

    // ==================== GALOIS FIELD OPERATIONS ====================

    /**
     * Multiply in GF(2^8)
     */
    private int gfMul(int a, int b) {
        int p = 0;

        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }

            boolean highBitSet = (a & 0x80) != 0;
            a <<= 1;

            if (highBitSet) {
                a ^= 0x1B;  // x^8 + x^4 + x^3 + x + 1
            }

            b >>= 1;
        }

        return p & 0xFF;
    }

    // ==================== KEY EXPANSION ====================

    private byte[] expandKey(byte[] key, KeySize keySize) {
        int keyWords = keySize.getWords();
        int rounds = keySize.getRounds();
        int totalWords = keyWords * (rounds + 1);

        int[] w = new int[totalWords];

        // Copy original key
        for (int i = 0; i < keyWords; i++) {
            w[i] = bytesToWord(key, i * 4);
        }

        // Generate remaining words
        for (int i = keyWords; i < totalWords; i++) {
            int temp = w[i - 1];

            if (i % keyWords == 0) {
                // Apply transformation every keyWords-th word
                temp = subWord(rotWord(temp)) ^ (RCON[i / keyWords] << 24);
            }
            else if (keyWords == 8 && i % keyWords == 4) {
                // AES-256 only: additional SubWord at position 4
                temp = subWord(temp);
            }

            w[i] = w[i - keyWords] ^ temp;
        }

        // Convert to bytes
        byte[] expandedKey = new byte[totalWords * 4];
        for (int i = 0; i < totalWords; i++) {
            wordToBytes(w[i], expandedKey, i * 4);
        }

        return expandedKey;
    }

    private int rotWord(int word) {
        return (word << 8) | ((word >>> 24) & 0xFF);
    }

    private int subWord(int word) {
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int byteVal = (word >>> (24 - i * 8)) & 0xFF;
            result |= (SBOX[byteVal] << (24 - i * 8));
        }
        return result;
    }

    private int bytesToWord(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 24) |
                ((bytes[offset + 1] & 0xFF) << 16) |
                ((bytes[offset + 2] & 0xFF) << 8) |
                (bytes[offset + 3] & 0xFF);
    }

    private void wordToBytes(int word, byte[] bytes, int offset) {
        bytes[offset] = (byte) (word >>> 24);
        bytes[offset + 1] = (byte) (word >>> 16);
        bytes[offset + 2] = (byte) (word >>> 8);
        bytes[offset + 3] = (byte) word;
    }

    // ==================== UTILITY METHODS ====================

    /**
     * Convert byte array to hex string
     */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Convert hex string to byte array
     */
    public static byte[] hexStringToBytes(String hex) {
        // Remove spaces and make lowercase
        hex = hex.replaceAll("\\s+", "").toLowerCase();

        // Check if valid length (must be even)
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        // Create byte array
        byte[] bytes = new byte[hex.length() / 2];

        // Convert each pair of hex digits to a byte
        for (int i = 0; i < hex.length(); i += 2) {
            String hexByte = hex.substring(i, i + 2);
            bytes[i / 2] = (byte) Integer.parseInt(hexByte, 16);
        }

        return bytes;
    }

    /**
     * Print state matrix for debugging
     */
    private void printState(byte[][] state, String label) {
        System.out.println(label + ":");
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.printf("%02x ", state[i][j] & 0xFF);
            }
            System.out.println();
        }
        System.out.println();
    }
}
