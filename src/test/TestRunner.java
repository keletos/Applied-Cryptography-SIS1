package test;

import core.AES;
import core.AESBlockCipher;
import core.KeySize;
import modes.*;
import random.RNG;
import java.util.Arrays;

/**
 * Automated Test Runner for Report Generation
 * Run this to validate all requirements
 */
public class TestRunner {

    private static int passed = 0;
    private static int failed = 0;
    private static RNG rng = new RNG();
    private static AESBlockCipher aes = new AESBlockCipher();

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║           AES IMPLEMENTATION TEST SUITE                    ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        long startTime = System.currentTimeMillis();

        // Run all tests
        testNISTVectors();
        testRoundTrip();
        testPadding();
        testGCMAuthentication();
        testLargeData();

        long endTime = System.currentTimeMillis();

        // Summary
        System.out.println("\n" + "═".repeat(60));
        System.out.println("SUMMARY");
        System.out.println("═".repeat(60));
        System.out.println("Total tests:  " + (passed + failed));
        System.out.println("Passed:       " + passed + " ✓");
        System.out.println("Failed:       " + failed + " ✗");
        System.out.println("Success rate: " + (100 * passed / (passed + failed)) + "%");
        System.out.println("Time:         " + (endTime - startTime) + " ms");
        System.out.println("═".repeat(60));

        if (failed == 0) {
            System.out.println("\n✓ ALL TESTS PASSED - Ready for submission!");
        } else {
            System.out.println("\n✗ SOME TESTS FAILED - Review implementation");
        }
    }

    // ==================== NIST TEST VECTORS ====================

    private static void testNISTVectors() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("TEST 1: NIST Test Vectors");
        System.out.println("─".repeat(60));

        // AES-128
        testVector("AES-128",
                "2b7e151628aed2a6abf7158809cf4f3c",
                "6bc1bee22e409f96e93d7e117393172a",
                "3ad77bb40d7a3660a89ecaf32466ef97",
                KeySize.K128);

        // AES-192
        testVector("AES-192",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "6bc1bee22e409f96e93d7e117393172a",
                "bd334f1d6e45f25ff712a214571fa5cc",
                KeySize.K192);

        // AES-256
        testVector("AES-256",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "6bc1bee22e409f96e93d7e117393172a",
                "f3eed1bdb5d2a03c064b5a7e3db181f8",
                KeySize.K256);
    }

    private static void testVector(String name, String keyHex, String ptHex, String ctHex, KeySize ks) {
        try {
            byte[] key = hexToBytes(keyHex);
            byte[] plaintext = hexToBytes(ptHex);
            byte[] expected = hexToBytes(ctHex);

            System.out.println("\n" + name + ":");
            System.out.println("  Key:       " + keyHex);
            System.out.println("  Plaintext: " + ptHex);
            System.out.println("  Expected:  " + ctHex);

            byte[] actual = aes.encryptBlock(plaintext, key);
            System.out.println("  Got:       " + bytesToHex(actual));

            if (Arrays.equals(expected, actual)) {
                System.out.println("  ✓ PASS");
                passed++;
            } else {
                System.out.println("  ✗ FAIL");
                failed++;
            }
        } catch (Exception e) {
            System.out.println("  ✗ ERROR: " + e.getMessage());
            failed++;
        }
    }

    // ==================== ROUND-TRIP TEST ====================

    private static void testRoundTrip() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("TEST 2: Round-Trip (Encrypt → Decrypt)");
        System.out.println("─".repeat(60));

        String[] messages = {
                "Hello",
                "The quick brown fox",
                "AES encryption test with multiple blocks of data for testing purposes"
        };

        CipherMode[] modes = {
                new ECBMode(aes),
                new CBCMode(aes, rng),
                new CTRMode(aes, rng),
                new GCMMode(aes, rng)
        };

        for (CipherMode mode : modes) {
            for (String msg : messages) {
                try {
                    byte[] plaintext = msg.getBytes();
                    byte[] key = rng.randomBytes(16);

                    byte[] encrypted = mode.encrypt(plaintext, key);
                    byte[] decrypted = mode.decrypt(encrypted, key);

                    if (Arrays.equals(plaintext, decrypted)) {
                        System.out.println("✓ " + mode.getModeName() + " - " + msg.length() + " bytes");
                        passed++;
                    } else {
                        System.out.println("✗ " + mode.getModeName() + " - Failed");
                        failed++;
                    }
                } catch (Exception e) {
                    System.out.println("✗ " + mode.getModeName() + " - Error: " + e.getMessage());
                    failed++;
                }
            }
        }
    }

    // ==================== PADDING TEST ====================

    private static void testPadding() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("TEST 3: PKCS#7 Padding");
        System.out.println("─".repeat(60));

        CBCMode cbc = new CBCMode(aes, rng);
        byte[] key = rng.randomBytes(16);

        // Test different lengths (1-16 bytes)
        for (int len = 1; len <= 16; len++) {
            try {
                byte[] plaintext = rng.randomBytes(len);
                byte[] encrypted = cbc.encrypt(plaintext, key);
                byte[] decrypted = cbc.decrypt(encrypted, key);

                if (Arrays.equals(plaintext, decrypted)) {
                    System.out.println("✓ Length " + len + " bytes (padding: " + (16 - len % 16) + ")");
                    passed++;
                } else {
                    System.out.println("✗ Length " + len + " bytes - Failed");
                    failed++;
                }
            } catch (Exception e) {
                System.out.println("✗ Length " + len + " - Error: " + e.getMessage());
                failed++;
            }
        }
    }

    // ==================== GCM AUTHENTICATION TEST ====================

    private static void testGCMAuthentication() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("TEST 4: GCM Authentication");
        System.out.println("─".repeat(60));

        GCMMode gcm = new GCMMode(aes, rng);
        byte[] key = rng.randomBytes(16);
        byte[] plaintext = "Secret message".getBytes();

        try {
            // Valid decryption
            byte[] encrypted = gcm.encrypt(plaintext, key);
            byte[] decrypted = gcm.decrypt(encrypted, key);

            if (Arrays.equals(plaintext, decrypted)) {
                System.out.println("✓ Valid GCM decryption");
                passed++;
            } else {
                System.out.println("✗ GCM decryption failed");
                failed++;
            }

            // Tampered ciphertext
            byte[] tampered = encrypted.clone();
            tampered[20] ^= 0x01;

            try {
                gcm.decrypt(tampered, key);
                System.out.println("✗ Should reject tampered data");
                failed++;
            } catch (IllegalArgumentException e) {
                System.out.println("✓ Correctly rejects tampered data");
                passed++;
            }

        } catch (Exception e) {
            System.out.println("✗ Error: " + e.getMessage());
            failed++;
        }
    }

    // ==================== LARGE DATA TEST ====================

    private static void testLargeData() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("TEST 5: Large Data (>1 MB)");
        System.out.println("─".repeat(60));

        CBCMode cbc = new CBCMode(aes, rng);
        byte[] key = rng.randomBytes(16);

        int[] sizes = {1024 * 1024, 2 * 1024 * 1024}; // 1 MB, 2 MB

        for (int size : sizes) {
            try {
                System.out.print("Testing " + (size / 1024 / 1024) + " MB... ");

                byte[] plaintext = rng.randomBytes(size);
                long start = System.currentTimeMillis();
                byte[] encrypted = cbc.encrypt(plaintext, key);
                byte[] decrypted = cbc.decrypt(encrypted, key);
                long end = System.currentTimeMillis();

                if (Arrays.equals(plaintext, decrypted)) {
                    System.out.println("✓ PASS (" + (end - start) + " ms)");
                    passed++;
                } else {
                    System.out.println("✗ FAIL");
                    failed++;
                }
            } catch (Exception e) {
                System.out.println("✗ Error: " + e.getMessage());
                failed++;
            }
        }
    }

    // ==================== UTILITIES ====================

    private static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}