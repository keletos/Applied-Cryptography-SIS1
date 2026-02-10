package test;

import core.AESBlockCipher;
import core.KeySize;
import modes.*;
import random.RNG;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Scanner;

/**
 * Interactive Console Application for AES Encryption/Decryption
 */
public class AESConsoleApp {

    private Scanner scanner;
    private RNG rng;
    private AESBlockCipher aesCore;

    // Current configuration
    private KeySize selectedKeySize = KeySize.K128;
    private String selectedMode = "CBC";
    private byte[] currentKey = null;

    public AESConsoleApp() {
        this.scanner = new Scanner(System.in);
        this.rng = new RNG();
        this.aesCore = new AESBlockCipher();
    }

    public static void main(String[] args) {
        AESConsoleApp app = new AESConsoleApp();
        app.run();
    }

    public void run() {
        printWelcomeBanner();

        while (true) {
            printMainMenu();
            int choice = getMenuChoice(1, 7);

            switch (choice) {
                case 1:
                    selectKeySize();
                    break;
                case 2:
                    selectMode();
                    break;
                case 3:
                    keyManagement();
                    break;
                case 4:
                    encryptOperation();
                    break;
                case 5:
                    decryptOperation();
                    break;
                case 6:
                    runTestVectors();
                    break;
                case 7:
                    System.out.println("\nGoodbye!");
                    return;
            }
        }
    }

    private void printWelcomeBanner() {
        System.out.println("\n╔════════════════════════════════════════════════════════════╗");
        System.out.println("║        AES ENCRYPTION/DECRYPTION CONSOLE APPLICATION       ║");
        System.out.println("║              Educational Implementation                    ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");
    }

    private void printMainMenu() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("MAIN MENU");
        System.out.println("─".repeat(60));
        System.out.println("Current Settings:");
        System.out.println("  Key Size: " + selectedKeySize);
        System.out.println("  Mode:     " + selectedMode);
        System.out.println("  Key:      " + (currentKey != null ? "SET (" + currentKey.length + " bytes)" : "NOT SET"));
        System.out.println("─".repeat(60));
        System.out.println("1. Select Key Size (AES-128/192/256)");
        System.out.println("2. Select Cipher Mode (ECB/CBC/CTR/GCM)");
        System.out.println("3. Key Management (Generate/Enter)");
        System.out.println("4. Encrypt");
        System.out.println("5. Decrypt");
        System.out.println("6. Run NIST Test Vectors");
        System.out.println("7. Exit");
        System.out.println("─".repeat(60));
        System.out.print("Enter choice: ");
    }

    // ==================== KEY SIZE SELECTION ====================

    private void selectKeySize() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("SELECT KEY SIZE");
        System.out.println("─".repeat(60));
        System.out.println("1. AES-128 (16 bytes)");
        System.out.println("2. AES-192 (24 bytes)");
        System.out.println("3. AES-256 (32 bytes)");
        System.out.println("─".repeat(60));
        System.out.print("Enter choice: ");

        int choice = getMenuChoice(1, 3);

        switch (choice) {
            case 1:
                selectedKeySize = KeySize.K128;
                break;
            case 2:
                selectedKeySize = KeySize.K192;
                break;
            case 3:
                selectedKeySize = KeySize.K256;
                break;
        }

        System.out.println("✓ Key size set to: " + selectedKeySize);

        // Clear current key if size changed
        if (currentKey != null && currentKey.length != selectedKeySize.getBytesAmount()) {
            currentKey = null;
            System.out.println("⚠ Previous key cleared (size mismatch)");
        }
    }

    // ==================== MODE SELECTION ====================

    private void selectMode() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("SELECT CIPHER MODE");
        System.out.println("─".repeat(60));
        System.out.println("1. ECB (Electronic Codebook) - Simple but insecure");
        System.out.println("2. CBC (Cipher Block Chaining) - Secure with IV");
        System.out.println("3. CTR (Counter) - Stream cipher mode");
        System.out.println("4. GCM (Galois/Counter Mode) - Authenticated encryption");
        System.out.println("─".repeat(60));
        System.out.print("Enter choice: ");

        int choice = getMenuChoice(1, 4);

        switch (choice) {
            case 1:
                selectedMode = "ECB";
                System.out.println("⚠ WARNING: ECB mode is not secure for most applications!");
                break;
            case 2:
                selectedMode = "CBC";
                break;
            case 3:
                selectedMode = "CTR";
                break;
            case 4:
                selectedMode = "GCM";
                break;
        }

        System.out.println("✓ Mode set to: " + selectedMode);
    }

    // ==================== KEY MANAGEMENT ====================

    private void keyManagement() {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("KEY MANAGEMENT");
        System.out.println("─".repeat(60));
        System.out.println("1. Generate Random Key");
        System.out.println("2. Enter Key Manually (Hex)");
        System.out.println("3. View Current Key");
        System.out.println("4. Back to Main Menu");
        System.out.println("─".repeat(60));
        System.out.print("Enter choice: ");

        int choice = getMenuChoice(1, 4);

        switch (choice) {
            case 1:
                generateRandomKey();
                break;
            case 2:
                enterKeyManually();
                break;
            case 3:
                viewCurrentKey();
                break;
            case 4:
                return;
        }
    }

    private void generateRandomKey() {
        currentKey = rng.randomBytes(selectedKeySize.getBytesAmount());
        System.out.println("\n✓ Random key generated!");
        System.out.println("Key (hex): " + bytesToHex(currentKey));
        System.out.println("Key (base64): " + bytesToBase64(currentKey));
    }

    private void enterKeyManually() {
        System.out.println("\nEnter key in hexadecimal format (without spaces)");
        System.out.println("Required length: " + (selectedKeySize.getBytesAmount() * 2) + " hex characters");
        System.out.print("Key: ");

        String hexKey = scanner.nextLine().trim().replaceAll("\\s+", "");

        try {
            byte[] key = hexToBytes(hexKey);

            if (key.length != selectedKeySize.getBytesAmount()) {
                System.out.println("✗ Error: Key must be " + selectedKeySize.getBytesAmount() + " bytes");
                return;
            }

            currentKey = key;
            System.out.println("✓ Key set successfully!");
        } catch (Exception e) {
            System.out.println("✗ Error: Invalid hexadecimal format");
        }
    }

    private void viewCurrentKey() {
        if (currentKey == null) {
            System.out.println("\n⚠ No key set");
            return;
        }

        System.out.println("\nCurrent Key:");
        System.out.println("  Hex:    " + bytesToHex(currentKey));
        System.out.println("  Base64: " + bytesToBase64(currentKey));
        System.out.println("  Length: " + currentKey.length + " bytes");
    }

    // ==================== ENCRYPTION ====================

    private void encryptOperation() {
        if (currentKey == null) {
            System.out.println("\n✗ Error: Please set a key first (Option 3)");
            return;
        }

        System.out.println("\n" + "─".repeat(60));
        System.out.println("ENCRYPTION");
        System.out.println("─".repeat(60));
        System.out.println("1. Enter Text (UTF-8)");
        System.out.println("2. Enter Hex");
        System.out.println("3. Load from File");
        System.out.println("4. Back");
        System.out.println("─".repeat(60));
        System.out.print("Enter choice: ");

        int choice = getMenuChoice(1, 4);
        if (choice == 4) return;

        byte[] plaintext = null;

        switch (choice) {
            case 1:
                plaintext = getTextInput();
                break;
            case 2:
                plaintext = getHexInput();
                break;
            case 3:
                plaintext = loadFromFile();
                break;
        }

        if (plaintext == null || plaintext.length == 0) {
            System.out.println("✗ Error: No data to encrypt");
            return;
        }

        try {
            System.out.println("\nEncrypting...");
            long startTime = System.nanoTime();

            CipherMode mode = getCipherMode();
            byte[] ciphertext = mode.encrypt(plaintext, currentKey);

            long endTime = System.nanoTime();
            double timeMs = (endTime - startTime) / 1_000_000.0;

            System.out.println("✓ Encryption successful!");
            System.out.println("Time: " + String.format("%.2f", timeMs) + " ms");

            displayOutput(ciphertext, plaintext.length);
        } catch (Exception e) {
            System.out.println("✗ Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ==================== DECRYPTION ====================

    private void decryptOperation() {
        if (currentKey == null) {
            System.out.println("\n✗ Error: Please set a key first (Option 3)");
            return;
        }

        System.out.println("\n" + "─".repeat(60));
        System.out.println("DECRYPTION");
        System.out.println("─".repeat(60));
        System.out.println("1. Enter Hex");
        System.out.println("2. Enter Base64");
        System.out.println("3. Load from File");
        System.out.println("4. Back");
        System.out.println("─".repeat(60));
        System.out.print("Enter choice: ");

        int choice = getMenuChoice(1, 4);
        if (choice == 4) return;

        byte[] ciphertext = null;

        switch (choice) {
            case 1:
                ciphertext = getHexInput();
                break;
            case 2:
                ciphertext = getBase64Input();
                break;
            case 3:
                ciphertext = loadFromFile();
                break;
        }

        if (ciphertext == null || ciphertext.length == 0) {
            System.out.println("✗ Error: No data to decrypt");
            return;
        }

        try {
            System.out.println("\nDecrypting...");
            long startTime = System.nanoTime();

            CipherMode mode = getCipherMode();
            byte[] plaintext = mode.decrypt(ciphertext, currentKey);

            long endTime = System.nanoTime();
            double timeMs = (endTime - startTime) / 1_000_000.0;

            System.out.println("✓ Decryption successful!");
            System.out.println("Time: " + String.format("%.2f", timeMs) + " ms");

            displayDecryptedOutput(plaintext);
        } catch (Exception e) {
            System.out.println("✗ Error: " + e.getMessage());
        }
    }

    // ==================== TEST VECTORS ====================

    private void runTestVectors() {
        System.out.println("\n" + "═".repeat(60));
        System.out.println("NIST TEST VECTORS");
        System.out.println("═".repeat(60));

        // AES-128 Test Vector
        System.out.println("\n--- AES-128 Test Vector ---");
        testVector(
                "2b7e151628aed2a6abf7158809cf4f3c",
                "6bc1bee22e409f96e93d7e117393172a",
                "3ad77bb40d7a3660a89ecaf32466ef97",
                KeySize.K128
        );

        // AES-192 Test Vector
        System.out.println("\n--- AES-192 Test Vector ---");
        testVector(
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "6bc1bee22e409f96e93d7e117393172a",
                "bd334f1d6e45f25ff712a214571fa5cc",
                KeySize.K192
        );

        // AES-256 Test Vector
        System.out.println("\n--- AES-256 Test Vector ---");
        testVector(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "6bc1bee22e409f96e93d7e117393172a",
                "f3eed1bdb5d2a03c064b5a7e3db181f8",
                KeySize.K256
        );

        System.out.println("\n" + "═".repeat(60));
        System.out.print("\nPress Enter to continue...");
        scanner.nextLine();
    }

    private void testVector(String keyHex, String plaintextHex, String expectedHex, KeySize keySize) {
        try {
            byte[] key = hexToBytes(keyHex);
            byte[] plaintext = hexToBytes(plaintextHex);
            byte[] expected = hexToBytes(expectedHex);

            System.out.println("Key:       " + keyHex);
            System.out.println("Plaintext: " + plaintextHex);
            System.out.println("Expected:  " + expectedHex);

            // Encrypt using our AES core directly (no mode)
            byte[] actual = aesCore.encryptBlock(plaintext, key);

            System.out.println("Got:       " + bytesToHex(actual));

            if (java.util.Arrays.equals(expected, actual)) {
                System.out.println("✓ PASS");
            } else {
                System.out.println("✗ FAIL");
            }
        } catch (Exception e) {
            System.out.println("✗ ERROR: " + e.getMessage());
        }
    }

    // ==================== HELPER METHODS ====================

    private CipherMode getCipherMode() {
        switch (selectedMode) {
            case "ECB":
                return new ECBMode(aesCore);
            case "CTR":
                return new CTRMode(aesCore, rng);
            case "GCM":
                return new GCMMode(aesCore, rng);
            default:
                return new CBCMode(aesCore, rng);
        }
    }

    private byte[] getTextInput() {
        System.out.print("\nEnter text: ");
        String text = scanner.nextLine();
        return text.getBytes();
    }

    private byte[] getHexInput() {
        System.out.print("\nEnter hex (without spaces): ");
        String hex = scanner.nextLine().trim().replaceAll("\\s+", "");
        try {
            return hexToBytes(hex);
        } catch (Exception e) {
            System.out.println("✗ Error: Invalid hex format");
            return null;
        }
    }

    private byte[] getBase64Input() {
        System.out.print("\nEnter base64: ");
        String base64 = scanner.nextLine().trim();
        try {
            return Base64.getDecoder().decode(base64);
        } catch (Exception e) {
            System.out.println("✗ Error: Invalid base64 format");
            return null;
        }
    }

    private byte[] loadFromFile() {
        System.out.print("\nEnter file path: ");
        String path = scanner.nextLine().trim();

        try {
            return Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            System.out.println("✗ Error: Cannot read file - " + e.getMessage());
            return null;
        }
    }

    private void displayOutput(byte[] data, int originalLength) {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("OUTPUT");
        System.out.println("─".repeat(60));
        System.out.println("Original length: " + originalLength + " bytes");
        System.out.println("Output length:   " + data.length + " bytes");
        System.out.println("─".repeat(60));

        // Show in multiple formats
        System.out.println("\n[HEX]");
        System.out.println(bytesToHex(data));

        System.out.println("\n[BASE64]");
        System.out.println(bytesToBase64(data));

        // Ask to save
        System.out.print("\nSave to file? (y/n): ");
        String response = scanner.nextLine().trim().toLowerCase();

        if (response.equals("y") || response.equals("yes")) {
            saveToFile(data);
        }
    }

    private void displayDecryptedOutput(byte[] data) {
        System.out.println("\n" + "─".repeat(60));
        System.out.println("DECRYPTED OUTPUT");
        System.out.println("─".repeat(60));
        System.out.println("Length: " + data.length + " bytes");
        System.out.println("─".repeat(60));

        // Try to display as text
        System.out.println("\n[TEXT]");
        try {
            String text = new String(data, "UTF-8");
            if (isPrintable(text)) {
                System.out.println(text);
            } else {
                System.out.println("(Binary data - not printable)");
            }
        } catch (Exception e) {
            System.out.println("(Cannot display as text)");
        }

        System.out.println("\n[HEX]");
        System.out.println(bytesToHex(data));

        // Ask to save
        System.out.print("\nSave to file? (y/n): ");
        String response = scanner.nextLine().trim().toLowerCase();

        if (response.equals("y") || response.equals("yes")) {
            saveToFile(data);
        }
    }

    private void saveToFile(byte[] data) {
        System.out.print("Enter output file path: ");
        String path = scanner.nextLine().trim();

        try {
            Files.write(Paths.get(path), data);
            System.out.println("✓ File saved successfully!");
        } catch (IOException e) {
            System.out.println("✗ Error: Cannot save file - " + e.getMessage());
        }
    }

    private int getMenuChoice(int min, int max) {
        while (true) {
            try {
                String input = scanner.nextLine().trim();
                int choice = Integer.parseInt(input);
                if (choice >= min && choice <= max) {
                    return choice;
                } else {
                    System.out.print("Invalid choice. Enter " + min + "-" + max + ": ");
                }
            } catch (NumberFormatException e) {
                System.out.print("Invalid input. Enter a number: ");
            }
        }
    }

    private boolean isPrintable(String text) {
        for (char c : text.toCharArray()) {
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
                return false;
            }
        }
        return true;
    }

    // Conversion utilities
    private byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}