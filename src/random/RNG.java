package random;

import java.util.ArrayList;
import java.util.List;

public class RNG {
    private long state;
    private long sequence; // For additional state complexity

    // Источники энтропии
    private long getTimeNano() {
        return System.nanoTime();
    }

    private long getThreadId() {
        return Thread.currentThread().getId();
    }

    private long getProcessId() {
        // Java 9+ has ProcessHandle.current().pid()
        // Fallback: use runtime memory address as entropy
        return System.identityHashCode(this);
    }

    private long getMemoryEntropy() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.freeMemory() ^ runtime.totalMemory();
    }

    // Новый источник: timing от пользовательского ввода или операций
    private long getUserTimingEntropy() {
        long start = System.nanoTime();
        // Симулируем некоторую работу для создания вариативности
        int dummy = 0;
        for (int i = 0; i < 100; i++) {
            dummy += i * i;
        }
        long end = System.nanoTime();
        return end - start + dummy;
    }

    // Конструктор — сбор энтропии и инициализация seed
    public RNG() {
        collectEntropy();
    }

    // Сбор энтропии из множественных источников
    private void collectEntropy() {
        long timeEntropy = getTimeNano();
        long threadEntropy = getThreadId();
        long processEntropy = getProcessId();
        long memoryEntropy = getMemoryEntropy();
        long timingEntropy = getUserTimingEntropy();

        // Улучшенное смешивание энтропии
        // Используем комбинацию XOR, вращения битов и умножения
        state = timeEntropy;
        state = mixEntropy(state, threadEntropy);
        state = mixEntropy(state, processEntropy);
        state = mixEntropy(state, memoryEntropy);
        state = mixEntropy(state, timingEntropy);

        // Инициализируем sequence для дополнительной сложности
        sequence = state ^ 0x123456789ABCDEFL;

        // Прогреваем генератор (discard первые значения)
        for (int i = 0; i < 20; i++) {
            nextInt();
        }
    }

    // Функция смешивания энтропии (более надежная чем простой XOR)
    private long mixEntropy(long a, long b) {
        // Применяем XOR, rotation и умножение для лучшего перемешивания
        a ^= b;
        a ^= (a << 13);
        a ^= (a >>> 17);
        a ^= (a << 5);
        return a * 0x5DEECE66DL + 0xBL;
    }

    // Улучшенный Linear Congruential Generator (64-bit)
    public int nextInt() {
        // LCG с параметрами из Numerical Recipes
        state = (state * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);

        // Добавляем sequence для увеличения периода
        sequence += 0x9E3779B97F4A7C15L;

        // Комбинируем state и sequence для лучшего распределения
        long result = state + sequence;

        // Применяем дополнительное перемешивание (tempering)
        result ^= (result >>> 12);
        result ^= (result << 25);
        result ^= (result >>> 27);

        return (int) (result >>> 32);
    }

    // Альтернативный метод: получить long
    public long nextLong() {
        return ((long) nextInt() << 32) | (nextInt() & 0xFFFFFFFFL);
    }

    // Генерация числа в диапазоне [0, bound)
    public int nextInt(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("bound must be positive");
        }

        int r = nextInt() & Integer.MAX_VALUE;
        int m = bound - 1;

        // Для степеней двойки
        if ((bound & m) == 0) {
            return (int) ((bound * (long) r) >> 31);
        }

        // Общий случай - избегаем модуло bias
        for (int u = r; u - (r = u % bound) + m < 0; u = nextInt() & Integer.MAX_VALUE);
        return r;
    }

    // Генерация массива случайных байт
    public byte[] randomBytes(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("n must be non-negative");
        }

        byte[] bytes = new byte[n];
        for (int i = 0; i < n; i++) {
            bytes[i] = (byte) nextInt();
        }
        return bytes;
    }

    // Метод для re-seeding (добавление новой энтропии)
    public void reseed() {
        collectEntropy();
    }

    // Вспомогательная функция для вывода в hex
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString();
    }

    // Демонстрация сбора энтропии
    public void printEntropyInfo() {
        System.out.println("=== Entropy Sources ===");
        System.out.println("Time (nano):    " + getTimeNano());
        System.out.println("Thread ID:      " + getThreadId());
        System.out.println("Process ID:     " + getProcessId());
        System.out.println("Memory:         " + getMemoryEntropy());
        System.out.println("User Timing:    " + getUserTimingEntropy());
        System.out.println("Current State:  " + state);
        System.out.println("Current Seq:    " + sequence);
    }

//    // Тест RNG
//    public static void main(String[] args) {
//        RNG rng = new RNG();
//
//        System.out.println("=== Demonstrating Entropy Collection ===\n");
//        rng.printEntropyInfo();
//
//        System.out.println("\n=== Generated Cryptographic Material ===\n");
//
//        byte[] key = rng.randomBytes(16); // AES-128 key
//        System.out.println("Generated 128-bit key:\n" + bytesToHex(key));
//
//        byte[] iv = rng.randomBytes(16); // CBC IV
//        System.out.println("\nGenerated IV:\n" + bytesToHex(iv));
//
//        byte[] nonce = rng.randomBytes(12); // CTR/GCM nonce
//        System.out.println("\nGenerated Nonce:\n" + bytesToHex(nonce));
//
//        // Демонстрация распределения
//        System.out.println("\n=== Distribution Test (first 20 random ints) ===");
//        for (int i = 0; i < 20; i++) {
//            System.out.printf("%d ", rng.nextInt(100));
//            if ((i + 1) % 10 == 0) System.out.println();
//        }
//
//        // Тест re-seeding
//        System.out.println("\n\n=== After Re-seeding ===\n");
//        rng.reseed();
//        rng.printEntropyInfo();
//    }
}