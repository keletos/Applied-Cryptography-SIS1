package core;

public enum KeySize
{
    K128(10, 4, 16),
    K192(12, 6, 24),
    K256(14, 8, 32);

    private final int rounds;
    private final int words;
    private final int bytes;

    private KeySize(int rounds, int words, int bytes)
    {
        this.rounds = rounds;
        this.words = words;
        this.bytes = bytes;
    }

    public int getRounds()
    {
        return rounds;
    }

    public int getWords()
    {
        return words;
    }

    public int getBytesAmount()
    {
        return bytes;
    }
}
