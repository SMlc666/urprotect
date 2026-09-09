namespace AsmStone.Encoding;

public static class BitField
{
    public static uint Read(uint value, int lsb, int width)
    {
        Validate(lsb, width, 32);
        if (width == 32)
        {
            return value;
        }

        return (value >> lsb) & ((1u << width) - 1u);
    }

    public static uint Insert(uint value, uint field, int lsb, int width)
    {
        Validate(lsb, width, 32);
        var mask = width == 32 ? uint.MaxValue : ((1u << width) - 1u) << lsb;
        return (value & ~mask) | ((field << lsb) & mask);
    }

    public static long SignExtend(uint value, int width)
    {
        Validate(0, width, 32);
        if (width == 32)
        {
            return unchecked((int)value);
        }

        var mask = (1u << width) - 1u;
        var sign = 1u << (width - 1);
        var narrowed = value & mask;
        return (long)(narrowed ^ sign) - sign;
    }

    private static void Validate(int lsb, int width, int size)
    {
        if (lsb < 0 || width <= 0 || lsb + width > size)
        {
            throw new ArgumentOutOfRangeException(nameof(width), "Bit field is outside the value.");
        }
    }
}
