namespace AsmStone.Encoding;

internal static class A64AdvSimdImmediate
{
    public static ulong DecodeType10(uint encoded)
    {
        var value = 0UL;
        for (var bit = 0; bit < 8; bit++)
        {
            if ((encoded & (1u << bit)) != 0)
            {
                value |= 0xFFUL << (bit * 8);
            }
        }

        return value;
    }

    public static bool TryEncodeType10(ulong value, out uint encoded)
    {
        encoded = 0;
        for (var bit = 0; bit < 8; bit++)
        {
            var byteValue = (value >> (bit * 8)) & 0xFF;
            if (byteValue == 0)
            {
                continue;
            }

            if (byteValue != 0xFF)
            {
                return false;
            }

            encoded |= 1u << bit;
        }

        return true;
    }
}
