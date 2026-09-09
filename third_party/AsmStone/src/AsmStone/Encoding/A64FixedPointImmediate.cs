namespace AsmStone.Encoding;

internal static class A64FixedPointImmediate
{
    public static int FractionalBits(string type)
    {
        var marker = type.IndexOf("_f", StringComparison.Ordinal);
        if (marker < 0)
        {
            return 0;
        }

        var index = marker + 2;
        var value = 0;
        while (index < type.Length && char.IsDigit(type[index]))
        {
            value = value * 10 + type[index++] - '0';
        }

        return value;
    }

    public static bool TryDecode(string type, uint encoded, out long value)
    {
        value = 0;
        if (!type.StartsWith("fixedpoint_", StringComparison.Ordinal))
        {
            return false;
        }

        var is32Bit = type.EndsWith("_i32", StringComparison.Ordinal);
        if (encoded >= (is32Bit ? 32u : 64u))
        {
            return false;
        }

        value = 64 - (long)(encoded | (is32Bit ? 0x20u : 0u));
        return value > 0;
    }

    public static bool TryEncode(string type, long value, out uint encoded)
    {
        encoded = 0;
        if (!type.StartsWith("fixedpoint_", StringComparison.Ordinal))
        {
            return false;
        }

        var is32Bit = type.EndsWith("_i32", StringComparison.Ordinal);
        var maximum = is32Bit ? 32 : 64;
        if (value < 1 || value > maximum)
        {
            return false;
        }

        encoded = (uint)(64 - value - (is32Bit ? 32 : 0));
        return true;
    }
}
