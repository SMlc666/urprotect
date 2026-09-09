namespace AsmStone.Encoding;

internal static class A64HinteImmediate
{
    public static bool TryDecode(uint encoded, out long value)
    {
        value = encoded;
        return IsValid(encoded);
    }

    public static bool TryEncode(long value, out uint encoded)
    {
        encoded = 0;
        if (value is < 0 or > ushort.MaxValue)
        {
            return false;
        }

        encoded = (uint)value;
        return IsValid(encoded);
    }

    private static bool IsValid(uint encoded)
    {
        return encoded <= ushort.MaxValue
            && (encoded < 12319u
                || encoded > 16383u
                || (encoded - 12319u) % 32u != 0);
    }
}
