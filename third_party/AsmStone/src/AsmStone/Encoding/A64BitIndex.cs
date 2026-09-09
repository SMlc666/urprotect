namespace AsmStone.Encoding;

internal static class A64BitIndex
{
    public static bool IsBitIndex(string type)
    {
        return type is "tbz_imm0_31_diag" or "tbz_imm32_63";
    }

    public static long Decode(string type, uint encoded)
    {
        return type == "tbz_imm32_63" ? encoded + 32L : encoded;
    }

    public static bool TryEncode(string type, long value, out uint encoded)
    {
        encoded = 0;
        if (!IsBitIndex(type))
        {
            return false;
        }

        if (type == "tbz_imm32_63")
        {
            if (value is < 32 or > 63)
            {
                return false;
            }

            encoded = (uint)(value - 32);
            return true;
        }

        if (value is < 0 or > 31)
        {
            return false;
        }

        encoded = (uint)value;
        return true;
    }
}
