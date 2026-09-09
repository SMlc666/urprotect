namespace AsmStone.Encoding;

internal static class A64MoveWideImmediate
{
    public static bool IsImmediate(string type)
    {
        return type == "movimm32_imm";
    }

    public static bool IsShift(string type)
    {
        return type is "movimm32_shift" or "movimm64_shift";
    }

    public static long DecodeShift(uint encoded)
    {
        return (encoded >> 4) * 16L;
    }

    public static bool TryEncodeShift(string type, long value, out uint encoded)
    {
        encoded = 0;
        if (!IsShift(type) || value < 0 || value % 16 != 0)
        {
            return false;
        }

        var halfword = value / 16;
        var maximum = type == "movimm32_shift" ? 1 : 3;
        if (halfword > maximum)
        {
            return false;
        }

        encoded = (uint)halfword << 4;
        return true;
    }
}
