namespace AsmStone.Encoding;

internal static class A64LogicalImmediate
{
    public static bool TryDecode(uint encoded, int registerWidth, out ulong value)
    {
        value = 0;
        if (registerWidth is not (32 or 64))
        {
            return false;
        }

        var n = (encoded >> 12) & 1u;
        var immr = (encoded >> 6) & 0x3Fu;
        var imms = encoded & 0x3Fu;
        if (registerWidth == 32 && n != 0)
        {
            return false;
        }

        var combined = (n << 6) | ((~imms) & 0x3Fu);
        var length = HighestSetBit(combined);
        if (length < 1)
        {
            return false;
        }

        var levels = (1u << length) - 1u;
        var s = imms & levels;
        var rotation = immr & levels;
        var elementSize = 1 << length;
        if (s == levels || elementSize > registerWidth)
        {
            return false;
        }

        var element = Ones((int)s + 1, elementSize);
        element = RotateRight(element, (int)rotation, elementSize);
        value = Replicate(element, elementSize, registerWidth);
        if (registerWidth == 32)
        {
            value &= uint.MaxValue;
        }

        return true;
    }

    public static bool TryEncode(ulong value, int registerWidth, out uint encoded)
    {
        encoded = 0;
        if (registerWidth is not (32 or 64))
        {
            return false;
        }

        if (registerWidth == 32)
        {
            value &= uint.MaxValue;
        }

        for (var length = 1; length <= (registerWidth == 64 ? 6 : 5); length++)
        {
            var elementSize = 1 << length;
            var elementMask = Mask(elementSize);
            var element = value & elementMask;
            if (Replicate(element, elementSize, registerWidth) != value)
            {
                continue;
            }

            for (var s = 0; s < elementSize - 1; s++)
            {
                var ones = Ones(s + 1, elementSize);
                for (var rotation = 0; rotation < elementSize; rotation++)
                {
                    if (RotateRight(ones, rotation, elementSize) != element)
                    {
                        continue;
                    }

                    var levels = (1u << length) - 1u;
                    var n = registerWidth == 64 && elementSize == 64 ? 1u : 0u;
                    var prefix = n == 1u ? 0u : (~(levels << 1) & 0x3Fu);
                    var imms = prefix | (uint)s;
                    encoded = (n << 12) | ((uint)rotation << 6) | imms;
                    return true;
                }
            }
        }

        return false;
    }

    private static int HighestSetBit(uint value)
    {
        var result = -1;
        while (value != 0)
        {
            result++;
            value >>= 1;
        }

        return result;
    }

    private static ulong Ones(int count, int width)
    {
        if (count >= 64)
        {
            return ulong.MaxValue;
        }

        return (1UL << count) - 1UL;
    }

    private static ulong Mask(int width)
    {
        return width == 64 ? ulong.MaxValue : (1UL << width) - 1UL;
    }

    private static ulong RotateRight(ulong value, int amount, int width)
    {
        amount %= width;
        var mask = Mask(width);
        value &= mask;
        if (amount == 0)
        {
            return value;
        }

        return ((value >> amount) | (value << (width - amount))) & mask;
    }

    private static ulong Replicate(ulong value, int elementSize, int registerWidth)
    {
        var result = 0UL;
        var mask = Mask(elementSize);
        value &= mask;
        for (var offset = 0; offset < registerWidth; offset += elementSize)
        {
            result |= value << offset;
        }

        return result;
    }
}
