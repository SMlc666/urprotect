namespace AsmStone.Encoding;

internal static class A64SVEImmediate
{
    public static bool IsOptionalLsl(string type)
    {
        return type.StartsWith("cpy_imm8_opt_lsl_i", StringComparison.Ordinal)
            || type.StartsWith("addsub_imm8_opt_lsl_i", StringComparison.Ordinal);
    }

    public static bool TryDecode(
        string type,
        uint encoded,
        int width,
        out long value,
        out int shift)
    {
        value = 0;
        shift = 0;
        if (!IsOptionalLsl(type) || (encoded & ~0x1FFu) != 0)
        {
            return false;
        }

        var immediate = encoded & 0xFFu;
        shift = (encoded & 0x100u) != 0 ? 8 : 0;
        var isSigned = type.StartsWith("cpy_", StringComparison.Ordinal);
        var elementWidth = ElementWidth(type);
        if (elementWidth == 8 && shift != 0)
        {
            shift = 0;
            return false;
        }

        if (isSigned)
        {
            var signed = immediate >= 0x80 ? (long)immediate - 0x100 : immediate;
            value = signed << shift;
            return IsValidSigned(value, elementWidth);
        }

        value = (long)immediate << shift;
        return IsValidUnsigned(value, elementWidth);
    }

    public static bool TryEncode(string type, long value, int width, out uint encoded)
    {
        encoded = 0;
        if (!IsOptionalLsl(type))
        {
            return false;
        }

        var isSigned = type.StartsWith("cpy_", StringComparison.Ordinal);
        var elementWidth = ElementWidth(type);
        for (var shift = 0; shift <= 8; shift += 8)
        {
            if (elementWidth == 8 && shift != 0)
            {
                continue;
            }

            if ((shift != 0 && value == 0) || (value & ((1L << shift) - 1)) != 0)
            {
                continue;
            }

            var unscaled = value >> shift;
            if (isSigned)
            {
                if (unscaled is < -128 or > 127 || !IsValidSigned(value, elementWidth))
                {
                    continue;
                }
            }
            else if (unscaled is < 0 or > 255 || !IsValidUnsigned(value, elementWidth))
            {
                continue;
            }

            encoded = (uint)(unscaled & 0xFF) | (shift == 0 ? 0u : 0x100u);
            return true;
        }

        return false;
    }

    public static bool TryEncode(
        string type,
        long value,
        int shift,
        int width,
        out uint encoded)
    {
        encoded = 0;
        if (!IsOptionalLsl(type))
        {
            return false;
        }

        var isSigned = type.StartsWith("cpy_", StringComparison.Ordinal);
        var elementWidth = ElementWidth(type);
        if (shift is not (0 or 8) || elementWidth == 8 && shift != 0)
        {
            return false;
        }

        if (value % (1L << shift) != 0)
        {
            return false;
        }

        var unscaled = value >> shift;
        if (isSigned
            ? unscaled is < -128 or > 127 || !IsValidSigned(value, elementWidth)
            : unscaled is < 0 or > 255 || !IsValidUnsigned(value, elementWidth))
        {
            return false;
        }

        encoded = (uint)(unscaled & 0xFF) | (shift == 0 ? 0u : 0x100u);
        return true;
    }

    public static int ElementWidth(string type)
    {
        return type[^2..] switch
        {
            "i8" => 8,
            "16" => 16,
            "32" => 32,
            "64" => 64,
            _ => 0,
        };
    }

    private static bool IsValidSigned(long value, int elementWidth)
    {
        if (elementWidth == 8)
        {
            return value is >= -128 and <= 127;
        }

        return value is >= -32768 and <= 32512 && (value & 0xFF) == 0
            || value is >= -128 and <= 127;
    }

    private static bool IsValidUnsigned(long value, int elementWidth)
    {
        if (elementWidth == 8)
        {
            return value is >= 0 and <= 255;
        }

        return value is >= 0 and <= 65280 && (value & 0xFF) == 0
            || value is >= 0 and <= 255;
    }

    public static bool TryDecodeIncDec(uint encoded, out long value)
    {
        if (encoded > 15)
        {
            value = 0;
            return false;
        }

        value = encoded + 1;
        return true;
    }

    public static bool TryEncodeIncDec(long value, out uint encoded)
    {
        if (value is < 1 or > 16)
        {
            encoded = 0;
            return false;
        }

        encoded = (uint)(value - 1);
        return true;
    }
}
