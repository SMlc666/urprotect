namespace AsmStone.Encoding;

internal static class A64VectorShift
{
    public static bool IsVectorShift(string type)
    {
        return type.StartsWith("vecshiftL", StringComparison.Ordinal)
            || type.StartsWith("vecshiftR", StringComparison.Ordinal)
            || type is "logical_vec_shift" or "logical_vec_hw_shift" or "move_vec_shift";
    }

    public static bool TryDecode(string type, uint encoded, out long shift)
    {
        if (type is "logical_vec_shift" or "logical_vec_hw_shift")
        {
            shift = encoded * 8L;
            return shift is 0 or 8 or 16 or 24;
        }

        if (type == "move_vec_shift")
        {
            shift = (encoded + 1) * 8L;
            return shift is 8 or 16;
        }

        if (!TryGetWidth(type, out var width, out var right, out var narrow))
        {
            shift = 0;
            return false;
        }

        var raw = right
            ? narrow ? width / 2 + (int)encoded : (int)encoded
            : width + (int)encoded;
        shift = right ? width - raw : raw - width;
        var maximum = right
            ? narrow ? width / 2 : width
            : narrow ? width / 2 : width - 1;
        var minimum = right ? 1 : 0;
        return shift >= minimum && shift <= maximum;
    }

    public static bool TryEncode(string type, long shift, out uint encoded)
    {
        encoded = 0;
        if (type is "logical_vec_shift" or "logical_vec_hw_shift")
        {
            if (type == "logical_vec_hw_shift" && shift is not (0 or 8))
            {
                return false;
            }

            if (shift is not (0 or 8 or 16 or 24))
            {
                return false;
            }

            encoded = (uint)(shift / 8);
            return true;
        }

        if (type == "move_vec_shift")
        {
            if (shift is not (8 or 16))
            {
                return false;
            }

            encoded = (uint)(shift / 8 - 1);
            return true;
        }

        if (!TryGetWidth(type, out var width, out var right, out var narrow))
        {
            return false;
        }

        var maximum = right
            ? narrow ? width / 2 : width
            : narrow ? width / 2 : width - 1;
        var minimum = right ? 1 : 0;
        if (shift < minimum || shift > maximum)
        {
            return false;
        }

        var raw = right ? width - shift : width + shift;
        encoded = right && narrow
            ? (uint)(raw - width / 2)
            : right ? (uint)raw : (uint)(raw - width);
        return true;
    }

    private static bool TryGetWidth(
        string type,
        out int width,
        out bool right,
        out bool narrow)
    {
        right = type.StartsWith("vecshiftR", StringComparison.Ordinal);
        narrow = type.Contains("Narrow", StringComparison.Ordinal);
        var start = right ? "vecshiftR".Length : "vecshiftL".Length;
        var end = type.IndexOf('_', start);
        var widthText = (end < 0 ? type[start..] : type[start..end])
            .Replace("Narrow", string.Empty, StringComparison.Ordinal);
        if (!int.TryParse(widthText, out width))
        {
            width = 0;
            return false;
        }

        return width is 8 or 16 or 32 or 64;
    }
}
