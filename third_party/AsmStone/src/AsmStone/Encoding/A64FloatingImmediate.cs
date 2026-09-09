namespace AsmStone.Encoding;

internal static class A64FloatingImmediate
{
    public static bool IsFloatingImmediate(string type)
    {
        return type is "fpimm8" or "fpimm16" or "fpimm32" or "fpimm64" or "fpimmbf16"
            or "sve_fpimm_half_one" or "sve_fpimm_half_two" or "sve_fpimm_zero_one";
    }

    public static bool IsExactFloatingImmediate(string type)
    {
        return type is "sve_fpimm_half_one" or "sve_fpimm_half_two" or "sve_fpimm_zero_one";
    }

    public static bool TryDecode(string type, uint encoded, out double value)
    {
        if (IsExactFloatingImmediate(type))
        {
            if (encoded > 1)
            {
                value = 0;
                return false;
            }

            value = type switch
            {
                "sve_fpimm_half_one" => encoded == 0 ? 0.5 : 1.0,
                "sve_fpimm_half_two" => encoded == 0 ? 0.5 : 2.0,
                _ => encoded == 0 ? 0.0 : 1.0,
            };
            return true;
        }

        if (!IsFloatingImmediate(type))
        {
            value = 0;
            return false;
        }

        value = Decode(encoded);
        return true;
    }

    public static bool TryEncode(string type, double value, out uint encoded)
    {
        if (IsExactFloatingImmediate(type))
        {
            encoded = type switch
            {
                "sve_fpimm_half_one" when value == 0.5 => 0,
                "sve_fpimm_half_one" when value == 1.0 => 1,
                "sve_fpimm_half_two" when value == 0.5 => 0,
                "sve_fpimm_half_two" when value == 2.0 => 1,
                "sve_fpimm_zero_one" when value == 0.0 => 0,
                "sve_fpimm_zero_one" when value == 1.0 => 1,
                _ => uint.MaxValue,
            };
            return encoded != uint.MaxValue;
        }

        encoded = 0;
        return IsFloatingImmediate(type) && TryEncode(value, out encoded);
    }

    public static double Decode(uint encoded)
    {
        var sign = (encoded >> 7) & 1u;
        var exponent = (encoded >> 4) & 7u;
        var mantissa = encoded & 0xFu;
        var bits = sign << 31;
        bits |= ((exponent & 4) != 0 ? 0u : 1u) << 30;
        bits |= ((exponent & 4) != 0 ? 0x1Fu : 0u) << 25;
        bits |= (exponent & 3) << 23;
        bits |= mantissa << 19;
        return BitConverter.UInt32BitsToSingle(bits);
    }

    public static bool TryEncode(double value, out uint encoded)
    {
        var targetBits = BitConverter.DoubleToInt64Bits(value);
        for (uint candidate = 0; candidate < 256; candidate++)
        {
            if (BitConverter.DoubleToInt64Bits(Decode(candidate)) == targetBits)
            {
                encoded = candidate;
                return true;
            }
        }

        encoded = 0;
        return false;
    }
}
