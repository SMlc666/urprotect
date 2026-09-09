namespace AsmStone.Model;

public enum A64RegisterModifierKind
{
    Unknown,
    Lsl,
    Lsr,
    Asr,
    Ror,
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

public readonly record struct A64RegisterModifier(
    A64RegisterModifierKind Kind,
    int Amount,
    uint RawEncoding)
{
    public static bool TryDecode(
        string codec,
        uint rawEncoding,
        out A64RegisterModifier modifier)
    {
        ArgumentNullException.ThrowIfNull(codec);
        if (codec is "logical_shifted_reg32" or "logical_shifted_reg64"
            or "arith_shifted_reg32" or "arith_shifted_reg64")
        {
            modifier = new A64RegisterModifier(
                (rawEncoding >> 6) switch
                {
                    0 => A64RegisterModifierKind.Lsl,
                    1 => A64RegisterModifierKind.Lsr,
                    2 => A64RegisterModifierKind.Asr,
                    3 => A64RegisterModifierKind.Ror,
                    _ => A64RegisterModifierKind.Unknown,
                },
                (int)(rawEncoding & 0x3F),
                rawEncoding);
            return true;
        }

        if (codec.StartsWith("arith_extended_reg", StringComparison.Ordinal))
        {
            modifier = new A64RegisterModifier(
                (rawEncoding >> 3) switch
                {
                    0 => A64RegisterModifierKind.Uxtb,
                    1 => A64RegisterModifierKind.Uxth,
                    2 => A64RegisterModifierKind.Uxtw,
                    3 => A64RegisterModifierKind.Uxtx,
                    4 => A64RegisterModifierKind.Sxtb,
                    5 => A64RegisterModifierKind.Sxth,
                    6 => A64RegisterModifierKind.Sxtw,
                    7 => A64RegisterModifierKind.Sxtx,
                    _ => A64RegisterModifierKind.Unknown,
                },
                (int)(rawEncoding & 0x7),
                rawEncoding);
            return true;
        }

        if (codec == "arith_extendlsl64")
        {
            modifier = new A64RegisterModifier(
                (rawEncoding & 0x20u) != 0
                    ? A64RegisterModifierKind.Sxtx
                    : A64RegisterModifierKind.Uxtx,
                (int)(rawEncoding & 0x7u),
                rawEncoding);
            return true;
        }

        modifier = new A64RegisterModifier(A64RegisterModifierKind.Unknown, 0, rawEncoding);
        return false;
    }

    public static bool TryEncode(
        string codec,
        A64RegisterModifierKind kind,
        int amount,
        out uint rawEncoding)
    {
        ArgumentNullException.ThrowIfNull(codec);
        rawEncoding = 0;
        if (amount < 0)
        {
            return false;
        }

        if (codec is "logical_shifted_reg32" or "logical_shifted_reg64"
            or "arith_shifted_reg32" or "arith_shifted_reg64")
        {
            var kindValue = kind switch
            {
                A64RegisterModifierKind.Lsl => 0,
                A64RegisterModifierKind.Lsr => 1,
                A64RegisterModifierKind.Asr => 2,
                A64RegisterModifierKind.Ror => 3,
                _ => -1,
            };
            var maximumAmount = codec.EndsWith("32", StringComparison.Ordinal) ? 31 : 63;
            if (kindValue < 0 || amount > maximumAmount)
            {
                return false;
            }

            rawEncoding = (uint)(amount | (kindValue << 6));
            return true;
        }

        if (codec.StartsWith("arith_extended_reg", StringComparison.Ordinal))
        {
            var kindValue = kind switch
            {
                A64RegisterModifierKind.Uxtb => 0,
                A64RegisterModifierKind.Uxth => 1,
                A64RegisterModifierKind.Uxtw => 2,
                A64RegisterModifierKind.Uxtx => 3,
                A64RegisterModifierKind.Sxtb => 4,
                A64RegisterModifierKind.Sxth => 5,
                A64RegisterModifierKind.Sxtw => 6,
                A64RegisterModifierKind.Sxtx => 7,
                _ => -1,
            };
            if (kindValue < 0 || amount > 4)
            {
                return false;
            }

            rawEncoding = (uint)(amount | (kindValue << 3));
            return true;
        }

        if (codec == "arith_extendlsl64")
        {
            if (kind is not (A64RegisterModifierKind.Uxtx or A64RegisterModifierKind.Sxtx)
                || amount > 4)
            {
                return false;
            }

            rawEncoding = (uint)amount
                | (kind == A64RegisterModifierKind.Sxtx ? 0x20u : 0u);
            return true;
        }

        return false;
    }
}
