namespace AsmStone.Encoding;

internal static class A64EnumImmediate
{
    public static bool IsEncodedEnum(string type)
    {
        return type is "sve_pred_enum"
            or "sve_vec_len_specifier_enum"
            or "sve_prfop"
            or "svcr_op"
            or "TIndexhint_op"
            or "barrier_op"
            or "barrier_nxs_op"
            or "ccode"
            or "inv_ccode"
            or "sys_cr_op"
            or "prfop"
            or "rprfop"
            or "pstatefield1_op"
            or "pstatefield4_op";
    }

    public static bool TryDecode(string type, uint encoded, int width, out long value)
    {
        value = type switch
        {
            "TIndexhint_op" => 1,
            "barrier_nxs_op" => (long)encoded + 16,
            _ => encoded,
        };
        return IsEncodedEnum(type)
            && (width <= 0 || width >= 32 || (encoded >> width) == 0)
            && IsValid(type, encoded);
    }

    public static bool TryEncode(string type, long value, int width, out uint encoded)
    {
        if (!IsEncodedEnum(type) || value < 0 || value > uint.MaxValue)
        {
            encoded = 0;
            return false;
        }

        encoded = type switch
        {
            "TIndexhint_op" when value == 1 => 0,
            "barrier_nxs_op" when value is 16 or 20 or 24 or 28 => (uint)value - 16,
            _ => (uint)value,
        };

        return (type != "TIndexhint_op" || value == 1)
            && (width >= 32 || width <= 0 || (encoded >> width) == 0)
            && IsValid(type, encoded);
    }

    public static bool IsValid(string type, uint encoded)
    {
        return type switch
        {
            // The named SVE patterns occupy a subset of the five-bit field,
            // but LLVM also accepts the remaining numeric pattern values.
            "sve_pred_enum" => encoded <= 31u,
            "sve_vec_len_specifier_enum" => encoded is 0u or 1u,
            // Numeric SVE prefetch hints are valid even when they have no
            // named printer-table entry.
            "sve_prfop" => encoded <= 15u,
            "svcr_op" => encoded is 1u or 2u or 3u,
            "TIndexhint_op" => encoded <= 1u,
            "barrier_op" => encoded <= 15u,
            "barrier_nxs_op" => encoded is 0u or 4u or 8u or 12u,
            "ccode" or "inv_ccode" => encoded <= 15u,
            "rprfop" => encoded <= 63u,
            _ => true,
        };
    }
}
