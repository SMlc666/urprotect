using AsmStone.Model;

namespace AsmStone.Generated;

internal readonly record struct A64ModifiedOperandShape(
    string RegisterField,
    string ModifierField,
    string RegisterType);

internal static class A64GeneratedOperandShapes
{
    public static bool TryGetVectorList(string type, out int count, out int elementWidth)
    {
        count = type switch
        {
            _ when type.StartsWith("VecListOne", StringComparison.Ordinal) => 1,
            _ when type.StartsWith("VecListTwo", StringComparison.Ordinal) => 2,
            _ when type.StartsWith("VecListThree", StringComparison.Ordinal) => 3,
            _ when type.StartsWith("VecListFour", StringComparison.Ordinal) => 4,
            _ => 0,
        };
        if (count == 0)
        {
            elementWidth = 0;
            return false;
        }

        var suffixStart = type.IndexOf("List", StringComparison.Ordinal) + 4 + CountNameLength(count);
        var suffix = type[suffixStart..];
        elementWidth = suffix.EndsWith('b') ? 8
            : suffix.EndsWith('h') ? 16
            : suffix.EndsWith('s') ? 32
            : suffix.EndsWith('d') ? 64
            : 0;
        return elementWidth != 0;
    }

    public static bool TryGetModifiedRegister(
        string type,
        out A64ModifiedOperandShape shape)
    {
        shape = type switch
        {
            "logical_shifted_reg32" or "arith_shifted_reg32"
                => new A64ModifiedOperandShape("Rm", "shift", "GPR32"),
            "logical_shifted_reg64" or "arith_shifted_reg64"
                => new A64ModifiedOperandShape("Rm", "shift", "GPR64"),
            "arith_extended_reg32_i32" or "arith_extended_reg32_i64"
                => new A64ModifiedOperandShape("Rm", "extend", "GPR32"),
            "arith_extended_reg32to64_i64"
                => new A64ModifiedOperandShape("Rm", "extend", "GPR32"),
            _ => default,
        };
        return shape.RegisterField is not null;
    }

    public static bool TryGetRegisterGroup(string type, out int count, out A64RegisterClass registerClass)
    {
        count = type switch
        {
            _ when type.StartsWith("ZPR2", StringComparison.Ordinal) => 2,
            _ when type.StartsWith("ZPR4", StringComparison.Ordinal) => 4,
            _ when type.StartsWith("ZZZZ", StringComparison.Ordinal) => 4,
            _ when type.StartsWith("ZZZ", StringComparison.Ordinal) => 3,
            _ when type.StartsWith("ZZ", StringComparison.Ordinal) => 2,
            _ when type.StartsWith("PPR2", StringComparison.Ordinal) => 2,
            _ when type.StartsWith("PP_", StringComparison.Ordinal) => 2,
            _ => 0,
        };
        registerClass = type.StartsWith('P')
            ? A64RegisterClass.Predicate
            : A64RegisterClass.SveVector;
        return count != 0;
    }

    public static bool TryGetRegisterPair(
        string type,
        out A64RegisterClass registerClass,
        out int registerWidth)
    {
        registerClass = A64RegisterClass.Special;
        registerWidth = 0;
        if (type is "WSeqPairClassOperand")
        {
            registerClass = A64RegisterClass.General;
            registerWidth = 32;
            return true;
        }

        if (type is "XSeqPairClassOperand" or "MrrsMssrPairClassOperand" or "SyspXzrPairOperand")
        {
            registerClass = A64RegisterClass.General;
            registerWidth = 64;
            return true;
        }

        return false;
    }

    public static bool TryGetMatrixRegister(
        string type,
        out A64MatrixRegisterKind kind,
        out int elementWidth)
    {
        kind = type switch
        {
            "ZTR" => A64MatrixRegisterKind.Zt,
            "ZK" => A64MatrixRegisterKind.Zk,
            _ when type.StartsWith("MatrixOp", StringComparison.Ordinal)
                => A64MatrixRegisterKind.Za,
            _ when type.StartsWith("TileOp", StringComparison.Ordinal)
                => A64MatrixRegisterKind.Tile,
            _ when type.StartsWith("TileVectorOp", StringComparison.Ordinal)
                => A64MatrixRegisterKind.TileVector,
            _ => default,
        };

        elementWidth = ElementWidth(type);
        return type is "ZTR" or "ZK"
            || type.StartsWith("MatrixOp", StringComparison.Ordinal)
            || type.StartsWith("TileOp", StringComparison.Ordinal)
            || type.StartsWith("TileVectorOp", StringComparison.Ordinal);
    }

    public static bool TryGetRegisterConstraint(
        string type,
        out A64RegisterConstraint constraint)
    {
        constraint = type switch
        {
            "ZK" => new A64RegisterConstraint(
                20,
                31,
                AllowedMask: (0xFu << 20) | (0xFu << 28)),
            "MatrixIndexGPR32Op8_11" => new A64RegisterConstraint(8, 11),
            "MatrixIndexGPR32Op12_15" => new A64RegisterConstraint(12, 15),
            "GPR32common" or "GPR64common" => new A64RegisterConstraint(0, 30),
            "GPR64x8" => new A64RegisterConstraint(0, 22, 2),
            "V128_0to7" or "FPR128_0to7" => new A64RegisterConstraint(0, 7),
            "V128_lo" or "V64_lo" or "FPR128_lo" or "FPR64_lo"
                => new A64RegisterConstraint(0, 15),
            _ when type.StartsWith("ZPR3b", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 7),
            _ when type.StartsWith("ZPR4b", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 15),
            "PPR3bAny" => new A64RegisterConstraint(0, 7),
            _ when type.StartsWith("PNR", StringComparison.Ordinal)
                && type.Contains("p8to15", StringComparison.Ordinal)
                => new A64RegisterConstraint(8, 15),
            "WSeqPairClassOperand" or "XSeqPairClassOperand" or "MrrsMssrPairClassOperand"
                => new A64RegisterConstraint(0, 30, 2),
            _ when type.StartsWith("PP_", StringComparison.Ordinal)
                && type.Contains("mul_r", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 14, 2),
            _ when type.StartsWith("ZZZZ", StringComparison.Ordinal)
                && type.Contains("mul_r", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 28, 4),
            _ when type.StartsWith("ZZ", StringComparison.Ordinal)
                && type.Contains("mul_r", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 30, 2),
            _ when type.StartsWith("ZZZZ", StringComparison.Ordinal)
                && type.Contains("strided", StringComparison.OrdinalIgnoreCase)
                && !type.Contains("and_contiguous", StringComparison.OrdinalIgnoreCase)
                => new A64RegisterConstraint(0, 31, AllowedMask: 0x000F000Fu),
            _ when type.StartsWith("ZZ", StringComparison.Ordinal)
                && type.Contains("strided", StringComparison.OrdinalIgnoreCase)
                && !type.Contains("and_contiguous", StringComparison.OrdinalIgnoreCase)
                => new A64RegisterConstraint(0, 31, AllowedMask: 0x00FF00FFu),
            _ when type.Contains("Mul2_Lo", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 14, 2),
            _ when type.Contains("Mul2_Hi", StringComparison.Ordinal)
                => new A64RegisterConstraint(16, 30, 2),
            _ when (type.StartsWith("ZPR", StringComparison.Ordinal)
                    || type.StartsWith("ZZ", StringComparison.Ordinal))
                && type.Contains("_3b", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 7),
            _ when (type.StartsWith("ZPR", StringComparison.Ordinal)
                    || type.StartsWith("ZZ", StringComparison.Ordinal))
                && type.Contains("_4b", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 15),
            _ when type.Contains("_0to7", StringComparison.Ordinal)
                => new A64RegisterConstraint(0, 7),
            _ when type.Contains("_lo", StringComparison.OrdinalIgnoreCase)
                => new A64RegisterConstraint(0, 15),
            _ => A64RegisterConstraint.Any,
        };

        return constraint != A64RegisterConstraint.Any;
    }

    public static int RegisterIndexBias(string type)
    {
        return type switch
        {
            "MatrixIndexGPR32Op8_11" or "PNR8_p8to15" or "PNR16_p8to15"
                or "PNR32_p8to15" or "PNR64_p8to15" or "PNRAny_p8to15" => 8,
            "MatrixIndexGPR32Op12_15" => 12,
            _ when type.Contains("Mul2_Hi", StringComparison.Ordinal)
                || type.Contains("mul_r_Hi", StringComparison.Ordinal)
                => 16,
            _ => 0,
        };
    }

    public static int RegisterIndexScale(string type)
    {
        if (type.StartsWith("ZZZZ", StringComparison.Ordinal)
            && type.Contains("mul_r", StringComparison.Ordinal))
        {
            return 4;
        }

        if (type.Contains("Mul2", StringComparison.Ordinal)
            || type.Contains("mul_r", StringComparison.Ordinal)
            || type.StartsWith("PP_", StringComparison.Ordinal)
                && type.Contains("mul_r", StringComparison.Ordinal))
        {
            return 2;
        }

        return 1;
    }

    public static int GroupStride(string type)
    {
        if (type.Contains("and_contiguous", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        if (type.Contains("strided", StringComparison.OrdinalIgnoreCase))
        {
            return type.StartsWith("ZZZZ", StringComparison.Ordinal) ? 4 : 8;
        }

        return 1;
    }

    public static int DecodeMatrixRegisterIndex(string type, int encoded)
    {
        if (type == "ZK")
        {
            return encoded < 4 ? 20 + encoded : 28 + (encoded - 4);
        }

        return encoded;
    }

    public static bool TryEncodeMatrixRegisterIndex(
        string type,
        int actual,
        out int encoded)
    {
        if (type == "ZK")
        {
            if (actual is >= 20 and <= 23)
            {
                encoded = actual - 20;
                return true;
            }

            if (actual is >= 28 and <= 31)
            {
                encoded = actual - 24;
                return true;
            }

            encoded = 0;
            return false;
        }

        encoded = actual;
        return actual >= 0;
    }

    public static int DecodeGroupFirstIndex(string type, int encoded, out int stride)
    {
        if (type.Contains("and_contiguous", StringComparison.OrdinalIgnoreCase))
        {
            if (type.StartsWith("ZZZZ", StringComparison.Ordinal))
            {
                if (encoded < 8)
                {
                    stride = 4;
                    return encoded < 4 ? encoded : encoded + 12;
                }

                stride = 1;
                return (encoded - 8) * 4;
            }

            if (encoded < 16)
            {
                stride = 8;
                return encoded < 8 ? encoded : encoded + 8;
            }

            stride = 1;
            return (encoded - 16) * 2;
        }

        stride = GroupStride(type);
        if (stride == 8)
        {
            return encoded < 8 ? encoded : encoded + 8;
        }

        if (stride == 4)
        {
            return encoded < 4 ? encoded : encoded + 12;
        }

        return encoded;
    }

    public static bool TryEncodeGroupFirstIndex(
        string type,
        int actual,
        int stride,
        out int encoded)
    {
        encoded = 0;
        if (type.Contains("and_contiguous", StringComparison.OrdinalIgnoreCase))
        {
            if (type.StartsWith("ZZZZ", StringComparison.Ordinal))
            {
                if (stride == 4 && ((actual is >= 0 and <= 3) || (actual is >= 16 and <= 19)))
                {
                    encoded = actual <= 3 ? actual : actual - 12;
                    return true;
                }

                if (stride == 1 && actual is >= 0 and <= 28 && actual % 4 == 0)
                {
                    encoded = actual / 4 + 8;
                    return true;
                }

                return false;
            }

            if (stride == 8 && ((actual is >= 0 and <= 7) || (actual is >= 16 and <= 23)))
            {
                encoded = actual < 8 ? actual : actual - 8;
                return true;
            }

            if (stride == 1 && actual is >= 0 and <= 30 && actual % 2 == 0)
            {
                encoded = actual / 2 + 16;
                return true;
            }

            return false;
        }

        if (stride == 8 && ((actual is >= 0 and <= 7) || (actual is >= 16 and <= 23)))
        {
            encoded = actual < 8 ? actual : actual - 8;
            return true;
        }

        if (stride == 4 && ((actual is >= 0 and <= 3) || (actual is >= 16 and <= 19)))
        {
            encoded = actual <= 3 ? actual : actual - 12;
            return true;
        }

        encoded = actual;
        return actual is >= 0 and <= 31;
    }

    public static int ElementWidth(string type)
    {
        if (type.StartsWith("VectorIndex", StringComparison.Ordinal)
            && type.Length > "VectorIndex".Length)
        {
            return type["VectorIndex".Length] switch
            {
                'B' => 8,
                'H' => 16,
                'S' => 32,
                'D' => 64,
                _ => 0,
            };
        }

        if (type.StartsWith("MatrixOp", StringComparison.Ordinal)
            || type.StartsWith("TileOp", StringComparison.Ordinal)
            || type.StartsWith("TileVectorOp", StringComparison.Ordinal)
            || type.StartsWith("ZPR", StringComparison.Ordinal)
            || type.StartsWith("PPR", StringComparison.Ordinal)
            || type.StartsWith("PNR", StringComparison.Ordinal)
            || type.Contains("asZPR", StringComparison.Ordinal))
        {
            var start = type.StartsWith("MatrixOp", StringComparison.Ordinal) ? "MatrixOp".Length
                : type.StartsWith("TileOp", StringComparison.Ordinal) ? "TileOp".Length
                : type.StartsWith("TileVectorOp", StringComparison.Ordinal) ? "TileVectorOp".Length
                : type.StartsWith("ZPR", StringComparison.Ordinal) ? "ZPR".Length
                : type.StartsWith("FPR", StringComparison.Ordinal) ? "FPR".Length
                : 3;
            while (start < type.Length && (type[start] is 'H' or 'V'))
            {
                start++;
            }

            var width = 0;
            while (start < type.Length && char.IsDigit(type[start]))
            {
                width = width * 10 + type[start++] - '0';
            }

            if (width is 8 or 16 or 32 or 64 or 128)
            {
                return width;
            }

            for (var index = start; index < type.Length; index++)
            {
                if (type[index] is 'b' or 'h' or 's' or 'd' or 'q')
                {
                    return type[index] switch
                    {
                        'b' => 8,
                        'h' => 16,
                        's' => 32,
                        'd' => 64,
                        'q' => 128,
                        _ => 0,
                    };
                }
            }
        }

        if (type.Contains("_b", StringComparison.Ordinal) || type.EndsWith('b'))
        {
            return 8;
        }

        if (type.Contains("_h", StringComparison.Ordinal) || type.EndsWith('h'))
        {
            return 16;
        }

        if (type.Contains("_s", StringComparison.Ordinal) || type.EndsWith('s'))
        {
            return 32;
        }

        if (type.Contains("_d", StringComparison.Ordinal) || type.EndsWith('d'))
        {
            return 64;
        }

        if (type.Contains("_q", StringComparison.Ordinal) || type.EndsWith('q'))
        {
            return 128;
        }

        return 0;
    }

    public static bool IsSveExtendedDuplicateIndex(string type)
    {
        return type.StartsWith("sve_elm_idx_extdup_", StringComparison.Ordinal);
    }

    public static bool TryGetImplicitImmediate(string type, out long value)
    {
        if (type is "VectorIndex0" or "VectorIndex032b" or "sme_elm_idx0_0"
            || type.StartsWith("uimm0", StringComparison.Ordinal))
        {
            value = 0;
            return true;
        }

        if (type is "VectorIndex1" or "VectorIndex132b")
        {
            value = 1;
            return true;
        }

        value = 0;
        return false;
    }

    private static int CountNameLength(int count)
    {
        return count switch
        {
            1 => 3,
            2 => 3,
            3 => 5,
            4 => 4,
            _ => 0,
        };
    }
}
