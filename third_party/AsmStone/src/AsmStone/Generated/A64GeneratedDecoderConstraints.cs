using AsmStone.Model;
using AsmStone.Encoding;

namespace AsmStone.Generated;

internal static class A64GeneratedDecoderConstraints
{
    public static bool Accept(
        A64CompiledInstruction candidate,
        uint encoding,
        A64FeatureSet features)
    {
        var result = candidate.Source.DecoderMethod switch
        {
            "DecodeAddSubImmShift"
                => IsAddSubImmediate(candidate, encoding),
            "DecodeMoveImmInstruction"
                => IsMoveWideImmediate(candidate, encoding),
            "DecodeAddSubERegInstruction"
                => ((encoding >> 10) & 0b111u) <= 4u,
            "DecodeThreeAddrSRegInstruction"
                => IsShiftedRegisterEncoding(candidate.Source.Name, encoding),
            "DecodeSystemPStateImm0_15Instruction"
                => IsPStateImm0To15(encoding),
            "DecodeSystemPStateImm0_1Instruction"
                => IsPStateImm0To1(encoding),
            "DecodeCPYMemOpInstruction"
                => AreDistinctCommon(
                    encoding & 0x1Fu,
                    (encoding >> 16) & 0x1Fu,
                    (encoding >> 5) & 0x1Fu),
            "DecodeSETMemOpInstruction"
                => AreDistinctCommonDestination(
                    encoding & 0x1Fu,
                    (encoding >> 16) & 0x1Fu,
                    (encoding >> 5) & 0x1Fu),
            "DecodeSETMemGoOpInstruction"
                => (encoding & 0x1Fu) != 31u
                    && ((encoding & 0x1Fu) != ((encoding >> 5) & 0x1Fu)),
            "DecodeLogicalImmInstruction"
                => IsLogicalImmediate(encoding, (encoding >> 31) != 0),
            "DecodeSVELogicalImmInstruction"
                => A64LogicalImmediate.TryDecode((encoding >> 5) & 0x1FFFu, 64, out _),
            _ => IsOperandEncodingValid(candidate, encoding),
        };
        return result;
    }

    private static bool IsAddSubImmediate(A64CompiledInstruction candidate, uint encoding)
    {
        // Add/sub immediate uses imm{13:12} for the shift selector; 10b and
        // 11b are reserved even though the TableGen field is 14 bits wide.
        return ((encoding >> 22) & 0b11u) <= 1u
            && IsOperandEncodingValid(candidate, encoding);
    }

    private static bool IsMoveWideImmediate(A64CompiledInstruction candidate, uint encoding)
    {
        return (!candidate.HasBindingType("movimm32_shift")
                || ((encoding >> 21) & 0b11u) <= 1u)
            && IsOperandEncodingValid(candidate, encoding);
    }

    private static bool IsOperandEncodingValid(A64CompiledInstruction candidate, uint encoding)
    {
        if (candidate.HasBindingType("svcr_op")
            && ((encoding >> 9) & 0b111u) is not (1u or 2u or 3u))
        {
            return false;
        }

        foreach (var binding in candidate.Bindings)
        {
            if (!candidate.TryReadField(binding.Name, encoding, out var register))
            {
                continue;
            }

            var type = binding.Type;
            if (A64EnumImmediate.IsEncodedEnum(type)
                && !A64EnumImmediate.IsValid(type, register))
            {
                return false;
            }

            if (A64SVEImmediate.IsOptionalLsl(type)
                && !A64SVEImmediate.TryDecode(
                    type,
                    register,
                    binding.FieldWidth,
                    out _,
                    out _))
            {
                return false;
            }

            if (type == "hinte_uimm16"
                && !A64HinteImmediate.TryDecode(register, out _))
            {
                return false;
            }

            if ((type.Contains("GPR64common", StringComparison.Ordinal)
                    || type.Contains("GPR32common", StringComparison.Ordinal)
                    || type.Contains("NoXZR", StringComparison.Ordinal))
                && register == 31u)
            {
                return false;
            }

            if (type.Contains("GPR64x8", StringComparison.Ordinal)
                && (register > 22u || (register & 1u) != 0))
            {
                return false;
            }

            if ((type.Contains("SeqPairClassOperand", StringComparison.Ordinal)
                    || type.Contains("MrrsMssrPairClassOperand", StringComparison.Ordinal))
                && (register & 1u) != 0)
            {
                return false;
            }
        }

        if ((candidate.HasBindingType("cpy_imm8_opt_lsl_i8")
                || candidate.HasBindingType("addsub_imm8_opt_lsl_i8"))
            && ((encoding >> 13) & 1u) != 0)
        {
            return false;
        }

        return true;
    }

    private static bool IsShiftedRegisterEncoding(string name, uint encoding)
    {
        if (name.Contains("W", StringComparison.Ordinal)
            && ((encoding >> 15) & 1u) != 0)
        {
            return false;
        }

        if ((name.Contains("ADD", StringComparison.Ordinal)
                || name.Contains("SUB", StringComparison.Ordinal))
            && ((encoding >> 22) & 0b11u) == 0b11u)
        {
            return false;
        }

        return true;
    }

    private static bool IsPStateImm0To15(uint encoding)
    {
        var op1 = (encoding >> 16) & 0b111u;
        var op2 = (encoding >> 5) & 0b111u;
        var pstate = (op1 << 3) | op2;
        return pstate is 3u or 4u or 5u or 25u or 26u or 28u or 30u or 31u;
    }

    private static bool IsLogicalImmediate(uint encoding, bool is64Bit)
    {
        var width = is64Bit ? 13 : 12;
        var immediate = (encoding >> 10) & ((1u << width) - 1u);
        return A64LogicalImmediate.TryDecode(immediate, is64Bit ? 64 : 32, out _);
    }

    private static bool IsPStateImm0To1(uint encoding)
    {
        var op1 = (encoding >> 16) & 0b111u;
        var op2 = (encoding >> 5) & 0b111u;
        var crmHigh = (encoding >> 9) & 0b111u;
        var pstate = (crmHigh << 6) | (op1 << 3) | op2;
        return pstate is 0x08u or 0x48u;
    }

    private static bool AreDistinctCommon(uint first, uint second, uint third)
    {
        return first != 31u
            && second != 31u
            && first != second
            && second != third
            && first != third;
    }

    private static bool AreDistinctCommonDestination(uint first, uint second, uint third)
    {
        return first != 31u
            && first != second
            && second != third
            && first != third;
    }
}
