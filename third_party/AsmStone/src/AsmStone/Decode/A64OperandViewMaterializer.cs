using AsmStone.Encoding;
using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone.Decode;

internal static class A64OperandViewMaterializer
{
    public static bool TryMaterialize(
        A64CompiledInstruction instruction,
        uint encoding,
        ulong address,
        Span<A64OperandView> destination,
        out int count,
        out A64Diagnostic diagnostic)
    {
        var memory = instruction.Memory;
        A64OperandView memoryOperand = default;
        var useMemory = memory is { } memoryBinding
            && TryMaterializeMemory(instruction, encoding, address, memoryBinding, out memoryOperand);
        var required = useMemory ? instruction.OperandCount : instruction.UncollapsedOperandCount;
        if (destination.Length < required)
        {
            count = 0;
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.BufferTooSmall,
                "The operand buffer is too small for the generated instruction.");
            return false;
        }

        count = 0;
        foreach (var binding in instruction.Bindings)
        {
            if (binding.FieldIndex < 0)
            {
                continue;
            }

            if (useMemory
                && memory is { } activeMemory
                && binding.Name != activeMemory.BaseName
                && (binding.Name == activeMemory.OffsetName
                    || binding.Name == activeMemory.IndexName
                    || binding.Name == activeMemory.ModifierName))
            {
                continue;
            }

            if (useMemory
                && memory is { } activeMemoryBinding
                && binding.Name == activeMemoryBinding.BaseName)
            {
                destination[count++] = memoryOperand
                    .WithBindingMetadataAndSemantics(
                        binding.RegisterConstraint,
                        binding.RegisterWidth,
                        binding.FieldWidth,
                        binding.Scale,
                        binding.IsSigned,
                        binding.AllowsStackPointer,
                        binding.AllowsZeroRegister,
                        binding.IsPageRelative,
                        binding.SemanticDomain,
                        binding.FixedModifierKind,
                        binding.FixedModifierAmount,
                        binding.ElementWidth,
                        Direction(binding.Direction),
                        binding.IsImplicit,
                        binding.TiedTo);
                continue;
            }

            if (!TryMaterializeBinding(binding, instruction, encoding, address, out var operand))
            {
                continue;
            }

            destination[count++] = operand
                .WithBindingMetadataAndSemantics(
                    binding.RegisterConstraint,
                    binding.RegisterWidth,
                    binding.FieldWidth,
                    binding.Scale,
                    binding.IsSigned,
                    binding.AllowsStackPointer,
                    binding.AllowsZeroRegister,
                    binding.IsPageRelative,
                    binding.SemanticDomain,
                    binding.FixedModifierKind,
                    binding.FixedModifierAmount,
                    binding.ElementWidth,
                    Direction(binding.Direction),
                    binding.IsImplicit,
                    binding.TiedTo);
        }

        diagnostic = A64Diagnostic.None;
        return true;
    }

    private static bool TryMaterializeBinding(
        A64CompiledBinding binding,
        A64CompiledInstruction instruction,
        uint encoding,
        ulong address,
        out A64OperandView operand)
    {
        if (binding.Kind == A64CompiledOperandKind.ModifiedRegister)
        {
            if (instruction.TryReadField(binding.FieldIndex, encoding, out var registerField)
                && instruction.TryReadField(binding.SecondaryFieldIndex, encoding, out var modifierField)
                && TryMaterializeRegister(
                    binding.Type.Contains("32", StringComparison.Ordinal) ? "GPR32" : "GPR64",
                    registerField,
                    out var modifiedRegister))
            {
                operand = A64OperandView.ModifiedRegisterValue(
                    binding.Name,
                    binding.Type,
                    modifiedRegister,
                    modifierField);
                return true;
            }

            operand = default;
            return false;
        }

        if (binding.Kind == A64CompiledOperandKind.RegisterModifier
            && instruction.TryReadField(binding.FieldIndex, encoding, out var standaloneModifierField)
            && A64RegisterModifier.TryDecode(binding.Type, standaloneModifierField, out var registerModifier))
        {
            operand = A64OperandView.RegisterModifierValue(
                binding.Name,
                binding.Type,
                registerModifier);
            return true;
        }

        if (A64GeneratedOperandShapes.TryGetMatrixRegister(
                binding.Type,
                out var matrixKind,
                out var matrixElementWidth))
        {
            var matrixValue = instruction.TryReadField(binding.FieldIndex, encoding, out var rawMatrix)
                ? rawMatrix
                : 0u;
            operand = A64OperandView.MatrixRegisterValue(
                binding.Name,
                binding.Type,
                matrixKind,
                A64GeneratedOperandShapes.DecodeMatrixRegisterIndex(binding.Type, (int)matrixValue),
                matrixElementWidth,
                matrixValue);
            return true;
        }

        if (A64GeneratedOperandShapes.TryGetRegisterPair(
                binding.Type,
                out var pairClass,
                out var pairWidth))
        {
            var encodedPair = instruction.TryReadField(binding.FieldIndex, encoding, out var rawPair)
                ? rawPair
                : 31u;
            if (binding.Type == "SyspXzrPairOperand")
            {
                var zero = A64Register.Zr(pairWidth);
                operand = A64OperandView.RegisterPairValue(binding.Name, binding.Type, zero, zero);
                return true;
            }

            var firstIndex = binding.RegisterIndexBias
                + (int)encodedPair * binding.RegisterIndexScale;
            var first = firstIndex <= 30
                ? new A64Register(pairClass, (byte)firstIndex, (byte)pairWidth)
                : A64Register.Zr(pairWidth);
            var second = firstIndex < 30
                ? new A64Register(pairClass, (byte)(firstIndex + 1), (byte)pairWidth)
                : A64Register.Zr(pairWidth);
            operand = A64OperandView.RegisterPairValue(binding.Name, binding.Type, first, second);
            return true;
        }

        if (!instruction.TryReadField(binding.FieldIndex, encoding, out var fieldValue))
        {
            operand = default;
            return false;
        }

        var fieldWidth = instruction.TryGetField(binding.Name, out var field)
            ? field.Width
            : 32;
        var codec = binding.Codec;
        if (codec is null)
        {
            operand = A64OperandView.EncodedFieldValue(binding.Name, binding.Type, fieldValue);
            return true;
        }

        if (binding.Type is "mrs_sysreg_op" or "msr_sysreg_op")
        {
            operand = A64OperandView.SystemRegisterValue(binding.Name, binding.Type, fieldValue);
            return true;
        }

        if (binding.Type == "MatrixTileList")
        {
            operand = A64OperandView.MatrixTileMaskValue(binding.Name, binding.Type, (byte)fieldValue);
            return true;
        }

        if (binding.Type is "logical_imm32" or "logical_imm64")
        {
            operand = A64LogicalImmediate.TryDecode(
                    fieldValue,
                    binding.Type == "logical_imm32" ? 32 : 64,
                    out var logicalImmediate)
                ? A64OperandView.ImmediateValue(
                    binding.Name,
                    binding.Type,
                    unchecked((long)logicalImmediate),
                    fieldValue,
                    A64ImmediateSemanticKind.LogicalImmediate)
                : A64OperandView.EncodedFieldValue(binding.Name, binding.Type, fieldValue);
            return true;
        }

        if (binding.Type == "simdimmtype10")
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                unchecked((long)A64AdvSimdImmediate.DecodeType10(fieldValue)),
                fieldValue,
                A64ImmediateSemanticKind.SimdImmediate);
            return true;
        }

        if (A64MoveWideImmediate.IsImmediate(binding.Type))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                fieldValue,
                fieldValue,
                A64ImmediateSemanticKind.MoveWideImmediate);
            return true;
        }

        if (A64MoveWideImmediate.IsShift(binding.Type))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                A64MoveWideImmediate.DecodeShift(fieldValue),
                fieldValue,
                A64ImmediateSemanticKind.Shift);
            return true;
        }

        if (A64FloatingImmediate.IsFloatingImmediate(binding.Type))
        {
            operand = A64FloatingImmediate.TryDecode(binding.Type, fieldValue, out var floatingValue)
                ? A64OperandView.FloatingImmediateValue(
                    binding.Name,
                    binding.Type,
                    floatingValue,
                    fieldValue)
                : A64OperandView.EncodedFieldValue(binding.Name, binding.Type, fieldValue);
            return true;
        }

        if (A64VectorShift.IsVectorShift(binding.Type))
        {
            operand = A64VectorShift.TryDecode(binding.Type, fieldValue, out var vectorShift)
                ? A64OperandView.ImmediateValue(
                    binding.Name,
                    binding.Type,
                    vectorShift,
                    fieldValue,
                    A64ImmediateSemanticKind.Shift)
                : A64OperandView.EncodedFieldValue(binding.Name, binding.Type, fieldValue);
            return true;
        }

        if (binding.Type == "sve_incdec_imm")
        {
            operand = A64SVEImmediate.TryDecodeIncDec(fieldValue, out var increment)
                ? A64OperandView.ImmediateValue(
                    binding.Name,
                    binding.Type,
                    increment,
                    fieldValue,
                    A64ImmediateSemanticKind.SveIncrement)
                : A64OperandView.EncodedFieldValue(binding.Name, binding.Type, fieldValue);
            return true;
        }

        if (A64BitIndex.IsBitIndex(binding.Type))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                A64BitIndex.Decode(binding.Type, fieldValue),
                fieldValue,
                A64ImmediateSemanticKind.BitIndex);
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.SveOptionalShift
            && A64SVEImmediate.TryDecode(
                binding.Type,
                fieldValue,
                fieldWidth,
                out var sveImmediate,
                out var sveShift))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                sveImmediate,
                fieldValue,
                A64ImmediateSemanticKind.SveOptionalShift,
                elementWidth: binding.ElementWidth,
                shiftAmount: sveShift);
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.HinteImmediate
            && A64HinteImmediate.TryDecode(fieldValue, out var hinteImmediate))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                hinteImmediate,
                fieldValue,
                A64ImmediateSemanticKind.HinteImmediate);
            return true;
        }

        var codecInfo = CodecInfo(codec);
        if (A64EnumImmediate.TryDecode(binding.Type, fieldValue, fieldWidth, out var enumValue))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                enumValue,
                fieldValue,
                A64ImmediateSemanticKind.Enum,
                binding.EnumKind);
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.LaneIndex)
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                fieldValue,
                fieldValue,
                A64ImmediateSemanticKind.LaneIndex,
                elementWidth: binding.ElementWidth,
                laneCount: binding.LaneCount);
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.ComplexRotation
            && A64ComplexRotation.TryDecode(binding.Type, fieldValue, out var angle))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                angle,
                fieldValue,
                A64ImmediateSemanticKind.ComplexRotation);
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.FixedPoint
            && A64FixedPointImmediate.TryDecode(binding.Type, fieldValue, out var fixedPoint))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                fixedPoint,
                fieldValue,
                A64ImmediateSemanticKind.FixedPoint,
                fractionalBits: binding.FractionalBits);
            return true;
        }

        if (A64GeneratedOperandShapes.TryGetVectorList(binding.Type, out var vectorCount, out var elementWidth)
            && fieldValue <= 31)
        {
            var first = A64Register.Vector((int)fieldValue);
            var second = vectorCount > 1 ? A64Register.Vector((int)((fieldValue + 1) & 31)) : default;
            var third = vectorCount > 2 ? A64Register.Vector((int)((fieldValue + 2) & 31)) : default;
            var fourth = vectorCount > 3 ? A64Register.Vector((int)((fieldValue + 3) & 31)) : default;
            operand = A64OperandView.VectorListValue(
                binding.Name,
                binding.Type,
                first,
                second,
                third,
                fourth,
                vectorCount,
                elementWidth);
            return true;
        }

        if (A64GeneratedOperandShapes.TryGetRegisterGroup(binding.Type, out var groupCount, out var groupClass)
            && fieldValue <= 31)
        {
            var groupElementWidth = A64GeneratedOperandShapes.ElementWidth(binding.Type);
            var firstIndex = A64GeneratedOperandShapes.DecodeGroupFirstIndex(
                binding.Type,
                (int)fieldValue,
                out var groupStride);
            if (!binding.Type.Contains("strided", StringComparison.OrdinalIgnoreCase))
            {
                firstIndex = binding.RegisterIndexBias
                    + (int)fieldValue * binding.RegisterIndexScale;
                groupStride = binding.GroupStride == 0 ? 1 : binding.GroupStride;
            }
            var first = GroupRegister(groupClass, firstIndex, groupElementWidth);
            var second = groupCount > 1 ? GroupRegister(groupClass, firstIndex + groupStride, groupElementWidth) : default;
            var third = groupCount > 2 ? GroupRegister(groupClass, firstIndex + groupStride * 2, groupElementWidth) : default;
            var fourth = groupCount > 3 ? GroupRegister(groupClass, firstIndex + groupStride * 3, groupElementWidth) : default;
            operand = A64OperandView.RegisterGroupValue(
                binding.Name,
                binding.Type,
                first,
                second,
                third,
                fourth,
                groupCount,
                groupElementWidth,
                groupStride);
            return true;
        }

        if (IsRegister(binding.Type, codec)
            && TryMaterializeRegister(binding, fieldValue, out var register))
        {
            operand = A64OperandView.RegisterValue(
                binding.Name,
                binding.Type,
                register,
                binding.ElementWidth,
                binding.PredicateMode);
            return true;
        }

        if (codec.OperandType == "OPERAND_PCREL"
            && TryMaterializeTarget(binding.Type, fieldValue, fieldWidth, address, out var target))
        {
            operand = A64OperandView.TargetValue(binding.Name, binding.Type, target, fieldValue);
            return true;
        }

        if (IsImmediate(binding.Type, codec))
        {
            operand = A64OperandView.ImmediateValue(
                binding.Name,
                binding.Type,
                MaterializeImmediate(binding.Type, codecInfo, fieldValue, fieldWidth),
                fieldValue);
            return true;
        }

        operand = A64OperandView.EncodedFieldValue(binding.Name, binding.Type, fieldValue);
        return true;
    }

    private static bool TryMaterializeMemory(
        A64CompiledInstruction instruction,
        uint encoding,
        ulong address,
        A64GeneratedMemoryBinding memory,
        out A64OperandView operand)
    {
        if (!instruction.TryGetBinding(memory.BaseName, out var baseBinding)
            || !instruction.TryReadField(memory.BaseName, encoding, out var baseField)
            || !TryMaterializeRegister(baseBinding, baseField, out var baseRegister))
        {
            operand = default;
            return false;
        }

        var offset = memory.FixedOffset;
        if (memory.OffsetName is not null)
        {
            if (!instruction.TryGetBinding(memory.OffsetName, out var offsetBinding)
                || offsetBinding.Codec is null
                || !instruction.TryReadField(memory.OffsetName, encoding, out var offsetField))
            {
                operand = default;
                return false;
            }

            offset = MaterializeImmediate(
                offsetBinding.Type,
                CodecInfo(offsetBinding.Codec),
                offsetField,
                instruction.TryGetField(memory.OffsetName, out var offsetSpec) ? offsetSpec.Width : 32);
        }

        A64Register indexRegister = default;
        var hasIndex = false;
        if (memory.IndexName is not null)
        {
            if (!instruction.TryGetBinding(memory.IndexName, out var indexBinding)
                || !instruction.TryReadField(memory.IndexName, encoding, out var indexField)
                || !TryMaterializeRegister(indexBinding, indexField, out indexRegister))
            {
                operand = default;
                return false;
            }

            hasIndex = true;
        }

        uint indexModifier = 0;
        var hasIndexModifier = false;
        var indexModifierKind = A64RegisterModifierKind.Unknown;
        var indexModifierAmount = 0;
        if (memory.ModifierName is not null)
        {
            if (!instruction.TryReadField(memory.ModifierName, encoding, out indexModifier))
            {
                operand = default;
                return false;
            }

            hasIndexModifier = true;
            if ((uint)memory.ModifierBindingIndex < (uint)instruction.Bindings.Length
                && A64GeneratedMemory.TryDecodeIndexModifier(
                    instruction.GetBinding(memory.ModifierBindingIndex).Type,
                    indexModifier,
                    out var modifier))
            {
                indexModifierKind = modifier.Kind;
                indexModifierAmount = modifier.Amount;
            }
        }

        operand = A64OperandView.MemoryValue(
            memory.BaseName,
            baseBinding.Type,
            baseRegister,
            offset,
            indexRegister,
            hasIndex,
            memory.Mode,
            indexModifier,
            hasIndexModifier,
            indexModifierKind,
            indexModifierAmount,
            A64GeneratedMemory.AccessSize(instruction),
            A64GeneratedMemory.Ordering(instruction));
        return true;
    }

    private static A64Register GroupRegister(A64RegisterClass groupClass, int index, int elementWidth)
    {
        return groupClass == A64RegisterClass.Predicate
            ? new A64Register(groupClass, checked((byte)index), 0)
            : A64Register.SveVector(index, elementWidth);
    }

    private static A64OperandEncodingInfo CodecInfo(A64GeneratedOperand codec)
    {
        return new A64OperandEncodingInfo(
            codec.Name,
            codec.OperandType,
            codec.DecoderMethod,
            codec.EncoderMethod,
            codec.PrintMethod,
            codec.ParserMatchClass,
            codec.RegClass,
            codec.ElementSize,
            codec.Type);
    }

    private static A64OperandDirection Direction(string direction)
    {
        return direction switch
        {
            "out" => A64OperandDirection.Output,
            "inout" => A64OperandDirection.InputOutput,
            _ => A64OperandDirection.Input,
        };
    }

    private static bool IsRegister(string type, A64GeneratedOperand codec)
    {
        return codec.OperandType == "OPERAND_REGISTER"
            || type.StartsWith("GPR", StringComparison.Ordinal)
            || type.StartsWith("FPR", StringComparison.Ordinal)
            || type.StartsWith("V", StringComparison.Ordinal)
                && !type.StartsWith("VectorIndex", StringComparison.Ordinal)
            || type.StartsWith("ZPR", StringComparison.Ordinal)
            || type.StartsWith("PPR", StringComparison.Ordinal)
            || type.StartsWith("PNR", StringComparison.Ordinal)
            || type.StartsWith("Z_", StringComparison.Ordinal)
            || type.StartsWith("MatrixIndexGPR", StringComparison.Ordinal);
    }

    private static bool IsImmediate(string type, A64GeneratedOperand codec)
    {
        return codec.OperandType is "OPERAND_IMMEDIATE"
            or "OPERAND_SHIFTED_IMMEDIATE"
            or "OPERAND_IMM_UINT8"
            or "OPERAND_IMM_UINT1"
            or "OPERAND_IMM_UINT4plus1"
            or "OPERAND_IMM_UINT5"
            or "OPERAND_IMPLICIT_IMM_0"
            || type.StartsWith("imm", StringComparison.OrdinalIgnoreCase)
            || type.StartsWith("simm", StringComparison.OrdinalIgnoreCase)
            || type.StartsWith("uimm", StringComparison.OrdinalIgnoreCase)
            || type.Contains("Imm", StringComparison.Ordinal);
    }

    private static bool TryMaterializeRegister(
        A64CompiledBinding binding,
        uint value,
        out A64Register register)
    {
        var decoded = binding.RegisterIndexBias
            + (long)value * binding.RegisterIndexScale;
        if (value > 31 || decoded is < 0 or > 31 || !binding.RegisterConstraint.Accepts((int)decoded))
        {
            register = default;
            return false;
        }

        var index = (int)decoded;
        switch (binding.RegisterClass)
        {
            case A64RegisterClass.General:
                if (index == 31)
                {
                    if (binding.AllowsStackPointer)
                    {
                        register = A64Register.Sp(binding.RegisterWidth == 0 ? 64 : binding.RegisterWidth);
                        return true;
                    }

                    if (binding.AllowsZeroRegister)
                    {
                        register = A64Register.Zr(binding.RegisterWidth == 0 ? 64 : binding.RegisterWidth);
                        return true;
                    }

                    register = default;
                    return false;
                }

                register = binding.RegisterWidth == 32 ? A64Register.W(index) : A64Register.X(index);
                return true;
            case A64RegisterClass.FloatingPoint:
                register = A64Register.FloatingPoint(index, binding.RegisterWidth);
                return true;
            case A64RegisterClass.Vector:
                register = A64Register.Vector(index, binding.RegisterWidth == 64 ? 64 : 128);
                return true;
            case A64RegisterClass.SveVector:
                register = A64Register.SveVector(index, binding.ElementWidth);
                return true;
            case A64RegisterClass.Predicate:
                register = new A64Register(A64RegisterClass.Predicate, (byte)index, 0);
                return true;
            default:
                register = default;
                return false;
        }
    }

    private static bool TryMaterializeRegister(string type, uint value, out A64Register register)
    {
        if (value > 31)
        {
            register = default;
            return false;
        }

        var index = (int)value;
        if (type.StartsWith("GPR", StringComparison.Ordinal)
            || type.StartsWith("MatrixIndexGPR", StringComparison.Ordinal))
        {
            var width = type.Contains("32", StringComparison.Ordinal) ? 32 : 64;
            if (index == 31 && type.Contains("sp", StringComparison.OrdinalIgnoreCase))
            {
                register = A64Register.Sp(width);
                return true;
            }

            if (index == 31 && (type.StartsWith("GPR32z", StringComparison.Ordinal)
                    || type.StartsWith("GPR64z", StringComparison.Ordinal)
                    || type is "GPR32" or "GPR64"))
            {
                register = A64Register.Zr(width);
                return true;
            }

            if (index == 31)
            {
                register = default;
                return false;
            }

            register = width == 32 ? A64Register.W(index) : A64Register.X(index);
            return true;
        }

        if (type.StartsWith("FPR", StringComparison.Ordinal))
        {
            register = A64Register.FloatingPoint(index, ParseRegisterWidth(type));
            return true;
        }

        if (type.StartsWith("V", StringComparison.Ordinal))
        {
            register = A64Register.Vector(index, type.StartsWith("V64", StringComparison.Ordinal) ? 64 : 128);
            return true;
        }

        if (type.StartsWith("ZPR", StringComparison.Ordinal)
            || type.StartsWith("ZZ", StringComparison.Ordinal)
            || type.StartsWith("Z_", StringComparison.Ordinal))
        {
            register = A64Register.SveVector(index, A64GeneratedOperandShapes.ElementWidth(type));
            return true;
        }

        if (type.StartsWith("PPR", StringComparison.Ordinal)
            || type.StartsWith("PNR", StringComparison.Ordinal))
        {
            register = new A64Register(A64RegisterClass.Predicate, checked((byte)index), 0);
            return true;
        }

        register = default;
        return false;
    }

    private static bool TryMaterializeTarget(
        string type,
        uint value,
        int width,
        ulong address,
        out ulong target)
    {
        var signed = SignExtend(value, width);
        var scale = type.Contains("adrp", StringComparison.OrdinalIgnoreCase)
            ? 12
            : type.Contains("adrlabel", StringComparison.OrdinalIgnoreCase) ? 0 : 2;
        var delta = signed << scale;
        target = delta >= 0
            ? unchecked(address + (ulong)delta)
            : unchecked(address - (ulong)(-(delta + 1)) - 1UL);
        return true;
    }

    private static long MaterializeImmediate(
        string type,
        A64OperandEncodingInfo codec,
        uint value,
        int width)
    {
        var isSigned = type.StartsWith("simm", StringComparison.OrdinalIgnoreCase)
            || codec.ParserMatchClass.StartsWith("SImm", StringComparison.Ordinal);
        var materialized = isSigned ? SignExtend(value, width) : value;
        if (type.StartsWith("addsub_shifted_imm", StringComparison.Ordinal))
        {
            return (long)(value & 0xFFFu) * (((value >> 12) & 1u) != 0 ? 0x1000 : 1);
        }

        return materialized * ReadScale(type, codec.PrintMethod);
    }

    private static int ParseRegisterWidth(string type)
    {
        if (type.Contains("128", StringComparison.Ordinal)) return 128;
        if (type.Contains("64", StringComparison.Ordinal)) return 64;
        if (type.Contains("32", StringComparison.Ordinal)) return 32;
        return type.Contains("8", StringComparison.Ordinal) ? 8 : 16;
    }

    private static int ReadScale(string type, string printMethod)
    {
        if (TryReadAngleValue(printMethod, "Scale<", out var printScale)
            || TryReadAngleValue(printMethod, "scale<", out printScale))
        {
            return printScale;
        }

        var immediate = type.IndexOf("imm", StringComparison.OrdinalIgnoreCase);
        if (immediate >= 0)
        {
            var index = immediate + 3;
            while (index < type.Length && char.IsDigit(type[index])) index++;
            if (index < type.Length && (type[index] is 's' or 'S'))
            {
                index++;
                var start = index;
                var scale = 0;
                while (index < type.Length && char.IsDigit(type[index]))
                {
                    scale = scale * 10 + type[index++] - '0';
                }

                if (index != start && scale != 0) return scale;
            }
        }

        return 1;
    }

    private static bool TryReadAngleValue(string text, string marker, out int value)
    {
        var markerIndex = text.IndexOf(marker, StringComparison.Ordinal);
        if (markerIndex < 0)
        {
            value = 0;
            return false;
        }

        var index = markerIndex + marker.Length;
        value = 0;
        var start = index;
        while (index < text.Length && char.IsDigit(text[index]))
        {
            value = value * 10 + text[index++] - '0';
        }

        return index != start && index < text.Length && text[index] == '>';
    }

    private static long SignExtend(uint value, int width)
    {
        if (width is <= 0 or > 32) return value;
        if (width == 32) return unchecked((int)value);
        var mask = (1u << width) - 1u;
        var sign = 1u << (width - 1);
        var narrowed = value & mask;
        return (long)(narrowed ^ sign) - sign;
    }
}
