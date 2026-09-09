using System.Globalization;
using AsmStone.Encoding;
using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone.Encode;

internal static partial class A64GeneratedEncoder
{
    public static bool TryEncode(
        A64Instruction instruction,
        A64FeatureSet features,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        encoding = 0;
        ArgumentNullException.ThrowIfNull(features);
        A64CompiledInstruction compiled;
        if (instruction.SourceName is null
            || !A64InstructionCatalog.TryGetCompiledByName(instruction.SourceName, out compiled))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                "Generated instructions require their TableGen source name.");
            return false;
        }

        var info = compiled.Info;
        if (!features.SupportsAll(compiled.Predicates))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.UnsupportedFeature,
                $"Generated instruction '{info.Name}' requires predicates: {info.Predicates}.");
            return false;
        }

        if (!info.HasCompleteEncoding)
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidInstruction,
                $"Generated instruction '{info.Name}' has a partial encoding.");
            return false;
        }

        encoding = (instruction.Encoding & info.Mask) == info.Value
            ? instruction.Encoding
            : info.Value;
        Span<uint> values = stackalloc uint[compiled.Fields.Length];
        Span<byte> assigned = stackalloc byte[compiled.Fields.Length];
        var operandIndex = 0;
        var hasMemory = A64GeneratedMemory.TryGet(compiled, out var memoryBindings);
        MemoryOperand? memoryOperand = null;
        for (var index = 0; index < instruction.Operands.Count; index++)
        {
            if (instruction.Operands[index] is not MemoryOperand candidateMemory)
            {
                continue;
            }

            if (memoryOperand is not null)
            {
                diagnostic = InvalidOperands(info.Name);
                encoding = 0;
                return false;
            }

            memoryOperand = candidateMemory;
        }
        if (memoryOperand is not null && !hasMemory)
        {
            diagnostic = InvalidOperand("memory", "a supported generated memory binding");
            encoding = 0;
            return false;
        }

        if (memoryOperand is not null && memoryOperand.Mode != memoryBindings.Mode)
        {
            diagnostic = InvalidOperand("memory", $"addressing mode {memoryBindings.Mode}");
            encoding = 0;
            return false;
        }

        var ordering = A64GeneratedMemory.Ordering(compiled);
        if (memoryOperand is not null
            && memoryOperand.Ordering != A64MemoryOrdering.None
            && memoryOperand.Ordering != ordering)
        {
            diagnostic = InvalidOperand("memory", $"ordering {ordering}");
            encoding = 0;
            return false;
        }

        var accessSize = A64GeneratedMemory.AccessSize(compiled);
        if (memoryOperand is not null
            && memoryOperand.AccessSize != 0
            && accessSize != 0
            && memoryOperand.AccessSize != accessSize)
        {
            diagnostic = InvalidOperand("memory", $"access size {accessSize} bytes");
            encoding = 0;
            return false;
        }

        if (memoryOperand is not null
            && memoryBindings.OffsetName is null
            && memoryOperand.Offset != memoryBindings.FixedOffset)
        {
            diagnostic = InvalidOperand("memory", "the fixed offset encoded by this instruction");
            encoding = 0;
            return false;
        }

        foreach (var binding in compiled.Bindings)
        {
            if (binding.Kind == A64CompiledOperandKind.ModifiedRegister)
            {
                if (operandIndex >= instruction.Operands.Count
                    || instruction.Operands[operandIndex] is not ModifiedRegisterOperand modified)
                {
                    diagnostic = InvalidOperands(info.Name);
                    encoding = 0;
                    return false;
                }

                if (!TryEncodeRegisterValue(
                        binding,
                        modified.Register,
                        out var registerValue,
                        out diagnostic))
                {
                    encoding = 0;
                    return false;
                }

                var modifierWidth = compiled.GetField(binding.SecondaryFieldIndex).Width;
                if (modifierWidth < 32 && (modified.Modifier >> modifierWidth) != 0)
                {
                    diagnostic = InvalidOperand(binding.Name, $"a modifier that fits {modifierWidth} bits");
                    encoding = 0;
                    return false;
                }

                if (!A64RegisterModifier.TryDecode(binding.Type, modified.Modifier, out var decodedModifier)
                    || !A64RegisterModifier.TryEncode(
                        binding.Type,
                        decodedModifier.Kind,
                        decodedModifier.Amount,
                        out var canonicalModifier)
                    || canonicalModifier != modified.Modifier)
                {
                    diagnostic = InvalidOperand(binding.Name, "a valid register modifier for its instruction width");
                    encoding = 0;
                    return false;
                }

                if (!TrySetValue(compiled, binding.FieldIndex, registerValue, values, assigned)
                    || !TrySetValue(compiled, binding.SecondaryFieldIndex, modified.Modifier, values, assigned))
                {
                    diagnostic = InvalidOperands(info.Name);
                    encoding = 0;
                    return false;
                }
                operandIndex++;
                continue;
            }

            if (binding.FieldIndex < 0)
            {
                continue;
            }

            if (memoryOperand is not null && hasMemory)
            {
                if (binding.FieldIndex == memoryBindings.BaseFieldIndex)
                {
                    if (!TryEncodeRegisterValue(
                            binding,
                            memoryOperand.Base,
                            out var baseValue,
                            out diagnostic))
                    {
                        encoding = 0;
                        return false;
                    }

                    if (!TrySetValue(compiled, binding.FieldIndex, baseValue, values, assigned))
                    {
                        diagnostic = InvalidOperands(info.Name);
                        encoding = 0;
                        return false;
                    }

                    operandIndex++;
                    continue;
                }

                if (binding.FieldIndex == memoryBindings.OffsetFieldIndex)
                {
                    if (memoryOperand.Index is not null || binding.Codec is null)
                    {
                        diagnostic = InvalidOperand("memory", "an offset without an index register");
                        encoding = 0;
                        return false;
                    }

                    if (!TryEncodeImmediateValue(
                            binding.Type,
                            binding.Codec,
                            memoryOperand.Offset,
                            compiled.GetField(binding.FieldIndex).Width,
                            out var offsetValue,
                            out diagnostic))
                    {
                        encoding = 0;
                        return false;
                    }

                    if (!TrySetValue(compiled, binding.FieldIndex, offsetValue, values, assigned))
                    {
                        diagnostic = InvalidOperands(info.Name);
                        encoding = 0;
                        return false;
                    }

                    continue;
                }

                if (binding.FieldIndex == memoryBindings.IndexFieldIndex)
                {
                    if (memoryOperand.Offset != 0 || memoryOperand.Index is null)
                    {
                        diagnostic = InvalidOperand("memory", "the index register required by its addressing mode");
                        encoding = 0;
                        return false;
                    }

                    if (!TryEncodeRegisterValue(
                            binding,
                            memoryOperand.Index.Value,
                            out var indexValue,
                            out diagnostic))
                    {
                        encoding = 0;
                        return false;
                    }

                    if (!TrySetValue(compiled, binding.FieldIndex, indexValue, values, assigned))
                    {
                        diagnostic = InvalidOperands(info.Name);
                        encoding = 0;
                        return false;
                    }

                    continue;
                }

                if (binding.FieldIndex == memoryBindings.ModifierFieldIndex)
                {
                    if (memoryOperand.Index is null
                        || !memoryOperand.IndexModifier.HasValue
                            && !memoryOperand.IndexModifierSemantics.HasValue)
                    {
                        diagnostic = InvalidOperand("memory", "an index modifier");
                        encoding = 0;
                        return false;
                    }

                    var modifierValue = memoryOperand.IndexModifier ?? 0;
                    if (memoryOperand.IndexModifier is { } rawModifier
                        && memoryOperand.IndexModifierSemantics is { } semanticModifier
                        && (memoryBindings.ModifierBindingIndex < 0
                            || !A64GeneratedMemory.TryEncodeIndexModifier(
                                compiled.GetBinding(memoryBindings.ModifierBindingIndex).Type,
                                semanticModifier,
                                out var semanticRaw)
                            || semanticRaw != rawModifier))
                    {
                        diagnostic = InvalidOperand("memory", "matching raw and typed index modifiers");
                        encoding = 0;
                        return false;
                    }

                    if (!memoryOperand.IndexModifier.HasValue
                        && (memoryBindings.ModifierBindingIndex < 0
                            || (uint)memoryBindings.ModifierBindingIndex >= (uint)compiled.Bindings.Length
                            || !A64GeneratedMemory.TryEncodeIndexModifier(
                                compiled.GetBinding(memoryBindings.ModifierBindingIndex).Type,
                                memoryOperand.IndexModifierSemantics!.Value,
                                out modifierValue)))
                    {
                        diagnostic = InvalidOperand("memory", "a valid index modifier");
                        encoding = 0;
                        return false;
                    }

                    if (!TryEncodeRawValue(compiled, binding.FieldIndex, modifierValue, out modifierValue, out diagnostic))
                    {
                        encoding = 0;
                        return false;
                    }

                    if (!TrySetValue(compiled, binding.FieldIndex, modifierValue, values, assigned))
                    {
                        diagnostic = InvalidOperands(info.Name);
                        encoding = 0;
                        return false;
                    }

                    continue;
                }
            }

            A64Operand operand;
            var consumesInstructionOperand = true;
            if (operandIndex >= instruction.Operands.Count
                || instruction.Operands[operandIndex] is MemoryOperand)
            {
                diagnostic = InvalidOperands(info.Name);
                encoding = 0;
                return false;
            }

            operand = instruction.Operands[operandIndex];

            if (consumesInstructionOperand)
            {
                operandIndex++;
            }

            if (!TryEncodeCompiledOperand(
                    binding,
                    compiled,
                    operand,
                    instruction.Address,
                    out var value,
                    out diagnostic))
            {
                encoding = 0;
                return false;
            }

            if (!TrySetValue(compiled, binding.FieldIndex, value, values, assigned))
            {
                diagnostic = InvalidOperands(info.Name);
                encoding = 0;
                return false;
            }
        }

        if (operandIndex != instruction.Operands.Count)
        {
            diagnostic = InvalidOperands(info.Name);
            encoding = 0;
            return false;
        }

        for (var index = 0; index < compiled.Fields.Length; index++)
        {
            if (assigned[index] != 0
                && !compiled.Fields[index].TryInsert(values[index], ref encoding, out diagnostic))
            {
                encoding = 0;
                return false;
            }
        }

        diagnostic = A64Diagnostic.None;
        return true;
    }

    private static bool TryEncodeRegisterValue(
        A64CompiledBinding binding,
        A64Register register,
        out uint value,
        out A64Diagnostic diagnostic)
    {
        if (register.Index > 31
            || register.Class != binding.RegisterClass
            || binding.RegisterWidth != 0 && register.Width != binding.RegisterWidth
            || !binding.RegisterConstraint.Accepts(register.Index))
        {
            value = 0;
            diagnostic = InvalidOperand(
                binding.Name,
                "a register with the class and width required by its codec");
            return false;
        }

        if (binding.RegisterClass == A64RegisterClass.General && register.Index == 31)
        {
            if (binding.AllowsStackPointer != register.IsStackPointer
                || binding.AllowsZeroRegister != register.IsZeroRegister)
            {
                value = 0;
                diagnostic = InvalidOperand(binding.Name, "the register role required by its codec");
                return false;
            }
        }

        var encodedIndex = register.Index - binding.RegisterIndexBias;
        if (encodedIndex < 0
            || binding.RegisterIndexScale <= 0
            || encodedIndex % binding.RegisterIndexScale != 0)
        {
            value = 0;
            diagnostic = InvalidOperand(binding.Name, "a register with the encoded index range required by its codec");
            return false;
        }

        value = (uint)(encodedIndex / binding.RegisterIndexScale);
        diagnostic = A64Diagnostic.None;
        return true;
    }

    private static bool TryEncodeRawValue(
        A64CompiledInstruction info,
        int fieldIndex,
        uint value,
        out uint encoded,
        out A64Diagnostic diagnostic)
    {
        var width = FieldWidth(info, fieldIndex);
        if (width < 32 && (value >> width) != 0)
        {
            encoded = 0;
            diagnostic = InvalidOperand(info.GetField(fieldIndex).Name, $"a value that fits {width} bits");
            return false;
        }

        encoded = value;
        diagnostic = A64Diagnostic.None;
        return true;
    }

    private static bool TryEncodeImmediateValue(
        string type,
        A64GeneratedOperand codec,
        long rawValue,
        int width,
        out uint value,
        out A64Diagnostic diagnostic)
    {
        if (type.StartsWith("addsub_shifted_imm", StringComparison.Ordinal))
        {
            if (rawValue < 0 || rawValue > 0xFFF000L || (rawValue > 0xFFF && (rawValue & 0xFFF) != 0))
            {
                value = 0;
                diagnostic = new A64Diagnostic(A64DiagnosticCode.OutOfRange, "Shifted ADD/SUB immediate is out of range.");
                return false;
            }

            value = rawValue <= 0xFFF ? (uint)rawValue : (uint)((rawValue >> 12) | 0x1000);
            diagnostic = A64Diagnostic.None;
            return true;
        }

        var scale = ReadScale(type, codec.PrintMethod);
        if (scale != 0 && rawValue % scale != 0)
        {
            value = 0;
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidOperand,
                $"Immediate for '{type}' is not divisible by its scale.");
            return false;
        }

        var unscaled = rawValue / scale;
        var isSigned = type.StartsWith("simm", StringComparison.OrdinalIgnoreCase)
            || codec.ParserMatchClass.StartsWith("SImm", StringComparison.Ordinal);
        var minimum = isSigned
            ? width == 32 ? int.MinValue : -(1L << (width - 1))
            : 0;
        var maximum = isSigned
            ? width == 32 ? int.MaxValue : (1L << (width - 1)) - 1
            : width == 32 ? uint.MaxValue : (1L << width) - 1;
        if (unscaled < minimum || unscaled > maximum)
        {
            value = 0;
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.OutOfRange,
                $"Immediate for '{type}' does not fit its field.");
            return false;
        }

        value = unchecked((uint)unscaled);
        diagnostic = A64Diagnostic.None;
        return true;
    }

    private static bool TryEncodeCompiledOperand(
        A64CompiledBinding binding,
        A64CompiledInstruction info,
        A64Operand operand,
        ulong address,
        out uint value,
        out A64Diagnostic diagnostic)
    {
        if (operand is EncodedFieldOperand raw)
        {
            return TryEncodeRawValue(info, binding.FieldIndex, raw.Value, out value, out diagnostic);
        }

        switch (binding.Kind)
        {
            case A64CompiledOperandKind.EncodedField:
                if (operand is EncodedFieldOperand encodedField)
                {
                    return TryEncodeRawValue(info, binding.FieldIndex, encodedField.Value, out value, out diagnostic);
                }

                break;
            case A64CompiledOperandKind.Register:
                if (operand is RegisterOperand register)
                {
                    if (!TryValidateFixedModifier(binding, register.Modifier, out diagnostic))
                    {
                        value = 0;
                        return false;
                    }

                    return TryEncodeRegisterValue(
                        binding,
                        register.Register,
                        out value,
                        out diagnostic);
                }

                break;
            case A64CompiledOperandKind.ModifiedRegister:
                if (operand is ModifiedRegisterOperand modified)
                {
                    if (!TryEncodeRegisterValue(
                            binding,
                            modified.Register,
                            out value,
                            out diagnostic))
                    {
                        return false;
                    }

                    if (!A64RegisterModifier.TryDecode(
                            binding.Type,
                            modified.Modifier,
                            out var decodedModifier)
                        || !A64RegisterModifier.TryEncode(
                            binding.Type,
                            decodedModifier.Kind,
                            decodedModifier.Amount,
                            out var canonicalModifier)
                        || canonicalModifier != modified.Modifier)
                    {
                        diagnostic = InvalidOperand(binding.Name, "a valid register modifier for its instruction width");
                        value = 0;
                        return false;
                    }

                    if (binding.SecondaryFieldIndex < 0
                        || binding.SecondaryFieldIndex >= info.Fields.Length
                        || (info.Fields[binding.SecondaryFieldIndex].Width < 32
                            && (modified.Modifier >> info.Fields[binding.SecondaryFieldIndex].Width) != 0))
                    {
                        diagnostic = InvalidOperand(binding.Name, "a modifier that fits its encoded field");
                        value = 0;
                        return false;
                    }

                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                break;
            case A64CompiledOperandKind.RegisterModifier:
                if (operand is RegisterModifierOperand registerModifier
                    && A64RegisterModifier.TryEncode(
                        binding.Type,
                        registerModifier.Modifier.Kind,
                        registerModifier.Modifier.Amount,
                        out var registerModifierValue))
                {
                    value = registerModifierValue;
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                diagnostic = InvalidOperand(binding.Name, "a valid arithmetic register modifier");
                value = 0;
                return false;
            case A64CompiledOperandKind.SystemRegister:
                if (operand is SystemRegisterOperand systemRegister)
                {
                    return TryEncodeRawValue(info, binding.FieldIndex, systemRegister.Encoding, out value, out diagnostic);
                }

                break;
            case A64CompiledOperandKind.MatrixTileMask:
                if (operand is MatrixTileMaskOperand tileMask)
                {
                    value = tileMask.Mask;
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                break;
            case A64CompiledOperandKind.MatrixRegister:
                if (operand is MatrixRegisterOperand matrix
                    && matrix.Kind == binding.MatrixRegisterKind
                    && (matrix.ElementWidth == 0 || matrix.ElementWidth == binding.ElementWidth))
                {
                    if (matrix.EncodedValue is { } rawMatrix
                        && (rawMatrix > int.MaxValue
                            || A64GeneratedOperandShapes.DecodeMatrixRegisterIndex(
                                binding.Type,
                                (int)rawMatrix) != matrix.Index))
                    {
                        diagnostic = InvalidOperand(binding.Name, "matching semantic and raw matrix register indices");
                        value = 0;
                        return false;
                    }

                    var encodedValue = matrix.EncodedValue
                        ?? (A64GeneratedOperandShapes.TryEncodeMatrixRegisterIndex(
                            binding.Type,
                            matrix.Index,
                            out var matrixIndex)
                            ? (uint)matrixIndex
                            : uint.MaxValue);
                    if (encodedValue == uint.MaxValue)
                    {
                        diagnostic = InvalidOperand(binding.Name, "a matrix register index allowed by its codec");
                        value = 0;
                        return false;
                    }

                    return TryEncodeRawValue(info, binding.FieldIndex, encodedValue, out value, out diagnostic);
                }

                break;
            case A64CompiledOperandKind.LogicalImmediate:
                if (operand is ImmediateOperand logicalImmediate)
                {
                    var logicalWidth = binding.Type == "logical_imm32" ? 32 : 64;
                    if (logicalImmediate.EncodedValue is { } logicalEncoded
                        && A64LogicalImmediate.TryDecode(logicalEncoded, logicalWidth, out var logicalMask)
                        && unchecked((long)logicalMask) == logicalImmediate.Value)
                    {
                        value = logicalEncoded;
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    if (A64LogicalImmediate.TryEncode(
                            unchecked((ulong)logicalImmediate.Value),
                            logicalWidth,
                            out value))
                    {
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    diagnostic = InvalidOperand(binding.Name, "a valid AArch64 logical immediate mask");
                    return false;
                }

                break;
            case A64CompiledOperandKind.SimdImmediate:
                if (operand is ImmediateOperand simdImmediate)
                {
                    if (simdImmediate.EncodedValue is { } simdEncoded
                        && unchecked((long)A64AdvSimdImmediate.DecodeType10(simdEncoded)) == simdImmediate.Value)
                    {
                        value = simdEncoded;
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    if (A64AdvSimdImmediate.TryEncodeType10(
                            unchecked((ulong)simdImmediate.Value),
                            out value))
                    {
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    diagnostic = InvalidOperand(binding.Name, "an AdvSIMD Type10 immediate");
                    return false;
                }

                break;
            case A64CompiledOperandKind.MoveWideShift:
                if (operand is ImmediateOperand moveWideShift)
                {
                    if (moveWideShift.EncodedValue is { } moveWideEncoded
                        && A64MoveWideImmediate.DecodeShift(moveWideEncoded) == moveWideShift.Value)
                    {
                        value = moveWideEncoded;
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    if (A64MoveWideImmediate.TryEncodeShift(binding.Type, moveWideShift.Value, out value))
                    {
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    diagnostic = InvalidOperand(binding.Name, "a valid move-wide halfword shift");
                    return false;
                }

                break;
            case A64CompiledOperandKind.MoveWideImmediate:
                if (operand is ImmediateOperand moveWideImmediate)
                {
                    return TryEncodeImmediateValue(binding, moveWideImmediate, out value, out diagnostic);
                }

                break;
            case A64CompiledOperandKind.FloatingImmediate:
                if (operand is FloatingImmediateOperand floatingImmediate)
                {
                    if (floatingImmediate.EncodedValue is { } floatingEncoded
                        && A64FloatingImmediate.TryDecode(
                            binding.Type,
                            floatingEncoded,
                            out var decodedFloating)
                        && BitConverter.DoubleToInt64Bits(decodedFloating)
                            == BitConverter.DoubleToInt64Bits(floatingImmediate.Value))
                    {
                        value = floatingEncoded;
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    if (A64FloatingImmediate.TryEncode(binding.Type, floatingImmediate.Value, out value))
                    {
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    diagnostic = InvalidOperand(binding.Name, "an encodable AArch64 floating immediate");
                    return false;
                }

                break;
            case A64CompiledOperandKind.VectorShift:
                if (operand is ImmediateOperand vectorShift
                    && A64VectorShift.TryEncode(binding.Type, vectorShift.Value, out value))
                {
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                value = 0;
                diagnostic = InvalidOperand(binding.Name, "a valid AdvSIMD vector shift");
                return false;

            case A64CompiledOperandKind.SveIncrement:
                if (operand is ImmediateOperand increment
                    && A64SVEImmediate.TryEncodeIncDec(increment.Value, out value))
                {
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                value = 0;
                diagnostic = InvalidOperand(binding.Name, "an SVE increment/decrement value between 1 and 16");
                return false;

            case A64CompiledOperandKind.BitIndex:
                if (operand is ImmediateOperand bitIndex
                    && A64BitIndex.TryEncode(binding.Type, bitIndex.Value, out value))
                {
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                value = 0;
                diagnostic = InvalidOperand(binding.Name, "a valid TBZ/TBNZ bit index");
                return false;

            case A64CompiledOperandKind.EnumImmediate:
                if (operand is ImmediateOperand enumImmediate
                    && (enumImmediate is not EnumImmediateOperand typedEnum
                        || typedEnum.EnumKind == A64EnumKind.Unknown
                        || typedEnum.EnumKind == binding.EnumKind)
                    && A64EnumImmediate.TryEncode(binding.Type, enumImmediate.Value, binding.FieldWidth, out value))
                {
                    if (enumImmediate.EncodedValue is { } enumEncoded
                        && A64EnumImmediate.TryDecode(
                            binding.Type,
                            enumEncoded,
                            binding.FieldWidth,
                            out var decodedEnumValue)
                        && decodedEnumValue == enumImmediate.Value)
                    {
                        value = enumEncoded;
                    }

                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                if (operand is EnumImmediateOperand mismatchedEnum
                    && mismatchedEnum.EnumKind != A64EnumKind.Unknown
                    && mismatchedEnum.EnumKind != binding.EnumKind)
                {
                    diagnostic = InvalidOperand(binding.Name, "the enum domain required by its codec");
                    value = 0;
                    return false;
                }

                break;
            case A64CompiledOperandKind.VectorList:
                if (operand is VectorRegisterListOperand vectorList
                    && vectorList.Registers.Count == binding.ShapeCount
                    && vectorList.ElementWidth == binding.ElementWidth)
                {
                    var first = vectorList.Registers[0].Index;
                    for (var index = 0; index < vectorList.Registers.Count; index++)
                    {
                        if (vectorList.Registers[index].Class != A64RegisterClass.Vector
                            || vectorList.Registers[index].Index != (first + index) % 32)
                        {
                            diagnostic = InvalidOperand(binding.Name, "a consecutive vector register list");
                            value = 0;
                            return false;
                        }
                    }

                    value = first;
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                break;
            case A64CompiledOperandKind.RegisterGroup:
                if (operand is RegisterGroupOperand registerGroup
                    && registerGroup.Registers.Count == binding.ShapeCount
                    && registerGroup.ElementWidth == binding.ElementWidth
                    && (binding.GroupStride == 0 || registerGroup.Stride == binding.GroupStride))
                {
                    var first = registerGroup.Registers[0].Index;
                    if (!binding.RegisterConstraint.Accepts(first))
                    {
                        diagnostic = InvalidOperand(binding.Name, "a register group with the range required by its codec");
                        value = 0;
                        return false;
                    }

                    var expectedClass = binding.Type.StartsWith('P')
                        ? A64RegisterClass.Predicate
                        : A64RegisterClass.SveVector;
                    var groupStride = binding.GroupStride == 0
                        ? registerGroup.Stride
                        : binding.GroupStride;
                    for (var index = 0; index < registerGroup.Registers.Count; index++)
                    {
                        if (registerGroup.Registers[index].Class != expectedClass
                            || registerGroup.Registers[index].Index
                                != (first + index * groupStride) % 32)
                        {
                            diagnostic = InvalidOperand(binding.Name, "a consecutive register group");
                            value = 0;
                            return false;
                        }
                    }

                    int encodedFirst;
                    if (binding.Type.StartsWith("ZZ", StringComparison.Ordinal)
                        && binding.Type.Contains("strided", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!A64GeneratedOperandShapes.TryEncodeGroupFirstIndex(
                                binding.Type,
                                first,
                                registerGroup.Stride,
                                out encodedFirst))
                        {
                            diagnostic = InvalidOperand(binding.Name, "a register group with the encoded stride required by its codec");
                            value = 0;
                            return false;
                        }
                    }
                    else
                    {
                        encodedFirst = first - binding.RegisterIndexBias;
                        if (encodedFirst < 0
                            || binding.RegisterIndexScale <= 0
                            || encodedFirst % binding.RegisterIndexScale != 0)
                        {
                            diagnostic = InvalidOperand(binding.Name, "a register group with the encoded range required by its codec");
                            value = 0;
                            return false;
                        }

                        encodedFirst /= binding.RegisterIndexScale;
                    }

                    value = (uint)encodedFirst;
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                break;
            case A64CompiledOperandKind.RegisterPair:
                if (operand is RegisterPairOperand pair
                    && pair.First.Class == binding.RegisterClass
                    && pair.Second.Class == binding.RegisterClass
                    && pair.First.Width == binding.RegisterWidth
                    && pair.Second.Width == binding.RegisterWidth
                    && pair.Second.Index == pair.First.Index + 1
                    && binding.RegisterConstraint.Accepts(pair.First.Index))
                {
                    value = pair.First.Index;
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                break;
            case A64CompiledOperandKind.PcRelative:
                if (operand is TargetOperand target)
                {
                    var targetBase = binding.IsPageRelative ? target.Address & ~0xFFFUL : target.Address;
                    var sourceBase = binding.IsPageRelative ? address & ~0xFFFUL : address;
                    TryGetDelta(targetBase, sourceBase, out var delta);
                    var scale = 1L << binding.PcRelativeScale;
                    if ((delta & (scale - 1)) != 0)
                    {
                        diagnostic = new A64Diagnostic(
                            A64DiagnosticCode.MisalignedTarget,
                            "Target is not aligned for its PC-relative encoding.");
                        value = 0;
                        return false;
                    }

                    var scaled = delta / scale;
                    var minimum = -(1L << (binding.FieldWidth - 1));
                    var maximum = (1L << (binding.FieldWidth - 1)) - 1;
                    if (scaled < minimum || scaled > maximum)
                    {
                        diagnostic = new A64Diagnostic(
                            A64DiagnosticCode.OutOfRange,
                            $"Target for '{binding.Name}' does not fit its signed field.");
                        value = 0;
                        return false;
                    }

                    value = unchecked((uint)scaled);
                    diagnostic = A64Diagnostic.None;
                    return true;
                }

                break;
            case A64CompiledOperandKind.Immediate:
                if (operand is ImmediateOperand immediate)
                {
                    if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.HinteImmediate)
                    {
                        if (immediate.EncodedValue is { } encodedHinte
                            && A64HinteImmediate.TryDecode(encodedHinte, out var decodedHinte)
                            && decodedHinte == immediate.Value)
                        {
                            value = encodedHinte;
                            diagnostic = A64Diagnostic.None;
                            return true;
                        }

                        if (A64HinteImmediate.TryEncode(immediate.Value, out value))
                        {
                            diagnostic = A64Diagnostic.None;
                            return true;
                        }

                        diagnostic = InvalidOperand(binding.Name, "a valid HINTE immediate");
                        value = 0;
                        return false;
                    }

                    if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.SveOptionalShift)
                    {
                        if (immediate.EncodedValue is { } encodedSveImmediate
                            && A64SVEImmediate.TryDecode(
                                binding.Type,
                                encodedSveImmediate,
                                binding.FieldWidth,
                                out var decodedSveImmediate,
                                out var decodedSveShift)
                            && decodedSveImmediate == immediate.Value
                            && (immediate.ShiftAmount == 0 || immediate.ShiftAmount == decodedSveShift))
                        {
                            value = encodedSveImmediate;
                            diagnostic = A64Diagnostic.None;
                            return true;
                        }

                        if (A64SVEImmediate.TryEncode(
                                binding.Type,
                                immediate.Value,
                                immediate.ShiftAmount,
                                binding.FieldWidth,
                                out value))
                        {
                            diagnostic = A64Diagnostic.None;
                            return true;
                        }

                        diagnostic = InvalidOperand(binding.Name, "a valid SVE immediate with optional lsl #8");
                        value = 0;
                        return false;
                    }

                    if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.LaneIndex)
                    {
                        if (immediate.Value < 0
                            || binding.LaneCount != 0 && immediate.Value >= binding.LaneCount
                            || immediate.Value >= (1L << Math.Min(binding.FieldWidth, 31)))
                        {
                            diagnostic = InvalidOperand(binding.Name, "a lane index allowed by its element width");
                            value = 0;
                            return false;
                        }

                        value = (uint)immediate.Value;
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.ComplexRotation
                        && A64ComplexRotation.TryEncode(binding.Type, immediate.Value, out value))
                    {
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.FixedPoint
                        && A64FixedPointImmediate.TryEncode(binding.Type, immediate.Value, out value))
                    {
                        diagnostic = A64Diagnostic.None;
                        return true;
                    }

                    return TryEncodeImmediateValue(binding, immediate, out value, out diagnostic);
                }

                break;
        }

        value = 0;
        diagnostic = InvalidOperand(binding.Name, "an operand matching its generated codec");
        return false;
    }

    private static bool TryValidateFixedModifier(
        A64CompiledBinding binding,
        A64RegisterModifier? modifier,
        out A64Diagnostic diagnostic)
    {
        if (binding.FixedModifierKind == A64RegisterModifierKind.Unknown
            || modifier is null)
        {
            diagnostic = A64Diagnostic.None;
            return true;
        }

        if (modifier.Value.Kind == binding.FixedModifierKind
            && modifier.Value.Amount == binding.FixedModifierAmount)
        {
            diagnostic = A64Diagnostic.None;
            return true;
        }

        diagnostic = InvalidOperand(binding.Name, "the fixed register extension or shift required by its codec");
        return false;
    }

    private static bool TryEncodeImmediateValue(
        A64CompiledBinding binding,
        ImmediateOperand immediate,
        out uint value,
        out A64Diagnostic diagnostic)
    {
        var rawValue = immediate.Value;
        if (binding.Type.StartsWith("addsub_shifted_imm", StringComparison.Ordinal))
        {
            if (immediate.EncodedValue is { } encodedValue
                && (long)(encodedValue & 0xFFFu) * (((encodedValue >> 12) & 1u) != 0 ? 0x1000 : 1) == rawValue)
            {
                value = encodedValue;
                diagnostic = A64Diagnostic.None;
                return true;
            }

            if (rawValue < 0 || rawValue > 0xFFF000L || (rawValue > 0xFFF && (rawValue & 0xFFF) != 0))
            {
                value = 0;
                diagnostic = new A64Diagnostic(A64DiagnosticCode.OutOfRange, "Shifted ADD/SUB immediate is out of range.");
                return false;
            }

            value = rawValue <= 0xFFF ? (uint)rawValue : (uint)((rawValue >> 12) | 0x1000);
            diagnostic = A64Diagnostic.None;
            return true;
        }

        var scale = binding.Scale;
        if (scale != 0 && rawValue % scale != 0)
        {
            value = 0;
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.InvalidOperand,
                $"Immediate for '{binding.Type}' is not divisible by its scale.");
            return false;
        }

        var unscaled = rawValue / scale;
        var minimum = binding.IsSigned
            ? binding.FieldWidth == 32 ? int.MinValue : -(1L << (binding.FieldWidth - 1))
            : 0;
        var maximum = binding.IsSigned
            ? binding.FieldWidth == 32 ? int.MaxValue : (1L << (binding.FieldWidth - 1)) - 1
            : binding.FieldWidth == 32 ? uint.MaxValue : (1L << binding.FieldWidth) - 1;
        if (unscaled < minimum || unscaled > maximum)
        {
            value = 0;
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.OutOfRange,
                $"Immediate for '{binding.Type}' does not fit its field.");
            return false;
        }

        value = unchecked((uint)unscaled);
        diagnostic = A64Diagnostic.None;
        return true;
    }

    private static bool TrySetValue(
        A64CompiledInstruction instruction,
        int index,
        uint value,
        Span<uint> values,
        Span<byte> assigned)
    {
        if ((uint)index >= (uint)instruction.Fields.Length)
        {
            return false;
        }

        values[index] = value;
        assigned[index] = 1;
        return true;
    }

    private static int FieldWidth(A64CompiledInstruction instruction, int index)
    {
        return (uint)index < (uint)instruction.Fields.Length
            ? instruction.Fields[index].Width
            : 32;
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

    private static bool TryGetDelta(ulong target, ulong source, out long delta)
    {
        var moduloDistance = target - source;
        delta = moduloDistance <= (ulong)long.MaxValue
            ? (long)moduloDistance
            : long.MinValue + (long)(moduloDistance - ((ulong)long.MaxValue + 1UL));
        return true;
    }

    private static A64Diagnostic InvalidOperands(string name)
    {
        return new A64Diagnostic(A64DiagnosticCode.InvalidOperand, $"Generated instruction '{name}' received the wrong operand count.");
    }

    private static A64Diagnostic InvalidOperand(string name, string expected)
    {
        return new A64Diagnostic(A64DiagnosticCode.InvalidOperand, $"Generated operand '{name}' expects {expected}.");
    }

}
