using AsmStone.Encoding;
using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone.Decode;

internal static partial class A64OperandMaterializer
{
    public static IReadOnlyList<A64Operand> Materialize(A64DecodedEncoding decoded, ulong address)
    {
        return Materialize(decoded.Metadata, new FieldAccessor(decoded.Fields), address);
    }

    internal static IReadOnlyList<A64Operand> Materialize(
        A64CompiledInstruction decoded,
        uint encoding,
        ulong address)
    {
        return Materialize(decoded, new FieldAccessor(decoded, encoding), address);
    }

    internal static bool TryMaterializeSemanticBinding(
        A64CompiledInstruction decoded,
        A64CompiledBinding binding,
        uint encoding,
        ulong address,
        out A64Operand operand)
    {
        return TryMaterializeBinding(binding, new FieldAccessor(decoded, encoding), address, out operand);
    }

    private static IReadOnlyList<A64Operand> Materialize(
        A64CompiledInstruction decoded,
        FieldAccessor fields,
        ulong address)
    {
        var memory = decoded.Memory;
        MemoryOperand? materializedMemory = null;
        var useMemory = memory is { } memoryBinding
            && TryMaterializeMemory(decoded, fields, memoryBinding, out materializedMemory);
        var operands = new A64Operand[useMemory ? decoded.OperandCount : decoded.UncollapsedOperandCount];
        if (operands.Length == 0)
        {
            return Array.Empty<A64Operand>();
        }
        var operandCount = 0;
        foreach (var binding in decoded.Bindings)
        {
            if (binding.FieldIndex < 0)
            {
                continue;
            }

            if (useMemory
                && memory is { } activeMemory
                && binding.FieldIndex != activeMemory.BaseFieldIndex
                && (binding.FieldIndex == activeMemory.OffsetFieldIndex
                    || binding.FieldIndex == activeMemory.IndexFieldIndex
                    || binding.FieldIndex == activeMemory.ModifierFieldIndex))
            {
                continue;
            }

            if (useMemory
                && memory is { } memoryOperandBinding
                && binding.FieldIndex == memoryOperandBinding.BaseFieldIndex)
            {
                operands[operandCount++] = materializedMemory!;
                continue;
            }

            if (TryMaterializeBinding(binding, fields, address, out var operand))
            {
                operands[operandCount++] = operand;
            }
        }

        return operandCount == operands.Length
            ? operands
            : operands.AsSpan(0, operandCount).ToArray();
    }

    private static bool TryMaterializeBinding(
        A64CompiledBinding binding,
        FieldAccessor fields,
        ulong address,
        out A64Operand operand)
    {
        if (binding.Kind == A64CompiledOperandKind.ModifiedRegister)
        {
            if (fields.TryGet(binding.FieldIndex, out var registerField)
                && fields.TryGet(binding.SecondaryFieldIndex, out var modifierField)
                && TryMaterializeRegister(binding, registerField.Value, out var modifiedRegister))
            {
                operand = new ModifiedRegisterOperand(
                    modifiedRegister,
                    modifierField.Value,
                    binding.Type);
                return true;
            }

            operand = default!;
            return false;
        }

        if (binding.Kind == A64CompiledOperandKind.RegisterModifier
            && fields.TryGet(binding.FieldIndex, out var standaloneModifierField)
            && A64RegisterModifier.TryDecode(binding.Type, standaloneModifierField.Value, out var registerModifier))
        {
            operand = new RegisterModifierOperand(registerModifier, binding.Type);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.MatrixRegister)
        {
            var encoded = fields.TryGet(binding.FieldIndex, out var matrixField)
                ? matrixField.Value
                : 0u;
            operand = new MatrixRegisterOperand(
                binding.MatrixRegisterKind,
                A64GeneratedOperandShapes.DecodeMatrixRegisterIndex(binding.Type, (int)encoded),
                binding.ElementWidth,
                binding.Type,
                fields.TryGet(binding.FieldIndex, out _) ? encoded : null);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.RegisterPair)
        {
            var encoded = fields.TryGet(binding.FieldIndex, out var pairField)
                ? pairField.Value
                : 31u;
            operand = MaterializeRegisterPair(binding, encoded);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.Immediate
            && binding.FieldIndex < 0
            && A64GeneratedOperandShapes.TryGetImplicitImmediate(binding.Type, out var implicitImmediate))
        {
            if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.LaneIndex)
            {
                operand = new LaneIndexOperand(
                    implicitImmediate,
                    binding.ElementWidth,
                    binding.LaneCount)
                {
                    SemanticDomain = binding.SemanticDomain,
                };
            }
            else
            {
                operand = new ImmediateOperand(implicitImmediate)
                {
                    SemanticKind = binding.ImmediateSemanticKind,
                    EnumKind = binding.EnumKind,
                    SemanticDomain = binding.SemanticDomain,
                    ElementWidth = binding.ElementWidth,
                    LaneCount = binding.LaneCount,
                    FractionalBits = binding.FractionalBits,
                };
            }

            return true;
        }

        if (!fields.TryGet(binding.FieldIndex, out var field))
        {
            operand = default!;
            return false;
        }

        if (binding.Codec is null)
        {
            operand = new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
            return true;
        }

        var codec = CodecInfo(binding.Codec);
        if (binding.Kind == A64CompiledOperandKind.SystemRegister)
        {
            operand = new SystemRegisterOperand(field.Value);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.MatrixTileMask)
        {
            operand = new MatrixTileMaskOperand((byte)field.Value);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.LogicalImmediate)
        {
            operand = A64LogicalImmediate.TryDecode(
                    field.Value,
                    binding.Type == "logical_imm32" ? 32 : 64,
                    out var logicalImmediate)
                ? new ImmediateOperand(unchecked((long)logicalImmediate), field.Value)
                {
                    SemanticKind = A64ImmediateSemanticKind.LogicalImmediate,
                    SemanticDomain = binding.SemanticDomain,
                }
                : new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.SimdImmediate)
        {
            operand = new ImmediateOperand(
                unchecked((long)A64AdvSimdImmediate.DecodeType10(field.Value)),
                field.Value)
            {
                SemanticKind = A64ImmediateSemanticKind.SimdImmediate,
                SemanticDomain = binding.SemanticDomain,
            };
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.MoveWideImmediate)
        {
            operand = new ImmediateOperand(field.Value, field.Value)
            {
                SemanticKind = A64ImmediateSemanticKind.MoveWideImmediate,
                SemanticDomain = binding.SemanticDomain,
            };
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.MoveWideShift)
        {
            operand = new ImmediateOperand(A64MoveWideImmediate.DecodeShift(field.Value), field.Value)
            {
                SemanticKind = A64ImmediateSemanticKind.Shift,
                SemanticDomain = binding.SemanticDomain,
            };
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.FloatingImmediate)
        {
            operand = A64FloatingImmediate.TryDecode(binding.Type, field.Value, out var floatingValue)
                ? new FloatingImmediateOperand(
                    floatingValue,
                    field.Value,
                    binding.Type)
                : new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.VectorShift)
        {
            operand = A64VectorShift.TryDecode(binding.Type, field.Value, out var vectorShift)
                ? new ImmediateOperand(vectorShift, field.Value)
                {
                    SemanticKind = A64ImmediateSemanticKind.Shift,
                    SemanticDomain = binding.SemanticDomain,
                }
                : new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.SveIncrement)
        {
            operand = A64SVEImmediate.TryDecodeIncDec(field.Value, out var increment)
                ? new ImmediateOperand(increment, field.Value)
                {
                    SemanticKind = A64ImmediateSemanticKind.SveIncrement,
                    SemanticDomain = binding.SemanticDomain,
                }
                : new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.BitIndex)
        {
            operand = new ImmediateOperand(A64BitIndex.Decode(binding.Type, field.Value), field.Value)
            {
                SemanticKind = A64ImmediateSemanticKind.BitIndex,
                SemanticDomain = binding.SemanticDomain,
            };
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.SveOptionalShift
            && A64SVEImmediate.TryDecode(
                binding.Type,
                field.Value,
                field.Width,
                out var sveImmediate,
                out var sveShift))
        {
            operand = new ImmediateOperand(sveImmediate, field.Value)
            {
                SemanticKind = A64ImmediateSemanticKind.SveOptionalShift,
                SemanticDomain = binding.SemanticDomain,
                ElementWidth = binding.ElementWidth,
                ShiftAmount = sveShift,
            };
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.HinteImmediate
            && A64HinteImmediate.TryDecode(field.Value, out var hinteImmediate))
        {
            operand = new ImmediateOperand(hinteImmediate, field.Value)
            {
                SemanticKind = A64ImmediateSemanticKind.HinteImmediate,
                SemanticDomain = binding.SemanticDomain,
            };
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.EnumImmediate
            && A64EnumImmediate.TryDecode(binding.Type, field.Value, field.Width, out var enumValue))
        {
            operand = new EnumImmediateOperand(enumValue, binding.EnumKind, field.Value)
            {
                SemanticDomain = binding.SemanticDomain,
            };
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.LaneIndex)
        {
            operand = new LaneIndexOperand(
                MaterializeImmediate(binding, field),
                binding.ElementWidth,
                binding.LaneCount,
                field.Value);
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.ComplexRotation)
        {
            operand = A64ComplexRotation.TryDecode(binding.Type, field.Value, out var angle)
                ? new ComplexRotationOperand(angle, field.Value)
                : new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
            return true;
        }

        if (binding.ImmediateSemanticKind == A64ImmediateSemanticKind.FixedPoint)
        {
            operand = A64FixedPointImmediate.TryDecode(binding.Type, field.Value, out var scale)
                ? new FixedPointOperand(
                    scale,
                    binding.FractionalBits,
                    field.Value)
                : new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.VectorList
            && field.Value <= 31)
        {
            var vectorCount = binding.ShapeCount;
            var elementWidth = binding.ElementWidth;
            var registers = new A64Register[vectorCount];
            for (var index = 0; index < vectorCount; index++)
            {
                registers[index] = A64Register.Vector((int)((field.Value + (uint)index) & 31));
            }

            operand = new VectorRegisterListOperand(registers, elementWidth);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.RegisterGroup
            && field.Value <= 31)
        {
            A64GeneratedOperandShapes.TryGetRegisterGroup(binding.Type, out var groupCount, out var groupClass);
            var elementWidth = A64GeneratedOperandShapes.ElementWidth(binding.Type);
            var firstIndex = TryDecodeRegisterIndex(binding, field.Value, out var decodedFirstIndex)
                ? decodedFirstIndex
                : (int)field.Value;
            var groupStride = binding.GroupStride;
            if (binding.Type.StartsWith("ZZ", StringComparison.Ordinal)
                && binding.Type.Contains("strided", StringComparison.OrdinalIgnoreCase))
            {
                firstIndex = A64GeneratedOperandShapes.DecodeGroupFirstIndex(
                    binding.Type,
                    (int)field.Value,
                    out groupStride);
            }
            var registers = new A64Register[groupCount];
            for (var index = 0; index < groupCount; index++)
            {
                var registerIndex = (firstIndex + index * groupStride) & 31;
                registers[index] = groupClass == A64RegisterClass.Predicate
                    ? new A64Register(groupClass, checked((byte)registerIndex), 0)
                    : A64Register.SveVector(registerIndex, elementWidth);
            }

            operand = new RegisterGroupOperand(
                registers,
                elementWidth,
                binding.Type)
            {
                Stride = groupStride,
                Constraint = binding.RegisterConstraint,
            };
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.Register
            && TryMaterializeRegister(binding, field.Value, out var register))
        {
            if (binding.RegisterClass == A64RegisterClass.Predicate
                || binding.PredicateMode != A64PredicateMode.None
                || binding.RegisterConstraint != A64RegisterConstraint.Any
                || binding.FixedModifierKind != A64RegisterModifierKind.Unknown)
            {
                operand = new RegisterOperand(register)
                {
                    Constraint = binding.RegisterConstraint,
                    ElementWidth = binding.ElementWidth,
                    PredicateMode = binding.PredicateMode,
                    Modifier = binding.FixedModifierKind == A64RegisterModifierKind.Unknown
                        ? null
                        : new A64RegisterModifier(
                            binding.FixedModifierKind,
                            binding.FixedModifierAmount,
                            0),
                    Codec = binding.Type,
                };
            }
            else
            {
                operand = CachedRegisterOperand(register);
            }

            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.PcRelative
            && TryMaterializeTarget(binding, field, address, out var target))
        {
            operand = new TargetOperand(target);
            return true;
        }

        if (binding.Kind == A64CompiledOperandKind.Immediate)
        {
            operand = new ImmediateOperand(MaterializeImmediate(binding, field), field.Value)
            {
                SemanticKind = binding.ImmediateSemanticKind,
                EnumKind = binding.EnumKind,
                SemanticDomain = binding.SemanticDomain,
                ElementWidth = binding.ElementWidth,
                LaneCount = binding.LaneCount,
                FractionalBits = binding.ImmediateSemanticKind == A64ImmediateSemanticKind.FixedPoint
                    ? binding.FractionalBits
                    : 0,
            };
            return true;
        }

        operand = new EncodedFieldOperand(binding.Name, field.Value, binding.Type, field.Width);
        return true;
    }

    private static RegisterPairOperand MaterializeRegisterPair(
        A64CompiledBinding binding,
        uint encoded)
    {
        if (binding.Type == "SyspXzrPairOperand")
        {
            return new RegisterPairOperand(
                A64Register.Zr(binding.RegisterWidth == 0 ? 64 : binding.RegisterWidth),
                A64Register.Zr(binding.RegisterWidth == 0 ? 64 : binding.RegisterWidth),
                binding.ElementWidth,
                binding.Type);
        }

        var width = binding.RegisterWidth == 0 ? 64 : binding.RegisterWidth;
        var first = encoded <= 30
            ? new A64Register(A64RegisterClass.General, (byte)encoded, (byte)width)
            : A64Register.Zr(width);
        var second = encoded <= 29
            ? new A64Register(A64RegisterClass.General, (byte)(encoded + 1), (byte)width)
            : A64Register.Zr(width);
        return new RegisterPairOperand(first, second, binding.ElementWidth, binding.Type);
    }

    private static bool TryMaterializeMemory(
        A64CompiledInstruction instruction,
        FieldAccessor fields,
        A64GeneratedMemoryBinding memory,
        out MemoryOperand operand)
    {
        if ((uint)memory.BaseBindingIndex >= (uint)instruction.Bindings.Length
            || !fields.TryGet(memory.BaseFieldIndex, out var baseField))
        {
            operand = default!;
            return false;
        }

        var baseBinding = instruction.GetBinding(memory.BaseBindingIndex);
        if (!TryMaterializeRegister(baseBinding, baseField.Value, out var baseRegister))
        {
            operand = default!;
            return false;
        }

        var offset = memory.FixedOffset;
        if (memory.OffsetFieldIndex >= 0
            && (uint)memory.OffsetBindingIndex < (uint)instruction.Bindings.Length)
        {
            if ((uint)memory.OffsetBindingIndex >= (uint)instruction.Bindings.Length)
            {
                operand = default!;
                return false;
            }

            var offsetBinding = instruction.GetBinding(memory.OffsetBindingIndex);
            if (offsetBinding.Codec is null
                || !fields.TryGet(memory.OffsetFieldIndex, out var offsetField))
            {
                operand = default!;
                return false;
            }

            offset = MaterializeImmediate(
                offsetBinding,
                offsetField);
        }

        A64Register? index = null;
        if (memory.IndexFieldIndex >= 0
            && (uint)memory.IndexBindingIndex < (uint)instruction.Bindings.Length)
        {
            if ((uint)memory.IndexBindingIndex >= (uint)instruction.Bindings.Length
                || !fields.TryGet(memory.IndexFieldIndex, out var indexField))
            {
                operand = default!;
                return false;
            }

            var indexBinding = instruction.GetBinding(memory.IndexBindingIndex);
            if (!TryMaterializeRegister(indexBinding, indexField.Value, out var indexRegister))
            {
                operand = default!;
                return false;
            }

            index = indexRegister;
        }

        uint? indexModifier = null;
        A64RegisterModifier? indexModifierSemantics = null;
        if (memory.ModifierFieldIndex >= 0)
        {
            if (!fields.TryGet(memory.ModifierFieldIndex, out var modifierField))
            {
                operand = default!;
                return false;
            }

            indexModifier = modifierField.Value;
            if ((uint)memory.ModifierBindingIndex < (uint)instruction.Bindings.Length)
            {
                A64GeneratedMemory.TryDecodeIndexModifier(
                    instruction.GetBinding(memory.ModifierBindingIndex).Type,
                    modifierField.Value,
                    out var decodedModifier);
                indexModifierSemantics = decodedModifier;
            }
        }

        operand = new MemoryOperand(baseRegister, offset, index, memory.Mode, indexModifier)
        {
            IndexModifierSemantics = indexModifierSemantics,
            AccessSize = A64GeneratedMemory.AccessSize(instruction),
            Ordering = A64GeneratedMemory.Ordering(instruction),
        };
        return true;
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

    private static bool IsRegister(string type, A64OperandEncodingInfo codec)
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

    private static bool IsImmediate(string type, A64OperandEncodingInfo codec)
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

    private static bool AllowsZeroRegister(string type)
    {
        return type.StartsWith("GPR32z", StringComparison.Ordinal)
            || type.StartsWith("GPR64z", StringComparison.Ordinal)
            || type is "GPR32" or "GPR64";
    }

    private static bool TryMaterializeRegister(
        A64CompiledBinding binding,
        uint value,
        out A64Register register)
    {
        if (!TryDecodeRegisterIndex(binding, value, out var index))
        {
            register = default;
            return false;
        }

        switch (binding.RegisterClass)
        {
            case A64RegisterClass.General:
                if (index == 31)
                {
                    if (binding.AllowsStackPointer)
                    {
                        register = A64Register.Sp(binding.RegisterWidth);
                        return true;
                    }

                    if (binding.AllowsZeroRegister)
                    {
                        register = A64Register.Zr(binding.RegisterWidth);
                        return true;
                    }

                    register = default;
                    return false;
                }

                register = binding.RegisterWidth == 32
                    ? A64Register.W(index)
                    : A64Register.X(index);
                return true;
            case A64RegisterClass.FloatingPoint:
                register = A64Register.FloatingPoint(index, binding.RegisterWidth);
                return true;
            case A64RegisterClass.Vector:
                register = A64Register.Vector(index, binding.RegisterWidth);
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

    private static bool TryDecodeRegisterIndex(
        A64CompiledBinding binding,
        uint encoded,
        out int index)
    {
        var decoded = binding.RegisterIndexBias
            + (long)encoded * binding.RegisterIndexScale;
        if (encoded > 31 || decoded is < 0 or > 31 || !binding.RegisterConstraint.Accepts((int)decoded))
        {
            index = 0;
            return false;
        }

        index = (int)decoded;
        return true;
    }

    private static bool TryMaterializeRegister(
        string type,
        uint value,
        out A64Register register)
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

            if (index == 31 && AllowsZeroRegister(type))
            {
                register = A64Register.Zr(width);
                return true;
            }

            if (index == 31 && type is "GPR32" or "GPR64")
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

    private static RegisterOperand CachedRegisterOperand(A64Register register)
    {
        if (register.Class == A64RegisterClass.General)
        {
            if (register.Role == A64RegisterRole.StackPointer)
            {
                return register.Width == 32 ? RegisterOperandCache.Wsp : RegisterOperandCache.Sp;
            }

            if (register.Role == A64RegisterRole.Zero)
            {
                return register.Width == 32 ? RegisterOperandCache.Wzr : RegisterOperandCache.Xzr;
            }

            return register.Width == 32
                ? RegisterOperandCache.W[register.Index]
                : RegisterOperandCache.X[register.Index];
        }

        if (register.Class == A64RegisterClass.Vector && register.Width == 128)
        {
            return RegisterOperandCache.V[register.Index];
        }

        if (register.Class == A64RegisterClass.Vector && register.Width == 64)
        {
            return RegisterOperandCache.V64[register.Index];
        }

        if (register.Class == A64RegisterClass.FloatingPoint)
        {
            return register.Width switch
            {
                8 => RegisterOperandCache.B[register.Index],
                16 => RegisterOperandCache.H[register.Index],
                32 => RegisterOperandCache.S[register.Index],
                64 => RegisterOperandCache.D[register.Index],
                128 => RegisterOperandCache.Q[register.Index],
                _ => new RegisterOperand(register),
            };
        }

        if (register.Class == A64RegisterClass.SveVector)
        {
            return register.Width switch
            {
                8 => RegisterOperandCache.Z8[register.Index],
                16 => RegisterOperandCache.Z16[register.Index],
                32 => RegisterOperandCache.Z32[register.Index],
                64 => RegisterOperandCache.Z64[register.Index],
                128 => RegisterOperandCache.Z128[register.Index],
                _ => RegisterOperandCache.Z[register.Index],
            };
        }

        if (register.Class == A64RegisterClass.Predicate)
        {
            return RegisterOperandCache.P[register.Index];
        }

        return new RegisterOperand(register);
    }

    private static bool TryMaterializeTarget(
        A64CompiledBinding binding,
        A64FieldValue field,
        ulong address,
        out ulong target)
    {
        var value = SignExtend(field.Value, field.Width);
        var delta = value << binding.PcRelativeScale;
        target = delta >= 0
            ? unchecked(address + (ulong)delta)
            : unchecked(address - (ulong)(-(delta + 1)) - 1UL);
        return true;
    }

    private static bool TryMaterializeTarget(
        string type,
        A64FieldValue field,
        ulong address,
        out ulong target)
    {
        var value = SignExtend(field.Value, field.Width);
        var scale = type.Contains("adrp", StringComparison.OrdinalIgnoreCase)
            ? 12
            : type.Contains("adrlabel", StringComparison.OrdinalIgnoreCase) ? 0 : 2;
        var delta = value << scale;
        target = delta >= 0
            ? unchecked(address + (ulong)delta)
            : unchecked(address - (ulong)(-(delta + 1)) - 1UL);
        return true;
    }

    private static long MaterializeImmediate(
        A64CompiledBinding binding,
        A64FieldValue field)
    {
        var value = binding.IsSigned
            ? SignExtend(field.Value, field.Width)
            : field.Value;
        if (binding.Kind == A64CompiledOperandKind.Immediate
            && binding.Type.StartsWith("addsub_shifted_imm", StringComparison.Ordinal))
        {
            return (long)(field.Value & 0xFFFu) * (((field.Value >> 12) & 1u) != 0 ? 0x1000 : 1);
        }

        return checked(value * binding.Scale);
    }

    private static long MaterializeImmediate(
        string type,
        A64OperandEncodingInfo codec,
        A64FieldValue field)
    {
        var isSigned = type.StartsWith("simm", StringComparison.OrdinalIgnoreCase)
            || codec.ParserMatchClass.StartsWith("SImm", StringComparison.Ordinal);
        var value = isSigned ? SignExtend(field.Value, field.Width) : field.Value;
        if (type.StartsWith("addsub_shifted_imm", StringComparison.Ordinal))
        {
            return (long)(field.Value & 0xFFFu) * (((field.Value >> 12) & 1u) != 0 ? 0x1000 : 1);
        }

        var scale = ReadScale(type, codec.PrintMethod);
        return checked(value * scale);
    }


    private static int ParseRegisterWidth(string type)
    {
        if (type.Contains("128", StringComparison.Ordinal))
        {
            return 128;
        }

        if (type.Contains("64", StringComparison.Ordinal))
        {
            return 64;
        }

        if (type.Contains("32", StringComparison.Ordinal))
        {
            return 32;
        }

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
        if (width is <= 0 or > 32)
        {
            return value;
        }

        if (width == 32)
        {
            return unchecked((int)value);
        }

        var mask = (1u << width) - 1u;
        var sign = 1u << (width - 1);
        var narrowed = value & mask;
        return (long)(narrowed ^ sign) - sign;
    }

    private readonly ref struct FieldAccessor
    {
        private readonly A64CompiledInstruction? compiled;
        private readonly IReadOnlyList<A64FieldValue>? decodedFields;
        private readonly uint encoding;

        public FieldAccessor(IReadOnlyList<A64FieldValue> fields)
        {
            compiled = null;
            decodedFields = fields;
            encoding = 0;
        }

        public FieldAccessor(A64CompiledInstruction instruction, uint encoding)
        {
            compiled = instruction;
            decodedFields = null;
            this.encoding = encoding;
        }

        public bool TryGet(string name, out A64FieldValue field)
        {
            if (compiled is not null)
            {
                if (compiled.TryGetField(name, out var fieldSpec)
                    && fieldSpec.TryRead(encoding, out var value))
                {
                    field = new A64FieldValue(fieldSpec.Name, value, fieldSpec.Width);
                    return true;
                }

                field = default;
                return false;
            }

            foreach (var candidate in decodedFields!)
            {
                if (string.Equals(candidate.Name, name, StringComparison.Ordinal))
                {
                    field = candidate;
                    return true;
                }
            }

            field = default;
            return false;
        }

        public bool TryGet(int index, out A64FieldValue field)
        {
            if (compiled is not null)
            {
                if (compiled.TryReadField(index, encoding, out var value))
                {
                    var fieldPlan = compiled.GetField(index);
                    field = new A64FieldValue(fieldPlan.Name, value, fieldPlan.Width);
                    return true;
                }

                field = default;
                return false;
            }

            if ((uint)index < (uint)decodedFields!.Count)
            {
                field = decodedFields[index];
                return true;
            }

            field = default;
            return false;
        }
    }

    private static class RegisterOperandCache
    {
        public static readonly RegisterOperand[] X = BuildGeneral(64);
        public static readonly RegisterOperand[] W = BuildGeneral(32);
        public static readonly RegisterOperand[] V = BuildVector();
        public static readonly RegisterOperand[] V64 = BuildVector(64);
        public static readonly RegisterOperand[] B = BuildFloating(8);
        public static readonly RegisterOperand[] H = BuildFloating(16);
        public static readonly RegisterOperand[] S = BuildFloating(32);
        public static readonly RegisterOperand[] D = BuildFloating(64);
        public static readonly RegisterOperand[] Q = BuildFloating(128);
        public static readonly RegisterOperand[] Z = BuildSve();
        public static readonly RegisterOperand[] Z8 = BuildSve(8);
        public static readonly RegisterOperand[] Z16 = BuildSve(16);
        public static readonly RegisterOperand[] Z32 = BuildSve(32);
        public static readonly RegisterOperand[] Z64 = BuildSve(64);
        public static readonly RegisterOperand[] Z128 = BuildSve(128);
        public static readonly RegisterOperand[] P = BuildPredicate();
        public static readonly RegisterOperand Sp = new(A64Register.Sp());
        public static readonly RegisterOperand Wsp = new(A64Register.Sp(32));
        public static readonly RegisterOperand Xzr = new(A64Register.Zr());
        public static readonly RegisterOperand Wzr = new(A64Register.Zr(32));

        private static RegisterOperand[] BuildGeneral(int width)
        {
            var result = new RegisterOperand[31];
            for (var index = 0; index < result.Length; index++)
            {
                result[index] = new RegisterOperand(width == 32 ? A64Register.W(index) : A64Register.X(index));
            }

            return result;
        }

        private static RegisterOperand[] BuildVector(int width = 128)
        {
            var result = new RegisterOperand[32];
            for (var index = 0; index < result.Length; index++) result[index] = new(A64Register.Vector(index, width));
            return result;
        }

        private static RegisterOperand[] BuildFloating(int width)
        {
            var result = new RegisterOperand[32];
            for (var index = 0; index < result.Length; index++)
            {
                result[index] = new RegisterOperand(A64Register.FloatingPoint(index, width));
            }

            return result;
        }

        private static RegisterOperand[] BuildSve(int elementWidth = 0)
        {
            var result = new RegisterOperand[32];
            for (var index = 0; index < result.Length; index++)
            {
                result[index] = new RegisterOperand(A64Register.SveVector(index, elementWidth))
                {
                    ElementWidth = elementWidth,
                };
            }

            return result;
        }

        private static RegisterOperand[] BuildPredicate()
        {
            var result = new RegisterOperand[32];
            for (var index = 0; index < result.Length; index++)
            {
                result[index] = new RegisterOperand(new A64Register(A64RegisterClass.Predicate, (byte)index, 0));
            }

            return result;
        }
    }

}
