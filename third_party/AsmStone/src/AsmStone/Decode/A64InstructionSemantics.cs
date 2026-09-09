using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone.Decode;

internal static class A64InstructionSemantics
{
    public static IReadOnlyList<A64InstructionOperand> Build(A64Instruction instruction)
    {
        if (instruction.SourceName is null
            || !A64InstructionCatalog.TryGetCompiledByName(instruction.SourceName, out var plan))
        {
            return Array.Empty<A64InstructionOperand>();
        }

        var result = new List<A64InstructionOperand>(plan.Bindings.Length);
        var resolvedOperands = new A64Operand?[plan.Bindings.Length];
        var implicitOperands = new bool[plan.Bindings.Length];
        var operandIndex = 0;
        var memory = plan.Memory;
        for (var index = 0; index < plan.Bindings.Length; index++)
        {
            var binding = plan.Bindings[index];
            A64Operand? operand = null;
            var isImplicit = binding.IsImplicit;
            if (!isImplicit && memory is { } activeMemory)
            {
                if (binding.FieldIndex == activeMemory.BaseFieldIndex)
                {
                    if ((uint)operandIndex < (uint)instruction.Operands.Count)
                    {
                        operand = instruction.Operands[operandIndex++];
                    }
                }
                else if (binding.FieldIndex == activeMemory.OffsetFieldIndex
                    || binding.FieldIndex == activeMemory.IndexFieldIndex
                    || binding.FieldIndex == activeMemory.ModifierFieldIndex)
                {
                    isImplicit = true;
                }
                else if ((uint)operandIndex < (uint)instruction.Operands.Count)
                {
                    operand = instruction.Operands[operandIndex++];
                }
            }
            else if (!isImplicit && (uint)operandIndex < (uint)instruction.Operands.Count)
            {
                operand = instruction.Operands[operandIndex++];
            }

            if (operand is null)
            {
                A64OperandMaterializer.TryMaterializeSemanticBinding(
                    plan,
                    binding,
                    instruction.Encoding,
                    instruction.Address,
                    out operand);
            }

            resolvedOperands[index] = operand;
            implicitOperands[index] = isImplicit;
            var hasEncodedTieTarget = false;
            if (binding.FieldIndex < 0 && binding.TiedTo is { } tieTarget)
            {
                for (var tiedIndex = 0; tiedIndex < plan.Bindings.Length; tiedIndex++)
                {
                    if (string.Equals(plan.Bindings[tiedIndex].Name, tieTarget, StringComparison.Ordinal)
                        && plan.Bindings[tiedIndex].FieldIndex >= 0)
                    {
                        hasEncodedTieTarget = true;
                        break;
                    }
                }
            }

            if (operand is null || hasEncodedTieTarget)
            {
                resolvedOperands[index] = null;
            }
        }

        for (var index = 0; index < plan.Bindings.Length; index++)
        {
            if (resolvedOperands[index] is not null
                || plan.Bindings[index].TiedTo is not { } tiedName)
            {
                continue;
            }

            for (var tiedIndex = 0; tiedIndex < plan.Bindings.Length; tiedIndex++)
            {
                if (string.Equals(plan.Bindings[tiedIndex].Name, tiedName, StringComparison.Ordinal)
                    && resolvedOperands[tiedIndex] is { } tiedOperand)
                {
                    resolvedOperands[index] = tiedOperand;
                    break;
                }
            }
        }

        for (var index = 0; index < plan.Bindings.Length; index++)
        {
            var binding = plan.Bindings[index];
            var tiedTo = binding.TiedTo;
            result.Add(new A64InstructionOperand(
                binding.Name,
                resolvedOperands[index],
                Direction(binding.Direction),
                implicitOperands[index],
                binding.Type,
                tiedTo)
            {
                Kind = Kind(binding.Kind),
                RegisterClass = binding.RegisterClass,
                RegisterConstraint = binding.RegisterConstraint,
                RegisterWidth = binding.RegisterWidth,
                FieldWidth = binding.FieldWidth,
                ElementWidth = binding.ElementWidth,
                ShapeCount = binding.ShapeCount,
                LaneCount = binding.LaneCount,
                GroupStride = binding.GroupStride,
                RegisterIndexBias = binding.RegisterIndexBias,
                RegisterIndexScale = binding.RegisterIndexScale,
                Scale = binding.Scale,
                IsSigned = binding.IsSigned,
                AllowsStackPointer = binding.AllowsStackPointer,
                AllowsZeroRegister = binding.AllowsZeroRegister,
                IsPageRelative = binding.IsPageRelative,
                ImmediateSemanticKind = binding.ImmediateSemanticKind,
                EnumKind = binding.EnumKind,
                PredicateMode = binding.PredicateMode,
                MatrixRegisterKind = binding.MatrixRegisterKind,
                FixedModifierKind = binding.FixedModifierKind,
                FixedModifierAmount = binding.FixedModifierAmount,
                FractionalBits = binding.FractionalBits,
                SemanticDomain = binding.SemanticDomain,
            });
        }

        return result;
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

    private static A64OperandKind Kind(A64CompiledOperandKind kind)
    {
        return kind switch
        {
            A64CompiledOperandKind.Register => A64OperandKind.Register,
            A64CompiledOperandKind.VectorList => A64OperandKind.VectorRegisterList,
            A64CompiledOperandKind.RegisterGroup => A64OperandKind.RegisterGroup,
            A64CompiledOperandKind.RegisterPair => A64OperandKind.RegisterPair,
            A64CompiledOperandKind.SystemRegister => A64OperandKind.SystemRegister,
            A64CompiledOperandKind.MatrixTileMask => A64OperandKind.MatrixTileMask,
            A64CompiledOperandKind.MatrixRegister => A64OperandKind.MatrixRegister,
            A64CompiledOperandKind.ModifiedRegister => A64OperandKind.ModifiedRegister,
            A64CompiledOperandKind.RegisterModifier => A64OperandKind.RegisterModifier,
            A64CompiledOperandKind.PcRelative => A64OperandKind.Target,
            A64CompiledOperandKind.FloatingImmediate => A64OperandKind.FloatingImmediate,
            A64CompiledOperandKind.EncodedField => A64OperandKind.EncodedField,
            _ => A64OperandKind.Immediate,
        };
    }
}
