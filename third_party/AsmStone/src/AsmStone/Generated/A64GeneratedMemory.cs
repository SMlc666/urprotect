using AsmStone.Model;

namespace AsmStone.Generated;

internal readonly record struct A64GeneratedMemoryBinding(
    string BaseName,
    string? OffsetName,
    string? IndexName,
    string? ModifierName,
    long FixedOffset,
    A64MemoryAddressingMode Mode)
{
    public int BaseFieldIndex { get; init; } = -1;
    public int OffsetFieldIndex { get; init; } = -1;
    public int IndexFieldIndex { get; init; } = -1;
    public int ModifierFieldIndex { get; init; } = -1;
    public int BaseBindingIndex { get; init; } = -1;
    public int OffsetBindingIndex { get; init; } = -1;
    public int IndexBindingIndex { get; init; } = -1;
    public int ModifierBindingIndex { get; init; } = -1;
}

internal static class A64GeneratedMemory
{
    public static bool TryGet(
        int instructionIndex,
        out A64GeneratedMemoryBinding memory)
    {
        if ((uint)instructionIndex < (uint)A64GeneratedInstructionTable.All.Length
            && A64GeneratedMemoryTable.Get(instructionIndex) is { } generatedMemory)
        {
            memory = generatedMemory;
            return true;
        }

        memory = default;
        return false;
    }

    public static bool TryGet(
        A64CompiledInstruction instruction,
        out A64GeneratedMemoryBinding memory)
    {
        if (instruction.Memory is { } compiledMemory)
        {
            memory = compiledMemory;
            return true;
        }

        memory = default;
        return false;
    }

    public static bool TryDecodeIndexModifier(
        string type,
        uint raw,
        out A64RegisterModifier modifier)
    {
        if (!type.StartsWith("ro_", StringComparison.Ordinal)
            || raw > 3)
        {
            modifier = default;
            return false;
        }

        var signed = (raw & 2u) != 0;
        var width = AccessWidth(type);
        var amount = width <= 8
            ? 0
            : (int)System.Numerics.BitOperations.Log2((uint)(width / 8));
        var kind = type.Contains("Xextend", StringComparison.Ordinal)
            ? signed ? A64RegisterModifierKind.Sxtx : A64RegisterModifierKind.Uxtx
            : signed ? A64RegisterModifierKind.Sxtw : A64RegisterModifierKind.Uxtw;
        modifier = new A64RegisterModifier(kind, (raw & 1u) != 0 ? amount : 0, raw);
        return true;
    }

    public static bool TryEncodeIndexModifier(
        string type,
        A64RegisterModifier modifier,
        out uint raw)
    {
        raw = 0;
        if (!type.StartsWith("ro_", StringComparison.Ordinal))
        {
            return false;
        }

        if (modifier.RawEncoding <= 3
            && TryDecodeIndexModifier(type, modifier.RawEncoding, out var decoded)
            && decoded.Kind == modifier.Kind
            && decoded.Amount == modifier.Amount)
        {
            raw = modifier.RawEncoding;
            return true;
        }

        var isX = type.Contains("Xextend", StringComparison.Ordinal);
        var signed = isX
            ? modifier.Kind is A64RegisterModifierKind.Sxtx
            : modifier.Kind is A64RegisterModifierKind.Sxtw;
        var unsigned = isX
            ? modifier.Kind is A64RegisterModifierKind.Uxtx
            : modifier.Kind is A64RegisterModifierKind.Uxtw;
        if (!signed && !unsigned)
        {
            return false;
        }

        var width = AccessWidth(type);
        var scaledAmount = width <= 8
            ? 0
            : (int)System.Numerics.BitOperations.Log2((uint)(width / 8));
        var isShifted = modifier.Amount == scaledAmount;
        if (modifier.Amount != 0 && !isShifted)
        {
            return false;
        }

        raw = (uint)((signed ? 2 : 0) | (isShifted ? 1 : 0));
        return true;
    }

    public static int AccessSize(A64CompiledInstruction instruction)
    {
        if (instruction.Memory is not { } memory)
        {
            return 0;
        }

        if ((uint)memory.OffsetBindingIndex < (uint)instruction.Bindings.Length)
        {
            var type = instruction.GetBinding(memory.OffsetBindingIndex).Type;
            var width = AccessWidth(type);
            if (width != 0)
            {
                return type.StartsWith("ro_", StringComparison.Ordinal) ? width / 8 : width;
            }
        }

        if ((uint)memory.ModifierBindingIndex < (uint)instruction.Bindings.Length)
        {
            var type = instruction.GetBinding(memory.ModifierBindingIndex).Type;
            var width = AccessWidth(type);
            if (width != 0)
            {
                return width / 8;
            }
        }

        foreach (var binding in instruction.Bindings)
        {
            if (binding.FieldIndex == memory.BaseFieldIndex
                || binding.FieldIndex == memory.IndexFieldIndex
                || binding.FieldIndex == memory.ModifierFieldIndex)
            {
                continue;
            }

            var width = AccessWidth(binding.Type);
            if (width != 0)
            {
                return width / 8;
            }

            if (binding.RegisterWidth is 8 or 16 or 32 or 64 or 128)
            {
                return binding.RegisterWidth / 8;
            }

            if (binding.Kind is A64CompiledOperandKind.RegisterGroup or A64CompiledOperandKind.VectorList
                && binding.ElementWidth != 0
                && binding.ShapeCount != 0)
            {
                return binding.ElementWidth / 8 * binding.ShapeCount;
            }
        }

        return 0;
    }

    public static A64MemoryOrdering Ordering(A64CompiledInstruction instruction)
    {
        var name = instruction.Source.Name;
        if (name.StartsWith("LDAR", StringComparison.Ordinal)
            || name.StartsWith("LDAP", StringComparison.Ordinal))
        {
            return A64MemoryOrdering.Acquire;
        }

        if (name.StartsWith("STLR", StringComparison.Ordinal)
            || name.StartsWith("STLX", StringComparison.Ordinal))
        {
            return A64MemoryOrdering.Release;
        }

        if ((instruction.Info.Flags & A64InstructionFlags.IsAtomic) == 0)
        {
            return A64MemoryOrdering.None;
        }

        var orderingName = name.Length != 0 && "BHSWDQX".Contains(name[^1])
            ? name[..^1]
            : name;
        if (orderingName.EndsWith("AL", StringComparison.Ordinal))
        {
            return A64MemoryOrdering.AcquireRelease;
        }

        if (orderingName.EndsWith('A'))
        {
            return A64MemoryOrdering.Acquire;
        }

        if (orderingName.EndsWith('L'))
        {
            return A64MemoryOrdering.Release;
        }

        return A64MemoryOrdering.None;
    }

    private static int AccessWidth(string type)
    {
        var marker = type.IndexOf("extend", StringComparison.OrdinalIgnoreCase);
        if (marker >= 0)
        {
            var index = marker + "extend".Length;
            while (index < type.Length && !char.IsDigit(type[index])) index++;
            var width = 0;
            while (index < type.Length && char.IsDigit(type[index]))
            {
                width = width * 10 + type[index++] - '0';
            }

            if (width != 0)
            {
                return width;
            }
        }

        var scale = type.LastIndexOf('s');
        if (scale >= 0 && scale + 1 < type.Length)
        {
            var value = 0;
            for (var index = scale + 1; index < type.Length && char.IsDigit(type[index]); index++)
            {
                value = value * 10 + type[index] - '0';
            }

            if (value != 0)
            {
                return value;
            }
        }

        return 0;
    }
}
