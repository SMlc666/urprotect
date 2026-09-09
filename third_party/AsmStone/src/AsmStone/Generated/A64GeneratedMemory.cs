using AsmStone.Model;
using System.Globalization;

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

    public static bool TryGet(A64EncodingInfo info, out A64GeneratedMemoryBinding memory)
    {
        memory = default;
        var bindings = ParseBindings(info.OperandBindings);
        var open = -1;
        var close = -1;
        string[] inside = [];
        for (var search = 0; ;)
        {
            var candidateOpen = info.Assembly.IndexOf('[', search);
            if (candidateOpen < 0)
            {
                break;
            }

            var candidateClose = info.Assembly.IndexOf(']', candidateOpen + 1);
            if (candidateClose < 0)
            {
                break;
            }

            var candidateInside = Placeholders(
                info.Assembly[(candidateOpen + 1)..candidateClose]).ToArray();
            if (candidateInside.Length != 0
                && bindings.TryGetValue(candidateInside[0], out var candidateBaseType)
                && IsGeneralRegister(candidateBaseType))
            {
                open = candidateOpen;
                close = candidateClose;
                inside = candidateInside;
                break;
            }

            search = candidateClose + 1;
        }

        if (open < 0)
        {
            return false;
        }

        string? offsetName = null;
        string? indexName = null;
        string? modifierName = null;
        var fixedOffset = ReadFixedOffset(info.Assembly[(open + 1)..close]);
        foreach (var name in inside.Skip(1))
        {
            if (!bindings.TryGetValue(name, out var type))
            {
                continue;
            }

            if (IsImmediate(type))
            {
                if (offsetName is not null)
                {
                    return false;
                }

                offsetName = name;
            }
            else if (IsRegister(type))
            {
                if (indexName is not null)
                {
                    return false;
                }

                indexName = name;
            }
            else if (type.StartsWith("ro_", StringComparison.Ordinal))
            {
                modifierName = name;
            }
        }

        var suffix = info.Assembly[(close + 1)..];
        var mode = suffix.TrimStart().StartsWith('!')
            ? A64MemoryAddressingMode.PreIndexed
            : indexName is not null ? A64MemoryAddressingMode.RegisterOffset : A64MemoryAddressingMode.Offset;
        if (suffix.Contains(','))
        {
            var suffixNames = Placeholders(suffix).Where(bindings.ContainsKey).ToArray();
            foreach (var name in suffixNames)
            {
                if (IsImmediate(bindings[name]))
                {
                    if (offsetName is not null)
                    {
                        return false;
                    }

                    offsetName = name;
                }
                else if (IsRegister(bindings[name]))
                {
                    if (indexName is not null)
                    {
                        return false;
                    }

                    indexName = name;
                }
            }

            if (suffixNames.Length != 0)
            {
                mode = A64MemoryAddressingMode.PostIndexed;
            }
        }

        memory = new A64GeneratedMemoryBinding(inside[0], offsetName, indexName, modifierName, fixedOffset, mode);
        return true;
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

    private static long ReadFixedOffset(string text)
    {
        var marker = text.IndexOf('#');
        if (marker < 0)
        {
            return 0;
        }

        var valueStart = marker + 1;
        var valueEnd = valueStart;
        if (valueEnd < text.Length && text[valueEnd] == '-')
        {
            valueEnd++;
        }

        while (valueEnd < text.Length && char.IsDigit(text[valueEnd]))
        {
            valueEnd++;
        }

        return long.TryParse(
            text[valueStart..valueEnd],
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var value)
            ? value
            : 0;
    }

    public static IReadOnlyDictionary<string, string> ParseBindings(string encoded)
    {
        var bindings = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in encoded.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = item.Split(':', 3);
            if (parts.Length == 3)
            {
                bindings[parts[0]] = parts[1];
            }
        }

        return bindings;
    }

    private static IEnumerable<string> Placeholders(string text)
    {
        for (var index = 0; index < text.Length; index++)
        {
            if (text[index] != '$' || index + 1 >= text.Length || !char.IsLetter(text[index + 1]))
            {
                continue;
            }

            var start = ++index;
            while (index + 1 < text.Length
                && (char.IsLetterOrDigit(text[index + 1]) || text[index + 1] == '_'))
            {
                index++;
            }

            yield return text[start..(index + 1)];
        }
    }

    private static bool IsGeneralRegister(string type)
    {
        return type.StartsWith("GPR", StringComparison.Ordinal)
            && !type.StartsWith("GPR32x", StringComparison.Ordinal);
    }

    private static bool IsRegister(string type)
    {
        return type.StartsWith("GPR", StringComparison.Ordinal)
            || type.StartsWith("FPR", StringComparison.Ordinal)
            || type.StartsWith("V", StringComparison.Ordinal)
            || type.StartsWith("ZPR", StringComparison.Ordinal)
            || type.StartsWith("PPR", StringComparison.Ordinal)
            || type.StartsWith("PNR", StringComparison.Ordinal);
    }

    private static bool IsImmediate(string type)
    {
        // Address offsets use immediate fields; register modifiers are folded
        // into the generated memory binding for the runtime plan.
        return type.StartsWith("simm", StringComparison.OrdinalIgnoreCase)
            || type.StartsWith("uimm", StringComparison.OrdinalIgnoreCase)
            || type.StartsWith("imm", StringComparison.OrdinalIgnoreCase)
            || type.StartsWith("timm", StringComparison.OrdinalIgnoreCase);
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
