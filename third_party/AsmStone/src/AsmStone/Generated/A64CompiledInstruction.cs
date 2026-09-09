using AsmStone.Model;

namespace AsmStone.Generated;

internal enum A64CompiledOperandKind : byte
{
    EncodedField,
    Register,
    Immediate,
    PcRelative,
    ModifiedRegister,
    SystemRegister,
    MatrixTileMask,
    LogicalImmediate,
    SimdImmediate,
    MoveWideImmediate,
    MoveWideShift,
    FloatingImmediate,
    VectorShift,
    SveIncrement,
    BitIndex,
    EnumImmediate,
    RegisterPair,
    MatrixRegister,
    RegisterModifier,
    VectorList,
    RegisterGroup,
}

internal sealed class A64CompiledInstruction
{
    public A64CompiledInstruction(
        A64GeneratedInstruction source,
        A64EncodingInfo info,
        A64CompiledField[] fields,
        A64CompiledBinding[] bindings,
        string[] predicates,
        int operandCount,
        int uncollapsedOperandCount,
        A64GeneratedMemoryBinding? memory)
    {
        Source = source;
        Info = info;
        Fields = fields;
        Bindings = bindings;
        Predicates = predicates;
        OperandCount = operandCount;
        UncollapsedOperandCount = uncollapsedOperandCount;
        Memory = memory;
    }

    public A64GeneratedInstruction Source { get; }

    public A64EncodingInfo Info { get; }

    public A64CompiledField[] Fields { get; }

    public A64CompiledBinding[] Bindings { get; }

    public string[] Predicates { get; }

    public int OperandCount { get; }

    public int UncollapsedOperandCount { get; }

    public A64GeneratedMemoryBinding? Memory { get; }

    public bool TryGetField(string name, out A64CompiledField field)
    {
        foreach (var candidate in Fields)
        {
            if (string.Equals(candidate.Name, name, StringComparison.Ordinal))
            {
                field = candidate;
                return true;
            }
        }

        field = default!;
        return false;
    }

    public A64CompiledField GetField(int index) => Fields[index];

    public bool TryGetFieldIndex(string name, out int index)
    {
        for (var i = 0; i < Fields.Length; i++)
        {
            if (string.Equals(Fields[i].Name, name, StringComparison.Ordinal))
            {
                index = i;
                return true;
            }
        }

        index = -1;
        return false;
    }

    public bool TryReadField(string name, uint encoding, out uint value)
    {
        value = 0;
        return TryGetField(name, out var field) && field.TryRead(encoding, out value);
    }

    public bool TryReadField(int index, uint encoding, out uint value)
    {
        if ((uint)index >= (uint)Fields.Length)
        {
            value = 0;
            return false;
        }

        return Fields[index].TryRead(encoding, out value);
    }

    public bool HasBindingType(string type)
    {
        foreach (var binding in Bindings)
        {
            if (string.Equals(binding.Type, type, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public bool TryGetBinding(string name, out A64CompiledBinding binding)
    {
        foreach (var candidate in Bindings)
        {
            if (string.Equals(candidate.Name, name, StringComparison.Ordinal))
            {
                binding = candidate;
                return true;
            }
        }

        binding = default;
        return false;
    }

    public A64CompiledBinding GetBinding(int index) => Bindings[index];
}

internal sealed class A64CompiledField
{
    public A64CompiledField(string name, A64CompiledFieldMapping[] mappings)
    {
        Name = name;
        Mappings = mappings;
        Width = mappings.Length == 0
            ? 0
            : mappings.Max(mapping => mapping.FieldBit) + 1;

        IsContiguous = mappings.Length != 0;
        EncodingShift = mappings.Length == 0 ? 0 : mappings[0].EncodingBit;
        FieldShift = mappings.Length == 0 ? 0 : mappings[0].FieldBit;
        for (var index = 0; index < mappings.Length; index++)
        {
            if (mappings[index].EncodingBit != EncodingShift + index
                || mappings[index].FieldBit != FieldShift + index)
            {
                IsContiguous = false;
                break;
            }
        }

        ValueMask = mappings.Length >= 32 ? uint.MaxValue : (1u << mappings.Length) - 1u;
    }

    public string Name { get; }

    public A64CompiledFieldMapping[] Mappings { get; }

    public int Width { get; }

    public bool IsContiguous { get; }

    public int EncodingShift { get; }

    public int FieldShift { get; }

    public uint ValueMask { get; }

    public bool TryRead(uint encoding, out uint value)
    {
        if (IsContiguous)
        {
            value = ((encoding >> EncodingShift) & ValueMask) << FieldShift;
            return true;
        }

        value = 0;
        foreach (var mapping in Mappings)
        {
            value |= ((encoding >> mapping.EncodingBit) & 1u) << mapping.FieldBit;
        }

        return Mappings.Length != 0;
    }

    public bool TryInsert(uint value, ref uint encoding, out A64Diagnostic diagnostic)
    {
        var maxFieldBit = Width - 1;
        var width = Width;
        var hasUnsignedOverflow = width < 32 && (value >> width) != 0;
        var hasSignExtension = width > 0 && width < 32
            && ((value >> maxFieldBit) & 1u) != 0
            && (value >> width) == (uint.MaxValue >> width);
        if (maxFieldBit < 0 || hasUnsignedOverflow && !hasSignExtension)
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.OutOfRange,
                $"Value for '{Name}' does not fit its encoded field.");
            return false;
        }

        if (IsContiguous)
        {
            var encodingMask = ValueMask << EncodingShift;
            encoding = (encoding & ~encodingMask)
                | (((value >> FieldShift) & ValueMask) << EncodingShift);
            diagnostic = A64Diagnostic.None;
            return true;
        }

        foreach (var mapping in Mappings)
        {
            var bit = (value >> mapping.FieldBit) & 1u;
            encoding = (encoding & ~(1u << mapping.EncodingBit)) | (bit << mapping.EncodingBit);
        }

        diagnostic = A64Diagnostic.None;
        return true;
    }
}

internal readonly record struct A64CompiledFieldMapping(int EncodingBit, int FieldBit);

internal readonly record struct A64CompiledBinding(
    string Name,
    string Type,
    string Direction,
    A64GeneratedOperand? Codec,
    int FieldIndex,
    int SecondaryFieldIndex,
    A64CompiledOperandKind Kind)
{
    public int FieldWidth { get; init; }
    public int Scale { get; init; } = 1;
    public int RegisterWidth { get; init; }
    public A64RegisterClass RegisterClass { get; init; } = A64RegisterClass.Special;
    public bool AllowsStackPointer { get; init; }
    public bool AllowsZeroRegister { get; init; }
    public int ShapeCount { get; init; }
    public int ElementWidth { get; init; }
    public bool IsPageRelative { get; init; }
    public int PcRelativeScale { get; init; }
    public bool IsSigned { get; init; }

    public A64RegisterConstraint RegisterConstraint { get; init; } = A64RegisterConstraint.Any;

    public A64ImmediateSemanticKind ImmediateSemanticKind { get; init; }

    public A64EnumKind EnumKind { get; init; }

    public string SemanticDomain { get; init; } = string.Empty;

    public int LaneCount { get; init; }

    public int FractionalBits { get; init; }

    public A64PredicateMode PredicateMode { get; init; }

    public A64MatrixRegisterKind MatrixRegisterKind { get; init; }

    public A64RegisterModifierKind FixedModifierKind { get; init; }

    public int FixedModifierAmount { get; init; }

    public int RegisterIndexBias { get; init; }

    public int RegisterIndexScale { get; init; } = 1;

    public int GroupStride { get; init; } = 1;

    public bool IsImplicit => Name.StartsWith('_') || FieldIndex < 0;

    public string? TiedTo { get; init; }
}
