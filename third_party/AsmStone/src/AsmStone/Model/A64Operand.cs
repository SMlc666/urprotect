namespace AsmStone.Model;

public abstract record A64Operand;

public enum A64OperandDirection
{
    Input,
    Output,
    InputOutput,
}

public enum A64PredicateMode
{
    None,
    Merge,
    Zero,
}

public enum A64ImmediateSemanticKind
{
    Plain,
    Enum,
    LaneIndex,
    ComplexRotation,
    FixedPoint,
    Shift,
    LogicalImmediate,
    SimdImmediate,
    MoveWideImmediate,
    SveIncrement,
    BitIndex,
    FloatingImmediate,
    SveOptionalShift,
    HinteImmediate,
}

public enum A64EnumKind
{
    Unknown,
    SvePredicatePattern,
    SvePrefetch,
    SveVectorLength,
    Svcr,
    TIndexHint,
    ConditionCode,
    Barrier,
    Prefetch,
    SystemControlRegister,
    PStateField,
}

public enum A64MatrixRegisterKind
{
    Za,
    Tile,
    TileVector,
    Zt,
    Zk,
}

public enum A64MemoryOrdering
{
    None,
    Acquire,
    Release,
    AcquireRelease,
}

public readonly record struct A64RegisterConstraint(
    int MinimumIndex,
    int MaximumIndex,
    int Step = 1,
    uint AllowedMask = 0)
{
    public static A64RegisterConstraint Any => new(0, 31);

    public bool Accepts(int index)
    {
        if ((uint)index > 31 || index < MinimumIndex || index > MaximumIndex)
        {
            return false;
        }

        if (AllowedMask != 0)
        {
            return (AllowedMask & (1u << index)) != 0;
        }

        return Step <= 1 || (index - MinimumIndex) % Step == 0;
    }
}

public sealed record A64InstructionOperand(
    string Name,
    A64Operand? Operand,
    A64OperandDirection Direction,
    bool IsImplicit,
    string Codec,
    string? TiedTo = null)
{
    public A64OperandKind Kind { get; init; } = A64OperandKind.EncodedField;

    public A64RegisterClass RegisterClass { get; init; } = A64RegisterClass.Special;

    public A64RegisterConstraint RegisterConstraint { get; init; } = A64RegisterConstraint.Any;

    public int RegisterWidth { get; init; }

    public int FieldWidth { get; init; }

    public int ElementWidth { get; init; }

    public int ShapeCount { get; init; }

    public int LaneCount { get; init; }

    public int GroupStride { get; init; }

    public int RegisterIndexBias { get; init; }

    public int RegisterIndexScale { get; init; } = 1;

    public int Scale { get; init; } = 1;

    public bool IsSigned { get; init; }

    public bool AllowsStackPointer { get; init; }

    public bool AllowsZeroRegister { get; init; }

    public bool IsPageRelative { get; init; }

    public A64ImmediateSemanticKind ImmediateSemanticKind { get; init; }

    public A64EnumKind EnumKind { get; init; }

    public A64PredicateMode PredicateMode { get; init; }

    public A64MatrixRegisterKind MatrixRegisterKind { get; init; }

    public A64RegisterModifierKind FixedModifierKind { get; init; }

    public int FixedModifierAmount { get; init; }

    public int FractionalBits { get; init; }

    public string SemanticDomain { get; init; } = string.Empty;
}

public record RegisterOperand(A64Register Register) : A64Operand
{
    public A64RegisterConstraint Constraint { get; init; } = A64RegisterConstraint.Any;

    public int ElementWidth { get; init; }

    public A64PredicateMode PredicateMode { get; init; }

    public A64RegisterModifier? Modifier { get; init; }

    public string Codec { get; init; } = string.Empty;
}

public sealed record RegisterPairOperand(
    A64Register First,
    A64Register Second,
    int ElementWidth = 0,
    string Codec = "") : A64Operand;

public sealed record MatrixRegisterOperand(
    A64MatrixRegisterKind Kind,
    int Index,
    int ElementWidth,
    string Codec = "",
    uint? EncodedValue = null) : A64Operand;

public sealed record VectorRegisterListOperand(
    IReadOnlyList<A64Register> Registers,
    int ElementWidth) : A64Operand;

public sealed record RegisterGroupOperand(
    IReadOnlyList<A64Register> Registers,
    int ElementWidth,
    string Codec) : A64Operand
{
    public int Stride { get; init; } = 1;

    public A64RegisterConstraint Constraint { get; init; } = A64RegisterConstraint.Any;
}

public sealed record SystemRegisterOperand(uint Encoding) : A64Operand
{
    public int Op0 => (int)((Encoding >> 14) & 0b11);

    public int Op1 => (int)((Encoding >> 11) & 0b111);

    public int Crn => (int)((Encoding >> 7) & 0b1111);

    public int Crm => (int)((Encoding >> 3) & 0b1111);

    public int Op2 => (int)(Encoding & 0b111);
}

public sealed record MatrixTileMaskOperand(byte Mask) : A64Operand;

public sealed record ModifiedRegisterOperand(
    A64Register Register,
    uint Modifier,
    string Codec) : A64Operand
{
    public static bool TryCreate(
        A64Register register,
        string codec,
        A64RegisterModifierKind kind,
        int amount,
        out ModifiedRegisterOperand operand)
    {
        if (A64RegisterModifier.TryEncode(codec, kind, amount, out var rawEncoding))
        {
            operand = new ModifiedRegisterOperand(register, rawEncoding, codec);
            return true;
        }

        operand = default!;
        return false;
    }

    public bool TryGetModifier(out A64RegisterModifier modifier)
    {
        return A64RegisterModifier.TryDecode(Codec, Modifier, out modifier);
    }
}

public sealed record RegisterModifierOperand(
    A64RegisterModifier Modifier,
    string Codec) : A64Operand
{
    public static bool TryCreate(
        string codec,
        A64RegisterModifierKind kind,
        int amount,
        out RegisterModifierOperand operand)
    {
        if (A64RegisterModifier.TryEncode(codec, kind, amount, out var rawEncoding))
        {
            operand = new RegisterModifierOperand(
                new A64RegisterModifier(kind, amount, rawEncoding),
                codec);
            return true;
        }

        operand = default!;
        return false;
    }
}

public record ImmediateOperand(long Value, uint? EncodedValue = null) : A64Operand
{
    public A64ImmediateSemanticKind SemanticKind { get; init; }

    public A64EnumKind EnumKind { get; init; }

    public string SemanticDomain { get; init; } = string.Empty;

    public int ElementWidth { get; init; }

    public int LaneCount { get; init; }

    public int FractionalBits { get; init; }

    public int ShiftAmount { get; init; }
}

public sealed record EnumImmediateOperand : ImmediateOperand
{
    public EnumImmediateOperand(long value, A64EnumKind enumKind, uint? encodedValue = null)
        : base(value, encodedValue)
    {
        EnumKind = enumKind;
        SemanticKind = A64ImmediateSemanticKind.Enum;
    }
}

public sealed record LaneIndexOperand : ImmediateOperand
{
    public LaneIndexOperand(long value, int elementWidth, int laneCount, uint? encodedValue = null)
        : base(value, encodedValue)
    {
        ElementWidth = elementWidth;
        LaneCount = laneCount;
        SemanticKind = A64ImmediateSemanticKind.LaneIndex;
    }
}

public sealed record ComplexRotationOperand : ImmediateOperand
{
    public ComplexRotationOperand(long value, uint? encodedValue = null)
        : base(value, encodedValue)
    {
        SemanticKind = A64ImmediateSemanticKind.ComplexRotation;
    }
}

public sealed record FixedPointOperand : ImmediateOperand
{
    public FixedPointOperand(long value, int fractionalBits, uint? encodedValue = null)
        : base(value, encodedValue)
    {
        FractionalBits = fractionalBits;
        SemanticKind = A64ImmediateSemanticKind.FixedPoint;
    }
}

public sealed record FloatingImmediateOperand(
    double Value,
    uint? EncodedValue = null,
    string Codec = "") : A64Operand
{
    public A64ImmediateSemanticKind SemanticKind { get; init; } = A64ImmediateSemanticKind.FloatingImmediate;
}

public sealed record EncodedFieldOperand(
    string Name,
    uint Value,
    string Codec = "",
    int Width = 0) : A64Operand;

public sealed record TargetOperand(ulong Address) : A64Operand;

public enum A64MemoryAddressingMode
{
    Offset,
    RegisterOffset,
    PreIndexed,
    PostIndexed,
}

public sealed record MemoryOperand(
    A64Register Base,
    long Offset = 0,
    A64Register? Index = null,
    A64MemoryAddressingMode Mode = A64MemoryAddressingMode.Offset,
    uint? IndexModifier = null) : A64Operand
{
    public A64RegisterModifier? IndexModifierSemantics { get; init; }

    public int AccessSize { get; init; }

    public A64MemoryOrdering Ordering { get; init; }

    public bool WritesBack => Mode is A64MemoryAddressingMode.PreIndexed or A64MemoryAddressingMode.PostIndexed;
}
