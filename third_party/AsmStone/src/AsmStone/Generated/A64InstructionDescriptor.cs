using AsmStone.Model;

namespace AsmStone.Generated;

public enum A64DecoderRuleKind : byte
{
    None,
    AddSubImmediate,
    MoveWideImmediate,
    AddSubExtendedRegister,
    ShiftedRegister,
    SystemPStateImmediate,
    CopyMemory,
    SetMemory,
    SetMemoryGo,
    LogicalImmediate,
    SveLogicalImmediate,
    UnconditionalBranch,
    Adr,
    TestAndBranch,
    Unknown,
}

public enum A64PcRelativeKind : byte
{
    None,
    Adr21,
    Adrp21,
    Branch26,
    Branch9,
    Branch19,
    Branch14,
    Literal19,
    PAuth16,
    Generic,
}

public enum A64RelocationKind : byte
{
    None,
    AArch64AdrPrelLo21,
    AArch64AdrpPage21,
    AArch64Jump26,
    AArch64Call26,
    AArch64Condbr9,
    AArch64Condbr19,
    AArch64Tstbr14,
    AArch64LdPrelLo19,
    AArch64PAuth,
}

public readonly record struct A64PcRelativeInfo(
    A64PcRelativeKind Kind,
    int FieldWidth,
    int ScaleShift,
    int Alignment,
    bool IsPageRelative,
    A64RelocationKind Relocation)
{
    public static A64PcRelativeInfo None => default;

    public bool IsPresent => Kind != A64PcRelativeKind.None;

    public int Unit => IsPresent ? 1 << ScaleShift : 0;

    public long Minimum => IsPresent ? -(1L << (FieldWidth - 1)) * Unit : 0;

    public long Maximum => IsPresent ? ((1L << (FieldWidth - 1)) - 1) * Unit : 0;
}

public readonly record struct A64FieldBitMapping(
    int EncodingBit,
    int FieldBit);

public sealed record A64FieldDescriptor(
    A64FieldId Id,
    string Name,
    int Width,
    bool IsContiguous,
    int EncodingShift,
    int FieldShift,
    uint ValueMask,
    IReadOnlyList<A64FieldBitMapping> Mappings);

public sealed record A64OperandCodecDescriptor(
    string Name,
    string OperandType,
    string DecoderMethod,
    string EncoderMethod,
    string PrintMethod,
    string ParserMatchClass,
    string RegisterClass,
    string ElementSize,
    string ValueType);

public sealed record A64OperandDescriptor(
    string Name,
    A64OperandKind Kind,
    A64OperandDirection Direction,
    bool IsImplicit,
    A64FieldId Field,
    A64FieldId SecondaryField,
    A64RegisterClass RegisterClass,
    A64RegisterConstraint RegisterConstraint,
    int RegisterWidth,
    int FieldWidth,
    int ElementWidth,
    int ShapeCount,
    int LaneCount,
    int GroupStride,
    int RegisterIndexBias,
    int RegisterIndexScale,
    int Scale,
    bool IsSigned,
    bool AllowsStackPointer,
    bool AllowsZeroRegister,
    A64ImmediateSemanticKind ImmediateSemanticKind,
    A64EnumKind EnumKind,
    A64PredicateMode PredicateMode,
    A64MatrixRegisterKind MatrixRegisterKind,
    A64RegisterModifierKind FixedModifierKind,
    int FixedModifierAmount,
    int FractionalBits,
    A64PcRelativeInfo PcRelative,
    string? TiedTo,
    string SourceType,
    A64OperandCodecDescriptor Codec);

public sealed record A64MemoryDescriptor(
    A64FieldId BaseField,
    A64FieldId OffsetField,
    A64FieldId IndexField,
    A64FieldId ModifierField,
    long FixedOffset,
    A64MemoryAddressingMode Mode,
    int AccessSize,
    A64MemoryOrdering Ordering)
{
    public string BaseName { get; init; } = string.Empty;
    public string? OffsetName { get; init; }
    public string? IndexName { get; init; }
    public string? ModifierName { get; init; }
}

public sealed record A64InstructionDescriptor(
    A64InstructionCode Code,
    string SourceName,
    string Mnemonic,
    uint Mask,
    uint Value,
    A64InstructionFlags Flags,
    bool HasCompleteEncoding,
    A64DecoderRuleKind DecoderRule,
    IReadOnlyList<string> Predicates,
    IReadOnlyList<A64FieldDescriptor> Fields,
    IReadOnlyList<A64OperandDescriptor> Operands,
    A64MemoryDescriptor? Memory,
    string AssemblyTemplate)
{
    public bool IsPcRelative => Operands.Any(operand => operand.PcRelative.IsPresent);
}
