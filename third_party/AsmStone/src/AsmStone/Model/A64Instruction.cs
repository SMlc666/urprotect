using AsmStone.Decode;

namespace AsmStone.Model;

public enum A64InstructionId
{
    Unknown,
    Generated,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    Nop,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    Branch,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    BranchWithLink,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    BranchRegister,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    BranchWithLinkRegister,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    Return,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    Address,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    AddressPage,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    AddImmediate,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    AddImmediateFlags,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    SubtractImmediate,
    [Obsolete("Use the generated instruction id and TableGen source name.")]
    SubtractImmediateFlags,
}

[Flags]
public enum A64InstructionFlags
{
    None = 0,
    SetsFlags = 1 << 0,
    IsBranch = 1 << 1,
    IsCall = 1 << 2,
    IsReturn = 1 << 3,
    IsPcRelative = 1 << 4,
    IsLoad = 1 << 5,
    IsStore = 1 << 6,
    IsCompare = 1 << 7,
    IsBarrier = 1 << 8,
    IsTerminator = 1 << 9,
    HasSideEffects = 1 << 10,
    WritesBack = 1 << 11,
    IsAtomic = 1 << 12,
    IsSystem = 1 << 13,
    IsAcquire = 1 << 14,
    IsRelease = 1 << 15,
    ReadsNzcv = 1 << 16,
    WritesNzcv = 1 << 17,
    ReadsFpcr = 1 << 18,
    WritesFpcr = 1 << 19,
    ReadsFfr = 1 << 20,
    WritesFfr = 1 << 21,
    MayRaiseFpException = 1 << 22,
}

public sealed record A64Instruction(
    A64InstructionId Id,
    string Mnemonic,
    IReadOnlyList<A64Operand> Operands,
    uint Encoding,
    ulong Address,
    A64InstructionFlags Flags = A64InstructionFlags.None)
{
    public string? SourceName { get; init; }

    public IReadOnlyList<A64InstructionOperand> OperandSemantics => GetOperandSemantics();

    public IReadOnlyList<A64InstructionOperand> GetOperandSemantics()
    {
        return A64InstructionSemantics.Build(this);
    }

    public bool IsUnknown => Id == A64InstructionId.Unknown;

    public bool IsGenerated => Id == A64InstructionId.Generated;
}
