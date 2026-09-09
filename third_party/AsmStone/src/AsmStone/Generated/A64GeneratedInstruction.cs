namespace AsmStone.Generated;

[Flags]
internal enum A64GeneratedFlags
{
    None = 0,
    Branch = 1 << 0,
    Call = 1 << 1,
    Return = 1 << 2,
    Load = 1 << 3,
    Store = 1 << 4,
    Compare = 1 << 5,
    Barrier = 1 << 6,
    Terminator = 1 << 7,
    SideEffects = 1 << 8,
    WritesBack = 1 << 9,
    Atomic = 1 << 10,
    System = 1 << 11,
    ReadsNzcv = 1 << 12,
    WritesNzcv = 1 << 13,
    ReadsFpcr = 1 << 14,
    WritesFpcr = 1 << 15,
    ReadsFfr = 1 << 16,
    WritesFfr = 1 << 17,
    MayRaiseFpException = 1 << 18,
}

internal sealed record A64GeneratedInstruction(
    string Name,
    string Mnemonic,
    string Assembly,
    uint Mask,
    uint Value,
    A64GeneratedFlags Flags,
    string DecoderMethod,
    string Predicates,
    string VariableFields,
    string FieldEncoding,
    string OperandBindings,
    string InputOperands,
    string OutputOperands,
    string Constraints,
    bool HasCompleteEncoding);
