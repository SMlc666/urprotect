using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.UnwindMetadata;

public enum UnwindSectionKind
{
    EhFrame,
    EhFrameHeader,
}

public enum UnwindPointerFormat : byte
{
    Absptr = 0x00,
    Uleb128 = 0x01,
    Udata2 = 0x02,
    Udata4 = 0x03,
    Udata8 = 0x04,
    Sleb128 = 0x09,
    Sdata2 = 0x0A,
    Sdata4 = 0x0B,
    Sdata8 = 0x0C,
}

public enum UnwindPointerApplication : byte
{
    Absolute = 0x00,
    PcRelative = 0x10,
    TextRelative = 0x20,
    DataRelative = 0x30,
    Funcrel = 0x40,
    Aligned = 0x50,
}

public readonly record struct UnwindEncoding(byte Raw)
{
    public UnwindPointerFormat Format => (UnwindPointerFormat)(Raw & 0x0F);

    public UnwindPointerApplication Application =>
        (UnwindPointerApplication)(Raw & 0x70);

    public bool IsIndirect => (Raw & 0x80) != 0;

    public bool IsOmit => Raw == 0xFF;

    public bool IsSupportedFormat =>
        IsOmit || Format is UnwindPointerFormat.Absptr
            or UnwindPointerFormat.Uleb128
            or UnwindPointerFormat.Udata2
            or UnwindPointerFormat.Udata4
            or UnwindPointerFormat.Udata8
            or UnwindPointerFormat.Sleb128
            or UnwindPointerFormat.Sdata2
            or UnwindPointerFormat.Sdata4
            or UnwindPointerFormat.Sdata8;

    public bool IsSupportedApplication =>
        IsOmit || Application is UnwindPointerApplication.Absolute
            or UnwindPointerApplication.PcRelative
            or UnwindPointerApplication.TextRelative
            or UnwindPointerApplication.DataRelative
            or UnwindPointerApplication.Funcrel
            or UnwindPointerApplication.Aligned;
}

public enum UnwindInstructionKind
{
    AdvanceLocation,
    DefCfa,
    DefCfaRegister,
    DefCfaOffset,
    Offset,
    Restore,
    RememberState,
    RestoreState,
    Nop,
    Unsupported,
}

public readonly record struct UnwindInstruction(
    UnwindInstructionKind Kind,
    ulong FileOffset,
    byte Opcode,
    ulong Operand,
    ulong Operand2,
    ReadOnlyMemory<byte> RawBytes);

public sealed record UnwindCie(
    FileRange RecordRange,
    FileOffset EntryOffset,
    uint Version,
    string Augmentation,
    long CodeAlignmentFactor,
    long DataAlignmentFactor,
    ulong ReturnAddressRegister,
    ReadOnlyMemory<byte> AugmentationData,
    UnwindEncoding? FdePointerEncoding,
    IReadOnlyList<UnwindInstruction> Instructions,
    ReadOnlyMemory<byte> RawBytes);

public sealed record UnwindFde(
    FileRange RecordRange,
    FileOffset EntryOffset,
    FileOffset CieEntryOffset,
    ulong InitialLocation,
    ulong AddressRange,
    ReadOnlyMemory<byte> AugmentationData,
    IReadOnlyList<UnwindInstruction> Instructions,
    ReadOnlyMemory<byte> RawBytes);

public readonly record struct UnwindHeaderTableEntry(
    ulong InitialLocation,
    ulong FdeAddress);

public sealed record UnwindFrameHeader(
    FileRange SectionRange,
    byte Version,
    UnwindEncoding EhFramePointerEncoding,
    ulong EhFrameAddress,
    UnwindEncoding FdeCountEncoding,
    UnwindEncoding TableEncoding,
    ulong FdeCount,
    IReadOnlyList<UnwindHeaderTableEntry> Entries,
    ReadOnlyMemory<byte> RawBytes);

public sealed record UnwindMetadataModel(
    SectionHeader EhFrameSection,
    SectionHeader? EhFrameHeaderSection,
    IReadOnlyList<UnwindCie> Cies,
    IReadOnlyList<UnwindFde> Fdes,
    UnwindFrameHeader? Header,
    ReadOnlyMemory<byte> EhFrameBytes,
    ReadOnlyMemory<byte> EhFrameHeaderBytes)
{
    public bool HasRecords => Cies.Count > 0 || Fdes.Count > 0;
}

public sealed record UnwindMetadataParseResult(
    UnwindMetadataModel? Model,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Model is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public static class UnwindMetadataLimits
{
    public const int MaximumRecordBytes = 1024 * 1024;
    public const int MaximumInstructionsPerRecord = 65536;
    public const int MaximumAugmentationBytes = 65536;
    public const int MaximumHeaderEntries = 262144;
    public const int MaximumLebBytes = 10;
    public const int MaximumInstructionBytes = 1024 * 1024;
    public const ulong MaximumRegisterNumber = 4096;
    public const int MaximumCfiEffects = 65536;
    public const ulong MaximumCfiOffset = 1024 * 1024;
}
