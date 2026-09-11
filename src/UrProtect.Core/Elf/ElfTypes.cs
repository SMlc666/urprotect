using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Elf;

public static class ElfConstants
{
    public const byte Class64 = 2;
    public const byte LittleEndian = 1;
    public const ushort TypeDyn = 3;
    public const ushort MachineAarch64 = 183;
    public const ushort HeaderSize64 = 64;
    public const ushort ProgramHeaderSize64 = 56;
    public const ushort SectionHeaderSize64 = 64;
    public const ushort DynamicEntrySize64 = 16;
    public const ushort SymbolEntrySize64 = 24;
    public const ushort RelaEntrySize64 = 24;
    public const ushort RelrEntrySize64 = 8;
    public const ushort PnXnum = ushort.MaxValue;
    public const ushort ShnXindex = ushort.MaxValue;

    public const uint PtNull = 0;
    public const uint PtLoad = 1;
    public const uint PtDynamic = 2;
    public const uint PtInterp = 3;
    public const uint PtNote = 4;
    public const uint PtPhdr = 6;
    public const uint PtTls = 7;
    public const uint PtGnuEhFrame = 0x6474E550;
    public const uint PtGnuStack = 0x6474E551;
    public const uint PtGnuRelro = 0x6474E552;
    public const uint PtGnuProperty = 0x6474E553;

    public const uint PfX = 1;
    public const uint PfW = 2;
    public const uint PfR = 4;

    public const ulong DtNull = 0;
    public const ulong DtNeeded = 1;
    public const ulong DtPltRelSz = 2;
    public const ulong DtPltGot = 3;
    public const ulong DtHash = 4;
    public const ulong DtStrTab = 5;
    public const ulong DtSymTab = 6;
    public const ulong DtRela = 7;
    public const ulong DtRelaSz = 8;
    public const ulong DtRelaEnt = 9;
    public const ulong DtStrSz = 10;
    public const ulong DtSymEnt = 11;
    public const ulong DtInit = 12;
    public const ulong DtFini = 13;
    public const ulong DtSoname = 14;
    public const ulong DtRpath = 15;
    public const ulong DtSymbolic = 16;
    public const ulong DtRel = 17;
    public const ulong DtRelSz = 18;
    public const ulong DtRelEnt = 19;
    public const ulong DtPltRel = 20;
    public const ulong DtJmpRel = 23;
    public const ulong DtInitArray = 25;
    public const ulong DtFiniArray = 26;
    public const ulong DtInitArraySz = 27;
    public const ulong DtFiniArraySz = 28;
    public const ulong DtRunPath = 29;
    public const ulong DtFlags = 30;
    public const ulong DtFlags1 = 0x6FFFFFFB;
    public const ulong Df1Pie = 0x08000000;
    public const ulong DtGnuHash = 0x6FFFFEF5;
    public const ulong DtVersym = 0x6FFFFFF0;
    public const ulong DtVerneed = 0x6FFFFFFE;
    public const ulong DtVerneedNum = 0x6FFFFFFF;
    public const ulong DtRelr = 36;
    public const ulong DtRelrSz = 35;
    public const ulong DtRelrEnt = 37;
    public const ulong DtAndroidRel = 0x6000000E;
    public const ulong DtAndroidRelsz = 0x6000000F;
    public const ulong DtAndroidRela = 0x60000011;
    public const ulong DtAndroidRelasz = 0x60000012;
    public const ulong DtAndroidRelr = 0x60000013;
    public const ulong DtAndroidRelrsz = 0x60000014;
    public const ulong DtAndroidRelrent = 0x60000015;
}

public enum ElfFileKind
{
    Unknown,
    PieExecutable,
    SharedObject,
}

public readonly record struct ElfHeader(
    ushort Type,
    ushort Machine,
    uint Version,
    ulong Entry,
    ulong ProgramHeaderOffset,
    ulong SectionHeaderOffset,
    uint Flags,
    ushort HeaderSize,
    ushort ProgramHeaderEntrySize,
    ushort ProgramHeaderCount,
    ushort SectionHeaderEntrySize,
    ushort SectionHeaderCount,
    ushort SectionNameIndex)
{
    public bool IsAarch64 => Machine == ElfConstants.MachineAarch64;

    public bool IsDynamic => Type == ElfConstants.TypeDyn;
}

public enum ProgramHeaderKind
{
    Unknown,
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Phdr,
    Tls,
    GnuEhFrame,
    GnuStack,
    GnuRelro,
    GnuProperty,
}

public readonly record struct ProgramHeader(
    uint Type,
    uint Flags,
    ulong Offset,
    ulong VirtualAddress,
    ulong PhysicalAddress,
    ulong FileSize,
    ulong MemorySize,
    ulong Alignment)
{
    public ProgramHeaderKind Kind => Type switch
    {
        ElfConstants.PtNull => ProgramHeaderKind.Null,
        ElfConstants.PtLoad => ProgramHeaderKind.Load,
        ElfConstants.PtDynamic => ProgramHeaderKind.Dynamic,
        ElfConstants.PtInterp => ProgramHeaderKind.Interp,
        ElfConstants.PtNote => ProgramHeaderKind.Note,
        ElfConstants.PtPhdr => ProgramHeaderKind.Phdr,
        ElfConstants.PtTls => ProgramHeaderKind.Tls,
        ElfConstants.PtGnuEhFrame => ProgramHeaderKind.GnuEhFrame,
        ElfConstants.PtGnuStack => ProgramHeaderKind.GnuStack,
        ElfConstants.PtGnuRelro => ProgramHeaderKind.GnuRelro,
        ElfConstants.PtGnuProperty => ProgramHeaderKind.GnuProperty,
        _ => ProgramHeaderKind.Unknown,
    };

    public bool IsKnownType => Kind != ProgramHeaderKind.Unknown;

    public bool IsLoadable => Type == ElfConstants.PtLoad;

    public bool IsExecutable => (Flags & ElfConstants.PfX) != 0;

    public bool IsWritable => (Flags & ElfConstants.PfW) != 0;

    public bool IsReadable => (Flags & ElfConstants.PfR) != 0;
}

public readonly record struct SectionHeader(
    uint Name,
    uint Type,
    ulong Flags,
    ulong Address,
    ulong Offset,
    ulong Size,
    uint Link,
    uint Info,
    ulong AddressAlignment,
    ulong EntrySize);

public readonly record struct DynamicEntry(ulong Tag, ulong Value)
{
    public bool IsTerminator => Tag == ElfConstants.DtNull;
}

public readonly record struct DynamicSymbol(
    uint Name,
    byte Info,
    byte Other,
    ushort SectionIndex,
    ulong Value,
    ulong Size);

public readonly record struct RelaRelocation(
    ulong Offset,
    ulong Info,
    long Addend,
    ulong SourceAddress,
    bool IsPlt)
{
    public uint Type => unchecked((uint)(Info & 0xFFFFFFFF));

    public uint SymbolIndex => unchecked((uint)(Info >> 32));
}

public readonly record struct RelrWord(ulong Value, ulong SourceAddress);

public readonly record struct AndroidPackedRelocationTable(
    ulong Address,
    ulong Size,
    bool IsRela,
    ReadOnlyMemory<byte> RawBytes);

public readonly record struct ElfNote(
    uint SegmentType,
    uint Type,
    ReadOnlyMemory<byte> Name,
    ReadOnlyMemory<byte> Descriptor,
    ulong FileOffset);

public sealed record ElfDynamicMetadata(
    IReadOnlyList<string> NeededLibraries,
    string? Soname,
    string? Rpath,
    string? RunPath,
    ReadOnlyMemory<byte> StringTable)
{
    public static ElfDynamicMetadata Empty { get; } = new(
        Array.Empty<string>(),
        null,
        null,
        null,
        ReadOnlyMemory<byte>.Empty);
}

public readonly record struct FileRange(ulong Offset, ulong Size)
{
    public bool TryGetEnd(out ulong end)
    {
        end = Offset + Size;
        return end >= Offset;
    }

    public bool Contains(ulong offset, ulong size = 1)
    {
        return TryGetEnd(out var end)
            && offset >= Offset
            && offset - Offset <= Size
            && size <= Size - (offset - Offset);
    }
}

public sealed class ElfFile
{
    public ElfFile(
        ReadOnlyMemory<byte> bytes,
        ElfHeader header,
        IReadOnlyList<ProgramHeader> programHeaders,
        IReadOnlyList<SectionHeader> sectionHeaders,
        LoadMap loadMap,
        IReadOnlyList<ElfNote> notes,
        ElfDynamicMetadata dynamicMetadata,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        IReadOnlyList<RelaRelocation> relaRelocations,
        IReadOnlyList<RelrWord> relrWords,
        IReadOnlyList<AndroidPackedRelocationTable> androidPackedRelocations,
        IReadOnlyList<DynamicSymbol> dynamicSymbols)
    {
        Bytes = bytes;
        Header = header;
        ProgramHeaders = programHeaders;
        SectionHeaders = sectionHeaders;
        LoadMap = loadMap;
        Notes = notes;
        DynamicMetadata = dynamicMetadata;
        DynamicEntries = dynamicEntries;
        RelaRelocations = relaRelocations;
        RelrWords = relrWords;
        AndroidPackedRelocations = androidPackedRelocations;
        DynamicSymbols = dynamicSymbols;
    }

    public ReadOnlyMemory<byte> Bytes { get; }

    public ElfHeader Header { get; }

    public IReadOnlyList<ProgramHeader> ProgramHeaders { get; }

    public IReadOnlyList<SectionHeader> SectionHeaders { get; }

    public LoadMap LoadMap { get; }

    public IReadOnlyList<ElfNote> Notes { get; }

    public ElfDynamicMetadata DynamicMetadata { get; }

    public IReadOnlyList<DynamicEntry> DynamicEntries { get; }

    public IReadOnlyList<RelaRelocation> RelaRelocations { get; }

    public IReadOnlyList<RelrWord> RelrWords { get; }

    public IReadOnlyList<AndroidPackedRelocationTable> AndroidPackedRelocations { get; }

    public IReadOnlyList<DynamicSymbol> DynamicSymbols { get; }

    public ElfFileKind Kind =>
        ProgramHeaders.Any(header => header.Type == ElfConstants.PtInterp)
            ? ElfFileKind.PieExecutable
            : ElfFileKind.SharedObject;
}

public sealed record ElfParseResult(
    ElfFile? File,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => File is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed record ElfValidationReport(IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsValid => Diagnostics.All(diagnostic => !diagnostic.IsError);
}
