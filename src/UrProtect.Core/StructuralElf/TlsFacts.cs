namespace UrProtect.Core.StructuralElf;

/// <summary>
/// Decoder-independent PT_TLS facts. The template is an owned snapshot of the
/// initialized bytes; the remainder of <see cref="MemorySize"/> is zero-fill.
/// </summary>
public sealed record TlsSegmentFacts(
    int ProgramHeaderIndex,
    int OwningLoadProgramHeaderIndex,
    FileOffset TemplateFileOffset,
    VirtualAddress TemplateAddress,
    ulong FileSize,
    ulong MemorySize,
    ulong Alignment,
    uint Permissions,
    ReadOnlyMemory<byte> InitializedTemplate)
{
    public ulong ZeroFillSize => MemorySize - FileSize;
}

/// <summary>Identity facts for a symbol referenced by a TLS relocation.</summary>
public sealed record TlsRelocationSymbolIdentity(
    uint SymbolIndex,
    string Name,
    byte Binding,
    byte Type,
    byte Visibility,
    ushort SectionIndex,
    ulong Value,
    ulong Size);

/// <summary>Bounded dynamic RELA table facts used as the source owner of TLS records.</summary>
public sealed record TlsRelocationTableFacts(
    VirtualAddress Address,
    FileOffset FileOffset,
    ulong Size,
    ulong EntrySize,
    bool IsPlt);

/// <summary>One bounded TLS RELA record and its best-known dynamic-symbol identity.</summary>
public sealed record TlsRelocationFacts(
    RelaRelocation Relocation,
    ulong WriteSize,
    TlsRelocationSymbolIdentity? Symbol,
    bool UsesRuntimeModuleResolution,
    bool IsDynamic = true);

/// <summary>Source owner of retained static TLS relocation records.</summary>
public sealed record TlsRelocationSectionFacts(
    int SectionHeaderIndex,
    FileOffset FileOffset,
    VirtualAddress Address,
    ulong Size,
    ulong EntrySize,
    uint SymbolTableSectionIndex,
    uint TargetSectionIndex);

/// <summary>
/// Runtime-neutral TLS dynamic metadata. Dynamic module numbers remain loader-owned;
/// a null symbol on DTPMOD is retained as a module-resolution requirement.
/// </summary>
public sealed record TlsDynamicFacts(
    IReadOnlyList<TlsRelocationTableFacts> RelocationTables,
    IReadOnlyList<TlsRelocationFacts> Relocations,
    VirtualAddress? TlsDescriptorPlt,
    VirtualAddress? TlsDescriptorGot,
    string? Soname)
{
    public static TlsDynamicFacts Empty { get; } = new(
        Array.Empty<TlsRelocationTableFacts>(),
        Array.Empty<TlsRelocationFacts>(),
        null,
        null,
        null);
}

/// <summary>Structural PT_TLS and dynamic-relocation facts owned by StructuralElf.</summary>
public sealed record ElfTlsMetadata(
    IReadOnlyList<TlsSegmentFacts> Segments,
    TlsDynamicFacts Dynamic,
    IReadOnlyList<TlsRelocationSectionFacts> StaticRelocationSections,
    IReadOnlyList<TlsRelocationFacts> StaticRelocations)
{
    public static ElfTlsMetadata Empty { get; } = new(
        Array.Empty<TlsSegmentFacts>(),
        TlsDynamicFacts.Empty,
        Array.Empty<TlsRelocationSectionFacts>(),
        Array.Empty<TlsRelocationFacts>());
}
