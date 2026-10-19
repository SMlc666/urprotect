using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.ElfLayout;

/// <summary>Physical placement strategies considered by the bounded ELF layout planner.</summary>
public enum ElfLayoutStrategy
{
    ExistingExecutableLoadExtension = 1,
    AvailableProgramHeaderSlot = 2,
    RelocatedProgramHeaderTable = 3,
}

public static class ElfLayoutStrategyExtensions
{
    public static string ToEvidenceValue(this ElfLayoutStrategy strategy) => strategy switch
    {
        ElfLayoutStrategy.ExistingExecutableLoadExtension => "existing-rx-load-extension",
        ElfLayoutStrategy.AvailableProgramHeaderSlot => "available-program-header-slot",
        ElfLayoutStrategy.RelocatedProgramHeaderTable => "relocated-program-header-table",
        _ => strategy.ToString(),
    };
}

public enum ElfProgramHeaderEditKind
{
    Unchanged = 0,
    ExtendedExecutableLoad = 1,
    ReplaceAvailableSlot = 2,
    UpdatedProgramHeaderTableMapping = 3,
    NewProgramHeader = 4,
}

public enum ElfLayoutEditKind
{
    Padding = 0,
    GeneratedCode = 1,
    BranchFixup = 2,
    LongBranch = 3,
    ProgramHeader = 4,
    ElfHeader = 5,
    ProgramHeaderTable = 6,
    UnwindMetadata = 7,
    JumpTableEntry = 8,
}

public enum ElfLayoutBranchEncodingKind
{
    Branch26 = 1,
}

public enum ElfLayoutBranchDecision
{
    Direct = 1,
    NearVeneer = 2,
    LongAddress = 3,
}

public static class ElfLayoutLimits
{
    public const ulong DefaultMaximumOutputBytes = 128UL * 1024 * 1024;
    public const int DefaultMaximumProgramHeaderCount = 128;
    public const int DefaultMaximumGeneratedCodeBytes = 8 * 1024 * 1024;
    public const int DefaultMaximumVeneerCount = 1024;
    public const int DefaultMaximumEditCount = 4096;
    public const ulong DefaultMaximumPaddingBytes = 16UL * 1024 * 1024;
    public const ulong DefaultSegmentAlignment = 4096;
    public const ulong DefaultCodeAlignment = 4;
    public const ulong DefaultMaximumAlignment = 16UL * 1024 * 1024;
    public const long Branch26MinimumDisplacement = -(128L * 1024 * 1024);
    public const long Branch26MaximumDisplacementExclusive = 128L * 1024 * 1024;
    public const int MaximumIdentityBytes = 128;
}

/// <summary>Bounds and optional strategy selection for one layout planning request.</summary>
public sealed record ElfLayoutOptions(
    ulong MaximumOutputBytes = ElfLayoutLimits.DefaultMaximumOutputBytes,
    int MaximumProgramHeaderCount = ElfLayoutLimits.DefaultMaximumProgramHeaderCount,
    int MaximumGeneratedCodeBytes = ElfLayoutLimits.DefaultMaximumGeneratedCodeBytes,
    int MaximumVeneerCount = ElfLayoutLimits.DefaultMaximumVeneerCount,
    int MaximumEditCount = ElfLayoutLimits.DefaultMaximumEditCount,
    ulong MaximumPaddingBytes = ElfLayoutLimits.DefaultMaximumPaddingBytes,
    ulong SegmentAlignment = ElfLayoutLimits.DefaultSegmentAlignment,
    ulong CodeAlignment = ElfLayoutLimits.DefaultCodeAlignment,
    ulong MaximumAlignment = ElfLayoutLimits.DefaultMaximumAlignment,
    ElfLayoutStrategy? RequestedStrategy = null)
{
    public static ElfLayoutOptions Default { get; } = new();
}

/// <summary>A checked file/virtual range pair. The virtual address is optional for an unmapped source range.</summary>
public readonly record struct ElfLayoutRange(
    FileOffset FileOffset,
    VirtualAddress VirtualAddress,
    ulong Size,
    bool HasVirtualAddress = true)
{
    public bool TryGetFileEnd(out FileOffset end)
    {
        if (Size > ulong.MaxValue - FileOffset.Value)
        {
            end = default;
            return false;
        }

        end = new FileOffset(FileOffset.Value + Size);
        return true;
    }

    public bool TryGetVirtualEnd(out VirtualAddress end)
    {
        if (!HasVirtualAddress || Size > ulong.MaxValue - VirtualAddress.Value)
        {
            end = default;
            return false;
        }

        end = new VirtualAddress(VirtualAddress.Value + Size);
        return true;
    }

    public bool ContainsFileRange(FileOffset offset, ulong size = 1) =>
        TryGetFileEnd(out var end)
        && offset.Value >= FileOffset.Value
        && offset.Value - FileOffset.Value <= Size
        && size <= end.Value - offset.Value;

    public bool ContainsVirtualRange(VirtualAddress address, ulong size = 1) =>
        HasVirtualAddress
        && TryGetVirtualEnd(out var end)
        && address.Value >= VirtualAddress.Value
        && address.Value - VirtualAddress.Value <= Size
        && size <= end.Value - address.Value;
}

/// <summary>Typed source code request consumed by the physical layout planner.</summary>
public sealed record ElfLayoutRegionRequest
{
    public ElfLayoutRegionRequest(
        string Identity,
        string SourceIdentity,
        VirtualAddress SourceAddress,
        ulong SourceSize,
        byte[] CodeBytes,
        uint Permissions = ElfConstants.PfR | ElfConstants.PfX,
        ulong Alignment = ElfLayoutLimits.DefaultCodeAlignment)
    {
        this.Identity = Identity;
        this.SourceIdentity = SourceIdentity;
        this.SourceAddress = SourceAddress;
        this.SourceSize = SourceSize;
        this.CodeBytes = CodeBytes?.ToArray() ?? throw new ArgumentNullException(nameof(CodeBytes));
        this.Permissions = Permissions;
        this.Alignment = Alignment;
    }

    public string Identity { get; }

    public string SourceIdentity { get; }

    public VirtualAddress SourceAddress { get; }

    public ulong SourceSize { get; }

    public byte[] CodeBytes { get; }

    public uint Permissions { get; }

    public ulong Alignment { get; }
}

/// <summary>Typed veneer bytes supplied by the semantic encoder; the layout layer only places them.</summary>
public sealed record ElfLayoutVeneerRequest
{
    public ElfLayoutVeneerRequest(
        string Identity,
        string TargetIdentity,
        byte[] CodeBytes,
        ulong MaximumBranchDistance = (ulong)ElfLayoutLimits.Branch26MaximumDisplacementExclusive,
        uint Permissions = ElfConstants.PfR | ElfConstants.PfX,
        ulong Alignment = ElfLayoutLimits.DefaultCodeAlignment)
    {
        this.Identity = Identity;
        this.TargetIdentity = TargetIdentity;
        this.CodeBytes = CodeBytes?.ToArray() ?? throw new ArgumentNullException(nameof(CodeBytes));
        this.MaximumBranchDistance = MaximumBranchDistance;
        this.Permissions = Permissions;
        this.Alignment = Alignment;
    }

    public string Identity { get; }

    public string TargetIdentity { get; }

    public byte[] CodeBytes { get; }

    public ulong MaximumBranchDistance { get; }

    public uint Permissions { get; }

    public ulong Alignment { get; }
}

/// <summary>Typed long-address sequence supplied by the semantic encoder.</summary>
public sealed record ElfLayoutLongBranchRequest
{
    public ElfLayoutLongBranchRequest(
        string Identity,
        byte[] CodeBytes,
        byte[]? SourceReplacementBytes = null,
        uint Permissions = ElfConstants.PfR | ElfConstants.PfX,
        ulong Alignment = ElfLayoutLimits.DefaultCodeAlignment)
    {
        this.Identity = Identity;
        this.CodeBytes = CodeBytes?.ToArray() ?? throw new ArgumentNullException(nameof(CodeBytes));
        this.SourceReplacementBytes = SourceReplacementBytes?.ToArray();
        this.Permissions = Permissions;
        this.Alignment = Alignment;
    }

    public string Identity { get; }

    public byte[] CodeBytes { get; }

    public byte[]? SourceReplacementBytes { get; }

    public uint Permissions { get; }

    public ulong Alignment { get; }
}

/// <summary>One typed branch relocation request. No decoder or third-party instruction type crosses this boundary.</summary>
public sealed record ElfLayoutBranchRequest
{
    public ElfLayoutBranchRequest(
        string Identity,
        string SourceIdentity,
        string TargetIdentity,
        VirtualAddress SourceAddress,
        uint SourceOffset,
        uint TargetOffset,
        ElfLayoutBranchEncodingKind Encoding = ElfLayoutBranchEncodingKind.Branch26,
        uint Opcode = 0x14000000,
        ElfLayoutVeneerRequest? NearVeneer = null,
        ElfLayoutLongBranchRequest? LongBranch = null)
    {
        this.Identity = Identity;
        this.SourceIdentity = SourceIdentity;
        this.TargetIdentity = TargetIdentity;
        this.SourceAddress = SourceAddress;
        this.SourceOffset = SourceOffset;
        this.TargetOffset = TargetOffset;
        this.Encoding = Encoding;
        this.Opcode = Opcode;
        this.NearVeneer = NearVeneer;
        this.LongBranch = LongBranch;
    }

    public string Identity { get; }

    public string SourceIdentity { get; }

    public string TargetIdentity { get; }

    public VirtualAddress SourceAddress { get; }

    public uint SourceOffset { get; }

    public uint TargetOffset { get; }

    public ElfLayoutBranchEncodingKind Encoding { get; }

    public uint Opcode { get; }

    public ElfLayoutVeneerRequest? NearVeneer { get; }

    public ElfLayoutLongBranchRequest? LongBranch { get; }
}

public sealed record ElfProgramHeaderPlan(
    int? SourceIndex,
    ProgramHeader? OriginalHeader,
    ProgramHeader PlannedHeader,
    ElfProgramHeaderEditKind EditKind);

public sealed record ElfLayoutPlacement(
    string Identity,
    string SourceIdentity,
    FileOffset FileOffset,
    VirtualAddress VirtualAddress,
    ulong Size,
    uint Permissions,
    ulong Alignment)
{
    public ElfLayoutRange Range => new(FileOffset, VirtualAddress, Size);
}

public sealed record ElfLayoutByteEdit(
    FileOffset Offset,
    byte[] Bytes,
    ElfLayoutEditKind Kind)
{
    public ElfLayoutByteEdit(FileOffset Offset, ReadOnlySpan<byte> Bytes, ElfLayoutEditKind Kind)
        : this(Offset, Bytes.ToArray(), Kind)
    {
    }
}

public sealed record ElfLayoutAddressMapEntry(
    string Identity,
    string SourceIdentity,
    ElfLayoutRange? SourceRange,
    ElfLayoutRange OutputRange);

/// <summary>
/// Planner-derived proof for one rewritten relative jump-table entry. Both the
/// source and output address domains remain explicit so evidence consumers can
/// independently recompute the entry encoding against the retained address map.
/// </summary>
public sealed record ElfLayoutJumpTableTargetBinding(
    SemanticEntityId TableIdentity,
    SemanticSourceRange SourceTableRange,
    SemanticEntityId EntryIdentity,
    SemanticEntityId TargetIdentity,
    SemanticEntityId TargetBaseIdentity,
    int EntryIndex,
    SemanticSourceRange SourceEntryRange,
    VirtualAddress SourceTargetAddress,
    VirtualAddress OutputTargetAddress,
    VirtualAddress SourceTargetBaseAddress,
    VirtualAddress OutputTargetBaseAddress,
    SemanticSourceRange OutputEntryRange,
    int EntryWidth,
    bool IsSigned,
    int Scale,
    long Addend,
    long SourceEncodedValue,
    long OutputEncodedValue);

public sealed record ElfBranchPlacementDecision(
    string Identity,
    string SourceIdentity,
    string TargetIdentity,
    ElfLayoutBranchDecision Decision,
    ElfLayoutRange SourceRange,
    ElfLayoutRange TargetRange,
    long? Displacement,
    string? VeneerIdentity,
    uint Opcode,
    long MinimumDisplacement,
    long MaximumDisplacementExclusive);

public sealed record ElfLayoutJumpTableEntryOutputBinding(
    SemanticEntityId EntryIdentity,
    SemanticEntityId TargetIdentity,
    VirtualAddress OutputTargetAddress);

public sealed record ElfLayoutJumpTableEditRequest(
    SemanticEntityId TableIdentity,
    SemanticSourceRange TableRange,
    VirtualAddress TargetBaseAddress,
    int EntryWidth,
    bool IsSigned,
    int Scale,
    long Addend,
    SemanticJumpTableRewritePolicy RewritePolicy,
    IReadOnlyList<SemanticJumpTableEntryBinding> Entries,
    SemanticJumpTableOwnership Ownership = SemanticJumpTableOwnership.Ambiguous,
    SemanticSourceRange? RequestedOutputRange = null,
    IReadOnlyList<Aarch64JumpTableReferenceProducer>? TableReferenceProducers = null,
    IReadOnlyList<Aarch64JumpTableOwnerReference>? OwnerReferences = null,
    bool OwnerInventoryComplete = false,
    SemanticSourceRange? SelectedFunctionSourceRange = null,
    SemanticSourceRange? SelectedFunctionOutputRange = null,
    SemanticEntityId? OutputTargetBaseIdentity = null,
    VirtualAddress? OutputTargetBaseAddress = null,
    IReadOnlyList<ElfLayoutJumpTableEntryOutputBinding>? OutputEntryBindings = null);

public sealed record ElfLayoutJumpTableClone(
    SemanticEntityId TableIdentity,
    SemanticSourceRange SourceTableRange,
    SemanticSourceRange RequestedOutputRange,
    ElfLayoutRange OutputRange,
    [property: JsonConverter(typeof(ElfLayoutEvidenceJumpTableOwnershipJsonConverter))]
    SemanticJumpTableOwnership Ownership,
    SemanticJumpTableRewritePolicy RewritePolicy,
    IReadOnlyList<Aarch64JumpTableReferenceProducer> TableReferenceProducers,
    IReadOnlyList<Aarch64JumpTableOwnerReference> OwnerReferences,
    bool OwnerInventoryComplete,
    uint Permissions);

/// <summary>
/// Keeps the layout-evidence v3 JSON ownership ordinals independent from the
/// semantic-plan snapshot's <see cref="SemanticJumpTableOwnership"/> ordinals.
/// </summary>
public sealed class ElfLayoutEvidenceJumpTableOwnershipJsonConverter : JsonConverter<SemanticJumpTableOwnership>
{
    public override SemanticJumpTableOwnership Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out var value))
        {
            throw new JsonException("Layout-evidence jump-table ownership must be an integer ordinal.");
        }

        return value switch
        {
            0 => SemanticJumpTableOwnership.Ambiguous,
            1 => SemanticJumpTableOwnership.SelectedFunctionPrivate,
            2 => SemanticJumpTableOwnership.Shared,
            3 => SemanticJumpTableOwnership.External,
            4 => SemanticJumpTableOwnership.RuntimeOwned,
            _ => throw new JsonException("Layout-evidence jump-table ownership ordinal is unsupported."),
        };
    }

    public override void Write(
        Utf8JsonWriter writer,
        SemanticJumpTableOwnership value,
        JsonSerializerOptions options)
    {
        var ordinal = value switch
        {
            SemanticJumpTableOwnership.Ambiguous => 0,
            SemanticJumpTableOwnership.SelectedFunctionPrivate => 1,
            SemanticJumpTableOwnership.Shared => 2,
            SemanticJumpTableOwnership.External => 3,
            SemanticJumpTableOwnership.RuntimeOwned => 4,
            _ => throw new JsonException("Semantic jump-table ownership is not defined."),
        };
        writer.WriteNumberValue(ordinal);
    }
}

public sealed record ElfLayoutTlsFixupRequest(
    string RegionIdentity,
    ulong OutputOffset,
    TlsSemanticFixup Fixup);

public sealed record ElfLayoutTlsFixupDecision(
    string RegionIdentity,
    TlsSemanticFixup Fixup,
    FileOffset OutputFileOffset,
    VirtualAddress OutputVirtualAddress,
    uint OutputEncoding);

public sealed record ElfLayoutPlan(
    string SourceSha256,
    ElfLayoutStrategy Strategy,
    ElfLayoutRange OldProgramHeaderTable,
    ElfLayoutRange NewProgramHeaderTable,
    int OldProgramHeaderCount,
    int NewProgramHeaderCount,
    ulong OutputLength,
    string PreservedMetadataSha256,
    IReadOnlyList<ElfProgramHeaderPlan> ProgramHeaders,
    IReadOnlyList<ElfLayoutPlacement> Placements,
    IReadOnlyList<ElfLayoutAddressMapEntry> AddressMap,
    IReadOnlyList<ElfBranchPlacementDecision> BranchDecisions,
    IReadOnlyList<ElfLayoutByteEdit> Edits)
{
    public IReadOnlyList<ElfLayoutTlsFixupDecision> TlsFixups { get; init; } = Array.Empty<ElfLayoutTlsFixupDecision>();

    public IReadOnlyList<ElfLayoutByteEdit> UnwindEdits { get; init; } = Array.Empty<ElfLayoutByteEdit>();

    public IReadOnlyList<ElfLayoutByteEdit> JumpTableEdits { get; init; } = Array.Empty<ElfLayoutByteEdit>();

    public IReadOnlyList<ElfLayoutJumpTableTargetBinding> JumpTableTargetBindings { get; init; } =
        Array.Empty<ElfLayoutJumpTableTargetBinding>();

    public IReadOnlyList<ElfLayoutJumpTableClone> JumpTableClones { get; init; } = Array.Empty<ElfLayoutJumpTableClone>();
}

/// <summary>Bounded serializable projection of a selected physical layout.</summary>
public sealed record ElfLayoutEvidence(
    int SchemaVersion,
    ElfLayoutStrategy Strategy,
    string SourceSha256,
    string OutputSha256,
    ulong OutputLength,
    ElfLayoutRange OldProgramHeaderTable,
    ElfLayoutRange NewProgramHeaderTable,
    string PreservedMetadataSha256,
    IReadOnlyList<ElfLayoutPlacement> Placements,
    IReadOnlyList<ElfLayoutAddressMapEntry> AddressMap,
    IReadOnlyList<ElfBranchPlacementDecision> BranchDecisions)
{
    public IReadOnlyList<ElfLayoutTlsFixupDecision> TlsFixups { get; init; } = Array.Empty<ElfLayoutTlsFixupDecision>();

    public IReadOnlyList<ElfLayoutByteEdit> UnwindEdits { get; init; } = Array.Empty<ElfLayoutByteEdit>();

    public IReadOnlyList<ElfLayoutByteEdit> JumpTableEdits { get; init; } = Array.Empty<ElfLayoutByteEdit>();

    public IReadOnlyList<ElfLayoutJumpTableTargetBinding> JumpTableTargetBindings { get; init; } =
        Array.Empty<ElfLayoutJumpTableTargetBinding>();

    public IReadOnlyList<ElfLayoutJumpTableClone> JumpTableClones { get; init; } = Array.Empty<ElfLayoutJumpTableClone>();

    public const int CurrentSchemaVersion = 3;

    public string StrategyValue => Strategy.ToEvidenceValue();
}

public sealed record ElfLayoutPlanningResult(
    ElfLayoutPlan? Plan,
    ElfLayoutEvidence? Evidence,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Plan is not null
        && Evidence is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed record ElfLayoutResult(
    ElfLayoutPlan? Plan,
    byte[]? Bytes,
    ElfFile? ParsedOutput,
    ElfLayoutEvidence? Evidence,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Plan is not null
        && Bytes is not null
        && ParsedOutput is not null
        && Evidence is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}
