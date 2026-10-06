using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Elf;

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
    IReadOnlyList<ElfLayoutByteEdit> Edits);

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
    public const int CurrentSchemaVersion = 1;

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

/// <summary>
/// Plans all supported physical ELF placement strategies before any bytes are written.
/// A PT_NULL entry is only one ordinary candidate in this planner.
/// </summary>
public static class ElfLayoutPlanner
{
    private const uint GeneratedSegmentPermissions = ElfConstants.PfR | ElfConstants.PfX;

    public static ElfLayoutPlanningResult Plan(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        IEnumerable<ElfLayoutRegionRequest> regionRequests,
        IEnumerable<ElfLayoutBranchRequest> branchRequests,
        ElfLayoutOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sourceFile);
        ArgumentNullException.ThrowIfNull(regionRequests);
        ArgumentNullException.ThrowIfNull(branchRequests);

        var diagnostics = new DiagnosticBag();
        options ??= ElfLayoutOptions.Default;
        ValidateOptions(options, diagnostics);
        var maximumRequests = Math.Max(options.MaximumEditCount, 1);
        var regions = ReadBounded(regionRequests, maximumRequests, out var regionsExceeded);
        var branches = ReadBounded(branchRequests, maximumRequests, out var branchesExceeded);
        if (regionsExceeded || branchesExceeded)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutOutputLimitExceeded, "The layout request stream exceeds its configured edit bound.");
        }

        var sourceLength = (ulong)sourceBytes.Length;
        if (sourceFile.Bytes.Length != sourceBytes.Length
            || !sourceFile.Bytes.Span.SequenceEqual(sourceBytes.Span))
        {
            diagnostics.Error(
                DiagnosticCode.ElfLayoutSourceMismatch,
                "The parsed ELF snapshot does not match the layout source snapshot.");
        }

        var sourceSha256 = Sha256(sourceBytes.Span);
        ValidateSource(sourceFile, sourceLength, options, diagnostics);
        ValidateRequests(sourceFile, sourceLength, regions, branches, options, diagnostics);
        if (diagnostics.HasErrors)
        {
            return new ElfLayoutPlanningResult(null, null, diagnostics.ToArray());
        }

        var strategies = options.RequestedStrategy is ElfLayoutStrategy requested
            ? new[] { requested }
            : new[]
            {
                ElfLayoutStrategy.ExistingExecutableLoadExtension,
                ElfLayoutStrategy.AvailableProgramHeaderSlot,
                ElfLayoutStrategy.RelocatedProgramHeaderTable,
            };
        var candidates = new List<LayoutCandidate>(strategies.Length);
        var candidateDiagnostics = new List<Diagnostic>();
        foreach (var strategy in strategies)
        {
            if (TryBuildCandidate(
                    sourceBytes,
                    sourceFile,
                    sourceLength,
                    sourceSha256,
                    regions,
                    branches,
                    options,
                    strategy,
                    out var candidate,
                    out var rejected))
            {
                candidates.Add(candidate!);
            }
            else
            {
                candidateDiagnostics.AddRange(rejected);
            }
        }

        if (candidates.Count == 0)
        {
            diagnostics.AddRange(candidateDiagnostics);
            if (!diagnostics.HasErrors)
            {
                diagnostics.Error(
                    DiagnosticCode.RehydrationLayoutUnavailable,
                    "No bounded ELF layout strategy can place the requested transformed code.");
            }

            return new ElfLayoutPlanningResult(null, null, diagnostics.ToArray());
        }

        var selected = candidates
            .OrderBy(candidate => candidate.Score.TableRelocation)
            .ThenBy(candidate => candidate.Score.ProgramHeaderCountDelta)
            .ThenBy(candidate => candidate.Score.MetadataHeaderEdits)
            .ThenBy(candidate => candidate.Score.PaddingBytes)
            .ThenBy(candidate => candidate.Score.StrategyRank)
            .First();
        var evidence = CreateEvidence(selected.Plan);
        return new ElfLayoutPlanningResult(selected.Plan, evidence, diagnostics.ToArray());
    }

    public static ElfLayoutPlanningResult Plan(
        ElfFile sourceFile,
        IEnumerable<ElfLayoutRegionRequest> regionRequests,
        IEnumerable<ElfLayoutBranchRequest> branchRequests,
        ElfLayoutOptions? options = null) =>
        Plan(sourceFile.Bytes, sourceFile, regionRequests, branchRequests, options);

    public static ElfLayoutPlanningResult CreatePlan(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        IEnumerable<ElfLayoutRegionRequest> regionRequests,
        IEnumerable<ElfLayoutBranchRequest> branchRequests,
        ElfLayoutOptions? options = null) =>
        Plan(sourceBytes, sourceFile, regionRequests, branchRequests, options);

    private static bool TryBuildCandidate(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        ulong sourceLength,
        string sourceSha256,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutBranchRequest> branches,
        ElfLayoutOptions options,
        ElfLayoutStrategy strategy,
        out LayoutCandidate? candidate,
        out IReadOnlyList<Diagnostic> rejected)
    {
        var diagnostics = new DiagnosticBag();
        candidate = null;
        rejected = Array.Empty<Diagnostic>();
        try
        {
            if (!TryGetProgramHeaderTableRange(sourceFile, sourceLength, out var oldTable, out var tableSize))
            {
                diagnostics.Error(
                    DiagnosticCode.TableOutOfBounds,
                    "The source program-header table cannot be represented by the bounded layout planner.",
                    sourceFile.Header.ProgramHeaderOffset);
                rejected = diagnostics.ToArray();
                return false;
            }

            var sourceHeaders = sourceFile.ProgramHeaders.ToArray();
            var plannedHeaders = sourceHeaders.ToList();
            var programHeaderCount = sourceHeaders.Length;
            var segmentAlignment = options.SegmentAlignment;
            var segmentFileStart = 0UL;
            var segmentVirtualStart = 0UL;
            var codeFileStart = 0UL;
            var codeVirtualStart = 0UL;
            var tableFileStart = sourceFile.Header.ProgramHeaderOffset;
            var tableVirtualAddress = oldTable.VirtualAddress.Value;
            var tableHasVirtualAddress = oldTable.HasVirtualAddress;
            var tableOutputSize = tableSize;
            var changedHeaderIndex = -1;
            var extensionHeader = default(ProgramHeader);
            var isExtension = strategy == ElfLayoutStrategy.ExistingExecutableLoadExtension;
            var isRelocation = strategy == ElfLayoutStrategy.RelocatedProgramHeaderTable;

            if (isExtension)
            {
                if (!TryFindExtensionHeader(sourceFile, sourceLength, out changedHeaderIndex, out extensionHeader))
                {
                    diagnostics.Error(
                        DiagnosticCode.RehydrationLayoutUnavailable,
                        "No terminal executable PT_LOAD can be safely extended without mapping unrelated source bytes.");
                    rejected = diagnostics.ToArray();
                    return false;
                }

                if (extensionHeader.Alignment > options.MaximumAlignment)
                {
                    diagnostics.Error(
                        DiagnosticCode.InvalidAlignment,
                        "The existing executable PT_LOAD alignment exceeds the configured layout bound.",
                        extensionHeader.Offset);
                    rejected = diagnostics.ToArray();
                    return false;
                }

                segmentFileStart = sourceLength;
                if (!TryAdd(extensionHeader.VirtualAddress, extensionHeader.FileSize, out codeVirtualStart))
                {
                    diagnostics.Error(DiagnosticCode.AddressOverflow, "The executable PT_LOAD extension address overflowed.");
                    rejected = diagnostics.ToArray();
                    return false;
                }

                codeFileStart = sourceLength;
                segmentVirtualStart = extensionHeader.VirtualAddress;
            }
            else
            {
                if (!TryGetAlignedPlacement(
                        sourceFile,
                        sourceLength,
                        options,
                        out segmentFileStart,
                        out segmentVirtualStart,
                        diagnostics))
                {
                    rejected = diagnostics.ToArray();
                    return false;
                }

                codeFileStart = segmentFileStart;
                codeVirtualStart = segmentVirtualStart;
                if (isRelocation)
                {
                    if (programHeaderCount >= options.MaximumProgramHeaderCount
                        || programHeaderCount >= ushort.MaxValue)
                    {
                        diagnostics.Error(
                            DiagnosticCode.RehydrationLayoutUnavailable,
                            "The relocated program-header table would exceed the bounded program-header count.");
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    var newCount = checked(programHeaderCount + 1);
                    tableOutputSize = checked((ulong)newCount * sourceFile.Header.ProgramHeaderEntrySize);
                    if (!TryAdd(segmentFileStart, tableOutputSize, out var codeAfterTable)
                        || !TryAlignUp(codeAfterTable, options.CodeAlignment, out codeFileStart)
                        || codeFileStart < segmentFileStart)
                    {
                        diagnostics.Error(DiagnosticCode.AddressOverflow, "The relocated program-header table placement overflowed.");
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    codeVirtualStart = checked(segmentVirtualStart + (codeFileStart - segmentFileStart));
                    tableFileStart = segmentFileStart;
                    tableVirtualAddress = segmentVirtualStart;
                    tableHasVirtualAddress = true;
                    programHeaderCount = newCount;
                }
                else if (!TryFindNullHeader(sourceHeaders, out changedHeaderIndex))
                {
                    diagnostics.Error(
                        DiagnosticCode.RehydrationLayoutUnavailable,
                        "The source ELF has no PT_NULL program-header candidate for the generated executable region.");
                    rejected = diagnostics.ToArray();
                    return false;
                }
            }

            var placements = new List<ElfLayoutPlacement>(regions.Count + options.MaximumVeneerCount);
            var addressMap = new List<ElfLayoutAddressMapEntry>(regions.Count + options.MaximumVeneerCount);
            var placementByIdentity = new Dictionary<string, ElfLayoutPlacement>(StringComparer.Ordinal);
            var edits = new List<ElfLayoutByteEdit>();
            var cursorFile = codeFileStart;
            var cursorVirtual = codeVirtualStart;
            foreach (var region in regions.OrderBy(region => region.Identity, StringComparer.Ordinal))
            {
                var previousFileCursor = cursorFile;
                if (!TryAlignPlacementCursor(
                        ref cursorFile,
                        ref cursorVirtual,
                        region.Alignment,
                        codeFileStart,
                        codeVirtualStart,
                        diagnostics))
                {
                    rejected = diagnostics.ToArray();
                    return false;
                }

                AddPaddingEdits(edits, previousFileCursor, cursorFile, options, diagnostics);
                if (diagnostics.HasErrors)
                {
                    rejected = diagnostics.ToArray();
                    return false;
                }

                var placement = new ElfLayoutPlacement(
                    region.Identity,
                    region.SourceIdentity,
                    new FileOffset(cursorFile),
                    new VirtualAddress(cursorVirtual),
                    checked((ulong)region.CodeBytes.Length),
                    region.Permissions,
                    region.Alignment);
                placements.Add(placement);
                placementByIdentity.Add(placement.Identity, placement);
                var sourceRange = GetSourceRange(sourceFile, region.SourceAddress, region.SourceSize);
                addressMap.Add(new ElfLayoutAddressMapEntry(placement.Identity, placement.SourceIdentity, sourceRange, placement.Range));
                edits.Add(new ElfLayoutByteEdit(placement.FileOffset, region.CodeBytes, ElfLayoutEditKind.GeneratedCode));
                cursorFile = checked(cursorFile + placement.Size);
                cursorVirtual = checked(cursorVirtual + placement.Size);
            }

            var branchDecisions = new List<ElfBranchPlacementDecision>(branches.Count);
            var veneerByIdentity = new Dictionary<string, ElfLayoutPlacement>(StringComparer.Ordinal);
            var veneerRequestByIdentity = new Dictionary<string, ElfLayoutVeneerRequest>(StringComparer.Ordinal);
            var longBranchByIdentity = new Dictionary<string, ElfLayoutPlacement>(StringComparer.Ordinal);
            var longBranchRequestByIdentity = new Dictionary<string, ElfLayoutLongBranchRequest>(StringComparer.Ordinal);
            foreach (var branch in branches.OrderBy(branch => branch.Identity, StringComparer.Ordinal))
            {
                if (!placementByIdentity.TryGetValue(branch.TargetIdentity, out var targetPlacement))
                {
                    diagnostics.Error(
                        DiagnosticCode.RehydrationMalformed,
                        $"Branch '{branch.Identity}' refers to an unknown target placement.");
                    rejected = diagnostics.ToArray();
                    return false;
                }

                var branchAddress = checked(branch.SourceAddress.Value + branch.SourceOffset);
                if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                        new VirtualAddress(branchAddress),
                        sizeof(uint),
                        out var branchFileOffset))
                {
                    diagnostics.Error(
                        DiagnosticCode.AddressUnmapped,
                        $"Branch '{branch.Identity}' is not mapped to a file-backed executable source instruction.",
                        branchAddress);
                    rejected = diagnostics.ToArray();
                    return false;
                }

                var targetAddress = checked(targetPlacement.VirtualAddress.Value + branch.TargetOffset);
                var targetRange = new ElfLayoutRange(
                    new FileOffset(checked(targetPlacement.FileOffset.Value + branch.TargetOffset)),
                    new VirtualAddress(targetAddress),
                    sizeof(uint));
                if (branch.Encoding != ElfLayoutBranchEncodingKind.Branch26)
                {
                    diagnostics.Error(
                        DiagnosticCode.ElfLayoutUnsupported,
                        $"Branch '{branch.Identity}' uses an unsupported layout encoding.",
                        branchAddress);
                    rejected = diagnostics.ToArray();
                    return false;
                }

                if (TryEncodeBranch26(branch.Opcode, branchAddress, targetAddress, out var directEncoding, out var directDisplacement))
                {
                    var sourceRange = GetSourceRange(sourceFile, new VirtualAddress(branchAddress), sizeof(uint));
                    branchDecisions.Add(new ElfBranchPlacementDecision(
                        branch.Identity,
                        branch.SourceIdentity,
                        branch.TargetIdentity,
                        ElfLayoutBranchDecision.Direct,
                        sourceRange ?? new ElfLayoutRange(branchFileOffset, new VirtualAddress(branchAddress), sizeof(uint)),
                        targetRange,
                        directDisplacement,
                        null,
                        branch.Opcode,
                        ElfLayoutLimits.Branch26MinimumDisplacement,
                        ElfLayoutLimits.Branch26MaximumDisplacementExclusive));
                    edits.Add(new ElfLayoutByteEdit(branchFileOffset, directEncoding, ElfLayoutEditKind.BranchFixup));
                    continue;
                }

                if (branch.NearVeneer is not null)
                {
                    var veneer = branch.NearVeneer;
                    if (!string.Equals(veneer.TargetIdentity, branch.TargetIdentity, StringComparison.Ordinal))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ElfLayoutMalformed,
                            $"Branch '{branch.Identity}' veneer target does not match the branch target.",
                            branchAddress);
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    ElfLayoutPlacement veneerPlacement;
                    if (veneerByIdentity.TryGetValue(veneer.Identity, out var existingVeneerPlacement))
                    {
                        if (!veneerRequestByIdentity.TryGetValue(veneer.Identity, out var existingVeneer)
                            || !EquivalentVeneerRequest(existingVeneer, veneer))
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutMalformed,
                                $"Veneer identity '{veneer.Identity}' is reused with different typed bytes or target metadata.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        veneerPlacement = existingVeneerPlacement;
                    }
                    else
                    {
                        veneerRequestByIdentity.Add(veneer.Identity, veneer);
                        if (veneerByIdentity.Count >= options.MaximumVeneerCount)
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutOutputLimitExceeded,
                                "The layout veneer count exceeds its configured bound.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        var previousFileCursor = cursorFile;
                        if (!TryAlignPlacementCursor(
                                ref cursorFile,
                                ref cursorVirtual,
                                veneer.Alignment,
                                codeFileStart,
                                codeVirtualStart,
                                diagnostics))
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        AddPaddingEdits(edits, previousFileCursor, cursorFile, options, diagnostics);
                        if (diagnostics.HasErrors)
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        veneerPlacement = new ElfLayoutPlacement(
                            veneer.Identity,
                            branch.SourceIdentity,
                            new FileOffset(cursorFile),
                            new VirtualAddress(cursorVirtual),
                            checked((ulong)veneer.CodeBytes.Length),
                            veneer.Permissions,
                            veneer.Alignment);
                        veneerByIdentity.Add(veneer.Identity, veneerPlacement);
                        placementByIdentity.Add(veneer.Identity, veneerPlacement);
                        placements.Add(veneerPlacement);
                        addressMap.Add(new ElfLayoutAddressMapEntry(
                            veneerPlacement.Identity,
                            veneerPlacement.SourceIdentity,
                            null,
                            veneerPlacement.Range));
                        edits.Add(new ElfLayoutByteEdit(
                            veneerPlacement.FileOffset,
                            veneer.CodeBytes,
                            ElfLayoutEditKind.GeneratedCode));
                        cursorFile = checked(cursorFile + veneerPlacement.Size);
                        cursorVirtual = checked(cursorVirtual + veneerPlacement.Size);
                    }

                    if (!TryEncodeBranch26(
                            branch.Opcode,
                            branchAddress,
                            veneerPlacement.VirtualAddress.Value,
                            out var veneerEncoding,
                            out var veneerDisplacement)
                        || veneerDisplacement is null
                        || (ulong)Math.Abs(veneerDisplacement.Value) > veneer.MaximumBranchDistance)
                    {
                        diagnostics.Error(
                            DiagnosticCode.ElfLayoutBranchOutOfRange,
                            $"Branch '{branch.Identity}' cannot reach its requested near veneer.",
                            branchAddress);
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    var sourceRangeForVeneer = GetSourceRange(sourceFile, new VirtualAddress(branchAddress), sizeof(uint));
                    branchDecisions.Add(new ElfBranchPlacementDecision(
                        branch.Identity,
                        branch.SourceIdentity,
                        branch.TargetIdentity,
                        ElfLayoutBranchDecision.NearVeneer,
                        sourceRangeForVeneer ?? new ElfLayoutRange(branchFileOffset, new VirtualAddress(branchAddress), sizeof(uint)),
                        veneerPlacement.Range,
                        veneerDisplacement,
                        veneer.Identity,
                        branch.Opcode,
                        ElfLayoutLimits.Branch26MinimumDisplacement,
                        ElfLayoutLimits.Branch26MaximumDisplacementExclusive));
                    edits.Add(new ElfLayoutByteEdit(branchFileOffset, veneerEncoding, ElfLayoutEditKind.BranchFixup));
                    continue;
                }

                if (branch.LongBranch is not null)
                {
                    var longBranch = branch.LongBranch;
                    ElfLayoutPlacement longPlacement;
                    if (longBranchByIdentity.TryGetValue(longBranch.Identity, out var existingLongPlacement))
                    {
                        if (!longBranchRequestByIdentity.TryGetValue(longBranch.Identity, out var existingLongBranch)
                            || !EquivalentLongBranchRequest(existingLongBranch, longBranch))
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutMalformed,
                                $"Long-branch identity '{longBranch.Identity}' is reused with different typed bytes or replacement metadata.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        longPlacement = existingLongPlacement;
                    }
                    else
                    {
                        longBranchRequestByIdentity.Add(longBranch.Identity, longBranch);
                        var previousFileCursor = cursorFile;
                        if (!TryAlignPlacementCursor(
                                ref cursorFile,
                                ref cursorVirtual,
                                longBranch.Alignment,
                                codeFileStart,
                                codeVirtualStart,
                                diagnostics))
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        AddPaddingEdits(edits, previousFileCursor, cursorFile, options, diagnostics);
                        if (diagnostics.HasErrors)
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        longPlacement = new ElfLayoutPlacement(
                            longBranch.Identity,
                            branch.SourceIdentity,
                            new FileOffset(cursorFile),
                            new VirtualAddress(cursorVirtual),
                            checked((ulong)longBranch.CodeBytes.Length),
                            longBranch.Permissions,
                            longBranch.Alignment);
                        longBranchByIdentity.Add(longBranch.Identity, longPlacement);
                        placementByIdentity.Add(longPlacement.Identity, longPlacement);
                        placements.Add(longPlacement);
                        addressMap.Add(new ElfLayoutAddressMapEntry(
                            longPlacement.Identity,
                            longPlacement.SourceIdentity,
                            null,
                            longPlacement.Range));
                        edits.Add(new ElfLayoutByteEdit(
                            longPlacement.FileOffset,
                            longBranch.CodeBytes,
                            ElfLayoutEditKind.GeneratedCode));
                        cursorFile = checked(cursorFile + longPlacement.Size);
                        cursorVirtual = checked(cursorVirtual + longPlacement.Size);
                    }

                    var longSourceRange = GetSourceRange(sourceFile, new VirtualAddress(branchAddress), sizeof(uint));
                    branchDecisions.Add(new ElfBranchPlacementDecision(
                        branch.Identity,
                        branch.SourceIdentity,
                        branch.TargetIdentity,
                        ElfLayoutBranchDecision.LongAddress,
                        longSourceRange ?? new ElfLayoutRange(branchFileOffset, new VirtualAddress(branchAddress), sizeof(uint)),
                        targetRange,
                        null,
                        longPlacement.Identity,
                        branch.Opcode,
                        ElfLayoutLimits.Branch26MinimumDisplacement,
                        ElfLayoutLimits.Branch26MaximumDisplacementExclusive));
                    if (longBranch.SourceReplacementBytes is not null)
                    {
                        if (longBranch.SourceReplacementBytes.Length == 0
                            || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                                new VirtualAddress(branchAddress),
                                checked((ulong)longBranch.SourceReplacementBytes.Length),
                                out _))
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutMalformed,
                                $"Long branch '{longBranch.Identity}' has an invalid source replacement range.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        edits.Add(new ElfLayoutByteEdit(
                            branchFileOffset,
                            longBranch.SourceReplacementBytes,
                            ElfLayoutEditKind.LongBranch));
                    }

                    continue;
                }

                diagnostics.Error(
                    DiagnosticCode.ElfLayoutBranchOutOfRange,
                    $"Branch '{branch.Identity}' is outside the direct Branch26 range and has no typed relaxation.",
                    branchAddress);
                rejected = diagnostics.ToArray();
                return false;
            }

            var generatedSpanBytes = checked(cursorFile - codeFileStart);
            var generatedCodeBytes = 0UL;
            foreach (var placement in placements)
            {
                generatedCodeBytes = checked(generatedCodeBytes + placement.Size);
            }

            if (generatedCodeBytes == 0 || generatedCodeBytes > (ulong)options.MaximumGeneratedCodeBytes)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "Generated code and typed veneers exceed the configured layout bound.");
                rejected = diagnostics.ToArray();
                return false;
            }

            var paddingBytes = 0UL;
            foreach (var padding in edits.Where(edit => edit.Kind == ElfLayoutEditKind.Padding))
            {
                paddingBytes = checked(paddingBytes + (ulong)padding.Bytes.Length);
            }
            if (paddingBytes > options.MaximumPaddingBytes)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "Layout padding exceeds the configured bound.");
                rejected = diagnostics.ToArray();
                return false;
            }
            var segmentFileSize = isRelocation
                ? checked((codeFileStart - segmentFileStart) + generatedSpanBytes)
                : generatedSpanBytes;
            var segmentVirtualSize = segmentFileSize;
            var plannedSegment = new ProgramHeader(
                ElfConstants.PtLoad,
                isExtension ? extensionHeader.Flags : GeneratedSegmentPermissions,
                isExtension ? extensionHeader.Offset : segmentFileStart,
                isExtension ? extensionHeader.VirtualAddress : segmentVirtualStart,
                isExtension ? extensionHeader.PhysicalAddress : segmentVirtualStart,
                isExtension ? checked(extensionHeader.FileSize + generatedSpanBytes) : segmentFileSize,
                isExtension ? checked(extensionHeader.MemorySize + generatedSpanBytes) : segmentVirtualSize,
                isExtension ? extensionHeader.Alignment : segmentAlignment);

            if (isExtension || strategy == ElfLayoutStrategy.AvailableProgramHeaderSlot)
            {
                plannedHeaders[changedHeaderIndex] = plannedSegment;
            }
            else
            {
                if (sourceFile.ProgramHeaders.Any(header => header.Type == ElfConstants.PtPhdr))
                {
                    for (var index = 0; index < plannedHeaders.Count; index++)
                    {
                        if (plannedHeaders[index].Type != ElfConstants.PtPhdr)
                        {
                            continue;
                        }

                        var original = plannedHeaders[index];
                        plannedHeaders[index] = original with
                        {
                            Offset = tableFileStart,
                            VirtualAddress = tableVirtualAddress,
                            PhysicalAddress = tableVirtualAddress,
                            FileSize = tableOutputSize,
                            MemorySize = tableOutputSize,
                        };
                    }
                }

                plannedHeaders.Add(plannedSegment);
            }

            var programHeaderPlans = new List<ElfProgramHeaderPlan>(plannedHeaders.Count);
            for (var index = 0; index < plannedHeaders.Count; index++)
            {
                var original = index < sourceHeaders.Length ? sourceHeaders[index] : (ProgramHeader?)null;
                var editKind = ElfProgramHeaderEditKind.Unchanged;
                if (original is null)
                {
                    editKind = ElfProgramHeaderEditKind.NewProgramHeader;
                }
                else if (plannedHeaders[index] != original.Value)
                {
                    editKind = plannedHeaders[index].Type == ElfConstants.PtPhdr
                        ? ElfProgramHeaderEditKind.UpdatedProgramHeaderTableMapping
                        : strategy == ElfLayoutStrategy.ExistingExecutableLoadExtension
                            ? ElfProgramHeaderEditKind.ExtendedExecutableLoad
                            : ElfProgramHeaderEditKind.ReplaceAvailableSlot;
                }

                programHeaderPlans.Add(new ElfProgramHeaderPlan(index < sourceHeaders.Length ? index : null, original, plannedHeaders[index], editKind));
            }

            AddPaddingEdits(edits, sourceLength, segmentFileStart, options, diagnostics);
            if (isRelocation)
            {
                var tableBytes = SerializeProgramHeaders(plannedHeaders);
                edits.Add(new ElfLayoutByteEdit(new FileOffset(tableFileStart), tableBytes, ElfLayoutEditKind.ProgramHeaderTable));
                var newProgramHeaderOffset = new byte[sizeof(ulong)];
                BinaryPrimitives.WriteUInt64LittleEndian(newProgramHeaderOffset, tableFileStart);
                edits.Add(new ElfLayoutByteEdit(
                    new FileOffset(ElfHeaderOffsets.ProgramHeaderOffset),
                    newProgramHeaderOffset,
                    ElfLayoutEditKind.ElfHeader));
                var newProgramHeaderCount = new byte[sizeof(ushort)];
                BinaryPrimitives.WriteUInt16LittleEndian(newProgramHeaderCount, checked((ushort)plannedHeaders.Count));
                edits.Add(new ElfLayoutByteEdit(
                    new FileOffset(ElfHeaderOffsets.ProgramHeaderCount),
                    newProgramHeaderCount,
                    ElfLayoutEditKind.ElfHeader));
                AddPaddingEdits(
                    edits,
                    checked(segmentFileStart + tableOutputSize),
                    codeFileStart,
                    options,
                    diagnostics);
            }
            else
            {
                var headerOffset = checked(sourceFile.Header.ProgramHeaderOffset
                    + checked((ulong)changedHeaderIndex * sourceFile.Header.ProgramHeaderEntrySize));
                edits.Add(new ElfLayoutByteEdit(
                    new FileOffset(headerOffset),
                    SerializeProgramHeader(plannedHeaders[changedHeaderIndex]),
                    ElfLayoutEditKind.ProgramHeader));
            }

            if (diagnostics.HasErrors)
            {
                rejected = diagnostics.ToArray();
                return false;
            }

            if (edits.Count > options.MaximumEditCount)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "The layout edit count exceeds the configured bound.");
                rejected = diagnostics.ToArray();
                return false;
            }

            var outputLength = Math.Max(sourceLength, cursorFile);
            if (outputLength > options.MaximumOutputBytes || outputLength > int.MaxValue)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "The planned Native Image exceeds the configured output bound.");
                rejected = diagnostics.ToArray();
                return false;
            }

            var newTable = new ElfLayoutRange(
                new FileOffset(tableFileStart),
                new VirtualAddress(tableVirtualAddress),
                tableOutputSize,
                tableHasVirtualAddress);
            var plan = new ElfLayoutPlan(
                sourceSha256,
                strategy,
                oldTable,
                newTable,
                sourceHeaders.Length,
                plannedHeaders.Count,
                outputLength,
                ComputePreservedMetadataFingerprint(plannedHeaders),
                programHeaderPlans,
                placements.OrderBy(placement => placement.Identity, StringComparer.Ordinal).ToArray(),
                addressMap.OrderBy(entry => entry.Identity, StringComparer.Ordinal).ToArray(),
                branchDecisions.OrderBy(decision => decision.Identity, StringComparer.Ordinal).ToArray(),
                edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind).ToArray());

            if (!ValidateCandidate(
                    sourceFile,
                    sourceLength,
                    options,
                    plan,
                    plannedHeaders,
                    segmentFileStart,
                    segmentVirtualStart,
                    plannedSegment,
                    diagnostics))
            {
                rejected = diagnostics.ToArray();
                return false;
            }

            var score = new CandidateScore(
                isRelocation ? 1 : 0,
                isRelocation ? 1 : 0,
                plan.ProgramHeaders.Count(header => header.EditKind != ElfProgramHeaderEditKind.Unchanged),
                paddingBytes,
                strategy switch
                {
                    ElfLayoutStrategy.ExistingExecutableLoadExtension => 0,
                    ElfLayoutStrategy.AvailableProgramHeaderSlot => 1,
                    _ => 2,
                });
            candidate = new LayoutCandidate(plan, score);
            return true;
        }
        catch (OverflowException)
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "ELF layout arithmetic overflowed before materialization.");
            rejected = diagnostics.ToArray();
            return false;
        }
        catch (ArgumentException exception)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, exception.Message);
            rejected = diagnostics.ToArray();
            return false;
        }
    }

    private static bool ValidateCandidate(
        ElfFile sourceFile,
        ulong sourceLength,
        ElfLayoutOptions options,
        ElfLayoutPlan plan,
        IReadOnlyList<ProgramHeader> plannedHeaders,
        ulong segmentFileStart,
        ulong segmentVirtualStart,
        ProgramHeader plannedSegment,
        DiagnosticBag diagnostics)
    {
        if (plan.NewProgramHeaderCount != plannedHeaders.Count
            || plan.NewProgramHeaderTable.Size != checked((ulong)plannedHeaders.Count * sourceFile.Header.ProgramHeaderEntrySize)
            || plan.OutputLength > options.MaximumOutputBytes)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The planned ELF table metadata is inconsistent.");
            return false;
        }

        foreach (var header in plannedHeaders)
        {
            if (!TryAdd(header.Offset, header.FileSize, out var fileEnd)
                || !TryAdd(header.VirtualAddress, header.MemorySize, out _)
                || fileEnd > plan.OutputLength)
            {
                diagnostics.Error(DiagnosticCode.InvalidProgramHeader, "A planned program-header range is not representable within the output.", header.Offset);
                return false;
            }
        }

        var loadHeaders = plannedHeaders
            .Where(header => header.Type == ElfConstants.PtLoad)
            .ToArray();
        var sortedVirtual = loadHeaders.OrderBy(header => header.VirtualAddress).ToArray();
        for (var index = 0; index < sortedVirtual.Length; index++)
        {
            var header = sortedVirtual[index];
            if (header.FileSize > header.MemorySize
                || !IsValidAlignment(header.Alignment, options.MaximumAlignment)
                || (header.Alignment > 1 && header.Offset % header.Alignment != header.VirtualAddress % header.Alignment)
                || !TryAdd(header.Offset, header.FileSize, out var fileEnd)
                || !TryAdd(header.VirtualAddress, header.MemorySize, out var virtualEnd)
                || fileEnd > plan.OutputLength)
            {
                diagnostics.Error(DiagnosticCode.InvalidSegment, "A planned PT_LOAD violates bounded range or alignment invariants.", header.Offset);
                return false;
            }

            if (index > 0)
            {
                var previous = sortedVirtual[index - 1];
                if (!TryAdd(previous.VirtualAddress, previous.MemorySize, out var previousEnd)
                    || previousEnd > header.VirtualAddress)
                {
                    diagnostics.Error(DiagnosticCode.InvalidSegment, "Planned PT_LOAD virtual ranges overlap or are out of order.", header.VirtualAddress);
                    return false;
                }
            }

            _ = virtualEnd;
        }

        var sortedFile = loadHeaders.OrderBy(header => header.Offset).ToArray();
        for (var index = 1; index < sortedFile.Length; index++)
        {
            var previous = sortedFile[index - 1];
            var current = sortedFile[index];
            if (!TryAdd(previous.Offset, previous.FileSize, out var previousEnd)
                || previousEnd > current.Offset)
            {
                diagnostics.Error(DiagnosticCode.InvalidSegment, "Planned PT_LOAD file ranges overlap.", current.Offset);
                return false;
            }
        }

        for (var index = 0; index < sortedFile.Length; index++)
        {
            if (sortedFile[index] != sortedVirtual[index])
            {
                diagnostics.Error(DiagnosticCode.InvalidSegment, "Planned PT_LOAD file and virtual ordering diverges.");
                return false;
            }
        }

        if (plannedSegment.Type != ElfConstants.PtLoad
            || plannedSegment.Flags != GeneratedSegmentPermissions
            || !IsValidAlignment(plannedSegment.Alignment, options.MaximumAlignment)
            || (plannedSegment.Alignment > 1
                && plannedSegment.Offset % plannedSegment.Alignment != plannedSegment.VirtualAddress % plannedSegment.Alignment)
            || (plannedSegment.Offset != segmentFileStart && plan.Strategy != ElfLayoutStrategy.ExistingExecutableLoadExtension
                || plannedSegment.VirtualAddress != segmentVirtualStart && plan.Strategy != ElfLayoutStrategy.ExistingExecutableLoadExtension))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The planned generated segment is not at the selected placement.");
            return false;
        }

        var ownedFileStart = plannedSegment.Offset;
        var ownedVirtualStart = plannedSegment.VirtualAddress;
        var ownedFileSize = plannedSegment.FileSize;
        var ownedVirtualSize = plannedSegment.MemorySize;
        if (plan.Strategy == ElfLayoutStrategy.ExistingExecutableLoadExtension)
        {
            var sourceExtension = plan.ProgramHeaders
                .First(header => header.EditKind == ElfProgramHeaderEditKind.ExtendedExecutableLoad
                    && header.OriginalHeader is ProgramHeader original
                    && original.Type == ElfConstants.PtLoad
                    && original.IsExecutable);
            var originalExtension = sourceExtension.OriginalHeader!.Value;
            if (!TryAdd(originalExtension.Offset, originalExtension.FileSize, out ownedFileStart)
                || !TryAdd(originalExtension.VirtualAddress, originalExtension.FileSize, out ownedVirtualStart)
                || plannedSegment.FileSize < originalExtension.FileSize
                || plannedSegment.MemorySize < originalExtension.MemorySize)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The executable extension ownership range is not representable.");
                return false;
            }

            ownedFileSize = plannedSegment.FileSize - originalExtension.FileSize;
            ownedVirtualSize = plannedSegment.MemorySize - originalExtension.MemorySize;
        }

        foreach (var placement in plan.Placements)
        {
            if (placement.Size == 0
                || placement.Permissions != plannedSegment.Flags
                || !IsValidAlignment(placement.Alignment, options.MaximumAlignment)
                || !TryAdd(placement.FileOffset.Value, placement.Size, out var placementFileEnd)
                || !TryAdd(placement.VirtualAddress.Value, placement.Size, out var placementVirtualEnd)
                || placementFileEnd > plan.OutputLength
                || placement.FileOffset.Value < plannedSegment.Offset
                || placementFileEnd > checked(plannedSegment.Offset + plannedSegment.FileSize)
                || placement.VirtualAddress.Value < plannedSegment.VirtualAddress
                || placementVirtualEnd > checked(plannedSegment.VirtualAddress + plannedSegment.MemorySize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, $"Placement '{placement.Identity}' is outside the generated executable segment.");
                return false;
            }
        }

        foreach (var metadata in plannedHeaders.Where(header => header.Type is not (ElfConstants.PtNull or ElfConstants.PtLoad)))
        {
            if (plan.Strategy == ElfLayoutStrategy.RelocatedProgramHeaderTable
                && metadata.Type == ElfConstants.PtPhdr)
            {
                continue;
            }

            if (metadata.FileSize > 0
                && RangesOverlap(ownedFileStart, ownedFileSize, metadata.Offset, metadata.FileSize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "Generated layout bytes overlap preserved program-header metadata.", metadata.Offset);
                return false;
            }

            if (metadata.MemorySize > 0
                && RangesOverlap(ownedVirtualStart, ownedVirtualSize, metadata.VirtualAddress, metadata.MemorySize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "Generated layout addresses overlap preserved program-header metadata.", metadata.VirtualAddress);
                return false;
            }
        }

        for (var index = 0; index < sourceFile.ProgramHeaders.Count; index++)
        {
            var original = sourceFile.ProgramHeaders[index];
            var planned = plannedHeaders[index];
            var allowedChange = plan.Strategy switch
            {
                ElfLayoutStrategy.ExistingExecutableLoadExtension => index == plan.ProgramHeaders[index].SourceIndex
                    && original.Type == ElfConstants.PtLoad
                    && original.IsExecutable,
                ElfLayoutStrategy.AvailableProgramHeaderSlot => index == plan.ProgramHeaders[index].SourceIndex
                    && original.Type == ElfConstants.PtNull,
                ElfLayoutStrategy.RelocatedProgramHeaderTable => original.Type == ElfConstants.PtPhdr,
                _ => false,
            };
            if (!allowedChange && original != planned)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Program header {index} changed outside the selected layout ownership boundary.",
                    sourceFile.Header.ProgramHeaderOffset);
                return false;
            }
        }

        if (plan.Strategy == ElfLayoutStrategy.RelocatedProgramHeaderTable)
        {
            var tableFileEnd = checked(plan.NewProgramHeaderTable.FileOffset.Value + plan.NewProgramHeaderTable.Size);
            var tableVirtualEnd = checked(plan.NewProgramHeaderTable.VirtualAddress.Value + plan.NewProgramHeaderTable.Size);
            var owningLoad = plannedHeaders.FirstOrDefault(header =>
                header.Type == ElfConstants.PtLoad
                && plan.NewProgramHeaderTable.FileOffset.Value >= header.Offset
                && tableFileEnd <= header.Offset + header.FileSize
                && plan.NewProgramHeaderTable.VirtualAddress.Value >= header.VirtualAddress
                && tableVirtualEnd <= header.VirtualAddress + header.MemorySize);
            if (owningLoad.Type != ElfConstants.PtLoad)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The relocated program-header table is not mapped by a planned PT_LOAD.");
                return false;
            }
        }

        var phdr = plannedHeaders.FirstOrDefault(header => header.Type == ElfConstants.PtPhdr);
        if (phdr.Type == ElfConstants.PtPhdr)
        {
            if (!TryAdd(phdr.Offset, phdr.FileSize, out var phdrFileEnd)
                || !TryAdd(phdr.VirtualAddress, phdr.MemorySize, out var phdrVirtualEnd)
                || !plannedHeaders.Any(header =>
                    header.Type == ElfConstants.PtLoad
                    && phdr.Offset >= header.Offset
                    && phdrFileEnd <= header.Offset + header.FileSize
                    && phdr.VirtualAddress >= header.VirtualAddress
                    && phdrVirtualEnd <= header.VirtualAddress + header.MemorySize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "PT_PHDR is not mapped by a planned PT_LOAD.");
                return false;
            }
        }

        if (sourceFile.Header.SectionHeaderOffset != 0
            && sourceFile.Header.SectionHeaderOffset > plan.OutputLength)
        {
            diagnostics.Error(DiagnosticCode.TableOutOfBounds, "The planned output would not retain the section-header table.");
            return false;
        }

        return ValidateEdits(plan, sourceLength, diagnostics);
    }

    private static bool ValidateEdits(ElfLayoutPlan plan, ulong sourceLength, DiagnosticBag diagnostics)
    {
        ulong previousEnd = 0;
        var first = true;
        foreach (var edit in plan.Edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind))
        {
            if (edit.Bytes is null || edit.Bytes.Length == 0)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A layout byte edit is empty.");
                return false;
            }

            if (!TryAdd(edit.Offset.Value, checked((ulong)edit.Bytes.Length), out var end)
                || end > plan.OutputLength)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A layout byte edit exceeds the planned output range.", edit.Offset.Value);
                return false;
            }

            if (!first && edit.Offset.Value < previousEnd)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutEditOverlap, "Layout byte edits overlap.", edit.Offset.Value);
                return false;
            }

            if (edit.Offset.Value < sourceLength && end > sourceLength && edit.Kind != ElfLayoutEditKind.Padding)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A non-padding source edit crosses the source/output boundary.", edit.Offset.Value);
                return false;
            }

            first = false;
            previousEnd = end;
        }

        return true;
    }

    private static void ValidateOptions(ElfLayoutOptions options, DiagnosticBag diagnostics)
    {
        if (options.MaximumOutputBytes == 0
            || options.MaximumOutputBytes > ElfLayoutLimits.DefaultMaximumOutputBytes
            || options.MaximumProgramHeaderCount <= 0
            || options.MaximumProgramHeaderCount > ElfLayoutLimits.DefaultMaximumProgramHeaderCount
            || options.MaximumGeneratedCodeBytes <= 0
            || options.MaximumGeneratedCodeBytes > ElfLayoutLimits.DefaultMaximumGeneratedCodeBytes
            || options.MaximumVeneerCount < 0
            || options.MaximumVeneerCount > ElfLayoutLimits.DefaultMaximumVeneerCount
            || options.MaximumEditCount <= 0
            || options.MaximumEditCount > ElfLayoutLimits.DefaultMaximumEditCount
            || options.MaximumPaddingBytes > options.MaximumOutputBytes
            || options.SegmentAlignment == 0
            || options.CodeAlignment == 0
            || !IsPowerOfTwo(options.SegmentAlignment)
            || !IsPowerOfTwo(options.CodeAlignment)
            || !IsPowerOfTwo(options.MaximumAlignment)
            || options.SegmentAlignment > options.MaximumAlignment
            || options.CodeAlignment > options.MaximumAlignment
            || (options.RequestedStrategy is { } requested && !Enum.IsDefined(requested)))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "ELF layout options are outside their bounded power-of-two limits.");
        }
    }

    private static void ValidateSource(
        ElfFile sourceFile,
        ulong sourceLength,
        ElfLayoutOptions options,
        DiagnosticBag diagnostics)
    {
        diagnostics.AddRange(ElfValidator.Validate(sourceFile).Diagnostics);
        if (!sourceFile.Header.IsAarch64
            || sourceFile.Header.Type is not (ElfConstants.TypeDyn or ElfConstants.TypeExec)
            || sourceFile.Header.ProgramHeaderEntrySize != ElfConstants.ProgramHeaderSize64
            || sourceFile.Header.ProgramHeaderCount == 0
            || sourceFile.Header.ProgramHeaderCount != sourceFile.ProgramHeaders.Count
            || sourceFile.Header.ProgramHeaderCount > options.MaximumProgramHeaderCount
            || sourceFile.Header.ProgramHeaderCount == ElfConstants.PnXnum)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutUnsupported, "The source ELF is outside the bounded layout planner identity or table contract.");
        }

        if (!TryGetProgramHeaderTableRange(sourceFile, sourceLength, out _, out _))
        {
            diagnostics.Error(DiagnosticCode.TableOutOfBounds, "The source program-header table is outside the source snapshot.");
        }

        foreach (var header in sourceFile.ProgramHeaders)
        {
            if (!TryAdd(header.Offset, header.FileSize, out var fileEnd) || fileEnd > sourceLength)
            {
                diagnostics.Error(DiagnosticCode.TableOutOfBounds, "A source program-header file range is outside the source snapshot.", header.Offset);
            }

            if (!TryAdd(header.VirtualAddress, header.MemorySize, out _))
            {
                diagnostics.Error(DiagnosticCode.AddressOverflow, "A source program-header virtual range overflowed.", header.VirtualAddress);
            }
        }

        ValidateSectionHeaderTable(sourceFile, sourceLength, diagnostics);
    }

    private static void ValidateSectionHeaderTable(
        ElfFile sourceFile,
        ulong sourceLength,
        DiagnosticBag diagnostics)
    {
        var header = sourceFile.Header;
        if (header.SectionHeaderOffset == 0 && header.SectionHeaderCount == 0)
        {
            return;
        }

        ulong tableSize = 0;
        ulong tableEnd = 0;
        var valid = header.SectionHeaderOffset != 0
            && header.SectionHeaderCount != 0
            && header.SectionHeaderEntrySize >= ElfConstants.SectionHeaderSize64
            && TryMultiply(header.SectionHeaderEntrySize, header.SectionHeaderCount, out tableSize)
            && TryAdd(header.SectionHeaderOffset, tableSize, out tableEnd)
            && tableEnd <= sourceLength
            && sourceFile.SectionHeaders.Count == header.SectionHeaderCount;
        if (valid
            && (RangesOverlap(header.SectionHeaderOffset, tableSize, 0, ElfConstants.HeaderSize64)
                || (TryGetProgramHeaderTableRange(sourceFile, sourceLength, out var programTable, out _)
                    && RangesOverlap(header.SectionHeaderOffset, tableSize, programTable.FileOffset.Value, programTable.Size))))
        {
            valid = false;
        }

        if (!valid)
        {
            diagnostics.Error(DiagnosticCode.TableOutOfBounds, "The source section-header table is not fully represented by the layout snapshot.", header.SectionHeaderOffset);
        }
    }

    private static void ValidateRequests(
        ElfFile sourceFile,
        ulong sourceLength,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutBranchRequest> branches,
        ElfLayoutOptions options,
        DiagnosticBag diagnostics)
    {
        if (regions.Count == 0
            || regions.Count > options.MaximumEditCount
            || branches.Count > options.MaximumEditCount - regions.Count)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutOutputLimitExceeded, "The layout request count is outside its configured bound.");
            return;
        }

        var identities = new HashSet<string>(StringComparer.Ordinal);
        var sourceRanges = new List<(ulong Offset, ulong Size, string Identity)>(regions.Count);
        foreach (var region in regions)
        {
            if (!IsValidIdentity(region.Identity)
                || !IsValidIdentity(region.SourceIdentity)
                || !identities.Add(region.Identity)
                || region.SourceSize < sizeof(uint)
                || (region.SourceSize & 3) != 0
                || (region.SourceAddress.Value & 3) != 0
                || region.CodeBytes.Length == 0
                || region.CodeBytes.Length > options.MaximumGeneratedCodeBytes
                || (region.CodeBytes.Length & 3) != 0
                || !IsPowerOfTwo(region.Alignment)
                || region.Alignment > options.MaximumAlignment
                || region.Permissions != GeneratedSegmentPermissions
                || !TryAdd(region.SourceAddress.Value, region.SourceSize, out _)
                || sourceFile.LoadMap.Segments.Count(segment =>
                    segment.IsExecutable && segment.ContainsVirtualAddress(region.SourceAddress.Value, region.SourceSize)) != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout region '{region.Identity}' is outside the bounded executable source contract.",
                    region.SourceAddress.Value);
                continue;
            }

            if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(region.SourceAddress, region.SourceSize, out var fileOffset)
                || fileOffset.Value > sourceLength
                || region.SourceSize > sourceLength - fileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.AddressUnmapped,
                    $"Layout region '{region.Identity}' is not file-backed by its executable PT_LOAD.",
                    region.SourceAddress.Value);
            }
            else if (IntersectsProtectedSourceMetadata(sourceFile, fileOffset.Value, region.SourceSize))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout region '{region.Identity}' overlaps an ELF header or preserved program-header metadata.",
                    fileOffset.Value);
            }
            else if (sourceRanges.Any(existing => RangesOverlap(existing.Offset, existing.Size, fileOffset.Value, region.SourceSize)))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout region '{region.Identity}' overlaps another transformed source range.",
                    fileOffset.Value);
            }
            else
            {
                sourceRanges.Add((fileOffset.Value, region.SourceSize, region.Identity));
            }
        }

        var branchIdentities = new HashSet<string>(StringComparer.Ordinal);
        var sourceSites = new HashSet<(string Identity, uint Offset)>();
        foreach (var branch in branches)
        {
            var sourceRegion = regions.FirstOrDefault(region => string.Equals(region.Identity, branch.SourceIdentity, StringComparison.Ordinal));
            var targetRegion = regions.FirstOrDefault(region => string.Equals(region.Identity, branch.TargetIdentity, StringComparison.Ordinal));
            if (!IsValidIdentity(branch.Identity)
                || !branchIdentities.Add(branch.Identity)
                || sourceRegion is null
                || targetRegion is null
                || branch.SourceAddress != sourceRegion.SourceAddress
                || !sourceSites.Add((branch.SourceIdentity, branch.SourceOffset))
                || branch.Encoding != ElfLayoutBranchEncodingKind.Branch26
                || (branch.SourceAddress.Value & 3) != 0
                || (branch.SourceOffset & 3) != 0
                || branch.SourceOffset > sourceRegion.SourceSize
                || sourceRegion.SourceSize - branch.SourceOffset < sizeof(uint)
                || (branch.TargetOffset & 3) != 0
                || branch.TargetOffset > (uint)targetRegion.CodeBytes.Length
                || targetRegion.CodeBytes.Length - branch.TargetOffset < sizeof(uint)
                || !IsBranchOpcode(branch.Opcode))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' is outside the bounded Branch26 contract.",
                    branch.SourceAddress.Value);
                continue;
            }

            if (branch.NearVeneer is not null
                && (!IsValidIdentity(branch.NearVeneer.Identity)
                    || !IsValidIdentity(branch.NearVeneer.TargetIdentity)
                    || !IsPowerOfTwo(branch.NearVeneer.Alignment)
                    || branch.NearVeneer.Alignment > options.MaximumAlignment
                    || branch.NearVeneer.CodeBytes.Length == 0
                    || (branch.NearVeneer.CodeBytes.Length & 3) != 0
                    || branch.NearVeneer.Permissions != GeneratedSegmentPermissions))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' has an invalid veneer request.",
                    branch.SourceAddress.Value);
            }

            if (branch.LongBranch is not null
                && (!IsValidIdentity(branch.LongBranch.Identity)
                    || !IsPowerOfTwo(branch.LongBranch.Alignment)
                    || branch.LongBranch.Alignment > options.MaximumAlignment
                    || branch.LongBranch.CodeBytes.Length == 0
                    || (branch.LongBranch.CodeBytes.Length & 3) != 0
                    || branch.LongBranch.Permissions != GeneratedSegmentPermissions
                    || branch.LongBranch.SourceReplacementBytes is null))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' has an invalid long-address request.",
                    branch.SourceAddress.Value);
            }
            else if (branch.LongBranch?.SourceReplacementBytes is { } replacement
                && (replacement.Length < sizeof(uint)
                    || (replacement.Length & 3) != 0
                    || (ulong)replacement.Length > sourceRegion!.SourceSize - branch.SourceOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' has a long-address source replacement outside its source region.",
                    branch.SourceAddress.Value);
            }
        }
    }

    private static bool TryGetAlignedPlacement(
        ElfFile sourceFile,
        ulong sourceLength,
        ElfLayoutOptions options,
        out ulong fileOffset,
        out ulong virtualAddress,
        DiagnosticBag diagnostics)
    {
        fileOffset = 0;
        virtualAddress = 0;
        if (!TryAlignUp(sourceLength, options.SegmentAlignment, out fileOffset))
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "The generated file placement alignment overflowed.");
            return false;
        }

        ulong highestVirtualEnd = 0;
        foreach (var header in sourceFile.ProgramHeaders.Where(header => header.Type == ElfConstants.PtLoad))
        {
            if (!TryAdd(header.VirtualAddress, header.MemorySize, out var end))
            {
                diagnostics.Error(DiagnosticCode.AddressOverflow, "An existing PT_LOAD virtual range overflowed.", header.VirtualAddress);
                return false;
            }

            highestVirtualEnd = Math.Max(highestVirtualEnd, end);
        }

        if (!TryAlignUp(highestVirtualEnd, options.SegmentAlignment, out virtualAddress))
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "The generated virtual placement alignment overflowed.");
            return false;
        }

        if (fileOffset % options.SegmentAlignment != virtualAddress % options.SegmentAlignment)
        {
            diagnostics.Error(DiagnosticCode.InvalidAlignment, "The generated file and virtual placements are not congruent.");
            return false;
        }

        return true;
    }

    private static bool TryFindExtensionHeader(
        ElfFile sourceFile,
        ulong sourceLength,
        out int index,
        out ProgramHeader header)
    {
        index = -1;
        header = default;
        var candidates = sourceFile.ProgramHeaders
            .Select((value, position) => (value, position))
            .Where(item => item.value.Type == ElfConstants.PtLoad
                && item.value.Flags == GeneratedSegmentPermissions
                && item.value.FileSize == item.value.MemorySize
                && TryAdd(item.value.Offset, item.value.FileSize, out var end)
                && end == sourceLength)
            .OrderByDescending(item => checked(item.value.VirtualAddress + item.value.MemorySize))
            .ThenBy(item => item.position)
            .ToArray();
        if (candidates.Length == 0)
        {
            return false;
        }

        index = candidates[0].position;
        header = candidates[0].value;
        return true;
    }

    private static bool TryFindNullHeader(IReadOnlyList<ProgramHeader> headers, out int index)
    {
        index = -1;
        for (var position = 0; position < headers.Count; position++)
        {
            if (headers[position].Type == ElfConstants.PtNull)
            {
                index = position;
                return true;
            }
        }

        return false;
    }

    private static ElfLayoutRange? GetSourceRange(ElfFile sourceFile, VirtualAddress address, ulong size)
    {
        if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(address, size, out var fileOffset))
        {
            return null;
        }

        return new ElfLayoutRange(fileOffset, address, size);
    }

    private static bool TryAlignPlacementCursor(
        ref ulong fileCursor,
        ref ulong virtualCursor,
        ulong alignment,
        ulong fileBase,
        ulong virtualBase,
        DiagnosticBag diagnostics)
    {
        if (!IsPowerOfTwo(alignment)
            || !TryAlignUp(fileCursor, alignment, out var alignedFile)
            || !TryAlignUp(virtualCursor, alignment, out var alignedVirtual))
        {
            diagnostics.Error(DiagnosticCode.InvalidAlignment, "A generated placement alignment is invalid.");
            return false;
        }

        if ((alignedFile - fileBase) != (alignedVirtual - virtualBase))
        {
            diagnostics.Error(DiagnosticCode.InvalidAlignment, "Generated file and virtual placement cursors diverged.");
            return false;
        }

        fileCursor = alignedFile;
        virtualCursor = alignedVirtual;
        return true;
    }

    private static void AddPaddingEdits(
        List<ElfLayoutByteEdit> edits,
        ulong start,
        ulong end,
        ElfLayoutOptions options,
        DiagnosticBag diagnostics)
    {
        if (end < start)
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "Layout padding range underflowed.");
            return;
        }

        var size = end - start;
        if (size == 0)
        {
            return;
        }

        if (size > options.MaximumPaddingBytes || size > int.MaxValue)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutOutputLimitExceeded, "Layout padding exceeds its bounded materialization size.");
            return;
        }

        edits.Add(new ElfLayoutByteEdit(new FileOffset(start), new byte[checked((int)size)], ElfLayoutEditKind.Padding));
    }

    private static T[] ReadBounded<T>(IEnumerable<T> values, int maximum, out bool exceeded)
    {
        exceeded = false;
        var boundedMaximum = Math.Max(maximum, 1);
        var result = new List<T>(Math.Min(boundedMaximum, 1024));
        foreach (var value in values)
        {
            if (result.Count >= boundedMaximum)
            {
                exceeded = true;
                break;
            }

            result.Add(value);
        }

        return result.ToArray();
    }

    private static bool IntersectsProtectedSourceMetadata(ElfFile file, ulong offset, ulong size)
    {
        if (RangesOverlap(offset, size, 0, ElfConstants.HeaderSize64))
        {
            return true;
        }

        if (TryGetProgramHeaderTableRange(file, (ulong)file.Bytes.Length, out var table, out _)
            && RangesOverlap(offset, size, table.FileOffset.Value, table.Size))
        {
            return true;
        }

        return file.ProgramHeaders.Any(header =>
            header.Type != ElfConstants.PtLoad
            && header.FileSize > 0
            && RangesOverlap(offset, size, header.Offset, header.FileSize));
    }

    private static bool TryGetProgramHeaderTableRange(
        ElfFile file,
        ulong sourceLength,
        out ElfLayoutRange range,
        out ulong size)
    {
        range = default;
        size = 0;
        if (file.Header.ProgramHeaderOffset < ElfConstants.HeaderSize64
            || file.Header.ProgramHeaderEntrySize == 0
            || file.Header.ProgramHeaderCount == 0
            || !TryMultiply(
                file.Header.ProgramHeaderEntrySize,
                file.Header.ProgramHeaderCount,
                out size)
            || !TryAdd(file.Header.ProgramHeaderOffset, size, out var end)
            || end > sourceLength)
        {
            return false;
        }

        var hasVirtualAddress = file.LoadMap.TryFileOffsetToVirtualAddress(
            new FileOffset(file.Header.ProgramHeaderOffset),
            size,
            out var virtualAddress);
        range = new ElfLayoutRange(
            new FileOffset(file.Header.ProgramHeaderOffset),
            virtualAddress,
            size,
            hasVirtualAddress);
        return true;
    }

    private static byte[] SerializeProgramHeaders(IReadOnlyList<ProgramHeader> headers)
    {
        var bytes = new byte[checked(headers.Count * ElfConstants.ProgramHeaderSize64)];
        for (var index = 0; index < headers.Count; index++)
        {
            SerializeProgramHeader(headers[index]).CopyTo(bytes, checked(index * ElfConstants.ProgramHeaderSize64));
        }

        return bytes;
    }

    private static byte[] SerializeProgramHeader(ProgramHeader header)
    {
        var bytes = new byte[ElfConstants.ProgramHeaderSize64];
        var span = bytes.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span[ElfProgramHeaderOffsets.Type..], header.Type);
        BinaryPrimitives.WriteUInt32LittleEndian(span[ElfProgramHeaderOffsets.Flags..], header.Flags);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.FileOffset..], header.Offset);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.VirtualAddress..], header.VirtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.PhysicalAddress..], header.PhysicalAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.FileSize..], header.FileSize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.MemorySize..], header.MemorySize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.Alignment..], header.Alignment);
        return bytes;
    }

    private static ElfLayoutEvidence CreateEvidence(ElfLayoutPlan plan) =>
        new(
            ElfLayoutEvidence.CurrentSchemaVersion,
            plan.Strategy,
            plan.SourceSha256,
            string.Empty,
            plan.OutputLength,
            plan.OldProgramHeaderTable,
            plan.NewProgramHeaderTable,
            plan.PreservedMetadataSha256,
            plan.Placements,
            plan.AddressMap,
            plan.BranchDecisions);

    private static string ComputePreservedMetadataFingerprint(IReadOnlyList<ProgramHeader> headers)
    {
        using var stream = new MemoryStream();
        foreach (var header in headers)
        {
            stream.Write(SerializeProgramHeader(header));
        }

        return Sha256(stream.ToArray());
    }

    private static bool EquivalentVeneerRequest(ElfLayoutVeneerRequest first, ElfLayoutVeneerRequest second) =>
        string.Equals(first.TargetIdentity, second.TargetIdentity, StringComparison.Ordinal)
        && first.MaximumBranchDistance == second.MaximumBranchDistance
        && first.Permissions == second.Permissions
        && first.Alignment == second.Alignment
        && first.CodeBytes.AsSpan().SequenceEqual(second.CodeBytes);

    private static bool EquivalentLongBranchRequest(ElfLayoutLongBranchRequest first, ElfLayoutLongBranchRequest second) =>
        first.Permissions == second.Permissions
        && first.Alignment == second.Alignment
        && first.CodeBytes.AsSpan().SequenceEqual(second.CodeBytes)
        && ((first.SourceReplacementBytes is null && second.SourceReplacementBytes is null)
            || (first.SourceReplacementBytes is not null
                && second.SourceReplacementBytes is not null
                && first.SourceReplacementBytes.AsSpan().SequenceEqual(second.SourceReplacementBytes)));

    private static bool IsValidIdentity(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= ElfLayoutLimits.MaximumIdentityBytes
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '/' or ':');

    private static bool IsBranchOpcode(uint opcode) =>
        (opcode & 0xFC000000u) is 0x14000000u or 0x94000000u;

    private static bool TryEncodeBranch26(
        uint opcode,
        ulong source,
        ulong target,
        out byte[] encoding,
        out long? displacement)
    {
        encoding = Array.Empty<byte>();
        displacement = null;
        if (!IsBranchOpcode(opcode)
            || (source & 3) != 0
            || (target & 3) != 0
            || !TryGetDisplacement(source, target, out var delta)
            || delta < ElfLayoutLimits.Branch26MinimumDisplacement
            || delta >= ElfLayoutLimits.Branch26MaximumDisplacementExclusive)
        {
            return false;
        }

        var value = (opcode & 0xFC000000u) | (uint)((delta >> 2) & 0x03FFFFFF);
        encoding = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(encoding, value);
        displacement = delta;
        return true;
    }

    private static bool TryGetDisplacement(ulong source, ulong target, out long displacement)
    {
        if (target >= source)
        {
            var delta = target - source;
            if (delta > long.MaxValue)
            {
                displacement = 0;
                return false;
            }

            displacement = (long)delta;
            return true;
        }

        var reverse = source - target;
        if (reverse > (ulong)long.MaxValue + 1)
        {
            displacement = 0;
            return false;
        }

        displacement = reverse == (ulong)long.MaxValue + 1
            ? long.MinValue
            : -(long)reverse;
        return true;
    }

    private static bool TryAlignUp(ulong value, ulong alignment, out ulong result)
    {
        result = 0;
        if (alignment == 0)
        {
            return false;
        }

        var remainder = value % alignment;
        if (remainder == 0)
        {
            result = value;
            return true;
        }

        var delta = alignment - remainder;
        if (value > ulong.MaxValue - delta)
        {
            return false;
        }

        result = value + delta;
        return true;
    }

    private static bool TryMultiply(ulong left, ulong right, out ulong result)
    {
        if (left != 0 && right > ulong.MaxValue / left)
        {
            result = 0;
            return false;
        }

        result = left * right;
        return true;
    }

    private static bool TryAdd(ulong value, ulong amount, out ulong result)
    {
        if (amount > ulong.MaxValue - value)
        {
            result = 0;
            return false;
        }

        result = value + amount;
        return true;
    }

    private static bool RangesOverlap(ulong firstStart, ulong firstSize, ulong secondStart, ulong secondSize)
    {
        return TryAdd(firstStart, firstSize, out var firstEnd)
            && TryAdd(secondStart, secondSize, out var secondEnd)
            && firstStart < secondEnd
            && secondStart < firstEnd;
    }

    private static bool IsPowerOfTwo(ulong value) => value != 0 && (value & (value - 1)) == 0;

    private static bool IsValidAlignment(ulong alignment, ulong maximum) =>
        alignment is 0 or 1 || alignment <= maximum && IsPowerOfTwo(alignment);

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record LayoutCandidate(ElfLayoutPlan Plan, CandidateScore Score);

    private readonly record struct CandidateScore(
        int TableRelocation,
        int ProgramHeaderCountDelta,
        int MetadataHeaderEdits,
        ulong PaddingBytes,
        int StrategyRank);
}

/// <summary>Materializes only a validated immutable layout plan and reparses the complete output.</summary>
public static class ElfLayoutMaterializer
{
    public static ElfLayoutResult Materialize(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        ElfLayoutPlan plan)
    {
        ArgumentNullException.ThrowIfNull(sourceFile);
        ArgumentNullException.ThrowIfNull(plan);

        var diagnostics = new DiagnosticBag();
        var sourceSha256 = Sha256(sourceBytes.Span);
        if (!string.Equals(sourceSha256, plan.SourceSha256, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutSourceMismatch, "The layout plan source digest does not match the materialization snapshot.");
            return Failure(plan, diagnostics);
        }

        if (sourceFile.Bytes.Length != sourceBytes.Length
            || !sourceFile.Bytes.Span.SequenceEqual(sourceBytes.Span)
            || plan.OutputLength > int.MaxValue
            || plan.OutputLength < (ulong)sourceBytes.Length)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The layout source or output length is outside the materializer bounds.");
            return Failure(plan, diagnostics);
        }

        if (!Enum.IsDefined(plan.Strategy)
            || plan.ProgramHeaders is null
            || plan.Placements is null
            || plan.AddressMap is null
            || plan.BranchDecisions is null
            || plan.Edits is null)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The layout plan collections or strategy are malformed.");
            return Failure(plan, diagnostics);
        }

        if (!ValidatePlanEdits(plan, (ulong)sourceBytes.Length, diagnostics))
        {
            return Failure(plan, diagnostics);
        }

        try
        {
            var output = new byte[checked((int)plan.OutputLength)];
            sourceBytes.Span.CopyTo(output);
            foreach (var edit in plan.Edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind))
            {
                edit.Bytes.AsSpan().CopyTo(output.AsSpan(checked((int)edit.Offset.Value), edit.Bytes.Length));
            }

            var parsed = ElfParser.Parse(output);
            diagnostics.AddRange(parsed.Diagnostics);
            if (parsed.File is null || parsed.Diagnostics.Any(diagnostic => diagnostic.IsError))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "Materialized ELF did not pass the bounded parser after layout edits.");
                return Failure(plan, diagnostics);
            }

            var validation = ElfValidator.Validate(parsed.File);
            if (!validation.IsValid)
            {
                diagnostics.AddRange(validation.Diagnostics);
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "Materialized ELF did not pass the bounded validator after layout edits.");
                return Failure(plan, diagnostics);
            }

            if (!ValidateParsedOutput(sourceFile, parsed.File, plan, output, diagnostics))
            {
                return Failure(plan, diagnostics);
            }

            var outputHash = Sha256(output);
            var evidence = new ElfLayoutEvidence(
                ElfLayoutEvidence.CurrentSchemaVersion,
                plan.Strategy,
                plan.SourceSha256,
                outputHash,
                plan.OutputLength,
                plan.OldProgramHeaderTable,
                plan.NewProgramHeaderTable,
                plan.PreservedMetadataSha256,
                plan.Placements,
                plan.AddressMap,
                plan.BranchDecisions);
            return new ElfLayoutResult(plan, output, parsed.File, evidence, diagnostics.ToArray());
        }
        catch (OverflowException)
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "ELF layout materialization arithmetic overflowed.");
            return Failure(plan, diagnostics);
        }
    }

    public static ElfLayoutResult Materialize(
        ElfFile sourceFile,
        ElfLayoutPlan plan) =>
        Materialize(sourceFile.Bytes, sourceFile, plan);

    public static ElfLayoutResult Materialize(
        ElfLayoutPlan plan,
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile) =>
        Materialize(sourceBytes, sourceFile, plan);

    private static ElfLayoutResult Failure(ElfLayoutPlan plan, DiagnosticBag diagnostics) =>
        new(plan, null, null, null, diagnostics.ToArray());

    private static bool ValidatePlanEdits(ElfLayoutPlan plan, ulong sourceLength, DiagnosticBag diagnostics)
    {
        ulong previousEnd = 0;
        var first = true;
        foreach (var edit in plan.Edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind))
        {
            if (edit.Bytes is null || edit.Bytes.Length == 0
                || !TryAdd(edit.Offset.Value, checked((ulong)edit.Bytes.Length), out var end)
                || end > plan.OutputLength
                || (!first && edit.Offset.Value < previousEnd))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutEditOverlap, "The layout plan contains an invalid or overlapping byte edit.", edit.Offset.Value);
                return false;
            }

            if (edit.Offset.Value < sourceLength && end > sourceLength && edit.Kind != ElfLayoutEditKind.Padding)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A planned source edit crosses the source/output boundary.", edit.Offset.Value);
                return false;
            }

            first = false;
            previousEnd = end;
        }

        return true;
    }

    private static bool ValidateParsedOutput(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        if (!outputFile.Header.IsAarch64
            || outputFile.Header.Type != sourceFile.Header.Type
            || outputFile.Header.ProgramHeaderOffset != plan.NewProgramHeaderTable.FileOffset.Value
            || outputFile.Header.ProgramHeaderCount != plan.NewProgramHeaderCount
            || outputFile.Header.ProgramHeaderEntrySize != sourceFile.Header.ProgramHeaderEntrySize
            || outputFile.Header.SectionHeaderOffset != sourceFile.Header.SectionHeaderOffset
            || outputFile.Header.SectionHeaderEntrySize != sourceFile.Header.SectionHeaderEntrySize
            || outputFile.Header.SectionHeaderCount != sourceFile.Header.SectionHeaderCount
            || outputFile.Header.SectionNameIndex != sourceFile.Header.SectionNameIndex
            || output.Length != checked((int)plan.OutputLength)
            || output.AsSpan().SequenceEqual(sourceFile.Bytes.Span))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "The reparsed ELF does not match the selected layout metadata.");
            return false;
        }

        if (outputFile.ProgramHeaders.Count != plan.ProgramHeaders.Count)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "The reparsed program-header count does not match the layout plan.");
            return false;
        }

        for (var index = 0; index < plan.ProgramHeaders.Count; index++)
        {
            if (outputFile.ProgramHeaders[index] != plan.ProgramHeaders[index].PlannedHeader)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Program header {index} differs from its planned serialization.");
                return false;
            }
        }

        if (!outputFile.SectionHeaders.SequenceEqual(sourceFile.SectionHeaders))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "The reparsed section-header table differs from the source table.");
            return false;
        }

        foreach (var placement in plan.Placements)
        {
            if (!outputFile.LoadMap.Segments.Any(segment =>
                    segment.ContainsFileOffset(placement.FileOffset.Value, placement.Size)
                    && segment.ContainsVirtualAddress(placement.VirtualAddress.Value, placement.Size)
                    && segment.IsExecutable))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Placement '{placement.Identity}' is not mapped by an executable output PT_LOAD.");
                return false;
            }
        }

        foreach (var decision in plan.BranchDecisions)
        {
            var sourceRange = decision.SourceRange;
            if (decision.Decision == ElfLayoutBranchDecision.LongAddress)
            {
                var replacements = plan.Edits
                    .Where(edit => edit.Kind == ElfLayoutEditKind.LongBranch && edit.Offset == sourceRange.FileOffset)
                    .ToArray();
                if (replacements.Length != 1
                    || sourceRange.FileOffset.Value > int.MaxValue
                    || !TryAdd(sourceRange.FileOffset.Value, checked((ulong)replacements[0].Bytes.Length), out var replacementEnd)
                    || replacementEnd > (ulong)output.Length
                    || !output.AsSpan(checked((int)sourceRange.FileOffset.Value), replacements[0].Bytes.Length)
                        .SequenceEqual(replacements[0].Bytes))
                {
                    diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Long branch decision '{decision.Identity}' does not match its typed source replacement.", sourceRange.FileOffset.Value);
                    return false;
                }

                continue;
            }

            if (decision.Decision is not (ElfLayoutBranchDecision.Direct or ElfLayoutBranchDecision.NearVeneer))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Branch decision '{decision.Identity}' uses an unsupported placement decision.", sourceRange.FileOffset.Value);
                return false;
            }

            if (!TryGetBranchEncoding(plan, decision, out var expected))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Branch decision '{decision.Identity}' has no materialized encoding.");
                return false;
            }

            var expectedBytes = expected;
            if (sourceRange.FileOffset.Value > int.MaxValue
                || sourceRange.Size != sizeof(uint)
                || !output.AsSpan(checked((int)sourceRange.FileOffset.Value), sizeof(uint)).SequenceEqual(expectedBytes))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Branch decision '{decision.Identity}' does not match its planned encoding.", sourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }

    private static bool TryGetBranchEncoding(
        ElfLayoutPlan plan,
        ElfBranchPlacementDecision decision,
        out byte[] expected)
    {
        expected = Array.Empty<byte>();
        if (decision.Displacement is not long displacement
            || decision.SourceRange.Size != sizeof(uint)
            || !ElfLayoutPlannerTryEncode(decision.Opcode, displacement, out expected))
        {
            return false;
        }

        var expectedBytes = expected;
        return plan.Edits.Any(edit =>
            edit.Kind == ElfLayoutEditKind.BranchFixup
            && edit.Offset == decision.SourceRange.FileOffset
            && edit.Bytes.AsSpan().SequenceEqual(expectedBytes));
    }

    private static bool ElfLayoutPlannerTryEncode(uint opcode, long displacement, out byte[] encoding)
    {
        encoding = Array.Empty<byte>();
        if ((opcode & 0xFC000000u) is not (0x14000000u or 0x94000000u)
            || displacement < ElfLayoutLimits.Branch26MinimumDisplacement
            || displacement >= ElfLayoutLimits.Branch26MaximumDisplacementExclusive
            || (displacement & 3) != 0)
        {
            return false;
        }

        encoding = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(encoding, (opcode & 0xFC000000u) | (uint)((displacement >> 2) & 0x03FFFFFF));
        return true;
    }

    private static bool TryAdd(ulong value, ulong amount, out ulong result)
    {
        if (amount > ulong.MaxValue - value)
        {
            result = 0;
            return false;
        }

        result = value + amount;
        return true;
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
