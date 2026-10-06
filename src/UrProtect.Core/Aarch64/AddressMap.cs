using System.Collections.ObjectModel;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

/// <summary>
/// Identifies one source entity and the range reserved for its planned output.
/// </summary>
/// <remarks>
/// The source and output ranges deliberately retain both file and virtual address
/// domains.  The semantic plan may be consumed before a physical ELF writer has
/// selected its final bytes, so callers must not replace either domain with an
/// unqualified integer.
/// </remarks>
public sealed record AddressMapEntry(
    SemanticEntityId Identity,
    SemanticSourceRange SourceRange,
    SemanticSourceRange OutputRange,
    SemanticEntityId? OutputIdentity = null)
{
    public SemanticEntityId SourceIdentity => Identity;

    public SemanticEntityId PlannedIdentity => OutputIdentity ?? Identity;

    public VirtualAddress SourceAddress => SourceRange.VirtualAddress;

    public FileOffset SourceFileOffset => SourceRange.FileOffset;

    public VirtualAddress OutputAddress => OutputRange.VirtualAddress;

    public FileOffset OutputFileOffset => OutputRange.FileOffset;
}

public sealed record AddressMapResult
{
    public AddressMapResult(AddressMap? Map, IEnumerable<Diagnostic> Diagnostics)
    {
        ArgumentNullException.ThrowIfNull(Diagnostics);
        this.Map = Map;
        this.Diagnostics = Array.AsReadOnly(Diagnostics.ToArray());
    }

    public AddressMap? Map { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsSuccess => Map is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Immutable old-to-new address mappings used by semantic fixups.
/// </summary>
public sealed class AddressMap
{
    private readonly IReadOnlyList<AddressMapEntry> entries;
    private readonly IReadOnlyDictionary<SemanticEntityId, AddressMapEntry> byIdentity;
    private readonly IReadOnlyDictionary<SemanticEntityId, AddressMapEntry> byOutputIdentity;

    public AddressMap(IEnumerable<AddressMapEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var result = Create(entries);
        if (!result.IsSuccess)
        {
            throw new ArgumentException(
                string.Join(Environment.NewLine, result.Diagnostics),
                nameof(entries));
        }

        this.entries = result.Map!.entries;
        byIdentity = result.Map.byIdentity;
        byOutputIdentity = result.Map.byOutputIdentity;
    }

    private AddressMap(
        IReadOnlyList<AddressMapEntry> entries,
        IReadOnlyDictionary<SemanticEntityId, AddressMapEntry> byIdentity,
        IReadOnlyDictionary<SemanticEntityId, AddressMapEntry> byOutputIdentity)
    {
        this.entries = entries;
        this.byIdentity = byIdentity;
        this.byOutputIdentity = byOutputIdentity;
    }

    public IReadOnlyList<AddressMapEntry> Entries => entries;

    public IReadOnlyList<AddressMapEntry> Functions => GetEntries(SemanticEntityKind.Function);

    public IReadOnlyList<AddressMapEntry> BasicBlocks => GetEntries(SemanticEntityKind.BasicBlock);

    public IReadOnlyList<AddressMapEntry> Literals => GetEntries(SemanticEntityKind.Literal);

    public IReadOnlyList<AddressMapEntry> Veneers => GetEntries(SemanticEntityKind.Veneer);

    public IReadOnlyList<AddressMapEntry> Tables => GetEntries(SemanticEntityKind.Table);

    public IReadOnlyList<AddressMapEntry> RelocationTargets =>
        GetEntries(SemanticEntityKind.RelocationTarget);

    public IReadOnlyList<AddressMapEntry> RelocationSites =>
        GetEntries(SemanticEntityKind.RelocationSite);

    public static AddressMapResult Create(IEnumerable<AddressMapEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var diagnostics = new DiagnosticBag();
        var materialized = entries.ToArray();
        var identities = new Dictionary<SemanticEntityId, AddressMapEntry>();
        var outputIdentities = new Dictionary<SemanticEntityId, AddressMapEntry>();
        var sourceRanges = new HashSet<AddressMapRangeKey>();
        var outputRanges = new HashSet<AddressMapRangeKey>();

        foreach (var entry in materialized)
        {
            if (entry is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMalformed,
                    "An address-map entry is null.");
                continue;
            }

            ValidateEntry(
                entry,
                identities,
                outputIdentities,
                sourceRanges,
                outputRanges,
                diagnostics);
        }

        ValidateNonOverlappingRanges(materialized, diagnostics);

        if (diagnostics.HasErrors)
        {
            return new AddressMapResult(null, diagnostics.ToArray());
        }

        var readOnlyEntries = Array.AsReadOnly(materialized);
        var readOnlyIdentities = new ReadOnlyDictionary<SemanticEntityId, AddressMapEntry>(identities);
        var readOnlyOutputIdentities =
            new ReadOnlyDictionary<SemanticEntityId, AddressMapEntry>(outputIdentities);
        var map = new AddressMap(readOnlyEntries, readOnlyIdentities, readOnlyOutputIdentities);
        return new AddressMapResult(map, diagnostics.ToArray());
    }

    public static AddressMapResult TryCreate(IEnumerable<AddressMapEntry> entries) => Create(entries);

    public static AddressMap FromEntries(IEnumerable<AddressMapEntry> entries) => new(entries);

    public bool TryGet(SemanticEntityId identity, out AddressMapEntry entry) =>
        byIdentity.TryGetValue(identity, out entry!);

    public bool TryGetOutput(SemanticEntityId identity, out AddressMapEntry entry) =>
        byOutputIdentity.TryGetValue(identity, out entry!);

    public IReadOnlyList<AddressMapEntry> GetEntries(SemanticEntityKind kind) =>
        Array.AsReadOnly(entries.Where(entry => entry.Identity.Kind == kind).ToArray());

    public bool TryMapEntity(SemanticEntityId identity, out VirtualAddress outputAddress)
    {
        if (byIdentity.TryGetValue(identity, out var entry))
        {
            outputAddress = entry.OutputAddress;
            return true;
        }

        outputAddress = default;
        return false;
    }

    public bool TryMapSourceAddress(
        SemanticEntityId identity,
        VirtualAddress sourceAddress,
        out VirtualAddress outputAddress)
    {
        if (!byIdentity.TryGetValue(identity, out var entry)
            || !Contains(entry.SourceRange.VirtualAddress, entry.SourceRange.Size, sourceAddress.Value))
        {
            outputAddress = default;
            return false;
        }

        return TryTranslate(
            entry.SourceRange.VirtualAddress.Value,
            entry.OutputRange.VirtualAddress.Value,
            entry.OutputRange.Size,
            sourceAddress.Value,
            out outputAddress);
    }

    public bool TryMapSourceAddress(VirtualAddress sourceAddress, out VirtualAddress outputAddress) =>
        TryMapSourceAddress(sourceAddress, preferredKind: null, out outputAddress);

    public bool TryMapSourceAddress(
        VirtualAddress sourceAddress,
        SemanticEntityKind preferredKind,
        out VirtualAddress outputAddress) =>
        TryMapSourceAddress(sourceAddress, (SemanticEntityKind?)preferredKind, out outputAddress);

    private bool TryMapSourceAddress(
        VirtualAddress sourceAddress,
        SemanticEntityKind? preferredKind,
        out VirtualAddress outputAddress)
    {
        var candidates = FindContainingVirtualAddress(sourceAddress.Value, preferredKind);
        if (candidates.Length != 1)
        {
            outputAddress = default;
            return false;
        }

        var entry = candidates[0];
        return TryTranslate(
            entry.SourceRange.VirtualAddress.Value,
            entry.OutputRange.VirtualAddress.Value,
            entry.OutputRange.Size,
            sourceAddress.Value,
            out outputAddress);
    }

    public bool TryMapSourceFileOffset(FileOffset sourceFileOffset, out FileOffset outputFileOffset)
    {
        var candidates = FindContainingFileOffset(sourceFileOffset.Value, preferredKind: null);
        if (candidates.Length != 1)
        {
            outputFileOffset = default;
            return false;
        }

        var entry = candidates[0];
        return TryTranslate(
            entry.SourceRange.FileOffset.Value,
            entry.OutputRange.FileOffset.Value,
            entry.OutputRange.Size,
            sourceFileOffset.Value,
            out outputFileOffset);
    }

    public bool TryMapSourceRange(
        SemanticSourceRange sourceRange,
        out SemanticSourceRange outputRange) =>
        TryMapSourceRange(sourceRange, preferredKind: null, out outputRange);

    public bool TryMapSourceRange(
        SemanticSourceRange sourceRange,
        SemanticEntityKind preferredKind,
        out SemanticSourceRange outputRange) =>
        TryMapSourceRange(sourceRange, (SemanticEntityKind?)preferredKind, out outputRange);

    private bool TryMapSourceRange(
        SemanticSourceRange sourceRange,
        SemanticEntityKind? preferredKind,
        out SemanticSourceRange outputRange)
    {
        if (sourceRange.Size == 0
            || !sourceRange.TryGetFileEnd(out _)
            || !sourceRange.TryGetVirtualEnd(out _))
        {
            outputRange = default;
            return false;
        }

        var candidates = entries
            .Where(entry =>
                Contains(entry.SourceRange.FileOffset.Value, entry.SourceRange.Size, sourceRange.FileOffset.Value)
                && Contains(entry.SourceRange.VirtualAddress, entry.SourceRange.Size, sourceRange.VirtualAddress.Value));
        var smallestCandidates = SelectSmallestCandidates(candidates, preferredKind);
        if (smallestCandidates.Length != 1)
        {
            outputRange = default;
            return false;
        }

        var entry = smallestCandidates[0];
        var fileDelta = sourceRange.FileOffset.Value - entry.SourceRange.FileOffset.Value;
        var virtualDelta = sourceRange.VirtualAddress.Value - entry.SourceRange.VirtualAddress.Value;
        if (fileDelta != virtualDelta
            || fileDelta >= entry.SourceRange.Size
            || fileDelta >= entry.OutputRange.Size
            || sourceRange.Size > entry.SourceRange.Size - fileDelta
            || sourceRange.Size > entry.OutputRange.Size - fileDelta
            || !TryAdd(entry.OutputRange.FileOffset.Value, fileDelta, out var outputFileOffset)
            || !TryAdd(entry.OutputRange.VirtualAddress.Value, fileDelta, out var outputVirtualAddress))
        {
            outputRange = default;
            return false;
        }

        outputRange = new SemanticSourceRange(
            new FileOffset(outputFileOffset),
            new VirtualAddress(outputVirtualAddress),
            sourceRange.Size);
        return true;
    }

    private AddressMapEntry[] FindContainingVirtualAddress(
        ulong sourceAddress,
        SemanticEntityKind? preferredKind)
    {
        var candidates = entries
            .Where(entry => Contains(entry.SourceRange.VirtualAddress, entry.SourceRange.Size, sourceAddress));
        return SelectSmallestCandidates(candidates, preferredKind);
    }

    private AddressMapEntry[] FindContainingFileOffset(
        ulong sourceFileOffset,
        SemanticEntityKind? preferredKind)
    {
        var candidates = entries
            .Where(entry =>
                Contains(entry.SourceRange.FileOffset.Value, entry.SourceRange.Size, sourceFileOffset));
        return SelectSmallestCandidates(candidates, preferredKind);
    }

    private static AddressMapEntry[] SelectSmallestCandidates(
        IEnumerable<AddressMapEntry> candidates,
        SemanticEntityKind? preferredKind)
    {
        var ordered = candidates.ToArray();
        if (preferredKind is { } kind)
        {
            var preferred = ordered.Where(entry => entry.Identity.Kind == kind).ToArray();
            if (preferred.Length != 0)
            {
                ordered = preferred;
            }
        }

        if (ordered.Length == 0)
        {
            return Array.Empty<AddressMapEntry>();
        }

        var smallestSize = ordered.Min(entry => entry.SourceRange.Size);
        var smallest = ordered
            .Where(entry => entry.SourceRange.Size == smallestSize)
            .ToArray();
        return smallest;
    }

    private static void ValidateEntry(
        AddressMapEntry entry,
        IDictionary<SemanticEntityId, AddressMapEntry> identities,
        IDictionary<SemanticEntityId, AddressMapEntry> outputIdentities,
        ISet<AddressMapRangeKey> sourceRanges,
        ISet<AddressMapRangeKey> outputRanges,
        DiagnosticBag diagnostics)
    {
        if (!Enum.IsDefined(typeof(SemanticEntityKind), entry.Identity.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMalformed,
                "An address-map entry has an unsupported source identity kind.");
        }

        if (string.IsNullOrWhiteSpace(entry.Identity.Value))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMalformed,
                "An address-map entry has an empty source identity.");
        }
        else if (!identities.TryAdd(entry.Identity, entry))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapDuplicate,
                $"The address map contains duplicate source identity '{entry.Identity.Value}'.");
        }

        if (entry.OutputIdentity is { } outputKindIdentity
            && !Enum.IsDefined(typeof(SemanticEntityKind), outputKindIdentity.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMalformed,
                "An address-map entry has an unsupported output identity kind.");
        }

        if (entry.OutputIdentity is { } outputIdentity
            && string.IsNullOrWhiteSpace(outputIdentity.Value))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMalformed,
                "An address-map entry has an empty output identity.");
        }
        else if (!outputIdentities.TryAdd(entry.PlannedIdentity, entry))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapDuplicate,
                $"The address map contains duplicate output identity '{entry.PlannedIdentity.Value}'.");
        }

        if (entry.SourceRange.Size == 0 || entry.OutputRange.Size == 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMalformed,
                "An address-map range must be non-empty.");
        }

        if (!entry.SourceRange.TryGetFileEnd(out _)
            || !entry.SourceRange.TryGetVirtualEnd(out _))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapOverflow,
                "An address-map source range overflows its typed address domain.");
        }

        if (!entry.OutputRange.TryGetFileEnd(out _)
            || !entry.OutputRange.TryGetVirtualEnd(out _))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapOverflow,
                "An address-map output range overflows its typed address domain.");
        }

        var sourceKey = new AddressMapRangeKey(
            entry.Identity.Kind,
            entry.SourceRange.FileOffset.Value,
            entry.SourceRange.VirtualAddress.Value);
        if (!sourceRanges.Add(sourceKey))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapDuplicate,
                "The address map contains a duplicate source range.");
        }

        var outputKey = new AddressMapRangeKey(
            entry.PlannedIdentity.Kind,
            entry.OutputRange.FileOffset.Value,
            entry.OutputRange.VirtualAddress.Value);
        if (!outputRanges.Add(outputKey))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapDuplicate,
                "The address map contains a duplicate output range.");
        }
    }

    private static void ValidateNonOverlappingRanges(
        IReadOnlyList<AddressMapEntry> entries,
        DiagnosticBag diagnostics)
    {
        for (var leftIndex = 0; leftIndex < entries.Count; leftIndex++)
        {
            var left = entries[leftIndex];
            if (left is null)
            {
                continue;
            }

            for (var rightIndex = leftIndex + 1; rightIndex < entries.Count; rightIndex++)
            {
                var right = entries[rightIndex];
                if (right is null)
                {
                    continue;
                }

                var sourceOverlap = left.Identity.Kind == right.Identity.Kind
                    && RangesOverlap(left.SourceRange, right.SourceRange);
                var outputOverlap = left.PlannedIdentity.Kind == right.PlannedIdentity.Kind
                    && RangesOverlap(left.OutputRange, right.OutputRange);
                if (sourceOverlap || outputOverlap)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapDuplicate,
                        "The address map contains overlapping source or output ranges.");
                }
            }
        }
    }

    private static bool RangesOverlap(SemanticSourceRange left, SemanticSourceRange right) =>
        RangesOverlap(left.FileOffset.Value, left.Size, right.FileOffset.Value, right.Size)
        || RangesOverlap(left.VirtualAddress.Value, left.Size, right.VirtualAddress.Value, right.Size);

    private static bool RangesOverlap(ulong leftStart, ulong leftSize, ulong rightStart, ulong rightSize)
    {
        if (leftStart <= rightStart)
        {
            return rightStart - leftStart < leftSize;
        }

        return leftStart - rightStart < rightSize;
    }

    private static bool Contains(VirtualAddress start, ulong size, ulong value) =>
        Contains(start.Value, size, value);

    private static bool Contains(ulong start, ulong size, ulong value) =>
        value >= start && value - start < size;

    private static bool TryTranslate(
        ulong sourceStart,
        ulong outputStart,
        ulong outputSize,
        ulong sourceAddress,
        out VirtualAddress outputAddress)
    {
        var delta = sourceAddress - sourceStart;
        if (delta >= outputSize || !TryAdd(outputStart, delta, out var translated))
        {
            outputAddress = default;
            return false;
        }

        outputAddress = new VirtualAddress(translated);
        return true;
    }

    private static bool TryTranslate(
        ulong sourceStart,
        ulong outputStart,
        ulong outputSize,
        ulong sourceAddress,
        out FileOffset outputFileOffset)
    {
        var delta = sourceAddress - sourceStart;
        if (delta >= outputSize || !TryAdd(outputStart, delta, out var translated))
        {
            outputFileOffset = default;
            return false;
        }

        outputFileOffset = new FileOffset(translated);
        return true;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        if (left > ulong.MaxValue - right)
        {
            result = default;
            return false;
        }

        result = checked(left + right);
        return true;
    }

    private readonly record struct AddressMapRangeKey(
        SemanticEntityKind Kind,
        ulong FileOffset,
        ulong VirtualAddress);
}
