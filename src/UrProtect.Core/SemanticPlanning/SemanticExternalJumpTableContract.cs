using System.Buffers.Binary;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>Validation shared by snapshot authors and the strict SPS6 decoder.</summary>
internal static class SemanticExternalJumpTableContract
{
    private const ushort FirstReservedSectionIndex = 0xFF00;
    private const byte ProviderTableBinding = 1; // STB_GLOBAL
    private const byte ProviderTableVisibility = 0; // STV_DEFAULT
    private const uint KnownLoadFlags = ElfConstants.PfR | ElfConstants.PfW | ElfConstants.PfX;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static void ValidateExtensionFields(
        SemanticExternalJumpTableExtension extension,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(extension);
        ArgumentNullException.ThrowIfNull(diagnostics);

        if (!IsCanonicalProviderTableIdentity(extension.TableIdentity.Value)
            || !TryValidateText(extension.TableIdentity.Value, "provider table identity", diagnostics))
        {
            Error(diagnostics, "An external jump-table extension requires a canonical provider-domain identity, not a path.");
        }

        if (!IsCanonicalSoname(extension.ProviderSoname)
            || !TryValidateText(extension.ProviderSoname, "provider SONAME", diagnostics))
        {
            Error(diagnostics, "The provider identity must contain an exact SONAME, not a path or empty name.");
        }

        if (!TryValidateText(extension.ProviderBuildIdHex, "provider build ID", diagnostics)
            || !IsLowercaseHex(extension.ProviderBuildIdHex, minimumCharacters: 8, maximumCharacters: 128)
            || (extension.ProviderBuildIdHex.Length & 1) != 0)
        {
            Error(diagnostics, "The provider GNU build ID must be canonical lowercase hexadecimal bytes.");
        }

        if (!TryValidateText(extension.ProviderSha256, "provider SHA-256", diagnostics)
            || !IsLowercaseHex(extension.ProviderSha256, minimumCharacters: 64, maximumCharacters: 64))
        {
            Error(diagnostics, "The provider SHA-256 must be exactly 64 lowercase hexadecimal characters.");
        }

        if (!Enum.IsDefined(extension.Encoding)
            || extension.Encoding != SemanticExternalJumpTableEncoding.SignedRelative32FromTableStart)
        {
            Error(diagnostics, "The external jump table uses an unsupported provider encoding.");
        }

        if (extension.ProviderFileSize == 0)
        {
            Error(diagnostics, "The provider content length must be non-zero.");
        }

        ValidateSymbol(
            extension.TableObject,
            ElfConstants.SttObject,
            requireReadOnlyData: true,
            extension.ProviderFileSize,
            "provider table object",
            diagnostics);
        if (extension.TableObject.Binding != ProviderTableBinding
            || extension.TableObject.Visibility != ProviderTableVisibility)
        {
            Error(
                diagnostics,
                "The provider table object must be externally resolvable as STB_GLOBAL and STV_DEFAULT for the exact GLOB_DAT contract.");
        }

        if (extension.TableObject.Range.Size != (ulong)extension.TableBytesSpan.Length
            || extension.TableBytesSpan.Length == 0
            || extension.TableBytesSpan.Length > SemanticPlanSnapshotLimits.MaximumExternalProviderTableBytesPerTable
            || extension.TableObject.Range.FileOffset.Value % sizeof(int) != 0
            || extension.TableObject.Range.VirtualAddress.Value % sizeof(int) != 0)
        {
            Error(diagnostics, "The provider table object range must exactly cover its bounded retained table bytes.");
        }

        var targetSymbolsWithinLimit = ValidateCount(
            extension.TargetSymbols.Count,
            SemanticPlanSnapshotLimits.MaximumExternalProviderSymbolsPerTable,
            "provider target symbol",
            diagnostics);
        var entriesWithinLimit = ValidateCount(
            extension.Entries.Count,
            SemanticPlanSnapshotLimits.MaximumExternalProviderTableEntriesPerTable,
            "external provider table entry",
            diagnostics);
        if (!targetSymbolsWithinLimit || !entriesWithinLimit)
        {
            return;
        }

        if (extension.TargetSymbols.Any(target => target is null)
            || extension.Entries.Any(entry => entry is null))
        {
            Error(diagnostics, "An external provider table contains a null target symbol or entry fact.");
            return;
        }

        var targetBySymbolIndex = new Dictionary<(ElfSymbolTableKind Table, uint Index), SemanticExternalProviderSymbol>();
        var targetNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var target in extension.TargetSymbols)
        {
            ValidateSymbol(
                target,
                ElfConstants.SttFunc,
                requireReadOnlyData: false,
                extension.ProviderFileSize,
                "provider-local target",
                diagnostics);
            var targetSymbolIdentity = (target.SymbolTable, target.SymbolIndex);
            var tableObjectIdentity = (extension.TableObject.SymbolTable, extension.TableObject.SymbolIndex);
            if (!targetBySymbolIndex.TryAdd(targetSymbolIdentity, target)
                || !targetNames.Add(target.Name)
                || targetSymbolIdentity == tableObjectIdentity
                || string.Equals(target.Name, extension.TableObject.Name, StringComparison.Ordinal))
            {
                Error(diagnostics, "Provider symbol identities must be unique within an external jump-table extension.");
            }

            if ((target.LoadSegmentFlags & ElfConstants.PfX) == 0
                || (target.LoadSegmentFlags & ElfConstants.PfW) != 0
                || (target.LoadSegmentFlags & ~KnownLoadFlags) != 0)
            {
                Error(diagnostics, "A provider target must be in a bounded non-writable executable PT_LOAD range.");
            }
        }

        if (extension.TargetSymbols.Count == 0 || extension.Entries.Count == 0)
        {
            Error(diagnostics, "An external provider table must retain at least one target symbol and entry.");
        }

        var expectedByteLength = (long)extension.Entries.Count * sizeof(int);
        if (expectedByteLength > SemanticPlanSnapshotLimits.MaximumExternalProviderTableBytesPerTable
            || extension.TableBytesSpan.Length != expectedByteLength)
        {
            Error(diagnostics, "The provider table byte count must equal its bounded signed-32 entry count.");
        }

        var orderedEntries = extension.Entries.OrderBy(entry => entry.Index).ToArray();
        var referencedTargetIndices = new HashSet<(ElfSymbolTableKind Table, uint Index)>();
        for (var entryIndex = 0; entryIndex < orderedEntries.Length; entryIndex++)
        {
            var entry = orderedEntries[entryIndex];
            var targetSymbolIdentity = (entry.TargetSymbolTable, entry.TargetSymbolIndex);
            if (entry.Index != entryIndex
                || !Enum.IsDefined(entry.TargetSymbolTable)
                || !targetBySymbolIndex.TryGetValue(targetSymbolIdentity, out var target))
            {
                Error(diagnostics, "Provider table entries must use unique contiguous indexes and exact target-symbol identities.");
                continue;
            }

            referencedTargetIndices.Add(targetSymbolIdentity);
            var byteOffset = checked(entryIndex * sizeof(int));
            if (byteOffset <= extension.TableBytesSpan.Length - sizeof(int)
                && BinaryPrimitives.ReadInt32LittleEndian(extension.TableBytesSpan.Slice(byteOffset, sizeof(int)))
                    != entry.SignedRelativeDisplacement)
            {
                Error(diagnostics, "A provider table entry does not match its retained signed-relative bytes.");
            }

            if (!TryApplySignedDisplacement(
                    extension.TableObject.Range.VirtualAddress.Value,
                    entry.SignedRelativeDisplacement,
                    out var resolvedTarget)
                || resolvedTarget != target.Range.VirtualAddress.Value)
            {
                Error(diagnostics, "A signed-relative provider table entry does not resolve to its exact provider-local target symbol.");
            }

            if (RangesOverlap(extension.TableObject.Range, target.Range, fileDomain: true)
                || RangesOverlap(extension.TableObject.Range, target.Range, fileDomain: false))
            {
                Error(diagnostics, "The provider target range overlaps the provider table object range.");
            }
        }

        if (referencedTargetIndices.Count != extension.TargetSymbols.Count)
        {
            Error(diagnostics, "The provider target symbol set contains an unreferenced or duplicate target fact.");
        }

        var targetFileRangesOverlap = HasOverlappingTargetRanges(extension.TargetSymbols, fileDomain: true);
        var targetVirtualRangesOverlap = HasOverlappingTargetRanges(extension.TargetSymbols, fileDomain: false);
        if (targetFileRangesOverlap || targetVirtualRangesOverlap)
        {
            Error(diagnostics, "Provider-local target symbol ranges must not alias or overlap.");
        }
    }

    public static void ValidateAggregate(
        IEnumerable<ISemanticPlanExtension> extensions,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(extensions);
        ArgumentNullException.ThrowIfNull(diagnostics);

        var externalTables = extensions.OfType<SemanticExternalJumpTableExtension>().ToArray();
        ValidateCount(externalTables.Length, SemanticPlanSnapshotLimits.MaximumExternalProviderTables, "external provider table", diagnostics);

        var providerHashes = new HashSet<string>(StringComparer.Ordinal);
        long symbols = 0;
        long entries = 0;
        long strings = 0;
        long bytes = 0;
        foreach (var extension in externalTables)
        {
            if (string.IsNullOrEmpty(extension.ProviderSha256)
                || !providerHashes.Add(extension.ProviderSha256))
            {
                Error(diagnostics, "A provider content identity may be carried only once in a canonical snapshot.");
            }

            symbols += 1L + extension.TargetSymbols.Count;
            entries += extension.Entries.Count;
            bytes += extension.TableBytesSpan.Length;
            strings += GetUtf8ByteCount(extension.TableIdentity.Value);
            strings += GetUtf8ByteCount(extension.ProviderSoname);
            strings += GetUtf8ByteCount(extension.ProviderBuildIdHex);
            strings += GetUtf8ByteCount(extension.ProviderSha256);
            strings += GetUtf8ByteCount(extension.TableObject.Name);
            foreach (var target in extension.TargetSymbols)
            {
                strings += target is null
                    ? SemanticPlanSnapshotLimits.MaximumStringBytes + 1
                    : GetUtf8ByteCount(target.Name);
            }
        }

        if (symbols > SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols)
        {
            Limit(diagnostics, "provider symbol", SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols);
        }

        if (entries > SemanticPlanSnapshotLimits.MaximumExternalProviderTableEntries)
        {
            Limit(diagnostics, "external provider table entry", SemanticPlanSnapshotLimits.MaximumExternalProviderTableEntries);
        }

        if (strings > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes)
        {
            Limit(diagnostics, "provider string byte", SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes);
        }

        if (bytes > SemanticPlanSnapshotLimits.MaximumExternalProviderTableBytes)
        {
            Limit(diagnostics, "provider table byte", SemanticPlanSnapshotLimits.MaximumExternalProviderTableBytes);
        }
    }

    private static void ValidateSymbol(
        SemanticExternalProviderSymbol symbol,
        byte expectedType,
        bool requireReadOnlyData,
        ulong providerFileSize,
        string description,
        DiagnosticBag diagnostics)
    {
        if (!Enum.IsDefined(symbol.SymbolTable)
            || (requireReadOnlyData && symbol.SymbolTable != ElfSymbolTableKind.Dynamic)
            || !TryValidateText(symbol.Name, $"{description} symbol name", diagnostics)
            || symbol.SymbolIndex == 0
            || symbol.Type != expectedType
            || symbol.Binding > 2
            || symbol.Visibility > 3
            || symbol.SectionIndex == 0
            || symbol.SectionIndex >= FirstReservedSectionIndex
            || symbol.Range.Size == 0
            || !symbol.Range.TryGetFileEnd(out var fileEnd)
            || fileEnd > providerFileSize
            || !symbol.Range.TryGetVirtualEnd(out _))
        {
            Error(diagnostics, $"The {description} symbol identity or provider range is malformed.");
        }

        if (requireReadOnlyData
            && (symbol.LoadSegmentFlags != ElfConstants.PfR
                || (symbol.LoadSegmentFlags & (ElfConstants.PfW | ElfConstants.PfX)) != 0))
        {
            Error(diagnostics, "The provider table object must be carried in a read-only, non-executable PT_LOAD range.");
        }

        if ((symbol.LoadSegmentFlags & ~KnownLoadFlags) != 0)
        {
            Error(diagnostics, $"The {description} has unsupported PT_LOAD permission bits.");
        }

        if (expectedType == ElfConstants.SttFunc
            && (symbol.Range.FileOffset.Value % sizeof(uint) != 0
                || symbol.Range.VirtualAddress.Value % sizeof(uint) != 0
                || symbol.Range.Size % sizeof(uint) != 0))
        {
            Error(diagnostics, $"The {description} AArch64 function range is not instruction-aligned.");
        }
    }

    private static bool TryValidateText(string? value, string name, DiagnosticBag diagnostics)
    {
        if (string.IsNullOrEmpty(value))
        {
            Error(diagnostics, $"The {name} is empty.");
            return false;
        }

        try
        {
            if (StrictUtf8.GetByteCount(value) > SemanticPlanSnapshotLimits.MaximumStringBytes
                || value.Any(character => character == '\0' || char.IsControl(character)))
            {
                Limit(diagnostics, name, SemanticPlanSnapshotLimits.MaximumStringBytes);
                return false;
            }

            return true;
        }
        catch (EncoderFallbackException)
        {
            Error(diagnostics, $"The {name} is not valid UTF-8.");
            return false;
        }
    }

    private static bool IsCanonicalProviderTableIdentity(string? identity) =>
        !string.IsNullOrEmpty(identity)
        && identity.Length <= 128
        && identity[0] != '.'
        && identity.All(character =>
            character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '.' or '_' or '-');

    private static bool IsCanonicalSoname(string? soname) =>
        !string.IsNullOrEmpty(soname)
        && soname.Length <= 255
        && soname[0] != '.'
        && soname.All(character =>
            character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '.' or '_' or '+' or '-');

    private static bool IsLowercaseHex(string? value, int minimumCharacters, int maximumCharacters) =>
        value is not null
        && value.Length >= minimumCharacters
        && value.Length <= maximumCharacters
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static int GetUtf8ByteCount(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return 0;
        }

        try
        {
            return StrictUtf8.GetByteCount(value);
        }
        catch (EncoderFallbackException)
        {
            return SemanticPlanSnapshotLimits.MaximumStringBytes + 1;
        }
    }

    private static bool TryApplySignedDisplacement(ulong baseAddress, int displacement, out ulong targetAddress)
    {
        if (displacement < 0)
        {
            var magnitude = (ulong)(-(long)displacement);
            if (baseAddress < magnitude)
            {
                targetAddress = default;
                return false;
            }

            targetAddress = baseAddress - magnitude;
            return true;
        }

        var positive = (uint)displacement;
        if (positive > ulong.MaxValue - baseAddress)
        {
            targetAddress = default;
            return false;
        }

        targetAddress = baseAddress + positive;
        return true;
    }

    private static bool RangesOverlap(
        SemanticExternalProviderRange left,
        SemanticExternalProviderRange right,
        bool fileDomain)
    {
        var leftStart = fileDomain ? left.FileOffset.Value : left.VirtualAddress.Value;
        var rightStart = fileDomain ? right.FileOffset.Value : right.VirtualAddress.Value;
        var leftValid = fileDomain ? left.TryGetFileEnd(out var leftEnd) : left.TryGetVirtualEnd(out leftEnd);
        var rightValid = fileDomain ? right.TryGetFileEnd(out var rightEnd) : right.TryGetVirtualEnd(out rightEnd);
        return leftValid && rightValid && leftStart < rightEnd && rightStart < leftEnd;
    }

    private static bool HasOverlappingTargetRanges(
        IReadOnlyList<SemanticExternalProviderSymbol> symbols,
        bool fileDomain)
    {
        var intervals = new ProviderInterval[symbols.Count];
        for (var index = 0; index < symbols.Count; index++)
        {
            var range = symbols[index].Range;
            var start = fileDomain ? range.FileOffset.Value : range.VirtualAddress.Value;
            ulong end;
            var valid = fileDomain
                ? range.TryGetFileEnd(out end)
                : range.TryGetVirtualEnd(out end);
            if (!valid)
            {
                // ValidateSymbol reports the checked-range overflow before this overlap pass.
                return false;
            }

            intervals[index] = new ProviderInterval(start, end);
        }

        Array.Sort(intervals, static (left, right) =>
        {
            var startOrder = left.Start.CompareTo(right.Start);
            return startOrder != 0 ? startOrder : left.End.CompareTo(right.End);
        });

        var furthestEnd = 0UL;
        for (var index = 0; index < intervals.Length; index++)
        {
            if (index > 0 && intervals[index].Start < furthestEnd)
            {
                return true;
            }

            if (intervals[index].End > furthestEnd)
            {
                furthestEnd = intervals[index].End;
            }
        }

        return false;
    }

    private readonly record struct ProviderInterval(ulong Start, ulong End);

    private static bool ValidateCount(int count, int maximum, string name, DiagnosticBag diagnostics)
    {
        if (count < 0 || count > maximum)
        {
            Limit(diagnostics, name, maximum);
            return false;
        }

        return true;
    }

    private static void Error(DiagnosticBag diagnostics, string message) =>
        diagnostics.Error(DiagnosticCode.SemanticPlanSnapshotMalformed, message);

    private static void Limit(DiagnosticBag diagnostics, string name, int maximum) =>
        diagnostics.Error(
            DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
            $"The semantic-plan snapshot {name} limit is {maximum}.");
}
