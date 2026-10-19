using System.Collections.ObjectModel;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>Provider-side table identity, intentionally not a SemanticEntityId.</summary>
public readonly record struct SemanticExternalProviderTableIdentity(string Value);

/// <summary>
/// Provider ELF virtual address. This is deliberately not the consumer-image
/// <see cref="VirtualAddress"/> used by the semantic plan's AddressMap.
/// </summary>
public readonly record struct SemanticExternalProviderAddress(ulong Value);

/// <summary>
/// Provider ELF file offset, kept separate from a consumer-image
/// <see cref="FileOffset"/>.
/// </summary>
public readonly record struct SemanticExternalProviderFileOffset(ulong Value);

/// <summary>A bounded byte-backed range in the provider ELF address domain.</summary>
public readonly record struct SemanticExternalProviderRange(
    SemanticExternalProviderFileOffset FileOffset,
    SemanticExternalProviderAddress VirtualAddress,
    ulong Size)
{
    public bool TryGetFileEnd(out ulong end) => TryAdd(FileOffset.Value, Size, out end);

    public bool TryGetVirtualEnd(out ulong end) => TryAdd(VirtualAddress.Value, Size, out end);

    private static bool TryAdd(ulong start, ulong size, out ulong end)
    {
        if (size > ulong.MaxValue - start)
        {
            end = default;
            return false;
        }

        end = start + size;
        return true;
    }
}

/// <summary>One provider ELF symbol row plus its bounded provider-owned range.</summary>
public sealed record SemanticExternalProviderSymbol(
    string Name,
    ElfSymbolTableKind SymbolTable,
    uint SymbolIndex,
    byte Binding,
    byte Type,
    byte Visibility,
    ushort SectionIndex,
    SemanticExternalProviderRange Range,
    uint LoadSegmentFlags);

/// <summary>The only provider table encoding admitted by this wire contract.</summary>
public enum SemanticExternalJumpTableEncoding : byte
{
    SignedRelative32FromTableStart = 1,
}

/// <summary>
/// One entry in the provider's signed-relative table. TargetSymbolIndex refers
/// to a symbol in the extension's provider-domain TargetSymbols collection.
/// </summary>
public sealed record SemanticExternalJumpTableEntryFact(
    int Index,
    int SignedRelativeDisplacement,
    ElfSymbolTableKind TargetSymbolTable,
    uint TargetSymbolIndex);

/// <summary>
/// Provider file content identity and provider-local table/target facts for one
/// external signed-relative jump table. No provider path or consumer virtual
/// address is part of this record.
/// </summary>
public sealed record SemanticExternalJumpTableExtension : ISemanticPlanExtension
{
    private readonly byte[] tableBytes;

    public SemanticExternalJumpTableExtension(
        SemanticExternalProviderTableIdentity tableIdentity,
        string providerSoname,
        string providerBuildIdHex,
        string providerSha256,
        ulong providerFileSize,
        SemanticExternalProviderSymbol tableObject,
        IEnumerable<SemanticExternalProviderSymbol> targetSymbols,
        IEnumerable<SemanticExternalJumpTableEntryFact> entries,
        IEnumerable<byte> tableBytes,
        SemanticExternalJumpTableEncoding encoding = SemanticExternalJumpTableEncoding.SignedRelative32FromTableStart)
    {
        ArgumentNullException.ThrowIfNull(providerSoname);
        ArgumentNullException.ThrowIfNull(providerBuildIdHex);
        ArgumentNullException.ThrowIfNull(providerSha256);
        ArgumentNullException.ThrowIfNull(tableObject);
        ArgumentNullException.ThrowIfNull(targetSymbols);
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(tableBytes);

        TableIdentity = tableIdentity;
        ProviderSoname = providerSoname;
        ProviderBuildIdHex = providerBuildIdHex;
        ProviderSha256 = providerSha256;
        ProviderFileSize = providerFileSize;
        TableObject = tableObject;
        TargetSymbols = CopyBounded(
            targetSymbols,
            SemanticPlanSnapshotLimits.MaximumExternalProviderSymbolsPerTable,
            nameof(targetSymbols));
        Entries = CopyBounded(
            entries,
            SemanticPlanSnapshotLimits.MaximumExternalProviderTableEntriesPerTable,
            nameof(entries));
        this.tableBytes = CopyBounded(
            tableBytes,
            SemanticPlanSnapshotLimits.MaximumExternalProviderTableBytesPerTable,
            nameof(tableBytes)).ToArray();
        Encoding = encoding;
    }

    private static ReadOnlyCollection<T> CopyBounded<T>(IEnumerable<T> values, int maximum, string parameterName)
    {
        var copy = new List<T>();
        using var enumerator = values.GetEnumerator();
        while (enumerator.MoveNext())
        {
            if (copy.Count == maximum)
            {
                throw new ArgumentOutOfRangeException(
                    parameterName,
                    $"The external provider collection exceeds its limit of {maximum} items.");
            }

            copy.Add(enumerator.Current);
        }

        return Array.AsReadOnly(copy.ToArray());
    }

    /// <summary>A stable symbolic identity, not an AddressMap row.</summary>
    public SemanticExternalProviderTableIdentity TableIdentity { get; }

    /// <summary>The exact SONAME expected from the trusted operator input.</summary>
    public string ProviderSoname { get; }

    /// <summary>Canonical lowercase hexadecimal GNU build ID.</summary>
    public string ProviderBuildIdHex { get; }

    /// <summary>Canonical lowercase SHA-256 of the complete provider file.</summary>
    public string ProviderSha256 { get; }

    /// <summary>Exact provider file length bound by ProviderSha256.</summary>
    public ulong ProviderFileSize { get; }

    public SemanticExternalProviderSymbol TableObject { get; }

    public IReadOnlyList<SemanticExternalProviderSymbol> TargetSymbols { get; }

    public IReadOnlyList<SemanticExternalJumpTableEntryFact> Entries { get; }

    public IReadOnlyList<byte> TableBytes => Array.AsReadOnly(tableBytes.ToArray());

    internal ReadOnlySpan<byte> TableBytesSpan => tableBytes;

    public SemanticExternalJumpTableEncoding Encoding { get; }

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.ExternalJumpTable;
}
