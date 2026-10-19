using System.Collections.ObjectModel;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

/// <summary>
/// One provider-local target identity. It intentionally carries no provider
/// address that could be mistaken for a consumer-image virtual address.
/// </summary>
public sealed record Aarch64ExternalProviderTargetIdentity(int Index, string SymbolName);

/// <summary>
/// Immutable provider facts supplied to the bounded external-table consumer
/// proof query. Callers must derive these facts from a successful, SHA-pinned
/// provider-facts read; the selected-function proof never reads provider bytes
/// or maps provider addresses into the consumer image.
/// </summary>
public sealed class Aarch64ExternalJumpTableProviderFacts
{
    public const int RequiredEntryCount = 4;
    public const int RequiredEntryWidth = sizeof(int);
    public const int RequiredTableByteLength = RequiredEntryCount * RequiredEntryWidth;

    public Aarch64ExternalJumpTableProviderFacts(
        string tableIdentity,
        string providerSoname,
        string providerBuildIdHex,
        string providerSha256,
        string tableObjectName,
        ulong tableObjectSize,
        string tableBytesSha256,
        IEnumerable<Aarch64ExternalProviderTargetIdentity> targetSymbols)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tableIdentity);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerSoname);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerBuildIdHex);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(tableObjectName);
        ArgumentException.ThrowIfNullOrWhiteSpace(tableBytesSha256);
        ArgumentNullException.ThrowIfNull(targetSymbols);

        TableIdentity = tableIdentity;
        ProviderSoname = providerSoname;
        ProviderBuildIdHex = providerBuildIdHex;
        ProviderSha256 = providerSha256;
        TableObjectName = tableObjectName;
        TableObjectSize = tableObjectSize;
        TableBytesSha256 = tableBytesSha256;
        TargetSymbols = CopyRequiredTargetSymbols(targetSymbols, nameof(targetSymbols));
    }

    /// <summary>Stable provider-domain table label; never an AddressMap entity.</summary>
    public string TableIdentity { get; }

    public string ProviderSoname { get; }

    public string ProviderBuildIdHex { get; }

    public string ProviderSha256 { get; }

    public string TableObjectName { get; }

    public ulong TableObjectSize { get; }

    public string TableBytesSha256 { get; }

    public IReadOnlyList<Aarch64ExternalProviderTargetIdentity> TargetSymbols { get; }

    private static ReadOnlyCollection<Aarch64ExternalProviderTargetIdentity> CopyRequiredTargetSymbols(
        IEnumerable<Aarch64ExternalProviderTargetIdentity> source,
        string parameterName)
    {
        var targets = new List<Aarch64ExternalProviderTargetIdentity>(RequiredEntryCount);
        using var enumerator = source.GetEnumerator();
        var sourceEnded = false;
        while (targets.Count < RequiredEntryCount)
        {
            if (!enumerator.MoveNext())
            {
                sourceEnded = true;
                break;
            }

            targets.Add(enumerator.Current
                ?? throw new ArgumentException("Provider target identities cannot contain null values.", parameterName));
        }

        if (sourceEnded || targets.Count != RequiredEntryCount || enumerator.MoveNext())
        {
            throw new ArgumentException(
                $"Exactly {RequiredEntryCount} provider target identities are required.",
                parameterName);
        }

        return Array.AsReadOnly(targets.ToArray());
    }
}

/// <summary>
/// Proof that one explicitly selected consumer BR is guarded by a safe bounded
/// default and reads an external provider table through one verified GLOB_DAT
/// pointer carrier. Provider facts remain identity-only and are not source VA
/// mappings, clone requests, or runtime translations.
/// </summary>
public sealed record Aarch64ExternalJumpTableConsumerProof
{
    internal Aarch64ExternalJumpTableConsumerProof(
        ElfFunctionSymbol selectedFunction,
        ulong compareAddress,
        ulong boundsBranchAddress,
        ulong safeDefaultAddress,
        IEnumerable<ulong> safeDefaultPathAddresses,
        ulong gotPageProducerAddress,
        ulong gotLoadProducerAddress,
        ulong indexedLoadAddress,
        ulong tableBaseAddAddress,
        ulong branchAddress,
        IEnumerable<ulong> producerAddresses,
        Aarch64RegisterView indexRegister,
        Aarch64RegisterView gotPointerRegister,
        Aarch64RegisterView loadedDisplacementRegister,
        Aarch64RegisterView targetRegister,
        int entryWidth,
        bool isSigned,
        int indexScaleShift,
        int lowerBound,
        int upperBound,
        VirtualAddress gotSlotAddress,
        FileOffset gotSlotFileOffset,
        Aarch64DynamicImportBinding importOwner,
        Aarch64ExternalJumpTableProviderFacts providerFacts,
        string proof)
    {
        ArgumentNullException.ThrowIfNull(safeDefaultPathAddresses);
        ArgumentNullException.ThrowIfNull(producerAddresses);
        ArgumentNullException.ThrowIfNull(importOwner);
        ArgumentNullException.ThrowIfNull(providerFacts);
        ArgumentException.ThrowIfNullOrWhiteSpace(proof);
        SelectedFunction = selectedFunction;
        CompareAddress = compareAddress;
        BoundsBranchAddress = boundsBranchAddress;
        SafeDefaultAddress = safeDefaultAddress;
        SafeDefaultPathAddresses = Array.AsReadOnly(safeDefaultPathAddresses.ToArray());
        GotPageProducerAddress = gotPageProducerAddress;
        GotLoadProducerAddress = gotLoadProducerAddress;
        IndexedLoadAddress = indexedLoadAddress;
        TableBaseAddAddress = tableBaseAddAddress;
        BranchAddress = branchAddress;
        ProducerAddresses = Array.AsReadOnly(producerAddresses.ToArray());
        IndexRegister = indexRegister;
        GotPointerRegister = gotPointerRegister;
        LoadedDisplacementRegister = loadedDisplacementRegister;
        TargetRegister = targetRegister;
        EntryWidth = entryWidth;
        IsSigned = isSigned;
        IndexScaleShift = indexScaleShift;
        LowerBound = lowerBound;
        UpperBound = upperBound;
        GotSlotAddress = gotSlotAddress;
        GotSlotFileOffset = gotSlotFileOffset;
        ImportOwner = importOwner;
        ProviderFacts = providerFacts;
        Proof = proof;
    }

    public ElfFunctionSymbol SelectedFunction { get; }

    public ulong CompareAddress { get; }

    public ulong BoundsBranchAddress { get; }

    public ulong SafeDefaultAddress { get; }

    public IReadOnlyList<ulong> SafeDefaultPathAddresses { get; }

    public ulong GotPageProducerAddress { get; }

    public ulong GotLoadProducerAddress { get; }

    public ulong IndexedLoadAddress { get; }

    public ulong TableBaseAddAddress { get; }

    public ulong BranchAddress { get; }

    /// <summary>Ordered ADRP, GOT LDR, signed indexed LDRSW, ADD, and BR sites.</summary>
    public IReadOnlyList<ulong> ProducerAddresses { get; }

    public Aarch64RegisterView IndexRegister { get; }

    public Aarch64RegisterView GotPointerRegister { get; }

    public Aarch64RegisterView LoadedDisplacementRegister { get; }

    public Aarch64RegisterView TargetRegister { get; }

    public int EntryWidth { get; }

    public bool IsSigned { get; }

    /// <summary>UXTW shift amount; the signed-32 fixture requires a 2-bit scale.</summary>
    public int IndexScaleShift { get; }

    public int LowerBound { get; }

    public int UpperBound { get; }

    public VirtualAddress GotSlotAddress { get; }

    public FileOffset GotSlotFileOffset { get; }

    public Aarch64DynamicImportBinding ImportOwner { get; }

    public Aarch64ExternalJumpTableProviderFacts ProviderFacts { get; }

    public string Proof { get; }
}
