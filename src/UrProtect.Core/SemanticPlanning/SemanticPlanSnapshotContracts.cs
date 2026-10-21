using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>
/// Describes the state a semantic fixup has before a physical layout resolver
/// supplies final placement or runtime bindings.
/// </summary>
public enum SemanticFixupResolutionState : byte
{
    Resolved,
    Deferred,
    Unresolved,
}

/// <summary>
/// Bounded limits for the canonical semantic-plan handoff projection.
/// </summary>
public static class SemanticPlanSnapshotLimits
{
    public const int MaximumCanonicalBytes = 16 * 1024 * 1024;
    public const int MaximumMetadataBytes = 2 * 1024 * 1024;
    public const int MaximumStringBytes = 4096;
    public const int MaximumAddressMapEntries = 131072;
    public const int MaximumInstructions = 131072;
    public const int MaximumFixups = 131072;
    public const int MaximumExtensions = 32768;
    public const int MaximumDiagnostics = 16384;
    public const int MaximumCandidates = 4096;
    public const int MaximumOperandsPerInstruction = 64;
    public const int MaximumRegisterEffectsPerInstruction = 256;
    public const int MaximumReferencesPerInstruction = 256;
    public const int MaximumRelocationsPerInstruction = 64;
    public const int MaximumRelaxationOptions = 8;
    public const int MaximumTargetsPerJumpTable = 65536;
    public const int MaximumJumpTableReferenceProducers = 16;
    public const int MaximumJumpTableOwnerReferences = 1024;
    public const int MaximumCfiRegisterEffects = 256;
    public const int MaximumTlsInstructions = 1024;
    public const int MaximumTlsRelocationSites = 64;
    public const int MaximumTlsRequirements = 16;
    public const int MaximumProducerAddresses = 64;
    public const int MaximumExternalProviderTables = 16;
    public const int MaximumExternalProviderSymbols = 2048;
    public const int MaximumExternalProviderSymbolsPerTable = 1024;
    public const int MaximumExternalProviderTableEntries = 8192;
    public const int MaximumExternalProviderTableEntriesPerTable = 4096;
    public const int MaximumExternalProviderStringBytes = 256 * 1024;
    public const int MaximumExternalProviderTableBytes = 16 * 1024;
    public const int MaximumExternalProviderTableBytesPerTable = 16 * 1024;
}

/// <summary>
/// Immutable projection of one semantic fixup and its resolution state.
/// </summary>
public sealed class SemanticFixupSnapshot
{
    internal SemanticFixupSnapshot(SemanticFixup fixup, SemanticFixupResolutionState resolutionState)
    {
        Fixup = fixup ?? throw new ArgumentNullException(nameof(fixup));
        ResolutionState = resolutionState;
    }

    public SemanticFixup Fixup { get; }

    public SemanticFixupResolutionState ResolutionState { get; }

    public SemanticFixupKind Kind => Fixup.Kind;

    public VirtualAddress SourceAddress => Fixup.SourceAddress;

    public FileOffset SourceFileOffset => Fixup.SourceFileOffset;

    public SemanticTarget Target => Fixup.Target;
}

/// <summary>
/// Canonical, immutable semantic-plan projection consumed by layout and
/// Protected Image producers. It is a handoff contract, not a physical ELF
/// writer or a Protected Image artifact codec.
/// </summary>
public sealed class SemanticPlanSnapshot
{
    private readonly byte[] canonicalBytes;

    internal SemanticPlanSnapshot(
        SemanticRewritePlan plan,
        IEnumerable<SemanticFixupSnapshot> fixups,
        byte[] canonicalBytes,
        string planSha256)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(fixups);
        ArgumentNullException.ThrowIfNull(canonicalBytes);
        ArgumentNullException.ThrowIfNull(planSha256);

        Plan = plan;
        Fixups = Array.AsReadOnly(fixups.ToArray());
        this.canonicalBytes = canonicalBytes.ToArray();
        PlanSha256 = planSha256;
    }

    public SemanticRewritePlan Plan { get; }

    public AddressMap AddressMap => Plan.AddressMap;

    public IReadOnlyList<AddressMapEntry> AddressMapEntries => Plan.AddressMap.Entries;

    public IReadOnlyList<SemanticInstruction> Instructions => Plan.Instructions;

    public IReadOnlyList<SemanticFixupSnapshot> Fixups { get; }

    public IReadOnlyList<ISemanticPlanExtension> Extensions => Plan.Extensions;

    public IReadOnlyList<Diagnostic> Diagnostics => Plan.Diagnostics;

    public bool HasDeferredFixups => Fixups.Any(fixup => fixup.ResolutionState == SemanticFixupResolutionState.Deferred);

    public bool HasUnresolvedFixups => Fixups.Any(fixup => fixup.ResolutionState == SemanticFixupResolutionState.Unresolved);

    /// <summary>
    /// Gets a defensive copy of the canonical representation, including its
    /// trailing SHA-256 digest.
    /// </summary>
    public byte[] CanonicalBytes => canonicalBytes.ToArray();

    public int CanonicalLength => canonicalBytes.Length;

    public string PlanSha256 { get; }

}

/// <summary>
/// Result of creating or decoding a semantic-plan snapshot.
/// </summary>
public sealed class SemanticPlanSnapshotResult
{
    internal SemanticPlanSnapshotResult(
        SemanticPlanSnapshot? snapshot,
        IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        Snapshot = snapshot;
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
    }

    public SemanticPlanSnapshot? Snapshot { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsSuccess => Snapshot is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);

    public string? PlanSha256 => Snapshot?.PlanSha256;

    public byte[]? CanonicalBytes => Snapshot?.CanonicalBytes;
}
