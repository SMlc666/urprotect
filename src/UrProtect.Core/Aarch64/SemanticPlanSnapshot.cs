using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

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
    public const int MaximumCfiRegisterEffects = 256;
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

    public static SemanticPlanSnapshotResult Create(SemanticRewritePlan plan) =>
        SemanticPlanSnapshotCodec.Create(plan);

    public static SemanticPlanSnapshotResult Project(SemanticRewritePlan plan) =>
        SemanticPlanSnapshotCodec.Create(plan);
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

/// <summary>
/// Projects a semantic rewrite plan into the canonical handoff snapshot. The
/// codec remains the single owner of bytes and digest computation.
/// </summary>
public static class SemanticPlanSnapshotProjector
{
    public static SemanticPlanSnapshotResult Project(SemanticRewritePlan plan) =>
        SemanticPlanSnapshotCodec.Create(plan);

    public static SemanticPlanSnapshotResult Create(SemanticRewritePlan plan) =>
        SemanticPlanSnapshotCodec.Create(plan);
}

/// <summary>
/// Owns canonical semantic-plan ordering, bounded serialization, digest
/// computation, and defensive decoding. The representation is deliberately
/// separate from the Protected Image ABI; a later artifact owner may bind this
/// digest without duplicating the semantic model.
/// </summary>
public static class SemanticPlanSnapshotCodec
{
    public const ushort Version = 1;
    public const ushort Aarch64Architecture = ElfConstants.MachineAarch64;
    public const string MagicText = "URP-SPS1";

    private const int DigestSize = 32;
    private const int MagicSize = 8;
    private const int HeaderSize = MagicSize + sizeof(ushort) + sizeof(ushort) + (sizeof(uint) * 6);
    private const int TotalLengthOffset = MagicSize + sizeof(ushort) + sizeof(ushort);
    private const string UnresolvedTargetMessage =
        "The semantic target remains unresolved and requires a sibling resolver.";
    private const string DeferredTargetMessage =
        "The semantic target is deferred to a layout or runtime resolver.";
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes(MagicText);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Creates a canonical snapshot from a semantic rewrite plan.
    /// </summary>
    public static SemanticPlanSnapshotResult Create(SemanticRewritePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return CreateCore(plan);
    }

    /// <summary>
    /// Alias for callers that use projection terminology at the handoff.
    /// </summary>
    public static SemanticPlanSnapshotResult Project(SemanticRewritePlan plan) => Create(plan);

    public static SemanticPlanSnapshotResult Encode(SemanticRewritePlan plan) => Create(plan);

    public static byte[] Serialize(SemanticPlanSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return snapshot.CanonicalBytes;
    }

    /// <summary>
    /// Decodes and validates a canonical snapshot. The digest is checked before
    /// any semantic record is accepted.
    /// </summary>
    public static SemanticPlanSnapshotResult Decode(ReadOnlyMemory<byte> canonicalBytes)
    {
        var diagnostics = new DiagnosticBag();
        if (canonicalBytes.Length < HeaderSize + DigestSize)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                "The semantic-plan snapshot is shorter than its bounded header and digest.");
            return Failure(diagnostics);
        }

        if (canonicalBytes.Length > SemanticPlanSnapshotLimits.MaximumCanonicalBytes)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                "The semantic-plan snapshot exceeds the maximum canonical byte length.");
            return Failure(diagnostics);
        }

        var bytes = canonicalBytes.Span;
        if (!bytes[..MagicSize].SequenceEqual(Magic))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot magic is invalid.");
            return Failure(diagnostics);
        }

        var storedDigest = bytes[^DigestSize..];
        var computedDigest = SHA256.HashData(bytes[..^DigestSize]);
        if (!CryptographicOperations.FixedTimeEquals(storedDigest, computedDigest))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotIntegrityMismatch,
                "The semantic-plan snapshot digest does not match its canonical bytes.");
            return Failure(diagnostics);
        }

        var reader = new SnapshotReader(canonicalBytes[..^DigestSize]);
        if (!reader.TrySkip(MagicSize)
            || !reader.TryReadUInt16(out var version)
            || !reader.TryReadUInt16(out var architecture)
            || !reader.TryReadUInt32(out var declaredLength)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumAddressMapEntries, out var mapCount)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumInstructions, out var instructionCount)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumFixups, out var fixupCount)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumExtensions, out var extensionCount)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumDiagnostics, out var diagnosticCount))
        {
            return MalformedReaderResult(reader, diagnostics);
        }

        if (version != Version)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                $"Semantic-plan snapshot version {version} is unsupported.");
            return Failure(diagnostics);
        }

        if (architecture != Aarch64Architecture)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                $"Semantic-plan snapshot architecture {architecture} is unsupported.");
            return Failure(diagnostics);
        }

        if (declaredLength != canonicalBytes.Length)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot declared length does not match its byte length.");
            return Failure(diagnostics);
        }

        var mapEntries = new List<AddressMapEntry>(mapCount);
        for (var index = 0; index < mapCount; index++)
        {
            if (!TryReadAddressMapEntry(reader, out var entry))
            {
                return MalformedReaderResult(reader, diagnostics);
            }

            mapEntries.Add(entry!);
        }

        var instructions = new List<SemanticInstruction>(instructionCount);
        for (var index = 0; index < instructionCount; index++)
        {
            if (!TryReadInstruction(reader, out var instruction))
            {
                return MalformedReaderResult(reader, diagnostics);
            }

            instructions.Add(instruction!);
        }

        var serializedFixupStates = new List<SemanticFixupResolutionState>(fixupCount);
        var fixups = new List<SemanticFixup>(fixupCount);
        for (var index = 0; index < fixupCount; index++)
        {
            if (!TryReadFixup(reader, out var fixup, out var state))
            {
                return MalformedReaderResult(reader, diagnostics);
            }

            fixups.Add(fixup!);
            serializedFixupStates.Add(state);
        }

        var extensions = new List<ISemanticPlanExtension>(extensionCount);
        for (var index = 0; index < extensionCount; index++)
        {
            if (!TryReadExtension(reader, out var extension))
            {
                return MalformedReaderResult(reader, diagnostics);
            }

            extensions.Add(extension!);
        }

        var planDiagnostics = new List<Diagnostic>(diagnosticCount);
        for (var index = 0; index < diagnosticCount; index++)
        {
            if (!TryReadDiagnostic(reader, out var diagnostic))
            {
                return MalformedReaderResult(reader, diagnostics);
            }

            planDiagnostics.Add(diagnostic);
        }

        if (!reader.IsAtEnd)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains trailing or unclaimed metadata.");
            return Failure(diagnostics);
        }

        var mapResult = AddressMap.Create(mapEntries);
        diagnostics.AddRange(mapResult.Diagnostics);
        if (!mapResult.IsSuccess || mapResult.Map is null)
        {
            return Failure(diagnostics);
        }

        SemanticRewritePlanResult planResult;
        try
        {
            planResult = SemanticRewritePlanBuilder.Build(
                mapResult.Map,
                instructions,
                fixups,
                extensions,
                planDiagnostics);
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains records that cannot form a semantic rewrite plan.");
            return Failure(diagnostics);
        }

        diagnostics.AddRange(planResult.Diagnostics);
        if (planResult.Plan is null || planResult.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return Failure(diagnostics);
        }

        var result = CreateCore(planResult.Plan);
        diagnostics.AddRange(result.Diagnostics);
        if (!result.IsSuccess || result.Snapshot is null)
        {
            return Failure(diagnostics);
        }

        if (serializedFixupStates.Count != result.Snapshot.Fixups.Count
            || serializedFixupStates.Where((state, index) =>
                state != result.Snapshot.Fixups[index].ResolutionState).Any())
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot fixup resolution classifications are not canonical.");
            return Failure(diagnostics);
        }

        if (!bytes.SequenceEqual(result.Snapshot.CanonicalBytes))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot records are valid but not in canonical order or form.");
            return Failure(diagnostics);
        }

        return new SemanticPlanSnapshotResult(result.Snapshot, diagnostics.ToArray());
    }

    public static SemanticPlanSnapshotResult Deserialize(ReadOnlyMemory<byte> canonicalBytes) =>
        Decode(canonicalBytes);

    public static SemanticPlanSnapshotResult Validate(ReadOnlyMemory<byte> canonicalBytes) =>
        Decode(canonicalBytes);

    /// <summary>
    /// Computes the one plan digest used by later artifact binders.
    /// </summary>
    public static string ComputeSha256(ReadOnlySpan<byte> canonicalBytes) =>
        Convert.ToHexString(SHA256.HashData(canonicalBytes)).ToLowerInvariant();

    public static string ComputePlanSha256(ReadOnlySpan<byte> canonicalBytes) =>
        ComputeSha256(canonicalBytes);

    public static bool VerifyDigest(
        ReadOnlyMemory<byte> canonicalBytes,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        var result = Decode(canonicalBytes);
        diagnostics = result.Diagnostics;
        return result.IsSuccess;
    }

    private static SemanticPlanSnapshotResult CreateCore(SemanticRewritePlan plan)
    {
        var diagnostics = new DiagnosticBag();
        var canonical = Canonicalize(plan, diagnostics);
        if (canonical is null || diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        var fixupSnapshots = canonical.Fixups
            .Select(fixup => new SemanticFixupSnapshot(fixup, GetResolutionState(fixup)))
            .ToArray();
        var classificationDiagnostics = CreateClassificationDiagnostics(fixupSnapshots);
        var combinedDiagnostics = DistinctDiagnostics(
            canonical.Diagnostics.Concat(classificationDiagnostics));
        if (combinedDiagnostics.Any(diagnostic => diagnostic.IsError))
        {
            diagnostics.AddRange(combinedDiagnostics);
            return Failure(diagnostics);
        }

        var canonicalPlan = new SemanticRewritePlan(
            canonical.AddressMap,
            canonical.Instructions,
            canonical.Fixups,
            canonical.Extensions,
            combinedDiagnostics);
        fixupSnapshots = canonicalPlan.Fixups
            .Select(fixup => new SemanticFixupSnapshot(fixup, GetResolutionState(fixup)))
            .ToArray();

        var withoutBytes = new SemanticPlanSnapshot(
            canonicalPlan,
            fixupSnapshots,
            Array.Empty<byte>(),
            string.Empty);
        if (!TrySerialize(withoutBytes, diagnostics, out var bytes))
        {
            return Failure(diagnostics);
        }

        var digest = ComputeSha256(bytes);
        var snapshot = new SemanticPlanSnapshot(canonicalPlan, fixupSnapshots, bytes, digest);
        return new SemanticPlanSnapshotResult(snapshot, DistinctDiagnostics(
            diagnostics.Concat(canonicalPlan.Diagnostics)));
    }

    private static CanonicalPlan? Canonicalize(
        SemanticRewritePlan plan,
        DiagnosticBag diagnostics)
    {
        if (plan.AddressMap is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic rewrite plan has no address map.");
            return null;
        }

        if (!ValidateCount(
                plan.AddressMap.Entries.Count,
                SemanticPlanSnapshotLimits.MaximumAddressMapEntries,
                "address-map entry",
                diagnostics)
            || !ValidateCount(
                plan.Instructions.Count,
                SemanticPlanSnapshotLimits.MaximumInstructions,
                "instruction",
                diagnostics)
            || !ValidateCount(
                plan.Fixups.Count,
                SemanticPlanSnapshotLimits.MaximumFixups,
                "fixup",
                diagnostics)
            || !ValidateCount(
                plan.Extensions.Count,
                SemanticPlanSnapshotLimits.MaximumExtensions,
                "extension",
                diagnostics)
            || !ValidateCount(
                plan.Diagnostics.Count,
                SemanticPlanSnapshotLimits.MaximumDiagnostics,
                "diagnostic",
                diagnostics))
        {
            return null;
        }

        foreach (var entry in plan.AddressMap.Entries)
        {
            ValidateAddressMapEntry(entry, diagnostics);
        }

        foreach (var instruction in plan.Instructions)
        {
            ValidateInstruction(instruction, diagnostics);
        }

        foreach (var fixup in plan.Fixups)
        {
            ValidateFixup(fixup, diagnostics);
        }

        var extensionKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var extension in plan.Extensions)
        {
            ValidateExtension(extension, extensionKeys, diagnostics);
        }

        foreach (var diagnostic in plan.Diagnostics)
        {
            ValidateDiagnostic(diagnostic, diagnostics);
        }

        if (diagnostics.HasErrors)
        {
            return null;
        }

        var sortedEntries = plan.AddressMap.Entries
            .OrderBy(entry => (int)entry.Identity.Kind)
            .ThenBy(entry => entry.Identity.Value, StringComparer.Ordinal)
            .ThenBy(entry => (int)entry.PlannedIdentity.Kind)
            .ThenBy(entry => entry.PlannedIdentity.Value, StringComparer.Ordinal)
            .ThenBy(entry => entry.SourceRange.VirtualAddress.Value)
            .ThenBy(entry => entry.SourceRange.FileOffset.Value)
            .ToArray();
        var mapResult = AddressMap.Create(sortedEntries);
        diagnostics.AddRange(mapResult.Diagnostics);
        if (!mapResult.IsSuccess || mapResult.Map is null)
        {
            return null;
        }

        var sortedInstructions = plan.Instructions
            .OrderBy(instruction => instruction.SourceVirtualAddress.Value)
            .ThenBy(instruction => instruction.SourceFileOffset.Value)
            .ThenBy(instruction => instruction.Encoding)
            .ToArray();
        var sortedFixups = plan.Fixups
            .OrderBy(fixup => fixup.SourceAddress.Value)
            .ThenBy(fixup => fixup.SourceFileOffset.Value)
            .ThenBy(fixup => (int)fixup.Kind)
            .ThenBy(fixup => fixup.OriginalEncoding)
            .ToArray();
        var sortedExtensions = plan.Extensions
            .OrderBy(extension => (int)extension.Kind)
            .ThenBy(GetExtensionSortKey, StringComparer.Ordinal)
            .ToArray();

        SemanticRewritePlanResult rebuilt;
        try
        {
            rebuilt = SemanticRewritePlanBuilder.Build(
                mapResult.Map,
                sortedInstructions,
                sortedFixups,
                sortedExtensions);
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic rewrite plan could not be rebuilt for canonical projection.");
            return null;
        }

        diagnostics.AddRange(rebuilt.Diagnostics);
        if (rebuilt.Plan is null || rebuilt.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return null;
        }

        var combinedDiagnostics = DistinctDiagnostics(
            plan.Diagnostics.Concat(rebuilt.Diagnostics));
        return new CanonicalPlan(
            mapResult.Map,
            sortedInstructions,
            sortedFixups,
            sortedExtensions,
            combinedDiagnostics);
    }

    private static List<Diagnostic> CreateClassificationDiagnostics(
        IReadOnlyList<SemanticFixupSnapshot> fixups)
    {
        var diagnostics = new List<Diagnostic>();
        foreach (var fixup in fixups)
        {
            switch (fixup.ResolutionState)
            {
                case SemanticFixupResolutionState.Deferred:
                    diagnostics.Add(new Diagnostic(
                        DiagnosticSeverity.Warning,
                        DiagnosticCode.SemanticFixupDeferred,
                        DeferredTargetMessage,
                        fixup.SourceFileOffset.Value));
                    break;
                case SemanticFixupResolutionState.Unresolved:
                    diagnostics.Add(new Diagnostic(
                        DiagnosticSeverity.Warning,
                        DiagnosticCode.SemanticTargetUnresolved,
                        UnresolvedTargetMessage,
                        fixup.SourceFileOffset.Value));
                    break;
            }
        }

        return diagnostics;
    }

    private static SemanticFixupResolutionState GetResolutionState(SemanticFixup fixup) =>
        fixup.Target.Resolution switch
        {
            SemanticTargetResolution.Exact => SemanticFixupResolutionState.Resolved,
            SemanticTargetResolution.BoundedSet
                or SemanticTargetResolution.RuntimeResolved => SemanticFixupResolutionState.Deferred,
            SemanticTargetResolution.Unresolved => SemanticFixupResolutionState.Unresolved,
            _ => SemanticFixupResolutionState.Unresolved,
        };

    private static Diagnostic[] DistinctDiagnostics(IEnumerable<Diagnostic> diagnostics) =>
        diagnostics
            .Distinct()
            .OrderBy(diagnostic => (int)diagnostic.Severity)
            .ThenBy(diagnostic => (int)diagnostic.Code)
            .ThenBy(diagnostic => diagnostic.Offset ?? ulong.MaxValue)
            .ThenBy(diagnostic => diagnostic.Message, StringComparer.Ordinal)
            .ToArray();

    private static bool TrySerialize(
        SemanticPlanSnapshot snapshot,
        DiagnosticBag diagnostics,
        out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        try
        {
            using var stream = new MemoryStream();
            using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(Magic);
                writer.Write(Version);
                writer.Write(Aarch64Architecture);
                writer.Write(0u);
                writer.Write(checked((uint)snapshot.AddressMapEntries.Count));
                writer.Write(checked((uint)snapshot.Instructions.Count));
                writer.Write(checked((uint)snapshot.Fixups.Count));
                writer.Write(checked((uint)snapshot.Extensions.Count));
                writer.Write(checked((uint)snapshot.Diagnostics.Count));

                var context = new CanonicalWriteContext(writer, diagnostics);
                foreach (var entry in snapshot.AddressMapEntries)
                {
                    WriteAddressMapEntry(context, entry);
                    context.EnsureWithinCanonicalLimit();
                }

                foreach (var instruction in snapshot.Instructions)
                {
                    WriteInstruction(context, instruction);
                    context.EnsureWithinCanonicalLimit();
                }

                foreach (var fixup in snapshot.Fixups)
                {
                    WriteFixup(context, fixup);
                    context.EnsureWithinCanonicalLimit();
                }

                foreach (var extension in snapshot.Extensions)
                {
                    WriteExtension(context, extension);
                    context.EnsureWithinCanonicalLimit();
                }

                foreach (var diagnostic in snapshot.Diagnostics)
                {
                    WriteDiagnostic(context, diagnostic);
                    context.EnsureWithinCanonicalLimit();
                }

                if (context.MetadataBytes > SemanticPlanSnapshotLimits.MaximumMetadataBytes)
                {
                    throw new SnapshotEncodingException(
                        "The semantic-plan snapshot metadata exceeds its bounded byte limit.",
                        DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
                }
            }

            if (stream.Length > SemanticPlanSnapshotLimits.MaximumCanonicalBytes - DigestSize
                || stream.Length > uint.MaxValue - DigestSize)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot exceeds its bounded canonical byte length.");
                return false;
            }

            bytes = stream.ToArray();
            var totalLength = checked(bytes.Length + DigestSize);
            BinaryPrimitives.WriteUInt32LittleEndian(
                bytes.AsSpan(TotalLengthOffset, sizeof(uint)),
                checked((uint)totalLength));
            var digest = SHA256.HashData(bytes);
            Array.Resize(ref bytes, totalLength);
            digest.CopyTo(bytes.AsSpan(totalLength - DigestSize));
            return true;
        }
        catch (SnapshotEncodingException exception)
        {
            diagnostics.Error(exception.Code, exception.Message);
            return false;
        }
        catch (Exception exception) when (exception is EncoderFallbackException or OverflowException)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot could not be encoded in its bounded canonical representation.");
            return false;
        }
    }

    private static SemanticPlanSnapshotResult Failure(DiagnosticBag diagnostics) =>
        new(null, diagnostics.ToArray());

    private static SemanticPlanSnapshotResult MalformedReaderResult(
        SnapshotReader reader,
        DiagnosticBag diagnostics)
    {
        diagnostics.Error(
            reader.FailureCode,
            reader.FailureMessage ?? "The semantic-plan snapshot is truncated or malformed.",
            reader.FailureOffset);
        return Failure(diagnostics);
    }

    private static bool ValidateCount(
        int count,
        int maximum,
        string name,
        DiagnosticBag diagnostics)
    {
        if (count >= 0 && count <= maximum)
        {
            return true;
        }

        diagnostics.Error(
            DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
            $"The semantic-plan snapshot contains too many {name} records (maximum {maximum}).");
        return false;
    }

    private static void ValidateAddressMapEntry(
        AddressMapEntry? entry,
        DiagnosticBag diagnostics)
    {
        if (entry is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null address-map entry.");
            return;
        }

        ValidateEntityId(entry.Identity, "address-map source identity", diagnostics);
        if (entry.OutputIdentity is { } outputIdentity)
        {
            ValidateEntityId(outputIdentity, "address-map output identity", diagnostics);
        }

        ValidateRange(entry.SourceRange, "address-map source", diagnostics);
        ValidateRange(entry.OutputRange, "address-map output", diagnostics);
    }

    private static void ValidateInstruction(
        SemanticInstruction? instruction,
        DiagnosticBag diagnostics)
    {
        if (instruction is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null semantic instruction.");
            return;
        }

        ValidateString(instruction.Mnemonic, "instruction mnemonic", false, diagnostics);
        ValidateRange(instruction.SourceRange, "instruction source", diagnostics);
        if (instruction.SourceRange.FileOffset != instruction.SourceFileOffset
            || instruction.SourceRange.VirtualAddress != instruction.SourceVirtualAddress
            || !instruction.SourceRange.IsInstructionRange)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic instruction does not carry a matching aligned source range.",
                instruction.SourceFileOffset.Value);
        }

        ValidateCount(
            instruction.Operands.Count,
            SemanticPlanSnapshotLimits.MaximumOperandsPerInstruction,
            "instruction operand",
            diagnostics);
        foreach (var operand in instruction.Operands)
        {
            ValidateOperand(operand, diagnostics, instruction.SourceFileOffset.Value);
        }

        ValidateCount(
            instruction.RegisterEffects.Count,
            SemanticPlanSnapshotLimits.MaximumRegisterEffectsPerInstruction,
            "instruction register-effect",
            diagnostics);
        foreach (var effect in instruction.RegisterEffects)
        {
            ValidateRegisterEffect(effect, diagnostics, instruction.SourceFileOffset.Value);
        }

        const SemanticFlagEffects knownFlags = SemanticFlagEffects.ReadNzcv | SemanticFlagEffects.WriteNzcv;
        if ((instruction.FlagEffects & ~knownFlags) != SemanticFlagEffects.None)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic instruction contains unsupported flag-effect bits.",
                instruction.SourceFileOffset.Value);
        }

        if (!Enum.IsDefined(typeof(Aarch64ControlFlowKind), instruction.ControlFlow))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic instruction contains an unsupported control-flow kind.",
                instruction.SourceFileOffset.Value);
        }

        ValidateTarget(instruction.ControlFlowTarget, "instruction control-flow target", diagnostics, instruction.SourceFileOffset.Value);
        ValidateExpression(instruction.PcRelativeExpression, diagnostics, instruction.SourceFileOffset.Value);
        ValidateLiteral(instruction.LiteralReference, diagnostics, instruction.SourceFileOffset.Value);

        ValidateCount(
            instruction.Relocations.Count,
            SemanticPlanSnapshotLimits.MaximumRelocationsPerInstruction,
            "instruction relocation",
            diagnostics);
        foreach (var relocation in instruction.Relocations)
        {
            ValidateRelocation(relocation, diagnostics, instruction.SourceFileOffset.Value);
        }

        ValidateCount(
            instruction.References.Count,
            SemanticPlanSnapshotLimits.MaximumReferencesPerInstruction,
            "instruction reference",
            diagnostics);
        foreach (var reference in instruction.References)
        {
            ValidateReference(reference, diagnostics, instruction.SourceFileOffset.Value);
        }
    }

    private static void ValidateOperand(
        SemanticOperand? operand,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (operand is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic instruction contains a null operand.",
                offset);
            return;
        }

        ValidateString(operand.Name, "operand name", false, diagnostics, offset);
        ValidateString(operand.Codec, "operand codec", false, diagnostics, offset);
        ValidateOptionalString(operand.TiedTo, "operand tie", diagnostics, offset);
        ValidateString(operand.SemanticDomain, "operand semantic domain", false, diagnostics, offset);
        if (!Enum.IsDefined(typeof(Aarch64OperandKind), operand.Kind)
            || !Enum.IsDefined(typeof(Aarch64OperandDirection), operand.Direction))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic operand contains an unsupported operand enum value.",
                offset);
        }

        ValidateRegisterConstraint(operand.RegisterConstraint, diagnostics, offset);
        if (operand.Register is { } register)
        {
            ValidateRegister(register, diagnostics, offset);
        }

        ValidateCount(
            operand.Registers.Count,
            SemanticPlanSnapshotLimits.MaximumCandidates,
            "operand register",
            diagnostics);
        foreach (var listRegister in operand.Registers)
        {
            ValidateRegister(listRegister, diagnostics, offset);
        }

        if (operand.Memory is { } memory)
        {
            ValidateRegister(memory.Base, diagnostics, offset);
            if (memory.Index is { } index)
            {
                ValidateRegister(index, diagnostics, offset);
            }

            ValidateString(memory.AddressingMode, "memory addressing mode", false, diagnostics, offset);
            ValidateString(memory.Ordering, "memory ordering", false, diagnostics, offset);
            if (memory.AccessSize <= 0 || memory.AccessSize > 4096)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A semantic memory operand has an invalid access size.",
                    offset);
            }
        }

        ValidatePositiveWidth(operand.RegisterWidth, "operand register width", diagnostics, offset);
        ValidatePositiveWidth(operand.FieldWidth, "operand field width", diagnostics, offset);
        ValidatePositiveWidth(operand.ElementWidth, "operand element width", diagnostics, offset);
    }

    private static void ValidateRegisterConstraint(
        Aarch64RegisterConstraint constraint,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (constraint.MinimumIndex < 0
            || constraint.MaximumIndex < constraint.MinimumIndex
            || constraint.MaximumIndex > 31
            || constraint.Step < 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic operand register constraint is outside the bounded AArch64 register domain.",
                offset);
        }
    }

    private static void ValidateRegisterEffect(
        SemanticRegisterEffect effect,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        ValidateRegister(effect.Register, diagnostics, offset);
        if (!Enum.IsDefined(typeof(SemanticRegisterEffectKind), effect.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic register effect contains an unsupported effect kind.",
                offset);
        }
    }

    private static void ValidateRegister(
        Aarch64RegisterView register,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (!Enum.IsDefined(typeof(Aarch64RegisterClass), register.Class)
            || !Enum.IsDefined(typeof(Aarch64RegisterRole), register.Role)
            || register.Index > 31
            || register.Width == 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic register view is outside the bounded AArch64 register domain.",
                offset);
        }
    }

    private static void ValidatePositiveWidth(
        int width,
        string name,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (width <= 0 || width > 4096)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"A {name} is outside the bounded width domain.",
                offset);
        }
    }

    private static void ValidateExpression(
        PcRelativeExpression? expression,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (expression is null)
        {
            return;
        }

        if (!Enum.IsDefined(typeof(PcRelativeExpressionKind), expression.Kind)
            || expression.Scale <= 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A PC-relative expression has an unsupported kind or scale.",
                offset);
        }

        ValidateTarget(expression.Target, "PC-relative expression target", diagnostics, offset, required: true);
    }

    private static void ValidateLiteral(
        LiteralReference? literal,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (literal is null)
        {
            return;
        }

        if (literal.AccessSize <= 0 || literal.AccessSize > 4096)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A literal reference has an invalid access size.",
                offset);
        }

        ValidateTarget(literal.Target, "literal target", diagnostics, offset, required: true);
        if (literal.PoolRange is { } poolRange)
        {
            ValidateRange(poolRange, "literal pool", diagnostics, offset);
        }
    }

    private static void ValidateReference(
        SemanticReference? reference,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (reference is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic instruction contains a null reference.",
                offset);
            return;
        }

        if (!Enum.IsDefined(typeof(SemanticReferenceKind), reference.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic reference contains an unsupported reference kind.",
                offset);
        }

        ValidateTarget(reference.Target, "semantic reference target", diagnostics, offset, required: true);
        ValidateExpression(reference.PcRelative, diagnostics, offset);
        ValidateLiteral(reference.Literal, diagnostics, offset);
        ValidateRelocation(reference.Relocation, diagnostics, offset);
        ValidateOptionalString(reference.Description, "reference description", diagnostics, offset);
    }

    private static void ValidateFixup(
        SemanticFixup? fixup,
        DiagnosticBag diagnostics)
    {
        if (fixup is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null fixup.");
            return;
        }

        var offset = fixup.SourceFileOffset.Value;
        if (!Enum.IsDefined(typeof(SemanticFixupKind), fixup.Kind)
            || !Enum.IsDefined(typeof(SemanticRelaxationKind), fixup.Relaxation))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic fixup contains an unsupported kind or relaxation.",
                offset);
        }

        ValidateRange(fixup.SourceRange, "fixup source", diagnostics, offset);
        if (fixup.SourceRange.FileOffset != fixup.SourceFileOffset
            || fixup.SourceRange.VirtualAddress != fixup.SourceAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic fixup does not carry a matching source range.",
                offset);
        }

        if (fixup.Kind != SemanticFixupKind.Relocation && !fixup.SourceRange.IsInstructionRange)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "An instruction fixup does not cover one aligned AArch64 instruction.",
                offset);
        }

        ValidateTarget(fixup.Target, "fixup target", diagnostics, offset, required: true);
        ValidateExpression(fixup.Expression, diagnostics, offset);
        ValidateRelocation(fixup.Relocation, diagnostics, offset);
        ValidateCount(
            fixup.RelaxationOptions.Count,
            SemanticPlanSnapshotLimits.MaximumRelaxationOptions,
            "fixup relaxation option",
            diagnostics);
        var relaxationOptions = new HashSet<SemanticRelaxationKind>();
        foreach (var option in fixup.RelaxationOptions)
        {
            if (!Enum.IsDefined(typeof(SemanticRelaxationKind), option)
                || !relaxationOptions.Add(option))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A semantic fixup contains duplicate or unsupported relaxation options.",
                    offset);
            }
        }

        if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Relocation is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A relocation fixup has no relocation binding.",
                offset);
        }

        if (fixup.Kind != SemanticFixupKind.Relocation && fixup.Expression is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A PC-relative fixup has no PC-relative expression.",
                offset);
        }
    }

    private static void ValidateRelocation(
        RelocationBinding? relocation,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (relocation is null)
        {
            return;
        }

        if (!Enum.IsDefined(typeof(Aarch64RelocationKind), relocation.Kind)
            || !relocation.IsKindConsistent)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A relocation binding has an unsupported or inconsistent raw AArch64 type/info pair.",
                offset);
        }

        ValidateTarget(relocation.Target, "relocation target", diagnostics, offset, required: true);
        ValidateOptionalString(relocation.SymbolName, "relocation symbol", diagnostics, offset);
    }

    private static void ValidateTarget(
        SemanticTarget? target,
        string name,
        DiagnosticBag diagnostics,
        ulong offset,
        bool required = false)
    {
        if (target is null)
        {
            if (required)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"A {name} is null.",
                    offset);
            }

            return;
        }

        if (!Enum.IsDefined(typeof(SemanticTargetResolution), target.Resolution))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                $"A {name} has an unsupported resolution state.",
                offset);
        }

        if (target.Identity is { } identity)
        {
            ValidateEntityId(identity, $"{name} identity", diagnostics, offset);
        }

        ValidateCount(
            target.CandidateIdentities.Count,
            SemanticPlanSnapshotLimits.MaximumCandidates,
            $"{name} candidate identity",
            diagnostics);
        var candidateIdentities = new HashSet<SemanticEntityId>();
        foreach (var candidateIdentity in target.CandidateIdentities)
        {
            ValidateEntityId(candidateIdentity, $"{name} candidate identity", diagnostics, offset);
            if (!candidateIdentities.Add(candidateIdentity))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"A {name} contains duplicate candidate identities.",
                    offset);
            }
        }

        ValidateCount(
            target.CandidateAddresses.Count,
            SemanticPlanSnapshotLimits.MaximumCandidates,
            $"{name} candidate address",
            diagnostics);
        var candidateAddresses = new HashSet<VirtualAddress>();
        foreach (var candidateAddress in target.CandidateAddresses)
        {
            if (!candidateAddresses.Add(candidateAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"A {name} contains duplicate candidate addresses.",
                    offset);
            }
        }

        ValidateOptionalString(target.RuntimeBinding, $"{name} runtime binding", diagnostics, offset);
        ValidateOptionalString(target.Diagnostic, $"{name} diagnostic", diagnostics, offset);
        switch (target.Resolution)
        {
            case SemanticTargetResolution.Exact
                when target.SourceAddress is null && target.Identity is null:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"An exact {name} has neither a source address nor an entity identity.",
                    offset);
                break;
            case SemanticTargetResolution.BoundedSet
                when target.CandidateAddresses.Count == 0 && target.CandidateIdentities.Count == 0:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"A bounded {name} has no candidates.",
                    offset);
                break;
            case SemanticTargetResolution.RuntimeResolved
                when string.IsNullOrWhiteSpace(target.RuntimeBinding):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"A runtime-resolved {name} has no binding identity.",
                    offset);
                break;
            case SemanticTargetResolution.Unresolved
                when string.IsNullOrWhiteSpace(target.Diagnostic):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"An unresolved {name} has no diagnostic.",
                    offset);
                break;
        }
    }

    private static void ValidateExtension(
        ISemanticPlanExtension? extension,
        HashSet<string> extensionKeys,
        DiagnosticBag diagnostics)
    {
        if (extension is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null extension.");
            return;
        }

        if (!Enum.IsDefined(typeof(SemanticPlanExtensionKind), extension.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported extension kind.");
            return;
        }

        var key = GetExtensionIdentityKey(extension);
        if (!extensionKeys.Add(key))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains duplicate extension identities.");
        }

        switch (extension)
        {
            case SemanticIndirectTargetExtension indirect:
                ValidateEntityId(indirect.SourceInstruction, "indirect-target source identity", diagnostics, indirect.SourceAddress.Value);
                ValidateTarget(indirect.Target, "indirect-target target", diagnostics, indirect.SourceAddress.Value, required: true);
                ValidateString(indirect.Diagnostic, "indirect-target diagnostic", false, diagnostics, indirect.SourceAddress.Value);
                break;
            case SemanticUnresolvedReferenceExtension unresolved:
                ValidateEntityId(unresolved.SourceInstruction, "unresolved-reference source identity", diagnostics, unresolved.SourceAddress.Value);
                ValidateTarget(unresolved.Target, "unresolved-reference target", diagnostics, unresolved.SourceAddress.Value, required: true);
                ValidateString(unresolved.Diagnostic, "unresolved-reference diagnostic", false, diagnostics, unresolved.SourceAddress.Value);
                if (!Enum.IsDefined(typeof(SemanticReferenceKind), unresolved.ReferenceKind))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotUnsupported,
                        "An unresolved-reference extension has an unsupported reference kind.",
                        unresolved.SourceAddress.Value);
                }

                break;
            case SemanticRelocationBindingExtension relocation:
                ValidateEntityId(relocation.RelocationSite, "relocation-extension site identity", diagnostics);
                ValidateRelocation(relocation.Binding, diagnostics, relocation.Binding.RelocationAddress?.Value ?? 0);
                ValidateString(relocation.Diagnostic, "relocation-extension diagnostic", false, diagnostics);
                break;
            case SemanticTlsBindingExtension tls:
                ValidateEntityId(tls.SourceIdentity, "TLS source identity", diagnostics);
                ValidateRange(tls.SourceRange, "TLS source", diagnostics);
                ValidateRelocation(tls.Binding, diagnostics, tls.SourceRange.FileOffset.Value);
                ValidateString(tls.Model, "TLS model", false, diagnostics);
                ValidateOptionalString(tls.Diagnostic, "TLS diagnostic", diagnostics);
                break;
            case SemanticJumpTableExtension jumpTable:
                ValidateEntityId(jumpTable.TableIdentity, "jump-table identity", diagnostics);
                ValidateRange(jumpTable.TableRange, "jump-table range", diagnostics);
                ValidatePositiveWidth(jumpTable.EntrySize, "jump-table entry size", diagnostics, jumpTable.TableRange.FileOffset.Value);
                ValidateOptionalString(jumpTable.Encoding, "jump-table encoding", diagnostics);
                ValidateCount(
                    jumpTable.Targets.Count,
                    SemanticPlanSnapshotLimits.MaximumTargetsPerJumpTable,
                    "jump-table target",
                    diagnostics);
                foreach (var target in jumpTable.Targets)
                {
                    ValidateTarget(target, "jump-table target", diagnostics, jumpTable.TableRange.FileOffset.Value, required: true);
                }

                break;
            case SemanticCfiEffectExtension cfi:
                ValidateEntityId(cfi.SourceIdentity, "CFI source identity", diagnostics);
                ValidateRange(cfi.SourceRange, "CFI source", diagnostics);
                ValidateString(cfi.Effect, "CFI effect", false, diagnostics);
                ValidateCount(
                    cfi.RegisterEffects.Count,
                    SemanticPlanSnapshotLimits.MaximumCfiRegisterEffects,
                    "CFI register effect",
                    diagnostics);
                foreach (var effect in cfi.RegisterEffects)
                {
                    ValidateRegisterEffect(effect, diagnostics, cfi.SourceRange.FileOffset.Value);
                }

                ValidateOptionalString(cfi.Diagnostic, "CFI diagnostic", diagnostics);
                break;
            default:
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    $"The semantic-plan extension type '{extension.GetType().Name}' has no canonical projection.");
                break;
        }
    }

    private static void ValidateDiagnostic(
        Diagnostic? diagnostic,
        DiagnosticBag diagnostics)
    {
        if (diagnostic is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null diagnostic.");
            return;
        }

        var actual = diagnostic.Value;
        if (!Enum.IsDefined(typeof(DiagnosticSeverity), actual.Severity)
            || !Enum.IsDefined(typeof(DiagnosticCode), actual.Code))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported diagnostic enum value.");
        }

        ValidateString(actual.Message, "diagnostic message", false, diagnostics, actual.Offset);
    }

    private static void ValidateRange(
        SemanticSourceRange range,
        string name,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (range.Size == 0
            || !range.TryGetFileEnd(out _)
            || !range.TryGetVirtualEnd(out _))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"The {name} range is empty or overflows its typed address domains.",
                offset);
        }
    }

    private static void ValidateEntityId(
        SemanticEntityId identity,
        string name,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (!Enum.IsDefined(typeof(SemanticEntityKind), identity.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                $"The {name} has an unsupported entity kind.",
                offset);
        }

        if (string.IsNullOrWhiteSpace(identity.Value))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"The {name} must be non-empty.",
                offset);
            return;
        }

        ValidateString(identity.Value, name, false, diagnostics, offset);
    }

    private static void ValidateString(
        string? value,
        string name,
        bool allowNull,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (value is null)
        {
            if (!allowNull)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"The {name} is null.",
                    offset);
            }

            return;
        }

        try
        {
            if (StrictUtf8.GetByteCount(value) > SemanticPlanSnapshotLimits.MaximumStringBytes)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    $"The {name} exceeds the maximum UTF-8 metadata length.",
                    offset);
            }
        }
        catch (EncoderFallbackException)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"The {name} is not valid UTF-8 text.",
                offset);
        }
    }

    private static void ValidateOptionalString(
        string? value,
        string name,
        DiagnosticBag diagnostics,
        ulong? offset = null) =>
        ValidateString(value, name, true, diagnostics, offset);

    private static string GetExtensionIdentityKey(ISemanticPlanExtension extension) =>
        extension switch
        {
            SemanticIndirectTargetExtension indirect =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(indirect.SourceInstruction)
                + GetUlongSortKey(indirect.SourceAddress.Value),
            SemanticUnresolvedReferenceExtension unresolved =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(unresolved.SourceInstruction)
                + GetUlongSortKey(unresolved.SourceAddress.Value)
                + GetIntSortKey((int)unresolved.ReferenceKind),
            SemanticRelocationBindingExtension relocation =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(relocation.RelocationSite),
            SemanticTlsBindingExtension tls =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(tls.SourceIdentity),
            SemanticJumpTableExtension jumpTable =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(jumpTable.TableIdentity),
            SemanticCfiEffectExtension cfi =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(cfi.SourceIdentity),
            _ => GetIntSortKey((int)extension.Kind)
                + GetOptionalStringSortKey(extension.GetType().FullName),
        };

    private static string GetExtensionSortKey(ISemanticPlanExtension extension) =>
        GetExtensionIdentityKey(extension)
        + GetOptionalStringSortKey(extension.GetType().FullName);

    private sealed record CanonicalPlan(
        AddressMap AddressMap,
        IReadOnlyList<SemanticInstruction> Instructions,
        IReadOnlyList<SemanticFixup> Fixups,
        IReadOnlyList<ISemanticPlanExtension> Extensions,
        IReadOnlyList<Diagnostic> Diagnostics);

    private sealed class SnapshotEncodingException : Exception
    {
        public SnapshotEncodingException(string message, DiagnosticCode code)
            : base(message)
        {
            Code = code;
        }

        public DiagnosticCode Code { get; }
    }

    private static void WriteAddressMapEntry(CanonicalWriteContext context, AddressMapEntry entry)
    {
        WriteEntityId(context, entry.Identity);
        WriteOptionalEntityId(context, entry.OutputIdentity);
        WriteRange(context, entry.SourceRange);
        WriteRange(context, entry.OutputRange);
    }

    private static void WriteInstruction(CanonicalWriteContext context, SemanticInstruction instruction)
    {
        context.Writer.Write(instruction.SourceVirtualAddress.Value);
        context.Writer.Write(instruction.SourceFileOffset.Value);
        context.WriteString(instruction.Mnemonic);
        context.Writer.Write(instruction.Encoding);
        WriteRange(context, instruction.SourceRange);

        context.WriteCount(instruction.Operands.Count);
        foreach (var operand in instruction.Operands)
        {
            WriteOperand(context, operand);
            context.EnsureWithinCanonicalLimit();
        }

        var registerEffects = instruction.RegisterEffects
            .OrderBy(effect => GetRegisterSortKey(effect.Register), StringComparer.Ordinal)
            .ThenBy(effect => (int)effect.Kind)
            .ThenBy(effect => effect.IsImplicit)
            .ToArray();
        context.WriteCount(registerEffects.Length);
        foreach (var effect in registerEffects)
        {
            WriteRegisterEffect(context, effect);
            context.EnsureWithinCanonicalLimit();
        }

        context.Writer.Write((byte)instruction.FlagEffects);
        context.Writer.Write((byte)instruction.ControlFlow);
        WriteOptionalTarget(context, instruction.ControlFlowTarget);
        WriteOptionalExpression(context, instruction.PcRelativeExpression);
        WriteOptionalLiteral(context, instruction.LiteralReference);

        var relocations = instruction.Relocations
            .OrderBy(GetRelocationSortKey, StringComparer.Ordinal)
            .ToArray();
        context.WriteCount(relocations.Length);
        foreach (var relocation in relocations)
        {
            WriteRelocation(context, relocation);
            context.EnsureWithinCanonicalLimit();
        }

        var references = instruction.References
            .OrderBy(reference => GetReferenceSortKey(reference), StringComparer.Ordinal)
            .ToArray();
        context.WriteCount(references.Length);
        foreach (var reference in references)
        {
            WriteReference(context, reference);
            context.EnsureWithinCanonicalLimit();
        }

        context.Writer.Write(instruction.OpaquePreservation ? (byte)1 : (byte)0);
    }

    private static void WriteOperand(CanonicalWriteContext context, SemanticOperand operand)
    {
        context.WriteString(operand.Name);
        context.Writer.Write((byte)operand.Kind);
        context.Writer.Write((byte)operand.Direction);
        context.Writer.Write(operand.IsImplicit ? (byte)1 : (byte)0);
        context.WriteString(operand.Codec);
        context.WriteOptionalString(operand.TiedTo);
        WriteOptionalRegister(context, operand.Register);
        context.WriteCount(operand.Registers.Count);
        foreach (var register in operand.Registers)
        {
            WriteRegister(context, register);
            context.EnsureWithinCanonicalLimit();
        }

        WriteOptionalMemory(context, operand.Memory);
        WriteOptionalInt64(context, operand.Immediate);
        WriteOptionalUInt64(context, operand.Target);
        WriteRegisterConstraint(context, operand.RegisterConstraint);
        context.Writer.Write(operand.RegisterWidth);
        context.Writer.Write(operand.FieldWidth);
        context.Writer.Write(operand.ElementWidth);
        context.Writer.Write(operand.AllowsStackPointer ? (byte)1 : (byte)0);
        context.Writer.Write(operand.AllowsZeroRegister ? (byte)1 : (byte)0);
        context.Writer.Write(operand.IsPageRelative ? (byte)1 : (byte)0);
        context.WriteString(operand.SemanticDomain);
    }

    private static void WriteRegisterEffect(CanonicalWriteContext context, SemanticRegisterEffect effect)
    {
        WriteRegister(context, effect.Register);
        context.Writer.Write((byte)effect.Kind);
        context.Writer.Write(effect.IsImplicit ? (byte)1 : (byte)0);
    }

    private static void WriteRegister(CanonicalWriteContext context, Aarch64RegisterView register)
    {
        context.Writer.Write((byte)register.Class);
        context.Writer.Write(register.Index);
        context.Writer.Write(register.Width);
        context.Writer.Write((byte)register.Role);
    }

    private static void WriteRegisterConstraint(
        CanonicalWriteContext context,
        Aarch64RegisterConstraint constraint)
    {
        context.Writer.Write(constraint.MinimumIndex);
        context.Writer.Write(constraint.MaximumIndex);
        context.Writer.Write(constraint.Step);
        context.Writer.Write(constraint.AllowedMask);
    }

    private static void WriteOptionalRegister(
        CanonicalWriteContext context,
        Aarch64RegisterView? register)
    {
        context.Writer.Write(register.HasValue ? (byte)1 : (byte)0);
        if (register is { } value)
        {
            WriteRegister(context, value);
        }
    }

    private static void WriteOptionalMemory(
        CanonicalWriteContext context,
        Aarch64MemoryReference? memory)
    {
        context.Writer.Write(memory is not null ? (byte)1 : (byte)0);
        if (memory is not { } value)
        {
            return;
        }

        WriteRegister(context, value.Base);
        WriteOptionalRegister(context, value.Index);
        context.Writer.Write(value.Offset);
        context.WriteString(value.AddressingMode);
        WriteOptionalUInt32(context, value.IndexModifier);
        context.Writer.Write(value.AccessSize);
        context.WriteString(value.Ordering);
        context.Writer.Write(value.WritesBack ? (byte)1 : (byte)0);
    }

    private static void WriteOptionalTarget(
        CanonicalWriteContext context,
        SemanticTarget? target)
    {
        context.Writer.Write(target is not null ? (byte)1 : (byte)0);
        if (target is not null)
        {
            WriteTarget(context, target);
        }
    }

    private static void WriteTarget(CanonicalWriteContext context, SemanticTarget target)
    {
        context.Writer.Write((byte)target.Resolution);
        WriteOptionalUInt64(context, target.SourceAddress?.Value);
        WriteOptionalEntityId(context, target.Identity);

        var identities = target.CandidateIdentities
            .OrderBy(identity => (int)identity.Kind)
            .ThenBy(identity => identity.Value, StringComparer.Ordinal)
            .ToArray();
        context.WriteCount(identities.Length);
        foreach (var identity in identities)
        {
            WriteEntityId(context, identity);
            context.EnsureWithinCanonicalLimit();
        }

        var addresses = target.CandidateAddresses.OrderBy(address => address.Value).ToArray();
        context.WriteCount(addresses.Length);
        foreach (var address in addresses)
        {
            context.Writer.Write(address.Value);
            context.EnsureWithinCanonicalLimit();
        }

        context.WriteOptionalString(target.RuntimeBinding);
        context.WriteOptionalString(target.Diagnostic);
    }

    private static void WriteOptionalExpression(
        CanonicalWriteContext context,
        PcRelativeExpression? expression)
    {
        context.Writer.Write(expression is not null ? (byte)1 : (byte)0);
        if (expression is null)
        {
            return;
        }

        context.Writer.Write((byte)expression.Kind);
        context.Writer.Write(expression.Place.Value);
        WriteTarget(context, expression.Target);
        context.Writer.Write(expression.Scale);
        context.Writer.Write(expression.IsPageRelative ? (byte)1 : (byte)0);
        context.Writer.Write(expression.Addend);
    }

    private static void WriteOptionalLiteral(
        CanonicalWriteContext context,
        LiteralReference? literal)
    {
        context.Writer.Write(literal is not null ? (byte)1 : (byte)0);
        if (literal is null)
        {
            return;
        }

        WriteTarget(context, literal.Target);
        context.Writer.Write(literal.AccessSize);
        context.Writer.Write(literal.IsLoad ? (byte)1 : (byte)0);
        WriteOptionalRange(context, literal.PoolRange);
    }

    private static void WriteRelocation(CanonicalWriteContext context, RelocationBinding relocation)
    {
        context.Writer.Write((byte)relocation.Kind);
        WriteTarget(context, relocation.Target);
        context.Writer.Write(relocation.Addend);
        context.Writer.Write(relocation.SymbolIndex);
        context.Writer.Write(relocation.IsPlt ? (byte)1 : (byte)0);
        context.WriteOptionalString(relocation.SymbolName);
        WriteOptionalUInt32(context, relocation.RelocationType);
        WriteOptionalUInt64(context, relocation.RawInfo);
        WriteOptionalUInt64(context, relocation.RelocationAddress?.Value);
        WriteOptionalUInt64(context, relocation.RelocationTableAddress?.Value);
    }

    private static void WriteReference(CanonicalWriteContext context, SemanticReference reference)
    {
        context.Writer.Write((byte)reference.Kind);
        WriteTarget(context, reference.Target);
        context.Writer.Write(reference.OperandIndex);
        WriteOptionalExpression(context, reference.PcRelative);
        WriteOptionalLiteral(context, reference.Literal);
        WriteOptionalRelocation(context, reference.Relocation);
        context.WriteOptionalString(reference.Description);
    }

    private static void WriteOptionalRelocation(
        CanonicalWriteContext context,
        RelocationBinding? relocation)
    {
        context.Writer.Write(relocation is not null ? (byte)1 : (byte)0);
        if (relocation is not null)
        {
            WriteRelocation(context, relocation);
        }
    }

    private static void WriteRange(CanonicalWriteContext context, SemanticSourceRange range)
    {
        context.Writer.Write(range.FileOffset.Value);
        context.Writer.Write(range.VirtualAddress.Value);
        context.Writer.Write(range.Size);
    }

    private static void WriteOptionalRange(
        CanonicalWriteContext context,
        SemanticSourceRange? range)
    {
        context.Writer.Write(range.HasValue ? (byte)1 : (byte)0);
        if (range is { } value)
        {
            WriteRange(context, value);
        }
    }

    private static void WriteEntityId(CanonicalWriteContext context, SemanticEntityId identity)
    {
        context.Writer.Write((byte)identity.Kind);
        context.WriteString(identity.Value);
    }

    private static void WriteOptionalEntityId(
        CanonicalWriteContext context,
        SemanticEntityId? identity)
    {
        context.Writer.Write(identity.HasValue ? (byte)1 : (byte)0);
        if (identity is { } value)
        {
            WriteEntityId(context, value);
        }
    }

    private static void WriteFixup(CanonicalWriteContext context, SemanticFixupSnapshot snapshot)
    {
        var fixup = snapshot.Fixup;
        context.Writer.Write((byte)snapshot.ResolutionState);
        context.Writer.Write((byte)fixup.Kind);
        context.Writer.Write(fixup.SourceAddress.Value);
        context.Writer.Write(fixup.SourceFileOffset.Value);
        context.Writer.Write(fixup.OriginalEncoding);
        WriteTarget(context, fixup.Target);
        WriteRange(context, fixup.SourceRange);
        WriteOptionalExpression(context, fixup.Expression);
        WriteOptionalRelocation(context, fixup.Relocation);
        context.Writer.Write((byte)fixup.Relaxation);
        var options = fixup.RelaxationOptions
            .Distinct()
            .OrderBy(option => (int)option)
            .ToArray();
        context.WriteCount(options.Length);
        foreach (var option in options)
        {
            context.Writer.Write((byte)option);
            context.EnsureWithinCanonicalLimit();
        }
    }

    private static void WriteExtension(
        CanonicalWriteContext context,
        ISemanticPlanExtension extension)
    {
        context.Writer.Write((byte)extension.Kind);
        switch (extension)
        {
            case SemanticIndirectTargetExtension indirect:
                WriteEntityId(context, indirect.SourceInstruction);
                context.Writer.Write(indirect.SourceAddress.Value);
                WriteTarget(context, indirect.Target);
                context.WriteString(indirect.Diagnostic);
                break;
            case SemanticUnresolvedReferenceExtension unresolved:
                WriteEntityId(context, unresolved.SourceInstruction);
                context.Writer.Write(unresolved.SourceAddress.Value);
                context.Writer.Write((byte)unresolved.ReferenceKind);
                WriteTarget(context, unresolved.Target);
                context.WriteString(unresolved.Diagnostic);
                break;
            case SemanticRelocationBindingExtension relocation:
                WriteEntityId(context, relocation.RelocationSite);
                WriteRelocation(context, relocation.Binding);
                context.WriteString(relocation.Diagnostic);
                break;
            case SemanticTlsBindingExtension tls:
                WriteEntityId(context, tls.SourceIdentity);
                WriteRange(context, tls.SourceRange);
                context.WriteString(tls.Model);
                WriteRelocation(context, tls.Binding);
                context.WriteOptionalString(tls.Diagnostic);
                break;
            case SemanticJumpTableExtension jumpTable:
                WriteEntityId(context, jumpTable.TableIdentity);
                WriteRange(context, jumpTable.TableRange);
                context.Writer.Write(jumpTable.EntrySize);
                context.WriteOptionalString(jumpTable.Encoding);
                var targets = jumpTable.Targets
                    .OrderBy(target => GetTargetSortKey(target), StringComparer.Ordinal)
                    .ToArray();
                context.WriteCount(targets.Length);
                foreach (var target in targets)
                {
                    WriteTarget(context, target);
                    context.EnsureWithinCanonicalLimit();
                }

                break;
            case SemanticCfiEffectExtension cfi:
                WriteEntityId(context, cfi.SourceIdentity);
                WriteRange(context, cfi.SourceRange);
                context.WriteString(cfi.Effect);
                var effects = cfi.RegisterEffects
                    .OrderBy(effect => GetRegisterSortKey(effect.Register), StringComparer.Ordinal)
                    .ThenBy(effect => (int)effect.Kind)
                    .ThenBy(effect => effect.IsImplicit)
                    .ToArray();
                context.WriteCount(effects.Length);
                foreach (var effect in effects)
                {
                    WriteRegisterEffect(context, effect);
                    context.EnsureWithinCanonicalLimit();
                }

                context.WriteOptionalString(cfi.Diagnostic);
                break;
            default:
                throw new SnapshotEncodingException(
                    "The semantic-plan extension has no canonical encoding.",
                    DiagnosticCode.SemanticPlanSnapshotUnsupported);
        }
    }

    private static void WriteDiagnostic(CanonicalWriteContext context, Diagnostic diagnostic)
    {
        context.Writer.Write((byte)diagnostic.Severity);
        context.Writer.Write((uint)diagnostic.Code);
        context.Writer.Write(diagnostic.Offset.HasValue ? (byte)1 : (byte)0);
        if (diagnostic.Offset is { } offset)
        {
            context.Writer.Write(offset);
        }

        context.WriteString(diagnostic.Message);
    }

    private static void WriteOptionalInt64(CanonicalWriteContext context, long? value)
    {
        context.Writer.Write(value.HasValue ? (byte)1 : (byte)0);
        if (value is { } actual)
        {
            context.Writer.Write(actual);
        }
    }

    private static void WriteOptionalUInt32(CanonicalWriteContext context, uint? value)
    {
        context.Writer.Write(value.HasValue ? (byte)1 : (byte)0);
        if (value is { } actual)
        {
            context.Writer.Write(actual);
        }
    }

    private static void WriteOptionalUInt64(CanonicalWriteContext context, ulong? value)
    {
        context.Writer.Write(value.HasValue ? (byte)1 : (byte)0);
        if (value is { } actual)
        {
            context.Writer.Write(actual);
        }
    }

    private static string GetRegisterSortKey(Aarch64RegisterView register) =>
        GetIntSortKey((int)register.Class)
        + GetByteSortKey(register.Index)
        + GetByteSortKey(register.Width)
        + GetIntSortKey((int)register.Role);

    private static string GetTargetSortKey(SemanticTarget target)
    {
        var candidateIdentities = target.CandidateIdentities
            .OrderBy(identity => GetEntitySortKey(identity), StringComparer.Ordinal)
            .Select(GetEntitySortKey)
            .ToArray();
        var candidateAddresses = target.CandidateAddresses
            .OrderBy(address => address.Value)
            .Select(address => GetUlongSortKey(address.Value))
            .ToArray();

        return GetIntSortKey((int)target.Resolution)
            + GetOptionalUInt64SortKey(target.SourceAddress?.Value)
            + GetOptionalEntitySortKey(target.Identity)
            + GetCollectionSortKey(candidateIdentities)
            + GetCollectionSortKey(candidateAddresses)
            + GetOptionalStringSortKey(target.RuntimeBinding)
            + GetOptionalStringSortKey(target.Diagnostic);
    }

    private static string GetRelocationSortKey(RelocationBinding relocation) =>
        GetIntSortKey((int)relocation.Kind)
        + GetTargetSortKey(relocation.Target)
        + GetLongSortKey(relocation.Addend)
        + GetUIntSortKey(relocation.SymbolIndex)
        + GetBoolSortKey(relocation.IsPlt)
        + GetOptionalStringSortKey(relocation.SymbolName)
        + GetOptionalUIntSortKey(relocation.RelocationType)
        + GetOptionalUInt64SortKey(relocation.RawInfo)
        + GetOptionalUInt64SortKey(relocation.RelocationAddress?.Value)
        + GetOptionalUInt64SortKey(relocation.RelocationTableAddress?.Value);

    private static string GetReferenceSortKey(SemanticReference reference) =>
        GetIntSortKey((int)reference.Kind)
        + GetIntSortKey(reference.OperandIndex)
        + GetTargetSortKey(reference.Target)
        + GetOptionalExpressionSortKey(reference.PcRelative)
        + GetOptionalLiteralSortKey(reference.Literal)
        + GetOptionalRelocationSortKey(reference.Relocation)
        + GetOptionalStringSortKey(reference.Description);

    private static string GetOptionalExpressionSortKey(PcRelativeExpression? expression) =>
        expression is { } value
            ? GetBoolSortKey(true)
                + GetIntSortKey((int)value.Kind)
                + GetUlongSortKey(value.Place.Value)
                + GetTargetSortKey(value.Target)
                + GetIntSortKey(value.Scale)
                + GetBoolSortKey(value.IsPageRelative)
                + GetLongSortKey(value.Addend)
            : GetBoolSortKey(false);

    private static string GetOptionalLiteralSortKey(LiteralReference? literal) =>
        literal is { } value
            ? GetBoolSortKey(true)
                + GetTargetSortKey(value.Target)
                + GetIntSortKey(value.AccessSize)
                + GetBoolSortKey(value.IsLoad)
                + GetOptionalRangeSortKey(value.PoolRange)
            : GetBoolSortKey(false);

    private static string GetOptionalRelocationSortKey(RelocationBinding? relocation) =>
        relocation is { } value
            ? GetBoolSortKey(true) + GetRelocationSortKey(value)
            : GetBoolSortKey(false);

    private static string GetRangeSortKey(SemanticSourceRange range) =>
        GetUlongSortKey(range.FileOffset.Value)
        + GetUlongSortKey(range.VirtualAddress.Value)
        + GetUlongSortKey(range.Size);

    private static string GetOptionalRangeSortKey(SemanticSourceRange? range) =>
        range is { } value
            ? GetBoolSortKey(true) + GetRangeSortKey(value)
            : GetBoolSortKey(false);

    private static string GetEntitySortKey(SemanticEntityId identity) =>
        GetIntSortKey((int)identity.Kind) + GetOptionalStringSortKey(identity.Value);

    private static string GetOptionalEntitySortKey(SemanticEntityId? identity) =>
        identity is { } value
            ? GetBoolSortKey(true) + GetEntitySortKey(value)
            : GetBoolSortKey(false);

    private static string GetCollectionSortKey(IEnumerable<string> values)
    {
        var materialized = values.ToArray();
        return GetIntSortKey(materialized.Length) + string.Concat(materialized);
    }

    private static string GetOptionalStringSortKey(string? value) =>
        value is null
            ? GetBoolSortKey(false)
            : GetBoolSortKey(true) + GetStringSortKey(value);

    private static string GetStringSortKey(string value) =>
        GetIntSortKey(value.Length) + value;

    private static string GetIntSortKey(int value) =>
        unchecked((uint)value).ToString("X8", CultureInfo.InvariantCulture);

    private static string GetUIntSortKey(uint value) =>
        value.ToString("X8", CultureInfo.InvariantCulture);

    private static string GetOptionalUIntSortKey(uint? value) =>
        value is { } actual
            ? GetBoolSortKey(true) + GetUIntSortKey(actual)
            : GetBoolSortKey(false);

    private static string GetOptionalUInt64SortKey(ulong? value) =>
        value is { } actual
            ? GetBoolSortKey(true) + GetUlongSortKey(actual)
            : GetBoolSortKey(false);

    private static string GetUlongSortKey(ulong value) =>
        value.ToString("X16", CultureInfo.InvariantCulture);

    private static string GetLongSortKey(long value) =>
        unchecked((ulong)value).ToString("X16", CultureInfo.InvariantCulture);

    private static string GetByteSortKey(byte value) =>
        value.ToString("X2", CultureInfo.InvariantCulture);

    private static string GetBoolSortKey(bool value) => value ? "1" : "0";

    private sealed class CanonicalWriteContext
    {
        public CanonicalWriteContext(BinaryWriter writer, DiagnosticBag diagnostics)
        {
            Writer = writer;
            Diagnostics = diagnostics;
        }

        public BinaryWriter Writer { get; }

        public DiagnosticBag Diagnostics { get; }

        public int MetadataBytes { get; private set; }

        public void EnsureWithinCanonicalLimit()
        {
            if (Writer.BaseStream.Length > SemanticPlanSnapshotLimits.MaximumCanonicalBytes - DigestSize)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot exceeds its bounded canonical byte length.",
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
            }
        }

        public void WriteString(string value)
        {
            ArgumentNullException.ThrowIfNull(value);
            byte[] bytes;
            try
            {
                bytes = StrictUtf8.GetBytes(value);
            }
            catch (EncoderFallbackException)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot contains invalid UTF-8 metadata.",
                    DiagnosticCode.SemanticPlanSnapshotMalformed);
            }

            if (bytes.Length > SemanticPlanSnapshotLimits.MaximumStringBytes)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot contains oversized string metadata.",
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
            }

            if (MetadataBytes > SemanticPlanSnapshotLimits.MaximumMetadataBytes - bytes.Length)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot metadata exceeds its bounded byte limit.",
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
            }

            MetadataBytes += bytes.Length;
            Writer.Write(checked((uint)bytes.Length));
            Writer.Write(bytes);
        }

        public void WriteOptionalString(string? value)
        {
            Writer.Write(value is not null ? (byte)1 : (byte)0);
            if (value is not null)
            {
                WriteString(value);
            }
        }

        public void WriteCount(int count)
        {
            if (count < 0)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot contains a negative collection count.",
                    DiagnosticCode.SemanticPlanSnapshotMalformed);
            }

            Writer.Write(checked((uint)count));
        }
    }

    private sealed class SnapshotReader
    {
        private readonly BoundedReader reader;
        private int metadataBytes;

        public SnapshotReader(ReadOnlyMemory<byte> source)
        {
            reader = new BoundedReader(source);
        }

        public bool IsAtEnd => Position == (ulong)reader.Length;

        public ulong Position { get; private set; }

        public DiagnosticCode FailureCode { get; private set; } = DiagnosticCode.SemanticPlanSnapshotMalformed;

        public string? FailureMessage { get; private set; }

        public ulong? FailureOffset { get; private set; }

        public bool TrySkip(ulong length)
        {
            if (!reader.Contains(Position, length))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated record.");
            }

            Position += length;
            return true;
        }

        public bool TryReadByte(out byte value)
        {
            value = default;
            if (!reader.TryReadByte(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated byte field.");
            }

            Position++;
            return true;
        }

        public bool TryReadUInt16(out ushort value)
        {
            value = default;
            if (!reader.TryReadUInt16(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated 16-bit field.");
            }

            Position += sizeof(ushort);
            return true;
        }

        public bool TryReadUInt32(out uint value)
        {
            value = default;
            if (!reader.TryReadUInt32(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated 32-bit field.");
            }

            Position += sizeof(uint);
            return true;
        }

        public bool TryReadUInt64(out ulong value)
        {
            value = default;
            if (!reader.TryReadUInt64(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated 64-bit field.");
            }

            Position += sizeof(ulong);
            return true;
        }

        public bool TryReadInt32(out int value)
        {
            value = default;
            if (!reader.TryReadInt32(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated signed 32-bit field.");
            }

            Position += sizeof(int);
            return true;
        }

        public bool TryReadInt64(out long value)
        {
            value = default;
            if (!reader.TryReadInt64(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated signed 64-bit field.");
            }

            Position += sizeof(long);
            return true;
        }

        public bool TryReadCount(int maximum, out int count)
        {
            count = default;
            if (!TryReadUInt32(out var raw))
            {
                return false;
            }

            if (raw > (uint)maximum || raw > int.MaxValue)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot contains a collection count outside its bounded limit.");
            }

            count = (int)raw;
            return true;
        }

        public bool TryReadUtf8String(out string value)
        {
            value = string.Empty;
            if (!TryReadUInt32(out var byteLength))
            {
                return false;
            }

            if (byteLength > SemanticPlanSnapshotLimits.MaximumStringBytes)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot contains oversized string metadata.");
            }

            if (!reader.TrySlice(Position, byteLength, out var bytes))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot string extends beyond its bounded input.");
            }

            try
            {
                value = StrictUtf8.GetString(bytes.Span);
            }
            catch (DecoderFallbackException)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains invalid UTF-8 metadata.");
            }

            if (metadataBytes > SemanticPlanSnapshotLimits.MaximumMetadataBytes - (int)byteLength)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot metadata exceeds its bounded byte limit.");
            }

            metadataBytes += (int)byteLength;
            Position += byteLength;
            return true;
        }

        public bool TryReadBool(out bool value)
        {
            value = false;
            if (!TryReadByte(out var raw))
            {
                return false;
            }

            if (raw > 1)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a non-canonical boolean value.");
            }

            value = raw != 0;
            return true;
        }

        public bool TryReadOptionalString(out string? value)
        {
            value = null;
            if (!TryReadBool(out var present))
            {
                return false;
            }

            if (!present)
            {
                return true;
            }

            if (!TryReadUtf8String(out var text))
            {
                return false;
            }

            value = text;
            return true;
        }

        public bool Fail(
            DiagnosticCode code,
            string message)
        {
            if (FailureMessage is null)
            {
                FailureCode = code;
                FailureMessage = message;
                FailureOffset = Position;
            }

            return false;
        }
    }

    private static bool TryReadAddressMapEntry(
        SnapshotReader reader,
        out AddressMapEntry? entry)
    {
        entry = null;
        if (!TryReadEntityId(reader, out var identity)
            || !TryReadOptionalEntityId(reader, out var outputIdentity)
            || !TryReadRange(reader, out var sourceRange)
            || !TryReadRange(reader, out var outputRange))
        {
            return false;
        }

        entry = new AddressMapEntry(identity, sourceRange, outputRange, outputIdentity);
        return true;
    }

    private static bool TryReadInstruction(
        SnapshotReader reader,
        out SemanticInstruction? instruction)
    {
        instruction = null;
        if (!reader.TryReadUInt64(out var sourceAddress)
            || !reader.TryReadUInt64(out var sourceFileOffset)
            || !reader.TryReadUtf8String(out var mnemonic)
            || !reader.TryReadUInt32(out var encoding)
            || !TryReadRange(reader, out var sourceRange)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumOperandsPerInstruction, out var operandCount))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(mnemonic))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains an empty instruction mnemonic.");
        }

        var operands = new List<SemanticOperand>(operandCount);
        for (var index = 0; index < operandCount; index++)
        {
            if (!TryReadOperand(reader, out var operand))
            {
                return false;
            }

            operands.Add(operand!);
        }

        if (!reader.TryReadCount(
                SemanticPlanSnapshotLimits.MaximumRegisterEffectsPerInstruction,
                out var registerEffectCount))
        {
            return false;
        }

        var registerEffects = new List<SemanticRegisterEffect>(registerEffectCount);
        for (var index = 0; index < registerEffectCount; index++)
        {
            if (!TryReadRegisterEffect(reader, out var effect))
            {
                return false;
            }

            registerEffects.Add(effect);
        }

        if (!reader.TryReadByte(out var flagEffects)
            || !reader.TryReadByte(out var controlFlow)
            || !TryReadOptionalTarget(reader, out var controlFlowTarget)
            || !TryReadOptionalExpression(reader, out var expression)
            || !TryReadOptionalLiteral(reader, out var literal)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumRelocationsPerInstruction, out var relocationCount))
        {
            return false;
        }

        var relocations = new List<RelocationBinding>(relocationCount);
        for (var index = 0; index < relocationCount; index++)
        {
            if (!TryReadRelocation(reader, out var relocation))
            {
                return false;
            }

            relocations.Add(relocation!);
        }

        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumReferencesPerInstruction, out var referenceCount))
        {
            return false;
        }

        var references = new List<SemanticReference>(referenceCount);
        for (var index = 0; index < referenceCount; index++)
        {
            if (!TryReadReference(reader, out var reference))
            {
                return false;
            }

            references.Add(reference!);
        }

        if (!reader.TryReadBool(out var opaquePreservation))
        {
            return false;
        }

        const SemanticFlagEffects knownFlags = SemanticFlagEffects.ReadNzcv | SemanticFlagEffects.WriteNzcv;
        if ((((SemanticFlagEffects)flagEffects & ~knownFlags) != SemanticFlagEffects.None)
            || !Enum.IsDefined(typeof(Aarch64ControlFlowKind), (Aarch64ControlFlowKind)controlFlow))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported instruction enum value.");
        }

        instruction = new SemanticInstruction(
            new VirtualAddress(sourceAddress),
            new FileOffset(sourceFileOffset),
            encoding,
            mnemonic,
            sourceRange,
            operands,
            registerEffects,
            (SemanticFlagEffects)flagEffects,
            (Aarch64ControlFlowKind)controlFlow,
            controlFlowTarget,
            expression,
            literal,
            relocations,
            references,
            opaquePreservation);
        return true;
    }

    private static bool TryReadOperand(
        SnapshotReader reader,
        out SemanticOperand? operand)
    {
        operand = null;
        if (!reader.TryReadUtf8String(out var name)
            || !reader.TryReadByte(out var kind)
            || !reader.TryReadByte(out var direction)
            || !reader.TryReadBool(out var isImplicit)
            || !reader.TryReadUtf8String(out var codec)
            || !reader.TryReadOptionalString(out var tiedTo)
            || !TryReadOptionalRegister(reader, out var register)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCandidates, out var registerCount))
        {
            return false;
        }

        var registers = new List<Aarch64RegisterView>(registerCount);
        for (var index = 0; index < registerCount; index++)
        {
            if (!TryReadRegister(reader, out var listRegister))
            {
                return false;
            }

            registers.Add(listRegister);
        }

        if (!TryReadOptionalMemory(reader, out var memory)
            || !TryReadOptionalInt64(reader, out var immediate)
            || !TryReadOptionalUInt64(reader, out var target)
            || !TryReadRegisterConstraint(reader, out var constraint)
            || !reader.TryReadInt32(out var registerWidth)
            || !reader.TryReadInt32(out var fieldWidth)
            || !reader.TryReadInt32(out var elementWidth)
            || !reader.TryReadBool(out var allowsStackPointer)
            || !reader.TryReadBool(out var allowsZeroRegister)
            || !reader.TryReadBool(out var isPageRelative)
            || !reader.TryReadUtf8String(out var semanticDomain))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(Aarch64OperandKind), (Aarch64OperandKind)kind)
            || !Enum.IsDefined(typeof(Aarch64OperandDirection), (Aarch64OperandDirection)direction))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported operand enum value.");
        }

        operand = new SemanticOperand(
            name,
            (Aarch64OperandKind)kind,
            (Aarch64OperandDirection)direction,
            isImplicit,
            codec,
            tiedTo,
            register,
            registers,
            memory,
            immediate,
            target,
            constraint,
            registerWidth,
            fieldWidth,
            elementWidth,
            allowsStackPointer,
            allowsZeroRegister,
            isPageRelative,
            semanticDomain);
        return true;
    }

    private static bool TryReadRegisterEffect(
        SnapshotReader reader,
        out SemanticRegisterEffect effect)
    {
        effect = default;
        if (!TryReadRegister(reader, out var register)
            || !reader.TryReadByte(out var kind)
            || !reader.TryReadBool(out var isImplicit))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(SemanticRegisterEffectKind), (SemanticRegisterEffectKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported register-effect enum value.");
        }

        effect = new SemanticRegisterEffect(register, (SemanticRegisterEffectKind)kind, isImplicit);
        return true;
    }

    private static bool TryReadRegister(
        SnapshotReader reader,
        out Aarch64RegisterView register)
    {
        register = default;
        if (!reader.TryReadByte(out var registerClass)
            || !reader.TryReadByte(out var index)
            || !reader.TryReadByte(out var width)
            || !reader.TryReadByte(out var role))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(Aarch64RegisterClass), (Aarch64RegisterClass)registerClass)
            || !Enum.IsDefined(typeof(Aarch64RegisterRole), (Aarch64RegisterRole)role))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported register enum value.");
        }

        register = new Aarch64RegisterView(
            (Aarch64RegisterClass)registerClass,
            index,
            width,
            (Aarch64RegisterRole)role);
        return true;
    }

    private static bool TryReadRegisterConstraint(
        SnapshotReader reader,
        out Aarch64RegisterConstraint constraint)
    {
        constraint = default;
        if (!reader.TryReadInt32(out var minimum)
            || !reader.TryReadInt32(out var maximum)
            || !reader.TryReadInt32(out var step)
            || !reader.TryReadUInt32(out var allowedMask))
        {
            return false;
        }

        constraint = new Aarch64RegisterConstraint(minimum, maximum, step, allowedMask);
        return true;
    }

    private static bool TryReadOptionalRegister(
        SnapshotReader reader,
        out Aarch64RegisterView? register)
    {
        register = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadRegister(reader, out var value))
        {
            return false;
        }

        register = value;
        return true;
    }

    private static bool TryReadOptionalMemory(
        SnapshotReader reader,
        out Aarch64MemoryReference? memory)
    {
        memory = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadRegister(reader, out var baseRegister)
            || !TryReadOptionalRegister(reader, out var index)
            || !reader.TryReadInt64(out var offset)
            || !reader.TryReadUtf8String(out var addressingMode)
            || !TryReadOptionalUInt32(reader, out var indexModifier)
            || !reader.TryReadInt32(out var accessSize)
            || !reader.TryReadUtf8String(out var ordering)
            || !reader.TryReadBool(out var writesBack))
        {
            return false;
        }

        memory = new Aarch64MemoryReference(
            baseRegister,
            index,
            offset,
            addressingMode,
            indexModifier,
            accessSize,
            ordering,
            writesBack);
        return true;
    }

    private static bool TryReadOptionalTarget(
        SnapshotReader reader,
        out SemanticTarget? target)
    {
        target = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadTarget(reader, out target))
        {
            return false;
        }

        return true;
    }

    private static bool TryReadTarget(
        SnapshotReader reader,
        out SemanticTarget? target)
    {
        target = null;
        if (!reader.TryReadByte(out var resolution)
            || !TryReadOptionalUInt64(reader, out var sourceAddress)
            || !TryReadOptionalEntityId(reader, out var identity)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCandidates, out var identityCount))
        {
            return false;
        }

        var identities = new List<SemanticEntityId>(identityCount);
        for (var index = 0; index < identityCount; index++)
        {
            if (!TryReadEntityId(reader, out var candidate))
            {
                return false;
            }

            identities.Add(candidate);
        }

        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCandidates, out var addressCount))
        {
            return false;
        }

        var addresses = new List<VirtualAddress>(addressCount);
        for (var index = 0; index < addressCount; index++)
        {
            if (!reader.TryReadUInt64(out var address))
            {
                return false;
            }

            addresses.Add(new VirtualAddress(address));
        }

        if (!reader.TryReadOptionalString(out var runtimeBinding)
            || !reader.TryReadOptionalString(out var diagnostic))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(SemanticTargetResolution), (SemanticTargetResolution)resolution))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported target resolution enum value.");
        }

        target = new SemanticTarget(
            (SemanticTargetResolution)resolution,
            sourceAddress is { } source ? new VirtualAddress(source) : null,
            identity,
            identities,
            addresses,
            runtimeBinding,
            diagnostic);
        return true;
    }

    private static bool TryReadOptionalExpression(
        SnapshotReader reader,
        out PcRelativeExpression? expression)
    {
        expression = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadByte(out var kind)
            || !reader.TryReadUInt64(out var place)
            || !TryReadTarget(reader, out var target)
            || !reader.TryReadInt32(out var scale)
            || !reader.TryReadBool(out var pageRelative)
            || !reader.TryReadInt64(out var addend))
        {
            return false;
        }

        if (target is null || !Enum.IsDefined(typeof(PcRelativeExpressionKind), (PcRelativeExpressionKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported PC-relative expression.");
        }

        expression = new PcRelativeExpression(
            (PcRelativeExpressionKind)kind,
            new VirtualAddress(place),
            target,
            scale,
            pageRelative,
            addend);
        return true;
    }

    private static bool TryReadOptionalLiteral(
        SnapshotReader reader,
        out LiteralReference? literal)
    {
        literal = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadTarget(reader, out var target)
            || !reader.TryReadInt32(out var accessSize)
            || !reader.TryReadBool(out var isLoad)
            || !TryReadOptionalRange(reader, out var poolRange))
        {
            return false;
        }

        if (target is null)
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot literal reference has no target.");
        }

        literal = new LiteralReference(target, accessSize, isLoad, poolRange);
        return true;
    }

    private static bool TryReadRelocation(
        SnapshotReader reader,
        out RelocationBinding? relocation)
    {
        relocation = null;
        if (!reader.TryReadByte(out var kind)
            || !TryReadTarget(reader, out var target)
            || !reader.TryReadInt64(out var addend)
            || !reader.TryReadUInt32(out var symbolIndex)
            || !reader.TryReadBool(out var isPlt)
            || !reader.TryReadOptionalString(out var symbolName)
            || !TryReadOptionalUInt32(reader, out var relocationType)
            || !TryReadOptionalUInt64(reader, out var rawInfo)
            || !TryReadOptionalUInt64(reader, out var relocationAddress)
            || !TryReadOptionalUInt64(reader, out var relocationTableAddress))
        {
            return false;
        }

        if (target is null || !Enum.IsDefined(typeof(Aarch64RelocationKind), (Aarch64RelocationKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported relocation binding.");
        }

        relocation = new RelocationBinding(
            (Aarch64RelocationKind)kind,
            target,
            addend,
            symbolIndex,
            isPlt,
            symbolName,
            relocationType,
            relocationAddress is { } address ? new VirtualAddress(address) : null,
            relocationTableAddress is { } tableAddress ? new VirtualAddress(tableAddress) : null)
        {
            RawInfo = rawInfo,
        };
        return true;
    }

    private static bool TryReadReference(
        SnapshotReader reader,
        out SemanticReference? reference)
    {
        reference = null;
        if (!reader.TryReadByte(out var kind)
            || !TryReadTarget(reader, out var target)
            || !reader.TryReadInt32(out var operandIndex)
            || !TryReadOptionalExpression(reader, out var expression)
            || !TryReadOptionalLiteral(reader, out var literal)
            || !TryReadOptionalRelocation(reader, out var relocation)
            || !reader.TryReadOptionalString(out var description))
        {
            return false;
        }

        if (target is null || !Enum.IsDefined(typeof(SemanticReferenceKind), (SemanticReferenceKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported semantic reference.");
        }

        reference = new SemanticReference(
            (SemanticReferenceKind)kind,
            target,
            operandIndex,
            expression,
            literal,
            relocation,
            description);
        return true;
    }

    private static bool TryReadOptionalRelocation(
        SnapshotReader reader,
        out RelocationBinding? relocation)
    {
        relocation = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        return TryReadRelocation(reader, out relocation);
    }

    private static bool TryReadFixup(
        SnapshotReader reader,
        out SemanticFixup? fixup,
        out SemanticFixupResolutionState state)
    {
        fixup = null;
        state = default;
        if (!reader.TryReadByte(out var stateValue)
            || !reader.TryReadByte(out var kind)
            || !reader.TryReadUInt64(out var sourceAddress)
            || !reader.TryReadUInt64(out var sourceFileOffset)
            || !reader.TryReadUInt32(out var originalEncoding)
            || !TryReadTarget(reader, out var target)
            || !TryReadRange(reader, out var sourceRange)
            || !TryReadOptionalExpression(reader, out var expression)
            || !TryReadOptionalRelocation(reader, out var relocation)
            || !reader.TryReadByte(out var relaxation)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumRelaxationOptions, out var optionCount))
        {
            return false;
        }

        var options = new List<SemanticRelaxationKind>(optionCount);
        for (var index = 0; index < optionCount; index++)
        {
            if (!reader.TryReadByte(out var option))
            {
                return false;
            }

            if (!Enum.IsDefined(typeof(SemanticRelaxationKind), (SemanticRelaxationKind)option))
            {
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The semantic-plan snapshot contains an unsupported relaxation option.");
            }

            options.Add((SemanticRelaxationKind)option);
        }

        if (target is null
            || !Enum.IsDefined(typeof(SemanticFixupResolutionState), (SemanticFixupResolutionState)stateValue)
            || !Enum.IsDefined(typeof(SemanticFixupKind), (SemanticFixupKind)kind)
            || !Enum.IsDefined(typeof(SemanticRelaxationKind), (SemanticRelaxationKind)relaxation))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported fixup enum value.");
        }

        state = (SemanticFixupResolutionState)stateValue;
        fixup = new SemanticFixup(
            (SemanticFixupKind)kind,
            new VirtualAddress(sourceAddress),
            new FileOffset(sourceFileOffset),
            originalEncoding,
            target,
            sourceRange,
            expression,
            relocation,
            (SemanticRelaxationKind)relaxation,
            options);
        return true;
    }

    private static bool TryReadExtension(
        SnapshotReader reader,
        out ISemanticPlanExtension? extension)
    {
        extension = null;
        if (!reader.TryReadByte(out var kind)
            || !Enum.IsDefined(typeof(SemanticPlanExtensionKind), (SemanticPlanExtensionKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported extension kind.");
        }

        switch ((SemanticPlanExtensionKind)kind)
        {
            case SemanticPlanExtensionKind.IndirectTargets:
                if (!TryReadEntityId(reader, out var indirectSource)
                    || !reader.TryReadUInt64(out var indirectAddress)
                    || !TryReadTarget(reader, out var indirectTarget)
                    || !reader.TryReadUtf8String(out var indirectDiagnostic))
                {
                    return false;
                }

                if (indirectTarget is null || string.IsNullOrWhiteSpace(indirectDiagnostic))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The indirect-target extension has no target or diagnostic.");
                }

                extension = new SemanticIndirectTargetExtension(
                    indirectSource,
                    new VirtualAddress(indirectAddress),
                    indirectTarget,
                    indirectDiagnostic);
                return true;
            case SemanticPlanExtensionKind.UnresolvedReference:
                if (!TryReadEntityId(reader, out var unresolvedSource)
                    || !reader.TryReadUInt64(out var unresolvedAddress)
                    || !reader.TryReadByte(out var referenceKind)
                    || !TryReadTarget(reader, out var unresolvedTarget)
                    || !reader.TryReadUtf8String(out var unresolvedDiagnostic))
                {
                    return false;
                }

                if (unresolvedTarget is null
                    || string.IsNullOrWhiteSpace(unresolvedDiagnostic)
                    || !Enum.IsDefined(typeof(SemanticReferenceKind), (SemanticReferenceKind)referenceKind))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotUnsupported,
                        "The unresolved-reference extension has an invalid target or reference kind.");
                }

                extension = new SemanticUnresolvedReferenceExtension(
                    unresolvedSource,
                    new VirtualAddress(unresolvedAddress),
                    (SemanticReferenceKind)referenceKind,
                    unresolvedTarget,
                    unresolvedDiagnostic);
                return true;
            case SemanticPlanExtensionKind.RelocationBinding:
                if (!TryReadEntityId(reader, out var relocationSite)
                    || !TryReadRelocation(reader, out var relocationBinding)
                    || !reader.TryReadUtf8String(out var relocationDiagnostic))
                {
                    return false;
                }

                if (relocationBinding is null || string.IsNullOrWhiteSpace(relocationDiagnostic))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The relocation extension has no binding or diagnostic.");
                }

                extension = new SemanticRelocationBindingExtension(
                    relocationSite,
                    relocationBinding,
                    relocationDiagnostic);
                return true;
            case SemanticPlanExtensionKind.TlsBinding:
                if (!TryReadEntityId(reader, out var tlsSource)
                    || !TryReadRange(reader, out var tlsRange)
                    || !reader.TryReadUtf8String(out var tlsModel)
                    || !TryReadRelocation(reader, out var tlsBinding)
                    || !reader.TryReadOptionalString(out var tlsDiagnostic))
                {
                    return false;
                }

                if (tlsBinding is null || string.IsNullOrWhiteSpace(tlsModel))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The TLS extension has no relocation binding or model.");
                }

                extension = new SemanticTlsBindingExtension(
                    tlsSource,
                    tlsRange,
                    tlsBinding,
                    tlsModel,
                    tlsDiagnostic);
                return true;
            case SemanticPlanExtensionKind.JumpTable:
                if (!TryReadEntityId(reader, out var tableIdentity)
                    || !TryReadRange(reader, out var tableRange)
                    || !reader.TryReadInt32(out var entrySize)
                    || !reader.TryReadOptionalString(out var tableEncoding)
                    || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumTargetsPerJumpTable, out var targetCount))
                {
                    return false;
                }

                var targets = new List<SemanticTarget>(targetCount);
                for (var index = 0; index < targetCount; index++)
                {
                    if (!TryReadTarget(reader, out var target) || target is null)
                    {
                        return reader.Fail(
                            DiagnosticCode.SemanticPlanSnapshotMalformed,
                            "The jump-table extension contains a null target.");
                    }

                    targets.Add(target);
                }

                if (entrySize <= 0)
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The jump-table extension has an invalid entry size.");
                }

                extension = new SemanticJumpTableExtension(
                    tableIdentity,
                    tableRange,
                    entrySize,
                    targets,
                    tableEncoding);
                return true;
            case SemanticPlanExtensionKind.CfiEffect:
                if (!TryReadEntityId(reader, out var cfiIdentity)
                    || !TryReadRange(reader, out var cfiRange)
                    || !reader.TryReadUtf8String(out var cfiEffect)
                    || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCfiRegisterEffects, out var effectCount))
                {
                    return false;
                }

                var effects = new List<SemanticRegisterEffect>(effectCount);
                for (var index = 0; index < effectCount; index++)
                {
                    if (!TryReadRegisterEffect(reader, out var effect))
                    {
                        return false;
                    }

                    effects.Add(effect);
                }

                if (!reader.TryReadOptionalString(out var cfiDiagnostic))
                {
                    return false;
                }

                if (string.IsNullOrWhiteSpace(cfiEffect))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The CFI extension has no effect description.");
                }

                extension = new SemanticCfiEffectExtension(
                    cfiIdentity,
                    cfiRange,
                    cfiEffect,
                    effects,
                    cfiDiagnostic);
                return true;
            default:
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The semantic-plan snapshot extension kind is not supported.");
        }
    }

    private static bool TryReadDiagnostic(
        SnapshotReader reader,
        out Diagnostic diagnostic)
    {
        diagnostic = default;
        ulong offset = 0;
        if (!reader.TryReadByte(out var severity)
            || !reader.TryReadUInt32(out var code)
            || !reader.TryReadBool(out var hasOffset)
            || (hasOffset && !reader.TryReadUInt64(out offset))
            || !reader.TryReadUtf8String(out var message))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(DiagnosticSeverity), (DiagnosticSeverity)severity)
            || code > int.MaxValue
            || !Enum.IsDefined(typeof(DiagnosticCode), (DiagnosticCode)code))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported diagnostic enum value.");
        }

        diagnostic = new Diagnostic(
            (DiagnosticSeverity)severity,
            (DiagnosticCode)code,
            message,
            hasOffset ? offset : null);
        return true;
    }

    private static bool TryReadEntityId(
        SnapshotReader reader,
        out SemanticEntityId identity)
    {
        identity = default;
        if (!reader.TryReadByte(out var kind)
            || !reader.TryReadUtf8String(out var value))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(SemanticEntityKind), (SemanticEntityKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported entity kind.");
        }

        identity = new SemanticEntityId((SemanticEntityKind)kind, value);
        return true;
    }

    private static bool TryReadOptionalEntityId(
        SnapshotReader reader,
        out SemanticEntityId? identity)
    {
        identity = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadEntityId(reader, out var value))
        {
            return false;
        }

        identity = value;
        return true;
    }

    private static bool TryReadRange(
        SnapshotReader reader,
        out SemanticSourceRange range)
    {
        range = default;
        if (!reader.TryReadUInt64(out var fileOffset)
            || !reader.TryReadUInt64(out var virtualAddress)
            || !reader.TryReadUInt64(out var size))
        {
            return false;
        }

        range = new SemanticSourceRange(
            new FileOffset(fileOffset),
            new VirtualAddress(virtualAddress),
            size);
        return true;
    }

    private static bool TryReadOptionalRange(
        SnapshotReader reader,
        out SemanticSourceRange? range)
    {
        range = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadRange(reader, out var value))
        {
            return false;
        }

        range = value;
        return true;
    }

    private static bool TryReadOptionalInt64(
        SnapshotReader reader,
        out long? value)
    {
        value = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadInt64(out var actual))
        {
            return false;
        }

        value = actual;
        return true;
    }

    private static bool TryReadOptionalUInt32(
        SnapshotReader reader,
        out uint? value)
    {
        value = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadUInt32(out var actual))
        {
            return false;
        }

        value = actual;
        return true;
    }

    private static bool TryReadOptionalUInt64(
        SnapshotReader reader,
        out ulong? value)
    {
        value = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadUInt64(out var actual))
        {
            return false;
        }

        value = actual;
        return true;
    }
}
