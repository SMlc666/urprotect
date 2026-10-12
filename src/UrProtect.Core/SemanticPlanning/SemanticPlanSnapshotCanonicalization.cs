using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.SemanticPlanning;

public static partial class SemanticPlanSnapshotCodec
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

    /// <summary>
    /// Computes the one plan digest used by later artifact binders.
    /// </summary>
    public static string ComputeSha256(ReadOnlySpan<byte> canonicalBytes) =>
        Convert.ToHexString(SHA256.HashData(canonicalBytes)).ToLowerInvariant();

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
}
