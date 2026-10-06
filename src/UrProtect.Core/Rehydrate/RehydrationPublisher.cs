using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Protect;

namespace UrProtect.Core.Rehydrate;

public sealed record RehydrationPublicationResult(
    bool Published,
    IReadOnlyList<Diagnostic> Diagnostics,
    NativeImageDescriptor? Descriptor = null);

/// <summary>Atomically publishes a successful Native Image and its hash-bound records.</summary>
public static class RehydrationPublisher
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static RehydrationPublicationResult Publish(
        RehydrationResult result,
        string nativeImagePath,
        string nativeImageRolePath,
        string recordPath)
    {
        ArgumentNullException.ThrowIfNull(result);
        var diagnostics = new DiagnosticBag();
        if (!ValidateRecord(result.Record, diagnostics))
        {
            return new RehydrationPublicationResult(false, diagnostics.ToArray());
        }

        if (!result.IsSuccess || result.NativeImage is null)
        {
            if (File.Exists(nativeImagePath) || File.Exists(nativeImageRolePath))
            {
                diagnostics.Error(DiagnosticCode.OutputIdentityMismatch, "A failed rehydration cannot retain a Native Image or successful role record.");
                return new RehydrationPublicationResult(false, diagnostics.ToArray());
            }

            return WriteFailureRecord(result.Record, recordPath, diagnostics);
        }

        var image = result.NativeImage;
        var bytes = image.Bytes;
        var imageHash = Sha256(bytes);
        if (bytes.Length is 0 or > RehydrationLimits.MaximumNativeImageBytes
            || !string.Equals(imageHash, result.Record.NativeImageSha256, StringComparison.Ordinal)
            || result.Record.NativeImageSize != bytes.LongLength
            || !string.Equals(imageHash, image.Descriptor.NativeImageSha256, StringComparison.Ordinal)
            || image.Descriptor.NativeImageSize != bytes.LongLength
            || string.Equals(imageHash, result.Record.SourceSha256, StringComparison.Ordinal)
            || string.Equals(imageHash, result.Record.ProtectedImageSha256, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.OutputIdentityMismatch, "Native Image bytes do not match the rehydration result bindings.");
            return new RehydrationPublicationResult(false, diagnostics.ToArray());
        }

        try
        {
            var imageFullPath = Path.GetFullPath(nativeImagePath);
            var roleFullPath = Path.GetFullPath(nativeImageRolePath);
            var recordFullPath = Path.GetFullPath(recordPath);
            if (new[] { imageFullPath, roleFullPath, recordFullPath }.Distinct(GetPathComparer()).Count() != 3)
            {
                diagnostics.Error(DiagnosticCode.OutputPathConflict, "Native Image publication paths must be distinct.");
                return new RehydrationPublicationResult(false, diagnostics.ToArray());
            }

            EnsureParentDirectory(imageFullPath);
            EnsureParentDirectory(roleFullPath);
            EnsureParentDirectory(recordFullPath);
            var recordBytes = Serialize(result.Record);
            var recordHash = Sha256(recordBytes);
            var descriptor = image.Descriptor with { RehydrationRecordSha256 = recordHash };
            var roleBytes = Serialize(descriptor);
            var destinations = new[] { imageFullPath, roleFullPath, recordFullPath };
            var contents = new[] { bytes, roleBytes, recordBytes };
            var temporaryPaths = new List<string>(destinations.Length);
            var movedPaths = new List<string>(destinations.Length);
            try
            {
                for (var index = 0; index < destinations.Length; index++)
                {
                    var temporary = CreateTemporaryPath(destinations[index]);
                    temporaryPaths.Add(temporary);
                    WriteAndVerify(temporary, contents[index]);
                }

                for (var index = 0; index < destinations.Length; index++)
                {
                    File.Move(temporaryPaths[index], destinations[index], overwrite: false);
                    movedPaths.Add(destinations[index]);
                }

                return new RehydrationPublicationResult(true, diagnostics.ToArray(), descriptor);
            }
            finally
            {
                foreach (var temporary in temporaryPaths)
                {
                    TryDelete(temporary);
                }

                if (movedPaths.Count > 0 && movedPaths.Count < destinations.Length)
                {
                    foreach (var moved in movedPaths)
                    {
                        TryDelete(moved);
                    }
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, exception.Message);
            return new RehydrationPublicationResult(false, diagnostics.ToArray());
        }
    }

    public static bool WriteFailureRecord(
        RehydrationRecord record,
        string recordPath,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        var bag = new DiagnosticBag();
        var result = WriteFailureRecord(record, recordPath, bag);
        diagnostics = bag.ToArray();
        return result.Published;
    }

    private static RehydrationPublicationResult WriteFailureRecord(
        RehydrationRecord record,
        string recordPath,
        DiagnosticBag diagnostics)
    {
        if (record.IsPassed || record.NativeImageSha256 is not null || record.NativeImageSize is not null)
        {
            diagnostics.Error(DiagnosticCode.OutputIdentityMismatch, "A failed rehydration record must not claim a successful Native Image.");
            return new RehydrationPublicationResult(false, diagnostics.ToArray());
        }

        try
        {
            var fullPath = Path.GetFullPath(recordPath);
            EnsureParentDirectory(fullPath);
            var temporary = CreateTemporaryPath(fullPath);
            try
            {
                WriteAndVerify(temporary, Serialize(record));
                File.Move(temporary, fullPath, overwrite: true);
            }
            finally
            {
                TryDelete(temporary);
            }

            return new RehydrationPublicationResult(true, diagnostics.ToArray());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, exception.Message);
            return new RehydrationPublicationResult(false, diagnostics.ToArray());
        }
    }

    public static bool ValidateRecord(RehydrationRecord record, DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var valid = true;
        void Invalid(string message)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, message);
            valid = false;
        }

        if (record.SchemaVersion != RehydrationRecord.CurrentSchemaVersion
            || !string.Equals(record.Stage, RehydrationRecord.StageName, StringComparison.Ordinal)
            || record.Status is not (RehydrationRecord.PassedStatus or RehydrationRecord.FailedStatus)
            || record.MaterializationStatus is not ("passed" or "failed"))
        {
            Invalid("Rehydration record schema, stage, or status is unsupported.");
        }

        foreach (var digest in new[]
                 {
                     record.SourceSha256,
                     record.RequestSha256,
                     record.ProtectedImageSha256,
                     record.ProducerBuildSha256,
                     record.ConsumerBuildSha256,
                 })
        {
            if (!IsDigest(digest))
            {
                Invalid("Rehydration record contains a malformed SHA-256 binding.");
                break;
            }
        }

        if (record.UnitId.Length is 0 or > 128
            || record.ProducerId.Length is 0 or > 128
            || record.ConsumerId.Length is 0 or > 128
            || record.Profile.Length is 0 or > 64
            || record.HandoffRecordPath != "handoff.json"
            || record.RawEvidenceManifestPath != "SHA256SUMS"
            || record.ProtectedImageSize is < 0 or > ProtectedImageLimits.MaximumArtifactBytes
            || record.DurationMilliseconds is < 0 or > 86_400_000
            || record.CpuMilliseconds is < 0 or > 86_400_000
            || record.WorkingSetBytes is < 0 or > (1L << 40)
            || record.Diagnostics is null
            || record.Diagnostics.Count > RehydrationLimits.MaximumDiagnostics)
        {
            Invalid("Rehydration record fields exceed their configured bounds.");
        }

        var recordDiagnostics = record.Diagnostics ?? Array.Empty<RehydrationDiagnostic>();
        if (record.Diagnostics is not null && recordDiagnostics.Any(diagnostic =>
                diagnostic.Message is null
                || diagnostic.Message.Length > RehydrationLimits.MaximumDiagnosticMessageBytes
                || diagnostic.Code is null
                || diagnostic.Code.Length > 128
                || diagnostic.Severity is null
                || diagnostic.Severity.Length > 16))
        {
            Invalid("Rehydration record diagnostics exceed their configured bounds.");
        }

        if (record.LayoutEvidence is not null)
        {
            var evidence = record.LayoutEvidence;
            if (evidence.SchemaVersion != ElfLayoutEvidence.CurrentSchemaVersion
                || !Enum.IsDefined(evidence.Strategy)
                || !IsDigest(evidence.SourceSha256)
                || !IsDigest(evidence.OutputSha256)
                || !IsDigest(evidence.PreservedMetadataSha256)
                || evidence.OutputLength is 0 or > RehydrationLimits.MaximumNativeImageBytes
                || evidence.Placements is null
                || evidence.Placements.Count > ElfLayoutLimits.DefaultMaximumEditCount
                || evidence.AddressMap is null
                || evidence.AddressMap.Count > ElfLayoutLimits.DefaultMaximumEditCount
                || evidence.BranchDecisions is null
                || evidence.BranchDecisions.Count > ElfLayoutLimits.DefaultMaximumEditCount
                || !string.Equals(evidence.SourceSha256, record.SourceSha256, StringComparison.Ordinal)
                || !string.Equals(evidence.OutputSha256, record.NativeImageSha256, StringComparison.Ordinal)
                || record.NativeImageSize != (long)evidence.OutputLength
                || !string.Equals(record.LayoutStrategy, evidence.StrategyValue, StringComparison.Ordinal)
                || !ValidateLayoutEvidence(evidence, diagnostics))
            {
                Invalid("Rehydration layout evidence is malformed or not bound to the Native Image record.");
            }
        }
        else if (record.IsPassed)
        {
            Invalid("A passed rehydration record must retain bounded layout evidence.");
        }

        if (record.HandoffRecordSha256 is not null && !IsDigest(record.HandoffRecordSha256))
        {
            Invalid("Rehydration handoff record binding is malformed.");
        }

        if (record.HandoffStatus is not null && record.HandoffStatus is not ("passed" or "failed" or "not-run"))
        {
            Invalid("Rehydration handoff status is unsupported.");
        }

        if (record.PreHandoffRecordSha256 is not null && !IsDigest(record.PreHandoffRecordSha256))
        {
            Invalid("Rehydration pre-handoff record binding is malformed.");
        }
        if (record.IsPassed)
        {
            if (record.ProtectedImageSize == 0
                || !IsDigest(record.NativeImageSha256)
                || record.NativeImageSize is <= 0 or > RehydrationLimits.MaximumNativeImageBytes
                || record.FirstFailureStage is not null
                || record.MaterializationStatus != "passed"
                || recordDiagnostics.Any(diagnostic => diagnostic.Severity == nameof(DiagnosticSeverity.Error)))
            {
                Invalid("A passed rehydration record must bind a valid Native Image and no failure stage.");
            }
        }
        else if (record.NativeImageSha256 is not null
                 || record.NativeImageSize is not null
                 || record.FirstFailureStage != RehydrationRecord.StageName
                 || record.MaterializationStatus != "failed"
                 || recordDiagnostics.Count == 0)
        {
            Invalid("A failed rehydration record must retain diagnostics and omit Native Image bindings.");
        }

        return valid && !diagnostics.HasErrors;
    }

    private static bool ValidateLayoutEvidence(ElfLayoutEvidence evidence, DiagnosticBag diagnostics)
    {
        var valid = true;
        void Invalid(string message)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, message);
            valid = false;
        }

        if (evidence.OutputLength == 0
            || !evidence.OldProgramHeaderTable.TryGetFileEnd(out _)
            || (evidence.OldProgramHeaderTable.HasVirtualAddress && !evidence.OldProgramHeaderTable.TryGetVirtualEnd(out _))
            || !evidence.NewProgramHeaderTable.TryGetFileEnd(out var newTableEnd)
            || (evidence.NewProgramHeaderTable.HasVirtualAddress && !evidence.NewProgramHeaderTable.TryGetVirtualEnd(out _))
            || newTableEnd.Value > evidence.OutputLength
            || evidence.OldProgramHeaderTable.Size == 0
            || evidence.NewProgramHeaderTable.Size == 0
            || evidence.Placements.Count == 0
            || !IsCanonicalIdentities(evidence.Placements.Select(placement => placement.Identity), Invalid)
            || !IsCanonicalIdentities(evidence.AddressMap.Select(entry => entry.Identity), Invalid)
            || !IsCanonicalIdentities(evidence.BranchDecisions.Select(decision => decision.Identity), Invalid))
        {
            Invalid("Rehydration layout evidence contains an invalid range or canonical identity projection.");
        }

        var placementByIdentity = new Dictionary<string, ElfLayoutPlacement>(StringComparer.Ordinal);
        foreach (var placement in evidence.Placements)
        {
            if (!IsLayoutIdentity(placement.Identity)
                || !IsLayoutIdentity(placement.SourceIdentity)
                || placement.Size == 0
                || placement.Permissions != (ElfConstants.PfR | ElfConstants.PfX)
                || !IsLayoutAlignment(placement.Alignment)
                || !placement.Range.TryGetFileEnd(out var fileEnd)
                || !placement.Range.TryGetVirtualEnd(out _)
                || fileEnd.Value > evidence.OutputLength
                || !placementByIdentity.TryAdd(placement.Identity, placement))
            {
                Invalid("Rehydration layout evidence contains an invalid placement.");
            }
        }

        foreach (var entry in evidence.AddressMap)
        {
            if (!IsLayoutIdentity(entry.Identity)
                || !IsLayoutIdentity(entry.SourceIdentity)
                || !placementByIdentity.TryGetValue(entry.Identity, out var placement)
                || entry.OutputRange != placement.Range
                || (entry.SourceRange is { } sourceRange
                    && (!sourceRange.TryGetFileEnd(out _)
                        || (sourceRange.HasVirtualAddress && !sourceRange.TryGetVirtualEnd(out _)))))
            {
                Invalid("Rehydration layout evidence contains an invalid address-map entry.");
            }
        }

        foreach (var decision in evidence.BranchDecisions)
        {
            if (!IsLayoutIdentity(decision.Identity)
                || !IsLayoutIdentity(decision.SourceIdentity)
                || !IsLayoutIdentity(decision.TargetIdentity)
                || !Enum.IsDefined(decision.Decision)
                || decision.SourceRange.Size != sizeof(uint)
                || !decision.SourceRange.TryGetFileEnd(out var sourceEnd)
                || sourceEnd.Value > evidence.OutputLength
                || decision.TargetRange.Size == 0
                || !decision.TargetRange.TryGetFileEnd(out var targetEnd)
                || targetEnd.Value > evidence.OutputLength
                || (decision.TargetRange.HasVirtualAddress && !decision.TargetRange.TryGetVirtualEnd(out _))
                || decision.Decision is (ElfLayoutBranchDecision.Direct or ElfLayoutBranchDecision.NearVeneer)
                    && (decision.Displacement is not long displacement
                        || displacement < ElfLayoutLimits.Branch26MinimumDisplacement
                        || displacement >= ElfLayoutLimits.Branch26MaximumDisplacementExclusive
                        || (displacement & 3) != 0)
                || decision.Decision == ElfLayoutBranchDecision.LongAddress && decision.Displacement is not null
                || decision.VeneerIdentity is not null && !IsLayoutIdentity(decision.VeneerIdentity))
            {
                Invalid("Rehydration layout evidence contains an invalid branch decision.");
            }
        }

        return valid;
    }

    private static bool IsCanonicalIdentities(IEnumerable<string> identities, Action<string> invalid)
    {
        var values = identities.ToArray();
        if (values.Length > ElfLayoutLimits.DefaultMaximumEditCount
            || values.Distinct(StringComparer.Ordinal).Count() != values.Length
            || !values.SequenceEqual(values.OrderBy(value => value, StringComparer.Ordinal)))
        {
            invalid("Rehydration layout evidence identities are not bounded and canonical.");
            return false;
        }

        return true;
    }

    private static bool IsLayoutIdentity(string? value) =>
        value is { Length: > 0 and <= ElfLayoutLimits.MaximumIdentityBytes }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '/' or ':');

    private static bool IsLayoutAlignment(ulong alignment) =>
        alignment is 0 or 1 || alignment <= ElfLayoutLimits.DefaultMaximumAlignment && (alignment & (alignment - 1)) == 0;

    private static byte[] Serialize<T>(T value) => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, JsonOptions) + "\n");

    private static void EnsureParentDirectory(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException($"Native Image output directory does not exist: {parent}");
        }
    }

    private static string CreateTemporaryPath(string path) => path + "." + Guid.NewGuid().ToString("N") + ".tmp";

    private static void WriteAndVerify(string path, byte[] bytes)
    {
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.SequentialScan))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        if (!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))
        {
            throw new IOException("Native Image publication bytes changed before rename.");
        }
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static bool IsDigest(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    private static StringComparer GetPathComparer() => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
