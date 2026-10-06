using System.Diagnostics;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Protect;

namespace UrProtect.Core.Rehydrate;

public static class RehydrationLimits
{
    public const int MaximumSourceBytes = 128 * 1024 * 1024;
    public const int MaximumNativeImageBytes = 128 * 1024 * 1024;
    public const int MaximumDiagnostics = 128;
    public const int MaximumDiagnosticMessageBytes = 4096;
    public const ulong PageAlignment = 4096;
}

public sealed record RehydrationOptions(
    string ExpectedSourceSha256,
    string ExpectedRequestSha256,
    string ExpectedUnitId,
    ProtectedImageProfile ExpectedProfile,
    string ExpectedProducerId,
    string ExpectedProducerBuildSha256,
    string ExpectedConsumerId,
    string ConsumerBuildSha256);

public sealed record NativeImageDescriptor(
    int SchemaVersion,
    string ArtifactRole,
    string AbiId,
    ushort AbiVersion,
    string Architecture,
    string UnitId,
    string Profile,
    string SourceSha256,
    string ProtectedImageSha256,
    string NativeImageSha256,
    long NativeImageSize,
    string ProducerId,
    string ProducerBuildSha256,
    string ConsumerId,
    string ConsumerBuildSha256,
    string RehydrationRecordSha256);

public sealed record NativeImage(
    byte[] Bytes,
    NativeImageDescriptor Descriptor,
    ElfFile ParsedImage)
{
    public ElfLayoutEvidence? LayoutEvidence { get; init; }
}

public sealed record RehydrationRecord(
    int SchemaVersion,
    string Stage,
    string Status,
    string UnitId,
    string Profile,
    string AbiId,
    ushort AbiVersion,
    string Architecture,
    string SourceSha256,
    string RequestSha256,
    string ProtectedImageSha256,
    long ProtectedImageSize,
    string? NativeImageSha256,
    long? NativeImageSize,
    string ProducerId,
    string ProducerBuildSha256,
    string ConsumerId,
    string ConsumerBuildSha256,
    string LayoutStrategy,
    string HandoffRecordPath,
    string RawEvidenceManifestPath,
    string MaterializationStatus,
    long DurationMilliseconds,
    long? CpuMilliseconds,
    long? WorkingSetBytes,
    string? FirstFailureStage,
    IReadOnlyList<RehydrationDiagnostic> Diagnostics,
    string? HandoffRecordSha256 = null,
    string? HandoffStatus = null,
    string? PreHandoffRecordSha256 = null,
    ElfLayoutEvidence? LayoutEvidence = null)
{
    public const int CurrentSchemaVersion = 1;
    public const string StageName = "rehydration";
    public const string PassedStatus = "passed";
    public const string FailedStatus = "failed";
    public const string CurrentLayoutStrategy = "generic-elf-layout-v1";

    public bool IsPassed => string.Equals(Status, PassedStatus, StringComparison.Ordinal);
}

public sealed record RehydrationDiagnostic(string Severity, string Code, string Message, ulong? Offset)
{
    public static RehydrationDiagnostic From(Diagnostic diagnostic) =>
        new(diagnostic.Severity.ToString(), diagnostic.Code.ToString(), diagnostic.Message, diagnostic.Offset);
}

public sealed record RehydrationResult(
    NativeImage? NativeImage,
    RehydrationRecord Record,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => NativeImage is not null
        && Record.IsPassed
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Authenticates Protected Image v1 operation records and materializes their code
/// into a deterministic AArch64 Native Image. It never invokes a loader.
/// </summary>
public static class GenericRehydrationEngine
{
    public static RehydrationResult Rehydrate(
        ReadOnlyMemory<byte> source,
        ReadOnlyMemory<byte> protectedArtifact,
        RehydrationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var stopwatch = Stopwatch.StartNew();
        var process = Process.GetCurrentProcess();
        process.Refresh();
        var cpuBefore = process.TotalProcessorTime;
        var workingSetBefore = process.WorkingSet64;
        var diagnostics = new DiagnosticBag();
        var sourceSha256 = Sha256(source.Span);
        var protectedSha256 = Sha256(protectedArtifact.Span);
        var sourceBytes = source.Length <= RehydrationLimits.MaximumSourceBytes ? source.ToArray() : Array.Empty<byte>();
        var artifactBytes = protectedArtifact.Length <= ProtectedImageLimits.MaximumArtifactBytes
            ? protectedArtifact.ToArray()
            : Array.Empty<byte>();
        ProtectedImageDocument? document = null;
        byte[]? output = null;
        ElfFile? outputFile = null;
        ElfLayoutEvidence? layoutEvidence = null;
        ElfLayoutStrategy? layoutStrategy = null;

        ValidateOptions(options, diagnostics);
        if (source.Length is 0 or > RehydrationLimits.MaximumSourceBytes)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Source Image size is outside the rehydration bounds.");
        }

        if (protectedArtifact.Length is 0 or > ProtectedImageLimits.MaximumArtifactBytes)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Protected Image size is outside the rehydration bounds.");
        }

        if (!string.Equals(sourceSha256, NormalizeSha256(options.ExpectedSourceSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageSourceMismatch, "Source Image digest does not match the rehydration request.");
        }

        if (!diagnostics.HasErrors)
        {
            var decoded = ProtectedImageCodec.Decode(
                artifactBytes,
                options.ExpectedSourceSha256,
                options.ExpectedRequestSha256);
            diagnostics.AddRange(decoded.Diagnostics);
            document = decoded.Image;
        }

        if (document is not null)
        {
            ValidateIdentityBindings(document, options, diagnostics);
        }

        ElfFile? sourceFile = null;
        if (sourceBytes.Length > 0 && sourceBytes.Length <= RehydrationLimits.MaximumSourceBytes)
        {
            var parsedSource = ElfParser.Parse(sourceBytes);
            if (parsedSource.File is null || parsedSource.Diagnostics.Any(diagnostic => diagnostic.IsError))
            {
                diagnostics.AddRange(parsedSource.Diagnostics);
                diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Source Image did not pass bounded AArch64 ELF parsing.");
            }
            else
            {
                sourceFile = parsedSource.File;
            }
        }

        if (document is not null && sourceFile is not null && !diagnostics.HasErrors)
        {
            var layoutResult = Materialize(sourceBytes, sourceFile, document, diagnostics);
            layoutEvidence = layoutResult?.Evidence;
            layoutStrategy = layoutResult?.Plan?.Strategy;
            if (layoutResult?.Bytes is not null
                && layoutResult.ParsedOutput is not null
                && layoutResult.Plan is not null
                && !diagnostics.HasErrors
                && ValidateNativeImage(sourceFile, layoutResult.ParsedOutput, layoutResult.Bytes, layoutResult.Plan, diagnostics))
            {
                output = layoutResult.Bytes;
                outputFile = layoutResult.ParsedOutput;
            }
        }

        stopwatch.Stop();
        process.Refresh();
        var cpuMilliseconds = Math.Max(0, (long)(process.TotalProcessorTime - cpuBefore).TotalMilliseconds);
        var workingSetBytes = Math.Max(workingSetBefore, process.WorkingSet64);
        var success = output is not null && outputFile is not null && !diagnostics.HasErrors && document is not null;
        var record = CreateRecord(
            options,
            document,
            sourceSha256,
            protectedSha256,
            protectedArtifact.Length,
            success ? output : null,
            stopwatch.ElapsedMilliseconds,
            cpuMilliseconds,
            workingSetBytes,
            diagnostics,
            layoutStrategy,
            layoutEvidence);
        if (!success)
        {
            return new RehydrationResult(null, record, diagnostics.ToArray());
        }

        var nativeHash = Sha256(output!);
        var descriptor = new NativeImageDescriptor(
            1,
            "native-image",
            "urprotect.native-image.v1",
            1,
            ProtectedImageAbiV1.Architecture,
            document!.UnitId,
            document.Profile.ToCliValue(),
            sourceSha256,
            protectedSha256,
            nativeHash,
            output!.LongLength,
            document.ProducerId,
            document.ProducerBuildSha256,
            document.RehydratorConsumerId,
            NormalizeSha256(options.ConsumerBuildSha256),
            string.Empty);
        return new RehydrationResult(
            new NativeImage(output, descriptor, outputFile!)
            {
                LayoutEvidence = layoutEvidence,
            },
            record,
            diagnostics.ToArray());
    }

    private static void ValidateOptions(RehydrationOptions options, DiagnosticBag diagnostics)
    {
        ValidateDigest(options.ExpectedSourceSha256, "expected source", diagnostics);
        ValidateDigest(options.ExpectedRequestSha256, "expected request", diagnostics);
        ValidateDigest(options.ExpectedProducerBuildSha256, "expected producer build", diagnostics);
        ValidateDigest(options.ConsumerBuildSha256, "consumer build", diagnostics);
        ValidateIdentity(options.ExpectedUnitId, "expected unit", diagnostics);
        ValidateIdentity(options.ExpectedProducerId, "expected producer", diagnostics);
        ValidateIdentity(options.ExpectedConsumerId, "expected consumer", diagnostics);
        if (options.ExpectedProfile is not (ProtectedImageProfile.OuterExecveat or ProtectedImageProfile.HostContextEntry))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageProfileMismatch, "Expected Protected Image profile is unsupported.");
        }
    }

    private static void ValidateIdentityBindings(
        ProtectedImageDocument image,
        RehydrationOptions options,
        DiagnosticBag diagnostics)
    {
        if (!string.Equals(image.UnitId, options.ExpectedUnitId, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "Protected Image unit identity does not match the rehydration request.");
        }

        if (image.Profile != options.ExpectedProfile)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageProfileMismatch, "Protected Image profile does not match the rehydration request.");
        }

        if (!string.Equals(image.ProducerId, options.ExpectedProducerId, StringComparison.Ordinal)
            || !string.Equals(image.ProducerBuildSha256, NormalizeSha256(options.ExpectedProducerBuildSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "Protected Image producer identity does not match the rehydration request.");
        }

        if (!string.Equals(image.RehydratorConsumerId, options.ExpectedConsumerId, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageConsumerMismatch, "Protected Image consumer identity does not match the rehydration request.");
        }

        if (!string.Equals(image.RequestSha256, NormalizeSha256(options.ExpectedRequestSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRequestMismatch, "Protected Image request digest does not match the rehydration request.");
        }
    }

    private static ElfLayoutResult? Materialize(
        byte[] source,
        ElfFile sourceFile,
        ProtectedImageDocument image,
        DiagnosticBag diagnostics)
    {
        if (image.Profile != ProtectedImageProfile.OuterExecveat)
        {
            diagnostics.Error(
                DiagnosticCode.RehydrationLayoutUnavailable,
                "The current Native Image materializer supports the outer-execveat layout only.");
            return null;
        }

        var regions = image.Operations.OfType<ProtectedImageEmitRegion>()
            .OrderBy(region => region.RegionId)
            .ToArray();
        var fixups = image.Operations.OfType<ProtectedImageEntryBranchFixup>()
            .OrderBy(fixup => fixup.SourceRegionId)
            .ThenBy(fixup => fixup.SourceOffset)
            .ToArray();
        if (regions.Length == 0 || fixups.Length != regions.Length)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Protected Image operation stream is incomplete.");
            return null;
        }

        var regionRequests = regions
            .Select(region => new ElfLayoutRegionRequest(
                RegionIdentity(region.RegionId),
                RegionIdentity(region.RegionId),
                region.SourceAddress,
                region.SourceSize,
                region.CodeBytes))
            .ToArray();
        var branchRequests = fixups
            .Select(fixup => new ElfLayoutBranchRequest(
                $"entry:{fixup.SourceRegionId}:{fixup.SourceOffset}",
                RegionIdentity(fixup.SourceRegionId),
                RegionIdentity(fixup.TargetRegionId),
                fixup.SourceAddress,
                fixup.SourceOffset,
                fixup.TargetOffset))
            .ToArray();

        var options = new ElfLayoutOptions(
            MaximumOutputBytes: RehydrationLimits.MaximumNativeImageBytes,
            MaximumProgramHeaderCount: ElfLayoutLimits.DefaultMaximumProgramHeaderCount,
            MaximumGeneratedCodeBytes: ProtectedImageLimits.MaximumAggregateCodeBytes,
            MaximumVeneerCount: ElfLayoutLimits.DefaultMaximumVeneerCount,
            MaximumEditCount: ElfLayoutLimits.DefaultMaximumEditCount,
            MaximumPaddingBytes: RehydrationLimits.MaximumNativeImageBytes,
            SegmentAlignment: RehydrationLimits.PageAlignment,
            CodeAlignment: ElfLayoutLimits.DefaultCodeAlignment,
            MaximumAlignment: ElfLayoutLimits.DefaultMaximumAlignment);
        var planning = ElfLayoutPlanner.Plan(source, sourceFile, regionRequests, branchRequests, options);
        diagnostics.AddRange(planning.Diagnostics);
        if (planning.Plan is null || planning.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return null;
        }

        var materialized = ElfLayoutMaterializer.Materialize(source, sourceFile, planning.Plan);
        diagnostics.AddRange(materialized.Diagnostics);
        return materialized;
    }

    private static bool ValidateNativeImage(
        ElfFile source,
        ElfFile native,
        byte[] output,
        ElfLayoutPlan plan,
        DiagnosticBag diagnostics)
    {
        if (!native.Header.IsAarch64
            || native.Header.Type != source.Header.Type
            || output.Length is < ElfConstants.HeaderSize64 or > RehydrationLimits.MaximumNativeImageBytes
            || output.Length != (long)plan.OutputLength
            || output.AsSpan().SequenceEqual(source.Bytes.Span))
        {
            diagnostics.Error(DiagnosticCode.NativeImageMalformed, "Native Image identity, architecture, type, size, or distinctness validation failed.");
            return false;
        }

        if (native.ProgramHeaders.Count != plan.NewProgramHeaderCount
            || plan.Placements.Count == 0
            || plan.Placements.Any(placement => !native.LoadMap.Segments.Any(segment =>
                segment.IsExecutable
                && segment.ContainsFileOffset(placement.FileOffset.Value, placement.Size)
                && segment.ContainsVirtualAddress(placement.VirtualAddress.Value, placement.Size))))
        {
            diagnostics.Error(DiagnosticCode.NativeImageMalformed, "Native Image does not retain the planned executable address map.");
            return false;
        }

        return true;
    }

    private static string RegionIdentity(uint regionId) => $"region:{regionId:D10}";

    private static RehydrationRecord CreateRecord(
        RehydrationOptions options,
        ProtectedImageDocument? image,
        string sourceSha256,
        string protectedImageSha256,
        long protectedImageSize,
        byte[]? nativeImage,
        long durationMilliseconds,
        long? cpuMilliseconds,
        long? workingSetBytes,
        DiagnosticBag diagnostics,
        ElfLayoutStrategy? layoutStrategy,
        ElfLayoutEvidence? layoutEvidence) =>
        new(
            RehydrationRecord.CurrentSchemaVersion,
            RehydrationRecord.StageName,
            diagnostics.HasErrors ? RehydrationRecord.FailedStatus : RehydrationRecord.PassedStatus,
            image?.UnitId ?? options.ExpectedUnitId,
            image?.Profile.ToCliValue() ?? options.ExpectedProfile.ToCliValue(),
            ProtectedImageAbiV1.AbiId,
            ProtectedImageAbiV1.AbiVersion,
            ProtectedImageAbiV1.Architecture,
            sourceSha256,
            image?.RequestSha256 ?? NormalizeSha256(options.ExpectedRequestSha256),
            protectedImageSha256,
            protectedImageSize,
            nativeImage is null ? null : Sha256(nativeImage),
            nativeImage?.LongLength,
            image?.ProducerId ?? options.ExpectedProducerId,
            image?.ProducerBuildSha256 ?? NormalizeSha256(options.ExpectedProducerBuildSha256),
            image?.RehydratorConsumerId ?? options.ExpectedConsumerId,
            NormalizeSha256(options.ConsumerBuildSha256),
            layoutStrategy?.ToEvidenceValue() ?? RehydrationRecord.CurrentLayoutStrategy,
            "handoff.json",
            "SHA256SUMS",
            diagnostics.HasErrors ? "failed" : "passed",
            durationMilliseconds,
            cpuMilliseconds,
            workingSetBytes,
            diagnostics.HasErrors ? RehydrationRecord.StageName : null,
            diagnostics.Take(RehydrationLimits.MaximumDiagnostics)
                .Select(RehydrationDiagnostic.From)
                .ToArray(),
            LayoutEvidence: layoutEvidence);

    private static void ValidateDigest(string value, string label, DiagnosticBag diagnostics)
    {
        if (value is null || value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, $"The {label} SHA-256 binding is malformed.");
        }
    }

    private static void ValidateIdentity(string value, string label, DiagnosticBag diagnostics)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '/' or ':')))
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, $"The {label} identity is outside the bounded format.");
        }
    }

    private static string NormalizeSha256(string value) => value is not null && value.Length == 64
        ? value.ToLowerInvariant()
        : string.Empty;

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
