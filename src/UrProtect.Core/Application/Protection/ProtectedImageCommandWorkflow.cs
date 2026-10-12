using System.Security.Cryptography;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using UrProtect.Core.Infrastructure.ProtectedImage;

namespace UrProtect.Core.Application.Protection;

/// <summary>Typed request for the filesystem-backed Protected Image producer.</summary>
public sealed record ProtectedImageCommandRequest(
    string InputPath,
    string ArtifactPath,
    string RolePath,
    string ManifestPath,
    string StagePath,
    string? JsonPath,
    string UnitId,
    ProtectedImageProfile Profile,
    string ProducerId,
    string? ProducerBuildSha256,
    string RehydratorConsumerId,
    string? ExpectedSourceSha256,
    string? ExpectedRequestSha256,
    IReadOnlyList<FunctionSelector> Functions,
    IReadOnlyList<ProtectionPass> Passes,
    IReadOnlyList<string> CommandArguments,
    string ToolVersion);

/// <summary>Producer output and stage evidence consumed by CLI rendering.</summary>
public sealed record ProtectedImageCommandResult(
    byte[]? InputBytes,
    ProtectedImageRoleRecord? Role,
    ProtectedImageStageRecord Stage,
    IReadOnlyList<Diagnostic> Diagnostics,
    bool Published,
    string ArtifactPath,
    string RolePath,
    string ManifestPath,
    string StagePath)
{
    public bool IsSuccess => Published && Role is not null && !Diagnostics.Any(diagnostic => diagnostic.IsError);
}

/// <summary>
/// Coordinates source snapshots, semantic protection emission, and atomic
/// Protected Image/stage publication. Filesystem and evidence side effects are
/// delegated to Infrastructure adapters.
/// </summary>
public static class ProtectedImageCommandWorkflow
{
    public static ProtectedImageCommandResult Execute(ProtectedImageCommandRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var pathDiagnostics = FileSystemAdapter.ValidateDistinctPaths(
            new[]
            {
                request.InputPath,
                request.ArtifactPath,
                request.RolePath,
                request.ManifestPath,
                request.StagePath,
            }.Concat(request.JsonPath is { Length: > 0 } and not "-"
                ? new[] { request.JsonPath }
                : Array.Empty<string>()),
            "Usage: protect-image input and evidence output paths must be distinct.",
            "Usage: invalid Protected Image output path");
        if (pathDiagnostics.Any(diagnostic => diagnostic.IsError))
        {
            var stage = CreateStage(request, null, null, BuildSha256(request), null, "not-started", 0, pathDiagnostics, ProtectedImageStageRecord.FailedStatus, false);
            return Result(null, null, stage, pathDiagnostics, false, request);
        }

        var input = FileSystemAdapter.Read(request.InputPath);
        var producerBuildSha256 = BuildSha256(request);
        if (!input.IsSuccess)
        {
            var stage = CreateStage(request, null, null, producerBuildSha256, null, "not-started", 0, input.Diagnostics, ProtectedImageStageRecord.FailedStatus, false);
            var stageDiagnostics = WriteStage(request.StagePath, stage);
            var diagnostics = input.Diagnostics.Concat(stageDiagnostics).ToArray();
            return Result(null, null, stage with { Diagnostics = diagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray() }, diagnostics, false, request);
        }

        var sourceSha256 = Sha256(input.Bytes);
        string? requestSha256 = null;
        try
        {
            requestSha256 = ProtectedImageCodec.ComputeRequestSha256(request.Functions, request.Passes);
        }
        catch (ArgumentException)
        {
            // The producer emits the stable request diagnostic; stage identity remains bounded.
        }

        var producerOptions = new ProtectedImageProducerOptions(
            request.UnitId,
            request.Profile,
            request.ProducerId,
            producerBuildSha256,
            request.RehydratorConsumerId,
            request.ExpectedSourceSha256,
            request.ExpectedRequestSha256);
        var emission = new ProtectionWorkflow().Emit(
            input.Bytes,
            new FunctionProtectionOptions(request.Functions, request.Passes),
            producerOptions);
        var transformedCount = emission.Functions.Count(function => function.Transformed);
        if (!emission.IsSuccess || emission.Role is null || emission.ArtifactBytes is null)
        {
            var failedStage = CreateStage(
                request,
                sourceSha256,
                requestSha256,
                emission.Role?.ProducerBuildSha256 ?? producerBuildSha256,
                null,
                emission.Functions.Count == 0 ? "not-started" : "failed",
                transformedCount,
                emission.Diagnostics,
                ProtectedImageStageRecord.FailedStatus,
                false,
                emission.AnalysisDurationMilliseconds,
                emission.EmissionDurationMilliseconds);
            var stageDiagnostics = WriteStage(request.StagePath, failedStage);
            var diagnostics = emission.Diagnostics.Concat(stageDiagnostics).ToArray();
            return Result(
                input.Bytes,
                null,
                failedStage with { Diagnostics = diagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray() },
                diagnostics,
                false,
                request);
        }

        var successStage = CreateStage(
            request,
            emission.Role.SourceSha256,
            emission.Role.RequestSha256,
            emission.Role.ProducerBuildSha256,
            emission.Role,
            "passed",
            transformedCount,
            emission.Diagnostics,
            ProtectedImageStageRecord.PassedStatus,
            true,
            emission.AnalysisDurationMilliseconds,
            emission.EmissionDurationMilliseconds);
        var publication = ProtectedImagePublisher.Publish(
            emission,
            request.ArtifactPath,
            request.RolePath,
            request.ManifestPath,
            request.StagePath,
            successStage);
        if (!publication.Published)
        {
            var diagnostics = emission.Diagnostics.Concat(publication.Diagnostics).ToArray();
            var failedStage = successStage with
            {
                Status = ProtectedImageStageRecord.FailedStatus,
                ArtifactSha256 = null,
                ArtifactSize = null,
                ArtifactRole = null,
                AbiId = null,
                AbiVersion = null,
                PublicationComplete = false,
                TransformationStatus = "publication-failed",
                FirstFailureStage = ProtectionWorkflowStage.Publication.ToString(),
                Diagnostics = diagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray(),
            };
            var stageDiagnostics = WriteStage(request.StagePath, failedStage);
            diagnostics = diagnostics.Concat(stageDiagnostics).ToArray();
            return Result(input.Bytes, null, failedStage, diagnostics, false, request);
        }

        var publishedRole = publication.Role ?? emission.Role;
        var publishedStage = successStage with
        {
            ArtifactPath = request.ArtifactPath,
            RolePath = request.RolePath,
            RawEvidenceManifestPath = request.ManifestPath,
            ArtifactSha256 = publishedRole.ArtifactSha256,
            ArtifactSize = publishedRole.ArtifactSize,
            Diagnostics = emission.Diagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray(),
        };
        return Result(input.Bytes, publishedRole, publishedStage, emission.Diagnostics, true, request);
    }

    private static ProtectedImageCommandResult Result(
        byte[]? input,
        ProtectedImageRoleRecord? role,
        ProtectedImageStageRecord stage,
        IEnumerable<Diagnostic> diagnostics,
        bool published,
        ProtectedImageCommandRequest request) =>
        new(input, role, stage, diagnostics.ToArray(), published, request.ArtifactPath, request.RolePath, request.ManifestPath, request.StagePath);

    private static ProtectedImageStageRecord CreateStage(
        ProtectedImageCommandRequest request,
        string? sourceSha256,
        string? requestSha256,
        string producerBuildSha256,
        ProtectedImageRoleRecord? role,
        string transformationStatus,
        int transformedCount,
        IEnumerable<Diagnostic> diagnostics,
        string status,
        bool publicationComplete,
        long? analysisDurationMilliseconds = null,
        long? emissionDurationMilliseconds = null) =>
        ProtectedImageStageRecord.Create(
            status,
            request.UnitId,
            request.Profile,
            sourceSha256,
            requestSha256,
            request.ProducerId,
            producerBuildSha256,
            request.RehydratorConsumerId,
            role?.ArtifactSha256,
            role?.ArtifactSize,
            CommandEvidenceAdapter.ComputeCommandDigest(request.CommandArguments),
            CommandEvidenceAdapter.ComputeEnvironmentDigest(ProtectedImageStageLimits.MaximumEnvironmentEntries),
            request.ArtifactPath,
            request.RolePath,
            request.ManifestPath,
            transformationStatus,
            transformedCount,
            request.Functions.Select(selector => selector.ToDisplayString()).ToArray(),
            ProtectionPassOrdering.Normalize(request.Passes).Select(ProtectionPassOrdering.Describe).ToArray(),
            diagnostics,
            publicationComplete,
            analysisDurationMilliseconds,
            emissionDurationMilliseconds);

    private static IReadOnlyList<Diagnostic> WriteStage(string path, ProtectedImageStageRecord stage)
    {
        if (ProtectedImagePublisher.WriteStage(path, stage, out var diagnostics))
        {
            return diagnostics;
        }

        return diagnostics;
    }

    private static string BuildSha256(ProtectedImageCommandRequest request) =>
        request.ProducerBuildSha256 is { Length: > 0 }
            ? request.ProducerBuildSha256.ToLowerInvariant()
            : CommandEvidenceAdapter.ComputeAssemblyBuildSha256(
                typeof(ProtectedImageCommandWorkflow).Assembly,
                $"urprotect-cli:{request.ToolVersion}");

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
