using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Infrastructure.Rehydration;

namespace UrProtect.Core.Application.Rehydration;

/// <summary>Typed request for the filesystem-backed rehydration use case.</summary>
public sealed record RehydrationCommandRequest(
    string InputPath,
    string ArtifactPath,
    string NativeImagePath,
    string NativeImageRolePath,
    string RecordPath,
    string? JsonPath,
    RehydrationOptions Options);

/// <summary>Rehydration and publication outcome consumed by CLI rendering.</summary>
public sealed record RehydrationCommandResult(
    RehydrationResult? Rehydration,
    RehydrationPublicationResult? Publication,
    RehydrationRecord? Record,
    NativeImageDescriptor? NativeImage,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Rehydration?.IsSuccess == true && Publication?.Published == true;
}

/// <summary>
/// Coordinates source/artifact snapshots, typed rehydration, and infrastructure
/// publication. It contains no command grammar or report rendering.
/// </summary>
public static class RehydrationCommandWorkflow
{
    public static RehydrationCommandResult Execute(RehydrationCommandRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var pathDiagnostics = FileSystemAdapter.ValidateDistinctPaths(
            new[]
            {
                request.InputPath,
                request.ArtifactPath,
                request.NativeImagePath,
                request.NativeImageRolePath,
                request.RecordPath,
            }.Concat(request.JsonPath is { Length: > 0 } and not "-"
                ? new[] { request.JsonPath }
                : Array.Empty<string>()),
            "Usage: rehydrate-image input and evidence output paths must be distinct.",
            "Usage: invalid rehydration output path");
        if (pathDiagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return Failure(pathDiagnostics);
        }

        var source = FileSystemAdapter.Read(request.InputPath);
        var artifact = FileSystemAdapter.Read(request.ArtifactPath);
        var readDiagnostics = source.Diagnostics.Concat(artifact.Diagnostics).ToArray();
        if (!source.IsSuccess || !artifact.IsSuccess)
        {
            return Failure(readDiagnostics);
        }

        var result = new ProtectionWorkflow().Materialize(source.Bytes, artifact.Bytes, request.Options);
        var publication = RehydrationPublisher.Publish(
            result,
            request.NativeImagePath,
            request.NativeImageRolePath,
            request.RecordPath);
        var diagnostics = result.Diagnostics.Concat(publication.Diagnostics).ToList();
        var record = result.Record;
        if (!publication.Published && result.IsSuccess)
        {
            var publicationFailure = diagnostics.LastOrDefault(diagnostic => diagnostic.IsError);
            if (!publicationFailure.IsError)
            {
                publicationFailure = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.OutputIoFailure,
                    "Native Image publication failed.");
            }
            record = record with
            {
                Status = RehydrationRecord.FailedStatus,
                NativeImageSha256 = null,
                NativeImageSize = null,
                MaterializationStatus = "failed",
                FirstFailureStage = RehydrationRecord.StageName,
                Diagnostics = record.Diagnostics.Concat(new[] { RehydrationDiagnostic.From(publicationFailure) })
                    .Take(RehydrationLimits.MaximumDiagnostics)
                    .ToArray(),
            };
            if (!RehydrationPublisher.WriteFailureRecord(record, request.RecordPath, out var writeDiagnostics))
            {
                diagnostics.AddRange(writeDiagnostics);
            }
        }

        return new RehydrationCommandResult(
            result,
            publication,
            record,
            publication.Descriptor ?? result.NativeImage?.Descriptor,
            diagnostics);
    }

    private static RehydrationCommandResult Failure(IReadOnlyList<Diagnostic> diagnostics) =>
        new(null, null, null, null, diagnostics);
}
