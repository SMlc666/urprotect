using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Application.Validation;

/// <summary>Typed request for a filesystem-backed validation command.</summary>
public sealed record ValidationCommandRequest(
    string InputPath,
    string? CopyPath,
    string? JsonPath,
    ValidationAnalysisMode AnalysisMode);

/// <summary>Validation result together with the source snapshot and publication state.</summary>
public sealed record ValidationCommandResult(
    byte[]? InputBytes,
    ValidationResult Validation,
    bool OutputPublished)
{
    public IReadOnlyList<Diagnostic> Diagnostics => Validation.Diagnostics;
}

/// <summary>Coordinates filesystem snapshots with the decoder-independent validation workflow.</summary>
public sealed class ValidationCommandWorkflow
{
    private readonly ValidationWorkflow validationWorkflow;

    public ValidationCommandWorkflow(ValidationWorkflow? validationWorkflow = null)
    {
        this.validationWorkflow = validationWorkflow ?? new ValidationWorkflow();
    }

    public ValidationCommandResult Execute(ValidationCommandRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var outputPaths = request.CopyPath is null
            ? Array.Empty<string>()
            : new[] { request.CopyPath };
        var reportPaths = request.JsonPath is { Length: > 0 } and not "-"
            ? new[] { request.JsonPath }
            : Array.Empty<string>();
        var pathDiagnostics = FileSystemAdapter.ValidateDistinctPaths(
            new[] { request.InputPath }.Concat(outputPaths).Concat(reportPaths),
            "Usage: validation input and output paths must be distinct.",
            "Usage: invalid output path");
        if (pathDiagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return Failure(pathDiagnostics, request.AnalysisMode);
        }

        if (request.CopyPath is not null)
        {
            // Keep validation, publication, and report projection on one immutable
            // source snapshot. A second read here could make the report hash differ
            // from the bytes that were validated and copied if the input changes.
            var copyInput = FileSystemAdapter.Read(request.InputPath);
            if (!copyInput.IsSuccess)
            {
                return Failure(copyInput.Diagnostics, request.AnalysisMode);
            }

            var result = request.AnalysisMode == ValidationAnalysisMode.ObservationOnly
                ? validationWorkflow.ValidateAndCopyObservationOnly(
                    request.InputPath,
                    request.CopyPath,
                    copyInput.Bytes)
                : validationWorkflow.ValidateAndCopyStructurally(
                    request.InputPath,
                    request.CopyPath,
                    copyInput.Bytes);
            return new ValidationCommandResult(
                copyInput.Bytes,
                result,
                result.OutputBytes is not null);
        }

        var inputSnapshot = FileSystemAdapter.Read(request.InputPath);
        if (!inputSnapshot.IsSuccess)
        {
            return Failure(inputSnapshot.Diagnostics, request.AnalysisMode);
        }

        var validation = request.AnalysisMode == ValidationAnalysisMode.ObservationOnly
            ? validationWorkflow.ValidateObservationOnly(inputSnapshot.Bytes)
            : validationWorkflow.ValidateStructurally(inputSnapshot.Bytes);
        return new ValidationCommandResult(inputSnapshot.Bytes, validation, false);
    }

    private static ValidationCommandResult Failure(
        IReadOnlyList<Diagnostic> diagnostics,
        ValidationAnalysisMode analysisMode)
    {
        var validation = new ValidationResult(
            null,
            null,
            diagnostics,
            null)
        {
            AnalysisMode = analysisMode,
        };
        return new ValidationCommandResult(null, validation, false);
    }
}
