using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;

namespace UrProtect.Core.Application.Protection;

/// <summary>Typed request for the filesystem-backed protect use case.</summary>
public sealed record FunctionProtectionCommandRequest(
    string InputPath,
    string OutputPath,
    string? JsonPath,
    FunctionProtectionOptions Options);

/// <summary>Result of protection analysis and optional atomic output publication.</summary>
public sealed record FunctionProtectionCommandResult(
    byte[]? InputBytes,
    FunctionProtectionOptions Options,
    FunctionProtectionResult Protection,
    bool OutputPublished)
{
    public IReadOnlyList<Diagnostic> Diagnostics => Protection.Diagnostics;
}

/// <summary>
/// Coordinates input snapshots, selected-function protection, and output
/// publication. Filesystem details remain in Infrastructure adapters while the
/// protection service remains an in-memory application/domain seam.
/// </summary>
public sealed class FunctionProtectionWorkflow
{
    private readonly FunctionProtectionService protectionService;

    public FunctionProtectionWorkflow(FunctionProtectionService? protectionService = null)
    {
        this.protectionService = protectionService ?? new FunctionProtectionService();
    }

    public FunctionProtectionCommandResult Execute(FunctionProtectionCommandRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var pathDiagnostics = FileSystemAdapter.ValidateDistinctPaths(
            new[] { request.InputPath, request.OutputPath }
                .Concat(request.JsonPath is { Length: > 0 } and not "-"
                    ? new[] { request.JsonPath }
                    : Array.Empty<string>()),
            "Usage: --output must point to a path different from the input and report outputs.",
            "Usage: invalid output path");
        if (pathDiagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return Failure(request.Options, pathDiagnostics);
        }

        var input = FileSystemAdapter.Read(request.InputPath, captureUnixMode: true);
        if (!input.IsSuccess)
        {
            return Failure(
                request.Options,
                input.Diagnostics,
                inputBytes: null);
        }

        var protection = protectionService.Protect(input.Bytes, request.Options);
        if (!protection.IsSuccess || protection.OutputBytes is null)
        {
            return new FunctionProtectionCommandResult(input.Bytes, request.Options, protection, false);
        }

        var publication = FileSystemAdapter.PublishAtomic(
            request.OutputPath,
            protection.OutputBytes,
            input.SourceMode);
        var diagnostics = protection.Diagnostics.Concat(publication.Diagnostics).ToArray();
        if (!publication.IsSuccess)
        {
            protection = protection with
            {
                OutputBytes = null,
                Diagnostics = diagnostics,
            };
            return new FunctionProtectionCommandResult(input.Bytes, request.Options, protection, false);
        }

        return new FunctionProtectionCommandResult(
            input.Bytes,
            request.Options,
            protection with { Diagnostics = diagnostics },
            true);
    }

    private static FunctionProtectionCommandResult Failure(
        FunctionProtectionOptions options,
        IReadOnlyList<Diagnostic> diagnostics,
        byte[]? inputBytes = null)
    {
        var result = new FunctionProtectionResult(
            null,
            Array.Empty<FunctionProtectionFunctionResult>(),
            diagnostics);
        return new FunctionProtectionCommandResult(inputBytes, options, result, false);
    }
}
