using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using UrProtect.Core.SemanticPlanning;

namespace UrProtect.Core.Application;

/// <summary>Trusted host-only provider path and exact identity pins.</summary>
public sealed record ExternalJumpTableProviderInput(
    string Path,
    string ExpectedSoname,
    string ExpectedBuildIdHex,
    string ExpectedSha256);

/// <summary>A bounded private provider-file snapshot or its input diagnostics.</summary>
public sealed record ExternalJumpTableProviderFileSnapshot(
    byte[]? Bytes,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Bytes is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Application coordinator for trusted provider input. All filesystem access
/// is delegated to the Infrastructure bounded-input adapter; only private
/// bytes and redacted diagnostics are returned to semantic planning.
/// </summary>
public static class ExternalJumpTableProviderFileReader
{
    public static ExternalJumpTableProviderFileSnapshot Read(ExternalJumpTableProviderInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (string.IsNullOrWhiteSpace(input.Path)
            || string.IsNullOrWhiteSpace(input.ExpectedSoname)
            || string.IsNullOrWhiteSpace(input.ExpectedBuildIdHex)
            || string.IsNullOrWhiteSpace(input.ExpectedSha256))
        {
            return Failure(
                DiagnosticCode.InvalidArgument,
                "External jump-table provider input requires a path and exact SONAME, build-ID, and SHA-256 pins.");
        }

        var snapshot = FileSystemAdapter.ReadBoundedPrivateSnapshot(
            input.Path,
            SemanticExternalJumpTableProviderReader.MaximumProviderElfBytes);
        return snapshot.IsSuccess
            ? new ExternalJumpTableProviderFileSnapshot(snapshot.Bytes, snapshot.Diagnostics)
            : new ExternalJumpTableProviderFileSnapshot(null, snapshot.Diagnostics);
    }

    private static ExternalJumpTableProviderFileSnapshot Failure(DiagnosticCode code, string message) =>
        new(
            null,
            new[] { new Diagnostic(DiagnosticSeverity.Error, code, message) });
}
