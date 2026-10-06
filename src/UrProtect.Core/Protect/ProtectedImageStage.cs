using System.Text;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Protect;

/// <summary>Bounded diagnostic projection retained with a Protected Image stage.</summary>
public sealed record ProtectedImageStageDiagnostic(
    string Severity,
    string Code,
    string Message,
    ulong? Offset)
{
    public static ProtectedImageStageDiagnostic From(Diagnostic diagnostic) =>
        new(diagnostic.Severity.ToString(), diagnostic.Code.ToString(), diagnostic.Message, diagnostic.Offset);
}

/// <summary>
/// Product-owned evidence for the Protected Image producer stage. The record is
/// deliberately separate from ProductReport and from evaluator compatibility
/// records so the emission boundary can evolve without expanding the legacy CLI
/// report contract.
/// </summary>
public sealed record ProtectedImageStageRecord(
    int SchemaVersion,
    string Stage,
    string Status,
    string UnitId,
    string Profile,
    string? SourceSha256,
    string? RequestSha256,
    string ProducerId,
    string ProducerBuildSha256,
    string RehydratorConsumerId,
    string? ArtifactSha256,
    long? ArtifactSize,
    string CommandDigest,
    string EnvironmentDigest,
    string ArtifactPath,
    string RolePath,
    string RawEvidenceManifestPath,
    string TransformationStatus,
    int TransformedFunctionCount,
    IReadOnlyList<string> Selectors,
    IReadOnlyList<string> Passes,
    IReadOnlyList<ProtectedImageStageDiagnostic> Diagnostics,
    string? ArtifactRole = null,
    string? AbiId = null,
    ushort? AbiVersion = null,
    bool PublicationComplete = false,
    long? AnalysisDurationMilliseconds = null,
    long? EmissionDurationMilliseconds = null)
{
    public const int CurrentSchemaVersion = 1;
    public const string ProducerStage = "protected-image-producer";
    public const string PassedStatus = "passed";
    public const string FailedStatus = "failed";

    public bool IsPassed => string.Equals(Status, PassedStatus, StringComparison.Ordinal);

    public static ProtectedImageStageRecord Create(
        string status,
        string unitId,
        ProtectedImageProfile profile,
        string? sourceSha256,
        string? requestSha256,
        string producerId,
        string producerBuildSha256,
        string rehydratorConsumerId,
        string? artifactSha256,
        long? artifactSize,
        string commandDigest,
        string environmentDigest,
        string artifactPath,
        string rolePath,
        string rawEvidenceManifestPath,
        string transformationStatus,
        int transformedFunctionCount,
        IReadOnlyList<string> selectors,
        IReadOnlyList<string> passes,
        IEnumerable<Diagnostic> diagnostics,
        bool publicationComplete,
        long? analysisDurationMilliseconds = null,
        long? emissionDurationMilliseconds = null) =>
        new(
            CurrentSchemaVersion,
            ProducerStage,
            status,
            unitId,
            profile.ToCliValue(),
            sourceSha256,
            requestSha256,
            producerId,
            producerBuildSha256,
            rehydratorConsumerId,
            artifactSha256,
            artifactSize,
            commandDigest,
            environmentDigest,
            artifactPath,
            rolePath,
            rawEvidenceManifestPath,
            transformationStatus,
            transformedFunctionCount,
            selectors.ToArray(),
            passes.ToArray(),
            diagnostics
                .Take(ProtectedImageStageLimits.MaximumDiagnostics)
                .Select(ProtectedImageStageDiagnostic.From)
                .ToArray(),
            publicationComplete ? ProtectedImageAbiV1.ArtifactRole : null,
            publicationComplete ? ProtectedImageAbiV1.AbiId : null,
            publicationComplete ? ProtectedImageAbiV1.AbiVersion : null,
            publicationComplete,
            analysisDurationMilliseconds,
            emissionDurationMilliseconds);

    public bool Validate(DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        var valid = true;
        if (SchemaVersion != CurrentSchemaVersion)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "Protected Image stage schema version is unsupported.");
            valid = false;
        }

        if (!string.Equals(Stage, ProducerStage, StringComparison.Ordinal)
            || Status is not (PassedStatus or FailedStatus))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Protected Image stage identity or status is invalid.");
            valid = false;
        }

        valid &= ValidateBoundedString(UnitId, ProtectedImageStageLimits.MaximumIdentityBytes, "unit", diagnostics);
        valid &= ValidateBoundedString(Profile, ProtectedImageStageLimits.MaximumIdentityBytes, "profile", diagnostics);
        valid &= ValidateBoundedString(ProducerId, ProtectedImageStageLimits.MaximumIdentityBytes, "producer", diagnostics);
        valid &= ValidateBoundedString(RehydratorConsumerId, ProtectedImageStageLimits.MaximumIdentityBytes, "rehydrator", diagnostics);
        valid &= ValidateBoundedString(ArtifactPath, ProtectedImageStageLimits.MaximumPathBytes, "artifact path", diagnostics);
        valid &= ValidateBoundedString(RolePath, ProtectedImageStageLimits.MaximumPathBytes, "role path", diagnostics);
        valid &= ValidateBoundedString(RawEvidenceManifestPath, ProtectedImageStageLimits.MaximumPathBytes, "raw manifest path", diagnostics);
        valid &= ValidateBoundedString(TransformationStatus, ProtectedImageStageLimits.MaximumIdentityBytes, "transformation status", diagnostics);
        valid &= ValidateDigest(CommandDigest, "command", diagnostics);
        valid &= ValidateDigest(EnvironmentDigest, "environment", diagnostics);
        valid &= ValidateDigest(ProducerBuildSha256, "producer build", diagnostics);
        valid &= ValidateOptionalDigest(SourceSha256, "source", diagnostics);
        valid &= ValidateOptionalDigest(RequestSha256, "request", diagnostics);
        valid &= ValidateOptionalDigest(ArtifactSha256, "artifact", diagnostics);

        if (Selectors is null || Selectors.Count is 0 or > ProtectedImageLimits.MaximumSelectorCount)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image stage selector count is outside the supported bounds.");
            valid = false;
        }
        else
        {
            foreach (var selector in Selectors)
            {
                valid &= ValidateBoundedString(selector, ProtectedImageLimits.MaximumSelectorBytes, "selector", diagnostics);
            }
        }

        if (Passes is null || Passes.Count is 0 or > 2)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image stage pass count is outside the supported bounds.");
            valid = false;
        }

        if (Diagnostics is null || Diagnostics.Count > ProtectedImageStageLimits.MaximumDiagnostics)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image stage diagnostic count is outside the supported bounds.");
            valid = false;
        }
        else
        {
            foreach (var diagnostic in Diagnostics)
            {
                valid &= ValidateBoundedString(diagnostic.Message, ProtectedImageStageLimits.MaximumDiagnosticMessageBytes, "diagnostic message", diagnostics);
                valid &= ValidateBoundedString(diagnostic.Code, ProtectedImageStageLimits.MaximumIdentityBytes, "diagnostic code", diagnostics);
                valid &= ValidateBoundedString(diagnostic.Severity, ProtectedImageStageLimits.MaximumIdentityBytes, "diagnostic severity", diagnostics);
            }
        }

        if (TransformedFunctionCount < 0 || TransformedFunctionCount > ProtectedImageLimits.MaximumRegions)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image stage transformed-function count is outside the supported bounds.");
            valid = false;
        }

        if (ArtifactSize is < 0 or > ProtectedImageLimits.MaximumArtifactBytes)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image stage artifact size is outside the supported bounds.");
            valid = false;
        }

        if (AnalysisDurationMilliseconds is < 0 or > ProtectedImageStageLimits.MaximumDurationMilliseconds
            || EmissionDurationMilliseconds is < 0 or > ProtectedImageStageLimits.MaximumDurationMilliseconds)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "Protected Image stage benchmark duration is outside the supported bounds.");
            valid = false;
        }
        if (IsPassed)
        {
            if (ArtifactSha256 is null || ArtifactSize is null || !PublicationComplete
                || !string.Equals(ArtifactRole, ProtectedImageAbiV1.ArtifactRole, StringComparison.Ordinal)
                || !string.Equals(AbiId, ProtectedImageAbiV1.AbiId, StringComparison.Ordinal)
                || AbiVersion != ProtectedImageAbiV1.AbiVersion)
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "A passed Protected Image stage must bind a published ABI artifact.");
                valid = false;
            }
        }
        else if (PublicationComplete)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "A failed Protected Image stage cannot claim complete publication.");
            valid = false;
        }

        return valid && !diagnostics.HasErrors;
    }

    private static bool ValidateBoundedString(
        string? value,
        int maximumBytes,
        string label,
        DiagnosticBag diagnostics)
    {
        if (string.IsNullOrEmpty(value))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, $"Protected Image stage {label} must not be empty.");
            return false;
        }

        try
        {
            if (StrictUtf8.GetByteCount(value) > maximumBytes)
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, $"Protected Image stage {label} exceeds its UTF-8 byte limit.");
                return false;
            }
        }
        catch (EncoderFallbackException)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, $"Protected Image stage {label} is not valid UTF-8.");
            return false;
        }

        return true;
    }

    private static bool ValidateOptionalDigest(string? value, string label, DiagnosticBag diagnostics) =>
        value is null || ValidateDigest(value, label, diagnostics);

    private static bool ValidateDigest(string? value, string label, DiagnosticBag diagnostics)
    {
        if (value is null || value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, $"Protected Image stage {label} SHA-256 must contain exactly 64 hexadecimal characters.");
            return false;
        }

        return true;
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
}

public static class ProtectedImageStageLimits
{
    public const int MaximumIdentityBytes = 128;
    public const int MaximumPathBytes = 1024;
    public const int MaximumDiagnosticMessageBytes = 4096;
    public const int MaximumDiagnostics = 128;
    public const int MaximumEnvironmentEntries = 4096;
    public const long MaximumDurationMilliseconds = 86_400_000;
}

