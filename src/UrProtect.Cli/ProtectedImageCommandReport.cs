using System.Text.Json;
using System.Text.Json.Serialization;
using UrProtect.Core.Protect;

namespace UrProtect.Cli;

/// <summary>
/// Focused CLI projection for the opt-in Protected Image producer. The legacy
/// ProductReport schema intentionally remains unchanged.
/// </summary>
public sealed record ProtectedImageCommandReport(
    int SchemaVersion,
    string ToolVersion,
    bool Success,
    ProtectedImageRoleRecord? Role,
    ProtectedImageStageRecord? Stage,
    string ArtifactPath,
    string RolePath,
    string ManifestPath,
    string StagePath,
    IReadOnlyList<ProductDiagnosticReport> Diagnostics)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize(ProtectedImageCommandReport report) =>
        JsonSerializer.Serialize(report, JsonOptions);
}
