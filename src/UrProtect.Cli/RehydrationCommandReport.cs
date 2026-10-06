using System.Text.Json;
using System.Text.Json.Serialization;
using UrProtect.Core.Rehydrate;

namespace UrProtect.Cli;

/// <summary>Focused report for the explicit Protected Image rehydration boundary.</summary>
public sealed record RehydrationCommandReport(
    int SchemaVersion,
    string ToolVersion,
    bool Success,
    RehydrationRecord? Record,
    NativeImageDescriptor? NativeImage,
    IReadOnlyList<ProductDiagnosticReport> Diagnostics)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize(RehydrationCommandReport report) => JsonSerializer.Serialize(report, JsonOptions);
}
