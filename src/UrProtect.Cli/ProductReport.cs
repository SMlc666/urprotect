using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Pack;
using UrProtect.Core.Pipeline;

namespace UrProtect.Cli;

public sealed record ProductReport(
    int SchemaVersion,
    string ToolVersion,
    bool Success,
    ProductInputReport Input,
    ProductElfReport? Elf,
    ProductDynamicReport? Dynamic,
    ProductSummaryReport Summary,
    IReadOnlyList<ProductDiagnosticReport> Diagnostics,
    ProductOutputReport? Output);

public sealed record ProductInputReport(long? ByteLength, string? Sha256);

public sealed record ProductElfReport(
    string Class,
    string Endianness,
    string Machine,
    string Type,
    string Kind);

public sealed record ProductDynamicReport(
    IReadOnlyList<string> NeededLibraries,
    string? Soname,
    string? Rpath,
    string? RunPath);

public sealed record ProductSummaryReport(
    int ProgramHeaders,
    int LoadSegments,
    int DynamicEntries,
    int DynamicSymbols,
    int SymbolVersionIndices,
    int VersionNeeds,
    int Notes,
    int RelaRelocations,
    int RelrWords,
    int AndroidPackedRelocations,
    int AnalysisCandidates);

public sealed record ProductDiagnosticReport(
    string Severity,
    string Code,
    string Message,
    ulong? Offset)
{
    public static ProductDiagnosticReport From(
        DiagnosticSeverity severity,
        string code,
        string message,
        ulong? offset = null) =>
        new(severity.ToString(), code, message, offset);

    public static ProductDiagnosticReport From(Diagnostic diagnostic) =>
        From(diagnostic.Severity, diagnostic.Code.ToString(), diagnostic.Message, diagnostic.Offset);
}

public sealed record ProductOutputReport(
    bool Requested,
    bool Published,
    bool ByteIdentical,
    string? Sha256);

public sealed record ProductPackReport(
    int SchemaVersion,
    string ToolVersion,
    bool Success,
    ProductPackInputReport Input,
    ProductPackPayloadReport Payload,
    ProductPackOutputReport Output,
    IReadOnlyList<ProductDiagnosticReport> Diagnostics);

public sealed record ProductPackInputReport(long? ByteLength, string? Sha256);

public sealed record ProductPackPayloadReport(
    string Compression,
    long SourceSize,
    long EncodedSize,
    string? SourceSha256,
    string? EncodedSha256,
    int LauncherAbiVersion,
    int FrameVersion,
    string? LauncherSha256,
    string LauncherMarker);

public sealed record ProductPackOutputReport(bool Published, string? Sha256);

public static class ProductReportFactory
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static ProductReport Create(
        string toolVersion,
        byte[] input,
        NoOpValidationResult result,
        bool outputRequested,
        bool outputPublished)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(result);
        var inputHash = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        var outputBytes = result.OutputBytes;
        var outputHash = outputBytes is null
            ? null
            : Convert.ToHexString(SHA256.HashData(outputBytes)).ToLowerInvariant();
        var byteIdentical = outputBytes is not null && input.AsSpan().SequenceEqual(outputBytes);

        return new ProductReport(
            1,
            toolVersion,
            result.IsSuccess,
            new ProductInputReport(input.Length, inputHash),
            CreateElfReport(result),
            CreateDynamicReport(result),
            CreateSummary(result),
            result.Diagnostics.Select(ProductDiagnosticReport.From).ToArray(),
            outputRequested
                ? new ProductOutputReport(outputRequested, outputPublished, byteIdentical, outputHash)
                : null);
    }

    public static ProductReport CreateFailure(
        string toolVersion,
        ProductDiagnosticReport diagnostic) =>
        new(
            1,
            toolVersion,
            false,
            new ProductInputReport(null, null),
            null,
            null,
            new ProductSummaryReport(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            new[] { diagnostic },
            null);

    public static string Serialize(ProductReport report) =>
        JsonSerializer.Serialize(report, JsonOptions);

    public static ProductPackReport CreatePack(string toolVersion, ElfPackResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return new ProductPackReport(
            1,
            toolVersion,
            result.IsSuccess,
            new ProductPackInputReport(
                result.SourceSize > 0 ? checked((long)result.SourceSize) : null,
                result.SourceSha256),
            new ProductPackPayloadReport(
                "deflate",
                checked((long)result.SourceSize),
                checked((long)result.EncodedSize),
                result.SourceSha256,
                result.EncodedSha256,
                result.LauncherAbiVersion,
                result.FrameVersion,
                result.LauncherSha256,
                LauncherContract.Marker),
            new ProductPackOutputReport(result.OutputPath is not null, result.WrapperSha256),
            result.Diagnostics.Select(ProductDiagnosticReport.From).ToArray());
    }

    public static string Serialize(ProductPackReport report) =>
        JsonSerializer.Serialize(report, JsonOptions);

    private static ProductElfReport? CreateElfReport(NoOpValidationResult result)
    {
        if (result.File is null)
        {
            return null;
        }

        var header = result.File.Header;
        return new ProductElfReport(
            header.HeaderSize == ElfConstants.HeaderSize64 ? "ELF64" : $"0x{header.HeaderSize:X}",
            "little",
            header.Machine == ElfConstants.MachineAarch64 ? "AArch64" : $"0x{header.Machine:X}",
            header.Type == ElfConstants.TypeDyn ? "ET_DYN" : $"0x{header.Type:X}",
            result.File.Kind.ToString());
    }

    private static ProductSummaryReport CreateSummary(NoOpValidationResult result)
    {
        var file = result.File;
        return new ProductSummaryReport(
            file?.ProgramHeaders.Count ?? 0,
            file?.LoadMap.Segments.Count ?? 0,
            file?.DynamicEntries.Count ?? 0,
            file?.DynamicSymbols.Count ?? 0,
            file?.SymbolVersions.VersionIndices.Count ?? 0,
            file?.SymbolVersions.NeededVersions.Count ?? 0,
            file?.Notes.Count ?? 0,
            file?.RelaRelocations.Count ?? 0,
            file?.RelrWords.Count ?? 0,
            file?.AndroidPackedRelocations.Count ?? 0,
            result.Analysis?.Candidates.Count ?? 0);
    }

    private static ProductDynamicReport? CreateDynamicReport(NoOpValidationResult result)
    {
        if (result.File is null)
        {
            return null;
        }

        var metadata = result.File.DynamicMetadata;
        return new ProductDynamicReport(
            metadata.NeededLibraries,
            metadata.Soname,
            metadata.Rpath,
            metadata.RunPath);
    }
}
