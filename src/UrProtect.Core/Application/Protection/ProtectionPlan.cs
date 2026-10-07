using System.Diagnostics;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;

using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;
namespace UrProtect.Core.Application.Protection;

/// <summary>
/// Layout-neutral result of protection analysis and code emission. It contains no
/// program-header slot, file offset, virtual placement, or final ELF bytes.
/// </summary>
public sealed record ProtectionPlan(
    string SourceSha256,
    IReadOnlyList<ProtectedImageEmitRegion> Regions,
    IReadOnlyList<ProtectedImageEntryBranchFixup> Fixups,
    IReadOnlyList<FunctionProtectionFunctionResult> Functions)
{
    public SemanticPlanSnapshot? SemanticSnapshot { get; init; }

    public int CodeByteLength => Regions.Sum(region => region.CodeBytes.Length);
}

public sealed record FunctionProtectionPlanResult(
    ProtectionPlan? Plan,
    IReadOnlyList<FunctionProtectionFunctionResult> Functions,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Plan is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>Product-owned producer options for the versioned Protected Image boundary.</summary>
public sealed record ProtectedImageProducerOptions(
    string UnitId,
    ProtectedImageProfile Profile,
    string ProducerId,
    string ProducerBuildSha256,
    string RehydratorConsumerId,
    string? ExpectedSourceSha256 = null,
    string? ExpectedRequestSha256 = null);

public sealed record ProtectedImageRoleRecord(
    int SchemaVersion,
    string ArtifactRole,
    string AbiId,
    ushort AbiVersion,
    string UnitId,
    string Profile,
    string SourceSha256,
    string ArtifactSha256,
    long ArtifactSize,
    string ProducerId,
    string ProducerBuildSha256,
    string RehydratorConsumerId,
    string RequestSha256,
    IReadOnlyList<string> Selectors,
    IReadOnlyList<string> Passes,
    string RawArtifactPath,
    bool RawArtifactRetained)
{
    public string Architecture { get; init; } = ProtectedImageAbiV1.Architecture;

    public string WorkflowOwner { get; init; } = ProtectionWorkflowIdentity.Owner;
}

public sealed record ProtectedImageEmissionResult(
    ProtectedImageRoleRecord? Role,
    byte[]? ArtifactBytes,
    IReadOnlyList<FunctionProtectionFunctionResult> Functions,
    IReadOnlyList<Diagnostic> Diagnostics,
    long? AnalysisDurationMilliseconds = null,
    long? EmissionDurationMilliseconds = null)
{
    public bool IsSuccess => Role is not null
        && ArtifactBytes is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public static class ProtectedImageAbiV1
{
    public const string ArtifactRole = "protected-image";
    public const string AbiId = "urprotect.protected-image.v1";
    public const string Architecture = "AArch64";
    public const ushort AbiVersion = ProtectedImageDocument.AbiVersion;
    public const string DefaultRehydratorConsumerId = "urprotect.rehydrator.v1";

    public static string ComputeArtifactSha256(ReadOnlySpan<byte> artifactBytes) =>
        Convert.ToHexString(SHA256.HashData(artifactBytes)).ToLowerInvariant();
}

/// <summary>
/// Converts the existing explicit protection service's layout-independent plan
/// into the managed Protected Image ABI. This class does not materialize an ELF,
/// choose a program-header slot, or perform native handoff.
/// </summary>
public sealed class ProtectedImageProducer
{
    private readonly ProtectionWorkflow workflow;

    public ProtectedImageProducer(ProtectionWorkflow? workflow = null)
    {
        this.workflow = workflow ?? new ProtectionWorkflow();
    }

    public ProtectedImageEmissionResult Emit(
        ReadOnlyMemory<byte> source,
        FunctionProtectionOptions request,
        ProtectedImageProducerOptions producerOptions)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(producerOptions);

        var diagnostics = new DiagnosticBag();
        var functions = Array.Empty<FunctionProtectionFunctionResult>();
        IReadOnlyList<FunctionSelector> selectors;
        IReadOnlyList<ProtectionPass> passes;
        try
        {
            selectors = request.Selectors?.ToArray()
                ?? throw new ArgumentException("The protection request selectors are required.", nameof(request));
            passes = request.Passes?.ToArray()
                ?? throw new ArgumentException("The protection request passes are required.", nameof(request));
        }
        catch (ArgumentException exception)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageRequestMismatch,
                exception.Message);
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray());
        }

        if (selectors.Count is 0 or > ProtectedImageLimits.MaximumSelectorCount)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "Protected Image producer selector count is outside the supported bounds.");
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray());
        }

        if (passes.Count is 0 or > 2)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "Protected Image producer pass count is outside the supported bounds.");
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray());
        }

        var sourceSnapshot = source.ToArray();
        var sourceSha256 = Convert.ToHexString(SHA256.HashData(sourceSnapshot)).ToLowerInvariant();
        if (producerOptions.ExpectedSourceSha256 is not null
            && !string.Equals(
                sourceSha256,
                NormalizeSha256(producerOptions.ExpectedSourceSha256),
                StringComparison.Ordinal))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageSourceMismatch,
                "Protected Image producer source digest does not match the requested source binding.");
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray());
        }

        string requestSha256;
        try
        {
            requestSha256 = ProtectedImageCodec.ComputeRequestSha256(
                selectors,
                passes);
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageRequestMismatch,
                "Protected Image producer request is outside the bounded request contract.");
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray());
        }

        if (producerOptions.ExpectedRequestSha256 is not null
            && !string.Equals(
                requestSha256,
                NormalizeSha256(producerOptions.ExpectedRequestSha256),
                StringComparison.Ordinal))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageRequestMismatch,
                "Protected Image producer request digest does not match the requested transformation binding.");
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray());
        }

        var analysisStarted = Stopwatch.GetTimestamp();
        var workflowPlan = workflow.Plan(
            sourceSnapshot,
            new FunctionProtectionOptions(selectors, passes));
        var analysisDurationMilliseconds = (long)Stopwatch.GetElapsedTime(analysisStarted).TotalMilliseconds;
        var planResult = workflowPlan.FunctionPlan;
        functions = planResult.Functions.ToArray();
        diagnostics.AddRange(workflowPlan.Diagnostics);
        if (!planResult.IsSuccess || planResult.Plan is null)
        {
            return new ProtectedImageEmissionResult(
                null,
                null,
                functions,
                diagnostics.ToArray(),
                analysisDurationMilliseconds,
                null);
        }

        var parsedSource = ElfParser.Parse(sourceSnapshot);
        diagnostics.AddRange(parsedSource.Diagnostics);
        if (parsedSource.File is null || diagnostics.HasErrors)
        {
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray(), analysisDurationMilliseconds, null);
        }

        var transformedTlsRelocations = FindTransformedTlsRelocations(parsedSource.File, planResult.Plan.Regions);
        if (transformedTlsRelocations.Length > 0)
        {
            if (planResult.Plan.SemanticSnapshot is null)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "A transformed TLS relocation requires a canonical semantic-plan snapshot before Protected Image publication.",
                    transformedTlsRelocations[0].Relocation.Offset);
                return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray(), analysisDurationMilliseconds, null);
            }

            ValidateTlsSnapshotSourceBindings(
                parsedSource.File,
                transformedTlsRelocations,
                planResult.Plan.SemanticSnapshot,
                diagnostics);
            if (diagnostics.HasErrors)
            {
                return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray(), analysisDurationMilliseconds, null);
            }
        }

        var operations = new List<ProtectedImageOperation>(checked(
            planResult.Plan.Regions.Count + planResult.Plan.Fixups.Count
                + (planResult.Plan.SemanticSnapshot is null ? 0 : 1)));
        var fixupsByRegion = planResult.Plan.Fixups
            .ToDictionary(fixup => fixup.SourceRegionId);
        foreach (var region in planResult.Plan.Regions.OrderBy(region => region.RegionId))
        {
            operations.Add(region);
            if (!fixupsByRegion.TryGetValue(region.RegionId, out var fixup))
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageMalformed,
                    "Protected Image producer plan contains an unbound region.");
                continue;
            }

            operations.Add(fixup);
        }

        if (planResult.Plan.SemanticSnapshot is { } semanticSnapshot)
        {
            operations.Add(new ProtectedImageSemanticPlanSnapshot(semanticSnapshot));
        }

        if (diagnostics.HasErrors)
        {
            return new ProtectedImageEmissionResult(null, null, functions, diagnostics.ToArray());
        }

        var document = new ProtectedImageDocument(
            producerOptions.UnitId,
            producerOptions.Profile,
            sourceSha256,
            producerOptions.ProducerId,
            producerOptions.ProducerBuildSha256,
            producerOptions.RehydratorConsumerId,
            requestSha256,
            selectors.Select(selector => selector.ToDisplayString()).ToArray(),
            ProtectionPassOrdering.Normalize(passes),
            operations);
        var emissionStarted = Stopwatch.GetTimestamp();
        var encoded = ProtectedImageCodec.Encode(document);
        diagnostics.AddRange(encoded.Diagnostics);
        var emissionDurationMilliseconds = (long)Stopwatch.GetElapsedTime(emissionStarted).TotalMilliseconds;
        if (!encoded.IsSuccess || encoded.ArtifactBytes is null)
        {
            return new ProtectedImageEmissionResult(
                null,
                null,
                functions,
                diagnostics.ToArray(),
                analysisDurationMilliseconds,
                emissionDurationMilliseconds);
        }

        var encodedArtifactBytes = encoded.ArtifactBytes;
        if (encodedArtifactBytes is null)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageMalformed,
                "Protected Image producer did not return artifact bytes after a successful codec result.");
            return new ProtectedImageEmissionResult(
                null,
                null,
                functions,
                diagnostics.ToArray(),
                analysisDurationMilliseconds,
                emissionDurationMilliseconds);
        }

        var decoded = ProtectedImageCodec.Decode(encodedArtifactBytes, sourceSha256, requestSha256);
        diagnostics.AddRange(decoded.Diagnostics);
        if (!decoded.IsSuccess || decoded.Image is null)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageMalformed,
                "Protected Image producer output failed the canonical ABI round trip.");
            return new ProtectedImageEmissionResult(
                null,
                null,
                functions,
                diagnostics.ToArray(),
                analysisDurationMilliseconds,
                emissionDurationMilliseconds);
        }

        var artifactBytes = encodedArtifactBytes;
        var role = new ProtectedImageRoleRecord(
            1,
            ProtectedImageAbiV1.ArtifactRole,
            ProtectedImageAbiV1.AbiId,
            ProtectedImageAbiV1.AbiVersion,
            document.UnitId,
            document.Profile.ToCliValue(),
            document.SourceSha256,
            ProtectedImageAbiV1.ComputeArtifactSha256(artifactBytes),
            artifactBytes.LongLength,
            document.ProducerId,
            document.ProducerBuildSha256,
            document.RehydratorConsumerId,
            document.RequestSha256,
            document.Selectors,
            document.Passes.Select(ProtectionPassOrdering.Describe).ToArray(),
            string.Empty,
            false)
        {
            WorkflowOwner = ProtectionWorkflowIdentity.Owner,
        };
        return new ProtectedImageEmissionResult(
            role,
            artifactBytes,
            functions,
            diagnostics.ToArray(),
            analysisDurationMilliseconds,
            emissionDurationMilliseconds);
    }

    private static TlsRelocationFacts[] FindTransformedTlsRelocations(
        ElfFile file,
        IReadOnlyList<ProtectedImageEmitRegion> regions) => file.TlsMetadata.StaticRelocations
        .Concat(file.TlsMetadata.Dynamic.Relocations)
        .Where(relocation => TlsRelocationClassifier.IsTlsRelocation(relocation.Relocation.Type))
        .Where(relocation => regions.Any(region => relocation.Relocation.Offset >= region.SourceAddress.Value
            && relocation.Relocation.Offset - region.SourceAddress.Value < region.SourceSize))
        .ToArray();

    private static void ValidateTlsSnapshotSourceBindings(
        ElfFile source,
        IReadOnlyList<TlsRelocationFacts> relocations,
        SemanticPlanSnapshot snapshot,
        DiagnosticBag diagnostics)
    {
        var decoded = SemanticPlanSnapshotCodec.Decode(snapshot.CanonicalBytes);
        diagnostics.AddRange(decoded.Diagnostics);
        if (!decoded.IsSuccess || decoded.Snapshot is null)
        {
            return;
        }

        var bindings = decoded.Snapshot.Extensions
            .OfType<SemanticTlsBindingExtension>()
            .Select(extension => extension.Binding)
            .ToArray();
        var sites = bindings
            .SelectMany(binding => binding.RelocationSites)
            .ToArray();
        foreach (var binding in bindings.Where(binding => binding.AccessModel == TlsAccessModel.InitialExec))
        {
            if (binding.GotEntry is null)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "A transformed TLSIE binding has no carried GOT entry ownership.",
                    binding.SourceRange.FileOffset.Value);
                continue;
            }

            var gotMatches = source.TlsMetadata.StaticRelocations
                .Concat(source.TlsMetadata.Dynamic.Relocations)
                .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsTprel64
                    && fact.Relocation.Offset == binding.GotEntry.SourceRange.VirtualAddress.Value
                    && fact.Relocation.Addend == binding.GotEntry.Addend
                    && fact.Symbol is not null
                    && fact.Symbol.SymbolIndex == binding.GotEntry.Symbol.SymbolIndex
                    && string.Equals(fact.Symbol.Name, binding.GotEntry.Symbol.Name, StringComparison.Ordinal))
                .ToArray();
            if (gotMatches.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "A transformed TLSIE binding does not match exactly one source-preserved GOT relocation.",
                    binding.GotEntry.SourceRange.FileOffset.Value);
            }
        }

        foreach (var fact in relocations)
        {
            if (!source.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(fact.Relocation.Offset),
                    fact.WriteSize,
                    out var sourceFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "A transformed TLS relocation has no bounded source file range.",
                    fact.Relocation.Offset);
                continue;
            }

            var matches = sites.Where(site => site.SourceRange.VirtualAddress == new VirtualAddress(fact.Relocation.Offset)
                    && site.SourceRange.FileOffset == sourceFileOffset
                    && site.SourceRange.Size == fact.WriteSize
                    && site.Binding.Kind == fact.Relocation.Kind
                    && site.Binding.RelocationType == fact.Relocation.Type
                    && site.Binding.RawInfo == fact.Relocation.Info
                    && site.Binding.SymbolIndex == fact.Relocation.SymbolIndex
                    && site.Binding.IsPlt == fact.Relocation.IsPlt
                    && string.Equals(site.Binding.SymbolName, fact.Symbol?.Name, StringComparison.Ordinal)
                    && site.Binding.Addend == fact.Relocation.Addend
                    && site.Binding.RelocationAddress == new VirtualAddress(fact.Relocation.Offset)
                    && site.Binding.RelocationTableAddress == new VirtualAddress(fact.Relocation.SourceAddress))
                .ToArray();
            if (matches.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "A transformed TLS relocation does not have exactly one matching typed model binding and semantic fixup.",
                    fact.Relocation.Offset);
            }
        }
    }

    private static string NormalizeSha256(string value) => value.Length == 64
        ? value.ToLowerInvariant()
        : string.Empty;
}
