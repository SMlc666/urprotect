using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.SemanticPlanning;

using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Infrastructure;
namespace UrProtect.Core.Application.Rehydration;

public static class RehydrationLimits
{
    public const int MaximumSourceBytes = 128 * 1024 * 1024;
    public const int MaximumNativeImageBytes = 128 * 1024 * 1024;
    public const int MaximumDiagnostics = 128;
    public const int MaximumDiagnosticMessageBytes = 4096;
    public const ulong PageAlignment = 4096;
}

public sealed record RehydrationOptions(
    string ExpectedSourceSha256,
    string ExpectedRequestSha256,
    string ExpectedUnitId,
    ProtectedImageProfile ExpectedProfile,
    string ExpectedProducerId,
    string ExpectedProducerBuildSha256,
    string ExpectedConsumerId,
    string ConsumerBuildSha256,
    string? ExpectedEntrySymbol = null,
    uint HostContextAbiVersion = HostContextContract.AbiVersion,
    HostContextCapability HostContextRequiredCapabilities = HostContextContract.MandatoryCapabilities);

public sealed record NativeImageDescriptor(
    int SchemaVersion,
    string ArtifactRole,
    string AbiId,
    ushort AbiVersion,
    string Architecture,
    string UnitId,
    string Profile,
    string SourceSha256,
    string ProtectedImageSha256,
    string NativeImageSha256,
    long NativeImageSize,
    string ProducerId,
    string ProducerBuildSha256,
    string ConsumerId,
    string ConsumerBuildSha256,
    string RehydrationRecordSha256)
{
    public string WorkflowOwner { get; init; } = ProtectionWorkflowIdentity.Owner;

    public string? EntrySymbol { get; init; }

    public uint? HostContextAbiVersion { get; init; }

    public HostContextCapability? RequiredCapabilities { get; init; }

    public string? ProfileValidationStatus { get; init; }

    public string LoaderIdentity { get; init; } = "kernel.execveat-at-empty-path";
}

public sealed record NativeImage(
    byte[] Bytes,
    NativeImageDescriptor Descriptor,
    ElfFile ParsedImage)
{
    public ElfLayoutEvidence? LayoutEvidence { get; init; }

    public string WorkflowOwner { get; init; } = ProtectionWorkflowIdentity.Owner;

    public string? EntrySymbol { get; init; }

    public string? EntryStatus { get; init; }

    public string? ReleaseOrder { get; init; }

    public string LoaderIdentity { get; init; } = "host-context.sealed-memfd.dlopen";
}

public sealed record RehydrationRecord(
    int SchemaVersion,
    string Stage,
    string Status,
    string UnitId,
    string Profile,
    string AbiId,
    ushort AbiVersion,
    string Architecture,
    string SourceSha256,
    string RequestSha256,
    string ProtectedImageSha256,
    long ProtectedImageSize,
    string? NativeImageSha256,
    long? NativeImageSize,
    string ProducerId,
    string ProducerBuildSha256,
    string ConsumerId,
    string ConsumerBuildSha256,
    string LayoutStrategy,
    string HandoffRecordPath,
    string RawEvidenceManifestPath,
    string MaterializationStatus,
    long DurationMilliseconds,
    long? CpuMilliseconds,
    long? WorkingSetBytes,
    string? FirstFailureStage,
    IReadOnlyList<RehydrationDiagnostic> Diagnostics,
    string? HandoffRecordSha256 = null,
    string? HandoffStatus = null,
    string? PreHandoffRecordSha256 = null,
    ElfLayoutEvidence? LayoutEvidence = null)
{
    public string WorkflowOwner { get; init; } = ProtectionWorkflowIdentity.Owner;

    public string? EntrySymbol { get; init; }

    public string? EntryStatus { get; init; }

    public string? ReleaseOrder { get; init; }

    public string LoaderIdentity { get; init; } = "host-context.sealed-memfd.dlopen";

    public string ProfileValidationStatus { get; init; } = "not-run";

    public uint? HostContextAbiVersion { get; init; }

    public HostContextCapability? RequiredCapabilities { get; init; }

    public const int CurrentSchemaVersion = 1;
    public const string StageName = "rehydration";
    public const string PassedStatus = "passed";
    public const string FailedStatus = "failed";
    public const string CurrentLayoutStrategy = "generic-elf-layout-v1";

    public bool IsPassed => string.Equals(Status, PassedStatus, StringComparison.Ordinal);
}

public sealed record RehydrationDiagnostic(string Severity, string Code, string Message, ulong? Offset)
{
    public static RehydrationDiagnostic From(Diagnostic diagnostic) =>
        new(diagnostic.Severity.ToString(), diagnostic.Code.ToString(), diagnostic.Message, diagnostic.Offset);
}

public sealed record RehydrationResult(
    NativeImage? NativeImage,
    RehydrationRecord Record,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => NativeImage is not null
        && Record.IsPassed
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Authenticates Protected Image v1 operation records and materializes their code
/// into a deterministic AArch64 Native Image. It never invokes a loader.
/// </summary>
public static class GenericRehydrationEngine
{
    public static RehydrationResult Rehydrate(
        ReadOnlyMemory<byte> source,
        ReadOnlyMemory<byte> protectedArtifact,
        RehydrationOptions options,
        IResourceSampler? resourceSampler = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var sampler = resourceSampler ?? new ProcessResourceSampler();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var resourcesBefore = sampler.Capture();
        var diagnostics = new DiagnosticBag();
        var sourceSha256 = Sha256(source.Span);
        var protectedSha256 = Sha256(protectedArtifact.Span);
        var sourceBytes = source.Length <= RehydrationLimits.MaximumSourceBytes ? source.ToArray() : Array.Empty<byte>();
        var artifactBytes = protectedArtifact.Length <= ProtectedImageLimits.MaximumArtifactBytes
            ? protectedArtifact.ToArray()
            : Array.Empty<byte>();
        ProtectedImageDocument? document = null;
        byte[]? output = null;
        ElfFile? outputFile = null;
        ElfLayoutEvidence? layoutEvidence = null;
        ElfLayoutStrategy? layoutStrategy = null;

        ValidateOptions(options, diagnostics);
        IProfileMaterializationPolicy? profilePolicy = null;
        if (!ProfileMaterializationPolicies.TryGet(options.ExpectedProfile, out profilePolicy, diagnostics))
        {
            profilePolicy = null;
        }
        if (source.Length is 0 or > RehydrationLimits.MaximumSourceBytes)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Source Image size is outside the rehydration bounds.");
        }

        if (protectedArtifact.Length is 0 or > ProtectedImageLimits.MaximumArtifactBytes)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Protected Image size is outside the rehydration bounds.");
        }

        if (!string.Equals(sourceSha256, NormalizeSha256(options.ExpectedSourceSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageSourceMismatch, "Source Image digest does not match the rehydration request.");
        }

        if (!diagnostics.HasErrors)
        {
            var decoded = ProtectedImageCodec.Decode(
                artifactBytes,
                options.ExpectedSourceSha256,
                options.ExpectedRequestSha256);
            diagnostics.AddRange(decoded.Diagnostics);
            document = decoded.Image;
        }

        if (document is not null)
        {
            ValidateIdentityBindings(document, options, diagnostics);
        }

        ElfFile? sourceFile = null;
        if (sourceBytes.Length > 0 && sourceBytes.Length <= RehydrationLimits.MaximumSourceBytes)
        {
            var parsedSource = ElfParser.Parse(sourceBytes);
            if (parsedSource.File is null || parsedSource.Diagnostics.Any(diagnostic => diagnostic.IsError))
            {
                diagnostics.AddRange(parsedSource.Diagnostics);
                diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Source Image did not pass bounded AArch64 ELF parsing.");
            }
            else
            {
                sourceFile = parsedSource.File;
            }
        }

        SemanticPlanSnapshot? semanticSnapshot = null;
        if (document is not null && sourceFile is not null)
        {
            semanticSnapshot = ValidateTlsSemanticSnapshotPresence(sourceFile, document, diagnostics);
        }

        if (document is not null && sourceFile is not null && profilePolicy is not null && !diagnostics.HasErrors)
        {
            var sourceValid = profilePolicy.ValidateSource(sourceFile, options, diagnostics);
            var layoutResult = sourceValid
                ? Materialize(sourceBytes, sourceFile, document, profilePolicy, diagnostics, semanticSnapshot)
                : null;
            layoutEvidence = layoutResult?.Evidence;
            layoutStrategy = layoutResult?.Plan?.Strategy;
            if (layoutResult?.Bytes is not null
                && layoutResult.ParsedOutput is not null
                && layoutResult.Plan is not null
                && !diagnostics.HasErrors
                && ValidateNativeImage(sourceFile, layoutResult.ParsedOutput, layoutResult.Bytes, layoutResult.Plan, diagnostics)
                && profilePolicy.ValidateOutput(layoutResult.ParsedOutput, options, diagnostics))
            {
                output = layoutResult.Bytes;
                outputFile = layoutResult.ParsedOutput;
            }
        }

        stopwatch.Stop();
        var resourcesAfter = sampler.Capture();
        var cpuMilliseconds = Math.Max(0, resourcesAfter.CpuMilliseconds - resourcesBefore.CpuMilliseconds);
        var workingSetBytes = Math.Max(resourcesBefore.WorkingSetBytes, resourcesAfter.WorkingSetBytes);
        var success = output is not null && outputFile is not null && !diagnostics.HasErrors && document is not null;
        var record = CreateRecord(
            options,
            document,
            sourceSha256,
            protectedSha256,
            protectedArtifact.Length,
            success ? output : null,
            stopwatch.ElapsedMilliseconds,
            cpuMilliseconds,
            workingSetBytes,
            diagnostics,
            layoutStrategy,
            layoutEvidence);
        if (!success)
        {
            return new RehydrationResult(null, record, diagnostics.ToArray());
        }

        var nativeHash = Sha256(output!);
        var descriptor = new NativeImageDescriptor(
            1,
            "native-image",
            "urprotect.native-image.v1",
            1,
            ProtectedImageAbiV1.Architecture,
            document!.UnitId,
            document.Profile.ToCliValue(),
            sourceSha256,
            protectedSha256,
            nativeHash,
            output!.LongLength,
            document.ProducerId,
            document.ProducerBuildSha256,
            document.RehydratorConsumerId,
            NormalizeSha256(options.ConsumerBuildSha256),
            string.Empty)
        {
            WorkflowOwner = ProtectionWorkflowIdentity.Owner,
            EntrySymbol = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? options.ExpectedEntrySymbol ?? HostContextContract.EntrySymbol
                : null,
            HostContextAbiVersion = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? options.HostContextAbiVersion
                : null,
            RequiredCapabilities = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? options.HostContextRequiredCapabilities
                : null,
            ProfileValidationStatus = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? "host-context-entry-validated"
                : "outer-execveat-validated",
            LoaderIdentity = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? "host-context.sealed-memfd.dlopen"
                : "kernel.execveat-at-empty-path",
        };
        return new RehydrationResult(
            new NativeImage(output, descriptor, outputFile!)
            {
                LayoutEvidence = layoutEvidence,
                WorkflowOwner = ProtectionWorkflowIdentity.Owner,
                EntrySymbol = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                    ? options.ExpectedEntrySymbol ?? HostContextContract.EntrySymbol
                    : null,
                EntryStatus = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry ? "not-run" : null,
                ReleaseOrder = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry ? "not-run" : null,
                LoaderIdentity = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                    ? "host-context.sealed-memfd.dlopen"
                    : "kernel.execveat-at-empty-path",
            },
            record,
            diagnostics.ToArray());
    }

    private static SemanticPlanSnapshot? ValidateTlsSemanticSnapshotPresence(
        ElfFile source,
        ProtectedImageDocument document,
        DiagnosticBag diagnostics)
    {
        var regions = document.Operations.OfType<ProtectedImageEmitRegion>().ToArray();
        var selectedTlsRelocations = source.TlsMetadata.StaticRelocations
            .Concat(source.TlsMetadata.Dynamic.Relocations)
            .Where(relocation => TlsRelocationClassifier.IsTlsRelocation(relocation.Relocation.Type))
            .Where(relocation => regions.Any(region => relocation.Relocation.Offset >= region.SourceAddress.Value
                && relocation.Relocation.Offset - region.SourceAddress.Value < region.SourceSize))
            .ToArray();
        var snapshots = document.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().ToArray();
        if (selectedTlsRelocations.Length == 0 && snapshots.Length == 0)
        {
            return null;
        }

        if (selectedTlsRelocations.Length > 0 && snapshots.Length != 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "A transformed TLS relocation requires exactly one canonical semantic-plan snapshot operation.",
                selectedTlsRelocations[0].Relocation.Offset);
            return null;
        }

        // Decode at the publication boundary as well as in the operation codec so the
        // selected source's relocation inventory is bound to the snapshot being applied.
        var decoded = SemanticPlanSnapshotCodec.Decode(snapshots[0].CanonicalBytes);
        diagnostics.AddRange(decoded.Diagnostics);
        if (!decoded.IsSuccess || decoded.Snapshot is null)
        {
            return null;
        }

        var valid = true;
        var tlsBindings = decoded.Snapshot.Extensions
            .OfType<SemanticTlsBindingExtension>()
            .Select(extension => extension.Binding)
            .ToArray();
        if (tlsBindings.Length == 0 && selectedTlsRelocations.Length == 0)
        {
            return null;
        }

        var sourceModule = TlsStructuralAdapter.CreateImageModule(source);
        diagnostics.AddRange(sourceModule.Diagnostics);
        if (!sourceModule.IsSuccess || sourceModule.Value is null)
        {
            return null;
        }

        foreach (var binding in tlsBindings)
        {
            if (binding.AccessModel is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "The current transformed TLS semantic slice accepts only local-exec or exact TLSIE MOVW model bindings.",
                    binding.SourceRange.FileOffset.Value);
                valid = false;
            }

            if (binding.AccessModel == TlsAccessModel.InitialExec)
            {
                if (binding.GotEntry is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsBindingUnresolved,
                        "The transformed initial-exec binding has no carried GOT entry ownership.",
                        binding.SourceRange.FileOffset.Value);
                    valid = false;
                }
                else
                {
                    var gotFacts = source.TlsMetadata.StaticRelocations
                        .Concat(source.TlsMetadata.Dynamic.Relocations)
                        .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsTprel64
                            && fact.Relocation.Offset == binding.GotEntry.SourceRange.VirtualAddress.Value
                            && fact.Relocation.Addend == binding.GotEntry.Addend
                            && fact.Symbol is not null
                            && fact.Symbol.SymbolIndex == binding.GotEntry.Symbol.SymbolIndex
                            && string.Equals(fact.Symbol.Name, binding.GotEntry.Symbol.Name, StringComparison.Ordinal))
                        .ToArray();
                    if (gotFacts.Length != 1)
                    {
                        diagnostics.Error(
                            DiagnosticCode.TlsBindingUnresolved,
                            "The transformed initial-exec binding does not match exactly one source-preserved TLSIE GOT relocation.",
                            binding.GotEntry.SourceRange.FileOffset.Value);
                        valid = false;
                    }
                }
            }

            if (binding.Module != sourceModule.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The carried TLS module/template facts do not match the parsed source PT_TLS contract.",
                    binding.SourceRange.FileOffset.Value);
                valid = false;
            }

            var sourceSymbols = selectedTlsRelocations
                .Where(relocation => binding.RelocationSites.Any(site =>
                    site.SourceRange.VirtualAddress.Value == relocation.Relocation.Offset))
                .Select(relocation => TlsStructuralAdapter.ProjectSymbol(relocation.Symbol))
                .Distinct()
                .ToArray();
            if (sourceSymbols.Length != 1 || sourceSymbols[0] != binding.Symbol)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "The carried TLS symbol identity does not match the selected source relocation symbols.",
                    binding.SourceRange.FileOffset.Value);
                valid = false;
            }
        }

        var carriedSites = tlsBindings
            .SelectMany(binding => binding.RelocationSites)
            .ToArray();
        foreach (var relocation in selectedTlsRelocations)
        {
            if (!source.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(relocation.Relocation.Offset),
                    relocation.WriteSize,
                    out var sourceFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "A transformed source TLS relocation has no bounded source file range.",
                    relocation.Relocation.Offset);
                valid = false;
                continue;
            }

            var matches = carriedSites.Where(site =>
                    site.SourceRange.VirtualAddress == new VirtualAddress(relocation.Relocation.Offset)
                    && site.SourceRange.FileOffset == sourceFileOffset
                    && site.SourceRange.Size == relocation.WriteSize
                    && site.Binding.Kind == relocation.Relocation.Kind
                    && site.Binding.RelocationType == relocation.Relocation.Type
                    && site.Binding.RawInfo == relocation.Relocation.Info
                    && site.Binding.SymbolIndex == relocation.Relocation.SymbolIndex
                    && site.Binding.IsPlt == relocation.Relocation.IsPlt
                    && string.Equals(site.Binding.SymbolName, relocation.Symbol?.Name, StringComparison.Ordinal)
                    && site.Binding.Addend == relocation.Relocation.Addend
                    && site.Binding.RelocationAddress == new VirtualAddress(relocation.Relocation.Offset)
                    && site.Binding.RelocationTableAddress == new VirtualAddress(relocation.Relocation.SourceAddress))
                .ToArray();
            if (matches.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "A transformed source TLS relocation does not bind exactly one matching typed semantic model and fixup.",
                    relocation.Relocation.Offset);
                valid = false;
            }
        }

        return valid ? decoded.Snapshot : null;
    }

    private static void ValidateOptions(RehydrationOptions options, DiagnosticBag diagnostics)
    {
        ValidateDigest(options.ExpectedSourceSha256, "expected source", diagnostics);
        ValidateDigest(options.ExpectedRequestSha256, "expected request", diagnostics);
        ValidateDigest(options.ExpectedProducerBuildSha256, "expected producer build", diagnostics);
        ValidateDigest(options.ConsumerBuildSha256, "consumer build", diagnostics);
        ValidateIdentity(options.ExpectedUnitId, "expected unit", diagnostics);
        ValidateIdentity(options.ExpectedProducerId, "expected producer", diagnostics);
        ValidateIdentity(options.ExpectedConsumerId, "expected consumer", diagnostics);
        if (options.ExpectedProfile is not (ProtectedImageProfile.OuterExecveat or ProtectedImageProfile.HostContextEntry))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageProfileMismatch, "Expected Protected Image profile is unsupported.");
        }

        if (options.ExpectedProfile == ProtectedImageProfile.HostContextEntry)
        {
            var entryName = options.ExpectedEntrySymbol ?? HostContextContract.EntrySymbol;
            if (!HostContextContract.TryValidateEntryName(entryName, out var entryError))
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, entryError ?? "The HostContext entry symbol is invalid.");
            }

            if (options.HostContextAbiVersion != HostContextContract.AbiVersion
                || !HostContextContract.HasRequiredCapabilities(
                    options.HostContextRequiredCapabilities,
                    HostContextContract.MandatoryCapabilities)
                || !HostContextContract.HasOnlySupportedCapabilities(options.HostContextRequiredCapabilities))
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageUnsupported, "The HostContext ABI or capability binding is unsupported.");
            }
        }
    }

    private static void ValidateIdentityBindings(
        ProtectedImageDocument image,
        RehydrationOptions options,
        DiagnosticBag diagnostics)
    {
        if (!string.Equals(image.UnitId, options.ExpectedUnitId, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "Protected Image unit identity does not match the rehydration request.");
        }

        if (image.Profile != options.ExpectedProfile)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageProfileMismatch, "Protected Image profile does not match the rehydration request.");
        }

        if (!string.Equals(image.ProducerId, options.ExpectedProducerId, StringComparison.Ordinal)
            || !string.Equals(image.ProducerBuildSha256, NormalizeSha256(options.ExpectedProducerBuildSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "Protected Image producer identity does not match the rehydration request.");
        }

        if (!string.Equals(image.RehydratorConsumerId, options.ExpectedConsumerId, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageConsumerMismatch, "Protected Image consumer identity does not match the rehydration request.");
        }

        if (!string.Equals(image.RequestSha256, NormalizeSha256(options.ExpectedRequestSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRequestMismatch, "Protected Image request digest does not match the rehydration request.");
        }
    }

    private static ElfLayoutResult? Materialize(
        byte[] source,
        ElfFile sourceFile,
        ProtectedImageDocument image,
        IProfileMaterializationPolicy profilePolicy,
        DiagnosticBag diagnostics,
        SemanticPlanSnapshot? semanticSnapshot)
    {
        if (image.Profile != profilePolicy.Profile)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageProfileMismatch,
                "The Protected Image profile does not match the selected materialization policy.");
            return null;
        }

        var regions = image.Operations.OfType<ProtectedImageEmitRegion>()
            .OrderBy(region => region.RegionId)
            .ToArray();
        var fixups = image.Operations.OfType<ProtectedImageEntryBranchFixup>()
            .OrderBy(fixup => fixup.SourceRegionId)
            .ThenBy(fixup => fixup.SourceOffset)
            .ToArray();
        if (regions.Length == 0 || fixups.Length != regions.Length)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Protected Image operation stream is incomplete.");
            return null;
        }

        var regionRequests = regions
            .Select(region => new ElfLayoutRegionRequest(
                RegionIdentity(region.RegionId),
                RegionIdentity(region.RegionId),
                region.SourceAddress,
                region.SourceSize,
                region.CodeBytes))
            .ToArray();
        var branchRequests = fixups
            .Select(fixup => new ElfLayoutBranchRequest(
                $"entry:{fixup.SourceRegionId}:{fixup.SourceOffset}",
                RegionIdentity(fixup.SourceRegionId),
                RegionIdentity(fixup.TargetRegionId),
                fixup.SourceAddress,
                fixup.SourceOffset,
                fixup.TargetOffset))
            .ToArray();

        var tlsFixupRequests = BuildTlsFixupRequests(image, semanticSnapshot, sourceFile, diagnostics);
        if (diagnostics.HasErrors)
        {
            return null;
        }

        var options = new ElfLayoutOptions(
            MaximumOutputBytes: RehydrationLimits.MaximumNativeImageBytes,
            MaximumProgramHeaderCount: ElfLayoutLimits.DefaultMaximumProgramHeaderCount,
            MaximumGeneratedCodeBytes: ProtectedImageLimits.MaximumAggregateCodeBytes,
            MaximumVeneerCount: ElfLayoutLimits.DefaultMaximumVeneerCount,
            MaximumEditCount: ElfLayoutLimits.DefaultMaximumEditCount,
            MaximumPaddingBytes: RehydrationLimits.MaximumNativeImageBytes,
            SegmentAlignment: RehydrationLimits.PageAlignment,
            CodeAlignment: ElfLayoutLimits.DefaultCodeAlignment,
            MaximumAlignment: ElfLayoutLimits.DefaultMaximumAlignment);
        var planning = ElfLayoutPlanner.Plan(
            source,
            sourceFile,
            regionRequests,
            branchRequests,
            options,
            tlsFixupRequests);
        diagnostics.AddRange(planning.Diagnostics);
        if (planning.Plan is null || planning.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return null;
        }

        var materialized = ElfLayoutMaterializer.Materialize(source, sourceFile, planning.Plan);
        diagnostics.AddRange(materialized.Diagnostics);
        return materialized;
    }

    private static bool ValidateNativeImage(
        ElfFile source,
        ElfFile native,
        byte[] output,
        ElfLayoutPlan plan,
        DiagnosticBag diagnostics)
    {
        if (!native.Header.IsAarch64
            || native.Header.Type != source.Header.Type
            || output.Length is < ElfConstants.HeaderSize64 or > RehydrationLimits.MaximumNativeImageBytes
            || output.Length != (long)plan.OutputLength
            || output.AsSpan().SequenceEqual(source.Bytes.Span))
        {
            diagnostics.Error(DiagnosticCode.NativeImageMalformed, "Native Image identity, architecture, type, size, or distinctness validation failed.");
            return false;
        }

        if (native.ProgramHeaders.Count != plan.NewProgramHeaderCount
            || plan.Placements.Count == 0
            || plan.Placements.Any(placement => !native.LoadMap.Segments.Any(segment =>
                segment.IsExecutable
                && segment.ContainsFileOffset(placement.FileOffset.Value, placement.Size)
                && segment.ContainsVirtualAddress(placement.VirtualAddress.Value, placement.Size))))
        {
            diagnostics.Error(DiagnosticCode.NativeImageMalformed, "Native Image does not retain the planned executable address map.");
            return false;
        }

        return true;
    }

    private static IReadOnlyList<ElfLayoutTlsFixupRequest> BuildTlsFixupRequests(
        ProtectedImageDocument image,
        SemanticPlanSnapshot? snapshot,
        ElfFile sourceFile,
        DiagnosticBag diagnostics)
    {
        if (snapshot is null)
        {
            return Array.Empty<ElfLayoutTlsFixupRequest>();
        }

        var semanticFixups = TlsSemanticFixupPlanner.Build(snapshot.Plan);
        diagnostics.AddRange(semanticFixups.Diagnostics);
        if (!semanticFixups.IsSuccess)
        {
            return Array.Empty<ElfLayoutTlsFixupRequest>();
        }

        var regions = image.Operations.OfType<ProtectedImageEmitRegion>().ToArray();
        var requests = new List<ElfLayoutTlsFixupRequest>(semanticFixups.Fixups.Count);
        foreach (var fixup in semanticFixups.Fixups)
        {
            if (fixup.AccessModel is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "Rehydration currently materializes only local-exec or exact TLSIE MOVW TLS semantic fixups.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var matchingRegions = regions.Where(region =>
                    region.SourceAddress == fixup.SequenceSourceRange.VirtualAddress
                    && region.SourceSize >= fixup.SequenceSourceRange.Size)
                .ToArray();
            if (matchingRegions.Length != 1
                || fixup.RelocationOutputRange.FileOffset.Value < fixup.SequenceOutputRange.FileOffset.Value
                || fixup.RelocationOutputRange.VirtualAddress.Value < fixup.SequenceOutputRange.VirtualAddress.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A local-exec TLS semantic fixup does not map to exactly one emitted Protected Image region.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var fileDelta = fixup.RelocationOutputRange.FileOffset.Value - fixup.SequenceOutputRange.FileOffset.Value;
            var virtualDelta = fixup.RelocationOutputRange.VirtualAddress.Value - fixup.SequenceOutputRange.VirtualAddress.Value;
            var regionLength = checked((ulong)matchingRegions[0].CodeBytes.Length);
            if (fileDelta != virtualDelta
                || fileDelta > regionLength
                || fixup.RelocationOutputRange.Size > regionLength - fileDelta)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec TLS output relocation site has inconsistent file and virtual address-map deltas.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var region = matchingRegions[0];
            var identity = RegionIdentity(region.RegionId);
            if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                    fixup.RelocationSourceRange.VirtualAddress,
                    fixup.RelocationSourceRange.Size,
                    out var sourceFileOffset)
                || sourceFileOffset != fixup.RelocationSourceRange.FileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec TLS fixup source range is not the structural ELF mapping.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            requests.Add(new ElfLayoutTlsFixupRequest(identity, fileDelta, fixup));
        }

        return Array.AsReadOnly(requests.ToArray());
    }

    private static string RegionIdentity(uint regionId) => $"region:{regionId:D10}";

    private static RehydrationRecord CreateRecord(
        RehydrationOptions options,
        ProtectedImageDocument? image,
        string sourceSha256,
        string protectedImageSha256,
        long protectedImageSize,
        byte[]? nativeImage,
        long durationMilliseconds,
        long? cpuMilliseconds,
        long? workingSetBytes,
        DiagnosticBag diagnostics,
        ElfLayoutStrategy? layoutStrategy,
        ElfLayoutEvidence? layoutEvidence) =>
        new(
            RehydrationRecord.CurrentSchemaVersion,
            RehydrationRecord.StageName,
            diagnostics.HasErrors ? RehydrationRecord.FailedStatus : RehydrationRecord.PassedStatus,
            image?.UnitId ?? options.ExpectedUnitId,
            image?.Profile.ToCliValue() ?? options.ExpectedProfile.ToCliValue(),
            ProtectedImageAbiV1.AbiId,
            ProtectedImageAbiV1.AbiVersion,
            ProtectedImageAbiV1.Architecture,
            sourceSha256,
            image?.RequestSha256 ?? NormalizeSha256(options.ExpectedRequestSha256),
            protectedImageSha256,
            protectedImageSize,
            nativeImage is null ? null : Sha256(nativeImage),
            nativeImage?.LongLength,
            image?.ProducerId ?? options.ExpectedProducerId,
            image?.ProducerBuildSha256 ?? NormalizeSha256(options.ExpectedProducerBuildSha256),
            image?.RehydratorConsumerId ?? options.ExpectedConsumerId,
            NormalizeSha256(options.ConsumerBuildSha256),
            layoutStrategy?.ToEvidenceValue() ?? RehydrationRecord.CurrentLayoutStrategy,
            "handoff.json",
            "SHA256SUMS",
            diagnostics.HasErrors ? "failed" : "passed",
            durationMilliseconds,
            cpuMilliseconds,
            workingSetBytes,
            diagnostics.HasErrors ? RehydrationRecord.StageName : null,
            diagnostics.Take(RehydrationLimits.MaximumDiagnostics)
                .Select(RehydrationDiagnostic.From)
                .ToArray(),
            LayoutEvidence: layoutEvidence)
        {
            WorkflowOwner = ProtectionWorkflowIdentity.Owner,
            EntrySymbol = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? options.ExpectedEntrySymbol ?? HostContextContract.EntrySymbol
                : null,
            ProfileValidationStatus = diagnostics.HasErrors
                ? "failed"
                : options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                    ? "host-context-entry-validated"
                    : "outer-execveat-validated",
            HostContextAbiVersion = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? options.HostContextAbiVersion
                : null,
            RequiredCapabilities = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? options.HostContextRequiredCapabilities
                : null,
            LoaderIdentity = options.ExpectedProfile == ProtectedImageProfile.HostContextEntry
                ? "host-context.sealed-memfd.dlopen"
                : "kernel.execveat-at-empty-path",
            EntryStatus = diagnostics.HasErrors ? "not-run" : "not-run",
            ReleaseOrder = diagnostics.HasErrors ? "not-run" : "not-run",
        };

    private static void ValidateDigest(string value, string label, DiagnosticBag diagnostics)
    {
        if (value is null || value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, $"The {label} SHA-256 binding is malformed.");
        }
    }

    private static void ValidateIdentity(string value, string label, DiagnosticBag diagnostics)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '/' or ':')))
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, $"The {label} identity is outside the bounded format.");
        }
    }

    private static string NormalizeSha256(string value) => value is not null && value.Length == 64
        ? value.ToLowerInvariant()
        : string.Empty;

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
