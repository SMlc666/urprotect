using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Aarch64Semantics;

using UrProtect.Core.ElfLayout;
using UrProtect.Core.UnwindMetadata;
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
            semanticSnapshot = ValidateSemanticPlanSnapshotPresence(sourceFile, document, diagnostics);
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
                && SemanticStaticFunctionPointerPublicationValidator.ValidateRehydratedImage(
                    sourceFile,
                    layoutResult.ParsedOutput,
                    layoutResult.Plan,
                    semanticSnapshot,
                    diagnostics)
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

    private static SemanticPlanSnapshot? ValidateSemanticPlanSnapshotPresence(
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
        if (snapshots.Length == 0)
        {
            if (regions.Length > 0)
            {
                diagnostics.Error(
                    selectedTlsRelocations.Length > 0
                        ? DiagnosticCode.TlsBindingUnresolved
                        : DiagnosticCode.ProtectedImageMalformed,
                    "A Protected Image with selected emit regions requires exactly one canonical semantic-plan snapshot operation.",
                    selectedTlsRelocations.Length > 0
                        ? selectedTlsRelocations[0].Relocation.Offset
                        : regions[0].SourceAddress.Value);
            }

            return null;
        }

        if (snapshots.Length != 1)
        {
            diagnostics.Error(
                selectedTlsRelocations.Length > 0
                    ? DiagnosticCode.TlsBindingUnresolved
                    : DiagnosticCode.ProtectedImageMalformed,
                "The Protected Image operation stream must contain exactly one canonical semantic-plan snapshot operation.",
                selectedTlsRelocations.Length > 0
                    ? selectedTlsRelocations[0].Relocation.Offset
                    : null);
            return null;
        }

        // Decode at the publication boundary as well as in the operation codec so the
        // selected source's semantic plan is bound to the snapshot being applied.
        var decoded = SemanticPlanSnapshotCodec.Decode(snapshots[0].CanonicalBytes);
        diagnostics.AddRange(decoded.Diagnostics);
        if (!decoded.IsSuccess || decoded.Snapshot is null)
        {
            return null;
        }

        if (!SemanticDynamicImportCallContract.ValidateSourceElf(
                source,
                decoded.Snapshot,
                diagnostics)
            || !SemanticStaticFunctionPointerCallContract.ValidateSourceElf(
                source,
                decoded.Snapshot,
                diagnostics)
            || !ValidateDynamicImportLogicalOutputMap(source, document, decoded.Snapshot, diagnostics)
            || !SemanticStaticFunctionPointerPublicationValidator.ValidateLogicalOutputMap(
                document,
                decoded.Snapshot,
                diagnostics)
            || !ValidateJumpTableOwnerReferences(source, document, decoded.Snapshot, diagnostics))
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
            // Non-TLS semantic plans, including indirect-target plans, are
            // validated by the canonical codec and retained as the rehydration
            // handoff contract. They do not require PT_TLS projection.
            return decoded.Snapshot;
        }

        var sourceModule = TlsStructuralAdapter.CreateImageModule(source);
        diagnostics.AddRange(sourceModule.Diagnostics);
        if (!sourceModule.IsSuccess || sourceModule.Value is null)
        {
            return null;
        }

        foreach (var binding in tlsBindings)
        {
            if (binding.AccessModel is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec or TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic or TlsAccessModel.TlsDesc))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "The current transformed TLS semantic slice accepts only bounded local-exec, initial-exec, local-dynamic, general-dynamic, or exact TLSDESC model bindings.",
                    binding.SourceRange.FileOffset.Value);
                valid = false;
            }

            if (binding.AccessModel is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
                && (binding.ResolverCall is null
                    || binding.ModuleOwner is null
                    || (binding.AccessModel == TlsAccessModel.GeneralDynamic && binding.DtpRelOwner is null)))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "The transformed TLSLD binding has no exact resolver-call and module-owner carriers.",
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
                            && TlsStructuralAdapter.SymbolsMatch(fact.Symbol, binding.GotEntry.Symbol))
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

    private static bool ValidateJumpTableOwnerReferences(
        ElfFile source,
        ProtectedImageDocument document,
        SemanticPlanSnapshot snapshot,
        DiagnosticBag diagnostics)
    {
        var selectedRegions = document.Operations.OfType<ProtectedImageEmitRegion>().ToArray();
        var selectedRegionKeys = selectedRegions
            .Select(region => (region.SourceAddress.Value, region.SourceSize))
            .ToHashSet();
        var tables = snapshot.Extensions.OfType<SemanticJumpTableExtension>().ToArray();
        var sourceFunctionSymbols = source.FunctionSymbols
            .GroupBy(function => (function.Name, function.Value, function.Size, function.SectionIndex))
            .ToDictionary(group => group.Key, group => group.First());
        var sourceRelocationsByIdentity = source.SectionRelocations
            .GroupBy(row => (
                row.RelocationSectionIndex,
                row.SymbolTableSectionIndex,
                row.Relocation.Offset,
                row.Relocation.SourceAddress,
                row.Relocation.Type,
                row.Relocation.Addend))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var decodedFunctions = new Dictionary<(ulong Start, ulong Size), RevalidatedJumpTableFunction>();
        var semanticInstructionsByAddress = snapshot.Plan.Instructions
            .GroupBy(instruction => instruction.SourceVirtualAddress.Value)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var decoder = new AsmStoneAdapter();
        ulong decodedInstructionCount = 0;
        ulong validatedEntryCount = 0;
        ulong validatedOwnerReferenceCount = 0;
        var sectionRelocationCount = (ulong)source.SectionRelocations.Count;
        var sourceFunctions = (ulong)source.FunctionSymbols.Count;
        var tableCount = (ulong)tables.Length;
        var aggregateWorkLimit = (ulong)SemanticPlanSnapshotLimits.MaximumInstructions;
        if (tableCount > 0
            && sectionRelocationCount > 0
            && sourceFunctions > 0
            && tableCount > aggregateWorkLimit / 5 / sectionRelocationCount / sourceFunctions)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "Jump-table ownership revalidation exceeds the aggregate relocation/function work limit.");
            return false;
        }

        var valid = true;
        foreach (var table in tables)
        {
            foreach (var owner in table.OwnerReferences)
            {
                var site = owner.InstructionAddress;
                var sectionIndex = owner.OwnerFunctionSectionIndex;
                if (owner.TargetSectionIndex != sectionIndex
                    || sectionIndex >= (uint)source.SectionHeaders.Count
                    || owner.OwnerFunctionSize == 0
                    || owner.OwnerFunctionStart > ulong.MaxValue - owner.OwnerFunctionSize
                    || site < owner.OwnerFunctionStart
                    || site > owner.OwnerFunctionStart + owner.OwnerFunctionSize
                    || sizeof(uint) > owner.OwnerFunctionStart + owner.OwnerFunctionSize - site)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A jump-table RELA owner does not bind its target section to the owning function section and bounded relocation site.",
                        site);
                    valid = false;
                    continue;
                }

                var section = source.SectionHeaders[checked((int)sectionIndex)];
                if (section != owner.OwnerFunctionSection
                    || section.Type == ElfConstants.ShtNobits
                    || (section.Flags & ElfConstants.ShfExecInstr) == 0
                    || section.Size == 0
                    || section.Address > owner.OwnerFunctionStart
                    || owner.OwnerFunctionStart - section.Address > section.Size
                    || owner.OwnerFunctionSize > section.Size - (owner.OwnerFunctionStart - section.Address)
                    || site < section.Address
                    || site - section.Address > section.Size
                    || sizeof(uint) > section.Size - (site - section.Address)
                    || section.Offset > (ulong)source.Bytes.Length
                    || section.Size > (ulong)source.Bytes.Length - section.Offset)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A jump-table RELA owner section does not match the parsed source section header or contain its file-backed function/site range.",
                        site);
                    valid = false;
                    continue;
                }

                var functionDelta = owner.OwnerFunctionStart - section.Address;
                if (section.Offset > ulong.MaxValue - functionDelta)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A jump-table owner function section file mapping overflows the source address domain.",
                        owner.OwnerFunctionStart);
                    valid = false;
                    continue;
                }

                var functionFileOffset = section.Offset + functionDelta;
                if (!source.LoadMap.Segments.Any(segment =>
                        segment.IsExecutable
                        && segment.ContainsVirtualAddress(owner.OwnerFunctionStart, owner.OwnerFunctionSize)
                        && segment.ContainsFileOffset(functionFileOffset, owner.OwnerFunctionSize)
                        && owner.OwnerFunctionStart - segment.VirtualAddress == functionFileOffset - segment.FileOffset))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A jump-table owner function is not contained in one executable file-backed PT_LOAD mapping.",
                        owner.OwnerFunctionStart);
                    valid = false;
                    continue;
                }

                var siteDelta = site - section.Address;
                if (section.Offset > ulong.MaxValue - siteDelta
                    || !source.LoadMap.TryVirtualAddressToFileOffset(
                        new VirtualAddress(site),
                        sizeof(uint),
                        out var mappedSiteOffset)
                    || mappedSiteOffset.Value != section.Offset + siteDelta
                    || !source.LoadMap.Segments.Any(segment =>
                        segment.IsExecutable
                        && segment.ContainsVirtualAddress(site, sizeof(uint))
                        && segment.ContainsFileOffset(section.Offset + siteDelta, sizeof(uint))
                        && site - segment.VirtualAddress == section.Offset + siteDelta - segment.FileOffset))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A jump-table RELA instruction site does not map to its source section's file-backed bytes.",
                        site);
                    valid = false;
                    continue;
                }

                var relocationIdentity = (
                    owner.RelocationSectionIndex,
                    owner.SymbolTableSectionIndex,
                    site,
                    owner.RelocationSourceAddress,
                    owner.RelocationType,
                    owner.Addend);
                if (!sourceRelocationsByIdentity.TryGetValue(relocationIdentity, out var relocationRows)
                    || relocationRows.Length != 1
                    || relocationRows[0].TargetSectionIndex != owner.TargetSectionIndex
                    || relocationRows[0].Symbol is not { } symbol
                    || symbol.SymbolIndex != owner.SymbolIndex
                    || symbol.SymbolTableSectionIndex != owner.SymbolTableSectionIndex
                    || !string.Equals(symbol.Name, owner.SymbolName, StringComparison.Ordinal)
                    || symbol.Binding != owner.SymbolBinding
                    || symbol.Type != owner.SymbolType
                    || symbol.Visibility != owner.SymbolVisibility
                    || symbol.SectionIndex != owner.SymbolSectionIndex
                    || symbol.Value != owner.SymbolValue
                    || symbol.Size != owner.SymbolSize)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A jump-table owner snapshot row does not match exactly one linked source RELA row and its symbol-table identity.",
                        site);
                    valid = false;
                    continue;
                }

                var hasFunctionIdentity = sectionIndex <= ushort.MaxValue
                    && sourceFunctionSymbols.ContainsKey((
                        owner.OwnerFunctionName,
                        owner.OwnerFunctionStart,
                        owner.OwnerFunctionSize,
                        (ushort)sectionIndex));
                var isSelected = selectedRegionKeys.Contains((owner.OwnerFunctionStart, owner.OwnerFunctionSize));
                if (!hasFunctionIdentity || owner.IsSelectedFunction != isSelected)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A jump-table owner snapshot row does not match one parsed source function symbol and its selected-region identity.",
                        site);
                    valid = false;
                }
            }

            if ((ulong)table.Entries.Count > (ulong)SemanticPlanSnapshotLimits.MaximumInstructions - validatedEntryCount
                || (ulong)table.OwnerReferences.Count > (ulong)SemanticPlanSnapshotLimits.MaximumInstructions - validatedOwnerReferenceCount)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "Jump-table source revalidation exceeds the aggregate entry or owner-reference work limit.",
                    table.TableRange.FileOffset.Value);
                valid = false;
                continue;
            }

            validatedEntryCount += (ulong)table.Entries.Count;
            validatedOwnerReferenceCount += (ulong)table.OwnerReferences.Count;
            if (!ValidateJumpTableSourceContract(
                    source,
                    selectedRegions,
                    snapshot,
                    table,
                    decoder,
                    decodedFunctions,
                    semanticInstructionsByAddress,
                    sourceFunctionSymbols,
                    ref decodedInstructionCount,
                    diagnostics))
            {
                valid = false;
            }
        }

        return valid;
    }

    private static bool ValidateJumpTableSourceContract(
        ElfFile source,
        IReadOnlyList<ProtectedImageEmitRegion> selectedRegions,
        SemanticPlanSnapshot snapshot,
        SemanticJumpTableExtension table,
        AsmStoneAdapter decoder,
        Dictionary<(ulong Start, ulong Size), RevalidatedJumpTableFunction> decodedFunctions,
        Dictionary<ulong, SemanticInstruction[]> semanticInstructionsByAddress,
        IReadOnlyDictionary<(string Name, ulong Value, ulong Size, ushort SectionIndex), ElfFunctionSymbol> sourceFunctionSymbols,
        ref ulong decodedInstructionCount,
        DiagnosticBag diagnostics)
    {
        if (!table.HasStructuredProof
            || table.SourceInstruction is not { } sourceInstruction
            || sourceInstruction.Kind != SemanticEntityKind.Instruction
            || table.TableReferenceProducers.Count != 2
            || table.OwnerInventoryComplete
            || table.RewritePolicy != SemanticJumpTableRewritePolicy.CopiedAndRetargeted)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A jump-table publication contract is missing its bounded selected reference or safe copy policy.",
                table.TableRange.FileOffset.Value);
            return false;
        }

        var producerAddresses = table.TableReferenceProducers
            .Select(producer => producer.InstructionAddress)
            .ToArray();
        if (!TryParseInstructionAddress(sourceInstruction, out var branchAddress)
            || !semanticInstructionsByAddress.TryGetValue(branchAddress, out var branchRows)
            || branchRows.Length != 1)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A jump-table source branch is not bound to exactly one canonical selected instruction.",
                table.TableRange.FileOffset.Value);
            return false;
        }
        var matchingRegions = selectedRegions
            .Where(region => ContainsRange(region.SourceAddress.Value, region.SourceSize, branchAddress, sizeof(uint))
                && producerAddresses.All(address => ContainsRange(
                    region.SourceAddress.Value,
                    region.SourceSize,
                    address,
                    sizeof(uint))))
            .ToArray();
        if (matchingRegions.Length != 1)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A jump-table branch and its complete base-reference chain do not belong to one selected source function region.",
                branchAddress);
            return false;
        }

        var selectedRegion = matchingRegions[0];
        var selectedFunctionSymbols = sourceFunctionSymbols.Keys
            .Where(function => function.Value == selectedRegion.SourceAddress.Value
                && function.Size == selectedRegion.SourceSize)
            .Take(2)
            .ToArray();
        if (selectedFunctionSymbols.Length != 1)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A jump-table source reference does not bind to one exact selected source-function symbol range.",
                selectedRegion.SourceAddress.Value);
            return false;
        }

        var functionKey = (selectedRegion.SourceAddress.Value, selectedRegion.SourceSize);
        if (!decodedFunctions.TryGetValue(functionKey, out var sourceFunction))
        {
            if (selectedRegion.SourceSize == 0
                || selectedRegion.SourceSize % sizeof(uint) != 0
                || !source.LoadMap.TryVirtualAddressToFileOffset(
                    selectedRegion.SourceAddress,
                    selectedRegion.SourceSize,
                    out var sourceOffset)
                || sourceOffset.Value > (ulong)source.Bytes.Length
                || selectedRegion.SourceSize > (ulong)source.Bytes.Length - sourceOffset.Value
                || sourceOffset.Value > int.MaxValue)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The selected jump-table source function is not one bounded file-backed instruction range.",
                    selectedRegion.SourceAddress.Value);
                return false;
            }

            var instructionCount = selectedRegion.SourceSize / sizeof(uint);
            if (instructionCount > (ulong)SemanticPlanSnapshotLimits.MaximumInstructions - decodedInstructionCount)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "Jump-table source revalidation exceeds the aggregate selected-instruction work limit.",
                    selectedRegion.SourceAddress.Value);
                return false;
            }

            var decoded = new Aarch64FunctionInstruction[checked((int)instructionCount)];
            for (ulong index = 0; index < instructionCount; index++)
            {
                var relativeOffset = checked(index * sizeof(uint));
                var fileOffset = checked(sourceOffset.Value + relativeOffset);
                var address = checked(selectedRegion.SourceAddress.Value + relativeOffset);
                if (fileOffset > int.MaxValue)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A selected jump-table source instruction exceeds the bounded file-offset domain.",
                        address);
                    return false;
                }

                var encoding = BinaryPrimitives.ReadUInt32LittleEndian(
                    source.Bytes.Span.Slice(checked((int)fileOffset), sizeof(uint)));
                var decode = decoder.Decode(encoding, address);
                if (!decode.IsSuccess || decode.Instruction is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "A selected jump-table source instruction cannot be re-decoded at publication.",
                        address);
                    return false;
                }

                decoded[checked((int)index)] = new Aarch64FunctionInstruction(
                    fileOffset,
                    address,
                    encoding,
                    decode);
            }

            decodedInstructionCount += instructionCount;
            sourceFunction = new RevalidatedJumpTableFunction(
                decoded,
                decoded.ToDictionary(instruction => instruction.Address));
            decodedFunctions.Add(functionKey, sourceFunction);
        }

        var sourceInstructions = sourceFunction.Instructions;
        var sourceByAddress = sourceFunction.ByAddress;
        foreach (var address in producerAddresses.Append(branchAddress))
        {
            if (!sourceByAddress.TryGetValue(address, out var sourceInstructionRow)
                || !semanticInstructionsByAddress.TryGetValue(address, out var semanticRows)
                || semanticRows.Length != 1
                || semanticRows[0].SourceFileOffset.Value != sourceInstructionRow.FileOffset
                || semanticRows[0].SourceRange.Size != sizeof(uint)
                || semanticRows[0].Encoding != sourceInstructionRow.Encoding
                || !string.Equals(
                    semanticRows[0].Mnemonic,
                    sourceInstructionRow.Decode.Instruction!.Mnemonic,
                    StringComparison.OrdinalIgnoreCase))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A selected jump-table producer or branch differs from its source instruction bytes and canonical instruction identity.",
                    address);
                return false;
            }
        }

        var branchOffset = branchAddress - selectedRegion.SourceAddress.Value;
        var branchIndex = branchOffset % sizeof(uint) == 0
            && branchOffset / sizeof(uint) < (ulong)sourceInstructions.Count
                ? checked((int)(branchOffset / sizeof(uint)))
                : -1;
        if (branchIndex < 0
            || sourceInstructions[branchIndex].Address != branchAddress
            || selectedRegion.SourceAddress.Value > ulong.MaxValue - selectedRegion.SourceSize)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The selected jump-table branch index or source-function range is not uniquely bounded at publication.",
                branchAddress);
            return false;
        }

        if (!Aarch64JumpTableResolver.TryResolve(
                sourceInstructions,
                branchIndex,
                selectedRegion.SourceAddress.Value,
                selectedRegion.SourceAddress.Value + selectedRegion.SourceSize,
                sourceByAddress,
                source,
                out var resolved,
                out var resolutionFailure,
                out _)
            || resolved is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The selected jump-table source reference cannot be revalidated at publication: " + resolutionFailure,
                branchAddress);
            return false;
        }

        if (!MatchesSourceJumpTable(table, resolved))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The rederived jump-table ownership or selected source reference differs from the snapshot.",
                branchAddress);
            return false;
        }

        return true;
    }

    private static bool MatchesSourceJumpTable(
        SemanticJumpTableExtension table,
        Aarch64JumpTableResolution resolved)
    {
        var expectedTableIdentity = SemanticEntityId.Table(
            $"0x{resolved.TableBase.Value:X}:{resolved.EntryWidth}:{resolved.LowerBound}:{resolved.UpperBound}");
        if (table.TableIdentity != expectedTableIdentity
            || table.TableRange.FileOffset.Value != resolved.TableFileOffset.Value
            || table.TableRange.VirtualAddress != resolved.TableBase
            || table.TableRange.Size != resolved.TableSize
            || table.EntrySize != resolved.EntryWidth
            || table.BaseAddress != resolved.TableBase
            || table.TargetBaseAddress != resolved.TargetBaseAddress
            || table.SourceInstruction != SemanticEntityId.Instruction(new VirtualAddress(resolved.SourceAddress))
            || table.IsSigned != resolved.IsSigned
            || table.Scale != resolved.Scale
            || table.Addend != resolved.Addend
            || table.LowerBound != resolved.LowerBound
            || table.UpperBound != resolved.UpperBound
            || table.OwnerInventoryComplete
            || table.RewritePolicy != SemanticJumpTableRewritePolicy.CopiedAndRetargeted
            || table.Ownership != (resolved.HasObservedAdditionalOwner
                ? SemanticJumpTableOwnership.Shared
                : SemanticJumpTableOwnership.Ambiguous)
            || table.TableReferenceProducers.Count != resolved.TableReferenceProducers.Count
            || !table.TableReferenceProducers.SequenceEqual(resolved.TableReferenceProducers)
            || table.OwnerReferences.Count != resolved.OwnerReferences.Count
            || !table.OwnerReferences.SequenceEqual(resolved.OwnerReferences)
            || table.Entries.Count != resolved.Entries.Count
            || table.Targets.Count != resolved.Entries.Count
            || !MatchesJumpTableTarget(table.DefaultTarget, resolved.DefaultTargetAddress))
        {
            return false;
        }

        var entries = table.Entries.OrderBy(entry => entry.Index).ToArray();
        for (var index = 0; index < entries.Length; index++)
        {
            var expected = resolved.Entries[index];
            var actual = entries[index];
            if (actual.Index != expected.Index
                || actual.EncodedValue != expected.EncodedValue
                || actual.SourceRange.FileOffset.Value != expected.SourceFileOffset.Value
                || actual.SourceRange.VirtualAddress != expected.SourceAddress
                || actual.SourceRange.Size != (ulong)resolved.EntryWidth
                || !MatchesJumpTableTarget(actual.Target, expected.TargetAddress))
            {
                return false;
            }
        }

        var expectedTargets = resolved.Entries
            .Select(entry => (Identity: SemanticEntityId.BasicBlock($"0x{entry.TargetAddress.Value:X}"), Address: entry.TargetAddress))
            .OrderBy(target => target.Identity.Value, StringComparer.Ordinal)
            .ToArray();
        var actualTargets = table.Targets
            .Select(target => target.Resolution == SemanticTargetResolution.Exact
                && target.Identity is { } identity
                && target.SourceAddress is { } address
                    ? (IsValid: true, Identity: identity, Address: address)
                    : (IsValid: false, Identity: default(SemanticEntityId), Address: default(VirtualAddress)))
            .OrderBy(target => target.Identity.Value, StringComparer.Ordinal)
            .ToArray();
        return actualTargets.Length == expectedTargets.Length
            && actualTargets.Select((target, index) => target.IsValid
                && target.Identity == expectedTargets[index].Identity
                && target.Address == expectedTargets[index].Address).All(matches => matches);
    }

    private static bool MatchesJumpTableTarget(SemanticTarget? target, VirtualAddress address) =>
        target is not null
        && target.Resolution == SemanticTargetResolution.Exact
        && target.SourceAddress == address
        && target.Identity == SemanticEntityId.BasicBlock($"0x{address.Value:X}");

    private sealed record RevalidatedJumpTableFunction(
        IReadOnlyList<Aarch64FunctionInstruction> Instructions,
        IReadOnlyDictionary<ulong, Aarch64FunctionInstruction> ByAddress);

    private static bool TryParseInstructionAddress(SemanticEntityId identity, out ulong address)
    {
        address = default;
        return identity.Kind == SemanticEntityKind.Instruction
            && identity.Value.StartsWith("0x", StringComparison.Ordinal)
            && ulong.TryParse(
                identity.Value.AsSpan(2),
                NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture,
                out address);
    }

    private static bool ValidateDynamicImportLogicalOutputMap(
        ElfFile source,
        ProtectedImageDocument document,
        SemanticPlanSnapshot snapshot,
        DiagnosticBag diagnostics)
    {
        var functionsByAddress = snapshot.AddressMap.Functions
            .OrderBy(function => function.SourceRange.VirtualAddress.Value)
            .ToArray();
        var regionsByIdentity = document.Operations.OfType<ProtectedImageEmitRegion>()
            .GroupBy(region => (region.SourceAddress, region.SourceSize))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var instructionsByAddress = snapshot.Plan.Instructions
            .GroupBy(instruction => instruction.SourceVirtualAddress)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var indirectTargetsByCall = snapshot.Extensions.OfType<SemanticIndirectTargetExtension>()
            .GroupBy(target => (target.SourceInstruction, target.SourceAddress))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var decoder = new AsmStoneAdapter();
        var sourceInstructionsForImportValidation = new List<Aarch64FunctionInstruction>();
        var selectedSourceRangesForImportValidation = new List<SemanticSourceRange>();
        var valid = true;

        foreach (var import in snapshot.Extensions.OfType<SemanticDynamicImportCallExtension>())
        {
            if (!snapshot.AddressMap.TryGet(import.CallIdentity, out var callEntry)
                || !TryFindSemanticRangeOwner(functionsByAddress, callEntry.SourceRange, out var function)
                || !regionsByIdentity.TryGetValue((function.SourceRange.VirtualAddress, function.SourceRange.Size), out var regions)
                || regions.Length != 1
                || function.OutputRange.Size != (ulong)regions[0].CodeBytes.Length)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                    "The dynamic-import call does not bind to one canonical function and matching Protected Image code region.",
                    import.CallAddress.Value);
                valid = false;
                continue;
            }

            foreach (var address in import.ProducerAddresses.Append(import.CallAddress))
            {
                var identity = SemanticEntityId.Instruction(address);
                if (!snapshot.AddressMap.TryGet(identity, out var entry)
                    || !ContainsSemanticRange(function.OutputRange, entry.OutputRange)
                    || entry.OutputRange.FileOffset.Value - function.OutputRange.FileOffset.Value
                        != entry.OutputRange.VirtualAddress.Value - function.OutputRange.VirtualAddress.Value)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                        "A dynamic-import call or producer has an output address-map range outside the emitted function region.",
                        address.Value);
                    valid = false;
                    continue;
                }

                var relativeOffset = entry.OutputRange.VirtualAddress.Value - function.OutputRange.VirtualAddress.Value;
                if (relativeOffset > (ulong)regions[0].CodeBytes.Length
                    || entry.OutputRange.Size > (ulong)regions[0].CodeBytes.Length - relativeOffset)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                        "A dynamic-import call or producer output range is outside the Protected Image code bytes.",
                        address.Value);
                    valid = false;
                }
            }
        }

        // The snapshot cannot erase all three import-owner carriers to evade per-owner
        // validation: every source BLR inside a selected emitted region retains one
        // independently projected instruction and one indirect-target extension.
        foreach (var region in document.Operations.OfType<ProtectedImageEmitRegion>())
        {
            if (region.SourceSize == 0
                || region.SourceSize % sizeof(uint) != 0
                || !source.LoadMap.TryVirtualAddressToFileOffset(
                    region.SourceAddress,
                    region.SourceSize,
                    out var sourceOffset)
                || sourceOffset.Value > (ulong)source.Bytes.Length
                || region.SourceSize > (ulong)source.Bytes.Length - sourceOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                    "A selected Protected Image region is not one bounded file-backed AArch64 source range.",
                    region.SourceAddress.Value);
                valid = false;
                continue;
            }

            selectedSourceRangesForImportValidation.Add(new SemanticSourceRange(
                new FileOffset(sourceOffset.Value),
                region.SourceAddress,
                region.SourceSize));

            for (ulong relative = 0; relative < region.SourceSize; relative += sizeof(uint))
            {
                var address = new VirtualAddress(checked(region.SourceAddress.Value + relative));
                var fileOffset = checked(sourceOffset.Value + relative);
                var raw = BinaryPrimitives.ReadUInt32LittleEndian(source.Bytes.Span.Slice(
                    checked((int)fileOffset), sizeof(uint)));
                var decoded = decoder.Decode(raw, address.Value);
                if (!decoded.IsSuccess || decoded.Instruction is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                        "A selected source-region instruction cannot be independently decoded at rehydration.",
                        address.Value);
                    valid = false;
                    continue;
                }

                sourceInstructionsForImportValidation.Add(new Aarch64FunctionInstruction(
                    fileOffset,
                    address.Value,
                    raw,
                    decoded));

                if (!string.Equals(decoded.Instruction.Mnemonic, "BLR", StringComparison.OrdinalIgnoreCase)
                    || decoded.Instruction.ControlFlow != Aarch64ControlFlowKind.IndirectBranch)
                {
                    continue;
                }

                var identity = SemanticEntityId.Instruction(address);
                if (!instructionsByAddress.TryGetValue(address, out var matches)
                    || matches.Length != 1
                    || !snapshot.AddressMap.TryGet(identity, out var instructionMap)
                    || instructionMap.SourceRange.FileOffset != new FileOffset(fileOffset)
                    || instructionMap.SourceRange.Size != sizeof(uint))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                        "A source BLR in a selected region is missing its exact semantic instruction/address-map carrier.",
                        address.Value);
                    valid = false;
                    continue;
                }

                if (!indirectTargetsByCall.TryGetValue((identity, address), out var targetExtensions)
                    || targetExtensions.Length != 1)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                        "A source BLR in a selected region is missing its unique indirect-target extension.",
                        address.Value);
                    valid = false;
                    continue;
                }

                var projection = Aarch64SemanticInstructionProjector.Project(
                    new Aarch64FunctionInstruction(fileOffset, address.Value, raw, decoded));
                if (!projection.IsSuccess
                    || projection.Instruction is null
                    || !SemanticDynamicImportCallContract.SameDecodedInstruction(
                        projection.Instruction,
                        matches[0],
                        targetExtensions[0].Target))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticDynamicImportOwnerMismatch,
                        "A source BLR semantic instruction differs from its independent decoder projection.",
                        address.Value);
                    valid = false;
                }
            }
        }

        if (!SemanticDynamicImportCallContract.ValidateSourceCallOwnershipCompleteness(
                source,
                snapshot,
                selectedSourceRangesForImportValidation,
                sourceInstructionsForImportValidation,
                diagnostics)
            || !SemanticStaticFunctionPointerCallContract.ValidateSourceCallOwnershipCompleteness(
                source,
                snapshot,
                selectedSourceRangesForImportValidation,
                sourceInstructionsForImportValidation,
                diagnostics))
        {
            valid = false;
        }

        return valid;
    }

    private static bool TryFindSemanticRangeOwner(
        AddressMapEntry[] sortedFunctions,
        SemanticSourceRange range,
        out AddressMapEntry function)
    {
        function = null!;
        var low = 0;
        var high = sortedFunctions.Length;
        while (low < high)
        {
            var middle = low + ((high - low) / 2);
            if (sortedFunctions[middle].SourceRange.VirtualAddress.Value <= range.VirtualAddress.Value)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        var index = low - 1;
        if (index < 0 || !ContainsSemanticRange(sortedFunctions[index].SourceRange, range))
        {
            return false;
        }

        function = sortedFunctions[index];
        return true;
    }

    private static bool ContainsSemanticRange(SemanticSourceRange outer, SemanticSourceRange inner) =>
        inner.VirtualAddress.Value >= outer.VirtualAddress.Value
        && inner.VirtualAddress.Value - outer.VirtualAddress.Value <= outer.Size
        && inner.Size <= outer.Size - (inner.VirtualAddress.Value - outer.VirtualAddress.Value)
        && inner.FileOffset.Value >= outer.FileOffset.Value
        && inner.FileOffset.Value - outer.FileOffset.Value <= outer.Size
        && inner.Size <= outer.Size - (inner.FileOffset.Value - outer.FileOffset.Value);

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
        var jumpTableRequests = BuildJumpTableRequests(semanticSnapshot, sourceFile, diagnostics);
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
        var initialPlanning = ElfLayoutPlanner.Plan(
            source,
            sourceFile,
            regionRequests,
            branchRequests,
            options,
            tlsFixupRequests,
            Array.Empty<ElfLayoutByteEdit>(),
            jumpTableRequests);
        diagnostics.AddRange(initialPlanning.Diagnostics);
        if (initialPlanning.Plan is null || initialPlanning.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return null;
        }

        var instructionFixedRegions = BuildSemanticPcRelativeFixupRegions(
            semanticSnapshot,
            image,
            initialPlanning.Plan,
            regionRequests,
            diagnostics);
        instructionFixedRegions = BuildJumpTableReferenceFixupRegions(
            semanticSnapshot,
            image,
            sourceFile,
            initialPlanning.Plan,
            instructionFixedRegions,
            diagnostics);
        if (diagnostics.HasErrors)
        {
            return null;
        }

        var instructionPlanning = RegionCodeBytesEqual(regionRequests, instructionFixedRegions)
            ? initialPlanning
            : ElfLayoutPlanner.Plan(
                source,
                sourceFile,
                instructionFixedRegions,
                branchRequests,
                options,
                tlsFixupRequests,
                Array.Empty<ElfLayoutByteEdit>(),
                jumpTableRequests);
        if (!ReferenceEquals(instructionPlanning, initialPlanning))
        {
            diagnostics.AddRange(instructionPlanning.Diagnostics);
        }

        if (instructionPlanning.Plan is null || instructionPlanning.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return null;
        }

        if (!HaveSamePlacements(initialPlanning.Plan, instructionPlanning.Plan))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "Applying selected-function AArch64 fixups changed the physical code placement after their address map was resolved.");
            return null;
        }

        var unwindEdits = BuildUnwindEdits(
            semanticSnapshot,
            sourceFile,
            image,
            instructionPlanning.Plan,
            diagnostics);
        if (diagnostics.HasErrors)
        {
            return null;
        }

        var planning = unwindEdits.Count == 0
            ? instructionPlanning
            : ElfLayoutPlanner.Plan(
                source,
                sourceFile,
                instructionFixedRegions,
                branchRequests,
                options,
                tlsFixupRequests,
                unwindEdits,
                jumpTableRequests);
        if (!ReferenceEquals(planning, instructionPlanning))
        {
            diagnostics.AddRange(planning.Diagnostics);
        }

        if (planning.Plan is null || planning.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return null;
        }

        if (unwindEdits.Count > 0
            && !HaveSamePlacements(instructionPlanning.Plan, planning.Plan))
        {
            diagnostics.Error(
                DiagnosticCode.UnwindAddressMapMissing,
                "Adding unwind edits changed the physical code placement after the CFI address map was resolved.");
            return null;
        }

        var materialized = ElfLayoutMaterializer.Materialize(source, sourceFile, planning.Plan);
        diagnostics.AddRange(materialized.Diagnostics);
        if (unwindEdits.Count > 0 && materialized.ParsedOutput is not null)
        {
            var reparsedUnwind = UnwindMetadataParser.Parse(materialized.ParsedOutput);
            diagnostics.AddRange(reparsedUnwind.Diagnostics);
            if (!reparsedUnwind.IsSuccess)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "The materialized Native Image failed its bounded unwind metadata reparse.");
                return null;
            }
        }

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

    private static IReadOnlyList<ElfLayoutJumpTableEditRequest> BuildJumpTableRequests(
        SemanticPlanSnapshot? snapshot,
        ElfFile sourceFile,
        DiagnosticBag diagnostics)
    {
        if (snapshot is null)
        {
            return Array.Empty<ElfLayoutJumpTableEditRequest>();
        }

        var requests = new List<ElfLayoutJumpTableEditRequest>();
        foreach (var table in snapshot.Extensions.OfType<SemanticJumpTableExtension>())
        {
            if (!table.HasStructuredProof
                || table.BaseAddress is null
                || table.TargetBaseAddress is null
                || table.SourceInstruction is null
                || table.OutputRange is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A jump-table extension consumed by rehydration is missing its structured proof contract.",
                    table.TableRange.FileOffset.Value);
                continue;
            }

            if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                    table.TableRange.VirtualAddress,
                    table.TableRange.Size,
                    out var tableFileOffset)
                || tableFileOffset != table.TableRange.FileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A jump-table snapshot range is not the structural source mapping.",
                    table.TableRange.FileOffset.Value);
                continue;
            }

            var selectedFunctionMappings = snapshot.Plan.AddressMap.Entries
                .Where(entry => entry.Identity.Kind == SemanticEntityKind.Function
                    && ContainsRange(
                        entry.SourceRange.VirtualAddress.Value,
                        entry.SourceRange.Size,
                        table.TargetBaseAddress.Value.Value,
                        sizeof(uint))
                    && table.Entries.All(binding => binding.Target.SourceAddress is { } target
                        && ContainsRange(
                            entry.SourceRange.VirtualAddress.Value,
                            entry.SourceRange.Size,
                            target.Value,
                            sizeof(uint))))
                .ToArray();
            var outputBaseMappings = snapshot.Plan.AddressMap.Entries
                .Where(entry => entry.Identity.Kind == SemanticEntityKind.BasicBlock
                    && ContainsRange(
                        entry.SourceRange.VirtualAddress.Value,
                        entry.SourceRange.Size,
                        table.TargetBaseAddress.Value.Value,
                        sizeof(uint)))
                .ToArray();
            if (selectedFunctionMappings.Length != 1 || outputBaseMappings.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A copied jump table requires one selected-function mapping and one output target-base mapping.",
                    table.TableRange.FileOffset.Value);
                continue;
            }

            var outputEntryBindings = new List<ElfLayoutJumpTableEntryOutputBinding>(table.Entries.Count);
            foreach (var entry in table.Entries)
            {
                if (entry.Target.Identity is not { } targetIdentity)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        "A copied jump-table entry has no target identity for its output address binding.",
                        entry.SourceRange.FileOffset.Value);
                    continue;
                }

                var targetMappings = snapshot.Plan.AddressMap.Entries
                    .Where(mapping => mapping.Identity == targetIdentity
                        && mapping.Identity.Kind == SemanticEntityKind.BasicBlock)
                    .ToArray();
                if (targetMappings.Length != 1)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        "A copied jump-table target has no unique selected-function output mapping.",
                        entry.SourceRange.FileOffset.Value);
                    continue;
                }

                outputEntryBindings.Add(new ElfLayoutJumpTableEntryOutputBinding(
                    entry.EntryIdentity,
                    targetIdentity,
                    targetMappings[0].OutputRange.VirtualAddress));
            }

            if (diagnostics.HasErrors || outputEntryBindings.Count != table.Entries.Count)
            {
                continue;
            }

            requests.Add(new ElfLayoutJumpTableEditRequest(
                table.TableIdentity,
                table.TableRange,
                table.TargetBaseAddress.Value,
                table.EntrySize,
                table.IsSigned,
                table.Scale,
                table.Addend,
                table.RewritePolicy,
                table.Entries,
                table.Ownership,
                table.OutputRange,
                table.TableReferenceProducers,
                table.OwnerReferences,
                table.OwnerInventoryComplete,
                selectedFunctionMappings[0].SourceRange,
                selectedFunctionMappings[0].OutputRange,
                outputBaseMappings[0].Identity,
                outputBaseMappings[0].OutputRange.VirtualAddress,
                Array.AsReadOnly(outputEntryBindings.ToArray())));
        }

        return Array.AsReadOnly(requests.ToArray());
    }

    private static IReadOnlyList<ElfLayoutRegionRequest> BuildSemanticPcRelativeFixupRegions(
        SemanticPlanSnapshot? snapshot,
        ProtectedImageDocument image,
        ElfLayoutPlan layoutPlan,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        DiagnosticBag diagnostics)
    {
        var fixups = snapshot?.Plan.Fixups
            .Where(fixup => fixup.Kind is SemanticFixupKind.AdrPrelPgHi21 or SemanticFixupKind.Call26)
            .ToArray() ?? Array.Empty<SemanticFixup>();
        if (fixups.Length == 0 || snapshot is null)
        {
            return regions;
        }

        var addressMap = BuildPhysicalSemanticAddressMap(snapshot, image, layoutPlan, diagnostics);
        if (addressMap is null)
        {
            return regions;
        }

        var regionBytes = regions.ToDictionary(
            region => region.Identity,
            region => region.CodeBytes.ToArray(),
            StringComparer.Ordinal);
        var emittedLocations = new HashSet<(string RegionIdentity, ulong Offset)>();
        foreach (var fixup in fixups)
        {
            var resolution = Aarch64SemanticFixupEncoder.Resolve(fixup, addressMap);
            diagnostics.AddRange(resolution.Diagnostics);
            if (!resolution.IsFinal
                || resolution.InstructionEncoding is not { } encoding
                || resolution.OutputSourceAddress is not { } outputSourceAddress)
            {
                if (!resolution.Diagnostics.Any(diagnostic => diagnostic.IsError))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupDeferred,
                        "The selected PC-relative instruction target did not resolve to a final physical output encoding.",
                        fixup.SourceFileOffset.Value);
                }

                continue;
            }

            var functionOwners = snapshot.Plan.AddressMap.Entries
                .Where(entry => entry.Identity.Kind == SemanticEntityKind.Function
                    && ContainsRange(
                        entry.SourceRange.VirtualAddress.Value,
                        entry.SourceRange.Size,
                        fixup.SourceAddress.Value,
                        sizeof(uint)))
                .ToArray();
            if (functionOwners.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A selected PC-relative fixup does not have one owning emitted function region.",
                    fixup.SourceFileOffset.Value);
                continue;
            }

            var sourceRegion = image.Operations
                .OfType<ProtectedImageEmitRegion>()
                .Where(region => region.SourceAddress == functionOwners[0].SourceRange.VirtualAddress
                    && region.SourceSize == functionOwners[0].SourceRange.Size)
                .ToArray();
            if (sourceRegion.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A selected PC-relative fixup does not match one Protected Image code region.",
                    fixup.SourceFileOffset.Value);
                continue;
            }

            var regionIdentity = RegionIdentity(sourceRegion[0].RegionId);
            var placement = layoutPlan.Placements
                .Where(candidate => candidate.Identity == regionIdentity
                    && candidate.SourceIdentity == regionIdentity)
                .ToArray();
            if (placement.Length != 1
                || !regionBytes.TryGetValue(regionIdentity, out var codeBytes)
                || placement[0].Size != (ulong)codeBytes.Length
                || outputSourceAddress.Value < placement[0].VirtualAddress.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A selected PC-relative fixup has no unique physical function placement.",
                    fixup.SourceFileOffset.Value);
                continue;
            }

            var outputOffset = outputSourceAddress.Value - placement[0].VirtualAddress.Value;
            if (outputOffset % sizeof(uint) != 0
                || outputOffset > (ulong)codeBytes.Length
                || sizeof(uint) > (ulong)codeBytes.Length - outputOffset
                || placement[0].FileOffset.Value > ulong.MaxValue - outputOffset
                || !addressMap.TryMapSourceRange(
                    fixup.SourceRange,
                    SemanticEntityKind.Instruction,
                    out var mappedRange)
                || mappedRange.VirtualAddress != outputSourceAddress
                || mappedRange.FileOffset.Value != placement[0].FileOffset.Value + outputOffset
                || !emittedLocations.Add((regionIdentity, outputOffset)))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMalformed,
                    "The selected PC-relative fixup output range is unaligned, duplicated, or inconsistent with its physical placement.",
                    fixup.SourceFileOffset.Value);
                continue;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(
                codeBytes.AsSpan(checked((int)outputOffset), sizeof(uint)),
                encoding);
        }

        return regions.Select(region => new ElfLayoutRegionRequest(
                region.Identity,
                region.SourceIdentity,
                region.SourceAddress,
                region.SourceSize,
                regionBytes[region.Identity],
                region.Permissions,
                region.Alignment))
            .ToArray();
    }

    private static IReadOnlyList<ElfLayoutRegionRequest> BuildJumpTableReferenceFixupRegions(
        SemanticPlanSnapshot? snapshot,
        ProtectedImageDocument image,
        ElfFile sourceFile,
        ElfLayoutPlan layoutPlan,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        DiagnosticBag diagnostics)
    {
        var tables = snapshot?.Extensions.OfType<SemanticJumpTableExtension>().ToArray()
            ?? Array.Empty<SemanticJumpTableExtension>();
        if (tables.Length == 0 || snapshot is null)
        {
            return regions;
        }

        var regionBytes = regions.ToDictionary(
            region => region.Identity,
            region => region.CodeBytes.ToArray(),
            StringComparer.Ordinal);
        var instructionEncoder = new Aarch64InstructionEncoder();
        var emittedSites = new HashSet<(string RegionIdentity, ulong Offset)>();
        foreach (var table in tables)
        {
            var clones = layoutPlan.JumpTableClones
                .Where(clone => clone.TableIdentity == table.TableIdentity)
                .ToArray();
            if (clones.Length != 1
                || table.TableReferenceProducers.Count != 2)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A copied jump table has no unique physical clone or selected base-reference chain.",
                    table.TableRange.FileOffset.Value);
                continue;
            }

            var producerAddresses = table.TableReferenceProducers
                .Select(producer => producer.InstructionAddress)
                .Distinct()
                .ToArray();
            var functionOwners = snapshot.Plan.AddressMap.Entries
                .Where(entry => entry.Identity.Kind == SemanticEntityKind.Function
                    && producerAddresses.All(address => ContainsRange(
                        entry.SourceRange.VirtualAddress.Value,
                        entry.SourceRange.Size,
                        address,
                        sizeof(uint))))
                .ToArray();
            if (functionOwners.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "The table-base producer chain does not belong to exactly one selected emitted function.",
                    table.TableRange.FileOffset.Value);
                continue;
            }

            var selectedRegion = image.Operations
                .OfType<ProtectedImageEmitRegion>()
                .Where(region => region.SourceAddress == functionOwners[0].SourceRange.VirtualAddress
                    && region.SourceSize == functionOwners[0].SourceRange.Size)
                .ToArray();
            if (selectedRegion.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "The selected table-base producer chain does not match exactly one Protected Image function region.",
                    table.TableRange.FileOffset.Value);
                continue;
            }

            var regionIdentity = RegionIdentity(selectedRegion[0].RegionId);
            var placement = layoutPlan.Placements
                .Where(candidate => candidate.Identity == regionIdentity
                    && candidate.SourceIdentity == regionIdentity)
                .ToArray();
            if (placement.Length != 1 || !regionBytes.TryGetValue(regionIdentity, out var codeBytes))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "The selected table-reference function has no unique output code placement.",
                    table.TableRange.FileOffset.Value);
                continue;
            }

            foreach (var producer in table.TableReferenceProducers)
            {
                var instructionMaps = snapshot.Plan.AddressMap.Entries
                    .Where(entry => entry.Identity.Kind == SemanticEntityKind.Instruction
                        && entry.SourceRange.VirtualAddress.Value == producer.InstructionAddress
                        && entry.SourceRange.Size == sizeof(uint))
                    .ToArray();
                if (instructionMaps.Length != 1
                    || instructionMaps[0].OutputRange.VirtualAddress.Value < functionOwners[0].OutputRange.VirtualAddress.Value)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        "A selected table-reference instruction has no unique emitted instruction mapping.",
                        producer.InstructionAddress);
                    continue;
                }

                var outputOffset = instructionMaps[0].OutputRange.VirtualAddress.Value
                    - functionOwners[0].OutputRange.VirtualAddress.Value;
                if (outputOffset % sizeof(uint) != 0
                    || outputOffset > (ulong)codeBytes.Length
                    || sizeof(uint) > (ulong)codeBytes.Length - outputOffset
                    || outputOffset > placement[0].Size
                    || sizeof(uint) > placement[0].Size - outputOffset
                    || placement[0].VirtualAddress.Value > ulong.MaxValue - outputOffset
                    || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                        new VirtualAddress(producer.InstructionAddress),
                        sizeof(uint),
                        out var sourceInstructionFileOffset)
                    || sourceInstructionFileOffset.Value > int.MaxValue
                    || !emittedSites.Add((regionIdentity, outputOffset)))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMalformed,
                        "A selected table-reference instruction has an invalid source/output byte binding.",
                        producer.InstructionAddress);
                    continue;
                }

                var sourceEncoding = BinaryPrimitives.ReadUInt32LittleEndian(
                    sourceFile.Bytes.Span.Slice(checked((int)sourceInstructionFileOffset.Value), sizeof(uint)));
                var outputTemplate = BinaryPrimitives.ReadUInt32LittleEndian(
                    codeBytes.AsSpan(checked((int)outputOffset), sizeof(uint)));
                var outputInstructionAddress = checked(placement[0].VirtualAddress.Value + outputOffset);
                var family = producer.Kind switch
                {
                    Aarch64JumpTableReferenceKind.AdrpPage => Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
                    Aarch64JumpTableReferenceKind.AddLow12 => Aarch64InstructionEncodingFamily.AddImmediate,
                    _ => (Aarch64InstructionEncodingFamily?)null,
                };
                if (family is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotUnsupported,
                        "The table-base producer chain contains an unsupported reference encoding family.",
                        producer.InstructionAddress);
                    continue;
                }

                var immediateOrTarget = producer.Kind == Aarch64JumpTableReferenceKind.AdrpPage
                    ? clones[0].OutputRange.VirtualAddress.Value
                    : clones[0].OutputRange.VirtualAddress.Value & 0xFFFUL;
                var encoded = instructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
                    sourceEncoding,
                    producer.InstructionAddress,
                    outputInstructionAddress,
                    family.Value,
                    immediateOrTarget,
                    OutputTemplateEncoding: outputTemplate));
                if (!encoded.IsSuccess)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupOutOfRange,
                        $"A selected table-base instruction could not be re-encoded to its physical read-only clone: {encoded.Diagnostic}",
                        producer.InstructionAddress);
                    continue;
                }

                BinaryPrimitives.WriteUInt32LittleEndian(
                    codeBytes.AsSpan(checked((int)outputOffset), sizeof(uint)),
                    encoded.Encoding);
            }
        }

        if (diagnostics.HasErrors)
        {
            return regions;
        }

        return regions.Select(region => new ElfLayoutRegionRequest(
                region.Identity,
                region.SourceIdentity,
                region.SourceAddress,
                region.SourceSize,
                regionBytes[region.Identity],
                region.Permissions,
                region.Alignment))
            .ToArray();
    }

    private static bool RegionCodeBytesEqual(
        IReadOnlyList<ElfLayoutRegionRequest> left,
        IReadOnlyList<ElfLayoutRegionRequest> right) =>
        left.Count == right.Count
        && left.Zip(right).All(pair =>
            pair.First.Identity == pair.Second.Identity
            && pair.First.CodeBytes.AsSpan().SequenceEqual(pair.Second.CodeBytes));

    private static IReadOnlyList<ElfLayoutByteEdit> BuildUnwindEdits(
        SemanticPlanSnapshot? snapshot,
        ElfFile sourceFile,
        ProtectedImageDocument image,
        ElfLayoutPlan layoutPlan,
        DiagnosticBag diagnostics)
    {
        if (snapshot is null)
        {
            return Array.Empty<ElfLayoutByteEdit>();
        }

        var addressMap = BuildPhysicalSemanticAddressMap(snapshot, image, layoutPlan, diagnostics);
        if (addressMap is null)
        {
            return Array.Empty<ElfLayoutByteEdit>();
        }

        var cfiEffects = snapshot.Plan.Extensions
            .OfType<SemanticCfiEffectExtension>()
            .ToArray();
        var unwind = UnwindMetadataParser.Parse(sourceFile);
        if (!unwind.IsSuccess)
        {
            if (cfiEffects.Length > 0)
            {
                diagnostics.AddRange(unwind.Diagnostics);
            }

            return Array.Empty<ElfLayoutByteEdit>();
        }

        // FDE locations and ranges are derived from the canonical address map.
        // Explicit CFI effects are additive; a transformed function with valid
        // unwind metadata still needs its FDE/header remapped when its output
        // range or internal instruction offsets changed.
        var rewrite = UnwindMetadataRewriter.Rewrite(sourceFile, addressMap, cfiEffects);
        diagnostics.AddRange(rewrite.Diagnostics);
        return rewrite.IsSuccess ? rewrite.Edits : Array.Empty<ElfLayoutByteEdit>();
    }

    private static AddressMap? BuildPhysicalSemanticAddressMap(
        SemanticPlanSnapshot snapshot,
        ProtectedImageDocument image,
        ElfLayoutPlan layoutPlan,
        DiagnosticBag diagnostics)
    {
        var regions = image.Operations
            .OfType<ProtectedImageEmitRegion>()
            .ToArray();
        var functionMappings = snapshot.Plan.AddressMap.Entries
            .Where(entry => entry.Identity.Kind == SemanticEntityKind.Function)
            .ToArray();
        var physicalEntries = new List<AddressMapEntry>(snapshot.Plan.AddressMap.Entries.Count);

        foreach (var entry in snapshot.Plan.AddressMap.Entries)
        {
            if (entry.Identity.Kind is SemanticEntityKind.Table or SemanticEntityKind.TableEntry)
            {
                var cloneOwners = layoutPlan.JumpTableClones
                    .Where(clone => ContainsRange(
                        clone.SourceTableRange.VirtualAddress.Value,
                        clone.SourceTableRange.Size,
                        entry.SourceRange.VirtualAddress.Value,
                        entry.SourceRange.Size))
                    .ToArray();
                if (cloneOwners.Length > 0)
                {
                    if (cloneOwners.Length != 1)
                    {
                        diagnostics.Error(
                            DiagnosticCode.SemanticAddressMapMalformed,
                            "A jump-table source entity maps to more than one copied table range.",
                            entry.SourceRange.FileOffset.Value);
                        continue;
                    }

                    var clone = cloneOwners[0];
                    var cloneDelta = entry.SourceRange.VirtualAddress.Value - clone.SourceTableRange.VirtualAddress.Value;
                    if (cloneDelta > clone.OutputRange.Size
                        || entry.SourceRange.Size > clone.OutputRange.Size - cloneDelta
                        || clone.OutputRange.FileOffset.Value > ulong.MaxValue - cloneDelta
                        || clone.OutputRange.VirtualAddress.Value > ulong.MaxValue - cloneDelta)
                    {
                        diagnostics.Error(
                            DiagnosticCode.SemanticAddressMapOverflow,
                            "A copied table entity exceeds its physical clone range.",
                            entry.SourceRange.FileOffset.Value);
                        continue;
                    }

                    physicalEntries.Add(entry with
                    {
                        OutputRange = new SemanticSourceRange(
                            new FileOffset(clone.OutputRange.FileOffset.Value + cloneDelta),
                            new VirtualAddress(clone.OutputRange.VirtualAddress.Value + cloneDelta),
                            entry.OutputRange.Size),
                    });
                    continue;
                }
            }

            var owners = functionMappings
                .Where(function => ContainsRange(
                    function.SourceRange.VirtualAddress.Value,
                    function.SourceRange.Size,
                    entry.SourceRange.VirtualAddress.Value,
                    entry.SourceRange.Size))
                .ToArray();
            if (owners.Length != 1)
            {
                physicalEntries.Add(entry);
                continue;
            }

            var owner = owners[0];
            var sourceFunction = regions
                .Where(region => region.SourceAddress == owner.SourceRange.VirtualAddress
                    && region.SourceSize == owner.SourceRange.Size)
                .ToArray();
            if (sourceFunction.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindAddressMapMissing,
                    "A semantic function mapping does not match exactly one emitted Protected Image region.",
                    owner.SourceRange.FileOffset.Value);
                continue;
            }

            var identity = RegionIdentity(sourceFunction[0].RegionId);
            var placement = layoutPlan.Placements
                .Where(candidate => candidate.Identity == identity
                    && candidate.SourceIdentity == identity)
                .ToArray();
            if (placement.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindAddressMapMissing,
                    "A transformed function has no unique physical layout placement.",
                    owner.SourceRange.FileOffset.Value);
                continue;
            }

            var logicalOutput = owner.OutputRange;
            if (entry.OutputRange.VirtualAddress.Value < logicalOutput.VirtualAddress.Value
                || entry.OutputRange.VirtualAddress.Value - logicalOutput.VirtualAddress.Value
                    > logicalOutput.Size
                || entry.OutputRange.Size > logicalOutput.Size
                    - (entry.OutputRange.VirtualAddress.Value - logicalOutput.VirtualAddress.Value))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMalformed,
                    "A semantic entity output range escapes its transformed function mapping.",
                    entry.SourceRange.FileOffset.Value);
                continue;
            }

            var delta = entry.OutputRange.VirtualAddress.Value - logicalOutput.VirtualAddress.Value;
            if (placement[0].FileOffset.Value > ulong.MaxValue - delta
                || placement[0].VirtualAddress.Value > ulong.MaxValue - delta)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapOverflow,
                    "A physical semantic output mapping overflows its address domain.",
                    entry.SourceRange.FileOffset.Value);
                continue;
            }

            physicalEntries.Add(entry with
            {
                OutputRange = new SemanticSourceRange(
                    new FileOffset(placement[0].FileOffset.Value + delta),
                    new VirtualAddress(placement[0].VirtualAddress.Value + delta),
                    entry.OutputRange.Size),
            });
        }

        if (diagnostics.HasErrors)
        {
            return null;
        }

        var result = AddressMap.Create(physicalEntries);
        diagnostics.AddRange(result.Diagnostics);
        return result.Map;
    }

    private static bool ContainsRange(ulong outerStart, ulong outerSize, ulong innerStart, ulong innerSize) =>
        innerStart >= outerStart
        && innerStart - outerStart <= outerSize
        && innerSize <= outerSize - (innerStart - outerStart);

    private static bool HaveSamePlacements(ElfLayoutPlan first, ElfLayoutPlan second) =>
        first.Placements.Count == second.Placements.Count
        && first.Placements.Zip(second.Placements).All(pair =>
            pair.First.Identity == pair.Second.Identity
            && pair.First.SourceIdentity == pair.Second.SourceIdentity
            && pair.First.FileOffset == pair.Second.FileOffset
            && pair.First.VirtualAddress == pair.Second.VirtualAddress
            && pair.First.Size == pair.Second.Size)
        && first.JumpTableClones.Count == second.JumpTableClones.Count
        && first.JumpTableClones.Zip(second.JumpTableClones).All(pair =>
            pair.First.TableIdentity == pair.Second.TableIdentity
            && pair.First.SourceTableRange == pair.Second.SourceTableRange
            && pair.First.RequestedOutputRange == pair.Second.RequestedOutputRange
            && pair.First.OutputRange == pair.Second.OutputRange
            && pair.First.Permissions == pair.Second.Permissions
            && pair.First.Ownership == pair.Second.Ownership
            && pair.First.RewritePolicy == pair.Second.RewritePolicy);

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
            if (fixup.AccessModel is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec or TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic or TlsAccessModel.TlsDesc))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "Rehydration currently materializes only bounded local-exec, initial-exec, local-dynamic, general-dynamic, or exact TLSDESC semantic fixups.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var matchingRegions = regions.Where(region =>
                    fixup.SequenceSourceRange.VirtualAddress.Value >= region.SourceAddress.Value
                    && fixup.SequenceSourceRange.VirtualAddress.Value - region.SourceAddress.Value <= region.SourceSize
                    && fixup.SequenceSourceRange.Size <= region.SourceSize
                        - (fixup.SequenceSourceRange.VirtualAddress.Value - region.SourceAddress.Value))
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
            var region = matchingRegions[0];
            var regionSourceDelta = fixup.SequenceOutputRange.VirtualAddress.Value >= region.SourceAddress.Value
                ? fixup.SequenceOutputRange.VirtualAddress.Value - region.SourceAddress.Value
                : ulong.MaxValue;
            var regionLength = checked((ulong)region.CodeBytes.Length);
            var outputOffset = regionSourceDelta != ulong.MaxValue
                && virtualDelta <= ulong.MaxValue - regionSourceDelta
                ? regionSourceDelta + virtualDelta
                : ulong.MaxValue;
            if (fileDelta != virtualDelta
                || outputOffset > regionLength
                || fixup.RelocationOutputRange.Size > regionLength - outputOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLS output relocation site has inconsistent file and virtual address-map deltas.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

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

            requests.Add(new ElfLayoutTlsFixupRequest(identity, outputOffset, fixup));
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
