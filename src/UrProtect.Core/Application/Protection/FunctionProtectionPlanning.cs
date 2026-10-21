using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.UnwindMetadata;

namespace UrProtect.Core.Application.Protection;

public sealed partial class FunctionProtectionService
{
    public FunctionProtectionPlanResult Plan(
        ReadOnlyMemory<byte> input,
        FunctionProtectionOptions options,
        Aarch64HostContextProofContext? proofContext = null) =>
        PlanCore(input, options, proofContext, externalProviderFacts: null, externalProviderExtension: null);

    internal FunctionProtectionPlanResult PlanWithExternalProvider(
        ReadOnlyMemory<byte> input,
        FunctionProtectionOptions options,
        Aarch64HostContextProofContext? proofContext,
        Aarch64ExternalJumpTableProviderFacts externalProviderFacts,
        SemanticExternalJumpTableExtension externalProviderExtension)
    {
        ArgumentNullException.ThrowIfNull(externalProviderFacts);
        ArgumentNullException.ThrowIfNull(externalProviderExtension);
        return PlanCore(input, options, proofContext, externalProviderFacts, externalProviderExtension);
    }

    private FunctionProtectionPlanResult PlanCore(
        ReadOnlyMemory<byte> input,
        FunctionProtectionOptions options,
        Aarch64HostContextProofContext? proofContext,
        Aarch64ExternalJumpTableProviderFacts? externalProviderFacts,
        SemanticExternalJumpTableExtension? externalProviderExtension)
    {
        ArgumentNullException.ThrowIfNull(options);
        var diagnostics = new DiagnosticBag();
        var functionResults = new List<FunctionProtectionFunctionResult>();
        if (!FunctionProtectionRequestValidator.TryValidate(
                options,
                diagnostics,
                out var selectorSnapshot,
                out var passSnapshot))
        {
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var sourceSnapshot = input.ToArray();
        var selectedPlan = new SelectedFunctionProtectionPlanner(decoder).Analyze(
            sourceSnapshot,
            selectorSnapshot,
            passSnapshot,
            proofContext,
            externalProviderFacts);
        diagnostics.AddRange(selectedPlan.Diagnostics);
        functionResults.AddRange(selectedPlan.FunctionResults);
        if (!selectedPlan.IsSuccess)
        {
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var analyses = selectedPlan.Analyses;
        var orderedPasses = ProtectionPassOrdering.Normalize(passSnapshot);
        if (!TryBuildProtectedCode(
                selectedPlan.File,
                analyses,
                orderedPasses,
                out var protectedCode,
                out var transformedResults,
                out var rewriteDiagnostics,
                codeBaseOverride: 0))
        {
            diagnostics.AddRange(rewriteDiagnostics);
            functionResults.AddRange(transformedResults);
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        functionResults.AddRange(transformedResults);
        var semanticSnapshot = BuildSemanticSnapshot(
            selectedPlan.File,
            analyses,
            protectedCode.Patches,
            diagnostics,
            externalProviderExtension);
        if (diagnostics.HasErrors)
        {
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var regions = new List<ProtectedImageEmitRegion>(protectedCode.Patches.Count);
        var fixups = new List<ProtectedImageEntryBranchFixup>(protectedCode.Patches.Count);
        for (var index = 0; index < protectedCode.Patches.Count; index++)
        {
            var patch = protectedCode.Patches[index];
            if (patch.TargetAddress > uint.MaxValue
                || patch.OutputSize > int.MaxValue
                || patch.TargetAddress > ulong.MaxValue - patch.OutputSize
                || patch.TargetAddress + patch.OutputSize > (ulong)protectedCode.Bytes.Length)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageLimitExceeded,
                    "The layout-neutral protected code region exceeds the Protected Image bounds.",
                    patch.SourceAddress);
                continue;
            }

            var regionId = checked((uint)index + 1);
            var generated = protectedCode.Bytes.AsSpan(
                checked((int)patch.TargetAddress),
                checked((int)patch.OutputSize)).ToArray();
            regions.Add(new ProtectedImageEmitRegion(
                regionId,
                new VirtualAddress(patch.SourceAddress),
                patch.SourceSize,
                generated));
            fixups.Add(new ProtectedImageEntryBranchFixup(
                regionId,
                regionId,
                new VirtualAddress(patch.SourceAddress),
                0,
                0,
                ProtectedImageFixupKind.Aarch64Branch26));
        }

        if (diagnostics.HasErrors || regions.Count != protectedCode.Patches.Count)
        {
            if (!diagnostics.HasErrors)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageMalformed,
                    "The layout-neutral protection plan did not bind every transformed function.");
            }

            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var plan = new ProtectionPlan(
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(sourceSnapshot)).ToLowerInvariant(),
            regions,
            fixups,
            functionResults)
        {
            SemanticSnapshot = semanticSnapshot,
        };
        return new FunctionProtectionPlanResult(plan, functionResults, diagnostics.ToArray());
    }

    private static SemanticPlanSnapshot? BuildSemanticSnapshot(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionAnalysis> analyses,
        IReadOnlyList<FunctionPatch> patches,
        DiagnosticBag diagnostics,
        SemanticExternalJumpTableExtension? externalProviderExtension = null)
    {
        var hasIndirectTargets = analyses.Any(analysis =>
            analysis.IndirectTargetResolutions.Count > 0
            || analysis.JumpTableResolutions.Count > 0
            || analysis.RuntimeIndirectCallResolutions.Count > 0
            || analysis.StaticFunctionPointerCallResolutions.Count > 0
            || analysis.ExternalJumpTableConsumerProofs.Count > 0);
        var hasTls = analyses.Any(analysis =>
            file.TlsMetadata.StaticRelocations
                .Concat(file.TlsMetadata.Dynamic.Relocations)
                .Any(fact => analysis.Function.TryGetEnd(out var end)
                    && fact.Relocation.Offset >= analysis.Function.Value
                    && fact.Relocation.Offset < end));

        if (hasIndirectTargets && hasTls)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "A selected function cannot combine the bounded indirect-target slice with a TLS semantic slice in one current snapshot.",
                analyses.First(analysis =>
                    analysis.IndirectTargetResolutions.Count > 0
                    || analysis.JumpTableResolutions.Count > 0
                    || analysis.RuntimeIndirectCallResolutions.Count > 0
                    || analysis.StaticFunctionPointerCallResolutions.Count > 0).Function.Value);
            return null;
        }

        var unwindParse = UnwindMetadataParser.Parse(file);
        var hasEhFrameProgramHeader = file.ProgramHeaders.Any(
            header => header.Type == ElfConstants.PtGnuEhFrame);
        if (hasEhFrameProgramHeader && !unwindParse.IsSuccess)
        {
            // An advertised GNU EH-frame table is part of the runtime
            // contract. Do not silently transform code while discarding
            // malformed unwind metadata.
            diagnostics.AddRange(unwindParse.Diagnostics);
            return null;
        }

        var hasValidUnwindMetadata = unwindParse.IsSuccess;
        if (hasValidUnwindMetadata
            && analyses.Any(analysis =>
                !file.TlsMetadata.StaticRelocations
                    .Concat(file.TlsMetadata.Dynamic.Relocations)
                    .Any(fact => analysis.Function.TryGetEnd(out var end)
                        && fact.Relocation.Offset >= analysis.Function.Value
                        && fact.Relocation.Offset < end)))
        {
            // The CFI snapshot factory also carries indirect-target extensions
            // projected by Aarch64SemanticPlanFactory. CFI must win this
            // selection because callback-shaped BLR instructions can coexist
            // with unwind-covered transformed code.
            var cfiSnapshot = BuildCfiSemanticSnapshot(file, analyses, patches, diagnostics, externalProviderExtension);
            if (cfiSnapshot is not null || diagnostics.HasErrors)
            {
                return cfiSnapshot;
            }
        }

        if (hasIndirectTargets)
        {
            return BuildIndirectSemanticSnapshot(file, analyses, patches, diagnostics, externalProviderExtension);
        }

        if (hasTls)
        {
            return BuildTlsSemanticSnapshot(file, analyses, patches, diagnostics);
        }

        return BuildBasicSemanticSnapshot(file, analyses, patches, diagnostics);
    }

    private static SemanticPlanSnapshot? BuildBasicSemanticSnapshot(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionAnalysis> analyses,
        IReadOnlyList<FunctionPatch> patches,
        DiagnosticBag diagnostics)
    {
        var plannedEntries = new List<AddressMapEntry>();
        var instructions = new List<SemanticInstruction>();
        var fixups = new List<SemanticFixup>();
        var extensions = new List<ISemanticPlanExtension>();
        var planDiagnostics = new List<Diagnostic>();

        foreach (var analysis in analyses)
        {
            var patch = patches.SingleOrDefault(candidate =>
                candidate.SourceAddress == analysis.Function.Value
                && candidate.SourceSize == analysis.Function.Size);
            if (patch.SourceSize == 0
                || !file.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(analysis.Function.Value),
                    analysis.Function.Size,
                    out var functionFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A selected function has no emitted logical output map for the canonical semantic snapshot.",
                    analysis.Function.Value);
                return null;
            }

            var ownerExtensions = BuildAddressReferenceOwnerExtensions(file, analysis, diagnostics);
            var projected = Aarch64SemanticPlanFactory.Create(
                analysis,
                Array.Empty<RelaRelocation>(),
                new Aarch64SemanticPlanFactoryOptions(
                    loadMap: file.LoadMap,
                    extensions: ownerExtensions));
            diagnostics.AddRange(projected.Diagnostics);
            if (!projected.IsSuccess || projected.Plan is null)
            {
                return null;
            }

            var referenceMapEntries = BuildAddressReferenceMapEntries(
                file,
                analysis,
                projected.Plan.AddressMap,
                diagnostics);
            plannedEntries.AddRange(projected.Plan.AddressMap.Entries.Select(entry =>
                MapIndirectEntry(entry, analysis, patch, functionFileOffset, diagnostics)));
            plannedEntries.AddRange(referenceMapEntries);
            instructions.AddRange(projected.Plan.Instructions);
            fixups.AddRange(projected.Plan.Fixups);
            extensions.AddRange(projected.Plan.Extensions);
            planDiagnostics.AddRange(projected.Plan.Diagnostics);
        }

        if (diagnostics.HasErrors)
        {
            return null;
        }

        var map = AddressMap.Create(plannedEntries);
        diagnostics.AddRange(map.Diagnostics);
        if (!map.IsSuccess || map.Map is null)
        {
            return null;
        }

        var plan = new SemanticRewritePlan(map.Map, instructions, fixups, extensions, planDiagnostics);
        var snapshot = SemanticPlanSnapshotCodec.Create(plan);
        diagnostics.AddRange(snapshot.Diagnostics);
        return snapshot.Snapshot;
    }

    private static System.Collections.ObjectModel.ReadOnlyCollection<ISemanticPlanExtension> BuildAddressReferenceOwnerExtensions(
        ElfFile file,
        Aarch64FunctionAnalysis analysis,
        DiagnosticBag diagnostics)
    {
        var extensions = new List<ISemanticPlanExtension>();
        var emittedRelocations = new HashSet<ulong>();
        var tlsModule = default(TlsModuleIdentity);
        var tlsModuleAttempted = false;
        var tlsFacts = file.TlsMetadata.StaticRelocations
            .Concat(file.TlsMetadata.Dynamic.Relocations)
            .ToArray();

        foreach (var reference in analysis.AddressReferences)
        {
            if (analysis.ExternalJumpTableConsumerProofs.Any(proof =>
                    proof.GotPageProducerAddress == reference.PageProducerAddress
                    && proof.GotLoadProducerAddress == reference.LoadProducerAddress
                    && proof.GotSlotAddress.Value == reference.TargetAddress.Value))
            {
                // The typed external-provider consumer proof owns this table object
                // import. It is not an indirect-call dynamic-import owner.
                continue;
            }

            if (reference.RelocationOwner is not { } relocation
                || !emittedRelocations.Add(relocation.Offset))
            {
                continue;
            }

            if (relocation.Type == ElfConstants.RArm64TlsTprel64)
            {
                var matchingFacts = tlsFacts
                    .Where(fact => fact.Relocation == relocation)
                    .ToArray();
                if (matchingFacts.Length != 1
                    || TlsStructuralAdapter.ProjectSymbol(matchingFacts[0].Symbol) is not { } symbol)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsBindingUnresolved,
                        "An ADRP-derived R_AARCH64_TLS_TPREL64 data reference has no unique typed dynamic TLS symbol owner.",
                        relocation.Offset);
                    continue;
                }

                if (!tlsModuleAttempted)
                {
                    var moduleResult = TlsStructuralAdapter.CreateImageModule(file);
                    diagnostics.AddRange(moduleResult.Diagnostics);
                    tlsModule = moduleResult.Value;
                    tlsModuleAttempted = true;
                }

                if (tlsModule is null)
                {
                    continue;
                }

                var projected = TlsStructuralAdapter.ProjectGotEntry(
                    file,
                    tlsModule,
                    symbol,
                    relocation.Addend);
                diagnostics.AddRange(projected.Diagnostics);
                if (projected.Value is not { } gotEntry)
                {
                    continue;
                }

                extensions.Add(new SemanticRelocationBindingExtension(
                    gotEntry.SourceIdentity,
                    gotEntry.Relocation,
                    "The selected-function ADRP/LDR range resolves to a unique writable, file-backed TLSIE GOT entry projected by TlsStructuralAdapter.ProjectGotEntry."));
                continue;
            }

            if (relocation.Type == ElfConstants.RArm64GlobDat)
            {
                if (reference.ImportOwner is not { } import
                    || import.Relocation != relocation)
                {
                    diagnostics.Error(
                        DiagnosticCode.IndirectTargetUnresolved,
                        "The selected-function GLOB_DAT data reference lacks a matching validated dynamic-symbol import owner.",
                        relocation.Offset);
                    continue;
                }

                var target = SemanticTarget.RuntimeResolved(
                    $"aarch64:elf-import:{import.SymbolName}:glob-dat@0x{import.GotAddress:X}");
                var binding = RelocationBinding.FromRelocation(relocation, target, import.SymbolName);
                extensions.Add(new SemanticRelocationBindingExtension(
                    SemanticEntityId.RelocationSite($"0x{relocation.Offset:X}"),
                    binding,
                    "The dynamic import owner is one undefined global/weak default-visible function-or-NOTYPE symbol in a writable, file-backed, aligned GLOB_DAT slot."));
                continue;
            }

            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"The selected-function ADRP/LDR chain reaches unsupported relocation owner type {relocation.Type}.",
                relocation.Offset);
        }

        foreach (var resolution in analysis.RuntimeIndirectCallResolutions
                     .Where(candidate => candidate.OwnerKind == Aarch64RuntimeIndirectCallOwnerKind.DynamicImport))
        {
            if (resolution.ImportBinding is not { } import
                || import.SymbolIndex >= (uint)file.DynamicSymbols.Count
                || !TryGetMappedSourceRange(file, import.GotAddress, sizeof(ulong), out var gotFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.IndirectTargetUnresolved,
                    "A selected dynamic-import call does not retain one parsed dynamic-symbol/GOT source owner.",
                    resolution.SourceAddress);
                continue;
            }

            var symbol = file.DynamicSymbols[checked((int)import.SymbolIndex)];
            if (!ElfParserUtilities.TryReadString(file.DynamicMetadata.StringTable, symbol.Name, out var symbolName)
                || !string.Equals(symbolName, import.SymbolName, StringComparison.Ordinal)
                || symbol.SectionIndex != 0
                || symbol.Value != 0
                || (byte)(symbol.Info >> 4) != import.SymbolBinding
                || (byte)(symbol.Info & 0x0F) != import.SymbolType
                || (byte)(symbol.Other & 0x03) != import.SymbolVisibility
                || import.Relocation.Offset != import.GotAddress
                || import.Relocation.Type != ElfConstants.RArm64GlobDat
                || import.Relocation.IsPlt)
            {
                diagnostics.Error(
                    DiagnosticCode.IndirectTargetUnresolved,
                    "A selected dynamic-import call's parsed dynsym/GLOB_DAT owner changed before semantic-plan construction.",
                    import.GotAddress);
                continue;
            }

            if (!SemanticDynamicImportCallContract.TryProjectVersionFacts(
                    file,
                    import.SymbolIndex,
                    out var symbolVersionIndexRaw,
                    out var versionRequirement,
                    out var versionFailure))
            {
                diagnostics.Error(
                    DiagnosticCode.IndirectTargetUnresolved,
                    versionFailure ?? "A selected dynamic import has no exact bounded source symbol-version owner.",
                    import.GotAddress);
                continue;
            }

            var gotRange = new SemanticSourceRange(
                gotFileOffset,
                new VirtualAddress(import.GotAddress),
                sizeof(ulong));
            var relocationSiteIdentity = SemanticEntityId.RelocationSite($"0x{import.Relocation.Offset:X}");
            extensions.Add(new SemanticDynamicImportCallExtension(
                SemanticEntityId.Instruction(new VirtualAddress(resolution.SourceAddress)),
                new VirtualAddress(resolution.SourceAddress),
                resolution.TargetRegister,
                resolution.ProducerAddresses.Select(address => new VirtualAddress(address)),
                new VirtualAddress(import.AddressPageProducerAddress),
                new VirtualAddress(import.PointerLoadProducerAddress),
                new VirtualAddress(import.PageAddress),
                gotRange,
                relocationSiteIdentity,
                import.Relocation.Offset,
                import.Relocation.Info,
                import.Relocation.Addend,
                import.Relocation.IsPlt,
                new VirtualAddress(import.Relocation.SourceAddress),
                import.SymbolIndex,
                symbol.Name,
                symbolName,
                symbol.Info,
                symbol.Other,
                (byte)(symbol.Info >> 4),
                (byte)(symbol.Info & 0x0F),
                (byte)(symbol.Other & 0x03),
                symbol.SectionIndex,
                symbol.Value,
                symbol.Size,
                symbolVersionIndexRaw,
                versionRequirement));
        }

        return Array.AsReadOnly(extensions.ToArray());
    }

    private static System.Collections.ObjectModel.ReadOnlyCollection<AddressMapEntry> BuildAddressReferenceMapEntries(
        ElfFile file,
        Aarch64FunctionAnalysis analysis,
        AddressMap existingMap,
        DiagnosticBag diagnostics)
    {
        var requiredRanges = new SortedDictionary<ulong, ulong>();
        foreach (var reference in analysis.AddressReferences)
        {
            AddRequiredRange(reference.PageAddress.Value, 1, reference.PageProducerAddress);
            AddRequiredRange(reference.TargetAddress.Value, reference.AccessSize, reference.LoadProducerAddress);
        }

        foreach (var table in analysis.JumpTableResolutions)
        {
            AddRequiredRange(table.TableBase.Value & ~0xFFFUL, 1, table.SourceAddress);
            AddRequiredRange(table.TableBase.Value, table.TableSize, table.SourceAddress);
        }

        foreach (var instruction in analysis.Instructions)
        {
            if (instruction.Decode.Instruction is not
                {
                    ControlFlow: Aarch64ControlFlowKind.DirectCall,
                    DirectTarget: { } target
                })
            {
                continue;
            }

            if (analysis.Function.TryGetEnd(out var functionEnd)
                && target >= analysis.Function.Value
                && target < functionEnd)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A direct call target inside the selected function is not represented by the supported external-call closure.",
                    instruction.Address);
                continue;
            }

            var executableOwners = file.LoadMap.Segments.Count(segment =>
                segment.IsExecutable
                && segment.ContainsVirtualAddress(target, sizeof(uint)));
            if (target % sizeof(uint) != 0
                || executableOwners != 1
                || !TryGetMappedSourceRange(file, target, sizeof(uint), out _))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A selected direct call target is not one aligned, file-backed executable source range.",
                    instruction.Address);
                continue;
            }

            AddRequiredRange(target, sizeof(uint), instruction.Address);
        }

        var candidates = new List<(ulong Start, ulong Size)>();
        foreach (var pair in requiredRanges)
        {
            var start = pair.Key;
            var size = pair.Value;
            if (TryGetMappedAddressReferenceRange(file, analysis, start, size, out _))
            {
                candidates.Add((start, size));
            }
            else
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A selected-function ADRP/LDR address reference is not one file-backed source range.",
                    start);
            }
        }

        var merged = new List<(ulong Start, ulong Size)>();
        foreach (var candidate in candidates.OrderBy(range => range.Start))
        {
            if (merged.Count == 0)
            {
                merged.Add(candidate);
                continue;
            }

            var prior = merged[^1];
            var priorEnd = checked(prior.Start + prior.Size);
            if (candidate.Start < priorEnd)
            {
                var candidateEnd = checked(candidate.Start + candidate.Size);
                var combinedSize = Math.Max(priorEnd, candidateEnd) - prior.Start;
                if (!TryGetMappedAddressReferenceRange(file, analysis, prior.Start, combinedSize, out _))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMalformed,
                        "Overlapping selected-function address references do not share one file-backed load range.",
                        prior.Start);
                    continue;
                }

                merged[^1] = (prior.Start, combinedSize);
            }
            else
            {
                merged.Add(candidate);
            }
        }

        var entries = new List<AddressMapEntry>(merged.Count);
        foreach (var range in merged)
        {
            if (existingMap.Entries.Any(entry => entry.Identity.Kind == SemanticEntityKind.RelocationTarget
                    && RangesOverlap(entry.SourceRange.VirtualAddress.Value, entry.SourceRange.Size, range.Start, range.Size)))
            {
                var alreadyMapped = existingMap.TryMapSourceAddress(
                    new VirtualAddress(range.Start),
                    SemanticEntityKind.RelocationTarget,
                    out var mappedStart)
                    && existingMap.TryMapSourceAddress(
                        new VirtualAddress(checked(range.Start + range.Size - 1)),
                        SemanticEntityKind.RelocationTarget,
                        out var mappedEnd)
                    && mappedStart.Value == range.Start
                    && mappedEnd.Value == checked(range.Start + range.Size - 1);
                if (alreadyMapped)
                {
                    continue;
                }

                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMalformed,
                    "A selected-function address-reference range partially overlaps a different relocation-target owner.",
                    range.Start);
                continue;
            }

            if (!TryGetMappedAddressReferenceRange(file, analysis, range.Start, range.Size, out var fileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A selected-function address-reference mapping has no unique file-backed source range.",
                    range.Start);
                continue;
            }

            var sourceRange = new SemanticSourceRange(
                fileOffset,
                new VirtualAddress(range.Start),
                range.Size);
            entries.Add(new AddressMapEntry(
                SemanticEntityId.RelocationTarget($"aarch64-data:{range.Start:X}:{range.Size:X}"),
                sourceRange,
                sourceRange));
        }

        foreach (var import in analysis.RuntimeIndirectCallResolutions
                     .Where(resolution => resolution.ImportBinding is not null)
                     .Select(resolution => resolution.ImportBinding!)
                     .GroupBy(binding => binding.Relocation.Offset)
                     .Select(group => group.First()))
        {
            if (!TryGetMappedSourceRange(file, import.GotAddress, sizeof(ulong), out var gotFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A dynamic-import relocation site has no exact file-backed GOT address-map range.",
                    import.GotAddress);
                continue;
            }

            var siteRange = new SemanticSourceRange(
                gotFileOffset,
                new VirtualAddress(import.GotAddress),
                sizeof(ulong));
            entries.Add(new AddressMapEntry(
                SemanticEntityId.RelocationSite($"0x{import.Relocation.Offset:X}"),
                siteRange,
                siteRange));
        }

        return Array.AsReadOnly(entries.ToArray());

        void AddRequiredRange(ulong address, ulong size, ulong diagnosticOffset)
        {
            if (size == 0 || address > ulong.MaxValue - size)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapOverflow,
                    "A selected-function address-reference range overflows its virtual address domain.",
                    diagnosticOffset);
                return;
            }

            if (!requiredRanges.TryGetValue(address, out var existingSize) || existingSize < size)
            {
                requiredRanges[address] = size;
            }
        }
    }

    private static bool TryGetMappedSourceRange(
        ElfFile file,
        ulong address,
        ulong size,
        out FileOffset fileOffset)
    {
        fileOffset = default;
        if (size == 0
            || !file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), size, out fileOffset)
            || fileOffset.Value > (ulong)file.Bytes.Length
            || size > (ulong)file.Bytes.Length - fileOffset.Value)
        {
            return false;
        }

        var owners = file.LoadMap.Segments.Count(segment =>
            segment.ContainsVirtualAddress(address, size)
            && segment.FileOffset <= ulong.MaxValue - (address - segment.VirtualAddress)
            && segment.ContainsFileOffset(segment.FileOffset + (address - segment.VirtualAddress), size));
        return owners == 1;
    }

    private static bool TryGetMappedAddressReferenceRange(
        ElfFile file,
        Aarch64FunctionAnalysis analysis,
        ulong address,
        ulong size,
        out FileOffset fileOffset)
    {
        if (TryGetMappedSourceRange(file, address, size, out fileOffset))
        {
            return true;
        }

        fileOffset = default;
        var targetRanges = analysis.AddressReferences
            .Where(reference => reference.PageAddress.Value == address
                && reference.TargetAddress.Value >= address
                && reference.TargetAddress.Value - address < 0x1000
                && reference.AccessSize > 0
                && TryGetMappedSourceRange(
                    file,
                    reference.TargetAddress.Value,
                    reference.AccessSize,
                    out _))
            .Select(reference => (Target: reference.TargetAddress.Value, Size: (ulong)reference.AccessSize))
            .Concat(analysis.JumpTableResolutions
                .Where(table => (table.TableBase.Value & ~0xFFFUL) == address
                    && table.TableBase.Value - address < 0x1000
                    && TryGetMappedSourceRange(file, table.TableBase.Value, table.TableSize, out _))
                .Select(table => (Target: table.TableBase.Value, Size: table.TableSize)))
            .Distinct()
            .ToArray();
        if (size != 1
            || (address & 0xFFFUL) != 0
            || targetRanges.Length == 0)
        {
            return false;
        }

        var owners = file.LoadMap.Segments
            .Where(segment => targetRanges.All(range =>
                segment.ContainsVirtualAddress(range.Target, range.Size)))
            .Select(segment =>
            {
                var pageStart = segment.VirtualAddress & ~0xFFFUL;
                var pageDelta = segment.VirtualAddress - pageStart;
                return (Segment: segment, PageStart: pageStart, PageDelta: pageDelta);
            })
            .Where(owner => owner.PageStart == address
                && owner.PageDelta <= owner.Segment.FileOffset
                && owner.Segment.Alignment >= 0x1000
                && (owner.Segment.FileOffset - owner.PageDelta) % 0x1000 == 0)
            .ToArray();
        if (owners.Length != 1)
        {
            return false;
        }

        var filePage = owners[0].Segment.FileOffset - owners[0].PageDelta;
        if (filePage >= (ulong)file.Bytes.Length)
        {
            return false;
        }

        fileOffset = new FileOffset(filePage);
        return true;
    }

    private static bool RangesOverlap(ulong leftStart, ulong leftSize, ulong rightStart, ulong rightSize) =>
        leftStart <= rightStart
            ? rightStart - leftStart < leftSize
            : leftStart - rightStart < rightSize;

    private static SemanticPlanSnapshot? BuildIndirectSemanticSnapshot(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionAnalysis> analyses,
        IReadOnlyList<FunctionPatch> patches,
        DiagnosticBag diagnostics,
        SemanticExternalJumpTableExtension? externalProviderExtension)
    {
        var indirectAnalyses = analyses
            .Where(analysis =>
                analysis.IndirectTargetResolutions.Count > 0
                || analysis.JumpTableResolutions.Count > 0
                || analysis.RuntimeIndirectCallResolutions.Count > 0
                || analysis.StaticFunctionPointerCallResolutions.Count > 0
                || analysis.ExternalJumpTableConsumerProofs.Count > 0)
            .ToArray();
        if (indirectAnalyses.Length != 1 || analyses.Count != 1)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "The bounded indirect-target slice requires exactly one selected function and cannot be combined with another selected function in the current snapshot.",
                indirectAnalyses.FirstOrDefault()?.Function.Value);
            return null;
        }

        var ownerExtensions = BuildAddressReferenceOwnerExtensions(file, indirectAnalyses[0], diagnostics).ToList();
        if (indirectAnalyses[0].ExternalJumpTableConsumerProofs.Count > 0)
        {
            if (externalProviderExtension is null
                || indirectAnalyses[0].ExternalJumpTableConsumerProofs.Count != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "An external provider-table proof requires one configured provider extension and one selected consumer.",
                    indirectAnalyses[0].Function.Value);
                return null;
            }

            ownerExtensions.Add(externalProviderExtension);
        }

        var result = Aarch64SemanticPlanFactory.Create(
            indirectAnalyses[0],
            Array.Empty<RelaRelocation>(),
            new Aarch64SemanticPlanFactoryOptions(
                loadMap: file.LoadMap,
                extensions: ownerExtensions));
        diagnostics.AddRange(result.Diagnostics);
        if (!result.IsSuccess || result.Plan is null)
        {
            return null;
        }

        var patch = patches.SingleOrDefault(candidate =>
            candidate.SourceAddress == indirectAnalyses[0].Function.Value
            && candidate.SourceSize == indirectAnalyses[0].Function.Size);
        if (patch.SourceSize == 0
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(indirectAnalyses[0].Function.Value),
                indirectAnalyses[0].Function.Size,
                out var sourceFunctionFileOffset))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "The selected indirect-control function has no emitted logical output map.",
                indirectAnalyses[0].Function.Value);
            return null;
        }

        var referenceMapEntries = BuildAddressReferenceMapEntries(
            file,
            indirectAnalyses[0],
            result.Plan.AddressMap,
            diagnostics);
        var plannedEntries = result.Plan.AddressMap.Entries
            .Select(entry => MapIndirectEntry(
                entry,
                indirectAnalyses[0],
                patch,
                sourceFunctionFileOffset,
                diagnostics))
            .Concat(referenceMapEntries)
            .ToArray();
        if (diagnostics.HasErrors)
        {
            return null;
        }

        var plannedMap = AddressMap.Create(plannedEntries);
        diagnostics.AddRange(plannedMap.Diagnostics);
        if (!plannedMap.IsSuccess || plannedMap.Map is null)
        {
            return null;
        }

        var placed = Aarch64SemanticPlanFactory.CreateWithPlacement(
            indirectAnalyses[0],
            plannedMap.Map,
            Array.Empty<RelaRelocation>(),
            file.LoadMap,
            ownerExtensions);
        diagnostics.AddRange(placed.Diagnostics);
        if (!placed.IsSuccess || placed.Plan is null)
        {
            return null;
        }

        var snapshot = SemanticPlanSnapshotCodec.Create(placed.Plan);
        diagnostics.AddRange(snapshot.Diagnostics);
        return snapshot.Snapshot;
    }

    private static SemanticPlanSnapshot? BuildCfiSemanticSnapshot(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionAnalysis> analyses,
        IReadOnlyList<FunctionPatch> patches,
        DiagnosticBag diagnostics,
        SemanticExternalJumpTableExtension? externalProviderExtension)
    {
        if (analyses.Count != 1)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "The bounded CFI snapshot slice requires exactly one selected function.",
                analyses.Count == 0 ? null : analyses[0].Function.Value);
            return null;
        }

        var analysis = analyses[0];
        var patch = patches.SingleOrDefault(candidate =>
            candidate.SourceAddress == analysis.Function.Value
            && candidate.SourceSize == analysis.Function.Size);
        if (patch.SourceSize == 0
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(analysis.Function.Value),
                analysis.Function.Size,
                out var sourceFileOffset))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "The selected CFI function has no emitted output map.",
                analysis.Function.Value);
            return null;
        }

        var ownerExtensions = BuildAddressReferenceOwnerExtensions(file, analysis, diagnostics).ToList();
        if (analysis.ExternalJumpTableConsumerProofs.Count > 0)
        {
            if (externalProviderExtension is null || analysis.ExternalJumpTableConsumerProofs.Count != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "An external provider-table proof requires one configured provider extension and one selected consumer.",
                    analysis.Function.Value);
                return null;
            }

            ownerExtensions.Add(externalProviderExtension);
        }

        var projected = Aarch64SemanticPlanFactory.Create(
            analysis,
            Array.Empty<RelaRelocation>(),
            new Aarch64SemanticPlanFactoryOptions(
                loadMap: file.LoadMap,
                extensions: ownerExtensions));
        diagnostics.AddRange(projected.Diagnostics);
        if (!projected.IsSuccess || projected.Plan is null)
        {
            return null;
        }

        var referenceMapEntries = BuildAddressReferenceMapEntries(
            file,
            analysis,
            projected.Plan.AddressMap,
            diagnostics);
        var plannedEntries = projected.Plan.AddressMap.Entries
            .Select(entry =>
            {
                var outputRange = entry.SourceRange;
                if (entry.Identity.Kind == SemanticEntityKind.Function)
                {
                    outputRange = new SemanticSourceRange(
                        new FileOffset(checked(sourceFileOffset.Value + patch.TargetAddress)),
                        new VirtualAddress(checked(analysis.Function.Value + patch.TargetAddress)),
                        patch.OutputSize);
                }
                else if (entry.Identity.Kind is SemanticEntityKind.Instruction or SemanticEntityKind.BasicBlock)
                {
                    if (!patch.InstructionOutputOffsets.TryGetValue(
                            entry.SourceRange.VirtualAddress.Value,
                            out var outputOffset))
                    {
                        diagnostics.Error(
                            DiagnosticCode.SemanticAddressMapMissing,
                            "A selected CFI entity has no emitted instruction output offset.",
                            entry.SourceRange.FileOffset.Value);
                        return entry;
                    }

                    outputRange = new SemanticSourceRange(
                        new FileOffset(checked(sourceFileOffset.Value + patch.TargetAddress + outputOffset)),
                        new VirtualAddress(checked(analysis.Function.Value + patch.TargetAddress + outputOffset)),
                        entry.SourceRange.Size);
                }

                return entry with { OutputRange = outputRange };
            })
            .Concat(referenceMapEntries)
            .ToArray();

        if (diagnostics.HasErrors)
        {
            return null;
        }

        var mapResult = AddressMap.Create(plannedEntries);
        diagnostics.AddRange(mapResult.Diagnostics);
        if (!mapResult.IsSuccess || mapResult.Map is null)
        {
            return null;
        }

        var snapshotPlan = new SemanticRewritePlan(
            mapResult.Map,
            projected.Plan.Instructions,
            projected.Plan.Fixups,
            projected.Plan.Extensions,
            projected.Plan.Diagnostics);
        var snapshot = SemanticPlanSnapshotCodec.Create(snapshotPlan);
        diagnostics.AddRange(snapshot.Diagnostics);
        return snapshot.Snapshot;
    }

    private static AddressMapEntry MapIndirectEntry(
        AddressMapEntry entry,
        Aarch64FunctionAnalysis analysis,
        FunctionPatch patch,
        FileOffset sourceFunctionFileOffset,
        DiagnosticBag diagnostics)
    {
        var outputRange = entry.SourceRange;
        var staticTargetIdentity = analysis.StaticFunctionPointerCallResolutions
            .Select(resolution => resolution.AdrpRelocation.Symbol is { } symbol
                ? SemanticEntityId.RelocationTarget(
                    $"static-function:{symbol.SymbolTableSectionIndex}:{symbol.SymbolIndex}:{symbol.Name}")
                : (SemanticEntityId?)null)
            .FirstOrDefault(identity => identity == entry.Identity);
        if (entry.Identity.Kind == SemanticEntityKind.Function && staticTargetIdentity is null)
        {
            outputRange = new SemanticSourceRange(
                new FileOffset(checked(sourceFunctionFileOffset.Value + patch.TargetAddress)),
                new VirtualAddress(checked(analysis.Function.Value + patch.TargetAddress)),
                patch.OutputSize);
        }
        else if (entry.Identity.Kind is SemanticEntityKind.Table or SemanticEntityKind.TableEntry)
        {
            var logicalCloneFileOffset = checked(sourceFunctionFileOffset.Value + patch.TargetAddress + patch.OutputSize);
            var logicalCloneVirtualAddress = checked(analysis.Function.Value + patch.TargetAddress + patch.OutputSize);
            foreach (var table in analysis.JumpTableResolutions
                         .OrderBy(table => table.TableBase.Value)
                         .ThenBy(table => table.SourceAddress))
            {
                var sourceEnd = checked(table.TableBase.Value + table.TableSize);
                if (entry.SourceRange.VirtualAddress.Value >= table.TableBase.Value
                    && entry.SourceRange.VirtualAddress.Value < sourceEnd
                    && entry.SourceRange.Size <= sourceEnd - entry.SourceRange.VirtualAddress.Value)
                {
                    var delta = entry.SourceRange.VirtualAddress.Value - table.TableBase.Value;
                    outputRange = new SemanticSourceRange(
                        new FileOffset(checked(logicalCloneFileOffset + delta)),
                        new VirtualAddress(checked(logicalCloneVirtualAddress + delta)),
                        entry.SourceRange.Size);
                    return entry with { OutputRange = outputRange };
                }

                logicalCloneFileOffset = checked(logicalCloneFileOffset + table.TableSize);
                logicalCloneVirtualAddress = checked(logicalCloneVirtualAddress + table.TableSize);
            }

            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                $"The jump-table entity '{entry.Identity.Value}' has no unique requested clone range after the selected function output.",
                entry.SourceRange.FileOffset.Value);
            return entry;
        }
        else if (entry.Identity.Kind is SemanticEntityKind.Instruction or SemanticEntityKind.BasicBlock)
        {
            if (!patch.InstructionOutputOffsets.TryGetValue(
                    entry.SourceRange.VirtualAddress.Value,
                    out var instructionOffset)
                || instructionOffset > patch.OutputSize
                || sizeof(uint) > patch.OutputSize - instructionOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    $"The selected indirect-control entity '{entry.Identity.Value}' has no emitted output binding.",
                    entry.SourceRange.FileOffset.Value);
                return entry;
            }

            var outputSize = (ulong)sizeof(uint);
            outputRange = new SemanticSourceRange(
                new FileOffset(checked(sourceFunctionFileOffset.Value + patch.TargetAddress + instructionOffset)),
                new VirtualAddress(checked(analysis.Function.Value + patch.TargetAddress + instructionOffset)),
                outputSize);
        }

        return entry with { OutputRange = outputRange };
    }

    private static SemanticPlanSnapshot? BuildTlsSemanticSnapshot(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionAnalysis> analyses,
        IReadOnlyList<FunctionPatch> patches,
        DiagnosticBag diagnostics)
    {
        var bindings = new List<SemanticTlsBindingExtension>();
        var instructions = new List<SemanticInstruction>();
        var fixups = new List<SemanticFixup>();
        var mapEntries = new List<AddressMapEntry>();
        var moduleResult = TlsStructuralAdapter.CreateImageModule(file);
        var allFacts = file.TlsMetadata.StaticRelocations
            .Concat(file.TlsMetadata.Dynamic.Relocations)
            .OrderBy(fact => fact.Relocation.Offset)
            .ToArray();

        foreach (var analysis in analyses)
        {
            if (!analysis.Function.TryGetEnd(out var functionEnd))
            {
                continue;
            }

            var facts = allFacts.Where(fact => fact.Relocation.Offset >= analysis.Function.Value
                    && fact.Relocation.Offset < functionEnd)
                .ToArray();
            if (facts.Length == 0)
            {
                continue;
            }

            var models = facts
                .Select(fact => TlsRelocationClassifier.GetAccessModel(fact.Relocation.Type))
                .Distinct()
                .ToArray();
            if (models.Length != 1
                || models[0] is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec or TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic or TlsAccessModel.TlsDesc))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "The selected function contains TLS relocations from more than one model or outside the bounded local-exec, initial-exec, local-dynamic, general-dynamic, and exact TLSDESC rewrite slices.",
                    facts[0].Relocation.Offset);
                continue;
            }
            var model = models[0]!.Value;
            var supported = model switch
            {
                TlsAccessModel.LocalExec => facts.All(fact => fact.Relocation.Type is
                    ElfConstants.RArm64TlsLeAddTprelHi12
                    or ElfConstants.RArm64TlsLeAddTprelLo12
                    or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                    or ElfConstants.RArm64TlsLeMovwTprelG1
                    or ElfConstants.RArm64TlsLeMovwTprelG0Nc
                    or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc),
                TlsAccessModel.InitialExec => facts.Length == 1
                    && facts[0].Relocation.Type == ElfConstants.RArm64TlsIeLdGottprelPrel19
                    || facts.Length == 2
                    && ((facts[0].Relocation.Type == ElfConstants.RArm64TlsIeMovwGottprelG1
                            && facts[1].Relocation.Type == ElfConstants.RArm64TlsIeMovwGottprelG0Nc)
                        || (facts[0].Relocation.Type == ElfConstants.RArm64TlsIeAdrGottprelPage21
                            && facts[1].Relocation.Type == ElfConstants.RArm64TlsIeLd64GottprelLo12Nc)),
                TlsAccessModel.LocalDynamic => facts.Length == 4
                    && facts[0].Relocation.Type == ElfConstants.RArm64TlsLdAdrPage21
                    && facts[1].Relocation.Type == ElfConstants.RArm64TlsLdAddLo12Nc
                    && facts[2].Relocation.Type == ElfConstants.RArm64TlsLdAddDtprelHi12
                    && facts[3].Relocation.Type is
                        ElfConstants.RArm64TlsLdAddDtprelLo12
                        or ElfConstants.RArm64TlsLdAddDtprelLo12Nc,
                TlsAccessModel.GeneralDynamic => facts.Length == 2
                    && facts.Select(fact => fact.Relocation.Type).SequenceEqual(new[]
                    {
                        ElfConstants.RArm64TlsGdAdrPage21,
                        ElfConstants.RArm64TlsGdAddLo12Nc,
                    }),
                TlsAccessModel.TlsDesc => facts.Length == 4
                    && facts.Select(fact => fact.Relocation.Type).SequenceEqual(new[]
                    {
                        ElfConstants.RArm64TlsDescAdrPage21,
                        ElfConstants.RArm64TlsDescLd64Lo12,
                        ElfConstants.RArm64TlsDescAddLo12,
                        ElfConstants.RArm64TlsDescCall,
                    }),
                _ => false,
            };
            if (!supported)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    model switch
                    {
                        TlsAccessModel.InitialExec => "The current initial-exec layout slice accepts only the standalone TLSIE LD_GOTTPREL_PREL19 relocation or ordered TLSIE MOVW G1/G0_NC and ADRP/LD64 GOTTPREL pairs.",
                        TlsAccessModel.LocalDynamic => "The current local-dynamic layout slice accepts only the exact TLSLD ADRP/ADD, direct __tls_get_addr, DTPREL ADD/ADD sequence.",
                        TlsAccessModel.GeneralDynamic => "The current general-dynamic layout slice accepts only the exact TLSGD ADRP/ADD, direct __tls_get_addr, and paired DTPMOD64/DTPREL64 owners.",
                        TlsAccessModel.TlsDesc => "The current TLSDESC layout slice accepts only the exact adjacent ADRP/LD64/ADD/TLSDESC_CALL marker sequence and one validated descriptor owner.",
                        _ => "The current local-exec layout slice accepts only ADD TPREL HI12/LO12, ADD TPREL HI12/LDST32 LO12_NC, or MOVW TPREL G1/G0_NC pairs.",
                    },
                    facts[0].Relocation.Offset);
                continue;
            }

            if (!moduleResult.IsSuccess || moduleResult.Value is null)
            {
                diagnostics.AddRange(moduleResult.Diagnostics);
                continue;
            }

            var patch = patches.SingleOrDefault(candidate =>
                candidate.SourceAddress == analysis.Function.Value
                && candidate.SourceSize == analysis.Function.Size);
            if (patch.SourceSize == 0 || patch.InstructionOutputOffsets is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "The selected local-exec function has no emitted instruction address map.",
                    analysis.Function.Value);
                continue;
            }

            var projectedInstructions = new List<SemanticInstruction>(analysis.Instructions.Count);
            foreach (var sourceInstruction in analysis.Instructions)
            {
                var projected = Aarch64SemanticInstructionProjector.Project(
                    sourceInstruction,
                    facts.Select(fact => fact.Relocation));
                diagnostics.AddRange(projected.Diagnostics);
                if (projected.Instruction is { } instruction)
                {
                    projectedInstructions.Add(instruction);
                }
            }

            instructions.AddRange(projectedInstructions);

            var sites = new List<TlsRelocationSite>(facts.Length);
            for (var index = 0; index < facts.Length; index++)
            {
                var site = TlsStructuralAdapter.ProjectRelocationSite(
                    file,
                    moduleResult.Value,
                    facts[index],
                    index);
                diagnostics.AddRange(site.Diagnostics);
                if (site.Value is not null)
                {
                    sites.Add(site.Value);
                }
            }

            var symbol = TlsStructuralAdapter.ProjectSymbol(facts[0].Symbol);
            TlsGotEntryBinding? gotEntry = null;
            if (model == TlsAccessModel.InitialExec)
            {
                if (symbol is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsBindingUnresolved,
                        "The selected initial-exec function has no resolved TLS symbol for GOT ownership.",
                        facts[0].Relocation.Offset);
                    continue;
                }

                var got = TlsStructuralAdapter.ProjectGotEntry(
                    file,
                    moduleResult.Value,
                    symbol,
                    facts[0].Relocation.Addend);
                diagnostics.AddRange(got.Diagnostics);
                gotEntry = got.Value;
                if (!got.IsSuccess || gotEntry is null)
                {
                    continue;
                }
            }
            TlsResolverCallBinding? resolverCall = null;
            TlsModuleOwnerBinding? moduleOwner = null;
            TlsDtpRelOwnerBinding? dtpRelOwner = null;
            TlsDescriptorOwnerBinding? descriptorOwner = null;
            if (model == TlsAccessModel.TlsDesc)
            {
                if (symbol is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsBindingUnresolved,
                        "The selected TLSDESC function has no resolved defined TLS symbol for descriptor ownership.",
                        facts[0].Relocation.Offset);
                    continue;
                }

                var descriptorProjection = TlsStructuralAdapter.ProjectDescriptorOwner(
                    file,
                    moduleResult.Value,
                    symbol,
                    facts[0].Relocation.Addend);
                diagnostics.AddRange(descriptorProjection.Diagnostics);
                descriptorOwner = descriptorProjection.Value;
                if (!descriptorProjection.IsSuccess || descriptorOwner is null)
                {
                    continue;
                }
            }
            if (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic)
            {
                var resolverCandidates = analysis.Instructions
                    .Where(instruction => instruction.Decode.Instruction?.ControlFlow == Aarch64ControlFlowKind.DirectCall)
                    .Where(instruction => TlsStructuralAdapter.IsExactResolverCall(
                        file,
                        new SemanticSourceRange(
                            new FileOffset(instruction.FileOffset),
                            new VirtualAddress(instruction.Address),
                            sizeof(uint))))
                    .ToArray();
                if (resolverCandidates.Length != 1)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsBindingUnresolved,
                        "The selected dynamic TLS sequence does not have exactly one direct __tls_get_addr call owned by its PLT binding.",
                        analysis.Function.Value);
                    continue;
                }

                var resolverSourceInstruction = resolverCandidates[0];
                var resolverProjection = TlsStructuralAdapter.ProjectResolverCall(
                    file,
                    new SemanticSourceRange(
                        new FileOffset(resolverSourceInstruction.FileOffset),
                        new VirtualAddress(resolverSourceInstruction.Address),
                        sizeof(uint)));
                diagnostics.AddRange(resolverProjection.Diagnostics);
                resolverCall = resolverProjection.Value;
                if (model == TlsAccessModel.LocalDynamic)
                {
                    var ownerProjection = TlsStructuralAdapter.ProjectModuleOwner(file, moduleResult.Value);
                    diagnostics.AddRange(ownerProjection.Diagnostics);
                    moduleOwner = ownerProjection.Value;
                    if (!resolverProjection.IsSuccess || resolverCall is null
                        || !ownerProjection.IsSuccess || moduleOwner is null)
                    {
                        continue;
                    }
                }
                else
                {
                    var ownerProjection = symbol is null
                        ? new TlsStructuralProjectionResult<TlsStructuralAdapter.TlsGeneralDynamicOwnerBinding>(null, new[]
                        {
                            new Diagnostic(
                                DiagnosticSeverity.Error,
                                DiagnosticCode.TlsBindingUnresolved,
                                "The selected general-dynamic function has no resolved TLS symbol for GOT owner projection.")
                        })
                        : TlsStructuralAdapter.ProjectGeneralDynamicOwners(file, moduleResult.Value, symbol, facts[0].Relocation.Addend);
                    diagnostics.AddRange(ownerProjection.Diagnostics);
                    if (ownerProjection.Value is { } generalOwners)
                    {
                        moduleOwner = generalOwners.ModuleOwner;
                        dtpRelOwner = generalOwners.DtpRelOwner;
                    }

                    if (!resolverProjection.IsSuccess || resolverCall is null
                        || !ownerProjection.IsSuccess || moduleOwner is null || dtpRelOwner is null)
                    {
                        continue;
                    }
                }
            }

            var recognition = Aarch64TlsSequenceRecognizer.Recognize(
                projectedInstructions,
                sites,
                moduleResult.Value,
                symbol,
                resolverTarget: model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
                    ? SemanticTarget.RuntimeResolved("symbol:__tls_get_addr")
                    : null,
                gotEntry: gotEntry,
                resolverCall: resolverCall,
                moduleOwner: moduleOwner,
                dtpRelOwner: dtpRelOwner,
                descriptorOwner: descriptorOwner);
            diagnostics.AddRange(recognition.Diagnostics);
            if (!recognition.IsSuccess || recognition.Binding is null)
            {
                continue;
            }

            var binding = recognition.Binding;
            bindings.Add(new SemanticTlsBindingExtension(binding));
            if (!file.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(analysis.Function.Value),
                    analysis.Function.Size,
                    out var sourceFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "The selected local-exec function is not fully file-backed by the structural load map.",
                    analysis.Function.Value);
                continue;
            }

            var sourceFunctionRange = new SemanticSourceRange(
                sourceFileOffset,
                new VirtualAddress(analysis.Function.Value),
                analysis.Function.Size);
            var logicalFunctionOutput = new SemanticSourceRange(
                sourceFileOffset,
                new VirtualAddress(analysis.Function.Value),
                patch.OutputSize);
            var functionIdentity = SemanticEntityId.Function(
                $"{analysis.Function.Table}:{analysis.Function.TableIndex}:0x{analysis.Function.Value:X}");
            mapEntries.Add(new AddressMapEntry(functionIdentity, sourceFunctionRange, logicalFunctionOutput));

            foreach (var instruction in projectedInstructions)
            {
                if (!patch.InstructionOutputOffsets.TryGetValue(instruction.SourceVirtualAddress.Value, out var outputOffset)
                    || outputOffset > patch.OutputSize
                    || sizeof(uint) > patch.OutputSize - outputOffset
                    || !TryAdd(sourceFileOffset.Value, outputOffset, out var outputFileOffset)
                    || !TryAdd(analysis.Function.Value, outputOffset, out var outputAddress))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        "A selected local-exec instruction has no valid emitted source-to-output mapping.",
                        instruction.SourceFileOffset.Value);
                    continue;
                }

                var outputRange = new SemanticSourceRange(
                    new FileOffset(outputFileOffset),
                    new VirtualAddress(outputAddress),
                    sizeof(uint));
                mapEntries.Add(new AddressMapEntry(
                    SemanticEntityId.Instruction(instruction.SourceVirtualAddress),
                    instruction.SourceRange,
                    outputRange));
            }

            var sourceInstructionsByAddress = analysis.Instructions.ToDictionary(item => item.Address);
            foreach (var site in binding.RelocationSites)
            {
                if (!patch.InstructionOutputOffsets.TryGetValue(site.SourceRange.VirtualAddress.Value, out var outputOffset)
                    || outputOffset > patch.OutputSize
                    || site.SourceRange.Size > patch.OutputSize - outputOffset
                    || !TryAdd(sourceFileOffset.Value, outputOffset, out var outputFileOffset)
                    || !TryAdd(analysis.Function.Value, outputOffset, out var outputAddress)
                    || !sourceInstructionsByAddress.TryGetValue(site.SourceRange.VirtualAddress.Value, out var sourceInstruction))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        "A local-exec relocation site has no valid emitted source-to-output mapping.",
                        site.SourceRange.FileOffset.Value);
                    continue;
                }

                var outputRange = new SemanticSourceRange(
                    new FileOffset(outputFileOffset),
                    new VirtualAddress(outputAddress),
                    site.SourceRange.Size);
                mapEntries.Add(new AddressMapEntry(
                    SemanticEntityId.RelocationSite($"0x{site.SourceRange.VirtualAddress.Value:X}"),
                    site.SourceRange,
                    outputRange));
                fixups.Add(SemanticFixup.FromRelocation(
                    site.SourceRange.VirtualAddress,
                    site.SourceRange.FileOffset,
                    sourceInstruction.Encoding,
                    site.Binding,
                    site.SourceRange));
            }
            if (resolverCall is { } call
                && sourceInstructionsByAddress.TryGetValue(call.SourceRange.VirtualAddress.Value, out var resolverInstruction))
            {
                fixups.Add(SemanticFixup.FromRelocation(
                    call.SourceRange.VirtualAddress,
                    call.SourceRange.FileOffset,
                    resolverInstruction.Encoding,
                    call.Relocation,
                    call.SourceRange));
            }
            else if (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "The local-dynamic resolver call has no projected source instruction mapping.",
                    binding.SourceRange.FileOffset.Value);
            }
        }

        if (bindings.Count == 0 || diagnostics.HasErrors)
        {
            return null;
        }

        var addressMap = AddressMap.Create(mapEntries);
        diagnostics.AddRange(addressMap.Diagnostics);
        if (!addressMap.IsSuccess || addressMap.Map is null)
        {
            return null;
        }

        var semanticPlan = SemanticRewritePlanBuilder.Build(
            addressMap.Map,
            instructions,
            fixups,
            bindings,
            diagnostics.ToArray());
        diagnostics.AddRange(semanticPlan.Diagnostics);
        if (!semanticPlan.IsSuccess || semanticPlan.Plan is null)
        {
            return null;
        }

        var tlsFixups = TlsSemanticFixupPlanner.Build(semanticPlan.Plan);
        diagnostics.AddRange(tlsFixups.Diagnostics);
        if (!tlsFixups.IsSuccess)
        {
            return null;
        }

        var snapshot = SemanticPlanSnapshotCodec.Create(semanticPlan.Plan);
        diagnostics.AddRange(snapshot.Diagnostics);
        return snapshot.Snapshot;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        if (right > ulong.MaxValue - left)
        {
            result = default;
            return false;
        }

        result = left + right;
        return true;
    }

}
