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
        FunctionProtectionOptions options)
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
            passSnapshot);
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
            diagnostics);
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
        DiagnosticBag diagnostics)
    {
        var hasIndirectTargets = analyses.Any(analysis =>
            analysis.IndirectTargetResolutions.Count > 0
            || analysis.JumpTableResolutions.Count > 0
            || analysis.RuntimeIndirectCallResolutions.Count > 0);
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
                    || analysis.RuntimeIndirectCallResolutions.Count > 0).Function.Value);
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
            return BuildCfiSemanticSnapshot(file, analyses, patches, diagnostics);
        }

        if (hasIndirectTargets)
        {
            return BuildIndirectSemanticSnapshot(file, analyses, patches, diagnostics);
        }

        return BuildTlsSemanticSnapshot(file, analyses, patches, diagnostics);
    }

    private static SemanticPlanSnapshot? BuildIndirectSemanticSnapshot(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionAnalysis> analyses,
        IReadOnlyList<FunctionPatch> patches,
        DiagnosticBag diagnostics)
    {
        var indirectAnalyses = analyses
            .Where(analysis =>
                analysis.IndirectTargetResolutions.Count > 0
                || analysis.JumpTableResolutions.Count > 0
                || analysis.RuntimeIndirectCallResolutions.Count > 0)
            .ToArray();
        if (indirectAnalyses.Length != 1 || analyses.Count != 1)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "The bounded indirect-target slice requires exactly one selected function and cannot be combined with another selected function in the current snapshot.",
                indirectAnalyses.FirstOrDefault()?.Function.Value);
            return null;
        }

        var result = Aarch64SemanticPlanFactory.Create(
            indirectAnalyses[0],
            Array.Empty<RelaRelocation>(),
            new Aarch64SemanticPlanFactoryOptions(loadMap: file.LoadMap));
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

        var plannedEntries = result.Plan.AddressMap.Entries
            .Select(entry => MapIndirectEntry(
                entry,
                indirectAnalyses[0],
                patch,
                sourceFunctionFileOffset,
                diagnostics))
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
            file.LoadMap);
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
        DiagnosticBag diagnostics)
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

        var projected = Aarch64SemanticPlanFactory.Create(
            analysis,
            Array.Empty<RelaRelocation>(),
            new Aarch64SemanticPlanFactoryOptions(loadMap: file.LoadMap));
        diagnostics.AddRange(projected.Diagnostics);
        if (!projected.IsSuccess || projected.Plan is null)
        {
            return null;
        }

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
        if (entry.Identity.Kind == SemanticEntityKind.Function)
        {
            outputRange = new SemanticSourceRange(
                new FileOffset(checked(sourceFunctionFileOffset.Value + patch.TargetAddress)),
                new VirtualAddress(checked(analysis.Function.Value + patch.TargetAddress)),
                patch.OutputSize);
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

            var outputSize = entry.Identity.Kind == SemanticEntityKind.Instruction
                ? (ulong)sizeof(uint)
                : (ulong)sizeof(uint);
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
                    && facts.Select(fact => fact.Relocation.Type).SequenceEqual(new[]
                    {
                        ElfConstants.RArm64TlsLdAdrPage21,
                        ElfConstants.RArm64TlsLdAddLo12Nc,
                        ElfConstants.RArm64TlsLdAddDtprelHi12,
                        ElfConstants.RArm64TlsLdAddDtprelLo12Nc,
                    }),
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
