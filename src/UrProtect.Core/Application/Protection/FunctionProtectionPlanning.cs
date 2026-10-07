using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;

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
        var semanticSnapshot = BuildTlsSemanticSnapshot(
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
                || models[0] is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "The selected function contains a TLS relocation outside the current local-exec or exact TLSIE MOVW rewrite slices.",
                    facts[0].Relocation.Offset);
                continue;
            }

            var model = models[0]!.Value;
            var supported = model == TlsAccessModel.LocalExec
                ? facts.All(fact => fact.Relocation.Type is
                    ElfConstants.RArm64TlsLeAddTprelHi12
                    or ElfConstants.RArm64TlsLeAddTprelLo12
                    or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                    or ElfConstants.RArm64TlsLeMovwTprelG1
                    or ElfConstants.RArm64TlsLeMovwTprelG0Nc
                    or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
                : facts.Length == 2
                    && facts[0].Relocation.Type == ElfConstants.RArm64TlsIeMovwGottprelG1
                    && facts[1].Relocation.Type == ElfConstants.RArm64TlsIeMovwGottprelG0Nc;
            if (!supported)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    model == TlsAccessModel.InitialExec
                        ? "The current initial-exec layout slice accepts only the ordered TLSIE MOVW GOTTPREL G1/G0_NC pair."
                        : "The current local-exec layout slice accepts only ADD TPREL HI12/LO12, ADD TPREL HI12/LDST32 LO12_NC, or MOVW TPREL G1/G0_NC pairs.",
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
                var projected = Aarch64SemanticInstructionProjector.Project(sourceInstruction);
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

            var recognition = Aarch64TlsSequenceRecognizer.Recognize(
                projectedInstructions,
                sites,
                moduleResult.Value,
                symbol,
                gotEntry: gotEntry);
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
