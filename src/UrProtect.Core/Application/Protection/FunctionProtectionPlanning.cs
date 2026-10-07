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

        var parse = selectedPlan.File;
        var analyses = selectedPlan.Analyses;
        var orderedPasses = ProtectionPassOrdering.Normalize(passSnapshot);
        if (!TryBuildProtectedCode(
                parse,
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
            functionResults);
        return new FunctionProtectionPlanResult(plan, functionResults, diagnostics.ToArray());
    }

}
