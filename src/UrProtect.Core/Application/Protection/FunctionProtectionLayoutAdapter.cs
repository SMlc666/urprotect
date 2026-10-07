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
    private static ulong AlignUp(ulong value, ulong alignment)
    {
        var remainder = value % alignment;
        return remainder == 0 ? value : checked(value + alignment - remainder);
    }

    private static bool TryGetCodeBase(ElfFile file, out ulong codeBase)
    {
        try
        {
            var highestVirtualEnd = file.LoadMap.Segments
                .Select(segment => checked(segment.VirtualAddress + segment.MemorySize))
                .DefaultIfEmpty(0UL)
                .Max();
            codeBase = AlignUp(highestVirtualEnd, SegmentAlignment);
            return true;
        }
        catch (OverflowException)
        {
            codeBase = 0;
            return false;
        }
    }

    private static ElfLayoutPlanningResult PlanProtectedCode(ElfFile file, ProtectedCode code)
    {
        var regions = new List<ElfLayoutRegionRequest>(code.Patches.Count);
        var branches = new List<ElfLayoutBranchRequest>(code.Patches.Count);
        for (var index = 0; index < code.Patches.Count; index++)
        {
            var patch = code.Patches[index];
            if (patch.TargetAddress < code.VirtualAddress
                || patch.OutputSize > (ulong)code.Bytes.Length
                || patch.TargetAddress - code.VirtualAddress > (ulong)code.Bytes.Length - patch.OutputSize
                || patch.OutputSize == 0
                || patch.OutputSize > int.MaxValue)
            {
                return new ElfLayoutPlanningResult(
                    null,
                    null,
                    new[]
                    {
                        new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.ProtectionLayoutUnavailable,
                            "A protected code patch is outside the emitted code buffer.",
                            patch.TargetAddress),
                    });
            }

            var regionIdentity = $"function:{index:D8}:{patch.SourceAddress:X}";
            var codeOffset = checked((int)(patch.TargetAddress - code.VirtualAddress));
            var codeBytes = code.Bytes.AsSpan(codeOffset, checked((int)patch.OutputSize)).ToArray();
            regions.Add(new ElfLayoutRegionRequest(
                regionIdentity,
                regionIdentity,
                new VirtualAddress(patch.SourceAddress),
                patch.SourceSize,
                codeBytes));
            branches.Add(new ElfLayoutBranchRequest(
                $"entry:{index}:{patch.SourceAddress:X}",
                regionIdentity,
                regionIdentity,
                new VirtualAddress(patch.SourceAddress),
                0,
                0));
        }

        var options = new ElfLayoutOptions(
            MaximumOutputBytes: ElfLayoutLimits.DefaultMaximumOutputBytes,
            MaximumProgramHeaderCount: ElfLayoutLimits.DefaultMaximumProgramHeaderCount,
            MaximumGeneratedCodeBytes: ProtectedImageLimits.MaximumAggregateCodeBytes,
            MaximumVeneerCount: ElfLayoutLimits.DefaultMaximumVeneerCount,
            MaximumEditCount: ElfLayoutLimits.DefaultMaximumEditCount,
            MaximumPaddingBytes: ElfLayoutLimits.DefaultMaximumPaddingBytes,
            SegmentAlignment: SegmentAlignment,
            CodeAlignment: ElfLayoutLimits.DefaultCodeAlignment,
            MaximumAlignment: ElfLayoutLimits.DefaultMaximumAlignment);
        return ElfLayoutPlanner.Plan(file.Bytes, file, regions, branches, options);
    }

}
