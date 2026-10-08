using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.SemanticPlanning;

public static class SemanticRewritePlanBuilder
{
    public static SemanticRewritePlanResult Build(
        AddressMap addressMap,
        IEnumerable<SemanticInstruction> instructions,
        IEnumerable<SemanticFixup> fixups,
        IEnumerable<ISemanticPlanExtension>? extensions = null,
        IEnumerable<Diagnostic>? initialDiagnostics = null)
    {
        ArgumentNullException.ThrowIfNull(addressMap);
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(fixups);

        var diagnostics = new DiagnosticBag();
        if (initialDiagnostics is not null)
        {
            diagnostics.AddRange(initialDiagnostics);
        }

        var instructionArray = instructions.ToArray();
        var fixupArray = fixups.ToArray();

        var instructionAddresses = new HashSet<VirtualAddress>();
        var instructionFileOffsets = new HashSet<FileOffset>();
        var pcRelativeInstructionSites = new HashSet<VirtualAddress>();
        var pcRelativeFixupSites = new HashSet<VirtualAddress>();
        var fixupSites = new HashSet<VirtualAddress>();
        var fixupFileSites = new HashSet<FileOffset>();
        foreach (var instruction in instructionArray)
        {
            if (instruction is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticInstructionMalformed,
                    "A semantic rewrite plan contains a null instruction.");
                continue;
            }

            if (!instruction.SourceRange.IsInstructionRange
                || !instruction.SourceRange.TryGetFileEnd(out _)
                || !instruction.SourceRange.TryGetVirtualEnd(out _)
                || instruction.SourceRange.VirtualAddress != instruction.SourceVirtualAddress
                || instruction.SourceRange.FileOffset != instruction.SourceFileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticInstructionMalformed,
                    "A semantic instruction has an invalid or mismatched AArch64 source range.",
                    instruction.SourceFileOffset.Value);
            }
            else if (!addressMap.TryMapSourceRange(
                instruction.SourceRange,
                SemanticEntityKind.Instruction,
                out _))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A semantic instruction source range has no unique planned output mapping.",
                    instruction.SourceFileOffset.Value);
            }

            if (instruction.LiteralReference is { } literalReference)
            {
                if (literalReference.AccessSize <= 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticInstructionMalformed,
                        "A literal reference must have a positive access size.",
                        instruction.SourceFileOffset.Value);
                }

                if (literalReference.PoolRange is { } poolRange
                    && (poolRange.Size == 0
                        || !poolRange.TryGetFileEnd(out _)
                        || !poolRange.TryGetVirtualEnd(out _)))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticInstructionMalformed,
                        "A literal-pool range is empty or overflows its address domain.",
                        instruction.SourceFileOffset.Value);
                }
            }

            if (!instructionAddresses.Add(instruction.SourceVirtualAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate instruction addresses.",
                    instruction.SourceVirtualAddress.Value);
            }

            if (!instructionFileOffsets.Add(instruction.SourceFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate instruction file offsets.",
                    instruction.SourceFileOffset.Value);
            }

            if (instruction.PcRelativeExpression is not null
                && !pcRelativeInstructionSites.Add(instruction.SourceVirtualAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate PC-relative instruction sites.",
                    instruction.SourceFileOffset.Value);
            }
        }

        foreach (var fixup in fixupArray)
        {
            if (fixup is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A semantic rewrite plan contains a null fixup.");
                continue;
            }

            if (!fixupSites.Add(fixup.SourceAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate fixup source sites.",
                    fixup.SourceFileOffset.Value);
            }

            if (IsPcRelativeFixup(fixup))
            {
                pcRelativeFixupSites.Add(fixup.SourceAddress);
            }

            if (!fixupFileSites.Add(fixup.SourceFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate fixup file sites.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.SourceRange.Size == 0
                || !fixup.SourceRange.TryGetFileEnd(out _)
                || !fixup.SourceRange.TryGetVirtualEnd(out _)
                || fixup.SourceRange.VirtualAddress != fixup.SourceAddress
                || fixup.SourceRange.FileOffset != fixup.SourceFileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A semantic fixup source range is empty or overflows its address domain.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind != SemanticFixupKind.Relocation && !fixup.SourceRange.IsInstructionRange)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "An instruction fixup must address one aligned AArch64 instruction.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Relocation is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A relocation fixup is missing its symbolic relocation binding.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Relocation is { } relocation)
            {
                if (!relocation.IsKindConsistent)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A relocation binding kind does not match its raw AArch64 relocation type.",
                        fixup.SourceFileOffset.Value);
                }

                if (relocation.RelocationAddress is { } relocationAddress
                    && relocationAddress != fixup.SourceAddress)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A relocation binding address does not match its semantic fixup source address.",
                        fixup.SourceFileOffset.Value);
                }

                var writeSize = SemanticFixup.GetRelocationWriteSize(relocation);
                if (writeSize == 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupUnsupported,
                        "The semantic relocation has no defined write width.",
                        fixup.SourceFileOffset.Value);
                }
                else if (fixup.SourceRange.Size != writeSize
                    || fixup.SourceRange.FileOffset.Value % writeSize != 0
                    || fixup.SourceRange.VirtualAddress.Value % writeSize != 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A relocation fixup source range has an invalid size or alignment for its relocation kind.",
                        fixup.SourceFileOffset.Value);
                }
            }

            if (fixup.Kind != SemanticFixupKind.Relocation && fixup.Expression is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A PC-relative instruction fixup is missing its expression.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Expression is not null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A relocation fixup cannot also carry a PC-relative expression.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind != SemanticFixupKind.Relocation && fixup.Relocation is not null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A PC-relative instruction fixup cannot carry an ELF relocation binding.",
                    fixup.SourceFileOffset.Value);
            }

            ValidateExpressionKind(fixup, diagnostics);
            ValidateTargetRelationships(fixup, diagnostics);
            ValidateTarget(fixup.Target, fixup.SourceFileOffset.Value, diagnostics);
        }

        foreach (var instructionSite in pcRelativeInstructionSites)
        {
            if (!pcRelativeFixupSites.Contains(instructionSite))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A PC-relative instruction is missing its semantic fixup.",
                    instructionSite.Value);
            }
        }

        var plan = new SemanticRewritePlan(
            addressMap,
            instructionArray,
            fixupArray,
            extensions,
            diagnostics.ToArray());
        return new SemanticRewritePlanResult(plan, diagnostics.ToArray());
    }

    private static bool IsPcRelativeFixup(SemanticFixup fixup) =>
        fixup.Kind != SemanticFixupKind.Relocation
        || fixup.Relocation?.Kind is
            Aarch64RelocationKind.Call26
                or Aarch64RelocationKind.Jump26
                or Aarch64RelocationKind.ConditionalBranch19
                or Aarch64RelocationKind.TestBranch14
                or Aarch64RelocationKind.AdrPrelLo21
                or Aarch64RelocationKind.AdrPrelPgHi21
                or Aarch64RelocationKind.Literal19
        || fixup.Relocation?.RelocationType is
            ElfConstants.RArm64TlsIeAdrGottprelPage21
            or ElfConstants.RArm64TlsIeLdGottprelPrel19;

    private static void ValidateExpressionKind(
        SemanticFixup fixup,
        DiagnosticBag diagnostics)
    {
        if (fixup.Expression is not { } expression || fixup.Kind == SemanticFixupKind.Relocation)
        {
            return;
        }

        var expectedKind = expression.Kind switch
        {
            PcRelativeExpressionKind.Branch26 => SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Call26 => SemanticFixupKind.Call26,
            PcRelativeExpressionKind.ConditionalBranch19 => SemanticFixupKind.ConditionalBranch19,
            PcRelativeExpressionKind.TestBranch14 => SemanticFixupKind.TestBranch14,
            PcRelativeExpressionKind.AdrPrelLo21 => SemanticFixupKind.AdrPrelLo21,
            PcRelativeExpressionKind.AdrPrelPgHi21 => SemanticFixupKind.AdrPrelPgHi21,
            PcRelativeExpressionKind.Literal19 => SemanticFixupKind.Literal19,
            _ => (SemanticFixupKind?)null,
        };
        var expectedScale = expression.Kind switch
        {
            PcRelativeExpressionKind.Branch26
                or PcRelativeExpressionKind.Call26
                or PcRelativeExpressionKind.ConditionalBranch19
                or PcRelativeExpressionKind.TestBranch14
                or PcRelativeExpressionKind.Literal19 => sizeof(uint),
            PcRelativeExpressionKind.AdrPrelLo21 => 1,
            PcRelativeExpressionKind.AdrPrelPgHi21 => 0x1000,
            _ => 0,
        };
        var expectedPageRelative = expression.Kind == PcRelativeExpressionKind.AdrPrelPgHi21;
        if (expression.Scale != expectedScale
            || expression.IsPageRelative != expectedPageRelative)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The PC-relative expression has an invalid scale or page-relative mode for its family.",
                fixup.SourceFileOffset.Value);
        }

        if (expression.Place.Value % sizeof(uint) != 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A PC-relative expression place is not aligned to an AArch64 instruction.",
                fixup.SourceFileOffset.Value);
        }

        if (expectedKind is null || expectedKind.Value != fixup.Kind)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The semantic fixup kind does not match its PC-relative expression kind.",
                fixup.SourceFileOffset.Value);
        }
    }

    private static void ValidateTargetRelationships(
        SemanticFixup fixup,
        DiagnosticBag diagnostics)
    {
        if (fixup.Expression is { } expression
            && !TargetsMatch(fixup.Target, expression.Target))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A PC-relative fixup target does not match its expression target.",
                fixup.SourceFileOffset.Value);
        }

        if (fixup.Relocation is { } relocation
            && !TargetsMatch(fixup.Target, relocation.Target))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation fixup target does not match its relocation binding target.",
                fixup.SourceFileOffset.Value);
        }
    }

    private static bool TargetsMatch(SemanticTarget left, SemanticTarget right) =>
        left.Resolution == right.Resolution
        && left.SourceAddress == right.SourceAddress
        && left.Identity == right.Identity
        && string.Equals(left.RuntimeBinding, right.RuntimeBinding, StringComparison.Ordinal)
        && string.Equals(left.Diagnostic, right.Diagnostic, StringComparison.Ordinal)
        && left.CandidateIdentities.ToHashSet().SetEquals(right.CandidateIdentities)
        && left.CandidateAddresses.ToHashSet().SetEquals(right.CandidateAddresses);

    private static void ValidateEntityIdentity(
        SemanticEntityId identity,
        string name,
        ulong offset,
        DiagnosticBag diagnostics)
    {
        if (!Enum.IsDefined(typeof(SemanticEntityKind), identity.Kind)
            || string.IsNullOrWhiteSpace(identity.Value))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"A {name} has an unsupported kind or empty value.",
                offset);
        }
    }

    private static void ValidateTarget(
        SemanticTarget target,
        ulong offset,
        DiagnosticBag diagnostics)
    {
        if (target.Identity is { } identity)
        {
            ValidateEntityIdentity(identity, "semantic target identity", offset, diagnostics);
        }

        var candidateIdentities = new HashSet<SemanticEntityId>();
        foreach (var candidateIdentity in target.CandidateIdentities)
        {
            ValidateEntityIdentity(candidateIdentity, "semantic target candidate identity", offset, diagnostics);
            if (!candidateIdentities.Add(candidateIdentity))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic target contains duplicate candidate identities.",
                    offset);
            }
        }

        var candidateAddresses = new HashSet<VirtualAddress>();
        foreach (var candidateAddress in target.CandidateAddresses)
        {
            if (!candidateAddresses.Add(candidateAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic target contains duplicate candidate addresses.",
                    offset);
            }
        }

        switch (target.Resolution)
        {
            case SemanticTargetResolution.Exact
                when target.SourceAddress is null && target.Identity is null:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "An exact semantic target has no source address or entity identity.",
                    offset);
                break;
            case SemanticTargetResolution.Exact:
                break;
            case SemanticTargetResolution.BoundedSet
                when target.CandidateAddresses.Count == 0 && target.CandidateIdentities.Count == 0:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "A bounded semantic target set is empty.",
                    offset);
                break;
            case SemanticTargetResolution.RuntimeResolved
                when string.IsNullOrWhiteSpace(target.RuntimeBinding):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "A runtime-resolved semantic target is missing its binding identity.",
                    offset);
                break;
            case SemanticTargetResolution.Unresolved
                when string.IsNullOrWhiteSpace(target.Diagnostic):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "An unresolved semantic target is missing a diagnostic.",
                    offset);
                break;
            case SemanticTargetResolution.BoundedSet:
            case SemanticTargetResolution.RuntimeResolved:
            case SemanticTargetResolution.Unresolved:
                diagnostics.Warning(
                    DiagnosticCode.SemanticTargetUnresolved,
                    target.Diagnostic ?? "The semantic target requires a sibling resolver before final encoding.",
                    offset);
                break;
            default:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "The semantic target has an unknown resolution kind.",
                    offset);
                break;
        }
    }

}
