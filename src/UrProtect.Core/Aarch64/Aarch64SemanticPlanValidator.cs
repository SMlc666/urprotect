using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

/// <summary>
/// Validation details for one resolved semantic fixup.
/// </summary>
public sealed record SemanticFixupValidationResult
{
    public SemanticFixupValidationResult(
        SemanticFixupResolution resolution,
        IEnumerable<Diagnostic> diagnostics)
        : this(resolution, resolution.IsDeferred, diagnostics)
    {
    }

    public SemanticFixupValidationResult(
        SemanticFixupResolution resolution,
        bool isDeferred,
        IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(diagnostics);

        Resolution = resolution;
        IsDeferred = isDeferred;
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
    }

    public SemanticFixupResolution Resolution { get; }

    public SemanticFixup Fixup => Resolution.Fixup;

    public bool IsDeferred { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsValidated => !IsDeferred
        && Resolution.IsFinal
        && Diagnostics.All(diagnostic => !diagnostic.IsError);

    public bool IsSuccess => IsValidated;
}

/// <summary>
/// Structured post-encode validation for a semantic rewrite plan.
/// </summary>
public sealed record SemanticPlanValidationResult
{
    public SemanticPlanValidationResult(
        IEnumerable<SemanticFixupValidationResult> fixups,
        IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(fixups);
        ArgumentNullException.ThrowIfNull(diagnostics);

        Fixups = Array.AsReadOnly(fixups.ToArray());
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
        DeferredFixups = Array.AsReadOnly(
            Fixups.Where(fixup => fixup.IsDeferred).ToArray());
    }

    public IReadOnlyList<SemanticFixupValidationResult> Fixups { get; }

    public IReadOnlyList<SemanticFixupValidationResult> DeferredFixups { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool HasDeferredFixups => DeferredFixups.Count != 0;

    public bool IsSuccess => !HasDeferredFixups
        && Diagnostics.All(diagnostic => !diagnostic.IsError)
        && Fixups.All(fixup => fixup.IsValidated);
}

/// <summary>
/// Performs read-only round-trip validation of encoded semantic fixups.
/// </summary>
/// <remarks>
/// This validator consumes symbolic plan and resolution records only. It never
/// chooses a physical ELF placement and never writes an instruction or
/// relocation value to an image buffer. The supplied decoder is the only
/// instruction-backend boundary.
/// </remarks>
public static class Aarch64SemanticPlanValidator
{
    public static SemanticPlanValidationResult Validate(
        SemanticRewritePlan plan,
        SemanticPlanResolutionResult resolution,
        IAarch64Decoder decoder)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(decoder);

        var diagnostics = new DiagnosticBag();
        AddUnique(diagnostics, plan.Diagnostics);
        AddUnique(diagnostics, resolution.Diagnostics);

        var validations = new List<SemanticFixupValidationResult>();
        var plannedFixups = plan.Fixups;
        var resolvedFixups = resolution.Fixups;
        var pairedCount = Math.Min(plannedFixups.Count, resolvedFixups.Count);

        for (var index = 0; index < pairedCount; index++)
        {
            var plannedFixup = plannedFixups[index];
            var resolvedFixup = resolvedFixups[index];
            if (plannedFixup is null)
            {
                AddDiagnostic(
                    diagnostics,
                    new Diagnostic(
                        DiagnosticSeverity.Error,
                        DiagnosticCode.SemanticFixupMalformed,
                        "A semantic rewrite plan contains a null fixup."));
                continue;
            }

            if (resolvedFixup is null)
            {
                AddDiagnostic(
                    diagnostics,
                    new Diagnostic(
                        DiagnosticSeverity.Error,
                        DiagnosticCode.SemanticFixupMalformed,
                        "A semantic resolution result contains a null fixup resolution.",
                        plannedFixup.SourceFileOffset.Value));
                continue;
            }

            if (!MatchesFixup(plannedFixup, resolvedFixup.Fixup))
            {
                var mismatch = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic resolution result does not correspond to the plan fixup at the same index.",
                    plannedFixup.SourceFileOffset.Value);
                AddDiagnostic(diagnostics, mismatch);
                validations.Add(
                    new SemanticFixupValidationResult(
                        resolvedFixup,
                        resolvedFixup.IsDeferred,
                        new[] { mismatch }));
                continue;
            }

            var validation = ValidateFixup(plan, resolvedFixup, decoder);
            validations.Add(validation);
            AddUnique(diagnostics, validation.Diagnostics);
        }

        if (plannedFixups.Count != resolvedFixups.Count)
        {
            AddDiagnostic(
                diagnostics,
                new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.SemanticPlanMalformed,
                    "The semantic plan and resolution result contain different fixup counts."));
        }

        return new SemanticPlanValidationResult(validations, diagnostics.ToArray());
    }

    public static SemanticPlanValidationResult Validate(
        SemanticRewritePlan plan,
        IAarch64Decoder decoder)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(decoder);

        return Validate(plan, plan.ResolveFixups(), decoder);
    }

    private static SemanticFixupValidationResult ValidateFixup(
        SemanticRewritePlan plan,
        SemanticFixupResolution resolution,
        IAarch64Decoder decoder)
    {
        var diagnostics = new DiagnosticBag();
        diagnostics.AddRange(resolution.Diagnostics);

        if (resolution.IsDeferred
            || RequiresDeferredTarget(resolution))
        {
            EnsureDeferredDiagnostic(resolution.Fixup, diagnostics);
            return new SemanticFixupValidationResult(
                resolution,
                true,
                diagnostics.ToArray());
        }

        if (!resolution.IsFinal)
        {
            if (!diagnostics.Any(diagnostic => diagnostic.IsError))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A non-deferred semantic fixup is not final and has no failure diagnostic.",
                    resolution.Fixup.SourceFileOffset.Value);
            }

            return new SemanticFixupValidationResult(
                resolution,
                false,
                diagnostics.ToArray());
        }

        if (resolution.Fixup.Kind == SemanticFixupKind.Relocation)
        {
            if (IsInstructionRelocation(resolution.Fixup.Relocation?.Kind))
            {
                if (resolution.InstructionEncoding is { } instructionEncoding)
                {
                    ValidateInstruction(plan, resolution, instructionEncoding, decoder, diagnostics);
                }
                else
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A final instruction relocation has no encoded instruction word.",
                        resolution.Fixup.SourceFileOffset.Value);
                }
            }
            else
            {
                ValidateRelocationOnly(plan, resolution, diagnostics);
            }
        }
        else if (resolution.InstructionEncoding is { } encoding)
        {
            ValidateInstruction(plan, resolution, encoding, decoder, diagnostics);
        }
        else
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A final instruction fixup has no encoded instruction word.",
                resolution.Fixup.SourceFileOffset.Value);
        }

        return new SemanticFixupValidationResult(
            resolution,
            false,
            diagnostics.ToArray());
    }

    private static void ValidateInstruction(
        SemanticRewritePlan plan,
        SemanticFixupResolution resolution,
        uint encoding,
        IAarch64Decoder decoder,
        DiagnosticBag diagnostics)
    {
        var fixup = resolution.Fixup;
        if (!TryValidateWriteRange(
                plan,
                fixup,
                resolution,
                sizeof(uint),
                diagnostics,
                out var outputRange)
            || resolution.OutputSourceAddress is not { } outputSourceAddress)
        {
            return;
        }

        if (!TryValidateResolvedTarget(plan, fixup, resolution, diagnostics, out var outputTargetAddress)
            || !TryValidateExpressionPlace(plan, fixup, outputSourceAddress, diagnostics))
        {
            return;
        }

        var decoded = decoder.Decode(encoding, outputSourceAddress.Value);
        if (!decoded.IsSuccess || decoded.Instruction is null)
        {
            var message = string.IsNullOrWhiteSpace(decoded.Diagnostic)
                ? $"The encoded AArch64 instruction 0x{encoding:X8} did not decode at the planned output address 0x{outputSourceAddress.Value:X}."
                : decoded.Diagnostic;
            diagnostics.Error(
                Aarch64SemanticInstructionProjector.GetDecodeDiagnosticCode(decoded.Status),
                message,
                fixup.SourceFileOffset.Value);
            return;
        }

        if (decoded.Instruction.Address != outputSourceAddress.Value
            || decoded.Instruction.Encoding != encoding)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The post-encode decoder returned an instruction with a mismatched address or encoding.",
                fixup.SourceFileOffset.Value);
            return;
        }

        var projection = Aarch64SemanticInstructionProjector.Project(
            new Aarch64FunctionInstruction(
                outputRange.FileOffset.Value,
                outputSourceAddress.Value,
                encoding,
                decoded));
        AddUnique(diagnostics, projection.Diagnostics);
        if (projection.Instruction is null || projection.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return;
        }

        var expectedExpressionKind = GetPcRelativeExpressionKind(fixup);
        if (expectedExpressionKind is { } expectedKind)
        {
            if (projection.Instruction.PcRelativeExpression is not { } actualExpression
                || actualExpression.Kind != expectedKind)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    $"The post-encode instruction family does not match the planned semantic fixup '{expectedKind}'.",
                    fixup.SourceFileOffset.Value);
                return;
            }

            if (decoded.Instruction.DirectTarget is not { } decodedTarget)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "The post-encode decoder did not expose the direct target required by the planned PC-relative fixup.",
                    fixup.SourceFileOffset.Value);
                return;
            }

            if (projection.Instruction.Operands
                .Where(operand => operand.Kind == Aarch64OperandKind.Target && operand.Target is not null)
                .Select(operand => operand.Target!.Value)
                .Any(operandTarget => operandTarget != decodedTarget))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "The post-encode target operand does not match the decoder's direct target.",
                    fixup.SourceFileOffset.Value);
                return;
            }

            if (!TryGetDecodedTarget(
                    fixup,
                    outputTargetAddress.Value,
                    out var expectedTarget))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupOutOfRange,
                    "The resolved semantic target and its addend do not fit the AArch64 address domain.",
                    fixup.SourceFileOffset.Value);
                return;
            }

            if (decodedTarget != expectedTarget)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    $"The post-encode target 0x{decodedTarget:X} does not match the resolved output target 0x{expectedTarget:X}.",
                    fixup.SourceFileOffset.Value);
            }

            return;
        }

        if (projection.Instruction.PcRelativeExpression is not null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The post-encode instruction has a PC-relative expression where the planned fixup has none.",
                fixup.SourceFileOffset.Value);
            return;
        }

        if (fixup.Relocation is { } relocation
            && !ValidateInstructionRelocation(
                fixup,
                relocation,
                outputTargetAddress,
                encoding,
                diagnostics))
        {
            return;
        }
    }

    private static bool ValidateInstructionRelocation(
        SemanticFixup fixup,
        RelocationBinding relocation,
        VirtualAddress outputTargetAddress,
        uint encoding,
        DiagnosticBag diagnostics)
    {
        if (!TryAddSigned(outputTargetAddress.Value, relocation.Addend, out var targetValue))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupOutOfRange,
                "The instruction relocation addend overflowed the address domain.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        switch (relocation.Kind)
        {
            case Aarch64RelocationKind.AddAbsLo12:
                if ((encoding & (1u << 22)) != 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "The ADD low-12 relocation requires an unshifted immediate field.",
                        fixup.SourceFileOffset.Value);
                    return false;
                }

                var addImmediate = (encoding >> 10) & 0xFFFu;
                if (addImmediate != (targetValue & 0xFFFu))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "The post-encode ADD low-12 immediate does not match the symbolic relocation target.",
                        fixup.SourceFileOffset.Value);
                    return false;
                }

                return true;
            case Aarch64RelocationKind.LoadStore:
                var encodedScale = 1UL << (int)((encoding >> 30) & 0x3);
                var expectedScale = relocation.RelocationType switch
                {
                    ElfConstants.RArm64Ldst8AbsLo12Nc => 1UL,
                    ElfConstants.RArm64Ldst16AbsLo12Nc => 2UL,
                    ElfConstants.RArm64Ldst32AbsLo12Nc => 4UL,
                    ElfConstants.RArm64Ldst64AbsLo12Nc => 8UL,
                    ElfConstants.RArm64Ldst128AbsLo12Nc => 16UL,
                    _ => encodedScale,
                };
                if (expectedScale != 16 && encodedScale != expectedScale)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "The post-encode load/store relocation width does not match the instruction access width.",
                        fixup.SourceFileOffset.Value);
                    return false;
                }

                var low12 = targetValue & 0xFFFUL;
                if (low12 % expectedScale != 0 || low12 / expectedScale > 0xFFFUL)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupOutOfRange,
                        "The post-encode load/store low-12 immediate is not aligned for the instruction access width.",
                        fixup.SourceFileOffset.Value);
                    return false;
                }

                var loadStoreImmediate = (encoding >> 10) & 0xFFFu;
                if (loadStoreImmediate != low12 / expectedScale)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "The post-encode load/store low-12 immediate does not match the symbolic relocation target.",
                        fixup.SourceFileOffset.Value);
                    return false;
                }

                return true;
            default:
                return true;
        }
    }

    private static bool IsInstructionRelocation(Aarch64RelocationKind? kind) =>
        kind is Aarch64RelocationKind.Call26
            or Aarch64RelocationKind.Jump26
            or Aarch64RelocationKind.ConditionalBranch19
            or Aarch64RelocationKind.TestBranch14
            or Aarch64RelocationKind.AdrPrelLo21
            or Aarch64RelocationKind.AdrPrelPgHi21
            or Aarch64RelocationKind.Literal19
            or Aarch64RelocationKind.AddAbsLo12
            or Aarch64RelocationKind.LoadStore;

    private static void ValidateRelocationOnly(
        SemanticRewritePlan plan,
        SemanticFixupResolution resolution,
        DiagnosticBag diagnostics)
    {
        var fixup = resolution.Fixup;
        var relocation = fixup.Relocation;
        if (relocation is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation-only fixup has no relocation binding.",
                fixup.SourceFileOffset.Value);
            return;
        }

        if (resolution.InstructionEncoding is not null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation-only fixup cannot carry an instruction encoding.",
                fixup.SourceFileOffset.Value);
            return;
        }

        if (!relocation.IsKindConsistent)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation-only binding kind does not match its raw AArch64 relocation type.",
                fixup.SourceFileOffset.Value);
        }

        if (relocation.RelocationAddress is { } relocationAddress
            && relocationAddress != fixup.SourceAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation-only binding address does not match its fixup source address.",
                fixup.SourceFileOffset.Value);
        }

        var writeSize = SemanticFixup.GetRelocationWriteSize(relocation.Kind);
        if (writeSize == 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupUnsupported,
                "A relocation-only fixup has no declared relocation write width.",
                fixup.SourceFileOffset.Value);
            return;
        }

        if (!TryValidateWriteRange(
                plan,
                fixup,
                resolution,
                writeSize,
                diagnostics,
                out var outputRange)
            || !TryValidateResolvedTarget(plan, fixup, resolution, diagnostics, out var outputTargetAddress))
        {
            return;
        }

        if (resolution.RelocationValue is not { } relocationValue)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A final relocation-only fixup has no symbolic relocation value.",
                fixup.SourceFileOffset.Value);
            return;
        }

        if (!TryGetExpectedRelocationValue(
                relocation,
                outputTargetAddress,
                outputRange.VirtualAddress,
                fixup.SourceFileOffset.Value,
                diagnostics,
                out var expectedRelocationValue))
        {
            return;
        }

        if (relocationValue != expectedRelocationValue)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"The symbolic relocation value 0x{relocationValue:X} does not match the planned value 0x{expectedRelocationValue:X}.",
                fixup.SourceFileOffset.Value);
        }
    }

    private static bool TryValidateWriteRange(
        SemanticRewritePlan plan,
        SemanticFixup fixup,
        SemanticFixupResolution resolution,
        ulong writeSize,
        DiagnosticBag diagnostics,
        out SemanticSourceRange outputRange)
    {
        outputRange = default;
        var valid = true;
        if (fixup.SourceRange.Size != writeSize
            || !fixup.SourceRange.TryGetFileEnd(out _)
            || !fixup.SourceRange.TryGetVirtualEnd(out _)
            || fixup.SourceRange.FileOffset.Value % writeSize != 0
            || fixup.SourceRange.VirtualAddress.Value % writeSize != 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A semantic fixup source range does not satisfy its declared write width, alignment, or address domain.",
                fixup.SourceFileOffset.Value);
            valid = false;
        }

        var preferredSourceKind = fixup.Kind == SemanticFixupKind.Relocation
            ? SemanticEntityKind.RelocationSite
            : SemanticEntityKind.Instruction;
        if (!plan.AddressMap.TryMapSourceRange(
                fixup.SourceRange,
                preferredSourceKind,
                out outputRange))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "A semantic fixup source range has no unique planned output mapping.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        if (outputRange.Size != writeSize
            || !outputRange.TryGetFileEnd(out _)
            || !outputRange.TryGetVirtualEnd(out _)
            || outputRange.FileOffset.Value % writeSize != 0
            || outputRange.VirtualAddress.Value % writeSize != 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A planned semantic fixup range does not satisfy its declared write width, alignment, or address domain.",
                fixup.SourceFileOffset.Value);
            valid = false;
        }

        if (resolution.OutputSourceAddress is not { } outputSourceAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A final semantic fixup has no planned output source address.",
                fixup.SourceFileOffset.Value);
            valid = false;
        }
        else if (outputSourceAddress != outputRange.VirtualAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "A resolved semantic fixup source address does not match the address map.",
                fixup.SourceFileOffset.Value);
            valid = false;
        }

        return valid;
    }

    private static bool TryValidateResolvedTarget(
        SemanticRewritePlan plan,
        SemanticFixup fixup,
        SemanticFixupResolution resolution,
        DiagnosticBag diagnostics,
        out VirtualAddress outputTargetAddress)
    {
        outputTargetAddress = default;
        if (resolution.OutputTargetAddress is not { } resolvedTarget)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticTargetUnresolved,
                "A final semantic fixup has no resolved output target.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        if (!TryGetMappedTargetAddresses(
                plan.AddressMap,
                fixup,
                fixup.Target,
                fixup.SourceFileOffset.Value,
                diagnostics,
                out var mappedTargets))
        {
            return false;
        }

        if (!mappedTargets.Contains(resolvedTarget))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "The resolved output target is not one of the target addresses planned by the address map.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        outputTargetAddress = resolvedTarget;
        return true;
    }

    private static bool TryGetMappedTargetAddresses(
        AddressMap addressMap,
        SemanticFixup fixup,
        SemanticTarget target,
        ulong diagnosticOffset,
        DiagnosticBag diagnostics,
        out HashSet<VirtualAddress> mappedTargets)
    {
        mappedTargets = new HashSet<VirtualAddress>();
        switch (target.Resolution)
        {
            case SemanticTargetResolution.Exact:
            {
                var hasMappedTarget = false;
                if (target.Identity is { } identity)
                {
                    if (!addressMap.TryMapEntity(identity, out var mappedIdentity))
                    {
                        diagnostics.Error(
                            DiagnosticCode.SemanticAddressMapMissing,
                            "The exact semantic target identity has no planned output mapping.",
                            diagnosticOffset);
                        return false;
                    }

                    mappedTargets.Add(mappedIdentity);
                    hasMappedTarget = true;
                }

                if (target.SourceAddress is { } sourceAddress)
                {
                    var preferredKind = target.Identity is { } targetIdentity
                        ? targetIdentity.Kind
                        : GetPreferredTargetKind(fixup);
                    if (!TryMapTargetAddress(
                            addressMap,
                            sourceAddress,
                            preferredKind,
                            out var mappedAddress))
                    {
                        diagnostics.Error(
                            DiagnosticCode.SemanticAddressMapMissing,
                            "The exact semantic target address has no unique planned output mapping.",
                            diagnosticOffset);
                        return false;
                    }

                    mappedTargets.Add(mappedAddress);
                    hasMappedTarget = true;
                }

                if (!hasMappedTarget)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticTargetUnresolved,
                        "An exact semantic target has no mapped identity or address.",
                        diagnosticOffset);
                    return false;
                }

                if (mappedTargets.Count != 1)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanMalformed,
                        "The exact semantic target identity and address map to different output addresses.",
                        diagnosticOffset);
                    return false;
                }

                return true;
            }
            case SemanticTargetResolution.BoundedSet:
                foreach (var candidateAddress in target.CandidateAddresses)
                {
                    if (!TryMapTargetAddress(
                            addressMap,
                            candidateAddress,
                            GetPreferredTargetKind(fixup),
                            out var mappedAddress))
                    {
                        diagnostics.Error(
                            DiagnosticCode.SemanticAddressMapMissing,
                            "A bounded semantic target address has no unique planned output mapping.",
                            diagnosticOffset);
                        return false;
                    }

                    mappedTargets.Add(mappedAddress);
                }

                foreach (var candidateIdentity in target.CandidateIdentities)
                {
                    if (!addressMap.TryMapEntity(candidateIdentity, out var mappedIdentity))
                    {
                        diagnostics.Error(
                            DiagnosticCode.SemanticAddressMapMissing,
                            "A bounded semantic target identity has no planned output mapping.",
                            diagnosticOffset);
                        return false;
                    }

                    mappedTargets.Add(mappedIdentity);
                }

                if (mappedTargets.Count == 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticTargetUnresolved,
                        "A bounded semantic target set is empty.",
                        diagnosticOffset);
                    return false;
                }

                return true;
            case SemanticTargetResolution.RuntimeResolved:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    target.Diagnostic ?? "A runtime-resolved semantic target requires a runtime resolver.",
                    diagnosticOffset);
                return false;
            case SemanticTargetResolution.Unresolved:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    target.Diagnostic ?? "The semantic target is unresolved.",
                    diagnosticOffset);
                return false;
            default:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "The semantic target has an unknown resolution kind.",
                    diagnosticOffset);
                return false;
        }
    }

    private static bool TryMapTargetAddress(
        AddressMap addressMap,
        VirtualAddress sourceAddress,
        SemanticEntityKind? preferredKind,
        out VirtualAddress outputAddress)
    {
        if (preferredKind is { } kind
            && addressMap.TryMapSourceAddress(sourceAddress, kind, out outputAddress))
        {
            return true;
        }

        return addressMap.TryMapSourceAddress(sourceAddress, out outputAddress);
    }

    private static SemanticEntityKind? GetPreferredTargetKind(SemanticFixup fixup)
    {
        if (fixup.Relocation is not null
            && fixup.Target.Identity is null
            && fixup.Target.SourceAddress is not null)
        {
            return SemanticEntityKind.RelocationTarget;
        }

        return fixup.Kind == SemanticFixupKind.Literal19
            || fixup.Relocation?.Kind == Aarch64RelocationKind.Literal19
            ? SemanticEntityKind.Literal
            : null;
    }

    private static bool TryValidateExpressionPlace(
        SemanticRewritePlan plan,
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        DiagnosticBag diagnostics)
    {
        if (fixup.Expression is not { } expression
            || expression.Place == fixup.SourceAddress)
        {
            return true;
        }

        if (!plan.AddressMap.TryMapSourceAddress(expression.Place, out var outputPlaceAddress))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "The PC-relative expression place has no unique planned output mapping.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        if (outputPlaceAddress != outputSourceAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "The planned PC-relative expression place does not match the output instruction address.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        return true;
    }

    private static PcRelativeExpressionKind? GetPcRelativeExpressionKind(SemanticFixup fixup)
    {
        if (fixup.Kind != SemanticFixupKind.Relocation)
        {
            return fixup.Kind switch
            {
                SemanticFixupKind.Branch26 => PcRelativeExpressionKind.Branch26,
                SemanticFixupKind.Call26 => PcRelativeExpressionKind.Call26,
                SemanticFixupKind.ConditionalBranch19 => PcRelativeExpressionKind.ConditionalBranch19,
                SemanticFixupKind.TestBranch14 => PcRelativeExpressionKind.TestBranch14,
                SemanticFixupKind.AdrPrelLo21 => PcRelativeExpressionKind.AdrPrelLo21,
                SemanticFixupKind.AdrPrelPgHi21 => PcRelativeExpressionKind.AdrPrelPgHi21,
                SemanticFixupKind.Literal19 => PcRelativeExpressionKind.Literal19,
                _ => null,
            };
        }

        return fixup.Relocation?.Kind switch
        {
            Aarch64RelocationKind.Jump26 => PcRelativeExpressionKind.Branch26,
            Aarch64RelocationKind.Call26 => PcRelativeExpressionKind.Call26,
            Aarch64RelocationKind.ConditionalBranch19 => PcRelativeExpressionKind.ConditionalBranch19,
            Aarch64RelocationKind.TestBranch14 => PcRelativeExpressionKind.TestBranch14,
            Aarch64RelocationKind.AdrPrelLo21 => PcRelativeExpressionKind.AdrPrelLo21,
            Aarch64RelocationKind.AdrPrelPgHi21 => PcRelativeExpressionKind.AdrPrelPgHi21,
            Aarch64RelocationKind.Literal19 => PcRelativeExpressionKind.Literal19,
            _ => null,
        };
    }

    private static bool TryGetExpectedRelocationValue(
        RelocationBinding relocation,
        VirtualAddress outputTargetAddress,
        VirtualAddress outputPlaceAddress,
        ulong diagnosticOffset,
        DiagnosticBag diagnostics,
        out ulong expectedValue)
    {
        expectedValue = default;
        if (!TryAddSigned(outputTargetAddress.Value, relocation.Addend, out var targetValue))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupOutOfRange,
                "The symbolic relocation addend overflowed the address domain.",
                diagnosticOffset);
            return false;
        }

        switch (relocation.Kind)
        {
            case Aarch64RelocationKind.Absolute64:
            case Aarch64RelocationKind.Relative:
            case Aarch64RelocationKind.GlobalData:
            case Aarch64RelocationKind.JumpSlot:
                expectedValue = targetValue;
                return true;
            case Aarch64RelocationKind.Absolute32:
                if (targetValue > uint.MaxValue)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupOutOfRange,
                        "The ABS32 relocation value exceeds the 32-bit address domain.",
                        diagnosticOffset);
                    return false;
                }

                expectedValue = targetValue;
                return true;
            case Aarch64RelocationKind.Prel64:
                if (!TryGetSignedDelta(targetValue, outputPlaceAddress.Value, out var prel64))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupOutOfRange,
                        "The PREL64 relocation expression does not fit the signed address domain.",
                        diagnosticOffset);
                    return false;
                }

                expectedValue = unchecked((ulong)prel64);
                return true;
            case Aarch64RelocationKind.Prel32:
                if (!TryGetSignedDelta(targetValue, outputPlaceAddress.Value, out var prel32)
                    || prel32 < int.MinValue
                    || prel32 > int.MaxValue)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupOutOfRange,
                        "The PREL32 relocation expression does not fit the signed 32-bit address domain.",
                        diagnosticOffset);
                    return false;
                }

                expectedValue = unchecked((uint)prel32);
                return true;
            default:
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupUnsupported,
                    $"The {relocation.Kind} relocation has no symbolic validation rule.",
                    diagnosticOffset);
                return false;
        }
    }

    private static bool TryGetDecodedTarget(
        SemanticFixup fixup,
        ulong outputTargetAddress,
        out ulong decodedTarget)
    {
        var addend = fixup.Expression?.Addend ?? fixup.Relocation?.Addend ?? 0;
        if (!TryAddSigned(outputTargetAddress, addend, out decodedTarget))
        {
            return false;
        }

        if (GetPcRelativeExpressionKind(fixup) == PcRelativeExpressionKind.AdrPrelPgHi21)
        {
            decodedTarget &= ~0xFFFUL;
        }

        return true;
    }

    private static bool TryGetSignedDelta(ulong target, ulong place, out long delta)
    {
        if (target >= place)
        {
            var positive = target - place;
            if (positive > long.MaxValue)
            {
                delta = default;
                return false;
            }

            delta = (long)positive;
            return true;
        }

        var magnitude = place - target;
        if (magnitude > (1UL << 63))
        {
            delta = default;
            return false;
        }

        delta = magnitude == (1UL << 63)
            ? long.MinValue
            : -(long)magnitude;
        return true;
    }

    private static bool TryAddSigned(ulong value, long addend, out ulong result)
    {
        if (addend >= 0)
        {
            var unsignedAddend = (ulong)addend;
            if (value > ulong.MaxValue - unsignedAddend)
            {
                result = default;
                return false;
            }

            result = value + unsignedAddend;
            return true;
        }

        var magnitude = addend == long.MinValue
            ? (ulong)long.MaxValue + 1
            : (ulong)(-addend);
        if (value < magnitude)
        {
            result = default;
            return false;
        }

        result = value - magnitude;
        return true;
    }

    private static bool RequiresDeferredTarget(SemanticFixupResolution resolution)
    {
        var target = resolution.Fixup.Target;
        return target.IsRuntimeResolved || target.IsBoundedSet;
    }

    private static bool MatchesFixup(SemanticFixup expected, SemanticFixup actual) =>
        expected.Kind == actual.Kind
        && expected.SourceAddress == actual.SourceAddress
        && expected.SourceFileOffset == actual.SourceFileOffset
        && expected.OriginalEncoding == actual.OriginalEncoding
        && expected.SourceRange == actual.SourceRange
        && TargetsMatch(expected.Target, actual.Target)
        && MatchesExpression(expected.Expression, actual.Expression)
        && MatchesRelocation(expected.Relocation, actual.Relocation)
        && expected.Relaxation == actual.Relaxation
        && expected.RelaxationOptions.SequenceEqual(actual.RelaxationOptions);

    private static bool MatchesExpression(
        PcRelativeExpression? expected,
        PcRelativeExpression? actual)
    {
        if (expected is null || actual is null)
        {
            return expected is null && actual is null;
        }

        return expected.Kind == actual.Kind
            && expected.Place == actual.Place
            && expected.Scale == actual.Scale
            && expected.IsPageRelative == actual.IsPageRelative
            && expected.Addend == actual.Addend
            && TargetsMatch(expected.Target, actual.Target);
    }

    private static bool MatchesRelocation(
        RelocationBinding? expected,
        RelocationBinding? actual)
    {
        if (expected is null || actual is null)
        {
            return expected is null && actual is null;
        }

        return expected.Kind == actual.Kind
            && TargetsMatch(expected.Target, actual.Target)
            && expected.Addend == actual.Addend
            && expected.SymbolIndex == actual.SymbolIndex
            && expected.IsPlt == actual.IsPlt
            && string.Equals(expected.SymbolName, actual.SymbolName, StringComparison.Ordinal)
            && expected.RelocationType == actual.RelocationType
            && expected.RelocationAddress == actual.RelocationAddress
            && expected.RelocationTableAddress == actual.RelocationTableAddress
            && expected.RawInfo == actual.RawInfo;
    }

    private static bool TargetsMatch(SemanticTarget left, SemanticTarget right) =>
        left.Resolution == right.Resolution
        && left.SourceAddress == right.SourceAddress
        && left.Identity == right.Identity
        && string.Equals(left.RuntimeBinding, right.RuntimeBinding, StringComparison.Ordinal)
        && string.Equals(left.Diagnostic, right.Diagnostic, StringComparison.Ordinal)
        && left.CandidateIdentities.ToHashSet().SetEquals(right.CandidateIdentities)
        && left.CandidateAddresses.ToHashSet().SetEquals(right.CandidateAddresses);

    private static void EnsureDeferredDiagnostic(
        SemanticFixup fixup,
        DiagnosticBag diagnostics)
    {
        if (!diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupDeferred))
        {
            diagnostics.Warning(
                DiagnosticCode.SemanticFixupDeferred,
                "The semantic fixup is deferred until a veneer, long-address, runtime, or bounded-set resolver supplies a final target.",
                fixup.SourceFileOffset.Value);
        }
    }

    private static void AddUnique(
        DiagnosticBag diagnostics,
        IEnumerable<Diagnostic> additions)
    {
        ArgumentNullException.ThrowIfNull(additions);
        foreach (var diagnostic in additions)
        {
            AddDiagnostic(diagnostics, diagnostic);
        }
    }

    private static void AddDiagnostic(
        DiagnosticBag diagnostics,
        Diagnostic diagnostic)
    {
        if (!diagnostics.Any(existing => existing == diagnostic))
        {
            diagnostics.Add(diagnostic);
        }
    }
}
