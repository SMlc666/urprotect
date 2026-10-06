using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

/// <summary>
/// Resolves semantic AArch64 fixups against a planned address map.
/// </summary>
/// <remarks>
/// This type produces symbolic fixup results and encoded instruction words. It
/// never writes an ELF buffer or selects a physical placement. Range relaxation
/// is reported as deferred so the layout planner can allocate a veneer or a
/// long-address sequence without introducing a second writer here.
/// </remarks>
public static class Aarch64SemanticFixupEncoder
{
    private const uint Branch26ImmediateMask = 0x03FF_FFFF;
    private const uint Branch19ImmediateMask = 0x00FF_FFE0;
    private const uint Branch14ImmediateMask = 0x0007_FFE0;
    private const uint AdrImmediateMask = 0x60FF_FFE0;
    private const uint AddImmediateMask = 0x003F_FC00;
    private const int InstructionAlignment = sizeof(uint);

    public static SemanticPlanResolutionResult Resolve(SemanticRewritePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var diagnostics = new DiagnosticBag();
        diagnostics.AddRange(plan.Diagnostics);
        var resolutions = new List<SemanticFixupResolution>(plan.Fixups.Count);

        foreach (var fixup in plan.Fixups)
        {
            var resolution = Resolve(fixup, plan.AddressMap);
            resolutions.Add(resolution);
            diagnostics.AddRange(resolution.Diagnostics);
        }

        return new SemanticPlanResolutionResult(resolutions, diagnostics.ToArray());
    }

    public static SemanticFixupResolution Resolve(
        SemanticFixup fixup,
        AddressMap addressMap)
    {
        ArgumentNullException.ThrowIfNull(fixup);
        ArgumentNullException.ThrowIfNull(addressMap);

        var diagnostics = new DiagnosticBag();
        if (!TryResolveSource(fixup, addressMap, diagnostics, out var outputSourceAddress, out var outputPlaceAddress))
        {
            return Failure(fixup, outputSourceAddress, diagnostics);
        }

        if (!TryResolveTarget(
                fixup,
                fixup.Target,
                addressMap,
                fixup.SourceFileOffset.Value,
                diagnostics,
                out var targetResolution,
                out var outputTargetAddress))
        {
            return Failure(fixup, outputSourceAddress, diagnostics);
        }

        if (targetResolution == SemanticTargetResolution.RuntimeResolved)
        {
            diagnostics.Warning(
                DiagnosticCode.SemanticFixupDeferred,
                "The fixup target is runtime-resolved and requires a loader or sibling target resolver.",
                fixup.SourceFileOffset.Value);
            return Deferred(fixup, outputSourceAddress, diagnostics);
        }

        if (targetResolution == SemanticTargetResolution.BoundedSet)
        {
            diagnostics.Warning(
                DiagnosticCode.SemanticFixupDeferred,
                "The fixup target is a bounded set and requires layout-time target selection.",
                fixup.SourceFileOffset.Value);
            return Deferred(fixup, outputSourceAddress, diagnostics, outputTargetAddress);
        }

        if (outputTargetAddress is not { } targetAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticTargetUnresolved,
                "The semantic fixup target did not resolve to an output address.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics);
        }

        var expression = fixup.Expression;
        if (fixup.Kind != SemanticFixupKind.Relocation && expression is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A PC-relative fixup is missing its expression.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics);
        }

        if (fixup.Kind == SemanticFixupKind.Relocation)
        {
            return ResolveRelocation(
                fixup,
                outputSourceAddress,
                outputPlaceAddress,
                targetAddress,
                diagnostics);
        }

        return ResolvePcRelative(
            fixup,
            outputSourceAddress,
            outputPlaceAddress,
            targetAddress,
            expression!,
            diagnostics);
    }

    private static SemanticFixupResolution ResolvePcRelative(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        PcRelativeExpression expression,
        DiagnosticBag diagnostics)
    {
        var addendTarget = AddSigned(targetAddress.Value, expression.Addend, diagnostics, fixup.SourceFileOffset.Value);
        if (addendTarget is null)
        {
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        var encoded = expression.Kind switch
        {
            PcRelativeExpressionKind.Branch26 or PcRelativeExpressionKind.Call26 =>
                EncodeBranch26(
                    fixup.OriginalEncoding,
                    outputPlaceAddress,
                    addendTarget.Value,
                    diagnostics,
                    fixup.SourceFileOffset.Value),
            PcRelativeExpressionKind.ConditionalBranch19 =>
                EncodeBranch19(
                    fixup.OriginalEncoding,
                    outputPlaceAddress,
                    addendTarget.Value,
                    diagnostics,
                    fixup.SourceFileOffset.Value),
            PcRelativeExpressionKind.TestBranch14 =>
                EncodeBranch14(
                    fixup.OriginalEncoding,
                    outputPlaceAddress,
                    addendTarget.Value,
                    diagnostics,
                    fixup.SourceFileOffset.Value),
            PcRelativeExpressionKind.AdrPrelLo21 =>
                EncodeAdr(
                    fixup.OriginalEncoding,
                    outputPlaceAddress,
                    addendTarget.Value,
                    diagnostics,
                    fixup.SourceFileOffset.Value),
            PcRelativeExpressionKind.AdrPrelPgHi21 =>
                EncodeAdrp(
                    fixup.OriginalEncoding,
                    outputPlaceAddress,
                    addendTarget.Value,
                    diagnostics,
                    fixup.SourceFileOffset.Value),
            PcRelativeExpressionKind.Literal19 =>
                EncodeLiteral19(
                    fixup.OriginalEncoding,
                    outputPlaceAddress,
                    addendTarget.Value,
                    diagnostics,
                    fixup.SourceFileOffset.Value),
            _ => UnsupportedEncoding(fixup, diagnostics),
        };

        if (encoded is null)
        {
            if (HasRelaxationOption(fixup) && CanRelax(diagnostics))
            {
                diagnostics.Warning(
                    DiagnosticCode.SemanticFixupDeferred,
                    "The PC-relative target is outside the direct encoding range; layout-time relaxation is required.",
                    fixup.SourceFileOffset.Value);
                return Deferred(fixup, outputSourceAddress, diagnostics, targetAddress);
            }

            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        return Success(fixup, outputSourceAddress, targetAddress, encoded.Value, null, diagnostics);
    }

    private static SemanticFixupResolution ResolveRelocation(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        DiagnosticBag diagnostics)
    {
        var relocation = fixup.Relocation;
        if (relocation is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation fixup is missing its relocation binding.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        if (!relocation.IsKindConsistent)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation binding kind does not match its raw AArch64 relocation type.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        var value = AddSigned(targetAddress.Value, relocation.Addend, diagnostics, fixup.SourceFileOffset.Value);
        if (value is null)
        {
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        return relocation.Kind switch
        {
            Aarch64RelocationKind.None =>
                Success(fixup, outputSourceAddress, targetAddress, null, null, diagnostics),
            Aarch64RelocationKind.Absolute64 or Aarch64RelocationKind.Relative or
                Aarch64RelocationKind.GlobalData or Aarch64RelocationKind.JumpSlot =>
                Success(fixup, outputSourceAddress, targetAddress, null, value, diagnostics),
            Aarch64RelocationKind.Absolute32 =>
                ResolveAbsolute32(fixup, outputSourceAddress, targetAddress, value.Value, diagnostics),
            Aarch64RelocationKind.Prel64 =>
                ResolvePrel64(fixup, outputSourceAddress, outputPlaceAddress, targetAddress, value.Value, diagnostics),
            Aarch64RelocationKind.Prel32 =>
                ResolvePrel32(fixup, outputSourceAddress, outputPlaceAddress, targetAddress, value.Value, diagnostics),
            Aarch64RelocationKind.Call26 or Aarch64RelocationKind.Jump26 =>
                ResolveRelocationBranch26(
                    fixup,
                    outputSourceAddress,
                    outputPlaceAddress,
                    targetAddress,
                    value.Value,
                    diagnostics),
            Aarch64RelocationKind.ConditionalBranch19 =>
                ResolveRelocationBranch19(
                    fixup,
                    outputSourceAddress,
                    outputPlaceAddress,
                    targetAddress,
                    value.Value,
                    diagnostics),
            Aarch64RelocationKind.TestBranch14 =>
                ResolveRelocationBranch14(
                    fixup,
                    outputSourceAddress,
                    outputPlaceAddress,
                    targetAddress,
                    value.Value,
                    diagnostics),
            Aarch64RelocationKind.Literal19 =>
                ResolveRelocationLiteral19(
                    fixup,
                    outputSourceAddress,
                    outputPlaceAddress,
                    targetAddress,
                    value.Value,
                    diagnostics),
            Aarch64RelocationKind.AdrPrelLo21 =>
                ResolveRelocationAdr(fixup, outputSourceAddress, outputPlaceAddress, value.Value, targetAddress, diagnostics),
            Aarch64RelocationKind.AdrPrelPgHi21 =>
                ResolveRelocationAdrp(fixup, outputSourceAddress, outputPlaceAddress, value.Value, targetAddress, diagnostics),
            Aarch64RelocationKind.AddAbsLo12 =>
                ResolveAddLo12(fixup, outputSourceAddress, targetAddress, value.Value, diagnostics),
            Aarch64RelocationKind.LoadStore =>
                ResolveLoadStoreLo12(fixup, outputSourceAddress, targetAddress, value.Value, diagnostics),
            _ => UnsupportedRelocation(fixup, outputSourceAddress, targetAddress, diagnostics),
        };
    }

    private static SemanticFixupResolution ResolveRelocationBranch26(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        ulong relocationValue,
        DiagnosticBag diagnostics)
    {
        var encoded = EncodeBranch26(
            fixup.OriginalEncoding,
            outputPlaceAddress,
            relocationValue,
            diagnostics,
            fixup.SourceFileOffset.Value);
        return FinishInstructionEncoding(
            fixup,
            outputSourceAddress,
            targetAddress,
            encoded,
            diagnostics);
    }

    private static SemanticFixupResolution ResolveRelocationBranch19(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        ulong relocationValue,
        DiagnosticBag diagnostics)
    {
        var encoded = EncodeBranch19(
            fixup.OriginalEncoding,
            outputPlaceAddress,
            relocationValue,
            diagnostics,
            fixup.SourceFileOffset.Value);
        return FinishInstructionEncoding(
            fixup,
            outputSourceAddress,
            targetAddress,
            encoded,
            diagnostics);
    }

    private static SemanticFixupResolution ResolveRelocationBranch14(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        ulong relocationValue,
        DiagnosticBag diagnostics)
    {
        var encoded = EncodeBranch14(
            fixup.OriginalEncoding,
            outputPlaceAddress,
            relocationValue,
            diagnostics,
            fixup.SourceFileOffset.Value);
        return FinishInstructionEncoding(
            fixup,
            outputSourceAddress,
            targetAddress,
            encoded,
            diagnostics);
    }

    private static SemanticFixupResolution ResolveRelocationLiteral19(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        ulong relocationValue,
        DiagnosticBag diagnostics)
    {
        var encoded = EncodeLiteral19(
            fixup.OriginalEncoding,
            outputPlaceAddress,
            relocationValue,
            diagnostics,
            fixup.SourceFileOffset.Value);
        return FinishInstructionEncoding(
            fixup,
            outputSourceAddress,
            targetAddress,
            encoded,
            diagnostics);
    }

    private static SemanticFixupResolution ResolveRelocationAdr(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        ulong value,
        VirtualAddress targetAddress,
        DiagnosticBag diagnostics)
    {
        var encoded = EncodeAdr(
            fixup.OriginalEncoding,
            outputPlaceAddress,
            value,
            diagnostics,
            fixup.SourceFileOffset.Value);
        return FinishInstructionEncoding(
            fixup,
            outputSourceAddress,
            targetAddress,
            encoded,
            diagnostics);
    }

    private static SemanticFixupResolution ResolveRelocationAdrp(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        ulong value,
        VirtualAddress targetAddress,
        DiagnosticBag diagnostics)
    {
        var encoded = EncodeAdrp(
            fixup.OriginalEncoding,
            outputPlaceAddress,
            value,
            diagnostics,
            fixup.SourceFileOffset.Value);
        return FinishInstructionEncoding(
            fixup,
            outputSourceAddress,
            targetAddress,
            encoded,
            diagnostics);
    }

    private static SemanticFixupResolution ResolveAbsolute32(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress targetAddress,
        ulong value,
        DiagnosticBag diagnostics)
    {
        if (value > uint.MaxValue)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupOutOfRange,
                "The ABS32 relocation value exceeds the 32-bit address domain.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        return Success(fixup, outputSourceAddress, targetAddress, null, value, diagnostics);
    }

    private static SemanticFixupResolution ResolvePrel64(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        ulong value,
        DiagnosticBag diagnostics)
    {
        if (!TryGetSignedDelta(value, outputPlaceAddress.Value, out var delta))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupOutOfRange,
                "The PREL64 relocation expression does not fit the signed address domain.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        return Success(fixup, outputSourceAddress, targetAddress, null, unchecked((ulong)delta), diagnostics);
    }

    private static SemanticFixupResolution ResolvePrel32(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputPlaceAddress,
        VirtualAddress targetAddress,
        ulong value,
        DiagnosticBag diagnostics)
    {
        if (!TryGetSignedDelta(value, outputPlaceAddress.Value, out var delta)
            || delta < int.MinValue
            || delta > int.MaxValue)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupOutOfRange,
                "The PREL32 relocation expression does not fit the signed 32-bit address domain.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        return Success(fixup, outputSourceAddress, targetAddress, null, unchecked((uint)delta), diagnostics);
    }

    private static SemanticFixupResolution ResolveAddLo12(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress targetAddress,
        ulong value,
        DiagnosticBag diagnostics)
    {
        if ((fixup.OriginalEncoding & (1u << 22)) != 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The ADD low-12 relocation requires an unshifted immediate field.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        var encoding = (fixup.OriginalEncoding & ~AddImmediateMask)
            | ((uint)(value & 0xFFF) << 10);
        return Success(fixup, outputSourceAddress, targetAddress, encoding, value, diagnostics);
    }

    private static SemanticFixupResolution ResolveLoadStoreLo12(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress targetAddress,
        ulong value,
        DiagnosticBag diagnostics)
    {
        var scaleBits = (int)((fixup.OriginalEncoding >> 30) & 0x3);
        var encodedScale = 1UL << scaleBits;
        var expectedScale = fixup.Relocation?.RelocationType switch
        {
            ElfConstants.RArm64Ldst8AbsLo12Nc => 1UL,
            ElfConstants.RArm64Ldst16AbsLo12Nc => 2UL,
            ElfConstants.RArm64Ldst32AbsLo12Nc => 4UL,
            ElfConstants.RArm64Ldst64AbsLo12Nc => 8UL,
            ElfConstants.RArm64Ldst128AbsLo12Nc => 16UL,
            _ => (ulong?)null,
        };
        var scale = expectedScale ?? encodedScale;
        if (expectedScale is { } requiredScale
            && requiredScale != 16
            && encodedScale != requiredScale)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The load/store relocation width does not match the instruction access width.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        var low12 = value & 0xFFF;
        if (low12 % scale != 0 || low12 / scale > 0xFFF)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupOutOfRange,
                "The load/store low-12 relocation is not aligned for the instruction access width.",
                fixup.SourceFileOffset.Value);
            return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        var encoding = (fixup.OriginalEncoding & ~AddImmediateMask)
            | ((uint)(low12 / scale) << 10);
        return Success(fixup, outputSourceAddress, targetAddress, encoding, value, diagnostics);
    }

    private static SemanticFixupResolution FinishInstructionEncoding(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress targetAddress,
        uint? encoded,
        DiagnosticBag diagnostics)
    {
        if (encoded is { } value)
        {
            return Success(fixup, outputSourceAddress, targetAddress, value, null, diagnostics);
        }

        if (HasRelaxationOption(fixup) && CanRelax(diagnostics))
        {
            diagnostics.Warning(
                DiagnosticCode.SemanticFixupDeferred,
                "The direct relocation encoding is out of range; layout-time relaxation is required.",
                fixup.SourceFileOffset.Value);
            return Deferred(fixup, outputSourceAddress, diagnostics, targetAddress);
        }

        return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
    }

    private static uint? EncodeBranch26(
        uint originalEncoding,
        VirtualAddress place,
        ulong target,
        DiagnosticBag diagnostics,
        ulong? diagnosticOffset = null)
    {
        if (place.Value % InstructionAlignment != 0 || target % InstructionAlignment != 0)
        {
            AddAlignmentDiagnostic(
                diagnostics,
                "The Branch26 place and target must be aligned to an AArch64 instruction.",
                diagnosticOffset);
            return null;
        }

        if (!TryGetScaledImmediate(target, place.Value, InstructionAlignment, 26, out var immediate))
        {
            AddOutOfRangeDiagnostic(
                diagnostics,
                "The Branch26 target is outside the signed 26-bit range.",
                diagnosticOffset);
            return null;
        }

        return (originalEncoding & ~Branch26ImmediateMask)
            | (unchecked((uint)immediate) & Branch26ImmediateMask);
    }

    private static uint? EncodeBranch19(
        uint originalEncoding,
        VirtualAddress place,
        ulong target,
        DiagnosticBag diagnostics,
        ulong? diagnosticOffset = null)
    {
        if (place.Value % InstructionAlignment != 0 || target % InstructionAlignment != 0)
        {
            AddAlignmentDiagnostic(
                diagnostics,
                "The conditional branch place and target must be aligned to an AArch64 instruction.",
                diagnosticOffset);
            return null;
        }

        if (!TryGetScaledImmediate(target, place.Value, InstructionAlignment, 19, out var immediate))
        {
            AddOutOfRangeDiagnostic(
                diagnostics,
                "The conditional branch target is outside the signed 19-bit range.",
                diagnosticOffset);
            return null;
        }

        return (originalEncoding & ~Branch19ImmediateMask)
            | ((unchecked((uint)immediate) & 0x7FFFF) << 5);
    }

    private static uint? EncodeBranch14(
        uint originalEncoding,
        VirtualAddress place,
        ulong target,
        DiagnosticBag diagnostics,
        ulong? diagnosticOffset = null)
    {
        if (place.Value % InstructionAlignment != 0 || target % InstructionAlignment != 0)
        {
            AddAlignmentDiagnostic(
                diagnostics,
                "The test branch place and target must be aligned to an AArch64 instruction.",
                diagnosticOffset);
            return null;
        }

        if (!TryGetScaledImmediate(target, place.Value, InstructionAlignment, 14, out var immediate))
        {
            AddOutOfRangeDiagnostic(
                diagnostics,
                "The test branch target is outside the signed 14-bit range.",
                diagnosticOffset);
            return null;
        }

        return (originalEncoding & ~Branch14ImmediateMask)
            | ((unchecked((uint)immediate) & 0x3FFF) << 5);
    }

    private static uint? EncodeAdr(
        uint originalEncoding,
        VirtualAddress place,
        ulong target,
        DiagnosticBag diagnostics,
        ulong? diagnosticOffset = null)
    {
        if (place.Value % InstructionAlignment != 0)
        {
            AddAlignmentDiagnostic(
                diagnostics,
                "The ADR place must be aligned to an AArch64 instruction.",
                diagnosticOffset);
            return null;
        }

        if (!TryGetSignedDelta(target, place.Value, out var delta)
            || delta < -(1L << 20)
            || delta > (1L << 20) - 1)
        {
            AddOutOfRangeDiagnostic(
                diagnostics,
                "The ADR target is outside the signed 21-bit byte range.",
                diagnosticOffset);
            return null;
        }

        var bits = unchecked((ulong)delta);
        var immLo = (uint)(bits & 0x3) << 29;
        var immHi = (uint)((bits >> 2) & 0x7FFFF) << 5;
        return (originalEncoding & ~AdrImmediateMask) | immLo | immHi;
    }

    private static uint? EncodeAdrp(
        uint originalEncoding,
        VirtualAddress place,
        ulong target,
        DiagnosticBag diagnostics,
        ulong? diagnosticOffset = null)
    {
        if (place.Value % InstructionAlignment != 0)
        {
            AddAlignmentDiagnostic(
                diagnostics,
                "The ADRP place must be aligned to an AArch64 instruction.",
                diagnosticOffset);
            return null;
        }

        var targetPage = target & ~0xFFFUL;
        var placePage = place.Value & ~0xFFFUL;
        if (!TryGetScaledImmediate(targetPage, placePage, 0x1000, 21, out var immediate))
        {
            AddOutOfRangeDiagnostic(
                diagnostics,
                "The ADRP target is outside the signed 21-bit page range.",
                diagnosticOffset);
            return null;
        }

        var bits = unchecked((ulong)immediate);
        var immLo = (uint)(bits & 0x3) << 29;
        var immHi = (uint)((bits >> 2) & 0x7FFFF) << 5;
        return (originalEncoding & ~AdrImmediateMask) | immLo | immHi;
    }

    private static uint? EncodeLiteral19(
        uint originalEncoding,
        VirtualAddress place,
        ulong target,
        DiagnosticBag diagnostics,
        ulong? diagnosticOffset = null)
    {
        if (place.Value % InstructionAlignment != 0 || target % InstructionAlignment != 0)
        {
            AddAlignmentDiagnostic(
                diagnostics,
                "The literal place and target must be aligned to an AArch64 instruction.",
                diagnosticOffset);
            return null;
        }

        if (!TryGetScaledImmediate(target, place.Value, InstructionAlignment, 19, out var immediate))
        {
            AddOutOfRangeDiagnostic(
                diagnostics,
                "The literal target is outside the signed 19-bit range.",
                diagnosticOffset);
            return null;
        }

        return (originalEncoding & ~Branch19ImmediateMask)
            | ((unchecked((uint)immediate) & 0x7FFFF) << 5);
    }

    private static uint? UnsupportedEncoding(SemanticFixup fixup, DiagnosticBag diagnostics)
    {
        diagnostics.Error(
            DiagnosticCode.SemanticFixupUnsupported,
            $"The PC-relative expression kind '{fixup.Expression?.Kind}' is not supported by the AArch64 semantic encoder.",
            fixup.SourceFileOffset.Value);
        return null;
    }

    private static SemanticFixupResolution UnsupportedRelocation(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress targetAddress,
        DiagnosticBag diagnostics)
    {
        diagnostics.Error(
            DiagnosticCode.SemanticFixupUnsupported,
            $"The AArch64 relocation kind '{fixup.Relocation?.Kind}' is not owned by this semantic encoder.",
            fixup.SourceFileOffset.Value);
        return Failure(fixup, outputSourceAddress, diagnostics, targetAddress);
    }

    private static bool TryResolveSource(
        SemanticFixup fixup,
        AddressMap addressMap,
        DiagnosticBag diagnostics,
        out VirtualAddress outputSourceAddress,
        out VirtualAddress outputPlaceAddress)
    {
        outputSourceAddress = default;
        outputPlaceAddress = default;
        if (fixup.SourceRange.Size == 0
            || !fixup.SourceRange.TryGetFileEnd(out _)
            || !fixup.SourceRange.TryGetVirtualEnd(out _)
            || fixup.SourceRange.VirtualAddress != fixup.SourceAddress
            || fixup.SourceRange.FileOffset != fixup.SourceFileOffset)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The semantic fixup source range is empty, overflowing, or mismatched.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        if (fixup.Relocation is { } sourceRelocation)
        {
            var sourceWriteSize = SemanticFixup.GetRelocationWriteSize(sourceRelocation.Kind);
            if (sourceWriteSize == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupUnsupported,
                    $"The {sourceRelocation.Kind} relocation has no defined write width.",
                    fixup.SourceFileOffset.Value);
                return false;
            }

            if (fixup.SourceRange.Size != sourceWriteSize
                || fixup.SourceRange.FileOffset.Value % sourceWriteSize != 0
                || fixup.SourceRange.VirtualAddress.Value % sourceWriteSize != 0)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "The semantic relocation source range has an invalid size or alignment.",
                    fixup.SourceFileOffset.Value);
                return false;
            }
        }
        else if (!fixup.SourceRange.IsInstructionRange)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "An instruction fixup must address one aligned AArch64 instruction.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        var preferredSourceKind = fixup.Kind == SemanticFixupKind.Relocation
            ? SemanticEntityKind.RelocationSite
            : SemanticEntityKind.Instruction;
        if (!addressMap.TryMapSourceRange(
                fixup.SourceRange,
                preferredSourceKind,
                out var outputRange))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "The semantic fixup source range has no unique planned output mapping.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        var requiredAlignment = fixup.Relocation is { } relocation
            ? SemanticFixup.GetRelocationWriteSize(relocation.Kind)
            : (ulong)InstructionAlignment;
        if (requiredAlignment == 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupUnsupported,
                "The semantic relocation has no defined write width.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        if (outputRange.FileOffset.Value % requiredAlignment != 0
            || outputRange.VirtualAddress.Value % requiredAlignment != 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The planned output fixup range is not aligned for its write width.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        outputSourceAddress = outputRange.VirtualAddress;
        outputPlaceAddress = outputSourceAddress;
        if (fixup.Expression is not { } expression
            || expression.Place == fixup.SourceAddress)
        {
            return true;
        }

        if (!addressMap.TryMapSourceAddress(expression.Place, out outputPlaceAddress))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "The PC-relative expression place has no planned output mapping.",
                fixup.SourceFileOffset.Value);
            return false;
        }

        return true;
    }

    private static bool TryResolveTarget(
        SemanticFixup fixup,
        SemanticTarget target,
        AddressMap addressMap,
        ulong diagnosticOffset,
        DiagnosticBag diagnostics,
        out SemanticTargetResolution resolution,
        out VirtualAddress? outputTargetAddress)
    {
        resolution = target.Resolution;
        outputTargetAddress = null;
        switch (target.Resolution)
        {
            case SemanticTargetResolution.Exact:
                return TryResolveExactTarget(
                    target,
                    addressMap,
                    GetPreferredTargetKind(fixup),
                    diagnosticOffset,
                    diagnostics,
                    out outputTargetAddress);
            case SemanticTargetResolution.BoundedSet:
                return TryResolveBoundedTarget(
                    target,
                    addressMap,
                    GetPreferredTargetKind(fixup),
                    diagnosticOffset,
                    diagnostics,
                    out outputTargetAddress);
            case SemanticTargetResolution.RuntimeResolved:
                if (string.IsNullOrWhiteSpace(target.RuntimeBinding))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticTargetUnresolved,
                        "A runtime-resolved target is missing its binding identity.",
                        diagnosticOffset);
                    return false;
                }

                return true;
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

    private static bool TryResolveExactTarget(
        SemanticTarget target,
        AddressMap addressMap,
        SemanticEntityKind? preferredKind,
        ulong diagnosticOffset,
        DiagnosticBag diagnostics,
        out VirtualAddress? outputTargetAddress)
    {
        outputTargetAddress = null;
        var hasIdentity = target.Identity is { };
        var hasAddress = target.SourceAddress is { };
        var identity = target.Identity.GetValueOrDefault();
        var sourceAddress = target.SourceAddress.GetValueOrDefault();
        var identityAddress = default(VirtualAddress);
        var addressAddress = default(VirtualAddress);
        var mappedByIdentity = hasIdentity && addressMap.TryMapEntity(identity, out identityAddress);
        var addressKind = hasIdentity ? identity.Kind : preferredKind;
        var mappedByAddress = hasAddress
            && TryMapTargetAddress(addressMap, sourceAddress, addressKind, out addressAddress);

        if (hasIdentity && !mappedByIdentity)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "The exact semantic target identity has no planned output mapping.",
                diagnosticOffset);
            return false;
        }

        if (hasAddress && !mappedByAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                "The exact semantic target address has no unique planned output mapping.",
                diagnosticOffset);
            return false;
        }

        if (!mappedByIdentity && !mappedByAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticTargetUnresolved,
                "An exact semantic target has no mapped identity or address.",
                diagnosticOffset);
            return false;
        }

        if (mappedByIdentity && mappedByAddress && identityAddress != addressAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "The exact semantic target identity and address map to different output addresses.",
                diagnosticOffset);
            return false;
        }

        outputTargetAddress = mappedByIdentity ? identityAddress : addressAddress;
        return true;
    }

    private static bool TryResolveBoundedTarget(
        SemanticTarget target,
        AddressMap addressMap,
        SemanticEntityKind? preferredKind,
        ulong diagnosticOffset,
        DiagnosticBag diagnostics,
        out VirtualAddress? outputTargetAddress)
    {
        outputTargetAddress = null;
        var mappedAddresses = new HashSet<VirtualAddress>();
        foreach (var candidate in target.CandidateAddresses)
        {
            if (!TryMapTargetAddress(addressMap, candidate, preferredKind, out var mapped))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A bounded semantic target address has no unique planned output mapping.",
                    diagnosticOffset);
                return false;
            }

            mappedAddresses.Add(mapped);
        }

        foreach (var identity in target.CandidateIdentities)
        {
            if (!addressMap.TryMapEntity(identity, out var mapped))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A bounded semantic target identity has no planned output mapping.",
                    diagnosticOffset);
                return false;
            }

            mappedAddresses.Add(mapped);
        }

        if (mappedAddresses.Count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticTargetUnresolved,
                "A bounded semantic target set is empty.",
                diagnosticOffset);
            return false;
        }

        if (mappedAddresses.Count == 1)
        {
            outputTargetAddress = mappedAddresses.Single();
        }

        return true;
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

    private static SemanticFixupResolution Success(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        VirtualAddress outputTargetAddress,
        uint? encoding,
        ulong? relocationValue,
        DiagnosticBag diagnostics) =>
        new(
            fixup,
            true,
            false,
            outputSourceAddress,
            outputTargetAddress,
            encoding,
            relocationValue,
            diagnostics.ToArray());

    private static SemanticFixupResolution Deferred(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        DiagnosticBag diagnostics,
        VirtualAddress? outputTargetAddress = null) =>
        new(
            fixup,
            true,
            true,
            outputSourceAddress,
            outputTargetAddress,
            null,
            null,
            diagnostics.ToArray());

    private static SemanticFixupResolution Failure(
        SemanticFixup fixup,
        VirtualAddress outputSourceAddress,
        DiagnosticBag diagnostics,
        VirtualAddress? outputTargetAddress = null) =>
        new(
            fixup,
            false,
            false,
            outputSourceAddress,
            outputTargetAddress,
            null,
            null,
            diagnostics.ToArray());

    private static bool HasRelaxationOption(SemanticFixup fixup) =>
        fixup.Relaxation != SemanticRelaxationKind.None
        || fixup.RelaxationOptions.Any(option => option != SemanticRelaxationKind.None);

    private static bool CanRelax(DiagnosticBag diagnostics) =>
        !diagnostics.Any(diagnostic =>
            diagnostic.IsError && diagnostic.Code != DiagnosticCode.SemanticFixupOutOfRange);

    private static void AddAlignmentDiagnostic(
        DiagnosticBag diagnostics,
        string message,
        ulong? diagnosticOffset = null) =>
        diagnostics.Error(DiagnosticCode.SemanticFixupMalformed, message, diagnosticOffset);

    private static void AddOutOfRangeDiagnostic(
        DiagnosticBag diagnostics,
        string message,
        ulong? diagnosticOffset = null) =>
        diagnostics.Error(DiagnosticCode.SemanticFixupOutOfRange, message, diagnosticOffset);

    private static ulong? AddSigned(
        ulong value,
        long addend,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (addend >= 0)
        {
            var unsignedAddend = (ulong)addend;
            if (value > ulong.MaxValue - unsignedAddend)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupOutOfRange,
                    "The semantic relocation addend overflowed the address domain.",
                    offset);
                return null;
            }

            return checked(value + unsignedAddend);
        }

        var magnitude = addend == long.MinValue
            ? (ulong)long.MaxValue + 1
            : (ulong)(-addend);
        if (value < magnitude)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupOutOfRange,
                "The semantic relocation addend underflowed the address domain.",
                offset);
            return null;
        }

        return value - magnitude;
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

    private static bool TryGetScaledImmediate(
        ulong target,
        ulong place,
        int scale,
        int width,
        out long immediate)
    {
        immediate = default;
        if (!TryGetSignedDelta(target, place, out var delta)
            || scale <= 0
            || delta % scale != 0)
        {
            return false;
        }

        var scaled = delta / scale;
        var minimum = -(1L << (width - 1));
        var maximum = (1L << (width - 1)) - 1;
        if (scaled < minimum || scaled > maximum)
        {
            return false;
        }

        immediate = scaled;
        return true;
    }
}
