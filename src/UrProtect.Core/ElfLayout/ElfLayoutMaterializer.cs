using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.SemanticPlanning;

namespace UrProtect.Core.ElfLayout;

public static class ElfLayoutMaterializer
{
    private static readonly int[] TlsDescPairOrdinals = { 0, 1, 2, 3 };
    private static readonly uint?[] TlsDescRelocationTypes =
    {
        ElfConstants.RArm64TlsDescAdrPage21,
        ElfConstants.RArm64TlsDescLd64Lo12,
        ElfConstants.RArm64TlsDescAddLo12,
        ElfConstants.RArm64TlsDescCall,
    };

    public static ElfLayoutResult Materialize(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        ElfLayoutPlan plan)
    {
        ArgumentNullException.ThrowIfNull(sourceFile);
        ArgumentNullException.ThrowIfNull(plan);

        var diagnostics = new DiagnosticBag();
        var sourceSha256 = Sha256(sourceBytes.Span);
        if (!string.Equals(sourceSha256, plan.SourceSha256, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutSourceMismatch, "The layout plan source digest does not match the materialization snapshot.");
            return Failure(plan, diagnostics);
        }

        if (sourceFile.Bytes.Length != sourceBytes.Length
            || !sourceFile.Bytes.Span.SequenceEqual(sourceBytes.Span)
            || plan.OutputLength > int.MaxValue
            || plan.OutputLength < (ulong)sourceBytes.Length)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The layout source or output length is outside the materializer bounds.");
            return Failure(plan, diagnostics);
        }

        if (!Enum.IsDefined(plan.Strategy)
            || plan.ProgramHeaders is null
            || plan.Placements is null
            || plan.AddressMap is null
            || plan.BranchDecisions is null
            || plan.Edits is null
            || plan.TlsFixups is null
            || plan.UnwindEdits is null
            || plan.JumpTableEdits is null
            || plan.JumpTableTargetBindings is null
            || plan.JumpTableClones is null)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The layout plan collections or strategy are malformed.");
            return Failure(plan, diagnostics);
        }

        if (!ValidatePlanEdits(plan, (ulong)sourceBytes.Length, diagnostics))
        {
            return Failure(plan, diagnostics);
        }

        try
        {
            var output = new byte[checked((int)plan.OutputLength)];
            sourceBytes.Span.CopyTo(output);
            foreach (var edit in plan.Edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind))
            {
                edit.Bytes.AsSpan().CopyTo(output.AsSpan(checked((int)edit.Offset.Value), edit.Bytes.Length));
            }

            var parsed = ElfParser.Parse(output);
            diagnostics.AddRange(parsed.Diagnostics);
            if (parsed.File is null || parsed.Diagnostics.Any(diagnostic => diagnostic.IsError))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "Materialized ELF did not pass the bounded parser after layout edits.");
                return Failure(plan, diagnostics);
            }

            var validation = ElfValidator.Validate(parsed.File);
            if (!validation.IsValid)
            {
                diagnostics.AddRange(validation.Diagnostics);
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "Materialized ELF did not pass the bounded validator after layout edits.");
                return Failure(plan, diagnostics);
            }

            if (!ValidateParsedOutput(sourceFile, parsed.File, plan, output, diagnostics)
                || !ValidateJumpTableTargetBindings(sourceFile, parsed.File, plan, output, diagnostics)
                || !ValidateTlsPreserved(sourceFile, parsed.File, diagnostics)
                || !ValidateTlsFixupOutput(sourceFile, parsed.File, plan, output, diagnostics))
            {
                return Failure(plan, diagnostics);
            }

            var outputHash = Sha256(output);
            var evidence = new ElfLayoutEvidence(
                ElfLayoutEvidence.CurrentSchemaVersion,
                plan.Strategy,
                plan.SourceSha256,
                outputHash,
                plan.OutputLength,
                plan.OldProgramHeaderTable,
                plan.NewProgramHeaderTable,
                plan.PreservedMetadataSha256,
                plan.Placements,
                plan.AddressMap,
                plan.BranchDecisions)
            {
                TlsFixups = plan.TlsFixups,
                UnwindEdits = plan.UnwindEdits,
                JumpTableEdits = plan.JumpTableEdits,
                JumpTableTargetBindings = plan.JumpTableTargetBindings,
                JumpTableClones = plan.JumpTableClones,
            };
            return new ElfLayoutResult(plan, output, parsed.File, evidence, diagnostics.ToArray());
        }
        catch (OverflowException)
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "ELF layout materialization arithmetic overflowed.");
            return Failure(plan, diagnostics);
        }
    }

    public static ElfLayoutResult Materialize(
        ElfFile sourceFile,
        ElfLayoutPlan plan) =>
        Materialize(sourceFile.Bytes, sourceFile, plan);

    public static ElfLayoutResult Materialize(
        ElfLayoutPlan plan,
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile) =>
        Materialize(sourceBytes, sourceFile, plan);

    private static ElfLayoutResult Failure(ElfLayoutPlan plan, DiagnosticBag diagnostics) =>
        new(plan, null, null, null, diagnostics.ToArray());

    private static bool ValidateTlsPreserved(
        ElfFile sourceFile,
        ElfFile outputFile,
        DiagnosticBag diagnostics)
    {
        var sourceSegments = sourceFile.TlsMetadata.Segments;
        var outputSegments = outputFile.TlsMetadata.Segments;
        if (sourceSegments.Count != outputSegments.Count)
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "Materialization changed the PT_TLS segment count.");
            return false;
        }

        for (var index = 0; index < sourceSegments.Count; index++)
        {
            var source = sourceSegments[index];
            var output = outputSegments[index];
            if (source.ProgramHeaderIndex != output.ProgramHeaderIndex
                || source.OwningLoadProgramHeaderIndex != output.OwningLoadProgramHeaderIndex
                || source.TemplateFileOffset != output.TemplateFileOffset
                || source.TemplateAddress != output.TemplateAddress
                || source.FileSize != output.FileSize
                || source.MemorySize != output.MemorySize
                || source.Alignment != output.Alignment
                || source.Permissions != output.Permissions
                || !source.InitializedTemplate.Span.SequenceEqual(output.InitializedTemplate.Span))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "Materialization moved or changed the PT_TLS template, zero-fill, alignment, permissions, or owning load.",
                    source.TemplateFileOffset.Value);
                return false;
            }
        }

        var sourceDynamic = sourceFile.TlsMetadata.Dynamic;
        var outputDynamic = outputFile.TlsMetadata.Dynamic;
        if (!sourceDynamic.RelocationTables.SequenceEqual(outputDynamic.RelocationTables)
            || !sourceDynamic.Relocations.SequenceEqual(outputDynamic.Relocations)
            || !sourceFile.TlsMetadata.StaticRelocationSections.SequenceEqual(outputFile.TlsMetadata.StaticRelocationSections)
            || !sourceFile.TlsMetadata.StaticRelocations.SequenceEqual(outputFile.TlsMetadata.StaticRelocations)
            || sourceDynamic.TlsDescriptorPlt != outputDynamic.TlsDescriptorPlt
            || sourceDynamic.TlsDescriptorGot != outputDynamic.TlsDescriptorGot
            || !string.Equals(sourceDynamic.Soname, outputDynamic.Soname, StringComparison.Ordinal))
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "Materialization changed TLS dynamic relocation ownership, symbol/module facts, TLSDESC metadata, or SONAME.");
            return false;
        }

        return true;
    }

    private static bool ValidateTlsFixupOutput(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        foreach (var decision in plan.TlsFixups)
        {
            if (decision is null || decision.Fixup is null || decision.Fixup.Relocation is null)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The layout plan contains a null TLS output fixup.");
                return false;
            }

            var fixup = decision.Fixup;
            var relocation = fixup.Relocation;
            var relocationType = relocation.RelocationType;
            if (fixup.AccessModel is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec or TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic or TlsAccessModel.TlsDesc)
                || (fixup.AccessModel == TlsAccessModel.LocalExec
                    && (fixup.RelocationFamily != TlsRelocationFamily.Tprel
                        || fixup.AddressExpression.Kind != TlsAddressExpressionKind.ThreadPointerRelative
                        || relocationType is not (ElfConstants.RArm64TlsLeAddTprelHi12
                            or ElfConstants.RArm64TlsLeAddTprelLo12
                            or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                            or ElfConstants.RArm64TlsLeMovwTprelG1
                            or ElfConstants.RArm64TlsLeMovwTprelG0Nc
                            or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)))
                || (fixup.AccessModel == TlsAccessModel.InitialExec
                    && (fixup.RelocationFamily != TlsRelocationFamily.GotTprel
                        || fixup.AddressExpression.Kind != TlsAddressExpressionKind.ThreadPointerRelative
                        || fixup.GotEntry is null
                        || relocationType is not (ElfConstants.RArm64TlsIeMovwGottprelG1
                            or ElfConstants.RArm64TlsIeMovwGottprelG0Nc
                            or ElfConstants.RArm64TlsIeAdrGottprelPage21
                            or ElfConstants.RArm64TlsIeLd64GottprelLo12Nc
                            or ElfConstants.RArm64TlsIeLdGottprelPrel19)))
                || (fixup.AccessModel == TlsAccessModel.TlsDesc
                    && (fixup.RelocationFamily != TlsRelocationFamily.TlsDesc
                        || fixup.AddressExpression.Kind != TlsAddressExpressionKind.DescriptorMediated
                        || fixup.DescriptorOwner is null
                        || relocationType is not (ElfConstants.RArm64TlsDescAdrPage21
                            or ElfConstants.RArm64TlsDescLd64Lo12
                            or ElfConstants.RArm64TlsDescAddLo12
                            or ElfConstants.RArm64TlsDescCall)))
                || (fixup.AccessModel is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
                    && (fixup.ResolverCall is null
                        || fixup.ModuleOwner is null
                        || (fixup.AccessModel == TlsAccessModel.GeneralDynamic && fixup.DtpRelOwner is null)
                        || (relocation.Kind == Aarch64RelocationKind.Call26
                            ? fixup.PairOrdinal != -1
                            : fixup.AccessModel == TlsAccessModel.LocalDynamic
                                ? relocationType is not (ElfConstants.RArm64TlsLdAdrPage21
                                    or ElfConstants.RArm64TlsLdAddLo12Nc
                                    or ElfConstants.RArm64TlsLdAddDtprelHi12
                                    or ElfConstants.RArm64TlsLdAddDtprelLo12
                                    or ElfConstants.RArm64TlsLdAddDtprelLo12Nc)
                                : relocationType is not (ElfConstants.RArm64TlsGdAdrPage21
                                    or ElfConstants.RArm64TlsGdAddLo12Nc)))))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "Materialization received a TLS output fixup outside the supported managed TLS slices.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var regionPlacements = plan.Placements.Where(placement => string.Equals(
                placement.Identity,
                decision.RegionIdentity,
                StringComparison.Ordinal)).ToArray();
            if (fixup.RelocationOutputRange.FileOffset.Value < fixup.SequenceOutputRange.FileOffset.Value
                || fixup.RelocationOutputRange.VirtualAddress.Value < fixup.SequenceOutputRange.VirtualAddress.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The semantic local-exec TLS relocation output range precedes its sequence mapping.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var logicalFileDelta = fixup.RelocationOutputRange.FileOffset.Value
                - fixup.SequenceOutputRange.FileOffset.Value;
            var logicalVirtualDelta = fixup.RelocationOutputRange.VirtualAddress.Value
                - fixup.SequenceOutputRange.VirtualAddress.Value;
            var regionAddressMap = plan.AddressMap.SingleOrDefault(entry =>
                string.Equals(entry.Identity, decision.RegionIdentity, StringComparison.Ordinal));
            var sequenceRegionOffset = regionAddressMap?.SourceRange is { } sourceRegionRange
                && fixup.SequenceOutputRange.VirtualAddress.Value >= sourceRegionRange.VirtualAddress.Value
                ? fixup.SequenceOutputRange.VirtualAddress.Value - sourceRegionRange.VirtualAddress.Value
                : ulong.MaxValue;
            var expectedPhysicalOffset = sequenceRegionOffset != ulong.MaxValue
                && logicalVirtualDelta <= ulong.MaxValue - sequenceRegionOffset
                ? sequenceRegionOffset + logicalVirtualDelta
                : ulong.MaxValue;
            if (regionPlacements.Length != 1
                || logicalFileDelta != logicalVirtualDelta
                || expectedPhysicalOffset == ulong.MaxValue
                || decision.OutputFileOffset.Value < regionPlacements[0].FileOffset.Value
                || decision.OutputVirtualAddress.Value < regionPlacements[0].VirtualAddress.Value
                || decision.OutputFileOffset.Value - regionPlacements[0].FileOffset.Value != expectedPhysicalOffset
                || decision.OutputVirtualAddress.Value - regionPlacements[0].VirtualAddress.Value != expectedPhysicalOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The physical local-exec TLS output site does not match its semantic source-to-output address map.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var sourceMatchCount = relocation.Kind == Aarch64RelocationKind.Call26
                ? sourceFile.RelaRelocations.Count(candidate =>
                    candidate.IsPlt
                    && candidate.Type == ElfConstants.RArm64JumpSlot
                    && candidate.SourceAddress == relocation.RelocationTableAddress?.Value
                    && candidate.SymbolIndex == relocation.SymbolIndex
                    && candidate.Addend == relocation.Addend
                    && string.Equals(
                        TryGetDynamicSymbolName(sourceFile, candidate.SymbolIndex),
                        relocation.SymbolName,
                        StringComparison.Ordinal))
                : sourceFile.TlsMetadata.StaticRelocations
                    .Concat(sourceFile.TlsMetadata.Dynamic.Relocations)
                    .Count(fact => fact.Relocation.Offset == fixup.RelocationSourceRange.VirtualAddress.Value
                        && fact.Relocation.Type == relocationType
                        && fact.Relocation.Info == relocation.RawInfo
                        && fact.Relocation.SymbolIndex == relocation.SymbolIndex
                        && fact.Relocation.Addend == relocation.Addend
                        && fact.Relocation.SourceAddress == relocation.RelocationTableAddress?.Value
                        && fact.WriteSize == fixup.RelocationSourceRange.Size
                        && fact.Symbol?.Name == relocation.SymbolName);
            if (sourceMatchCount != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The materialized TLS fixup does not match exactly one source relocation identity.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            if (fixup.AccessModel == TlsAccessModel.InitialExec
                && (fixup.GotEntry is null
                    || !ValidateInitialExecGotEntryPreserved(sourceFile, outputFile, output, fixup.GotEntry, diagnostics)))
            {
                return false;
            }
            if (fixup.AccessModel is TlsAccessModel.GeneralDynamic
                && (fixup.ModuleOwner is null
                    || fixup.DtpRelOwner is null
                    || !ValidateDynamicOwnerPairPreserved(sourceFile, outputFile, output, fixup.ModuleOwner, fixup.DtpRelOwner, diagnostics)))
            {
                return false;
            }
            if (fixup.AccessModel == TlsAccessModel.TlsDesc
                && (fixup.DescriptorOwner is null
                    || !ValidateTlsDescriptorOwnerPreserved(
                        sourceFile,
                        outputFile,
                        output,
                        fixup.DescriptorOwner,
                        diagnostics)))
            {
                return false;
            }

            if (!outputFile.LoadMap.TryVirtualAddressToFileOffset(
                    decision.OutputVirtualAddress,
                    sizeof(uint),
                    out var outputFileOffset)
                || outputFileOffset != decision.OutputFileOffset
                || !outputFile.LoadMap.Segments.Any(segment =>
                    segment.IsExecutable
                    && segment.ContainsVirtualAddress(decision.OutputVirtualAddress.Value, sizeof(uint))
                    && segment.ContainsFileOffset(decision.OutputFileOffset.Value, sizeof(uint)))
                || decision.OutputFileOffset.Value > int.MaxValue
                || decision.OutputFileOffset.Value > (ulong)output.Length
                || sizeof(uint) > (ulong)output.Length - decision.OutputFileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec TLS output fixup is not uniquely mapped by an executable output PT_LOAD.",
                    decision.OutputVirtualAddress.Value);
                return false;
            }

            var outputEncoding = BinaryPrimitives.ReadUInt32LittleEndian(
                output.AsSpan(checked((int)decision.OutputFileOffset.Value), sizeof(uint)));
            if (outputEncoding != decision.OutputEncoding)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed output instruction does not contain its planned local-exec TLS relocation fixup.",
                    decision.OutputFileOffset.Value);
                return false;
            }
        }

        return ValidateLocalExecAddFixupPairs(sourceFile, plan, output, diagnostics)
            && ValidateLocalExecLdst32FixupPairs(sourceFile, outputFile, plan, output, diagnostics)
            && ValidateLocalExecMovwFixupPairs(sourceFile, outputFile, plan, output, diagnostics)
            && ValidateInitialExecMovwFixupPairs(sourceFile, plan, output, diagnostics)
            && ValidateInitialExecLdGotPrel19FixupSites(sourceFile, outputFile, plan, output, diagnostics)
            && ValidateInitialExecAdrLd64FixupPairs(sourceFile, outputFile, plan, output, diagnostics)
            && ValidateTlsDescFixupSequences(sourceFile, plan, output, diagnostics);
    }

    private static bool ValidateLocalExecAddFixupPairs(
        ElfFile sourceFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var groups = plan.TlsFixups
            .Where(decision => decision?.Fixup?.Relocation?.RelocationType is
                ElfConstants.RArm64TlsLeAddTprelHi12
                or ElfConstants.RArm64TlsLeAddTprelLo12
                or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
            .GroupBy(decision => (decision.RegionIdentity, decision.Fixup.SequenceSourceRange));

        foreach (var group in groups)
        {
            if (group.Any(decision => decision.Fixup.Relocation.RelocationType
                    == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
                && group.All(decision => decision.Fixup.Relocation.RelocationType is
                    ElfConstants.RArm64TlsLeAddTprelHi12
                    or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc))
            {
                continue;
            }

            var ordered = group.OrderBy(decision => decision.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 2
                && ordered[0].Fixup.PairOrdinal == 0
                && ordered[1].Fixup.PairOrdinal == 1
                && ordered[0].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsLeAddTprelHi12
                && ordered[1].Fixup.Relocation.RelocationType is
                    ElfConstants.RArm64TlsLeAddTprelLo12 or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                && ordered[0].Fixup.Relocation.Addend == ordered[1].Fixup.Relocation.Addend
                && ordered[0].Fixup.Relocation.SymbolIndex == ordered[1].Fixup.Relocation.SymbolIndex
                && string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                && ordered[0].Fixup.SequenceOutputRange == ordered[1].Fixup.SequenceOutputRange
                && ordered[0].OutputFileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputFileOffset.Value
                    == ordered[0].OutputFileOffset.Value + sizeof(uint)
                && ordered[0].OutputVirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputVirtualAddress.Value
                    == ordered[0].OutputVirtualAddress.Value + sizeof(uint)
                && ordered[0].Fixup.RelocationSourceRange.FileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.FileOffset.Value
                    == ordered[0].Fixup.RelocationSourceRange.FileOffset.Value + sizeof(uint)
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    == ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint);

            if (valid)
            {
                var first = ordered[0];
                var sourceOffset = first.Fixup.RelocationSourceRange.FileOffset.Value;
                var outputOffset = first.OutputFileOffset.Value;
                valid = sourceOffset >= sizeof(uint)
                    && outputOffset >= sizeof(uint)
                    && TryReadWords(
                        sourceFile.Bytes.Span,
                        sourceOffset - sizeof(uint),
                        4 * sizeof(uint),
                        out var sourceWords)
                    && TryReadWords(
                        output,
                        outputOffset - sizeof(uint),
                        4 * sizeof(uint),
                        out var outputWords)
                    && Aarch64TlsInstructionSemantics.IsSupportedLocalExecAddSequence(
                        first.Fixup.Relocation.RelocationType!.Value,
                        sourceWords[1],
                        ordered[1].Fixup.Relocation.RelocationType!.Value,
                        sourceWords[2],
                        sourceWords[0],
                        sourceWords[3])
                    && Aarch64TlsInstructionSemantics.IsSupportedLocalExecAddSequence(
                        first.Fixup.Relocation.RelocationType!.Value,
                        outputWords[1],
                        ordered[1].Fixup.Relocation.RelocationType!.Value,
                        outputWords[2],
                        outputWords[0],
                        outputWords[3]);
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed local-exec ADD TPREL pair does not retain its TP-relative ADD chain, output order, register ownership, and final TLS access.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }

    private static bool ValidateInitialExecLdGotPrel19FixupSites(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var groups = plan.TlsFixups
            .Where(decision => decision?.Fixup?.Relocation?.RelocationType
                == ElfConstants.RArm64TlsIeLdGottprelPrel19)
            .GroupBy(decision => (decision.RegionIdentity, decision.Fixup.SequenceSourceRange));
        foreach (var group in groups)
        {
            var ordered = group.OrderBy(decision => decision.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 1
                && ordered[0].Fixup.PairOrdinal == 0
                && ordered[0].Fixup.GotEntry is { } gotEntry
                && string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    gotEntry.Symbol.Name,
                    StringComparison.Ordinal)
                && ordered[0].Fixup.Relocation.Addend == gotEntry.Addend
                && ordered[0].Fixup.SequenceSourceRange.Size >= 4 * sizeof(uint)
                && ordered[0].Fixup.SequenceOutputRange.Size >= 4 * sizeof(uint)
                && ordered[0].Fixup.SequenceSourceRange.FileOffset.Value % sizeof(uint) == 0
                && ordered[0].Fixup.SequenceSourceRange.VirtualAddress.Value % sizeof(uint) == 0
                && ordered[0].Fixup.SequenceOutputRange.FileOffset.Value % sizeof(uint) == 0
                && ordered[0].Fixup.SequenceOutputRange.VirtualAddress.Value % sizeof(uint) == 0
                && ordered[0].Fixup.RelocationSourceRange.FileOffset
                    == ordered[0].Fixup.SequenceSourceRange.FileOffset
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress
                    == ordered[0].Fixup.SequenceSourceRange.VirtualAddress
                && ordered[0].OutputFileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[0].OutputVirtualAddress.Value <= ulong.MaxValue - sizeof(uint);
            var placement = valid
                ? plan.Placements.SingleOrDefault(candidate => string.Equals(
                    candidate.Identity,
                    group.Key.RegionIdentity,
                    StringComparison.Ordinal))
                : null;
            if (placement is null)
            {
                valid = false;
            }

            if (valid && placement is not null)
            {
                var first = ordered[0];
                var sourceOffset = first.Fixup.RelocationSourceRange.FileOffset.Value;
                var outputOffset = first.OutputFileOffset.Value;
                valid = sourceOffset <= int.MaxValue
                    && sourceOffset <= (ulong)sourceFile.Bytes.Length
                    && sizeof(uint) <= (ulong)sourceFile.Bytes.Length - sourceOffset
                    && outputOffset <= int.MaxValue
                    && outputOffset <= (ulong)output.Length
                    && sizeof(uint) <= (ulong)output.Length - outputOffset
                    && first.Fixup.SequenceSourceRange.TryGetFileEnd(out _)
                    && first.Fixup.SequenceSourceRange.TryGetVirtualEnd(out _)
                    && first.Fixup.SequenceOutputRange.TryGetFileEnd(out _)
                    && first.Fixup.SequenceOutputRange.TryGetVirtualEnd(out _)
                    && sourceOffset == first.Fixup.SequenceSourceRange.FileOffset.Value
                    && first.OutputVirtualAddress.Value >= placement.VirtualAddress.Value
                    && outputOffset >= placement.FileOffset.Value
                    && outputOffset - placement.FileOffset.Value <= first.Fixup.SequenceOutputRange.Size
                    && sizeof(uint) <= first.Fixup.SequenceOutputRange.Size
                        - (outputOffset - placement.FileOffset.Value)
                    && first.OutputVirtualAddress.Value >= placement.VirtualAddress.Value
                    && first.OutputVirtualAddress.Value - placement.VirtualAddress.Value
                        == outputOffset - placement.FileOffset.Value
                    && first.OutputVirtualAddress.Value - placement.VirtualAddress.Value <= placement.Size
                    && outputOffset - placement.FileOffset.Value <= ulong.MaxValue - (4UL * sizeof(uint))
                    && outputOffset - placement.FileOffset.Value + (4UL * sizeof(uint)) <= placement.Size;
                if (valid)
                {
                    var sourceEncoding = BinaryPrimitives.ReadUInt32LittleEndian(
                        sourceFile.Bytes.Span.Slice(checked((int)sourceOffset), sizeof(uint)));
                    var outputEncoding = BinaryPrimitives.ReadUInt32LittleEndian(
                        output.AsSpan(checked((int)outputOffset), sizeof(uint)));
                    var outputSequenceOffset = outputOffset - placement.FileOffset.Value;
                    var outputSequenceSize = Math.Max(
                        first.Fixup.SequenceOutputRange.Size,
                        checked(outputSequenceOffset + (4UL * sizeof(uint))));
                    valid = Aarch64TlsInstructionSemantics.IsSupportedInitialExecLdGotPrel19Sequence(
                        ReadWords(sourceFile.Bytes.Span, first.Fixup.SequenceSourceRange),
                        checked((int)((sourceOffset - first.Fixup.SequenceSourceRange.FileOffset.Value) / sizeof(uint))),
                        requireZeroSourceImmediate: true)
                        && Aarch64TlsInstructionSemantics.IsSupportedInitialExecLdGotPrel19Sequence(
                            ReadWords(output, new SemanticSourceRange(
                                new FileOffset(placement.FileOffset.Value),
                                placement.VirtualAddress,
                                outputSequenceSize)),
                            checked((int)(outputSequenceOffset / sizeof(uint))))
                        && Aarch64TlsInstructionSemantics.TryEncodeInitialExecLdGotPrel19(
                            sourceEncoding,
                            outputEncoding,
                            first.OutputVirtualAddress.Value,
                            first.Fixup.GotEntry!.SourceRange.VirtualAddress.Value,
                            first.Fixup.Addend,
                            out var expectedEncoding)
                        && outputEncoding == expectedEncoding;
                }
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed TLSIE LD_GOTTPREL_PREL19 literal does not retain its source GOT owner, signed PC-relative range, register chain, or output mapping.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }

    private static bool ValidateTlsDescFixupSequences(
        ElfFile sourceFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var groups = plan.TlsFixups
            .Where(decision => decision?.Fixup?.AccessModel == TlsAccessModel.TlsDesc)
            .GroupBy(decision => (decision.RegionIdentity, decision.Fixup.SequenceSourceRange));
        foreach (var group in groups)
        {
            var ordered = group.OrderBy(decision => decision.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 4
                && ordered.Select(decision => decision.Fixup.PairOrdinal).SequenceEqual(TlsDescPairOrdinals)
                && ordered.Select(decision => decision.Fixup.Relocation.RelocationType).SequenceEqual(TlsDescRelocationTypes)
                && ordered.All(decision => decision.Fixup.DescriptorOwner is not null)
                && ordered.Zip(ordered.Skip(1)).All(pair =>
                    pair.Second.Fixup.RelocationSourceRange.VirtualAddress.Value
                        == pair.First.Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                    && pair.Second.OutputVirtualAddress.Value
                        == pair.First.OutputVirtualAddress.Value + sizeof(uint)
                    && pair.Second.OutputFileOffset.Value
                        == pair.First.OutputFileOffset.Value + sizeof(uint));

            if (valid)
            {
                var first = ordered[0];
                var sourceRange = first.Fixup.SequenceSourceRange;
                var sourceOffset = sourceRange.FileOffset.Value;
                var outputOffset = first.OutputFileOffset.Value;
                valid = sourceRange.Size >= 8 * sizeof(uint)
                    && first.Fixup.SequenceOutputRange.Size >= 8 * sizeof(uint)
                    && sourceOffset <= (ulong)sourceFile.Bytes.Length
                    && sourceRange.Size <= (ulong)sourceFile.Bytes.Length - sourceOffset
                    && outputOffset <= (ulong)output.Length
                    && first.Fixup.SequenceOutputRange.Size <= (ulong)output.Length - outputOffset
                    && TryReadWords(sourceFile.Bytes.Span, sourceOffset, sourceRange.Size, out var sourceWords)
                    && TryReadWords(output, outputOffset, first.Fixup.SequenceOutputRange.Size, out var outputWords)
                    && Aarch64TlsInstructionSemantics.IsSupportedTlsDescWordSequence(
                        sourceWords,
                        first.Fixup.DescriptorOwner!,
                        sourceRange.VirtualAddress.Value)
                    && Aarch64TlsInstructionSemantics.IsSupportedTlsDescWordSequence(
                        outputWords,
                        first.Fixup.DescriptorOwner!,
                        first.OutputVirtualAddress.Value);
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed TLSDESC fixup sequence does not retain its descriptor owner, ordered markers, exact register flow, or output mapping.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }
    private static uint[] ReadWords(ReadOnlySpan<byte> bytes, SemanticSourceRange range)
    {
        if (range.Size == 0 || range.Size % sizeof(uint) != 0 || range.Size > int.MaxValue
            || range.FileOffset.Value > int.MaxValue
            || range.FileOffset.Value > (ulong)bytes.Length
            || range.Size > (ulong)bytes.Length - range.FileOffset.Value)
        {
            return Array.Empty<uint>();
        }

        var words = new uint[checked((int)(range.Size / sizeof(uint)))];
        for (var index = 0; index < words.Length; index++)
        {
            words[index] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(
                checked((int)(range.FileOffset.Value + ((ulong)index * sizeof(uint)))),
                sizeof(uint)));
        }

        return words;
    }
    private static bool ValidateInitialExecAdrLd64FixupPairs(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var groups = plan.TlsFixups
            .Where(decision => decision?.Fixup?.Relocation?.RelocationType is
                ElfConstants.RArm64TlsIeAdrGottprelPage21
                or ElfConstants.RArm64TlsIeLd64GottprelLo12Nc)
            .GroupBy(decision => (decision.RegionIdentity, decision.Fixup.SequenceSourceRange));
        foreach (var group in groups)
        {
            var ordered = group.OrderBy(decision => decision.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 2
                && ordered[0].Fixup.PairOrdinal == 0
                && ordered[1].Fixup.PairOrdinal == 1
                && ordered[0].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeAdrGottprelPage21
                && ordered[1].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeLd64GottprelLo12Nc
                && ordered[0].Fixup.Addend == ordered[1].Fixup.Addend
                && ordered[0].Fixup.Relocation.SymbolIndex == ordered[1].Fixup.Relocation.SymbolIndex
                && string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                && ordered[0].Fixup.GotEntry == ordered[1].Fixup.GotEntry
                && ordered[0].Fixup.RelocationSourceRange.FileOffset.Value >= ordered[0].Fixup.SequenceSourceRange.FileOffset.Value
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value >= ordered[0].Fixup.SequenceSourceRange.VirtualAddress.Value
                && ordered[0].OutputFileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputFileOffset.Value == ordered[0].OutputFileOffset.Value + sizeof(uint)
                && ordered[0].OutputVirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputVirtualAddress.Value == ordered[0].OutputVirtualAddress.Value + sizeof(uint)
                && ordered[0].Fixup.RelocationSourceRange.FileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.FileOffset.Value
                    == ordered[0].Fixup.RelocationSourceRange.FileOffset.Value + sizeof(uint)
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    == ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint);
            var placement = valid
                ? plan.Placements.SingleOrDefault(candidate => string.Equals(
                    candidate.Identity,
                    group.Key.RegionIdentity,
                    StringComparison.Ordinal))
                : null;
            if (placement is null)
            {
                valid = false;
            }
            else if (ordered[0].OutputFileOffset.Value < placement.FileOffset.Value
                || ordered[0].OutputVirtualAddress.Value < placement.VirtualAddress.Value)
            {
                valid = false;
            }

            if (valid && placement is not null)
            {
                var first = ordered[0].Fixup;
                var sourceDelta = first.RelocationSourceRange.FileOffset.Value
                    - first.SequenceSourceRange.FileOffset.Value;
                var outputDelta = ordered[0].OutputFileOffset.Value - placement.FileOffset.Value;
                var sourcePairDelta = sourceDelta / sizeof(uint) <= int.MaxValue
                    ? (int)(sourceDelta / sizeof(uint))
                    : -1;
                var outputPairDelta = outputDelta / sizeof(uint) <= int.MaxValue
                    ? (int)(outputDelta / sizeof(uint))
                    : -1;
                var sourceWords = Array.Empty<uint>();
                var outputWords = Array.Empty<uint>();
                var sourceRead = sourcePairDelta >= 0
                    && outputPairDelta >= 0
                    && sourceDelta % sizeof(uint) == 0
                    && outputDelta % sizeof(uint) == 0
                    && TryReadWords(
                        sourceFile.Bytes.Span,
                        first.SequenceSourceRange.FileOffset.Value,
                        first.SequenceSourceRange.Size,
                        out sourceWords)
                    && TryReadWords(
                        output,
                        placement.FileOffset.Value,
                        placement.Size,
                        out outputWords);
                valid = sourceRead
                    && Aarch64TlsInstructionSemantics.IsSupportedInitialExecAdrLd64Sequence(
                        sourceWords,
                        sourcePairDelta,
                        requireSourceLow12Zero: false)
                    && Aarch64TlsInstructionSemantics.IsSupportedInitialExecAdrLd64Sequence(
                        outputWords,
                        outputPairDelta,
                        requireSourceLow12Zero: false)
                    && first.GotEntry is { } gotEntry
                    && Aarch64TlsInstructionSemantics.TryEncodeInitialExecAdrLd64Pair(
                        sourceWords[sourcePairDelta],
                        sourceWords[sourcePairDelta + 1],
                        outputWords[outputPairDelta],
                        outputWords[outputPairDelta + 1],
                        ordered[0].OutputVirtualAddress.Value,
                        gotEntry.SourceRange.VirtualAddress.Value,
                        first.Addend,
                        out var expectedAdr,
                        out var expectedLd)
                    && outputWords[outputPairDelta] == expectedAdr
                    && outputWords[outputPairDelta + 1] == expectedLd;
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed TLSIE ADRP/LD64 GOTTPREL pair does not retain its source-preserved GOT chain, page/low-12 semantics, register wiring, addend, and output order.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }
    private static bool ValidateInitialExecMovwFixupPairs(
        ElfFile sourceFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var groups = plan.TlsFixups
            .Where(decision => decision?.Fixup?.Relocation?.RelocationType is
                ElfConstants.RArm64TlsIeMovwGottprelG1 or ElfConstants.RArm64TlsIeMovwGottprelG0Nc)
            .GroupBy(decision => (decision.RegionIdentity, decision.Fixup.SequenceSourceRange));
        foreach (var group in groups)
        {
            var ordered = group.OrderBy(decision => decision.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 2
                && ordered[0].Fixup.PairOrdinal == 0
                && ordered[1].Fixup.PairOrdinal == 1
                && ordered[0].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG1
                && ordered[1].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG0Nc
                && ordered[0].Fixup.Relocation.Addend == ordered[1].Fixup.Relocation.Addend
                && ordered[0].Fixup.Relocation.SymbolIndex == ordered[1].Fixup.Relocation.SymbolIndex
                && string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                && ordered[0].Fixup.GotEntry == ordered[1].Fixup.GotEntry
                && ordered[0].OutputFileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputFileOffset.Value == ordered[0].OutputFileOffset.Value + sizeof(uint)
                && ordered[0].OutputVirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputVirtualAddress.Value == ordered[0].OutputVirtualAddress.Value + sizeof(uint);
            if (valid)
            {
                var first = ordered[0];
                var placement = plan.Placements.SingleOrDefault(candidate =>
                    string.Equals(candidate.Identity, first.RegionIdentity, StringComparison.Ordinal));
                if (placement is null
                    || first.Fixup.SequenceSourceRange.Size == 0
                    || first.Fixup.SequenceSourceRange.Size % sizeof(uint) != 0
                    || first.Fixup.SequenceOutputRange.Size % sizeof(uint) != 0
                    || first.Fixup.RelocationSourceRange.FileOffset.Value < first.Fixup.SequenceSourceRange.FileOffset.Value
                    || first.OutputFileOffset.Value < placement.FileOffset.Value)
                {
                    valid = false;
                }
                else
                {
                    var sourcePairDelta = first.Fixup.RelocationSourceRange.FileOffset.Value
                        - first.Fixup.SequenceSourceRange.FileOffset.Value;
                    var outputPairDelta = first.OutputFileOffset.Value - placement.FileOffset.Value;
                    var sourceRead = TryReadWords(
                        sourceFile.Bytes.Span,
                        first.Fixup.SequenceSourceRange.FileOffset.Value,
                        first.Fixup.SequenceSourceRange.Size,
                        out var sourceWords);
                    var outputRequiredSize = Math.Max(
                        first.Fixup.SequenceOutputRange.Size,
                        checked(outputPairDelta + (7UL * sizeof(uint))));
                    var outputRead = TryReadWords(
                        output,
                        placement.FileOffset.Value,
                        outputRequiredSize,
                        out var outputWords);
                    var sourceChain = sourceRead
                        && sourcePairDelta % sizeof(uint) == 0
                        && Aarch64TlsInstructionSemantics.IsSupportedInitialExecMovwSequence(
                            sourceWords,
                            checked((int)(sourcePairDelta / sizeof(uint))));
                    var outputChain = outputRead
                        && outputPairDelta % sizeof(uint) == 0
                        && Aarch64TlsInstructionSemantics.IsSupportedInitialExecMovwSequence(
                            outputWords,
                            checked((int)(outputPairDelta / sizeof(uint))));
                    valid = sourceChain && outputChain;
                }
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed TLSIE MOVW GOTTPREL pair does not retain its source-preserved GOT chain, instruction shape, register wiring, addend, and output order.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }

    private static bool TryReadWords(
        ReadOnlySpan<byte> bytes,
        ulong offset,
        ulong size,
        out uint[] words)
    {
        words = Array.Empty<uint>();
        if (size == 0
            || size % sizeof(uint) != 0
            || size > int.MaxValue
            || offset > int.MaxValue
            || offset > (ulong)bytes.Length
            || size > (ulong)bytes.Length - offset)
        {
            return false;
        }

        words = new uint[checked((int)(size / sizeof(uint)))];
        for (var index = 0; index < words.Length; index++)
        {
            words[index] = BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.Slice(checked((int)(offset + ((ulong)index * sizeof(uint)))), sizeof(uint)));
        }

        return true;
    }

    private static bool ValidateTlsDescriptorOwnerPreserved(
        ElfFile sourceFile,
        ElfFile outputFile,
        byte[] output,
        TlsDescriptorOwnerBinding owner,
        DiagnosticBag diagnostics)
    {
        var sourceFacts = sourceFile.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDesc
                && fact.Relocation.Offset == owner.DescriptorRange.VirtualAddress.Value
                && fact.Relocation.Info == owner.Relocation.RawInfo
                && fact.Relocation.IsPlt == owner.Relocation.IsPlt
                && fact.Relocation.Addend == owner.Relocation.Addend
                && fact.Relocation.SourceAddress == owner.Relocation.RelocationTableAddress?.Value
                && string.Equals(fact.Symbol?.Name, owner.Symbol.Name, StringComparison.Ordinal)
                && fact.WriteSize == sizeof(ulong))
            .ToArray();
        var outputFacts = outputFile.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDesc
                && fact.Relocation.Offset == owner.DescriptorRange.VirtualAddress.Value
                && fact.Relocation.Info == owner.Relocation.RawInfo
                && fact.Relocation.IsPlt == owner.Relocation.IsPlt
                && fact.Relocation.Addend == owner.Relocation.Addend
                && fact.Relocation.SourceAddress == owner.Relocation.RelocationTableAddress?.Value
                && string.Equals(fact.Symbol?.Name, owner.Symbol.Name, StringComparison.Ordinal)
                && fact.WriteSize == sizeof(ulong))
            .ToArray();
        var valid = sourceFacts.Length == 1
            && outputFacts.Length == 1
            && owner.DescriptorRange.Size == 2 * sizeof(ulong)
            && sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                owner.DescriptorRange.VirtualAddress,
                owner.DescriptorRange.Size,
                out var sourceDescriptorOffset)
            && sourceDescriptorOffset == owner.DescriptorRange.FileOffset
            && outputFile.LoadMap.TryVirtualAddressToFileOffset(
                owner.DescriptorRange.VirtualAddress,
                owner.DescriptorRange.Size,
                out var outputDescriptorOffset)
            && outputDescriptorOffset == owner.DescriptorRange.FileOffset
            && sourceDescriptorOffset.Value <= int.MaxValue
            && outputDescriptorOffset.Value <= int.MaxValue
            && sourceDescriptorOffset.Value <= (ulong)sourceFile.Bytes.Length
            && outputDescriptorOffset.Value <= (ulong)output.Length
            && owner.DescriptorRange.Size <= (ulong)sourceFile.Bytes.Length - sourceDescriptorOffset.Value
            && owner.DescriptorRange.Size <= (ulong)output.Length - outputDescriptorOffset.Value
            && sourceFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(owner.DescriptorRange.VirtualAddress.Value, owner.DescriptorRange.Size)
                && segment.ContainsFileOffset(owner.DescriptorRange.FileOffset.Value, owner.DescriptorRange.Size)
                && (segment.Flags & ElfConstants.PfW) != 0) == 1
            && outputFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(owner.DescriptorRange.VirtualAddress.Value, owner.DescriptorRange.Size)
                && segment.ContainsFileOffset(owner.DescriptorRange.FileOffset.Value, owner.DescriptorRange.Size)
                && (segment.Flags & ElfConstants.PfW) != 0) == 1
            && sourceFile.Bytes.Span.Slice(
                checked((int)sourceDescriptorOffset.Value), checked((int)owner.DescriptorRange.Size))
                .SequenceEqual(output.AsSpan(
                    checked((int)outputDescriptorOffset.Value), checked((int)owner.DescriptorRange.Size)));
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "The TLSDESC descriptor owner moved, changed, lost writable ownership, or no longer has one matching loader relocation.",
                owner.DescriptorRange.FileOffset.Value);
            return false;
        }

        return ValidateTlsOwnedRangePreserved(
                sourceFile,
                outputFile,
                output,
                owner.ResolverPltRange,
                owner.ResolverPltRange.Size,
                executable: true,
                diagnostics)
            && ValidateTlsOwnedRangePreserved(
                sourceFile,
                outputFile,
                output,
                owner.ResolverGotRange,
                owner.ResolverGotRange.Size,
                executable: false,
                diagnostics);
    }

    private static bool ValidateTlsOwnedRangePreserved(
        ElfFile sourceFile,
        ElfFile outputFile,
        byte[] output,
        SemanticSourceRange range,
        ulong size,
        bool executable,
        DiagnosticBag diagnostics)
    {
        var sourceMapped = sourceFile.LoadMap.TryVirtualAddressToFileOffset(
            range.VirtualAddress,
            size,
            out var sourceOffset);
        var outputMapped = outputFile.LoadMap.TryVirtualAddressToFileOffset(
            range.VirtualAddress,
            size,
            out var outputOffset);
        var segmentCheck = executable
            ? sourceFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(range.VirtualAddress.Value, size)
                && segment.ContainsFileOffset(range.FileOffset.Value, size)
                && segment.IsExecutable) == 1
                && outputFile.LoadMap.Segments.Count(segment =>
                    segment.ContainsVirtualAddress(range.VirtualAddress.Value, size)
                    && segment.ContainsFileOffset(range.FileOffset.Value, size)
                    && segment.IsExecutable) == 1
            : sourceFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(range.VirtualAddress.Value, size)
                && segment.ContainsFileOffset(range.FileOffset.Value, size)
                && (segment.Flags & ElfConstants.PfW) != 0) == 1
                && outputFile.LoadMap.Segments.Count(segment =>
                    segment.ContainsVirtualAddress(range.VirtualAddress.Value, size)
                    && segment.ContainsFileOffset(range.FileOffset.Value, size)
                    && (segment.Flags & ElfConstants.PfW) != 0) == 1;
        var valid = sourceMapped
            && outputMapped
            && sourceOffset == range.FileOffset
            && outputOffset == range.FileOffset
            && sourceOffset.Value <= int.MaxValue
            && outputOffset.Value <= int.MaxValue
            && sourceOffset.Value <= (ulong)sourceFile.Bytes.Length
            && outputOffset.Value <= (ulong)output.Length
            && size <= (ulong)sourceFile.Bytes.Length - sourceOffset.Value
            && size <= (ulong)output.Length - outputOffset.Value
            && segmentCheck
            && sourceFile.Bytes.Span.Slice(checked((int)sourceOffset.Value), checked((int)size))
                .SequenceEqual(output.AsSpan(checked((int)outputOffset.Value), checked((int)size)));
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "A TLSDESC resolver PLT/GOT owned range moved, changed, or lost its required segment permissions.",
                range.FileOffset.Value);
        }

        return valid;
    }
    private static bool ValidateDynamicOwnerPairPreserved(
        ElfFile sourceFile,
        ElfFile outputFile,
        byte[] output,
        TlsModuleOwnerBinding moduleOwner,
        TlsDtpRelOwnerBinding dtpRelOwner,
        DiagnosticBag diagnostics)
    {
        if (!ValidateDynamicOwnerPreserved(sourceFile, outputFile, output, moduleOwner.SourceRange, moduleOwner.Relocation, diagnostics)
            || !ValidateDynamicOwnerPreserved(sourceFile, outputFile, output, dtpRelOwner.SourceRange, dtpRelOwner.Relocation, diagnostics))
        {
            return false;
        }

        return moduleOwner.SourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(ulong)
            && moduleOwner.SourceRange.FileOffset.Value <= ulong.MaxValue - sizeof(ulong)
            && dtpRelOwner.SourceRange.VirtualAddress.Value == moduleOwner.SourceRange.VirtualAddress.Value + sizeof(ulong)
            && dtpRelOwner.SourceRange.FileOffset.Value == moduleOwner.SourceRange.FileOffset.Value + sizeof(ulong);
    }

    private static bool ValidateDynamicOwnerPreserved(
        ElfFile sourceFile,
        ElfFile outputFile,
        byte[] output,
        SemanticSourceRange ownerRange,
        RelocationBinding ownerRelocation,
        DiagnosticBag diagnostics)
    {
        var sourceFacts = sourceFile.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ownerRelocation.RelocationType
                && fact.Relocation.Offset == ownerRange.VirtualAddress.Value
                && fact.Relocation.Info == ownerRelocation.RawInfo
                && fact.Relocation.Addend == ownerRelocation.Addend
                && fact.Relocation.SourceAddress == ownerRelocation.RelocationTableAddress?.Value)
            .ToArray();
        var outputFacts = outputFile.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ownerRelocation.RelocationType
                && fact.Relocation.Offset == ownerRange.VirtualAddress.Value
                && fact.Relocation.Info == ownerRelocation.RawInfo
                && fact.Relocation.Addend == ownerRelocation.Addend
                && fact.Relocation.SourceAddress == ownerRelocation.RelocationTableAddress?.Value)
            .ToArray();
        if (sourceFacts.Length != 1 || outputFacts.Length != 1
            || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(ownerRange.VirtualAddress, sizeof(ulong), out var sourceOffset)
            || !outputFile.LoadMap.TryVirtualAddressToFileOffset(ownerRange.VirtualAddress, sizeof(ulong), out var outputOffset)
            || sourceOffset != ownerRange.FileOffset
            || outputOffset != ownerRange.FileOffset
            || sourceOffset.Value > int.MaxValue
            || outputOffset.Value > int.MaxValue
            || sourceOffset.Value > (ulong)sourceFile.Bytes.Length
            || outputOffset.Value > (ulong)output.Length
            || sizeof(ulong) > (ulong)sourceFile.Bytes.Length - sourceOffset.Value
            || sizeof(ulong) > (ulong)output.Length - outputOffset.Value
            || !sourceFile.Bytes.Span.Slice(checked((int)sourceOffset.Value), sizeof(ulong))
                .SequenceEqual(output.AsSpan(checked((int)outputOffset.Value), sizeof(ulong))))
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "A TLSGD loader-owned GOT word moved, changed, or lost its dynamic relocation owner.",
                ownerRange.FileOffset.Value);
            return false;
        }

        return true;
    }

    private static bool ValidateLocalDynamicModuleOwnerPreserved(
        ElfFile sourceFile,
        ElfFile outputFile,
        byte[] output,
        TlsModuleOwnerBinding owner,
        DiagnosticBag diagnostics)
    {
        var sourceFacts = sourceFile.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDtpMod64
                && fact.Relocation.Offset == owner.SourceRange.VirtualAddress.Value
                && fact.Relocation.SymbolIndex == 0
                && fact.Relocation.Addend == owner.Relocation.Addend
                && fact.Relocation.SourceAddress == owner.Relocation.RelocationTableAddress?.Value
                && fact.Symbol is null
                && fact.WriteSize == sizeof(ulong))
            .ToArray();
        var outputFacts = outputFile.TlsMetadata.Dynamic.Relocations
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsDtpMod64
                && fact.Relocation.Offset == owner.SourceRange.VirtualAddress.Value
                && fact.Relocation.SymbolIndex == 0
                && fact.Relocation.Addend == owner.Relocation.Addend
                && fact.Relocation.SourceAddress == owner.Relocation.RelocationTableAddress?.Value
                && fact.Symbol is null
                && fact.WriteSize == sizeof(ulong))
            .ToArray();
        if (sourceFacts.Length != 1 || outputFacts.Length != 1
            || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                owner.SourceRange.VirtualAddress,
                sizeof(ulong),
                out var sourceOffset)
            || sourceOffset != owner.SourceRange.FileOffset
            || !outputFile.LoadMap.TryVirtualAddressToFileOffset(
                owner.SourceRange.VirtualAddress,
                sizeof(ulong),
                out var outputOffset)
            || outputOffset != owner.SourceRange.FileOffset
            || sourceOffset.Value > int.MaxValue
            || outputOffset.Value > int.MaxValue
            || sourceOffset.Value > (ulong)sourceFile.Bytes.Length
            || outputOffset.Value > (ulong)output.Length
            || sizeof(ulong) > (ulong)sourceFile.Bytes.Length - sourceOffset.Value
            || sizeof(ulong) > (ulong)output.Length - outputOffset.Value
            || sourceFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(owner.SourceRange.VirtualAddress.Value, sizeof(ulong))
                && segment.ContainsFileOffset(owner.SourceRange.FileOffset.Value, sizeof(ulong))
                && (segment.Flags & ElfConstants.PfW) != 0) != 1
            || outputFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(owner.SourceRange.VirtualAddress.Value, sizeof(ulong))
                && segment.ContainsFileOffset(owner.SourceRange.FileOffset.Value, sizeof(ulong))
                && (segment.Flags & ElfConstants.PfW) != 0) != 1
            || !sourceFile.Bytes.Span.Slice(checked((int)sourceOffset.Value), sizeof(ulong))
                .SequenceEqual(output.AsSpan(checked((int)outputOffset.Value), sizeof(ulong))))
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "The TLSLD DTPMOD64 owner moved, changed, lost writable ownership, or no longer has one matching loader relocation.",
                owner.SourceRange.FileOffset.Value);
            return false;
        }

        return true;
    }

    private static bool ValidateInitialExecGotEntryPreserved(
        ElfFile sourceFile,
        ElfFile outputFile,
        byte[] output,
        TlsGotEntryBinding gotEntry,
        DiagnosticBag diagnostics)
    {
        if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                gotEntry.SourceRange.VirtualAddress,
                sizeof(ulong),
                out var sourceOffset)
            || sourceOffset != gotEntry.SourceRange.FileOffset
            || !outputFile.LoadMap.TryVirtualAddressToFileOffset(
                gotEntry.SourceRange.VirtualAddress,
                sizeof(ulong),
                out var outputOffset)
            || outputOffset != gotEntry.SourceRange.FileOffset
            || outputOffset.Value > int.MaxValue
            || outputOffset.Value > (ulong)output.Length
            || sizeof(ulong) > (ulong)output.Length - outputOffset.Value
            || sourceOffset.Value > int.MaxValue
            || sizeof(ulong) > (ulong)sourceFile.Bytes.Length - sourceOffset.Value
            || sourceFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(gotEntry.SourceRange.VirtualAddress.Value, sizeof(ulong))
                && segment.ContainsFileOffset(gotEntry.SourceRange.FileOffset.Value, sizeof(ulong))
                && (segment.Flags & ElfConstants.PfW) != 0) != 1
            || outputFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(gotEntry.SourceRange.VirtualAddress.Value, sizeof(ulong))
                && segment.ContainsFileOffset(gotEntry.SourceRange.FileOffset.Value, sizeof(ulong))
                && (segment.Flags & ElfConstants.PfW) != 0) != 1
            || !sourceFile.Bytes.Span.Slice(checked((int)sourceOffset.Value), sizeof(ulong))
                .SequenceEqual(output.AsSpan(checked((int)outputOffset.Value), sizeof(ulong))))
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "The TLSIE GOT entry was moved, changed, lost writable ownership, or is not source-mapped in the output.",
                gotEntry.SourceRange.FileOffset.Value);
            return false;
        }

        var sourceFacts = sourceFile.TlsMetadata.StaticRelocations
            .Concat(sourceFile.TlsMetadata.Dynamic.Relocations)
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsTprel64
                && fact.Relocation.Offset == gotEntry.SourceRange.VirtualAddress.Value
                && fact.Relocation.Info == gotEntry.Relocation.RawInfo
                && !fact.Relocation.IsPlt
                && fact.Relocation.Addend == gotEntry.Addend
                && fact.Symbol is not null
                && TlsStructuralAdapter.SymbolsMatch(fact.Symbol, gotEntry.Symbol))
            .ToArray();
        if (sourceFacts.Length != 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "The TLSIE GOT entry does not retain exactly one source R_AARCH64_TLS_TPREL64 owner.",
                gotEntry.SourceRange.FileOffset.Value);
            return false;
        }

        return true;
    }

    private static bool ValidateLocalExecLdst32FixupPairs(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var ldstGroups = plan.TlsFixups
            .Where(decision => decision?.Fixup?.Relocation?.RelocationType
                == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
            .GroupBy(decision => (decision.RegionIdentity, decision.Fixup.SequenceSourceRange));

        foreach (var ldstGroup in ldstGroups)
        {
            var ordered = plan.TlsFixups
                .Where(decision => decision is not null
                    && string.Equals(decision.RegionIdentity, ldstGroup.Key.RegionIdentity, StringComparison.Ordinal)
                    && decision.Fixup.SequenceSourceRange == ldstGroup.Key.SequenceSourceRange
                    && decision.Fixup.Relocation.RelocationType is
                        ElfConstants.RArm64TlsLeAddTprelHi12 or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
                .OrderBy(decision => decision.Fixup.PairOrdinal)
                .ToArray();

            if (ordered.Length != 2
                || ordered[0].Fixup.PairOrdinal != 0
                || ordered[1].Fixup.PairOrdinal != 1
                || ordered[0].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeAddTprelHi12
                || ordered[1].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeLdst32TprelLo12Nc
                || ordered[0].Fixup.Relocation.Addend != ordered[1].Fixup.Relocation.Addend
                || ordered[0].Fixup.Relocation.SymbolIndex != ordered[1].Fixup.Relocation.SymbolIndex
                || !string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                || ordered[0].Fixup.Symbol is null
                || ordered[1].Fixup.Symbol != ordered[0].Fixup.Symbol
                || ordered[1].Fixup.Module != ordered[0].Fixup.Module
                || ordered[0].Fixup.SequenceOutputRange != ordered[1].Fixup.SequenceOutputRange
                || ordered[0].Fixup.RelocationSourceRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.FileOffset.Value
                    != ordered[0].Fixup.RelocationSourceRange.FileOffset.Value + sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    != ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                || ordered[0].OutputFileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].OutputVirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].OutputFileOffset.Value
                    != ordered[0].OutputFileOffset.Value + sizeof(uint)
                || ordered[1].OutputVirtualAddress.Value
                    != ordered[0].OutputVirtualAddress.Value + sizeof(uint))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The materialized local-exec LDST32 TLS pair is incomplete, interleaved, or inconsistent in identity, addend, order, or mapped output ranges.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var first = ordered[0];
            var second = ordered[1];
            if (first.Fixup.RelocationSourceRange.FileOffset.Value < sizeof(uint)
                || first.OutputFileOffset.Value < sizeof(uint)
                || first.Fixup.RelocationSourceRange.VirtualAddress.Value < sizeof(uint)
                || first.OutputVirtualAddress.Value < sizeof(uint)
                || first.Fixup.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || second.Fixup.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || first.OutputFileOffset.Value > int.MaxValue
                || second.OutputFileOffset.Value > int.MaxValue
                || first.Fixup.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - first.Fixup.RelocationSourceRange.FileOffset.Value
                || second.Fixup.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - second.Fixup.RelocationSourceRange.FileOffset.Value
                || first.OutputFileOffset.Value > (ulong)output.Length
                || sizeof(uint) > (ulong)output.Length - first.OutputFileOffset.Value
                || second.OutputFileOffset.Value > (ulong)output.Length
                || sizeof(uint) > (ulong)output.Length - second.OutputFileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The materialized local-exec LDST32 TLS pair is outside the bounded source or output image.",
                    first.Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var sourceFirstEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)first.Fixup.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            var sourceSecondEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)second.Fixup.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            var outputFirstEncoding = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(
                checked((int)first.OutputFileOffset.Value), sizeof(uint)));
            var outputSecondEncoding = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(
                checked((int)second.OutputFileOffset.Value), sizeof(uint)));
            var sourceThreadPointerEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)first.Fixup.RelocationSourceRange.FileOffset.Value - sizeof(uint)), sizeof(uint)));
            var outputThreadPointerEncoding = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(
                checked((int)first.OutputFileOffset.Value - sizeof(uint)), sizeof(uint)));
            if (!Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Sequence(
                    sourceThreadPointerEncoding,
                    sourceFirstEncoding,
                    sourceSecondEncoding)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Sequence(
                    outputThreadPointerEncoding,
                    outputFirstEncoding,
                    outputSecondEncoding)
                || first.Fixup.Symbol is null
                || !Aarch64TlsInstructionSemantics.TryAddSigned(
                    first.Fixup.Symbol.Value,
                    first.Fixup.Addend,
                    out var tprelOffset)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Pair(
                    first.Fixup.Relocation.RelocationType!.Value,
                    sourceFirstEncoding,
                    first.Fixup.RelocationSourceRange.VirtualAddress.Value,
                    first.Fixup.Relocation.Addend,
                    second.Fixup.Relocation.RelocationType!.Value,
                    sourceSecondEncoding,
                    second.Fixup.RelocationSourceRange.VirtualAddress.Value,
                    second.Fixup.Relocation.Addend,
                    tprelOffset)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Pair(
                    first.Fixup.Relocation.RelocationType!.Value,
                    outputFirstEncoding,
                    first.OutputVirtualAddress.Value,
                    first.Fixup.Relocation.Addend,
                    second.Fixup.Relocation.RelocationType!.Value,
                    outputSecondEncoding,
                    second.OutputVirtualAddress.Value,
                    second.Fixup.Relocation.Addend,
                    tprelOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed local-exec LDST32 TLS pair does not retain its ABI width, scale, opcode, register, addend, and output-order contract.",
                    first.Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }

    private static bool ValidateLocalExecMovwFixupPairs(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var movwGroups = plan.TlsFixups
            .Where(decision => decision?.Fixup?.Relocation?.RelocationType is { } type
                && type is ElfConstants.RArm64TlsLeMovwTprelG1 or ElfConstants.RArm64TlsLeMovwTprelG0Nc)
            .GroupBy(decision => (decision.RegionIdentity, decision.Fixup.SequenceSourceRange));

        foreach (var group in movwGroups)
        {
            var ordered = group.OrderBy(decision => decision.Fixup.PairOrdinal).ToArray();
            if (ordered.Length != 2
                || ordered[0].Fixup.PairOrdinal != 0
                || ordered[1].Fixup.PairOrdinal != 1
                || ordered[0].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeMovwTprelG1
                || ordered[1].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeMovwTprelG0Nc
                || ordered[0].Fixup.Relocation.Addend != ordered[1].Fixup.Relocation.Addend
                || ordered[0].Fixup.Relocation.SymbolIndex != ordered[1].Fixup.Relocation.SymbolIndex
                || !string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                || ordered[0].Fixup.SequenceOutputRange != ordered[1].Fixup.SequenceOutputRange
                || ordered[0].Fixup.RelocationSourceRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.FileOffset.Value
                    != ordered[0].Fixup.RelocationSourceRange.FileOffset.Value + sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    != ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                || ordered[0].OutputFileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].OutputVirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].OutputFileOffset.Value != ordered[0].OutputFileOffset.Value + sizeof(uint)
                || ordered[1].OutputVirtualAddress.Value != ordered[0].OutputVirtualAddress.Value + sizeof(uint))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The materialized local-exec MOVW TLS pair is incomplete, interleaved, or inconsistent in identity, addend, order, or mapped output ranges.",
                    ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var first = ordered[0];
            var second = ordered[1];
            if (first.Fixup.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || second.Fixup.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || first.OutputFileOffset.Value > int.MaxValue
                || second.OutputFileOffset.Value > int.MaxValue
                || first.Fixup.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - first.Fixup.RelocationSourceRange.FileOffset.Value
                || second.Fixup.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - second.Fixup.RelocationSourceRange.FileOffset.Value
                || first.OutputFileOffset.Value > (ulong)output.Length
                || sizeof(uint) > (ulong)output.Length - first.OutputFileOffset.Value
                || second.OutputFileOffset.Value > (ulong)output.Length
                || sizeof(uint) > (ulong)output.Length - second.OutputFileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The materialized local-exec MOVW TLS pair is outside the bounded input or output image.",
                    first.Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var sourceFirstEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)first.Fixup.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            var sourceSecondEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)second.Fixup.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            var outputFirstEncoding = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(
                checked((int)first.OutputFileOffset.Value), sizeof(uint)));
            var outputSecondEncoding = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(
                checked((int)second.OutputFileOffset.Value), sizeof(uint)));
            if (!Aarch64TlsInstructionSemantics.IsSupportedLocalExecMovwPair(
                    ElfConstants.RArm64TlsLeMovwTprelG1,
                    sourceFirstEncoding,
                    first.Fixup.RelocationSourceRange.VirtualAddress.Value,
                    first.Fixup.Relocation.Addend,
                    ElfConstants.RArm64TlsLeMovwTprelG0Nc,
                    sourceSecondEncoding,
                    second.Fixup.RelocationSourceRange.VirtualAddress.Value,
                    second.Fixup.Relocation.Addend)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecMovwPair(
                    ElfConstants.RArm64TlsLeMovwTprelG1,
                    outputFirstEncoding,
                    first.OutputVirtualAddress.Value,
                    first.Fixup.Relocation.Addend,
                    ElfConstants.RArm64TlsLeMovwTprelG0Nc,
                    outputSecondEncoding,
                    second.OutputVirtualAddress.Value,
                    second.Fixup.Relocation.Addend))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The reparsed local-exec MOVW TLS pair does not retain matching ABI instruction forms, destination register, addends, and output order.",
                    first.Fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }

    private static bool ValidatePlanEdits(ElfLayoutPlan plan, ulong sourceLength, DiagnosticBag diagnostics)
    {
        ulong previousEnd = 0;
        var first = true;
        foreach (var edit in plan.Edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind))
        {
            if (edit.Bytes is null || edit.Bytes.Length == 0
                || !TryAdd(edit.Offset.Value, checked((ulong)edit.Bytes.Length), out var end)
                || end > plan.OutputLength
                || (!first && edit.Offset.Value < previousEnd))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutEditOverlap, "The layout plan contains an invalid or overlapping byte edit.", edit.Offset.Value);
                return false;
            }

            if (edit.Offset.Value < sourceLength && end > sourceLength && edit.Kind != ElfLayoutEditKind.Padding)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A planned source edit crosses the source/output boundary.", edit.Offset.Value);
                return false;
            }

            first = false;
            previousEnd = end;
        }

        return true;
    }

    private static bool ValidateParsedOutput(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        if (!outputFile.Header.IsAarch64
            || outputFile.Header.Type != sourceFile.Header.Type
            || outputFile.Header.ProgramHeaderOffset != plan.NewProgramHeaderTable.FileOffset.Value
            || outputFile.Header.ProgramHeaderCount != plan.NewProgramHeaderCount
            || outputFile.Header.ProgramHeaderEntrySize != sourceFile.Header.ProgramHeaderEntrySize
            || outputFile.Header.SectionHeaderOffset != sourceFile.Header.SectionHeaderOffset
            || outputFile.Header.SectionHeaderEntrySize != sourceFile.Header.SectionHeaderEntrySize
            || outputFile.Header.SectionHeaderCount != sourceFile.Header.SectionHeaderCount
            || outputFile.Header.SectionNameIndex != sourceFile.Header.SectionNameIndex
            || output.Length != checked((int)plan.OutputLength)
            || output.AsSpan().SequenceEqual(sourceFile.Bytes.Span))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "The reparsed ELF does not match the selected layout metadata.");
            return false;
        }

        if (outputFile.ProgramHeaders.Count != plan.ProgramHeaders.Count)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "The reparsed program-header count does not match the layout plan.");
            return false;
        }

        for (var index = 0; index < plan.ProgramHeaders.Count; index++)
        {
            if (outputFile.ProgramHeaders[index] != plan.ProgramHeaders[index].PlannedHeader)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Program header {index} differs from its planned serialization.");
                return false;
            }
        }

        if (!outputFile.SectionHeaders.SequenceEqual(sourceFile.SectionHeaders))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, "The reparsed section-header table differs from the source table.");
            return false;
        }

        foreach (var placement in plan.Placements)
        {
            if (!outputFile.LoadMap.Segments.Any(segment =>
                    segment.ContainsFileOffset(placement.FileOffset.Value, placement.Size)
                    && segment.ContainsVirtualAddress(placement.VirtualAddress.Value, placement.Size)
                    && segment.IsExecutable))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Placement '{placement.Identity}' is not mapped by an executable output PT_LOAD.");
                return false;
            }
        }

        foreach (var unwindEdit in plan.UnwindEdits)
        {
            if (unwindEdit.Kind != ElfLayoutEditKind.UnwindMetadata
                || unwindEdit.Bytes.Length == 0
                || unwindEdit.Offset.Value > (ulong)output.Length
                || (ulong)unwindEdit.Bytes.Length > (ulong)output.Length - unwindEdit.Offset.Value
                || !output.AsSpan(checked((int)unwindEdit.Offset.Value), unwindEdit.Bytes.Length)
                    .SequenceEqual(unwindEdit.Bytes))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutPostValidationFailed,
                    "An unwind metadata edit does not match the materialized output.",
                    unwindEdit.Offset.Value);
                return false;
            }
        }

        foreach (var decision in plan.BranchDecisions)
        {
            var sourceRange = decision.SourceRange;
            if (decision.Decision == ElfLayoutBranchDecision.LongAddress)
            {
                var replacements = plan.Edits
                    .Where(edit => edit.Kind == ElfLayoutEditKind.LongBranch && edit.Offset == sourceRange.FileOffset)
                    .ToArray();
                if (replacements.Length != 1
                    || sourceRange.FileOffset.Value > int.MaxValue
                    || !TryAdd(sourceRange.FileOffset.Value, checked((ulong)replacements[0].Bytes.Length), out var replacementEnd)
                    || replacementEnd > (ulong)output.Length
                    || !output.AsSpan(checked((int)sourceRange.FileOffset.Value), replacements[0].Bytes.Length)
                        .SequenceEqual(replacements[0].Bytes))
                {
                    diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Long branch decision '{decision.Identity}' does not match its typed source replacement.", sourceRange.FileOffset.Value);
                    return false;
                }

                continue;
            }

            if (decision.Decision is not (ElfLayoutBranchDecision.Direct or ElfLayoutBranchDecision.NearVeneer))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Branch decision '{decision.Identity}' uses an unsupported placement decision.", sourceRange.FileOffset.Value);
                return false;
            }

            if (!TryGetBranchEncoding(plan, decision, out var expected))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Branch decision '{decision.Identity}' has no materialized encoding.");
                return false;
            }

            var expectedBytes = expected;
            if (sourceRange.FileOffset.Value > int.MaxValue
                || sourceRange.Size != sizeof(uint)
                || !output.AsSpan(checked((int)sourceRange.FileOffset.Value), sizeof(uint)).SequenceEqual(expectedBytes))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutPostValidationFailed, $"Branch decision '{decision.Identity}' does not match its planned encoding.", sourceRange.FileOffset.Value);
                return false;
            }
        }

        return true;
    }

    private static bool ValidateJumpTableTargetBindings(
        ElfFile sourceFile,
        ElfFile outputFile,
        ElfLayoutPlan plan,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        var bindings = plan.JumpTableTargetBindings;
        var materializedTableEdits = plan.Edits
            .Where(edit => edit.Kind == ElfLayoutEditKind.JumpTableEntry)
            .ToArray();
        if (bindings.Count != plan.JumpTableEdits.Count
            || materializedTableEdits.Length != plan.JumpTableEdits.Count)
        {
            diagnostics.Error(
                DiagnosticCode.ElfLayoutPostValidationFailed,
                "Jump-table target bindings, planned table edits, and materialized table edits must have one-to-one counts.");
            return false;
        }

        var tableEditOffsets = new HashSet<ulong>();
        foreach (var tableEdit in plan.JumpTableEdits)
        {
            var matches = materializedTableEdits
                .Where(edit => edit.Offset == tableEdit.Offset)
                .ToArray();
            if (tableEdit.Kind != ElfLayoutEditKind.JumpTableEntry
                || !tableEditOffsets.Add(tableEdit.Offset.Value)
                || matches.Length != 1
                || !matches[0].Bytes.AsSpan().SequenceEqual(tableEdit.Bytes))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutPostValidationFailed,
                    "Jump-table edits contain an untyped, duplicate, missing, or mismatched materialized row.",
                    tableEdit.Offset.Value);
                return false;
            }
        }

        var entryIdentities = new HashSet<SemanticEntityId>();
        var boundEntryOffsets = new HashSet<ulong>();
        var cloneIdentities = plan.JumpTableClones.Select(clone => clone.TableIdentity).ToHashSet();
        if (cloneIdentities.Count != plan.JumpTableClones.Count
            || !cloneIdentities.SetEquals(bindings.Select(binding => binding.TableIdentity).Distinct()))
        {
            diagnostics.Error(
                DiagnosticCode.ElfLayoutPostValidationFailed,
                "Jump-table clone records and entry target bindings do not have a one-to-one table identity set.");
            return false;
        }

        foreach (var tableGroup in bindings.GroupBy(binding => binding.TableIdentity))
        {
            var ordered = tableGroup.OrderBy(binding => binding.EntryIndex).ToArray();
            if (ordered.Length == 0
                || tableGroup.Key.Kind != SemanticEntityKind.Table
                || string.IsNullOrWhiteSpace(tableGroup.Key.Value))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutPostValidationFailed,
                    "A jump-table target binding has no typed table identity.");
                return false;
            }

            var first = ordered[0];
            var tableRange = first.SourceTableRange;
            if (first.EntryWidth is not (1 or 2 or 4 or 8)
                || tableRange.Size == 0
                || tableRange.Size % (ulong)first.EntryWidth != 0
                || tableRange.Size / (ulong)first.EntryWidth != (ulong)ordered.Length
                || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                    tableRange.VirtualAddress,
                    tableRange.Size,
                    out var mappedTableOffset)
                || mappedTableOffset != tableRange.FileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutPostValidationFailed,
                    "A jump-table target binding does not retain a bounded, file-backed source table range.",
                    tableRange.FileOffset.Value);
                return false;
            }

            var tableClones = plan.JumpTableClones
                .Where(clone => clone.TableIdentity == first.TableIdentity)
                .ToArray();
            if (tableClones.Length != 1
                || tableClones[0].RewritePolicy != SemanticJumpTableRewritePolicy.CopiedAndRetargeted
                || tableClones[0].SourceTableRange != tableRange
                || tableClones[0].OutputRange.Size != tableRange.Size
                || !TryGetFileBackedReadOnlyOffset(
                    outputFile,
                    tableClones[0].OutputRange.VirtualAddress,
                    tableClones[0].OutputRange.Size,
                    out var mappedCloneOffset)
                || mappedCloneOffset != tableClones[0].OutputRange.FileOffset
                || tableRange.FileOffset.Value > int.MaxValue
                || tableRange.Size > (ulong)sourceFile.Bytes.Length - tableRange.FileOffset.Value
                || !sourceFile.Bytes.Span.Slice(
                        checked((int)tableRange.FileOffset.Value),
                        checked((int)tableRange.Size))
                    .SequenceEqual(output.AsSpan(
                        checked((int)tableRange.FileOffset.Value),
                        checked((int)tableRange.Size)))
                || !TryMapPhysicalAddress(
                    plan.AddressMap,
                    tableRange.VirtualAddress,
                    out var mappedCloneAddress,
                    out var mappedCloneAddressFileOffset)
                || mappedCloneAddress != tableClones[0].OutputRange.VirtualAddress
                || mappedCloneAddressFileOffset != tableClones[0].OutputRange.FileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutPostValidationFailed,
                    "A jump-table clone is not a distinct PF_R-only mapping, or the original table bytes/address were not preserved.",
                    tableRange.FileOffset.Value);
                return false;
            }

            for (var ordinal = 0; ordinal < ordered.Length; ordinal++)
            {
                var binding = ordered[ordinal];
                var entry = binding.SourceEntryRange;
                var outputEntry = binding.OutputEntryRange;
                var width = binding.EntryWidth;
                var delta = checked((ulong)ordinal * (ulong)width);
                if (binding.EntryIndex < first.EntryIndex
                    || binding.EntryIndex - first.EntryIndex != ordinal
                    || binding.EntryIdentity.Kind != SemanticEntityKind.TableEntry
                    || binding.EntryIdentity != SemanticEntityId.TableEntry(
                        $"{binding.TableIdentity.Value}:{binding.EntryIndex}")
                    || string.IsNullOrWhiteSpace(binding.TargetIdentity.Value)
                    || !entryIdentities.Add(binding.EntryIdentity)
                    || binding.SourceTableRange != tableRange
                    || binding.EntryWidth is not (1 or 2 or 4 or 8)
                    || binding.Scale <= 0
                    || entry.Size != (ulong)width
                    || delta > ulong.MaxValue - tableRange.FileOffset.Value
                    || delta > ulong.MaxValue - tableRange.VirtualAddress.Value
                    || entry.FileOffset.Value != tableRange.FileOffset.Value + delta
                    || entry.VirtualAddress.Value != tableRange.VirtualAddress.Value + delta
                    || !entry.TryGetFileEnd(out var entryEnd)
                    || entryEnd > (ulong)sourceFile.Bytes.Length
                    || entry.FileOffset.Value > int.MaxValue
                    || outputEntry.Size != (ulong)width
                    || !boundEntryOffsets.Add(outputEntry.FileOffset.Value))
                {
                    diagnostics.Error(
                        DiagnosticCode.ElfLayoutPostValidationFailed,
                        "A jump-table target binding has a missing, duplicate, or mismatched source entry identity/index/range.",
                        entry.FileOffset.Value);
                    return false;
                }

                if (!TryReadJumpTableValue(
                        sourceFile.Bytes.Span.Slice(checked((int)entry.FileOffset.Value), width),
                        binding.IsSigned,
                        out var sourceEncoded)
                    || sourceEncoded != binding.SourceEncodedValue
                    || !TryGetRelativeEntryValue(
                        binding.SourceTargetAddress.Value,
                        binding.SourceTargetBaseAddress.Value,
                        binding.Addend,
                        binding.Scale,
                        binding.IsSigned,
                        width,
                        out var sourceValueFromAddresses)
                    || sourceValueFromAddresses != sourceEncoded)
                {
                    diagnostics.Error(
                        DiagnosticCode.ElfLayoutPostValidationFailed,
                        "A jump-table target binding does not agree with the retained source entry bytes and source target/base addresses.",
                        entry.FileOffset.Value);
                    return false;
                }

                if (!TryMapPhysicalAddress(
                        plan.AddressMap,
                        binding.SourceTargetAddress,
                        out var mappedOutputTarget,
                        out var mappedOutputTargetFileOffset,
                        binding.TargetIdentity)
                    || mappedOutputTarget != binding.OutputTargetAddress
                    || !TryMapPhysicalAddress(
                        plan.AddressMap,
                        binding.SourceTargetBaseAddress,
                        out var mappedOutputBase,
                        out var mappedOutputBaseFileOffset,
                        binding.TargetBaseIdentity)
                    || mappedOutputBase != binding.OutputTargetBaseAddress
                    || !TryGetFileBackedExecutableOffset(
                        sourceFile,
                        binding.SourceTargetAddress,
                        sizeof(uint),
                        out _)
                    || !TryGetFileBackedExecutableOffset(
                        outputFile,
                        binding.OutputTargetAddress,
                        sizeof(uint),
                        out var outputTargetFileOffset)
                    || outputTargetFileOffset != mappedOutputTargetFileOffset
                    || !TryGetFileBackedExecutableOffset(
                        outputFile,
                        binding.OutputTargetBaseAddress,
                        sizeof(uint),
                        out var outputBaseFileOffset)
                    || outputBaseFileOffset != mappedOutputBaseFileOffset)
                {
                    diagnostics.Error(
                        DiagnosticCode.ElfLayoutPostValidationFailed,
                        "A jump-table target binding is not uniquely mapped from source to file-backed executable output.",
                        entry.FileOffset.Value);
                    return false;
                }

                if (!TryGetRelativeEntryValue(
                        binding.OutputTargetAddress.Value,
                        binding.OutputTargetBaseAddress.Value,
                        binding.Addend,
                        binding.Scale,
                        binding.IsSigned,
                        width,
                        out var outputValueFromAddresses)
                    || outputValueFromAddresses != binding.OutputEncodedValue)
                {
                    diagnostics.Error(
                        DiagnosticCode.ElfLayoutPostValidationFailed,
                        "A jump-table target binding's output target/base do not reproduce its encoded entry value.",
                        entry.FileOffset.Value);
                    return false;
                }

                var tableEdits = plan.JumpTableEdits.Where(edit =>
                    edit.Kind == ElfLayoutEditKind.JumpTableEntry
                    && edit.Offset == outputEntry.FileOffset).ToArray();
                var materializedEdits = plan.Edits.Where(edit =>
                    edit.Kind == ElfLayoutEditKind.JumpTableEntry
                    && edit.Offset == outputEntry.FileOffset).ToArray();
                if (tableEdits.Length != 1
                    || materializedEdits.Length != 1
                    || tableEdits[0].Bytes.Length != width
                    || !tableEdits[0].Bytes.AsSpan().SequenceEqual(materializedEdits[0].Bytes)
                    || !TryReadJumpTableValue(tableEdits[0].Bytes, binding.IsSigned, out var editValue)
                    || editValue != binding.OutputEncodedValue
                    || outputEntry.FileOffset.Value > int.MaxValue
                    || !TryGetFileBackedReadOnlyOffset(
                        outputFile,
                        outputEntry.VirtualAddress,
                        checked((ulong)width),
                        out var outputEntryFileOffset)
                    || outputEntryFileOffset != outputEntry.FileOffset
                    || !output.AsSpan(checked((int)outputEntry.FileOffset.Value), width)
                        .SequenceEqual(tableEdits[0].Bytes))
                {
                    diagnostics.Error(
                        DiagnosticCode.ElfLayoutPostValidationFailed,
                        "A jump-table target binding does not match exactly one planned edit and its materialized clone bytes.",
                        outputEntry.FileOffset.Value);
                    return false;
                }
            }
        }

        if (!boundEntryOffsets.SetEquals(tableEditOffsets))
        {
            diagnostics.Error(
                DiagnosticCode.ElfLayoutPostValidationFailed,
                "Jump-table target bindings do not form a one-to-one mapping to materialized table edit offsets.");
            return false;
        }

        return true;
    }

    private static bool TryMapPhysicalAddress(
        IReadOnlyList<ElfLayoutAddressMapEntry> addressMap,
        VirtualAddress sourceAddress,
        out VirtualAddress outputAddress,
        out FileOffset outputFileOffset,
        SemanticEntityId? expectedIdentity = null)
    {
        VirtualAddress? mappedAddress = null;
        FileOffset? mappedFileOffset = null;
        foreach (var entry in addressMap)
        {
            if (expectedIdentity is { } identity
                && !string.Equals(entry.Identity, identity.Value, StringComparison.Ordinal))
            {
                continue;
            }

            if (entry.SourceRange is not { } sourceRange
                || sourceAddress.Value < sourceRange.VirtualAddress.Value
                || sourceAddress.Value - sourceRange.VirtualAddress.Value >= sourceRange.Size)
            {
                continue;
            }

            var delta = sourceAddress.Value - sourceRange.VirtualAddress.Value;
            if (delta >= entry.OutputRange.Size
                || entry.OutputRange.VirtualAddress.Value > ulong.MaxValue - delta
                || entry.OutputRange.FileOffset.Value > ulong.MaxValue - delta
                || mappedAddress is not null)
            {
                outputAddress = default;
                outputFileOffset = default;
                return false;
            }

            mappedAddress = new VirtualAddress(entry.OutputRange.VirtualAddress.Value + delta);
            mappedFileOffset = new FileOffset(entry.OutputRange.FileOffset.Value + delta);
        }

        outputAddress = mappedAddress.GetValueOrDefault();
        outputFileOffset = mappedFileOffset.GetValueOrDefault();
        return mappedAddress is not null && mappedFileOffset is not null;
    }

    private static bool TryGetFileBackedExecutableOffset(
        ElfFile file,
        VirtualAddress address,
        ulong size,
        out FileOffset fileOffset)
    {
        if (!file.LoadMap.TryVirtualAddressToFileOffset(address, size, out fileOffset))
        {
            return false;
        }

        var mappedFileOffset = fileOffset.Value;
        return file.LoadMap.Segments.Count(segment =>
            segment.IsExecutable
            && segment.ContainsVirtualAddress(address.Value, size)
            && segment.ContainsFileOffset(mappedFileOffset, size)) == 1;
    }

    private static bool TryGetFileBackedReadOnlyOffset(
        ElfFile file,
        VirtualAddress address,
        ulong size,
        out FileOffset fileOffset)
    {
        if (!file.LoadMap.TryVirtualAddressToFileOffset(address, size, out fileOffset))
        {
            return false;
        }

        var mappedFileOffset = fileOffset.Value;
        return file.LoadMap.Segments.Count(segment =>
            (segment.Flags & ElfConstants.PfR) != 0
            && (segment.Flags & (ElfConstants.PfW | ElfConstants.PfX)) == 0
            && segment.ContainsVirtualAddress(address.Value, size)
            && segment.ContainsFileOffset(mappedFileOffset, size)) == 1;
    }

    private static bool TryReadJumpTableValue(
        ReadOnlySpan<byte> bytes,
        bool isSigned,
        out long value)
    {
        value = default;
        switch (bytes.Length)
        {
            case 1:
                value = isSigned ? unchecked((sbyte)bytes[0]) : bytes[0];
                return true;
            case 2:
                value = isSigned
                    ? BinaryPrimitives.ReadInt16LittleEndian(bytes)
                    : BinaryPrimitives.ReadUInt16LittleEndian(bytes);
                return true;
            case 4:
                value = isSigned
                    ? BinaryPrimitives.ReadInt32LittleEndian(bytes)
                    : BinaryPrimitives.ReadUInt32LittleEndian(bytes);
                return true;
            case 8:
                if (isSigned)
                {
                    value = BinaryPrimitives.ReadInt64LittleEndian(bytes);
                    return true;
                }

                var unsigned = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
                if (unsigned > long.MaxValue)
                {
                    return false;
                }

                value = checked((long)unsigned);
                return true;
            default:
                return false;
        }
    }

    private static bool TryGetRelativeEntryValue(
        ulong target,
        ulong targetBase,
        long addend,
        int scale,
        bool isSigned,
        int width,
        out long encoded)
    {
        encoded = default;
        if (scale <= 0
            || width is not (1 or 2 or 4 or 8)
            || !TryGetSignedDelta(target, targetBase, out var delta)
            || !TrySubtractSigned(delta, addend, out var adjusted)
            || adjusted % scale != 0)
        {
            return false;
        }

        encoded = adjusted / scale;
        var bits = checked(width * 8);
        if (isSigned)
        {
            var minimum = bits == 64 ? long.MinValue : -(1L << (bits - 1));
            var maximum = bits == 64 ? long.MaxValue : (1L << (bits - 1)) - 1;
            return encoded >= minimum && encoded <= maximum;
        }

        return encoded >= 0 && (width == 8 || (ulong)encoded <= ((1UL << bits) - 1));
    }

    private static bool TryGetSignedDelta(ulong left, ulong right, out long delta)
    {
        if (left >= right)
        {
            var difference = left - right;
            if (difference > long.MaxValue)
            {
                delta = default;
                return false;
            }

            delta = checked((long)difference);
            return true;
        }

        var negativeDifference = right - left;
        if (negativeDifference > (1UL << 63))
        {
            delta = default;
            return false;
        }

        delta = negativeDifference == (1UL << 63)
            ? long.MinValue
            : -checked((long)negativeDifference);
        return true;
    }

    private static bool TrySubtractSigned(long value, long subtrahend, out long result)
    {
        if ((subtrahend > 0 && value < long.MinValue + subtrahend)
            || (subtrahend < 0 && value > long.MaxValue + subtrahend))
        {
            result = default;
            return false;
        }

        result = value - subtrahend;
        return true;
    }

    private static string? TryGetDynamicSymbolName(ElfFile file, uint symbolIndex)
    {
        if (symbolIndex >= file.DynamicSymbols.Count)
        {
            return null;
        }

        var symbol = file.DynamicSymbols[(int)symbolIndex];
        return ElfParserUtilities.TryReadString(file.DynamicMetadata.StringTable, symbol.Name, out var name)
            ? name
            : null;
    }

    private static bool TryGetBranchEncoding(
        ElfLayoutPlan plan,
        ElfBranchPlacementDecision decision,
        out byte[] expected)
    {
        expected = Array.Empty<byte>();
        if (decision.SourceRange.Size != sizeof(uint)
            || !ElfLayoutBranchEncoding.TryEncode(
                decision.Opcode,
                decision.SourceRange.VirtualAddress.Value,
                decision.TargetRange.VirtualAddress.Value,
                out expected,
                out _))
        {
            return false;
        }

        var expectedBytes = expected;
        return plan.Edits.Any(edit =>
            edit.Kind == ElfLayoutEditKind.BranchFixup
            && edit.Offset == decision.SourceRange.FileOffset
            && edit.Bytes.AsSpan().SequenceEqual(expectedBytes));
    }

    private static bool TryAdd(ulong value, ulong amount, out ulong result)
    {
        if (amount > ulong.MaxValue - value)
        {
            result = 0;
            return false;
        }

        result = value + amount;
        return true;
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

}
