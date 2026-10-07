using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.SemanticPlanning;

namespace UrProtect.Core.ElfLayout;

public static class ElfLayoutMaterializer
{
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
            || plan.TlsFixups is null)
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
            if (fixup.AccessModel is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec)
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
                            or ElfConstants.RArm64TlsIeLd64GottprelLo12Nc))))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSemanticsUnsupported,
                    "Materialization received a TLS output fixup outside the supported local-exec or TLSIE MOVW subset.",
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
            if (regionPlacements.Length != 1
                || logicalFileDelta != logicalVirtualDelta
                || decision.OutputFileOffset.Value < regionPlacements[0].FileOffset.Value
                || decision.OutputVirtualAddress.Value < regionPlacements[0].VirtualAddress.Value
                || decision.OutputFileOffset.Value - regionPlacements[0].FileOffset.Value != logicalFileDelta
                || decision.OutputVirtualAddress.Value - regionPlacements[0].VirtualAddress.Value != logicalVirtualDelta)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The physical local-exec TLS output site does not match its semantic source-to-output address map.",
                    fixup.RelocationSourceRange.FileOffset.Value);
                return false;
            }

            var sourceMatches = sourceFile.TlsMetadata.StaticRelocations
                .Concat(sourceFile.TlsMetadata.Dynamic.Relocations)
                .Where(fact => fact.Relocation.Offset == fixup.RelocationSourceRange.VirtualAddress.Value
                    && fact.Relocation.Type == relocationType
                    && fact.Relocation.Info == relocation.RawInfo
                    && fact.Relocation.SymbolIndex == relocation.SymbolIndex
                    && fact.Relocation.Addend == relocation.Addend
                    && fact.Relocation.SourceAddress == relocation.RelocationTableAddress?.Value
                    && fact.WriteSize == fixup.RelocationSourceRange.Size
                    && fact.Symbol?.Name == relocation.SymbolName)
                .ToArray();
            if (sourceMatches.Length != 1)
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
            && ValidateInitialExecAdrLd64FixupPairs(sourceFile, outputFile, plan, output, diagnostics);
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
                        requireSourceLow12Zero: true)
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
                && fact.Symbol.SymbolIndex == gotEntry.Symbol.SymbolIndex
                && string.Equals(fact.Symbol.Name, gotEntry.Symbol.Name, StringComparison.Ordinal))
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

    private static bool TryGetBranchEncoding(
        ElfLayoutPlan plan,
        ElfBranchPlacementDecision decision,
        out byte[] expected)
    {
        expected = Array.Empty<byte>();
        if (decision.Displacement is not long displacement
            || decision.SourceRange.Size != sizeof(uint)
            || !ElfLayoutPlannerTryEncode(decision.Opcode, displacement, out expected))
        {
            return false;
        }

        var expectedBytes = expected;
        return plan.Edits.Any(edit =>
            edit.Kind == ElfLayoutEditKind.BranchFixup
            && edit.Offset == decision.SourceRange.FileOffset
            && edit.Bytes.AsSpan().SequenceEqual(expectedBytes));
    }

    private static bool ElfLayoutPlannerTryEncode(uint opcode, long displacement, out byte[] encoding)
    {
        encoding = Array.Empty<byte>();
        if ((opcode & 0xFC000000u) is not (0x14000000u or 0x94000000u)
            || displacement < ElfLayoutLimits.Branch26MinimumDisplacement
            || displacement >= ElfLayoutLimits.Branch26MaximumDisplacementExclusive
            || (displacement & 3) != 0)
        {
            return false;
        }

        encoding = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(encoding, (opcode & 0xFC000000u) | (uint)((displacement >> 2) & 0x03FFFFFF));
        return true;
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
