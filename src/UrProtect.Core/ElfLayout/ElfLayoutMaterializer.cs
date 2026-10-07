using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

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
            || plan.Edits is null)
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

            if (!ValidateParsedOutput(sourceFile, parsed.File, plan, output, diagnostics))
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
                plan.BranchDecisions);
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
