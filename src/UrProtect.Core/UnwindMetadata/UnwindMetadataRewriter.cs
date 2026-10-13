using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.UnwindMetadata;

public sealed record UnwindFdeRewrite(
    FileRange SourceRecord,
    FileRange OutputRecord,
    SemanticSourceRange SourceCodeRange,
    SemanticSourceRange OutputCodeRange,
    bool IsChanged);

public sealed record UnwindMetadataRewriteResult(
    UnwindMetadataModel? SourceModel,
    byte[]? EhFrameBytes,
    byte[]? EhFrameHeaderBytes,
    IReadOnlyList<ElfLayoutByteEdit> Edits,
    IReadOnlyList<UnwindFdeRewrite> FdeRewrites,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => SourceModel is not null
        && EhFrameBytes is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public static class UnwindMetadataRewriter
{
    public static UnwindMetadataRewriteResult Rewrite(
        ElfFile sourceFile,
        AddressMap addressMap,
        IEnumerable<SemanticCfiEffectExtension>? cfiEffects = null)
    {
        ArgumentNullException.ThrowIfNull(sourceFile);
        ArgumentNullException.ThrowIfNull(addressMap);
        var diagnostics = new DiagnosticBag();
        var parsed = UnwindMetadataParser.Parse(sourceFile);
        diagnostics.AddRange(parsed.Diagnostics);
        if (parsed.Model is null || parsed.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return Failure(null, diagnostics);
        }

        var model = parsed.Model;
        var effects = (cfiEffects ?? Array.Empty<SemanticCfiEffectExtension>()).ToArray();
        if (effects.Length > UnwindMetadataLimits.MaximumCfiEffects)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The CFI effect stream exceeds its configured bound.");
            return Failure(model, diagnostics);
        }

        var fdeTransforms = new Dictionary<ulong, FdeTransform>();
        foreach (var fde in model.Fdes)
        {
            if (!TryGetCodeRange(sourceFile, fde, out var sourceRange))
            {
                if (addressMap.TryMapSourceAddress(new VirtualAddress(fde.InitialLocation), out _))
                {
                    diagnostics.Error(
                        DiagnosticCode.UnwindAddressMapMissing,
                        "An FDE range is not file-mapped through the source load map.",
                        fde.EntryOffset.Value);
                }

                continue;
            }

            if (!addressMap.TryMapSourceRangeToContainingOutput(
                    sourceRange,
                    SemanticEntityKind.Function,
                    out var outputRange))
            {
                if (addressMap.TryMapSourceAddress(new VirtualAddress(fde.InitialLocation), out _))
                {
                    diagnostics.Error(
                        DiagnosticCode.UnwindAddressMapMissing,
                        "An FDE range is not contained by one selected output mapping.",
                        fde.EntryOffset.Value);
                }

                continue;
            }

            var matchingEffects = effects
                .Where(effect => RangesOverlap(
                    effect.SourceRange.VirtualAddress.Value,
                    effect.SourceRange.Size,
                    sourceRange.VirtualAddress.Value,
                    sourceRange.Size))
                .OrderBy(effect => effect.SourceRange.VirtualAddress.Value)
                .ToArray();
            if (outputRange == sourceRange && matchingEffects.Length == 0)
            {
                continue;
            }

            if (fde.Instructions.Any(instruction => instruction.Kind == UnwindInstructionKind.Unsupported))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataUnsupported,
                    "An FDE selected for rewriting contains opaque CFI instructions.",
                    fde.EntryOffset.Value);
                continue;
            }

            var cie = model.Cies.FirstOrDefault(candidate => candidate.EntryOffset.Value == fde.CieEntryOffset.Value);
            if (cie is null)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "An FDE transform has no parsed CIE owner.",
                    fde.EntryOffset.Value);
                continue;
            }

            fdeTransforms[fde.EntryOffset.Value] = new FdeTransform(
                sourceRange,
                outputRange,
                matchingEffects,
                cie.FdePointerEncoding ?? new UnwindEncoding(0),
                cie.CodeAlignmentFactor,
                addressMap);
        }

        if (diagnostics.HasErrors)
        {
            return Failure(model, diagnostics);
        }

        var outputRecords = new List<OutputRecord>();
        var outputFdeOffsets = new Dictionary<ulong, ulong>();
        var records = model.Cies
            .Select(cie => new InputRecord(cie.EntryOffset.Value, cie.RecordRange, cie.RawBytes.ToArray(), null, null))
            .Concat(model.Fdes.Select(fde => new InputRecord(
                fde.EntryOffset.Value,
                fde.RecordRange,
                fde.RawBytes.ToArray(),
                fde,
                fdeTransforms.TryGetValue(fde.EntryOffset.Value, out var transform)
                    ? transform
                    : null)))
            .OrderBy(record => record.Offset)
            .ToArray();

        var sourceCursor = 0UL;
        var outputOffset = 0UL;
        foreach (var record in records)
        {
            if (record.Offset < model.EhFrameSection.Offset)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "An unwind record starts before its bounded .eh_frame section.",
                    record.Offset);
                return Failure(model, diagnostics);
            }

            var recordOffset = checked(record.Offset - model.EhFrameSection.Offset);
            if (recordOffset < sourceCursor
                || recordOffset > (ulong)model.EhFrameBytes.Length
                || record.RawBytes.Length > model.EhFrameBytes.Length - checked((int)recordOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "Unwind records overlap or exceed the bounded .eh_frame section.",
                    record.Offset);
                return Failure(model, diagnostics);
            }

            var gapLength = checked((int)(recordOffset - sourceCursor));
            if (gapLength > 0)
            {
                var gap = model.EhFrameBytes.Slice(checked((int)sourceCursor), gapLength).ToArray();
                outputRecords.Add(new OutputRecord(null, outputOffset, gap));
                outputOffset = checked(outputOffset + (ulong)gap.Length);
            }

            byte[] bytes;
            if (record.Fde is { } fde && record.Transform is { } transform)
            {
                if (!TryBuildFdeRecord(model.EhFrameSection, fde, transform, out bytes, diagnostics))
                {
                    return Failure(model, diagnostics);
                }
            }
            else
            {
                bytes = record.RawBytes;
            }

            outputRecords.Add(new OutputRecord(record, outputOffset, bytes));
            if (record.Fde is not null)
            {
                outputFdeOffsets[record.Offset] = outputOffset;
            }

            outputOffset = checked(outputOffset + (ulong)bytes.Length);
            sourceCursor = checked(recordOffset + (ulong)record.RawBytes.Length);
        }

        if (sourceCursor > (ulong)model.EhFrameBytes.Length)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The parsed .eh_frame records exceed their bounded section bytes.",
                model.EhFrameSection.Offset);
            return Failure(model, diagnostics);
        }

        var trailing = model.EhFrameBytes.Span[checked((int)sourceCursor)..].ToArray();
        var ehFrameBytes = new byte[checked((int)(outputOffset + checked((ulong)trailing.Length)))];
        var writeOffset = 0;
        foreach (var record in outputRecords)
        {
            record.Bytes.CopyTo(ehFrameBytes, writeOffset);
            writeOffset += record.Bytes.Length;
        }

        trailing.CopyTo(ehFrameBytes, writeOffset);
        if (ehFrameBytes.Length != model.EhFrameBytes.Length)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataUnsupported,
                "The bounded unwind rewriter cannot change .eh_frame section length without a coordinated section/layout update.",
                model.EhFrameSection.Offset);
            return Failure(model, diagnostics);
        }

        var headerBytes = model.Header is null
            ? null
            : RewriteHeader(
                model,
                outputFdeOffsets,
                fdeTransforms,
                diagnostics);

        if (diagnostics.HasErrors)
        {
            return Failure(model, diagnostics);
        }

        var fdeRewrites = model.Fdes
            .Where(fde => fdeTransforms.ContainsKey(fde.EntryOffset.Value))
            .Select(fde =>
            {
                var transform = fdeTransforms[fde.EntryOffset.Value];
                var outputRecord = outputRecords.Single(record => record.Input?.Offset == fde.EntryOffset.Value);
                return new UnwindFdeRewrite(
                    fde.RecordRange,
                    new FileRange(
                        checked(model.EhFrameSection.Offset + outputRecord.OutputOffset),
                        (ulong)outputRecord.Bytes.Length),
                    transform.SourceRange,
                    transform.OutputRange,
                    !transform.SourceRange.Equals(transform.OutputRange)
                        || transform.Effects.Length != 0);
            })
            .ToArray();

        var edits = new List<ElfLayoutByteEdit>();
        if (!ehFrameBytes.AsSpan().SequenceEqual(model.EhFrameBytes.Span))
        {
            edits.Add(new ElfLayoutByteEdit(
                new FileOffset(model.EhFrameSection.Offset),
                ehFrameBytes,
                ElfLayoutEditKind.UnwindMetadata));
        }

        if (headerBytes is not null
            && !headerBytes.AsSpan().SequenceEqual(model.EhFrameHeaderBytes.Span))
        {
            edits.Add(new ElfLayoutByteEdit(
                new FileOffset(model.EhFrameHeaderSection!.Value.Offset),
                headerBytes,
                ElfLayoutEditKind.UnwindMetadata));
        }

        return new UnwindMetadataRewriteResult(
            model,
            ehFrameBytes,
            headerBytes,
            edits.AsReadOnly(),
            fdeRewrites,
            diagnostics.ToArray());
    }

    private static byte[]? RewriteHeader(
        UnwindMetadataModel model,
        Dictionary<ulong, ulong> outputFdeOffsets,
        IReadOnlyDictionary<ulong, FdeTransform> transforms,
        DiagnosticBag diagnostics)
    {
        var header = model.Header!;
        var bytes = header.RawBytes.ToArray();
        var cursor = 4;
        if (!TrySkipEncoded(header.EhFramePointerEncoding, bytes, ref cursor)
            || !TrySkipEncoded(header.FdeCountEncoding, bytes, ref cursor))
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataUnsupported,
                "CFI header rewriting requires fixed-width pointer encodings.",
                header.SectionRange.Offset);
            return null;
        }

        var fdesByAddress = model.Fdes.ToDictionary(
            fde => checked(model.EhFrameSection.Address
                + (fde.EntryOffset.Value - model.EhFrameSection.Offset)),
            fde => fde);
        var orderedEntries = header.Entries
            .Select(entry =>
            {
                if (!fdesByAddress.TryGetValue(entry.FdeAddress, out var fde)
                    || !outputFdeOffsets.TryGetValue(fde.EntryOffset.Value, out var outputOffset))
                {
                    return (Entry: entry, Fde: (UnwindFde?)null, InitialLocation: entry.InitialLocation, FdeAddress: entry.FdeAddress);
                }

                var initialLocation = transforms.TryGetValue(fde.EntryOffset.Value, out var transform)
                    ? transform.OutputRange.VirtualAddress.Value
                    : entry.InitialLocation;
                return (
                    Entry: entry,
                    Fde: fde,
                    InitialLocation: initialLocation,
                    FdeAddress: checked(model.EhFrameSection.Address + outputOffset));
            })
            .OrderBy(item => item.InitialLocation)
            .ThenBy(item => item.FdeAddress)
            .ToArray();

        if (orderedEntries.Any(item => item.Fde is null))
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The .eh_frame_hdr table contains an entry without a parsed FDE owner.",
                header.SectionRange.Offset);
            return null;
        }

        for (var index = 0; index < orderedEntries.Length; index++)
        {
            var initialOffset = cursor;
            if (!TryGetEncodedWidth(header.TableEncoding, bytes, cursor, out var initialWidth)
                || !TryGetEncodedWidth(header.TableEncoding, bytes, cursor + initialWidth, out var fdeWidth))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataUnsupported,
                    "CFI header table rewriting requires fixed-width pointer encodings.",
                    header.SectionRange.Offset);
                return null;
            }

            var initialFieldAddress = checked(header.SectionRange.Offset
                - model.EhFrameHeaderSection!.Value.Offset
                + model.EhFrameHeaderSection.Value.Address
                + (ulong)initialOffset);
            var fdeFieldAddress = checked(initialFieldAddress + (ulong)initialWidth);
            var ordered = orderedEntries[index];
            if (!TryWriteEncoded(
                    header.TableEncoding,
                    bytes,
                    initialOffset,
                    initialFieldAddress,
                    header.SectionRange.Offset
                        - model.EhFrameHeaderSection.Value.Offset
                        + model.EhFrameHeaderSection.Value.Address,
                    ordered.InitialLocation)
                || !TryWriteEncoded(
                    header.TableEncoding,
                    bytes,
                    initialOffset + initialWidth,
                    fdeFieldAddress,
                    header.SectionRange.Offset
                        - model.EhFrameHeaderSection.Value.Offset
                        + model.EhFrameHeaderSection.Value.Address,
                    ordered.FdeAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataUnsupported,
                    "A mapped FDE cannot be represented by the existing .eh_frame_hdr encodings.",
                    header.SectionRange.Offset);
                return null;
            }

            cursor = checked(cursor + initialWidth + fdeWidth);
        }

        return bytes;
    }

    private static bool TryBuildFdeRecord(
        SectionHeader ehFrameSection,
        UnwindFde fde,
        FdeTransform? transform,
        out byte[] bytes,
        DiagnosticBag diagnostics)
    {
        bytes = fde.RawBytes.ToArray();
        if (transform is null)
        {
            return true;
        }

        var prefixLength = GetLengthPrefixSize(bytes);
        if (prefixLength == 0
            || fde.CieEntryOffset.Value < ehFrameSection.Offset
            || fde.EntryOffset.Value < ehFrameSection.Offset)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "An FDE record has an invalid bounded length prefix.",
                fde.EntryOffset.Value);
            return false;
        }

        var identifierRecordOffset = checked((int)(
            fde.CieEntryOffset.Value == fde.CieEntryOffset.Value
                ? prefixLength
                : prefixLength));
        var initialOffset = checked(identifierRecordOffset + sizeof(uint));
        var pointerEncoding = transform.PointerEncoding;
        var initialWidth = GetFixedWidth(pointerEncoding);
        if (initialWidth == 0
            || initialOffset + initialWidth > bytes.Length)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataUnsupported,
                "An FDE initial-location encoding is not fixed-width.",
                fde.EntryOffset.Value);
            return false;
        }

        var instructionOffset = fde.Instructions.Count == 0
            ? bytes.Length
            : checked((int)(fde.Instructions[0].FileOffset - fde.EntryOffset.Value));
        if (instructionOffset < initialOffset + initialWidth
            || instructionOffset > bytes.Length)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "An FDE instruction range is outside its bounded record.",
                fde.EntryOffset.Value);
            return false;
        }

        var instructionBytes = BuildInstructionBytes(
            fde,
            transform,
            diagnostics);
        if (instructionBytes is null
            || instructionBytes.Length != bytes.Length - instructionOffset)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataUnsupported,
                "The bounded FDE rewriter cannot change an FDE record length.",
                fde.EntryOffset.Value);
            return false;
        }

        bytes = new byte[checked(instructionOffset + instructionBytes.Length)];
        fde.RawBytes.Span[..instructionOffset].CopyTo(bytes);
        instructionBytes.CopyTo(bytes, instructionOffset);
        var initialFieldAddress = checked(
            ehFrameSection.Address
                + (fde.EntryOffset.Value - ehFrameSection.Offset)
                + (ulong)initialOffset);
        if (!TryWriteEncoded(
                pointerEncoding,
                bytes,
                initialOffset,
                initialFieldAddress,
                ehFrameSection.Address,
                transform.OutputRange.VirtualAddress.Value)
            || !TryWriteEncoded(
                new UnwindEncoding((byte)(pointerEncoding.Raw & 0x0F)),
                bytes,
                initialOffset + initialWidth,
                checked(initialFieldAddress + (ulong)initialWidth),
                ehFrameSection.Address,
                transform.OutputRange.Size))
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataUnsupported,
                "The mapped FDE location or range cannot be represented by its CIE encoding.",
                fde.EntryOffset.Value);
            return false;
        }

        return TryWriteRecordLength(bytes, prefixLength, diagnostics, fde.EntryOffset.Value);
    }

    private static byte[]? BuildInstructionBytes(
        UnwindFde fde,
        FdeTransform transform,
        DiagnosticBag diagnostics)
    {
        var effects = transform.Effects;
        var result = new List<byte>();
        var pending = effects.ToList();
        var sourceCurrent = fde.InitialLocation;
        var outputCurrent = transform.OutputRange.VirtualAddress.Value;

        foreach (var instruction in fde.Instructions)
        {
            var replaced = false;
            while (pending.Count > 0
                && pending[0].SourceRange.VirtualAddress.Value == sourceCurrent)
            {
                var encoded = new List<byte>();
                if (!TryEncodeEffect(pending[0], encoded, diagnostics)
                    || encoded.Count != instruction.RawBytes.Length)
                {
                    diagnostics.Error(
                        DiagnosticCode.UnwindMetadataUnsupported,
                        "A canonical CFI effect cannot replace the existing bounded instruction width.",
                        pending[0].SourceRange.FileOffset.Value);
                    return null;
                }

                result.AddRange(encoded);
                pending.RemoveAt(0);
                replaced = true;
            }

            if (replaced)
            {
                // The effect owns this CFI instruction boundary. In
                // particular, replacing an advance opcode must not also emit
                // the original advance, or the bounded FDE length changes.
                continue;
            }

            if (instruction.Kind == UnwindInstructionKind.AdvanceLocation)
            {
                var sourceDelta = checked(instruction.Operand * (ulong)transform.CodeAlignmentFactor);
                var sourceNext = checked(sourceCurrent + sourceDelta);
                if (!TryMapCfiLocation(transform, sourceNext, out var outputNext)
                    || !TryEncodeAdvanceLocation(
                        instruction.RawBytes.Span,
                        outputNext - outputCurrent,
                        transform.CodeAlignmentFactor,
                        result))
                {
                    diagnostics.Error(
                        DiagnosticCode.UnwindAddressMapMissing,
                        "A CFI location transition has no representable output address mapping.",
                        instruction.FileOffset);
                    return null;
                }

                sourceCurrent = sourceNext;
                outputCurrent = outputNext;
                continue;
            }

            result.AddRange(instruction.RawBytes.ToArray());
        }

        while (pending.Count > 0 && pending[0].SourceRange.VirtualAddress.Value == sourceCurrent)
        {
            if (!TryEncodeEffect(pending[0], result, diagnostics))
            {
                return null;
            }

            pending.RemoveAt(0);
        }

        if (pending.Count != 0)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindAddressMapMissing,
                "A CFI effect does not land on an existing CFI instruction boundary.",
                pending[0].SourceRange.FileOffset.Value);
            return null;
        }

        return result.ToArray();
    }

    private static bool TryMapCfiLocation(
        FdeTransform transform,
        ulong sourceAddress,
        out ulong outputAddress)
    {
        if (transform.SourceRange.Size <= ulong.MaxValue - transform.SourceRange.VirtualAddress.Value
            && sourceAddress == transform.SourceRange.VirtualAddress.Value + transform.SourceRange.Size)
        {
            if (transform.OutputRange.Size > ulong.MaxValue - transform.OutputRange.VirtualAddress.Value)
            {
                outputAddress = default;
                return false;
            }

            outputAddress = transform.OutputRange.VirtualAddress.Value + transform.OutputRange.Size;
            return true;
        }

        if (!transform.AddressMap.TryMapSourceAddress(
                new VirtualAddress(sourceAddress),
                out var mapped))
        {
            outputAddress = default;
            return false;
        }

        outputAddress = mapped.Value;
        return true;
    }
    private static bool TryEncodeAdvanceLocation(
        ReadOnlySpan<byte> raw,
        ulong byteDelta,
        long codeAlignmentFactor,
        List<byte> destination)
    {
        if (codeAlignmentFactor <= 0
            || byteDelta % checked((ulong)codeAlignmentFactor) != 0)
        {
            return false;
        }

        var units = byteDelta / checked((ulong)codeAlignmentFactor);
        if (raw.Length == 1 && units <= 63)
        {
            destination.Add((byte)(0x40U + units));
            return true;
        }

        if (raw.Length == 2 && units <= byte.MaxValue)
        {
            destination.Add(0x02);
            destination.Add((byte)units);
            return true;
        }

        if (raw.Length == 3 && units <= ushort.MaxValue)
        {
            destination.Add(0x03);
            destination.Add((byte)units);
            destination.Add((byte)(units >> 8));
            return true;
        }

        if (raw.Length == 5 && units <= uint.MaxValue)
        {
            destination.Add(0x04);
            destination.AddRange(BitConverter.GetBytes(checked((uint)units)));
            return true;
        }

        return false;
    }

    private static bool TryEncodeEffect(
        SemanticCfiEffectExtension effect,
        List<byte> destination,
        DiagnosticBag diagnostics)
    {
        if (string.Equals(effect.Effect, "nop", StringComparison.Ordinal))
        {
            destination.Add(0);
            return true;
        }

        const string prefix = "cfa=sp+";
        if (!effect.Effect.StartsWith(prefix, StringComparison.Ordinal)
            || !ulong.TryParse(effect.Effect.AsSpan(prefix.Length), out var offset)
            || offset > UnwindMetadataLimits.MaximumCfiOffset)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataUnsupported,
                $"The CFI effect '{effect.Effect}' has no bounded encoder.",
                effect.SourceRange.FileOffset.Value);
            return false;
        }

        destination.Add(0x0C);
        destination.Add(0x1F);
        WriteUleb(destination, offset);
        return true;
    }

    private static bool TryGetCodeRange(
        ElfFile sourceFile,
        UnwindFde fde,
        out SemanticSourceRange range)
    {
        range = default;
        if (fde.AddressRange == 0
            || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(fde.InitialLocation),
                fde.AddressRange,
                out var fileOffset))
        {
            return false;
        }

        range = new SemanticSourceRange(
            fileOffset,
            new VirtualAddress(fde.InitialLocation),
            fde.AddressRange);
        return true;
    }

    private static bool TryWriteRecordLength(
        byte[] bytes,
        int prefixLength,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        var contentLength = checked(bytes.Length - prefixLength);
        if (prefixLength == sizeof(uint))
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes, checked((uint)contentLength));
            return true;
        }

        if (prefixLength == sizeof(uint) + sizeof(ulong))
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes, uint.MaxValue);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(sizeof(uint)), checked((ulong)contentLength));
            return true;
        }

        diagnostics.Error(
            DiagnosticCode.UnwindMetadataMalformed,
            "The FDE length prefix is outside the supported ELF64 forms.",
            offset);
        return false;
    }

    private static bool TryWriteEncoded(
        UnwindEncoding encoding,
        byte[] bytes,
        int offset,
        ulong fieldAddress,
        ulong dataBase,
        ulong value)
    {
        var width = GetFixedWidth(encoding);
        if (width == 0 || offset < 0 || offset > bytes.Length - width)
        {
            return false;
        }

        if (!TryGetRawValue(encoding, fieldAddress, dataBase, value, out var raw, out var signed))
        {
            return false;
        }

        var span = bytes.AsSpan(offset, width);
        if (signed)
        {
            switch (width)
            {
                case 2:
                    BinaryPrimitives.WriteInt16LittleEndian(span, checked((short)raw));
                    return true;
                case 4:
                    BinaryPrimitives.WriteInt32LittleEndian(span, checked((int)raw));
                    return true;
                case 8:
                    BinaryPrimitives.WriteInt64LittleEndian(span, checked((long)raw));
                    return true;
            }
        }
        else
        {
            switch (width)
            {
                case 2:
                    BinaryPrimitives.WriteUInt16LittleEndian(span, checked((ushort)raw));
                    return true;
                case 4:
                    BinaryPrimitives.WriteUInt32LittleEndian(span, checked((uint)raw));
                    return true;
                case 8:
                    BinaryPrimitives.WriteUInt64LittleEndian(span, checked((ulong)raw));
                    return true;
            }
        }

        return false;
    }

    private static bool TryGetRawValue(
        UnwindEncoding encoding,
        ulong fieldAddress,
        ulong dataBase,
        ulong value,
        out long raw,
        out bool signed)
    {
        raw = 0;
        signed = encoding.Format is
            UnwindPointerFormat.Sdata2
            or UnwindPointerFormat.Sdata4
            or UnwindPointerFormat.Sdata8;
        var width = GetFixedWidth(encoding);
        if (width == 0
            || encoding.IsIndirect
            || encoding.Application is not (
                UnwindPointerApplication.Absolute
                or UnwindPointerApplication.PcRelative
                or UnwindPointerApplication.DataRelative))
        {
            return false;
        }

        if (encoding.Application == UnwindPointerApplication.Absolute)
        {
            if (signed)
            {
                if (value > long.MaxValue)
                {
                    return false;
                }

                raw = checked((long)value);
            }
            else
            {
                raw = unchecked((long)value);
            }

            return Fits(raw, width, signed);
        }

        if (!TrySubtract(value, encoding.Application == UnwindPointerApplication.DataRelative
                ? dataBase
                : fieldAddress,
                out raw)
            || !Fits(raw, width, signed: true))
        {
            return false;
        }

        return true;
    }

    private static bool TrySubtract(ulong value, ulong baseAddress, out long result)
    {
        if (value >= baseAddress)
        {
            var difference = value - baseAddress;
            if (difference > long.MaxValue)
            {
                result = 0;
                return false;
            }

            result = checked((long)difference);
            return true;
        }

        var negative = baseAddress - value;
        if (negative > (ulong)long.MaxValue + 1)
        {
            result = 0;
            return false;
        }

        result = negative == (ulong)long.MaxValue + 1
            ? long.MinValue
            : -checked((long)negative);
        return true;
    }

    private static bool Fits(long value, int width, bool signed)
    {
        if (!signed)
        {
            return value >= 0 && (ulong)value <= width switch
            {
                2 => ushort.MaxValue,
                4 => uint.MaxValue,
                8 => ulong.MaxValue,
                _ => 0,
            };
        }

        return width switch
        {
            2 => value >= short.MinValue && value <= short.MaxValue,
            4 => value >= int.MinValue && value <= int.MaxValue,
            8 => true,
            _ => false,
        };
    }

    private static bool TryGetEncodedWidth(
        UnwindEncoding encoding,
        byte[] bytes,
        int offset,
        out int width)
    {
        width = GetFixedWidth(encoding);
        return width != 0 && offset >= 0 && offset <= bytes.Length - width;
    }

    private static bool TrySkipEncoded(
        UnwindEncoding encoding,
        byte[] bytes,
        ref int offset)
    {
        if (!TryGetEncodedWidth(encoding, bytes, offset, out var width))
        {
            return false;
        }

        offset = checked(offset + width);
        return true;
    }

    private static int GetLengthPrefixSize(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= sizeof(uint)
            && BinaryPrimitives.ReadUInt32LittleEndian(bytes) == uint.MaxValue
            ? sizeof(uint) + sizeof(ulong)
            : sizeof(uint);

    private static int GetFixedWidth(UnwindEncoding encoding) =>
        encoding.Format switch
        {
            UnwindPointerFormat.Absptr
                or UnwindPointerFormat.Udata8
                or UnwindPointerFormat.Sdata8 => sizeof(ulong),
            UnwindPointerFormat.Udata4
                or UnwindPointerFormat.Sdata4 => sizeof(uint),
            UnwindPointerFormat.Udata2
                or UnwindPointerFormat.Sdata2 => sizeof(ushort),
            _ => 0,
        };

    private static void WriteUleb(List<byte> destination, ulong value)
    {
        do
        {
            var current = (byte)(value & 0x7F);
            value >>= 7;
            destination.Add(value == 0 ? current : (byte)(current | 0x80));
        }
        while (value != 0);
    }

    private static bool RangesOverlap(ulong firstStart, ulong firstSize, ulong secondStart, ulong secondSize) =>
        firstSize > 0
        && secondSize > 0
        && firstStart <= ulong.MaxValue - firstSize
        && secondStart <= ulong.MaxValue - secondSize
        && firstStart < secondStart + secondSize
        && secondStart < firstStart + firstSize;

    private static UnwindMetadataRewriteResult Failure(
        UnwindMetadataModel? model,
        DiagnosticBag diagnostics) =>
        new(model, null, null, Array.Empty<ElfLayoutByteEdit>(), Array.Empty<UnwindFdeRewrite>(), diagnostics.ToArray());

    private sealed record InputRecord(
        ulong Offset,
        FileRange Range,
        byte[] RawBytes,
        UnwindFde? Fde,
        FdeTransform? Transform);

    private sealed record OutputRecord(
        InputRecord? Input,
        ulong OutputOffset,
        byte[] Bytes);

    private sealed record FdeTransform
    {
        public SemanticSourceRange SourceRange { get; }

        public SemanticSourceRange OutputRange { get; }

        public SemanticCfiEffectExtension[] Effects { get; }

        public UnwindEncoding PointerEncoding { get; }

        public long CodeAlignmentFactor { get; }

        public AddressMap AddressMap { get; }

        public FdeTransform(
            SemanticSourceRange sourceRange,
            SemanticSourceRange outputRange,
            SemanticCfiEffectExtension[] effects,
            UnwindEncoding pointerEncoding,
            long codeAlignmentFactor,
            AddressMap addressMap)
        {
            SourceRange = sourceRange;
            OutputRange = outputRange;
            Effects = effects;
            PointerEncoding = pointerEncoding;
            CodeAlignmentFactor = codeAlignmentFactor;
            AddressMap = addressMap;
        }
    }
}
