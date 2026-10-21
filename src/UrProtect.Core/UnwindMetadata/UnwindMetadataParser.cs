using System.Buffers.Binary;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.UnwindMetadata;

public static class UnwindMetadataParser
{
    public static UnwindMetadataParseResult Parse(ElfFile file)
    {
        ArgumentNullException.ThrowIfNull(file);

        var diagnostics = new DiagnosticBag();
        var ehFrame = FindSection(file, ".eh_frame", diagnostics);
        var ehFrameHeader = FindSection(file, ".eh_frame_hdr", diagnostics);
        if (ehFrame is null)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataUnavailable,
                "The ELF has no bounded .eh_frame section.");
            return new UnwindMetadataParseResult(null, diagnostics.ToArray());
        }

        if (!TryReadSection(file, ehFrame.Value, UnwindSectionKind.EhFrame, diagnostics, out var ehFrameBytes))
        {
            return new UnwindMetadataParseResult(null, diagnostics.ToArray());
        }

        ReadOnlyMemory<byte> headerBytes = ReadOnlyMemory<byte>.Empty;
        if (ehFrameHeader is { } header
            && !TryReadSection(file, header, UnwindSectionKind.EhFrameHeader, diagnostics, out headerBytes))
        {
            return new UnwindMetadataParseResult(null, diagnostics.ToArray());
        }

        var cies = new List<UnwindCie>();
        var fdes = new List<UnwindFde>();
        ParseEhFrame(ehFrame.Value, ehFrameBytes, cies, fdes, diagnostics);

        UnwindFrameHeader? parsedHeader = null;
        if (ehFrameHeader is { } frameHeader && !diagnostics.HasErrors)
        {
            TryParseHeader(
                frameHeader,
                headerBytes,
                ehFrame.Value,
                fdes,
                diagnostics,
                out parsedHeader);
        }

        if (diagnostics.HasErrors)
        {
            return new UnwindMetadataParseResult(null, diagnostics.ToArray());
        }

        return new UnwindMetadataParseResult(
            new UnwindMetadataModel(
                ehFrame.Value,
                ehFrameHeader,
                cies.AsReadOnly(),
                fdes.AsReadOnly(),
                parsedHeader,
                ehFrameBytes,
                headerBytes),
            diagnostics.ToArray());
    }

    private static SectionHeader? FindSection(
        ElfFile file,
        string name,
        DiagnosticBag diagnostics)
    {
        if (file.SectionHeaders.Count == 0)
        {
            return null;
        }

        var names = FindSectionNames(file, diagnostics);
        foreach (var (index, section) in file.SectionHeaders.Select((value, index) => (index, value)))
        {
            if (names.TryGetValue((uint)index, out var sectionName)
                && string.Equals(sectionName, name, StringComparison.Ordinal))
            {
                return section;
            }
        }

        return null;
    }

    private static Dictionary<uint, string> FindSectionNames(
        ElfFile file,
        DiagnosticBag diagnostics)
    {
        var result = new Dictionary<uint, string>();
        if (file.Header.SectionNameIndex >= file.SectionHeaders.Count)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The ELF section-name index is outside the parsed section table.",
                ElfHeaderOffsets.SectionNameIndex);
            return result;
        }

        var stringSection = file.SectionHeaders[file.Header.SectionNameIndex];
        if (!TryReadSection(
                file,
                stringSection,
                UnwindSectionKind.EhFrameHeader,
                diagnostics,
                out var bytes))
        {
            return result;
        }

        for (var index = 0; index < file.SectionHeaders.Count; index++)
        {
            var offset = file.SectionHeaders[index].Name;
            if (offset >= (uint)bytes.Length)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "A section name offset is outside the section-name string table.",
                    stringSection.Offset);
                return result;
            }

            var remaining = bytes.Span[(int)offset..];
            var terminator = remaining.IndexOf((byte)0);
            if (terminator < 0)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "A section name is not NUL terminated.",
                    stringSection.Offset + offset);
                return result;
            }

            result[(uint)index] = Encoding.UTF8.GetString(remaining[..terminator]);
        }

        return result;
    }

    private static bool TryReadSection(
        ElfFile file,
        SectionHeader section,
        UnwindSectionKind kind,
        DiagnosticBag diagnostics,
        out ReadOnlyMemory<byte> bytes)
    {
        bytes = ReadOnlyMemory<byte>.Empty;
        if (section.Size > int.MaxValue
            || section.Offset > (ulong)file.Bytes.Length
            || section.Size > (ulong)file.Bytes.Length - section.Offset)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                $"{kind} section range is outside the bounded input.",
                section.Offset);
            return false;
        }

        bytes = file.Bytes.Slice(
            checked((int)section.Offset),
            checked((int)section.Size));
        return true;
    }

    private static void ParseEhFrame(
        SectionHeader section,
        ReadOnlyMemory<byte> bytes,
        List<UnwindCie> cies,
        List<UnwindFde> fdes,
        DiagnosticBag diagnostics)
    {
        var pendingFdes = new List<PendingFde>();
        var offset = 0;
        while (offset < bytes.Length)
        {
            var recordOffset = offset;
            if (!TryReadLength(
                    bytes.Span,
                    ref offset,
                    out var contentLength,
                    out var recordLength,
                    diagnostics,
                    checked(section.Offset + (ulong)recordOffset)))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "An .eh_frame record has an invalid length.",
                    checked(section.Offset + (ulong)recordOffset));
                return;
            }

            if (contentLength == 0)
            {
                if (bytes.Span[offset..].IndexOfAnyExcept((byte)0) >= 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.UnwindMetadataMalformed,
                        "Nonzero bytes follow the .eh_frame terminator.",
                        checked(section.Offset + (ulong)offset));
                }

                break;
            }

            if (contentLength > UnwindMetadataLimits.MaximumRecordBytes
                || contentLength > (ulong)(bytes.Length - offset))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "An .eh_frame record exceeds its bounded section range.",
                    checked(section.Offset + (ulong)recordOffset));
                return;
            }

            var contentStart = offset;
            var contentEnd = checked(contentStart + (int)contentLength);
            var recordBytes = bytes.Slice(recordOffset, checked((int)recordLength));
            if (contentEnd - contentStart < sizeof(uint))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "An .eh_frame record is missing its CIE/FDE identifier.",
                    checked(section.Offset + (ulong)recordOffset));
                return;
            }

            var identifier = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Span[contentStart..]);
            var identifierAbsoluteOffset = checked(section.Offset + (ulong)contentStart);
            offset = contentEnd;
            if (identifier == 0)
            {
                ParseCie(
                    checked(section.Offset + (ulong)recordOffset),
                    new FileRange(
                        checked(section.Offset + (ulong)recordOffset),
                        recordLength),
                    recordBytes,
                    bytes.Slice(
                        contentStart + sizeof(uint),
                        checked((int)contentLength - sizeof(uint))),
                    cies,
                    diagnostics);
            }
            else
            {
                pendingFdes.Add(new PendingFde(
                    checked(section.Offset + (ulong)recordOffset),
                    new FileRange(
                        checked(section.Offset + (ulong)recordOffset),
                        recordLength),
                    recordBytes,
                    identifierAbsoluteOffset,
                    checked(contentStart - recordOffset),
                    identifier));
            }
        }

        foreach (var pending in pendingFdes)
        {
            ParseFde(section, pending, cies, fdes, diagnostics);
        }
    }

    private static bool TryReadLength(
        ReadOnlySpan<byte> bytes,
        ref int offset,
        out ulong contentLength,
        out ulong recordLength,
        DiagnosticBag diagnostics,
        ulong diagnosticOffset)
    {
        contentLength = 0;
        recordLength = 0;
        if (offset > bytes.Length - sizeof(uint))
        {
            return false;
        }

        var recordStart = offset;
        var length32 = BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
        offset += sizeof(uint);
        if (length32 == uint.MaxValue)
        {
            if (offset > bytes.Length - sizeof(ulong))
            {
                return false;
            }

            contentLength = BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]);
            offset += sizeof(ulong);
        }
        else
        {
            contentLength = length32;
        }

        if (contentLength > int.MaxValue
            || contentLength > (ulong)(bytes.Length - offset))
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "An .eh_frame record length exceeds the bounded input.",
                diagnosticOffset);
            return false;
        }

        var prefixLength = checked((ulong)(offset - recordStart));
        if (contentLength > ulong.MaxValue - prefixLength)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "An .eh_frame record length overflows the bounded arithmetic domain.",
                diagnosticOffset);
            return false;
        }

        recordLength = prefixLength + contentLength;
        return true;
    }

    private static void ParseCie(
        ulong absoluteOffset,
        FileRange range,
        ReadOnlyMemory<byte> recordBytes,
        ReadOnlyMemory<byte> content,
        List<UnwindCie> cies,
        DiagnosticBag diagnostics)
    {
        var reader = new UnwindCursor(content.Span);
        if (!reader.TryReadByte(out var version)
            || version == 0
            || !reader.TryReadNullTerminatedString(out var augmentation)
            || !reader.TryReadUleb(out var codeAlignmentRaw)
            || codeAlignmentRaw > (ulong)long.MaxValue
            || !reader.TryReadSleb(out var dataAlignment)
            || !reader.TryReadUleb(out var returnRegister)
            || returnRegister > UnwindMetadataLimits.MaximumRegisterNumber)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "A CIE header is truncated or has invalid bounded operands.",
                absoluteOffset);
            return;
        }

        var augmentationData = ReadAugmentationData(
            ref reader,
            augmentation,
            diagnostics,
            absoluteOffset,
            out var fdePointerEncoding);
        if (diagnostics.HasErrors)
        {
            return;
        }

        var instructionFileOffset = checked(
            absoluteOffset
            + (ulong)(recordBytes.Length - content.Length));
        var instructions = ParseInstructions(
            ref reader,
            instructionFileOffset,
            diagnostics);
        cies.Add(new UnwindCie(
            range,
            new FileOffset(absoluteOffset),
            version,
            augmentation,
            checked((long)codeAlignmentRaw),
            dataAlignment,
            returnRegister,
            augmentationData,
            fdePointerEncoding,
            instructions,
            recordBytes));
    }

    private static void ParseFde(
        SectionHeader section,
        PendingFde pending,
        IReadOnlyList<UnwindCie> cies,
        List<UnwindFde> fdes,
        DiagnosticBag diagnostics)
    {
        var recordStart = pending.RecordRange.Offset;
        var ciePointerFieldOffset = pending.IdentifierAbsoluteOffset;
        if (ciePointerFieldOffset < recordStart
            || pending.CieIdentifier > ciePointerFieldOffset - section.Offset)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "An FDE CIE pointer underflows the .eh_frame section.",
                pending.AbsoluteOffset);
            return;
        }

        var cieOffset = ciePointerFieldOffset - pending.CieIdentifier;
        var cie = cies.FirstOrDefault(item => item.EntryOffset.Value == cieOffset);
        if (cie is null)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "An FDE refers to a CIE that was not found in the bounded .eh_frame records.",
                pending.AbsoluteOffset);
            return;
        }

        var cursor = new UnwindCursor(pending.RecordBytes.Span[(pending.IdentifierRecordOffset + sizeof(uint))..]);
        var pointerEncoding = cie.FdePointerEncoding ?? new UnwindEncoding(0);
        var initialFieldFileOffset = checked(pending.IdentifierAbsoluteOffset + sizeof(uint));
        var initialFieldAddress = checked(
            section.Address + (initialFieldFileOffset - section.Offset));
        var initialPosition = cursor.Position;
        if (!cursor.TryReadEncoded(pointerEncoding, initialFieldAddress, section.Address, out var initialLocation)
            || !cursor.TryReadEncoded(
                new UnwindEncoding((byte)(pointerEncoding.Raw & 0x0F)),
                checked(initialFieldAddress + (ulong)(cursor.Position - initialPosition)),
                section.Address,
                out var addressRange))
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "An FDE address range is truncated or uses an unsupported encoding.",
                pending.AbsoluteOffset);
            return;
        }

        var augmentationData = ReadAugmentationData(
            ref cursor,
            cie.Augmentation,
            diagnostics,
            pending.AbsoluteOffset,
            out _,
            decodeCieAugmentations: false);
        if (diagnostics.HasErrors)
        {
            return;
        }

        var instructionFileOffset = checked(
            pending.AbsoluteOffset
            + (ulong)(pending.IdentifierRecordOffset + sizeof(uint)));
        var instructions = ParseInstructions(ref cursor, instructionFileOffset, diagnostics);
        fdes.Add(new UnwindFde(
            pending.RecordRange,
            new FileOffset(pending.AbsoluteOffset),
            new FileOffset(cieOffset),
            initialLocation,
            addressRange,
            augmentationData,
            instructions,
            pending.RecordBytes));
    }

    private static ReadOnlyMemory<byte> ReadAugmentationData(
        ref UnwindCursor reader,
        string augmentation,
        DiagnosticBag diagnostics,
        ulong offset,
        out UnwindEncoding? fdePointerEncoding,
        bool decodeCieAugmentations = true)
    {
        fdePointerEncoding = null;
        if (!augmentation.StartsWith('z'))
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        if (!reader.TryReadUleb(out var length)
            || length > UnwindMetadataLimits.MaximumAugmentationBytes
            || length > (ulong)reader.Remaining.Length)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "CFI augmentation data is outside its bounded record.",
                offset);
            return ReadOnlyMemory<byte>.Empty;
        }

        var data = reader.ReadBytes(checked((int)length));
        if (!decodeCieAugmentations)
        {
            return data;
        }

        var augmentationReader = new UnwindCursor(data.Span);
        foreach (var character in augmentation.Skip(1))
        {
            switch (character)
            {
                case 'L':
                    if (!augmentationReader.TryReadByte(out _))
                    {
                        diagnostics.Error(
                            DiagnosticCode.UnwindMetadataMalformed,
                            "The CIE L augmentation operand is truncated.",
                            offset);
                        return data;
                    }

                    break;
                case 'P':
                    if (!augmentationReader.TryReadByte(out var personalityEncoding)
                        || !augmentationReader.TryReadEncoded(
                            new UnwindEncoding(personalityEncoding),
                            0,
                            0,
                            out _))
                    {
                        diagnostics.Error(
                            DiagnosticCode.UnwindMetadataMalformed,
                            "The CIE P augmentation operand is malformed.",
                            offset);
                        return data;
                    }

                    break;
                case 'R':
                    if (!augmentationReader.TryReadByte(out var encoding))
                    {
                        diagnostics.Error(
                            DiagnosticCode.UnwindMetadataMalformed,
                            "The CIE R augmentation operand is truncated.",
                            offset);
                        return data;
                    }

                    fdePointerEncoding = new UnwindEncoding(encoding);
                    break;
                default:
                    diagnostics.Warning(
                        DiagnosticCode.UnwindMetadataUnsupported,
                        $"The CIE augmentation '{character}' is retained as opaque data.",
                        offset);
                    break;
            }
        }

        return data;
    }

    private static List<UnwindInstruction> ParseInstructions(
        ref UnwindCursor reader,
        ulong absoluteOffset,
        DiagnosticBag diagnostics)
    {
        var result = new List<UnwindInstruction>();
        while (reader.Remaining.Length > 0)
        {
            if (result.Count >= UnwindMetadataLimits.MaximumInstructionsPerRecord)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "A CFI instruction stream exceeds its configured limit.",
                    absoluteOffset);
                break;
            }

            var start = reader.Position;
            if (!reader.TryReadByte(out var opcode))
            {
                break;
            }

            var kind = UnwindInstructionKind.Unsupported;
            ulong operand = 0;
            ulong operand2 = 0;
            var valid = true;
            var known = true;
            switch (opcode)
            {
                case 0x00:
                    kind = UnwindInstructionKind.Nop;
                    break;
                case >= 0x40 and <= 0x7F:
                    kind = UnwindInstructionKind.AdvanceLocation;
                    operand = (ulong)(opcode & 0x3F);
                    break;
                case >= 0x80 and <= 0xBF:
                    kind = UnwindInstructionKind.Offset;
                    operand = (ulong)(opcode & 0x3F);
                    valid = reader.TryReadUleb(out operand2);
                    break;
                case >= 0xC0 and <= 0xFF:
                    kind = UnwindInstructionKind.Restore;
                    operand = (ulong)(opcode & 0x3F);
                    break;
                case 0x01:
                    valid = reader.TryReadUInt64(out operand);
                    break;
                case 0x02:
                    kind = UnwindInstructionKind.AdvanceLocation;
                    valid = reader.TryReadByte(out var delta1);
                    operand = delta1;
                    break;
                case 0x03:
                    kind = UnwindInstructionKind.AdvanceLocation;
                    valid = reader.TryReadUInt16(out var delta2);
                    operand = delta2;
                    break;
                case 0x04:
                    kind = UnwindInstructionKind.AdvanceLocation;
                    valid = reader.TryReadUInt32(out var delta4);
                    operand = delta4;
                    break;
                case 0x05:
                    kind = UnwindInstructionKind.Offset;
                    valid = reader.TryReadUleb(out operand)
                        && reader.TryReadUleb(out operand2);
                    break;
                case 0x06:
                    kind = UnwindInstructionKind.Restore;
                    valid = reader.TryReadUleb(out operand);
                    break;
                case 0x07:
                case 0x08:
                    valid = reader.TryReadUleb(out operand);
                    break;
                case 0x09:
                    valid = reader.TryReadUleb(out operand)
                        && reader.TryReadUleb(out operand2);
                    break;
                case 0x0A:
                    kind = UnwindInstructionKind.RememberState;
                    break;
                case 0x0B:
                    kind = UnwindInstructionKind.RestoreState;
                    break;
                case 0x0C:
                    kind = UnwindInstructionKind.DefCfa;
                    valid = reader.TryReadUleb(out operand)
                        && reader.TryReadUleb(out operand2);
                    break;
                case 0x0D:
                    kind = UnwindInstructionKind.DefCfaRegister;
                    valid = reader.TryReadUleb(out operand);
                    break;
                case 0x0E:
                    kind = UnwindInstructionKind.DefCfaOffset;
                    valid = reader.TryReadUleb(out operand);
                    break;
                case 0x0F:
                    valid = TryReadBlock(ref reader, out operand);
                    break;
                case 0x10:
                    valid = reader.TryReadUleb(out operand)
                        && TryReadBlock(ref reader, out operand2);
                    break;
                case 0x11:
                {
                    kind = UnwindInstructionKind.Offset;
                    long offsetSf = 0;
                    valid = reader.TryReadUleb(out operand)
                        && reader.TryReadSleb(out offsetSf);
                    operand2 = unchecked((ulong)offsetSf);
                    break;
                }
                case 0x12:
                {
                    kind = UnwindInstructionKind.DefCfa;
                    long cfaSf = 0;
                    valid = reader.TryReadUleb(out operand)
                        && reader.TryReadSleb(out cfaSf);
                    operand2 = unchecked((ulong)cfaSf);
                    break;
                }
                case 0x13:
                    kind = UnwindInstructionKind.DefCfaOffset;
                    valid = reader.TryReadSleb(out var cfaOffsetSf);
                    operand = unchecked((ulong)cfaOffsetSf);
                    break;
                case 0x14:
                    valid = reader.TryReadUleb(out operand)
                        && reader.TryReadUleb(out operand2);
                    break;
                case 0x15:
                {
                    long valueOffsetSf = 0;
                    valid = reader.TryReadUleb(out operand)
                        && reader.TryReadSleb(out valueOffsetSf);
                    operand2 = unchecked((ulong)valueOffsetSf);
                    break;
                }
                case 0x16:
                    valid = reader.TryReadUleb(out operand)
                        && TryReadBlock(ref reader, out operand2);
                    break;
                default:
                    known = false;
                    break;
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "A CFI instruction has truncated or overflowing operands.",
                    checked(absoluteOffset + (ulong)start));
                return result;
            }

            var end = reader.Position;
            var raw = reader.Slice(start, end - start);
            if (!known)
            {
                if (reader.Remaining.Length > 0)
                {
                    reader.Skip(reader.Remaining.Length);
                    raw = reader.Slice(start, reader.Position - start);
                }

                result.Add(new UnwindInstruction(
                    UnwindInstructionKind.Unsupported,
                    checked(absoluteOffset + (ulong)start),
                    opcode,
                    0,
                    0,
                    raw));
                diagnostics.Warning(
                    DiagnosticCode.UnwindMetadataUnsupported,
                    $"CFI opcode 0x{opcode:X2} is preserved as opaque data.",
                    checked(absoluteOffset + (ulong)start));
                break;
            }

            result.Add(new UnwindInstruction(
                kind,
                checked(absoluteOffset + (ulong)start),
                opcode,
                operand,
                operand2,
                raw));
        }

        return result;
    }

    private static bool TryReadBlock(ref UnwindCursor reader, out ulong length)
    {
        length = 0;
        if (!reader.TryReadUleb(out length)
            || length > UnwindMetadataLimits.MaximumInstructionBytes
            || length > (ulong)reader.Remaining.Length)
        {
            return false;
        }

        reader.Skip(checked((int)length));
        return true;
    }

    private static bool TryParseHeader(
        SectionHeader headerSection,
        ReadOnlyMemory<byte> bytes,
        SectionHeader ehFrame,
        IReadOnlyList<UnwindFde> fdes,
        DiagnosticBag diagnostics,
        out UnwindFrameHeader? result)
    {
        result = null;
        var reader = new UnwindCursor(bytes.Span);
        if (!reader.TryReadByte(out var version)
            || !reader.TryReadByte(out var ehFrameEncoding)
            || !reader.TryReadByte(out var fdeCountEncoding)
            || !reader.TryReadByte(out var tableEncoding)
            || version != 1)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The .eh_frame_hdr version or encoding header is malformed.",
                headerSection.Offset);
            return false;
        }

        var ehFramePlace = checked(headerSection.Address + (ulong)reader.Position);
        if (!reader.TryReadEncoded(
                new UnwindEncoding(ehFrameEncoding),
                ehFramePlace,
                headerSection.Address,
                out var ehFrameAddress)
            || ehFrameAddress != ehFrame.Address)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The .eh_frame_hdr does not point to the declared .eh_frame section.",
                headerSection.Offset);
            return false;
        }

        var countPlace = checked(headerSection.Address + (ulong)reader.Position);
        if (!reader.TryReadEncoded(
                new UnwindEncoding(fdeCountEncoding),
                countPlace,
                headerSection.Address,
                out var fdeCount))
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The .eh_frame_hdr FDE count uses an unsupported encoding.",
                headerSection.Offset);
            return false;
        }

        if (fdeCount > UnwindMetadataLimits.MaximumHeaderEntries)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The .eh_frame_hdr FDE count exceeds its configured bound.",
                headerSection.Offset);
            return false;
        }

        var entries = new List<UnwindHeaderTableEntry>(checked((int)fdeCount));
        for (var index = 0; index < (int)fdeCount; index++)
        {
            var initialPlace = checked(headerSection.Address + (ulong)reader.Position);
            if (!reader.TryReadEncoded(
                    new UnwindEncoding(tableEncoding),
                    initialPlace,
                    headerSection.Address,
                    out var initial))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "The .eh_frame_hdr initial-location table is truncated or uses an unsupported encoding.",
                    checked(headerSection.Offset + (ulong)reader.Position));
                return false;
            }

            var fdePlace = checked(headerSection.Address + (ulong)reader.Position);
            if (!reader.TryReadEncoded(
                    new UnwindEncoding(tableEncoding),
                    fdePlace,
                    headerSection.Address,
                    out var fde))
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "The .eh_frame_hdr FDE table is truncated or uses an unsupported encoding.",
                    checked(headerSection.Offset + (ulong)reader.Position));
                return false;
            }

            if (entries.Count > 0 && entries[^1].InitialLocation > initial)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "The .eh_frame_hdr table is not sorted by initial location.",
                    headerSection.Offset);
                return false;
            }

            var mappedFde = fdes.FirstOrDefault(item =>
                item.EntryOffset.Value <= ulong.MaxValue - ehFrame.Address
                && checked(ehFrame.Address + (item.EntryOffset.Value - ehFrame.Offset)) == fde);
            if (mappedFde is null)
            {
                diagnostics.Error(
                    DiagnosticCode.UnwindMetadataMalformed,
                    "The .eh_frame_hdr table contains an FDE address outside the parsed .eh_frame records.",
                    checked(headerSection.Offset + (ulong)reader.Position));
                return false;
            }

            entries.Add(new UnwindHeaderTableEntry(initial, fde));
        }

        if (reader.Remaining.Length != 0)
        {
            diagnostics.Error(
                DiagnosticCode.UnwindMetadataMalformed,
                "The .eh_frame_hdr contains bytes outside its declared FDE table.",
                checked(headerSection.Offset + (ulong)reader.Position));
            return false;
        }

        result = new UnwindFrameHeader(
            new FileRange(headerSection.Offset, headerSection.Size),
            version,
            new UnwindEncoding(ehFrameEncoding),
            ehFrame.Address,
            new UnwindEncoding(fdeCountEncoding),
            new UnwindEncoding(tableEncoding),
            fdeCount,
            entries.AsReadOnly(),
            bytes);
        return true;
    }

    private sealed record PendingFde(
        ulong AbsoluteOffset,
        FileRange RecordRange,
        ReadOnlyMemory<byte> RecordBytes,
        ulong IdentifierAbsoluteOffset,
        int IdentifierRecordOffset,
        uint CieIdentifier);

    private ref struct UnwindCursor
    {
        private ReadOnlySpan<byte> bytes;
        private int offset;

        public UnwindCursor(ReadOnlySpan<byte> bytes)
        {
            this.bytes = bytes;
            offset = 0;
        }

        public int Position => offset;

        public ReadOnlySpan<byte> Remaining => bytes[offset..];

        public ReadOnlyMemory<byte> Slice(int start, int length) =>
            bytes.Slice(start, length).ToArray();

        public void Skip(int length)
        {
            if (length < 0 || length > Remaining.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            offset += length;
        }

        public bool TryReadByte(out byte value)
        {
            value = 0;
            if (Remaining.Length < sizeof(byte))
            {
                return false;
            }

            value = bytes[offset++];
            return true;
        }

        public bool TryReadUInt16(out ushort value)
        {
            value = 0;
            if (Remaining.Length < sizeof(ushort))
            {
                return false;
            }

            value = BinaryPrimitives.ReadUInt16LittleEndian(Remaining);
            offset += sizeof(ushort);
            return true;
        }

        public bool TryReadUInt32(out uint value)
        {
            value = 0;
            if (Remaining.Length < sizeof(uint))
            {
                return false;
            }

            value = BinaryPrimitives.ReadUInt32LittleEndian(Remaining);
            offset += sizeof(uint);
            return true;
        }

        public bool TryReadUInt64(out ulong value)
        {
            value = 0;
            if (Remaining.Length < sizeof(ulong))
            {
                return false;
            }

            value = BinaryPrimitives.ReadUInt64LittleEndian(Remaining);
            offset += sizeof(ulong);
            return true;
        }

        public bool TryReadInt16(out short value)
        {
            value = 0;
            if (Remaining.Length < sizeof(short))
            {
                return false;
            }

            value = BinaryPrimitives.ReadInt16LittleEndian(Remaining);
            offset += sizeof(short);
            return true;
        }

        public bool TryReadInt32(out int value)
        {
            value = 0;
            if (Remaining.Length < sizeof(int))
            {
                return false;
            }

            value = BinaryPrimitives.ReadInt32LittleEndian(Remaining);
            offset += sizeof(int);
            return true;
        }

        public bool TryReadInt64(out long value)
        {
            value = 0;
            if (Remaining.Length < sizeof(long))
            {
                return false;
            }

            value = BinaryPrimitives.ReadInt64LittleEndian(Remaining);
            offset += sizeof(long);
            return true;
        }

        public bool TryReadNullTerminatedString(out string value)
        {
            value = string.Empty;
            var index = Remaining.IndexOf((byte)0);
            if (index < 0)
            {
                return false;
            }

            value = Encoding.UTF8.GetString(Remaining[..index]);
            offset += index + 1;
            return true;
        }

        public bool TryReadUleb(out ulong value)
        {
            value = 0;
            for (var index = 0; index < UnwindMetadataLimits.MaximumLebBytes; index++)
            {
                if (!TryReadByte(out var current))
                {
                    return false;
                }

                var payload = (ulong)(current & 0x7F);
                if (index == 9 && payload > 1)
                {
                    return false;
                }

                value |= payload << (index * 7);
                if ((current & 0x80) == 0)
                {
                    return true;
                }
            }

            return false;
        }

        public bool TryReadSleb(out long value)
        {
            value = 0;
            byte current = 0;
            for (var index = 0; index < UnwindMetadataLimits.MaximumLebBytes; index++)
            {
                if (!TryReadByte(out current))
                {
                    return false;
                }

                var shift = index * 7;
                value |= (long)(current & 0x7F) << shift;
                if ((current & 0x80) == 0)
                {
                    if (shift < 63 && (current & 0x40) != 0)
                    {
                        value |= -1L << (shift + 7);
                    }

                    return true;
                }

                if (index == 9)
                {
                    return false;
                }
            }

            return false;
        }

        public ReadOnlyMemory<byte> ReadBytes(int length)
        {
            if (length < 0 || length > Remaining.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            var result = Remaining[..length].ToArray();
            offset += length;
            return result;
        }

        public bool TryReadEncoded(
            UnwindEncoding encoding,
            ulong fieldAddress,
            ulong dataBase,
            out ulong value)
        {
            value = 0;
            if (encoding.IsOmit
                || !encoding.IsSupportedFormat
                || !encoding.IsSupportedApplication
                || encoding.IsIndirect
                || encoding.Application is UnwindPointerApplication.Aligned)
            {
                return encoding.IsOmit;
            }

            var signed = encoding.Format is
                UnwindPointerFormat.Sleb128
                or UnwindPointerFormat.Sdata2
                or UnwindPointerFormat.Sdata4
                or UnwindPointerFormat.Sdata8;
            long signedRaw = 0;
            ulong unsignedRaw = 0;
            var read = encoding.Format switch
            {
                UnwindPointerFormat.Absptr => TryReadUInt64(out unsignedRaw),
                UnwindPointerFormat.Uleb128 => TryReadUleb(out unsignedRaw),
                UnwindPointerFormat.Udata2 => TryReadUInt16(out var u16) && Assign(u16, out unsignedRaw),
                UnwindPointerFormat.Udata4 => TryReadUInt32(out var u32) && Assign(u32, out unsignedRaw),
                UnwindPointerFormat.Udata8 => TryReadUInt64(out unsignedRaw),
                UnwindPointerFormat.Sleb128 => TryReadSleb(out signedRaw),
                UnwindPointerFormat.Sdata2 => TryReadInt16(out var s16) && Assign(s16, out signedRaw),
                UnwindPointerFormat.Sdata4 => TryReadInt32(out var s32) && Assign((long)s32, out signedRaw),
                UnwindPointerFormat.Sdata8 => TryReadInt64(out signedRaw),
                _ => false,
            };
            if (!read)
            {
                return false;
            }

            if (encoding.Application == UnwindPointerApplication.Absolute)
            {
                value = signed ? unchecked((ulong)signedRaw) : unsignedRaw;
                return true;
            }

            if (encoding.Application is not (
                    UnwindPointerApplication.PcRelative
                    or UnwindPointerApplication.DataRelative))
            {
                return false;
            }

            var delta = signed ? signedRaw : unchecked((long)unsignedRaw);
            var baseAddress = unchecked((long)(encoding.Application == UnwindPointerApplication.DataRelative
                ? dataBase
                : fieldAddress));
            var resolved = baseAddress + delta;
            if ((delta > 0 && resolved < baseAddress)
                || (delta < 0 && resolved > baseAddress))
            {
                return false;
            }

            value = unchecked((ulong)resolved);
            return true;
        }

        private static bool Assign(ulong value, out ulong result)
        {
            result = value;
            return true;
        }

        private static bool Assign(short value, out long result)
        {
            result = value;
            return true;
        }

        private static bool Assign(long value, out long result)
        {
            result = value;
            return true;
        }
    }
}
