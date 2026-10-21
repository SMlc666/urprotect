using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using static UrProtect.Core.StructuralElf.ElfParserUtilities;

namespace UrProtect.Core.StructuralElf;

public static class ElfParser
{
    public static ElfParseResult Parse(ReadOnlyMemory<byte> bytes) => ParseCore(bytes, limits: null);

    internal static ElfParseResult Parse(ReadOnlyMemory<byte> bytes, ElfParserLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        return ParseCore(bytes, limits);
    }

    private static ElfParseResult ParseCore(ReadOnlyMemory<byte> bytes, ElfParserLimits? limits)
    {
        var diagnostics = new DiagnosticBag();
        var reader = new BoundedReader(bytes);
        var workBudget = limits is null ? null : new ElfParserWorkBudget(limits);
        if (workBudget is not null && !workBudget.ValidateInputLength(bytes.Length, diagnostics))
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }
        if (bytes.Length < ElfConstants.HeaderSize64)
        {
            diagnostics.Error(
                DiagnosticCode.InputTooSmall,
                $"An ELF64 header requires at least {ElfConstants.HeaderSize64} bytes.");
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        if (!HasElfMagic(reader))
        {
            diagnostics.Error(DiagnosticCode.InvalidMagic, "The input does not start with the ELF magic.");
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        if (!reader.TryReadByte(ElfHeaderOffsets.Class, out var elfClass) || elfClass != ElfConstants.Class64)
        {
            diagnostics.Error(DiagnosticCode.UnsupportedClass, "Only ELFCLASS64 inputs are supported.", ElfHeaderOffsets.Class);
        }

        if (!reader.TryReadByte(ElfHeaderOffsets.DataEncoding, out var dataEncoding) || dataEncoding != ElfConstants.LittleEndian)
        {
            diagnostics.Error(DiagnosticCode.UnsupportedEndianness, "Only little-endian ELF inputs are supported.", ElfHeaderOffsets.DataEncoding);
        }

        if (!reader.TryReadByte(ElfHeaderOffsets.IdentificationVersion, out var identVersion)
            || identVersion != ElfConstants.IdentificationVersionCurrent)
        {
            diagnostics.Error(DiagnosticCode.InvalidHeader, "Only the current ELF identification version is supported.", ElfHeaderOffsets.IdentificationVersion);
        }

        if (diagnostics.HasErrors)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        if (!TryReadHeader(reader, out var header))
        {
            diagnostics.Error(DiagnosticCode.InvalidHeader, "The ELF64 header is truncated or malformed.");
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        if (header.ProgramHeaderCount == ElfConstants.PnXnum
            || (header.SectionHeaderOffset != 0
                && (header.SectionHeaderCount == 0 || header.SectionNameIndex == ElfConstants.ShnXindex)))
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedExtendedNumbering,
                "ELF extended table numbering is not supported by the initial parser boundary.");
        }

        if (header.Machine != ElfConstants.MachineAarch64)
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedMachine,
                $"Machine 0x{header.Machine:X} is not AArch64.",
                ElfHeaderOffsets.Machine);
        }

        if (header.Type is not (ElfConstants.TypeDyn or ElfConstants.TypeExec))
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedFileType,
                $"ELF type {header.Type} is not a supported ET_DYN or ET_EXEC type.",
                ElfHeaderOffsets.Type);
        }

        if (header.Version != ElfConstants.HeaderVersionCurrent)
        {
            diagnostics.Error(DiagnosticCode.InvalidHeader, "Only the current ELF header version is supported.", ElfHeaderOffsets.Version);
        }

        if (header.HeaderSize != ElfConstants.HeaderSize64)
        {
            diagnostics.Error(DiagnosticCode.InvalidHeader, "The ELF64 header size is not exactly 64 bytes.", ElfHeaderOffsets.HeaderSize);
        }

        if (header.ProgramHeaderCount > 0
            && header.ProgramHeaderEntrySize != ElfConstants.ProgramHeaderSize64)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidHeader,
                "The program-header entry size is not the ELF64 size.",
                ElfHeaderOffsets.ProgramHeaderEntrySize);
        }

        if (diagnostics.HasErrors)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var programHeaders = ParseProgramHeaders(reader, header, diagnostics, workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        if (limits?.RequireSingleDynamicWithoutInterpreter == true
            && (programHeaders.Count(programHeader => programHeader.Type == ElfConstants.PtDynamic) != 1
                || programHeaders.Any(programHeader => programHeader.Type == ElfConstants.PtInterp)))
        {
            diagnostics.Error(
                DiagnosticCode.InvalidProgramHeader,
                "The bounded ELF parse profile requires exactly one PT_DYNAMIC and no PT_INTERP.");
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        if (!programHeaders.Any(headerEntry => headerEntry.IsLoadable))
        {
            diagnostics.Error(DiagnosticCode.MissingLoadSegment, "The input has no PT_LOAD segment.");
        }

        if (diagnostics.HasErrors)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var requireCompleteSectionTable = limits?.RequireCompleteSectionHeaderTable == true;
        var sectionHeaders = ParseSectionHeaders(
            reader,
            header,
            diagnostics,
            workBudget,
            requireCompleteSectionTable);
        if (workBudget?.IsExceeded == true
            || (requireCompleteSectionTable && diagnostics.HasErrors))
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var loadMap = LoadMap.Create(programHeaders);
        var notes = ParseNotes(reader, programHeaders, diagnostics, workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var dynamicEntries = ParseDynamicEntries(reader, programHeaders, diagnostics, workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        if (limits is not null
            && TryGetForbiddenDynamicTag(
                dynamicEntries,
                limits.ForbiddenDynamicTags,
                limits.ForbiddenDynamicTagValueMasks,
                out var forbiddenTag))
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedDynamicTag,
                $"The bounded ELF parse policy rejects dynamic tag/value 0x{forbiddenTag:X} before expanded metadata traversal.");
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var dynamicMetadata = ParseDynamicMetadata(reader, loadMap, dynamicEntries, diagnostics, workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }
        var relaRelocations = ParseRelaRelocations(
            reader,
            loadMap,
            dynamicEntries,
            diagnostics,
            workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var sectionRelocations = ElfSectionRelocationParser.Parse(bytes, sectionHeaders, diagnostics, workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var relrWords = ParseRelrWords(reader, loadMap, dynamicEntries, diagnostics, workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var androidPackedRelocations = ParseAndroidPackedRelocations(
            reader,
            loadMap,
            dynamicEntries,
            diagnostics,
            workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var dynamicSymbols = ParseDynamicSymbols(reader, loadMap, dynamicEntries, diagnostics, workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }
        var functionSymbols = ParseFunctionSymbols(
            reader,
            sectionHeaders,
            dynamicMetadata,
            dynamicSymbols,
            diagnostics,
            workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }
        var symbolVersions = ElfSymbolVersionParser.Parse(
            reader,
            loadMap,
            dynamicEntries,
            dynamicMetadata,
            dynamicSymbols,
            diagnostics);
        var tlsMetadata = ElfTlsParser.Parse(
            bytes,
            programHeaders,
            sectionHeaders,
            loadMap,
            dynamicEntries,
            dynamicMetadata,
            dynamicSymbols,
            relaRelocations,
            diagnostics,
            workBudget);
        if (workBudget?.IsExceeded == true)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var file = new ElfFile(
            bytes,
            header,
            programHeaders,
            sectionHeaders,
            loadMap,
            notes,
            dynamicMetadata,
            symbolVersions,
            dynamicEntries,
            relaRelocations,
            sectionRelocations,
            relrWords,
            androidPackedRelocations,
            dynamicSymbols,
            functionSymbols,
            tlsMetadata);

        var validation = ElfValidator.Validate(file);
        foreach (var diagnostic in validation.Diagnostics)
        {
            diagnostics.Add(diagnostic);
        }

        return new ElfParseResult(file, diagnostics.ToArray());
    }

    private static bool TryGetForbiddenDynamicTag(
        IReadOnlyList<DynamicEntry> entries,
        IReadOnlySet<ulong> forbiddenTags,
        IReadOnlyDictionary<ulong, ulong> forbiddenValueMasks,
        out ulong tag)
    {
        foreach (var entry in entries)
        {
            if (forbiddenTags.Contains(entry.Tag)
                || (forbiddenValueMasks.TryGetValue(entry.Tag, out var forbiddenMask)
                    && (entry.Value & forbiddenMask) != 0))
            {
                tag = entry.Tag;
                return true;
            }
        }

        tag = default;
        return false;
    }

    private static bool HasElfMagic(BoundedReader reader)
    {
        return reader.TryReadByte(ElfHeaderOffsets.Magic, out var b0)
            && reader.TryReadByte(ElfHeaderOffsets.Magic + 1, out var b1)
            && reader.TryReadByte(ElfHeaderOffsets.Magic + 2, out var b2)
            && reader.TryReadByte(ElfHeaderOffsets.Magic + 3, out var b3)
            && b0 == 0x7F
            && b1 == (byte)'E'
            && b2 == (byte)'L'
            && b3 == (byte)'F';
    }

    private static bool TryReadHeader(BoundedReader reader, out ElfHeader header)
    {
        header = default;
        if (!reader.TryReadUInt16(ElfHeaderOffsets.Type, out var type)
            || !reader.TryReadUInt16(ElfHeaderOffsets.Machine, out var machine)
            || !reader.TryReadUInt32(ElfHeaderOffsets.Version, out var version)
            || !reader.TryReadUInt64(ElfHeaderOffsets.Entry, out var entry)
            || !reader.TryReadUInt64(ElfHeaderOffsets.ProgramHeaderOffset, out var programHeaderOffset)
            || !reader.TryReadUInt64(ElfHeaderOffsets.SectionHeaderOffset, out var sectionHeaderOffset)
            || !reader.TryReadUInt32(ElfHeaderOffsets.Flags, out var flags)
            || !reader.TryReadUInt16(ElfHeaderOffsets.HeaderSize, out var headerSize)
            || !reader.TryReadUInt16(ElfHeaderOffsets.ProgramHeaderEntrySize, out var programHeaderEntrySize)
            || !reader.TryReadUInt16(ElfHeaderOffsets.ProgramHeaderCount, out var programHeaderCount)
            || !reader.TryReadUInt16(ElfHeaderOffsets.SectionHeaderEntrySize, out var sectionHeaderEntrySize)
            || !reader.TryReadUInt16(ElfHeaderOffsets.SectionHeaderCount, out var sectionHeaderCount)
            || !reader.TryReadUInt16(ElfHeaderOffsets.SectionNameIndex, out var sectionNameIndex))
        {
            return false;
        }

        header = new ElfHeader(
            type,
            machine,
            version,
            entry,
            programHeaderOffset,
            sectionHeaderOffset,
            flags,
            headerSize,
            programHeaderEntrySize,
            programHeaderCount,
            sectionHeaderEntrySize,
            sectionHeaderCount,
            sectionNameIndex);
        return true;
    }

    private static List<ProgramHeader> ParseProgramHeaders(
        BoundedReader reader,
        ElfHeader header,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        if (workBudget is not null
            && !workBudget.TryReserveTable(
                header.ProgramHeaderCount,
                ElfConstants.ProgramHeaderSize64,
                workBudget.Limits.MaximumProgramHeaders,
                "program-header table",
                diagnostics,
                header.ProgramHeaderOffset))
        {
            return new List<ProgramHeader>();
        }

        var result = new List<ProgramHeader>(header.ProgramHeaderCount);
        if (header.ProgramHeaderCount == 0)
        {
            return result;
        }

        if (!TryTableRange(
                header.ProgramHeaderOffset,
                header.ProgramHeaderEntrySize,
                header.ProgramHeaderCount,
                reader.Length,
                out _))
        {
            diagnostics.Error(
                DiagnosticCode.TableOutOfBounds,
                "The program-header table is outside the input.",
                header.ProgramHeaderOffset);
            return result;
        }

        for (var index = 0; index < header.ProgramHeaderCount; index++)
        {
            if (!TryElementOffset(
                    header.ProgramHeaderOffset,
                    header.ProgramHeaderEntrySize,
                    (ulong)index,
                    out var offset)
                || !reader.TryReadUInt32(offset + ElfProgramHeaderOffsets.Type, out var type)
                || !reader.TryReadUInt32(offset + ElfProgramHeaderOffsets.Flags, out var flags)
                || !reader.TryReadUInt64(offset + ElfProgramHeaderOffsets.FileOffset, out var fileOffset)
                || !reader.TryReadUInt64(offset + ElfProgramHeaderOffsets.VirtualAddress, out var virtualAddress)
                || !reader.TryReadUInt64(offset + ElfProgramHeaderOffsets.PhysicalAddress, out var physicalAddress)
                || !reader.TryReadUInt64(offset + ElfProgramHeaderOffsets.FileSize, out var fileSize)
                || !reader.TryReadUInt64(offset + ElfProgramHeaderOffsets.MemorySize, out var memorySize)
                || !reader.TryReadUInt64(offset + ElfProgramHeaderOffsets.Alignment, out var alignment))
            {
                diagnostics.Error(
                    DiagnosticCode.InvalidProgramHeader,
                    $"Program header {index} is truncated.",
                    header.ProgramHeaderOffset);
                return result;
            }

            var programHeader = new ProgramHeader(
                type,
                flags,
                fileOffset,
                virtualAddress,
                physicalAddress,
                fileSize,
                memorySize,
                alignment);
            result.Add(programHeader);
            if (!programHeader.IsKnownType)
            {
                diagnostics.Warning(
                    DiagnosticCode.UnknownProgramHeaderType,
                    $"Program header {index} has unknown type 0x{type:X8}; it is preserved as raw metadata.",
                    offset);
            }
            ValidateProgramHeader(reader, programHeader, diagnostics);
        }

        return result;
    }

    private static void ValidateProgramHeader(
        BoundedReader reader,
        ProgramHeader header,
        DiagnosticBag diagnostics)
    {
        if (header.FileSize > header.MemorySize && header.IsLoadable)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidSegment,
                "A PT_LOAD file size cannot exceed its memory size.",
                header.Offset);
        }

        if (header.FileSize > 0 && !reader.Contains(header.Offset, header.FileSize))
        {
            diagnostics.Error(
                DiagnosticCode.TableOutOfBounds,
                "A program-header file range is outside the input.",
                header.Offset);
        }

        if (header.Alignment > 1)
        {
            if (!IsPowerOfTwo(header.Alignment))
            {
                diagnostics.Error(
                    DiagnosticCode.InvalidAlignment,
                    "A program-header alignment must be zero, one, or a power of two.",
                    header.Offset);
            }
            else if (header.Offset % header.Alignment != header.VirtualAddress % header.Alignment)
            {
                diagnostics.Error(
                    DiagnosticCode.InvalidAlignment,
                    "A program-header file and virtual address are not alignment-congruent.",
                    header.Offset);
            }
        }
    }

    private static List<SectionHeader> ParseSectionHeaders(
        BoundedReader reader,
        ElfHeader header,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget,
        bool requireCompleteDeclaredTable)
    {
        if (workBudget is not null
            && !workBudget.TryReserveTable(
                header.SectionHeaderCount,
                header.SectionHeaderEntrySize,
                workBudget.Limits.MaximumSectionHeaders,
                "section-header table",
                diagnostics,
                header.SectionHeaderOffset))
        {
            return new List<SectionHeader>();
        }

        if (requireCompleteDeclaredTable
            && !ValidateSectionHeaderDeclaration(header, diagnostics))
        {
            return new List<SectionHeader>();
        }

        var result = new List<SectionHeader>(header.SectionHeaderCount);
        if (header.SectionHeaderOffset == 0 || header.SectionHeaderCount == 0)
        {
            return result;
        }

        if (header.SectionHeaderEntrySize < ElfConstants.SectionHeaderSize64
            || !TryTableRange(
                header.SectionHeaderOffset,
                header.SectionHeaderEntrySize,
                header.SectionHeaderCount,
                reader.Length,
                out _))
        {
            if (requireCompleteDeclaredTable)
            {
                diagnostics.Error(
                    DiagnosticCode.TableOutOfBounds,
                    "The bounded ELF parse profile requires the complete declared section-header table to be in bounds.",
                    header.SectionHeaderOffset);
            }
            else
            {
                diagnostics.Warning(
                    DiagnosticCode.TableOutOfBounds,
                    "The optional section-header table could not be safely read and was ignored.",
                    header.SectionHeaderOffset);
            }

            return result;
        }

        for (var index = 0; index < header.SectionHeaderCount; index++)
        {
            if (!TryElementOffset(
                    header.SectionHeaderOffset,
                    header.SectionHeaderEntrySize,
                    (ulong)index,
                    out var offset)
                || !reader.TryReadUInt32(offset, out var name)
                || !reader.TryReadUInt32(offset + 4, out var type)
                || !reader.TryReadUInt64(offset + 8, out var flags)
                || !reader.TryReadUInt64(offset + 16, out var address)
                || !reader.TryReadUInt64(offset + 24, out var fileOffset)
                || !reader.TryReadUInt64(offset + 32, out var size)
                || !reader.TryReadUInt32(offset + 40, out var link)
                || !reader.TryReadUInt32(offset + 44, out var info)
                || !reader.TryReadUInt64(offset + 48, out var alignment)
                || !reader.TryReadUInt64(offset + 56, out var entrySize))
            {
                if (requireCompleteDeclaredTable)
                {
                    diagnostics.Error(
                        DiagnosticCode.TableOutOfBounds,
                        "The bounded ELF parse profile could not parse every declared section-header row.",
                        offset);
                }
                else
                {
                    diagnostics.Warning(
                        DiagnosticCode.TableOutOfBounds,
                        "The optional section-header table was truncated and was ignored.",
                        offset);
                }

                result.Clear();
                return result;
            }

            result.Add(new SectionHeader(
                name,
                type,
                flags,
                address,
                fileOffset,
                size,
                link,
                info,
                alignment,
                entrySize));
        }

        return result;
    }

    private static bool ValidateSectionHeaderDeclaration(
        ElfHeader header,
        DiagnosticBag diagnostics)
    {
        var sectionless = header.SectionHeaderOffset == 0
            && header.SectionHeaderCount == 0
            && header.SectionNameIndex == 0
            && header.SectionHeaderEntrySize is 0 or ElfConstants.SectionHeaderSize64;
        if (sectionless)
        {
            return true;
        }

        if (header.SectionHeaderOffset == 0
            || header.SectionHeaderCount == 0
            || header.SectionHeaderEntrySize < ElfConstants.SectionHeaderSize64
            || header.SectionNameIndex == ElfConstants.ShnXindex
            || header.SectionNameIndex >= header.SectionHeaderCount)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidHeader,
                "The bounded ELF parse profile requires a consistent sectionless declaration or a complete declared section table.",
                ElfHeaderOffsets.SectionHeaderOffset);
            return false;
        }

        return true;
    }

    private static List<ElfNote> ParseNotes(
        BoundedReader reader,
        IReadOnlyList<ProgramHeader> programHeaders,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        if (workBudget is not null)
        {
            ulong totalNoteBytes = 0;
            foreach (var header in programHeaders)
            {
                if (header.Type is not (ElfConstants.PtNote or ElfConstants.PtGnuProperty))
                {
                    continue;
                }

                if (header.FileSize > ulong.MaxValue - totalNoteBytes)
                {
                    workBudget.Fail("note-segment work size overflowed", diagnostics, header.Offset);
                    return new List<ElfNote>();
                }

                totalNoteBytes += header.FileSize;
            }

            if (!workBudget.TryCharge(totalNoteBytes, "note-segment traversal", diagnostics))
            {
                return new List<ElfNote>();
            }
        }

        var result = new List<ElfNote>();
        foreach (var header in programHeaders.Where(header =>
                     header.Type is ElfConstants.PtNote or ElfConstants.PtGnuProperty))
        {
            if (header.FileSize == 0)
            {
                continue;
            }

            if (!TryAdd(header.Offset, header.FileSize, out var segmentEnd))
            {
                diagnostics.Error(
                    DiagnosticCode.NoteMalformed,
                    "The note segment range overflowed.",
                    header.Offset);
                continue;
            }

            var cursor = header.Offset;
            while (cursor < segmentEnd)
            {
                if (segmentEnd - cursor < 12
                    || !reader.TryReadUInt32(cursor, out var nameSize)
                    || !reader.TryReadUInt32(cursor + 4, out var descriptorSize)
                    || !reader.TryReadUInt32(cursor + 8, out var type))
                {
                    diagnostics.Error(
                        DiagnosticCode.NoteMalformed,
                        "The ELF note header is truncated.",
                        cursor);
                    break;
                }

                var nameOffset = cursor + 12;
                if (!TryAlign4(nameSize, out var alignedNameSize)
                    || !TryAlign4(descriptorSize, out var alignedDescriptorSize)
                    || !TryAdd(nameOffset, alignedNameSize, out var descriptorOffset)
                    || !TryAdd(descriptorOffset, alignedDescriptorSize, out var nextOffset)
                    || nextOffset > segmentEnd
                    || !reader.Contains(nameOffset, nameSize)
                    || !reader.Contains(descriptorOffset, descriptorSize)
                    || !reader.TrySlice(nameOffset, nameSize, out var name)
                    || !reader.TrySlice(descriptorOffset, descriptorSize, out var descriptor))
                {
                    diagnostics.Error(
                        DiagnosticCode.NoteMalformed,
                        "The ELF note payload is outside the note segment.",
                        cursor);
                    break;
                }

                if (workBudget is not null
                    && (result.Count >= workBudget.Limits.MaximumNotes
                        || !workBudget.TryCharge(64, "ELF note record allocation", diagnostics, cursor)))
                {
                    if (!workBudget.IsExceeded)
                    {
                        workBudget.Fail(
                            $"ELF note record count exceeds limit {workBudget.Limits.MaximumNotes} before allocation",
                            diagnostics,
                            cursor);
                    }

                    return result;
                }

                result.Add(new ElfNote(header.Type, type, name, descriptor, cursor));
                cursor = nextOffset;
            }
        }

        return result;
    }

    private static ElfDynamicMetadata ParseDynamicMetadata(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        var stringTags = dynamicEntries.Where(entry => entry.Tag is
            ElfConstants.DtNeeded or
            ElfConstants.DtSoname or
            ElfConstants.DtRpath or
            ElfConstants.DtRunPath).ToArray();
        var hasStringTable = TryGetDynamicValue(dynamicEntries, ElfConstants.DtStrTab, out var stringAddress);
        var hasStringSize = TryGetDynamicValue(dynamicEntries, ElfConstants.DtStrSz, out var stringSize);
        if (!hasStringTable && !hasStringSize && stringTags.Length == 0)
        {
            return ElfDynamicMetadata.Empty;
        }

        if (workBudget is not null
            && (stringSize > (ulong)workBudget.Limits.MaximumDynamicStringTableBytes
                || !workBudget.TryCharge(stringSize, "dynamic string-table bytes", diagnostics, stringAddress)))
        {
            if (!workBudget.IsExceeded)
            {
                workBudget.Fail(
                    $"dynamic string-table size {stringSize} exceeds limit {workBudget.Limits.MaximumDynamicStringTableBytes} before string-table traversal",
                    diagnostics,
                    stringAddress);
            }

            return ElfDynamicMetadata.Empty;
        }

        if (!hasStringTable || !hasStringSize
            || !TryResolveVirtualRange(reader, loadMap, stringAddress, stringSize, out var fileOffset)
            || !reader.TrySlice(fileOffset, stringSize, out var stringTable))
        {
            diagnostics.Error(
                DiagnosticCode.DynamicTableMalformed,
                "The dynamic string table is missing or does not map to file-backed bytes.",
                stringAddress);
            return ElfDynamicMetadata.Empty;
        }

        var needed = new List<string>();
        string? soname = null;
        string? rpath = null;
        string? runPath = null;
        foreach (var entry in stringTags)
        {
            if (!TryReadString(stringTable, entry.Value, out var value, workBudget, diagnostics))
            {
                if (workBudget?.IsExceeded == true)
                {
                    return ElfDynamicMetadata.Empty;
                }

                diagnostics.Error(
                    DiagnosticCode.DynamicTableMalformed,
                    $"Dynamic string offset {entry.Value} is outside the string table.",
                    entry.Value);
                continue;
            }

            switch (entry.Tag)
            {
                case ElfConstants.DtNeeded:
                    needed.Add(value);
                    break;
                case ElfConstants.DtSoname:
                    soname = value;
                    break;
                case ElfConstants.DtRpath:
                    rpath = value;
                    break;
                case ElfConstants.DtRunPath:
                    runPath = value;
                    break;
            }
        }

        return new ElfDynamicMetadata(needed, soname, rpath, runPath, stringTable);
    }

    private static IReadOnlyList<DynamicEntry> ParseDynamicEntries(
        BoundedReader reader,
        IReadOnlyList<ProgramHeader> programHeaders,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        var dynamicHeader = programHeaders.FirstOrDefault(header => header.Type == ElfConstants.PtDynamic);
        if (dynamicHeader.Type != ElfConstants.PtDynamic)
        {
            return Array.Empty<DynamicEntry>();
        }

        if (dynamicHeader.FileSize % ElfConstants.DynamicEntrySize64 != 0)
        {
            diagnostics.Error(
                DiagnosticCode.DynamicTableMalformed,
                "The PT_DYNAMIC size is not a multiple of the ELF64 dynamic entry size.",
                dynamicHeader.Offset);
            return Array.Empty<DynamicEntry>();
        }

        var count = dynamicHeader.FileSize / ElfConstants.DynamicEntrySize64;
        if (workBudget is not null
            && !workBudget.TryReserveTable(
                count,
                ElfConstants.DynamicEntrySize64,
                workBudget.Limits.MaximumDynamicEntries,
                "PT_DYNAMIC entry table",
                diagnostics,
                dynamicHeader.Offset))
        {
            return Array.Empty<DynamicEntry>();
        }

        if (count > int.MaxValue)
        {
            diagnostics.Error(
                DiagnosticCode.DynamicTableMalformed,
                "The PT_DYNAMIC entry count is too large.",
                dynamicHeader.Offset);
            return Array.Empty<DynamicEntry>();
        }

        var result = new List<DynamicEntry>((int)count);
        var terminated = false;
        for (ulong index = 0; index < count; index++)
        {
            if (!TryElementOffset(
                    dynamicHeader.Offset,
                    ElfConstants.DynamicEntrySize64,
                    index,
                    out var offset)
                || !reader.TryReadUInt64(offset, out var tag)
                || !reader.TryReadUInt64(offset + 8, out var value))
            {
                diagnostics.Error(
                    DiagnosticCode.DynamicTableMalformed,
                    "The PT_DYNAMIC table contains a truncated entry.",
                    offset);
                break;
            }

            result.Add(new DynamicEntry(tag, value));
            if (tag == ElfConstants.DtNull)
            {
                terminated = true;
                break;
            }
        }

        if (!terminated)
        {
            diagnostics.Error(
                DiagnosticCode.DynamicTableUnterminated,
                "The PT_DYNAMIC table has no DT_NULL terminator.",
                dynamicHeader.Offset);
        }

        return result;
    }

    private static List<RelaRelocation> ParseRelaRelocations(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        var result = new List<RelaRelocation>();
        if (TryGetDynamicValue(dynamicEntries, ElfConstants.DtJmpRel, out _)
            && TryGetDynamicValue(dynamicEntries, ElfConstants.DtPltRel, out var pltRel)
            && pltRel != ElfConstants.DtRela)
        {
            diagnostics.Error(
                DiagnosticCode.RelocationTableMalformed,
                "The PLT relocation table is not an ELF64 RELA table.");
        }

        ParseRelaTable(ElfConstants.DtRela, ElfConstants.DtRelaSz, false);
        ParseRelaTable(ElfConstants.DtJmpRel, ElfConstants.DtPltRelSz, true);
        return result;

        void ParseRelaTable(ulong addressTag, ulong sizeTag, bool isPlt)
        {
            if (!TryGetDynamicValue(dynamicEntries, addressTag, out var address)
                || !TryGetDynamicValue(dynamicEntries, sizeTag, out var size)
                || size == 0)
            {
                return;
            }

            ulong entrySize = ElfConstants.RelaEntrySize64;
            if (TryGetDynamicValue(dynamicEntries, ElfConstants.DtRelaEnt, out var declaredEntrySize))
            {
                entrySize = declaredEntrySize;
            }

            if (entrySize != ElfConstants.RelaEntrySize64 || size % entrySize != 0)
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "The RELA table has an unsupported entry size or a partial entry.",
                    address);
                return;
            }

            if (!TryResolveVirtualRange(reader, loadMap, address, size, out var fileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.DynamicPointerUnmapped,
                    "The dynamic RELA table does not map to file-backed bytes.",
                    address);
                return;
            }

            var count = size / entrySize;
            if (workBudget is not null
                && !workBudget.TryReserveDynamicRelocationTable(
                    count,
                    entrySize,
                    "dynamic RELA relocation table",
                    diagnostics,
                    address))
            {
                return;
            }

            for (ulong index = 0; index < count; index++)
            {
                if (!TryElementOffset(fileOffset, entrySize, index, out var offset)
                    || !reader.TryReadUInt64(offset, out var relocationOffset)
                    || !reader.TryReadUInt64(offset + 8, out var info)
                    || !reader.TryReadInt64(offset + 16, out var addend))
                {
                    diagnostics.Error(
                        DiagnosticCode.RelocationTableMalformed,
                        "The RELA table contains a truncated entry.",
                        offset);
                    return;
                }

                if (!TryMultiply(index, entrySize, out var sourceDelta)
                    || !TryAdd(address, sourceDelta, out var sourceAddress))
                {
                    diagnostics.Error(
                        DiagnosticCode.AddressOverflow,
                        "The RELA source address overflowed.",
                        address);
                    return;
                }

                result.Add(new RelaRelocation(
                    relocationOffset,
                    info,
                    addend,
                    sourceAddress,
                    isPlt));
            }
        }
    }

    private static List<RelrWord> ParseRelrWords(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        var result = new List<RelrWord>();
        foreach (var tags in new[]
        {
            (Address: ElfConstants.DtRelr, Size: ElfConstants.DtRelrSz, Entry: ElfConstants.DtRelrEnt),
            (Address: ElfConstants.DtAndroidRelr, Size: ElfConstants.DtAndroidRelrsz, Entry: ElfConstants.DtAndroidRelrent),
        })
        {
            if (!TryGetDynamicValue(dynamicEntries, tags.Address, out var address)
                || !TryGetDynamicValue(dynamicEntries, tags.Size, out var size)
                || size == 0)
            {
                continue;
            }

            ulong entrySize = ElfConstants.RelrEntrySize64;
            if (TryGetDynamicValue(dynamicEntries, tags.Entry, out var declaredEntrySize))
            {
                entrySize = declaredEntrySize;
            }

            if (entrySize != ElfConstants.RelrEntrySize64 || size % entrySize != 0)
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "The RELR table has an unsupported entry size or a partial entry.",
                    address);
                continue;
            }

            if (!TryResolveVirtualRange(reader, loadMap, address, size, out var fileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.DynamicPointerUnmapped,
                    "The dynamic RELR table does not map to file-backed bytes.",
                    address);
                continue;
            }

            var count = size / entrySize;
            if (workBudget is not null
                && !workBudget.TryReserveRelrTable(
                    count,
                    entrySize,
                    "RELR relocation table",
                    diagnostics,
                    address))
            {
                continue;
            }

            for (ulong index = 0; index < count; index++)
            {
                if (!TryElementOffset(fileOffset, entrySize, index, out var offset)
                    || !reader.TryReadUInt64(offset, out var value))
                {
                    diagnostics.Error(
                        DiagnosticCode.RelocationTableMalformed,
                        "The RELR table contains a truncated entry.",
                        offset);
                    break;
                }

                if (!TryMultiply(index, entrySize, out var sourceDelta)
                    || !TryAdd(address, sourceDelta, out var sourceAddress))
                {
                    diagnostics.Error(
                        DiagnosticCode.AddressOverflow,
                        "The RELR source address overflowed.",
                        address);
                    break;
                }

                result.Add(new RelrWord(value, sourceAddress));
            }
        }

        return result;
    }

    private static List<AndroidPackedRelocationTable> ParseAndroidPackedRelocations(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        var result = new List<AndroidPackedRelocationTable>();
        ParseTable(ElfConstants.DtAndroidRel, ElfConstants.DtAndroidRelsz, isRela: false);
        ParseTable(ElfConstants.DtAndroidRela, ElfConstants.DtAndroidRelasz, isRela: true);
        return result;

        void ParseTable(ulong addressTag, ulong sizeTag, bool isRela)
        {
            var hasAddress = TryGetDynamicValue(dynamicEntries, addressTag, out var address);
            var hasSize = TryGetDynamicValue(dynamicEntries, sizeTag, out var size);
            if (!hasAddress && !hasSize)
            {
                return;
            }

            if (!hasAddress || !hasSize || size == 0)
            {
                if (size != 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.RelocationTableMalformed,
                        "The Android packed relocation table is missing an address or size tag.",
                        address);
                }

                return;
            }

            if (!TryResolveVirtualRange(reader, loadMap, address, size, out var fileOffset)
                || !reader.TrySlice(fileOffset, size, out var rawBytes))
            {
                diagnostics.Error(
                    DiagnosticCode.DynamicPointerUnmapped,
                    "The Android packed relocation table does not map to file-backed bytes.",
                    address);
                return;
            }

            result.Add(new AndroidPackedRelocationTable(address, size, isRela, rawBytes));
        }
    }

    private static IReadOnlyList<DynamicSymbol> ParseDynamicSymbols(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        if (!TryGetDynamicValue(dynamicEntries, ElfConstants.DtSymTab, out var address))
        {
            return Array.Empty<DynamicSymbol>();
        }

        ulong entrySize = ElfConstants.SymbolEntrySize64;
        if (TryGetDynamicValue(dynamicEntries, ElfConstants.DtSymEnt, out var declaredEntrySize))
        {
            entrySize = declaredEntrySize;
        }

        if (entrySize != ElfConstants.SymbolEntrySize64)
        {
            diagnostics.Error(
                DiagnosticCode.SymbolTableMalformed,
                "The dynamic symbol table has an unsupported entry size.",
                address);
            return Array.Empty<DynamicSymbol>();
        }

        if (!TryGetSymbolCount(
                reader,
                loadMap,
                dynamicEntries,
                diagnostics,
                workBudget,
                out var symbolCount))
        {
            if (workBudget?.IsExceeded == true)
            {
                return Array.Empty<DynamicSymbol>();
            }

            diagnostics.Warning(
                DiagnosticCode.SymbolTableMalformed,
                "The dynamic symbol count could not be derived from the available hash table; symbols were not materialized.",
                address);
            return Array.Empty<DynamicSymbol>();
        }

        if (workBudget is not null
            && !workBudget.TryReserveTable(
                symbolCount,
                entrySize,
                workBudget.Limits.MaximumDynamicSymbols,
                "dynamic symbol table",
                diagnostics,
                address))
        {
            return Array.Empty<DynamicSymbol>();
        }

        if (!TryMultiply(symbolCount, entrySize, out var size))
        {
            diagnostics.Error(
                DiagnosticCode.SymbolTableMalformed,
                "The dynamic symbol table size overflowed.",
                address);
            return Array.Empty<DynamicSymbol>();
        }
        if (!TryResolveVirtualRange(reader, loadMap, address, size, out var fileOffset))
        {
            diagnostics.Error(
                DiagnosticCode.DynamicPointerUnmapped,
                "The dynamic symbol table does not map to file-backed bytes.",
                address);
            return Array.Empty<DynamicSymbol>();
        }

        var result = new List<DynamicSymbol>(symbolCount > int.MaxValue ? int.MaxValue : (int)symbolCount);
        for (ulong index = 0; index < symbolCount; index++)
        {
            if (!TryElementOffset(fileOffset, entrySize, index, out var offset)
                || !reader.TryReadUInt32(offset, out var name)
                || !reader.TryReadByte(offset + 4, out var info)
                || !reader.TryReadByte(offset + 5, out var other)
                || !reader.TryReadUInt16(offset + 6, out var sectionIndex)
                || !reader.TryReadUInt64(offset + 8, out var value)
                || !reader.TryReadUInt64(offset + 16, out var symbolSize))
            {
                diagnostics.Error(
                    DiagnosticCode.SymbolTableMalformed,
                    "The dynamic symbol table contains a truncated entry.",
                    offset);
                return result;
            }

            result.Add(new DynamicSymbol(name, info, other, sectionIndex, value, symbolSize));
        }

        return result;
    }

    private static List<ElfFunctionSymbol> ParseFunctionSymbols(
        BoundedReader reader,
        IReadOnlyList<SectionHeader> sectionHeaders,
        ElfDynamicMetadata dynamicMetadata,
        IReadOnlyList<DynamicSymbol> dynamicSymbols,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget)
    {
        var result = new List<ElfFunctionSymbol>();
        if (workBudget is not null
            && !workBudget.TryCharge((ulong)dynamicSymbols.Count, "dynamic function-symbol projection", diagnostics))
        {
            return result;
        }

        for (var index = 0; index < dynamicSymbols.Count; index++)
        {
            var symbol = dynamicSymbols[index];
            if ((symbol.Info & 0x0F) != ElfConstants.SttFunc || symbol.Size == 0)
            {
                continue;
            }

            if (!TryReadString(dynamicMetadata.StringTable, symbol.Name, out var name, workBudget, diagnostics))
            {
                if (workBudget?.IsExceeded == true)
                {
                    return result;
                }

                diagnostics.Warning(
                    DiagnosticCode.SymbolTableMalformed,
                    "A dynamic function symbol name is outside the dynamic string table.",
                    symbol.Name);
                continue;
            }

            result.Add(new ElfFunctionSymbol(
                name,
                ElfSymbolTableKind.Dynamic,
                checked((uint)index),
                (byte)(symbol.Info >> 4),
                symbol.Other,
                symbol.SectionIndex,
                symbol.Value,
                symbol.Size));
        }

        for (var sectionIndex = 0; sectionIndex < sectionHeaders.Count; sectionIndex++)
        {
            var symbolTable = sectionHeaders[sectionIndex];
            if (symbolTable.Type != ElfConstants.ShtSymTab)
            {
                continue;
            }

            if (symbolTable.EntrySize == 0
                || symbolTable.EntrySize != ElfConstants.SymbolEntrySize64
                || symbolTable.Size % symbolTable.EntrySize != 0
                || symbolTable.Link >= (uint)sectionHeaders.Count)
            {
                diagnostics.Warning(
                    DiagnosticCode.SymbolTableMalformed,
                    "A static symbol table has an unsupported layout and was ignored.",
                    symbolTable.Offset);
                continue;
            }

            var stringTable = sectionHeaders[(int)symbolTable.Link];
            if (stringTable.Type != ElfConstants.ShtStrTab
                || !reader.Contains(stringTable.Offset, stringTable.Size)
                || !reader.TrySlice(stringTable.Offset, stringTable.Size, out var strings))
            {
                diagnostics.Warning(
                    DiagnosticCode.SymbolTableMalformed,
                    "A static symbol table string table is not file-backed.",
                    stringTable.Offset);
                continue;
            }

            var count = symbolTable.Size / symbolTable.EntrySize;
            if (workBudget is not null
                && !workBudget.TryReserveStaticSymbolTable(
                    count,
                    symbolTable.EntrySize,
                    "static symbol table",
                    diagnostics,
                    symbolTable.Offset))
            {
                return result;
            }

            if (count > int.MaxValue
                || !reader.Contains(symbolTable.Offset, symbolTable.Size))
            {
                diagnostics.Warning(
                    DiagnosticCode.SymbolTableMalformed,
                    "A static symbol table is outside the input.",
                    symbolTable.Offset);
                continue;
            }

            for (ulong symbolIndex = 0; symbolIndex < count; symbolIndex++)
            {
                if (!TryElementOffset(
                        symbolTable.Offset,
                        symbolTable.EntrySize,
                        symbolIndex,
                        out var offset)
                    || !reader.TryReadUInt32(offset, out var nameOffset)
                    || !reader.TryReadByte(offset + 4, out var info)
                    || !reader.TryReadByte(offset + 5, out var other)
                    || !reader.TryReadUInt16(offset + 6, out var section)
                    || !reader.TryReadUInt64(offset + 8, out var value)
                    || !reader.TryReadUInt64(offset + 16, out var size))
                {
                    diagnostics.Warning(
                        DiagnosticCode.SymbolTableMalformed,
                        "A static symbol table contains a truncated entry.",
                        offset);
                    break;
                }

                if ((info & 0x0F) != ElfConstants.SttFunc
                    || size == 0
                    || !TryReadString(strings, nameOffset, out var name, workBudget, diagnostics))
                {
                    continue;
                }

                result.Add(new ElfFunctionSymbol(
                    name,
                    ElfSymbolTableKind.Static,
                    checked((uint)symbolIndex),
                    (byte)(info >> 4),
                    other,
                    section,
                    value,
                    size));
            }
        }

        return result;
    }

    private static bool TryGetSymbolCount(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget,
        out ulong symbolCount)
    {
        if (TryGetDynamicValue(dynamicEntries, ElfConstants.DtHash, out var hashAddress))
        {
            if (TryResolveVirtualRange(reader, loadMap, hashAddress, 8, out var hashFileOffset)
                && reader.TryReadUInt32(hashFileOffset + 4, out var count))
            {
                symbolCount = count;
                if (workBudget is not null
                    && symbolCount > (ulong)workBudget.Limits.MaximumDynamicSymbols)
                {
                    workBudget.Fail(
                        $"dynamic symbol count {symbolCount} exceeds limit {workBudget.Limits.MaximumDynamicSymbols} before symbol-table allocation",
                        diagnostics,
                        hashAddress);
                    return false;
                }

                return true;
            }

            symbolCount = default;
            return false;
        }

        if (!TryGetDynamicValue(dynamicEntries, ElfConstants.DtGnuHash, out var gnuHashAddress)
            || !TryResolveVirtualRange(reader, loadMap, gnuHashAddress, 16, out var gnuHashFileOffset)
            || !reader.TryReadUInt32(gnuHashFileOffset, out var bucketCount)
            || !reader.TryReadUInt32(gnuHashFileOffset + 4, out var symbolOffset)
            || !reader.TryReadUInt32(gnuHashFileOffset + 8, out var bloomWordCount)
            || !reader.TryReadUInt32(gnuHashFileOffset + 12, out _)
            || bucketCount == 0
            || bloomWordCount == 0)
        {
            symbolCount = default;
            return false;
        }

        if (workBudget is not null
            && (bucketCount > (uint)workBudget.Limits.MaximumDynamicSymbols
                || bloomWordCount > (uint)workBudget.Limits.MaximumDynamicSymbols))
        {
            workBudget.Fail(
                $"GNU hash bucket/bloom count exceeds the dynamic-symbol limit {workBudget.Limits.MaximumDynamicSymbols} before bucket or chain traversal",
                diagnostics,
                gnuHashAddress);
            symbolCount = default;
            return false;
        }

        if (!TryMultiply(bloomWordCount, sizeof(ulong), out var bloomBytes)
            || !TryMultiply(bucketCount, sizeof(uint), out var bucketBytes)
            || !TryAdd(gnuHashAddress, 16, out var bloomAddress)
            || !TryAdd(bloomAddress, bloomBytes, out var bucketAddress)
            || !TryResolveVirtualRange(reader, loadMap, bucketAddress, bucketBytes, out var bucketFileOffset))
        {
            diagnostics.Error(
                DiagnosticCode.SymbolTableMalformed,
                "The GNU hash table layout is outside file-backed memory.",
                gnuHashAddress);
            symbolCount = default;
            return false;
        }

        if (workBudget is not null
            && !workBudget.TryCharge(bucketBytes, "GNU hash bucket traversal", diagnostics, bucketAddress))
        {
            symbolCount = default;
            return false;
        }

        // The bounded provider profile walks GNU hash chains after the bucket array.
        // Keep the ordinary no-profile parser path unchanged in this scoped remediation.
        var chainTableAddress = bucketAddress;
        if (workBudget is not null
            && !TryAdd(bucketAddress, bucketBytes, out chainTableAddress))
        {
            diagnostics.Error(
                DiagnosticCode.SymbolTableMalformed,
                "The bounded GNU hash chain table address overflows.",
                gnuHashAddress);
            symbolCount = default;
            return false;
        }

        ulong maxSymbol = symbolOffset == 0 ? 0 : symbolOffset - 1;
        var foundSymbol = false;
        var maxChainEntries = workBudget is null
            ? (ulong)Math.Max(1, reader.Length / sizeof(uint))
            : (ulong)workBudget.Limits.MaximumDynamicSymbols;
        for (ulong bucketIndex = 0; bucketIndex < bucketCount; bucketIndex++)
        {
            if (!TryElementOffset(bucketFileOffset, sizeof(uint), bucketIndex, out var bucketOffset)
                || !reader.TryReadUInt32(bucketOffset, out var bucketValue)
                || bucketValue < symbolOffset)
            {
                continue;
            }

            foundSymbol = true;
            var symbolIndex = (ulong)bucketValue;
            if (workBudget is not null && symbolIndex >= (ulong)workBudget.Limits.MaximumDynamicSymbols)
            {
                workBudget.Fail(
                    $"GNU hash bucket symbol index {symbolIndex} exceeds dynamic-symbol limit {workBudget.Limits.MaximumDynamicSymbols}",
                    diagnostics,
                    gnuHashAddress);
                symbolCount = default;
                return false;
            }

            for (ulong chainIndex = 0; chainIndex < maxChainEntries; chainIndex++)
            {
                if (workBudget is not null
                    && !workBudget.TryCharge(sizeof(uint), "GNU hash chain traversal", diagnostics, gnuHashAddress))
                {
                    symbolCount = default;
                    return false;
                }

                if (symbolIndex < symbolOffset
                    || !TrySubtract(symbolIndex, symbolOffset, out var chainIndexValue)
                    || !TryMultiply(chainIndexValue, sizeof(uint), out var chainDelta)
                    || !TryAdd(chainTableAddress, chainDelta, out var chainAddress)
                    || !TryResolveVirtualRange(reader, loadMap, chainAddress, sizeof(uint), out var chainFileOffset)
                    || !reader.TryReadUInt32(chainFileOffset, out var chainValue))
                {
                    diagnostics.Error(
                        DiagnosticCode.SymbolTableMalformed,
                        "The GNU hash chain is truncated or overflows.",
                        gnuHashAddress);
                    symbolCount = default;
                    return false;
                }

                maxSymbol = Math.Max(maxSymbol, symbolIndex);
                if ((chainValue & 1) != 0)
                {
                    break;
                }

                if (symbolIndex == ulong.MaxValue)
                {
                    diagnostics.Error(
                        DiagnosticCode.SymbolTableMalformed,
                        "The GNU hash chain index overflowed.",
                        gnuHashAddress);
                    symbolCount = default;
                    return false;
                }

                symbolIndex++;
                if (chainIndex == maxChainEntries - 1)
                {
                    if (workBudget is not null)
                    {
                        workBudget.Fail(
                            $"GNU hash chain exceeds dynamic-symbol limit {workBudget.Limits.MaximumDynamicSymbols} without termination before reading another chain entry",
                            diagnostics,
                            gnuHashAddress);
                    }
                    else
                    {
                        diagnostics.Error(
                            DiagnosticCode.SymbolTableMalformed,
                            "The GNU hash chain has no terminating entry.",
                            gnuHashAddress);
                    }

                    symbolCount = default;
                    return false;
                }
            }
        }

        symbolCount = foundSymbol ? maxSymbol + 1 : symbolOffset;
        if (workBudget is not null
            && symbolCount > (ulong)workBudget.Limits.MaximumDynamicSymbols)
        {
            workBudget.Fail(
                $"GNU-hash-derived dynamic symbol count {symbolCount} exceeds limit {workBudget.Limits.MaximumDynamicSymbols}",
                diagnostics,
                gnuHashAddress);
            return false;
        }

        return true;
    }

}

/// <summary>Opt-in parser limits for a bounded structural ELF consumer.</summary>
internal sealed record ElfParserLimits(
    int MaximumInputBytes,
    int MaximumProgramHeaders,
    int MaximumSectionHeaders,
    int MaximumDynamicEntries,
    int MaximumNotes,
    int MaximumDynamicSymbols,
    int MaximumStaticSymbols,
    int MaximumDynamicRelocationRows,
    int MaximumSectionRelocationRows,
    int MaximumRelrRows,
    int MaximumDynamicStringTableBytes,
    int MaximumStringScanBytes,
    ulong MaximumAggregateWorkBytes,
    IReadOnlySet<ulong> ForbiddenDynamicTags,
    IReadOnlyDictionary<ulong, ulong> ForbiddenDynamicTagValueMasks,
    bool RequireSingleDynamicWithoutInterpreter = false,
    bool RequireCompleteSectionHeaderTable = false);

/// <summary>
/// Shared work accounting used only by an opt-in bounded parser profile. The
/// budget is charged before allocations, record walks, or bounded string scans.
/// </summary>
internal sealed class ElfParserWorkBudget(ElfParserLimits limits)
{
    private ulong workBytes;
    private ulong staticSymbolRows;
    private ulong dynamicRelocationRows;
    private ulong relrRows;

    public ElfParserLimits Limits { get; } = limits ?? throw new ArgumentNullException(nameof(limits));

    public bool IsExceeded { get; private set; }

    public bool ValidateInputLength(int inputBytes, DiagnosticBag diagnostics)
    {
        if (inputBytes < 0 || inputBytes > Limits.MaximumInputBytes)
        {
            return Fail(
                $"input size {inputBytes} exceeds the bounded provider parse input limit {Limits.MaximumInputBytes}",
                diagnostics);
        }

        return true;
    }

    public bool TryReserveTable(
        ulong count,
        ulong rowSize,
        int maximumRows,
        string description,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (count > (ulong)maximumRows)
        {
            return Fail(
                $"{description} declares {count} rows, exceeding its {maximumRows}-row limit before allocation or traversal",
                diagnostics,
                offset);
        }

        if (rowSize != 0 && count > ulong.MaxValue / rowSize)
        {
            return Fail($"{description} byte size overflows before allocation or traversal", diagnostics, offset);
        }

        return TryCharge(count * rowSize, description, diagnostics, offset);
    }

    public bool TryReserveStaticSymbolTable(
        ulong count,
        ulong rowSize,
        string description,
        DiagnosticBag diagnostics,
        ulong? offset = null) =>
        TryReserveAggregateRows(
            ref staticSymbolRows,
            count,
            rowSize,
            Limits.MaximumStaticSymbols,
            description,
            diagnostics,
            offset);

    public bool TryReserveDynamicRelocationTable(
        ulong count,
        ulong rowSize,
        string description,
        DiagnosticBag diagnostics,
        ulong? offset = null) =>
        TryReserveAggregateRows(
            ref dynamicRelocationRows,
            count,
            rowSize,
            Limits.MaximumDynamicRelocationRows,
            description,
            diagnostics,
            offset);

    public bool TryReserveRelrTable(
        ulong count,
        ulong rowSize,
        string description,
        DiagnosticBag diagnostics,
        ulong? offset = null) =>
        TryReserveAggregateRows(
            ref relrRows,
            count,
            rowSize,
            Limits.MaximumRelrRows,
            description,
            diagnostics,
            offset);

    public bool TryCharge(
        ulong amount,
        string description,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (IsExceeded)
        {
            return false;
        }

        if (amount > Limits.MaximumAggregateWorkBytes - workBytes)
        {
            return Fail(
                $"the bounded ELF parser exceeded its {Limits.MaximumAggregateWorkBytes}-byte aggregate work budget before {description}",
                diagnostics,
                offset);
        }

        workBytes += amount;
        return true;
    }

    private bool TryReserveAggregateRows(
        ref ulong reservedRows,
        ulong count,
        ulong rowSize,
        int maximumRows,
        string description,
        DiagnosticBag diagnostics,
        ulong? offset)
    {
        if (count > (ulong)maximumRows - reservedRows)
        {
            return Fail(
                $"aggregate {description} rows exceed limit {maximumRows} before allocation or traversal",
                diagnostics,
                offset);
        }

        if (rowSize != 0 && count > ulong.MaxValue / rowSize)
        {
            return Fail($"{description} byte size overflows before allocation or traversal", diagnostics, offset);
        }

        if (!TryCharge(count * rowSize, description, diagnostics, offset))
        {
            return false;
        }

        reservedRows += count;
        return true;
    }

    public bool TryGetStringScanLength(
        ulong remainingBytes,
        ulong offset,
        DiagnosticBag diagnostics,
        out ulong scanLength)
    {
        scanLength = Math.Min(remainingBytes, (ulong)Limits.MaximumStringScanBytes);
        return TryCharge(scanLength, "dynamic/static symbol string scan", diagnostics, offset);
    }

    public bool Fail(string reason, DiagnosticBag diagnostics, ulong? offset = null)
    {
        if (!IsExceeded)
        {
            diagnostics.Error(DiagnosticCode.ElfParserWorkLimitExceeded, $"The bounded ELF parser rejected input: {reason}.", offset);
            IsExceeded = true;
        }

        return false;
    }
}
