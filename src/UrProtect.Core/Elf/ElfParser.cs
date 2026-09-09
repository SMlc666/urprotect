using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Elf;

public static class ElfParser
{
    public static ElfParseResult Parse(ReadOnlyMemory<byte> bytes)
    {
        var diagnostics = new DiagnosticBag();
        var reader = new BoundedReader(bytes);
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

        if (!reader.TryReadByte(4, out var elfClass) || elfClass != ElfConstants.Class64)
        {
            diagnostics.Error(DiagnosticCode.UnsupportedClass, "Only ELFCLASS64 inputs are supported.", 4);
        }

        if (!reader.TryReadByte(5, out var dataEncoding) || dataEncoding != ElfConstants.LittleEndian)
        {
            diagnostics.Error(DiagnosticCode.UnsupportedEndianness, "Only little-endian ELF inputs are supported.", 5);
        }

        if (!reader.TryReadByte(6, out var identVersion) || identVersion != 1)
        {
            diagnostics.Error(DiagnosticCode.InvalidHeader, "Only the current ELF identification version is supported.", 6);
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

        if (header.Machine != ElfConstants.MachineAarch64)
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedMachine,
                $"Machine 0x{header.Machine:X} is not AArch64.",
                18);
        }

        if (header.Type != ElfConstants.TypeDyn)
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedFileType,
                $"ELF type {header.Type} is not the supported ET_DYN type.",
                16);
        }

        if (header.Version != 1)
        {
            diagnostics.Error(DiagnosticCode.InvalidHeader, "Only the current ELF header version is supported.", 20);
        }

        if (header.HeaderSize != ElfConstants.HeaderSize64)
        {
            diagnostics.Error(DiagnosticCode.InvalidHeader, "The ELF64 header size is not exactly 64 bytes.", 52);
        }

        if (header.ProgramHeaderCount > 0
            && header.ProgramHeaderEntrySize != ElfConstants.ProgramHeaderSize64)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidHeader,
                "The program-header entry size is not the ELF64 size.",
                54);
        }

        if (diagnostics.HasErrors)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var programHeaders = ParseProgramHeaders(reader, header, diagnostics);
        if (!programHeaders.Any(headerEntry => headerEntry.IsLoadable))
        {
            diagnostics.Error(DiagnosticCode.MissingLoadSegment, "The input has no PT_LOAD segment.");
        }

        if (diagnostics.HasErrors)
        {
            return new ElfParseResult(null, diagnostics.ToArray());
        }

        var sectionHeaders = ParseSectionHeaders(reader, header, diagnostics);
        var loadMap = LoadMap.Create(programHeaders);
        var dynamicEntries = ParseDynamicEntries(reader, programHeaders, diagnostics);
        var relaRelocations = ParseRelaRelocations(
            reader,
            loadMap,
            dynamicEntries,
            diagnostics);
        var relrWords = ParseRelrWords(reader, loadMap, dynamicEntries, diagnostics);
        var dynamicSymbols = ParseDynamicSymbols(reader, loadMap, dynamicEntries, diagnostics);

        var file = new ElfFile(
            bytes,
            header,
            programHeaders,
            sectionHeaders,
            loadMap,
            dynamicEntries,
            relaRelocations,
            relrWords,
            dynamicSymbols);

        var validation = ElfValidator.Validate(file);
        foreach (var diagnostic in validation.Diagnostics)
        {
            diagnostics.Add(diagnostic);
        }

        return new ElfParseResult(file, diagnostics.ToArray());
    }

    private static bool HasElfMagic(BoundedReader reader)
    {
        return reader.TryReadByte(0, out var b0)
            && reader.TryReadByte(1, out var b1)
            && reader.TryReadByte(2, out var b2)
            && reader.TryReadByte(3, out var b3)
            && b0 == 0x7F
            && b1 == (byte)'E'
            && b2 == (byte)'L'
            && b3 == (byte)'F';
    }

    private static bool TryReadHeader(BoundedReader reader, out ElfHeader header)
    {
        header = default;
        if (!reader.TryReadUInt16(16, out var type)
            || !reader.TryReadUInt16(18, out var machine)
            || !reader.TryReadUInt32(20, out var version)
            || !reader.TryReadUInt64(24, out var entry)
            || !reader.TryReadUInt64(32, out var programHeaderOffset)
            || !reader.TryReadUInt64(40, out var sectionHeaderOffset)
            || !reader.TryReadUInt32(48, out var flags)
            || !reader.TryReadUInt16(52, out var headerSize)
            || !reader.TryReadUInt16(54, out var programHeaderEntrySize)
            || !reader.TryReadUInt16(56, out var programHeaderCount)
            || !reader.TryReadUInt16(58, out var sectionHeaderEntrySize)
            || !reader.TryReadUInt16(60, out var sectionHeaderCount)
            || !reader.TryReadUInt16(62, out var sectionNameIndex))
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
        DiagnosticBag diagnostics)
    {
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
                || !reader.TryReadUInt32(offset, out var type)
                || !reader.TryReadUInt32(offset + 4, out var flags)
                || !reader.TryReadUInt64(offset + 8, out var fileOffset)
                || !reader.TryReadUInt64(offset + 16, out var virtualAddress)
                || !reader.TryReadUInt64(offset + 24, out var physicalAddress)
                || !reader.TryReadUInt64(offset + 32, out var fileSize)
                || !reader.TryReadUInt64(offset + 40, out var memorySize)
                || !reader.TryReadUInt64(offset + 48, out var alignment))
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
        DiagnosticBag diagnostics)
    {
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
            diagnostics.Warning(
                DiagnosticCode.TableOutOfBounds,
                "The optional section-header table could not be safely read and was ignored.",
                header.SectionHeaderOffset);
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
                diagnostics.Warning(
                    DiagnosticCode.TableOutOfBounds,
                    "The optional section-header table was truncated and was ignored.",
                    offset);
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

    private static IReadOnlyList<DynamicEntry> ParseDynamicEntries(
        BoundedReader reader,
        IReadOnlyList<ProgramHeader> programHeaders,
        DiagnosticBag diagnostics)
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
        DiagnosticBag diagnostics)
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
        DiagnosticBag diagnostics)
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

    private static IReadOnlyList<DynamicSymbol> ParseDynamicSymbols(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics)
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
                out var symbolCount))
        {
            diagnostics.Warning(
                DiagnosticCode.SymbolTableMalformed,
                "The dynamic symbol count could not be derived from the available hash table; symbols were not materialized.",
                address);
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

    private static bool TryGetSymbolCount(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics,
        out ulong symbolCount)
    {
        if (TryGetDynamicValue(dynamicEntries, ElfConstants.DtHash, out var hashAddress))
        {
            if (TryResolveVirtualRange(reader, loadMap, hashAddress, 8, out var hashFileOffset)
                && reader.TryReadUInt32(hashFileOffset + 4, out var count))
            {
                symbolCount = count;
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

        ulong maxSymbol = symbolOffset == 0 ? 0 : symbolOffset - 1;
        var foundSymbol = false;
        var maxChainEntries = (ulong)Math.Max(1, reader.Length / sizeof(uint));
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
            for (ulong chainIndex = 0; chainIndex < maxChainEntries; chainIndex++)
            {
                if (symbolIndex < symbolOffset
                    || !TrySubtract(symbolIndex, symbolOffset, out var chainIndexValue)
                    || !TryMultiply(chainIndexValue, sizeof(uint), out var chainDelta)
                    || !TryAdd(bucketAddress, chainDelta, out var chainAddress)
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
                    diagnostics.Error(
                        DiagnosticCode.SymbolTableMalformed,
                        "The GNU hash chain has no terminating entry.",
                        gnuHashAddress);
                    symbolCount = default;
                    return false;
                }
            }
        }

        symbolCount = foundSymbol ? maxSymbol + 1 : symbolOffset;
        return true;
    }

    private static bool TryResolveVirtualRange(
        BoundedReader reader,
        LoadMap loadMap,
        ulong virtualAddress,
        ulong size,
        out ulong fileOffset)
    {
        fileOffset = default;
        return loadMap.TryVirtualAddressToFileOffset(virtualAddress, size, out fileOffset)
            && reader.Contains(fileOffset, size);
    }

    private static bool TryGetDynamicValue(
        IReadOnlyList<DynamicEntry> entries,
        ulong tag,
        out ulong value)
    {
        foreach (var entry in entries)
        {
            if (entry.Tag == tag)
            {
                value = entry.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static bool TryTableRange(
        ulong offset,
        ulong entrySize,
        ulong count,
        int sourceLength,
        out ulong size)
    {
        size = 0;
        if (!TryMultiply(entrySize, count, out size))
        {
            return false;
        }

        return TryAdd(offset, size, out var end) && end <= (ulong)sourceLength;
    }

    private static bool TryElementOffset(
        ulong baseOffset,
        ulong entrySize,
        ulong index,
        out ulong offset)
    {
        offset = default;
        return TryMultiply(entrySize, index, out var delta)
            && TryAdd(baseOffset, delta, out offset)
            && offset <= int.MaxValue;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        result = left + right;
        return result >= left;
    }

    private static bool TrySubtract(ulong left, ulong right, out ulong result)
    {
        if (left < right)
        {
            result = default;
            return false;
        }

        result = left - right;
        return true;
    }

    private static bool TryMultiply(ulong left, ulong right, out ulong result)
    {
        if (left != 0 && right > ulong.MaxValue / left)
        {
            result = default;
            return false;
        }

        result = left * right;
        return true;
    }

    private static bool IsPowerOfTwo(ulong value) => (value & (value - 1)) == 0;
}
