using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.StructuralElf;

/// <summary>Parses and validates bounded TLS metadata without consulting an instruction decoder.</summary>
internal static class ElfTlsParser
{
    private const byte SymbolTypeTls = 6;
    private const ushort SymbolUndefined = 0;
    private const int MaximumTlsRelocations = 1_048_576;

    public static ElfTlsMetadata Parse(
        ReadOnlyMemory<byte> bytes,
        IReadOnlyList<ProgramHeader> programHeaders,
        IReadOnlyList<SectionHeader> sectionHeaders,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        ElfDynamicMetadata dynamicMetadata,
        IReadOnlyList<DynamicSymbol> dynamicSymbols,
        IReadOnlyList<RelaRelocation> relocations,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(programHeaders);
        ArgumentNullException.ThrowIfNull(sectionHeaders);
        ArgumentNullException.ThrowIfNull(loadMap);
        ArgumentNullException.ThrowIfNull(dynamicEntries);
        ArgumentNullException.ThrowIfNull(dynamicMetadata);
        ArgumentNullException.ThrowIfNull(dynamicSymbols);
        ArgumentNullException.ThrowIfNull(relocations);
        ArgumentNullException.ThrowIfNull(diagnostics);

        var segments = ParseSegments(bytes, programHeaders, diagnostics);
        var descriptorPlt = ParseOptionalDynamicAddress(
            ElfConstants.DtTlsDescPlt,
            "DT_TLSDESC_PLT",
            dynamicEntries,
            programHeaders,
            diagnostics,
            requireExecutable: true);
        var descriptorGot = ParseOptionalDynamicAddress(
            ElfConstants.DtTlsDescGot,
            "DT_TLSDESC_GOT",
            dynamicEntries,
            programHeaders,
            diagnostics,
            requireExecutable: false);
        if (descriptorPlt.HasValue != descriptorGot.HasValue)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "DT_TLSDESC_PLT and DT_TLSDESC_GOT must be present together.");
        }

        var relocationTables = ParseRelocationTables(bytes, loadMap, dynamicEntries, diagnostics);
        var tlsRelocations = ParseRelocations(
            programHeaders,
            loadMap,
            dynamicMetadata,
            dynamicSymbols,
            relocations,
            relocationTables,
            segments,
            diagnostics);
        var staticRelocations = ParseStaticRelocations(
            bytes,
            sectionHeaders,
            loadMap,
            segments,
            relocationTables,
            diagnostics);
        ValidateCrossTableRelocationOverlaps(
            tlsRelocations.Concat(staticRelocations.Relocations).ToArray(),
            diagnostics);
        var dynamic = new TlsDynamicFacts(
            Array.AsReadOnly(relocationTables.ToArray()),
            Array.AsReadOnly(tlsRelocations.ToArray()),
            descriptorPlt,
            descriptorGot,
            dynamicMetadata.Soname);
        return new ElfTlsMetadata(
            Array.AsReadOnly(segments.ToArray()),
            dynamic,
            Array.AsReadOnly(staticRelocations.Tables.ToArray()),
            Array.AsReadOnly(staticRelocations.Relocations.ToArray()));
    }

    private static List<TlsSegmentFacts> ParseSegments(
        ReadOnlyMemory<byte> bytes,
        IReadOnlyList<ProgramHeader> programHeaders,
        DiagnosticBag diagnostics)
    {
        var result = new List<TlsSegmentFacts>();
        var reader = new BoundedReader(bytes);
        var candidates = programHeaders
            .Select((header, index) => (Header: header, Index: index))
            .Where(item => item.Header.Type == ElfConstants.PtTls)
            .ToArray();
        if (candidates.Length > 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The ELF contains more than one PT_TLS segment.");
        }

        foreach (var (header, index) in candidates)
        {
            var valid = true;
            if (header.FileSize > header.MemorySize)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "PT_TLS p_filesz exceeds p_memsz.",
                    header.Offset);
                valid = false;
            }

            if (header.MemorySize == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "PT_TLS has an empty memory template range.",
                    header.Offset);
                valid = false;
            }

            if (header.Alignment > 1
                && (!IsPowerOfTwo(header.Alignment)
                    || header.Offset % header.Alignment != header.VirtualAddress % header.Alignment))
            {
                diagnostics.Error(
                    DiagnosticCode.InvalidAlignment,
                    "PT_TLS alignment must be a power of two and its file/virtual addresses must be congruent.",
                    header.Offset);
                valid = false;
            }

            if ((header.Flags & ElfConstants.PfX) != 0
                || (header.Flags & ElfConstants.PfR) == 0
                || (header.Flags & ~(ElfConstants.PfR | ElfConstants.PfW)) != 0)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "PT_TLS permissions must be readable and must not request executable or unknown permissions.",
                    header.Offset);
                valid = false;
            }

            if (!TryAdd(header.Offset, header.FileSize, out _)
                || !TryAdd(header.VirtualAddress, header.MemorySize, out _)
                || (header.FileSize != 0 && !reader.Contains(header.Offset, header.FileSize)))
            {
                diagnostics.Error(
                    DiagnosticCode.TableOutOfBounds,
                    "The PT_TLS template or memory range overflows its bounded address domain.",
                    header.Offset);
                valid = false;
            }

            var owners = programHeaders
                .Select((load, loadIndex) => (Header: load, Index: loadIndex))
                .Where(item => item.Header.Type == ElfConstants.PtLoad
                    && Contains(item.Header.VirtualAddress, item.Header.MemorySize, header.VirtualAddress, header.MemorySize)
                    && (header.FileSize == 0
                        || (Contains(item.Header.Offset, item.Header.FileSize, header.Offset, header.FileSize)
                            && (header.VirtualAddress - item.Header.VirtualAddress
                                == header.Offset - item.Header.Offset))))
                .ToArray();
            var isUnmappedZeroFileTlsObservation =
                owners.Length == 0
                && header.FileSize == 0
                && header.VirtualAddress == 0
                && reader.Contains(header.Offset, 0);
            if (isUnmappedZeroFileTlsObservation)
            {
                // Go's AArch64 linker emits a zero-file TLS BSS marker with a
                // zero virtual address and no owning load. Its file offset can
                // point at the end of the image even though no template bytes
                // are read. Keep this bounded structural shape observable;
                // managed TLS projection still requires an owning load.
            }
            else if (owners.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "PT_TLS must be fully contained by exactly one PT_LOAD with matching file/virtual mapping.",
                    header.Offset);
                valid = false;
            }
            else
            {
                var load = owners[0].Header;
                if ((load.Flags & ElfConstants.PfR) == 0
                    || ((header.Flags & ElfConstants.PfW) != 0 && (load.Flags & ElfConstants.PfW) == 0))
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsMetadataMalformed,
                        "The owning PT_LOAD permissions do not cover the PT_TLS permission contract.",
                        header.Offset);
                    valid = false;
                }
            }

            if (!valid)
            {
                continue;
            }

            var template = header.FileSize == 0
                ? ReadOnlyMemory<byte>.Empty
                : bytes.Slice(checked((int)header.Offset), checked((int)header.FileSize)).ToArray();
            result.Add(new TlsSegmentFacts(
                index,
                owners.Length == 1 ? owners[0].Index : -1,
                new FileOffset(header.Offset),
                new VirtualAddress(header.VirtualAddress),
                header.FileSize,
                header.MemorySize,
                header.Alignment,
                header.Flags,
                template));
        }

        return result;
    }

    private static (List<TlsRelocationSectionFacts> Tables, List<TlsRelocationFacts> Relocations) ParseStaticRelocations(
        ReadOnlyMemory<byte> bytes,
        IReadOnlyList<SectionHeader> sectionHeaders,
        LoadMap loadMap,
        IReadOnlyList<TlsSegmentFacts> tlsSegments,
        IReadOnlyList<TlsRelocationTableFacts> dynamicTables,
        DiagnosticBag diagnostics)
    {
        var reader = new BoundedReader(bytes);
        var tables = new List<TlsRelocationSectionFacts>();
        var relocations = new List<TlsRelocationFacts>();
        for (var sectionIndex = 0; sectionIndex < sectionHeaders.Count; sectionIndex++)
        {
            var section = sectionHeaders[sectionIndex];
            if (section.Type != ElfConstants.ShtRela)
            {
                continue;
            }

            if (section.EntrySize != ElfConstants.RelaEntrySize64
                || section.Size % ElfConstants.RelaEntrySize64 != 0
                || !reader.Contains(section.Offset, section.Size))
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "A section-owned RELA table has an unsupported entry size, partial record, or unbounded file range.",
                    section.Offset);
                continue;
            }

            if (dynamicTables.Any(table => RangesOverlap(
                    section.Offset,
                    section.Size,
                    table.FileOffset.Value,
                    table.Size)))
            {
                // DT_RELA/DT_JMPREL sections are already represented under their
                // dynamic-table owner and must not be duplicated as static edits.
                continue;
            }

            var count = section.Size / ElfConstants.RelaEntrySize64;
            if (count > MaximumTlsRelocations)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    $"A section-owned TLS relocation table exceeds the bounded record limit of {MaximumTlsRelocations}.",
                    section.Offset);
                continue;
            }

            var beforeCount = relocations.Count;
            var symbols = default(StaticSymbolSource?);
            for (ulong entryIndex = 0; entryIndex < count; entryIndex++)
            {
                if (!ElfParserUtilities.TryElementOffset(
                        section.Offset,
                        section.EntrySize,
                        entryIndex,
                        out var fileOffset)
                    || !reader.TryReadUInt64(fileOffset, out var targetAddress)
                    || !reader.TryReadUInt64(fileOffset + 8, out var info)
                    || !reader.TryReadInt64(fileOffset + 16, out var addend))
                {
                    diagnostics.Error(
                        DiagnosticCode.RelocationTableMalformed,
                        "A section-owned RELA table contains a truncated record.",
                        fileOffset);
                    break;
                }

                var relocationType = unchecked((uint)(info & 0xFFFFFFFF));
                var writeSize = GetTlsRelocationWriteSize(relocationType);
                if (writeSize == 0)
                {
                    continue;
                }

                if (symbols is null)
                {
                    symbols = TryCreateStaticSymbolSource(
                        section,
                        sectionHeaders,
                        reader,
                        diagnostics);
                    if (symbols is null)
                    {
                        break;
                    }
                }

                var symbolIndex = unchecked((uint)(info >> 32));
                TlsRelocationSymbolIdentity? symbol = null;
                if (symbolIndex != 0)
                {
                    if (!TryReadStaticTlsSymbol(
                            reader,
                            symbols,
                            symbolIndex,
                            out symbol,
                            out var symbolFailure))
                    {
                        diagnostics.Error(
                            DiagnosticCode.TlsBindingUnresolved,
                            symbolFailure,
                            section.Offset);
                        continue;
                    }

                    if (symbol is { SectionIndex: not SymbolUndefined } definedSymbol
                        && (tlsSegments.Count != 1
                            || definedSymbol.Value > tlsSegments[0].MemorySize
                            || definedSymbol.Size > tlsSegments[0].MemorySize - definedSymbol.Value))
                    {
                        diagnostics.Error(
                            DiagnosticCode.TlsMetadataMalformed,
                            $"Defined TLS symbol '{definedSymbol.Name}' is outside PT_TLS.",
                            section.Offset);
                    }
                }

                var targetOwners = loadMap.Segments
                    .Where(segment => segment.ContainsVirtualAddress(targetAddress, writeSize)
                        && (IsInstructionRelocation(relocationType)
                            ? segment.IsExecutable
                            : (segment.Flags & ElfConstants.PfW) != 0))
                    .ToArray();
                if (!loadMap.TryVirtualAddressToFileOffset(
                        new VirtualAddress(targetAddress),
                        writeSize,
                        out _)
                    || targetOwners.Length != 1)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsMetadataMalformed,
                        "A section-owned TLS instruction relocation target is not uniquely mapped by an executable PT_LOAD.",
                        targetAddress);
                }

                if (!ElfParserUtilities.TryMultiply(entryIndex, section.EntrySize, out var sourceDelta)
                    || !TryAdd(section.Address, sourceDelta, out var sourceAddress))
                {
                    diagnostics.Error(
                        DiagnosticCode.AddressOverflow,
                        "A section-owned TLS relocation table address overflowed.",
                        section.Offset);
                    continue;
                }

                var relocation = new RelaRelocation(
                    targetAddress,
                    info,
                    addend,
                    sourceAddress,
                    IsPlt: false);
                relocations.Add(new TlsRelocationFacts(
                    relocation,
                    writeSize,
                    symbol,
                    relocationType == ElfConstants.RArm64TlsDtpMod64
                        || symbol is { SectionIndex: SymbolUndefined },
                    IsDynamic: false));
            }

            if (relocations.Count != beforeCount)
            {
                tables.Add(new TlsRelocationSectionFacts(
                    sectionIndex,
                    new FileOffset(section.Offset),
                    new VirtualAddress(section.Address),
                    section.Size,
                    section.EntrySize,
                    section.Link,
                    section.Info));
            }
        }

        ValidateRelocationTargetOverlaps(relocations, diagnostics);
        return (tables, relocations.OrderBy(item => item.Relocation.Offset)
            .ThenBy(item => item.Relocation.Type)
            .ToList());
    }

    private static StaticSymbolSource? TryCreateStaticSymbolSource(
        SectionHeader relocationSection,
        IReadOnlyList<SectionHeader> sectionHeaders,
        BoundedReader reader,
        DiagnosticBag diagnostics)
    {
        if (relocationSection.Link >= (uint)sectionHeaders.Count)
        {
            diagnostics.Error(
                DiagnosticCode.SymbolTableMalformed,
                "A TLS RELA section links outside the section-header table.",
                relocationSection.Offset);
            return null;
        }

        var symbolTable = sectionHeaders[checked((int)relocationSection.Link)];
        if (symbolTable.Type is not (ElfConstants.ShtSymTab or ElfConstants.ShtDynSym)
            || symbolTable.EntrySize != ElfConstants.SymbolEntrySize64
            || symbolTable.Size % ElfConstants.SymbolEntrySize64 != 0
            || symbolTable.Link >= (uint)sectionHeaders.Count
            || !reader.Contains(symbolTable.Offset, symbolTable.Size))
        {
            diagnostics.Error(
                DiagnosticCode.SymbolTableMalformed,
                "A TLS RELA section's linked symbol table has an unsupported or unbounded layout.",
                symbolTable.Offset);
            return null;
        }

        var strings = sectionHeaders[checked((int)symbolTable.Link)];
        if (strings.Type != ElfConstants.ShtStrTab
            || !reader.Contains(strings.Offset, strings.Size)
            || !reader.TrySlice(strings.Offset, strings.Size, out var stringBytes))
        {
            diagnostics.Error(
                DiagnosticCode.SymbolTableMalformed,
                "A TLS RELA symbol table's linked string table is not bounded SHT_STRTAB data.",
                strings.Offset);
            return null;
        }

        return new StaticSymbolSource(symbolTable, stringBytes);
    }

    private static bool TryReadStaticTlsSymbol(
        BoundedReader reader,
        StaticSymbolSource source,
        uint symbolIndex,
        out TlsRelocationSymbolIdentity? identity,
        out string failure)
    {
        identity = null;
        failure = string.Empty;
        var table = source.SymbolTable;
        var count = table.Size / ElfConstants.SymbolEntrySize64;
        if (symbolIndex >= count
            || !ElfParserUtilities.TryElementOffset(
                table.Offset,
                table.EntrySize,
                symbolIndex,
                out var offset)
            || !reader.TryReadUInt32(offset, out var nameOffset)
            || !reader.TryReadByte(offset + 4, out var info)
            || !reader.TryReadByte(offset + 5, out var other)
            || !reader.TryReadUInt16(offset + 6, out var sectionIndex)
            || !reader.TryReadUInt64(offset + 8, out var value)
            || !reader.TryReadUInt64(offset + 16, out var size))
        {
            failure = $"TLS relocation symbol index {symbolIndex} is outside the bounded linked symbol table.";
            return false;
        }

        var type = (byte)(info & 0x0F);
        if (type != SymbolTypeTls)
        {
            failure = $"TLS relocation symbol index {symbolIndex} does not identify STT_TLS.";
            return false;
        }

        if (!ElfParserUtilities.TryReadString(source.StringTable, nameOffset, out var name)
            || string.IsNullOrWhiteSpace(name))
        {
            failure = $"TLS relocation symbol index {symbolIndex} has no bounded non-empty name.";
            return false;
        }

        identity = new TlsRelocationSymbolIdentity(
            symbolIndex,
            name,
            (byte)(info >> 4),
            type,
            (byte)(other & 0x03),
            sectionIndex,
            value,
            size);
        return true;
    }

    private static void ValidateRelocationTargetOverlaps(
        IReadOnlyList<TlsRelocationFacts> relocations,
        DiagnosticBag diagnostics)
    {
        var ordered = relocations.OrderBy(item => item.Relocation.Offset).ToArray();
        for (var index = 1; index < ordered.Length; index++)
        {
            var previous = ordered[index - 1];
            var current = ordered[index];
            if (!TryAdd(previous.Relocation.Offset, previous.WriteSize, out var previousEnd)
                || current.Relocation.Offset < previousEnd)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "Static TLS relocation target ranges overlap or overflow.",
                    current.Relocation.Offset);
            }
        }
    }

    private static void ValidateCrossTableRelocationOverlaps(
        IReadOnlyList<TlsRelocationFacts> relocations,
        DiagnosticBag diagnostics)
    {
        var ordered = relocations
            .OrderBy(item => item.Relocation.Offset)
            .ThenBy(item => item.IsDynamic)
            .ToArray();
        for (var index = 1; index < ordered.Length; index++)
        {
            var previous = ordered[index - 1];
            var current = ordered[index];
            if (previous.IsDynamic == current.IsDynamic)
            {
                continue;
            }

            if (TryAdd(previous.Relocation.Offset, previous.WriteSize, out var previousEnd)
                && current.Relocation.Offset < previousEnd)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "Dynamic and section-owned TLS relocation target ranges overlap.",
                    current.Relocation.Offset);
            }
        }
    }

    private static List<TlsRelocationTableFacts> ParseRelocationTables(
        ReadOnlyMemory<byte> bytes,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        DiagnosticBag diagnostics)
    {
        var reader = new BoundedReader(bytes);
        var result = new List<TlsRelocationTableFacts>();
        ValidateTable(
            new[] { ElfConstants.DtRela, ElfConstants.DtRelaSz, ElfConstants.DtRelaEnt },
            isPlt: false);
        ValidateTable(
            new[] { ElfConstants.DtJmpRel, ElfConstants.DtPltRelSz, ElfConstants.DtPltRel },
            isPlt: true);
        return result;

        void ValidateTable(ulong[] tags, bool isPlt)
        {
            var entriesByTag = tags.ToDictionary(
                tag => tag,
                tag => dynamicEntries.Where(entry => entry.Tag == tag).ToArray());
            foreach (var (tag, matches) in entriesByTag)
            {
                if (matches.Length > 1)
                {
                    diagnostics.Error(
                        DiagnosticCode.RelocationTableMalformed,
                        $"TLS relocation metadata tag 0x{tag:X} is duplicated.");
                }
            }

            var totalTags = entriesByTag.Values.Sum(matches => matches.Length);
            var addressTag = tags[0];
            var sizeTag = tags[1];
            var formatTag = tags[2];
            if (totalTags == 0)
            {
                return;
            }

            if (!isPlt
                && entriesByTag[addressTag].Length == 0
                && entriesByTag[sizeTag].Length == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "The RELA metadata contains an entry-size tag without a bounded address and size tuple.",
                    dynamicEntries.First(entry => tags.Contains(entry.Tag)).Value);
                return;
            }

            if (entriesByTag[addressTag].Length != 1
                || entriesByTag[sizeTag].Length != 1
                || (isPlt && entriesByTag[formatTag].Length != 1))
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    isPlt
                        ? "The PLT RELA address/size/format metadata is partial or inconsistent."
                        : "The RELA address/size metadata is partial or inconsistent.");
                return;
            }

            var address = entriesByTag[addressTag][0].Value;
            var size = entriesByTag[sizeTag][0].Value;
            ulong entrySize = ElfConstants.RelaEntrySize64;
            if (!isPlt && entriesByTag[formatTag].Length == 1)
            {
                entrySize = entriesByTag[formatTag][0].Value;
            }

            if (isPlt && entriesByTag[formatTag][0].Value != ElfConstants.DtRela)
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "The PLT relocation table does not use the required RELA format.",
                    address);
                return;
            }

            if (entrySize != ElfConstants.RelaEntrySize64 || size % entrySize != 0)
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "A TLS relocation table has an unsupported entry size or partial record.",
                    address);
                return;
            }

            if (size == 0)
            {
                return;
            }

            if (!loadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(address),
                    size,
                    out var fileOffset)
                || !reader.Contains(fileOffset.Value, size))
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "A TLS relocation table has an unsupported format, partial record, or unmapped bounded range.",
                    address);
                return;
            }

            result.Add(new TlsRelocationTableFacts(
                new VirtualAddress(address),
                fileOffset,
                size,
                entrySize,
                isPlt));
        }
    }

    private static List<TlsRelocationFacts> ParseRelocations(
        IReadOnlyList<ProgramHeader> programHeaders,
        LoadMap loadMap,
        ElfDynamicMetadata dynamicMetadata,
        IReadOnlyList<DynamicSymbol> dynamicSymbols,
        IReadOnlyList<RelaRelocation> relocations,
        IReadOnlyList<TlsRelocationTableFacts> relocationTables,
        IReadOnlyList<TlsSegmentFacts> tlsSegments,
        DiagnosticBag diagnostics)
    {
        var result = new List<TlsRelocationFacts>();
        foreach (var relocation in relocations)
        {
            var writeSize = GetTlsRelocationWriteSize(relocation.Type);
            if (writeSize == 0)
            {
                continue;
            }

            if (result.Count >= MaximumTlsRelocations)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    $"The ELF exceeds the bounded TLS relocation limit of {MaximumTlsRelocations}.",
                    relocation.SourceAddress);
                break;
            }

            TlsRelocationSymbolIdentity? symbolIdentity = null;
            if (relocation.SymbolIndex != 0)
            {
                if (relocation.SymbolIndex >= (uint)dynamicSymbols.Count)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsBindingUnresolved,
                        $"TLS relocation symbol index {relocation.SymbolIndex} is outside the dynamic symbol table.",
                        relocation.SourceAddress);
                }
                else
                {
                    var symbol = dynamicSymbols[checked((int)relocation.SymbolIndex)];
                    var symbolType = (byte)(symbol.Info & 0x0F);
                    if (symbolType != SymbolTypeTls)
                    {
                        diagnostics.Error(
                            DiagnosticCode.TlsMetadataMalformed,
                            $"TLS relocation symbol index {relocation.SymbolIndex} does not identify an STT_TLS symbol.",
                            relocation.SourceAddress);
                    }

                    if (!ElfParserUtilities.TryReadString(dynamicMetadata.StringTable, symbol.Name, out var symbolName)
                        || string.IsNullOrWhiteSpace(symbolName))
                    {
                        diagnostics.Error(
                            DiagnosticCode.TlsBindingUnresolved,
                            $"TLS relocation symbol index {relocation.SymbolIndex} has no bounded non-empty name.",
                            relocation.SourceAddress);
                    }
                    else
                    {
                        symbolIdentity = new TlsRelocationSymbolIdentity(
                            relocation.SymbolIndex,
                            symbolName,
                            (byte)(symbol.Info >> 4),
                            symbolType,
                            (byte)(symbol.Other & 0x03),
                            symbol.SectionIndex,
                            symbol.Value,
                            symbol.Size);
                    }
                }
            }

            var tableOwners = relocationTables.Where(table =>
                relocation.SourceAddress >= table.Address.Value
                && relocation.SourceAddress - table.Address.Value <= table.Size
                && ElfConstants.RelaEntrySize64 <= table.Size - (relocation.SourceAddress - table.Address.Value)
                && (relocation.SourceAddress - table.Address.Value) % table.EntrySize == 0).ToArray();
            if (tableOwners.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.RelocationTableMalformed,
                    "A TLS relocation record has no unique bounded dynamic RELA table owner.",
                    relocation.SourceAddress);
            }

            var isInstructionRelocation = IsInstructionRelocation(relocation.Type);
            var targetSegments = programHeaders
                .Where(header => header.Type == ElfConstants.PtLoad
                    && Contains(header.VirtualAddress, header.FileSize, relocation.Offset, writeSize)
                    && (isInstructionRelocation
                        ? (header.Flags & ElfConstants.PfX) != 0
                        : (header.Flags & ElfConstants.PfW) != 0))
                .ToArray();
            if (!loadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(relocation.Offset),
                    writeSize,
                    out _)
                || targetSegments.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "A TLS relocation target is not uniquely mapped with the permissions required by its relocation width and family.",
                    relocation.Offset);
            }

            if (symbolIdentity is { SectionIndex: not SymbolUndefined } definedSymbol)
            {
                var owningTls = tlsSegments.FirstOrDefault(segment =>
                    segment.ProgramHeaderIndex >= 0
                    && definedSymbol.Value <= segment.MemorySize
                    && definedSymbol.Size <= segment.MemorySize - definedSymbol.Value);
                if (owningTls is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsMetadataMalformed,
                        $"Defined TLS symbol '{definedSymbol.Name}' is outside the declared PT_TLS memory template.",
                        relocation.SourceAddress);
                }
            }

            var requiresModuleResolution = relocation.Type == ElfConstants.RArm64TlsDtpMod64
                || symbolIdentity is { SectionIndex: SymbolUndefined };
            result.Add(new TlsRelocationFacts(
                relocation,
                writeSize,
                symbolIdentity,
                requiresModuleResolution));
        }

        var sorted = result.OrderBy(item => item.Relocation.Offset).ThenBy(item => item.Relocation.Type).ToArray();
        for (var index = 1; index < sorted.Length; index++)
        {
            var previous = sorted[index - 1];
            var current = sorted[index];
            if (!TryAdd(previous.Relocation.Offset, previous.WriteSize, out var previousEnd)
                || current.Relocation.Offset < previousEnd)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "TLS relocation target ranges overlap, overflow, or duplicate an existing TLS relocation site.",
                    current.Relocation.Offset);
            }
        }

        return sorted.ToList();
    }

    private static VirtualAddress? ParseOptionalDynamicAddress(
        ulong tag,
        string name,
        IReadOnlyList<DynamicEntry> entries,
        IReadOnlyList<ProgramHeader> programHeaders,
        DiagnosticBag diagnostics,
        bool requireExecutable)
    {
        var matches = entries.Where(entry => entry.Tag == tag).ToArray();
        if (matches.Length == 0)
        {
            return null;
        }

        if (matches.Length != 1 || matches[0].Value == 0)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                $"{name} must occur at most once and, when present, contain a nonzero address.");
            return null;
        }

        var address = matches[0].Value;
        var owners = programHeaders.Where(header => header.Type == ElfConstants.PtLoad
            && Contains(header.VirtualAddress, header.MemorySize, address, 1)
            && (requireExecutable
                ? (header.Flags & ElfConstants.PfX) != 0
                : (header.Flags & ElfConstants.PfW) != 0)).ToArray();
        if (owners.Length != 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                $"{name} is not uniquely mapped by a PT_LOAD with the required permissions.",
                address);
            return null;
        }

        return new VirtualAddress(address);
    }

    private static ulong GetTlsRelocationWriteSize(uint relocationType)
    {
        if (IsInstructionRelocation(relocationType))
        {
            return sizeof(uint);
        }

        return relocationType is ElfConstants.RArm64TlsDtpMod64
            or ElfConstants.RArm64TlsDtpRel64
            or ElfConstants.RArm64TlsTprel64
            or ElfConstants.RArm64TlsDesc
            ? (ulong)sizeof(ulong)
            : 0;
    }

    private static bool IsInstructionRelocation(uint relocationType) =>
        relocationType is >= ElfConstants.RArm64TlsGdAdrPrel21
            and <= ElfConstants.RArm64TlsLdLdst128DtprelLo12Nc;

    private static bool Contains(ulong start, ulong rangeSize, ulong target, ulong targetSize) =>
        target >= start
        && target - start <= rangeSize
        && targetSize <= rangeSize - (target - start);

    private static bool IsPowerOfTwo(ulong value) => value != 0 && (value & (value - 1)) == 0;

    private static bool RangesOverlap(ulong leftStart, ulong leftSize, ulong rightStart, ulong rightSize) =>
        leftStart <= rightStart
            ? rightStart - leftStart < leftSize
            : leftStart - rightStart < rightSize;

    private sealed record StaticSymbolSource(SectionHeader SymbolTable, ReadOnlyMemory<byte> StringTable);

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        result = left + right;
        return result >= left;
    }
}
