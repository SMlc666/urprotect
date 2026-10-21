using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.StructuralElf;

/// <summary>One bounded symbol record owned by a section-linked ELF symbol table.</summary>
public sealed record ElfSectionSymbolIdentity(
    uint SymbolIndex,
    uint SymbolTableSectionIndex,
    uint NameOffset,
    string Name,
    byte Info,
    byte Other,
    ushort SectionIndex,
    ulong Value,
    ulong Size)
{
    public byte Binding => (byte)(Info >> 4);

    public byte Type => (byte)(Info & 0x0F);

    public byte Visibility => (byte)(Other & 0x03);
}

/// <summary>
/// One section-owned RELA row. The relocation target is the source instruction/data
/// site; <see cref="RelocationSourceAddress"/> identifies the row in its RELA table.
/// </summary>
public sealed record ElfSectionRelocation(
    int RelocationSectionIndex,
    FileOffset RelocationSectionFileOffset,
    VirtualAddress RelocationSectionAddress,
    uint SymbolTableSectionIndex,
    uint TargetSectionIndex,
    RelaRelocation Relocation,
    ElfSectionSymbolIdentity? Symbol)
{
    public VirtualAddress RelocationSourceAddress => new(Relocation.SourceAddress);
}

/// <summary>
/// Parses section-linked RELA owner facts on demand from the already bounded section
/// table. Section headers remain optional; absence simply yields no ownership proof.
/// </summary>
internal static class ElfSectionRelocationParser
{
    private const ulong MaximumRecordsPerSection = 1_000_000;

    public static IReadOnlyList<ElfSectionRelocation> Parse(
        ReadOnlyMemory<byte> bytes,
        IReadOnlyList<SectionHeader> sectionHeaders,
        DiagnosticBag diagnostics,
        ElfParserWorkBudget? workBudget = null)
    {
        ArgumentNullException.ThrowIfNull(sectionHeaders);
        ArgumentNullException.ThrowIfNull(diagnostics);

        var reader = new BoundedReader(bytes);
        if (workBudget is not null)
        {
            ulong totalRows = 0;
            foreach (var section in sectionHeaders)
            {
                if (section.Type != ElfConstants.ShtRela)
                {
                    continue;
                }

                var rows = section.Size / ElfConstants.RelaEntrySize64;
                if (rows > (ulong)workBudget.Limits.MaximumSectionRelocationRows
                    || rows > (ulong)workBudget.Limits.MaximumSectionRelocationRows - totalRows)
                {
                    workBudget.Fail(
                        $"aggregate section-owned RELA rows exceed limit {workBudget.Limits.MaximumSectionRelocationRows} before traversal",
                        diagnostics,
                        section.Offset);
                    return Array.Empty<ElfSectionRelocation>();
                }

                totalRows += rows;
            }

            if (!workBudget.TryReserveTable(
                    totalRows,
                    ElfConstants.RelaEntrySize64,
                    workBudget.Limits.MaximumSectionRelocationRows,
                    "aggregate section-owned RELA rows",
                    diagnostics))
            {
                return Array.Empty<ElfSectionRelocation>();
            }
        }

        var result = new List<ElfSectionRelocation>();
        for (var sectionIndex = 0; sectionIndex < sectionHeaders.Count; sectionIndex++)
        {
            var relocationSection = sectionHeaders[sectionIndex];
            if (relocationSection.Type != ElfConstants.ShtRela)
            {
                continue;
            }

            if (relocationSection.EntrySize != ElfConstants.RelaEntrySize64
                || relocationSection.Size % ElfConstants.RelaEntrySize64 != 0
                || !reader.Contains(relocationSection.Offset, relocationSection.Size))
            {
                diagnostics.Warning(
                    DiagnosticCode.RelocationTableMalformed,
                    "A section-owned RELA table has an unsupported entry size, partial record, or unbounded file range; its owner facts were ignored.",
                    relocationSection.Offset);
                continue;
            }

            var recordCount = relocationSection.Size / ElfConstants.RelaEntrySize64;
            if (recordCount > MaximumRecordsPerSection)
            {
                diagnostics.Warning(
                    DiagnosticCode.RelocationTableMalformed,
                    "A section-owned RELA table exceeds the bounded owner-record limit; its owner facts were ignored.",
                    relocationSection.Offset);
                continue;
            }

            if (!TryGetLinkedSymbolTable(
                    relocationSection,
                    sectionHeaders,
                    reader,
                    out var symbolTable,
                    out var stringTable))
            {
                diagnostics.Warning(
                    DiagnosticCode.SymbolTableMalformed,
                    "A section-owned RELA table has no bounded linked ELF64 symbol/string table; its owner facts were ignored.",
                    relocationSection.Offset);
                continue;
            }

            var parsed = new List<ElfSectionRelocation>(checked((int)recordCount));
            var complete = true;
            for (ulong entryIndex = 0; entryIndex < recordCount; entryIndex++)
            {
                if (!ElfParserUtilities.TryElementOffset(
                        relocationSection.Offset,
                        relocationSection.EntrySize,
                        entryIndex,
                        out var entryOffset)
                    || !reader.TryReadUInt64(entryOffset, out var targetAddress)
                    || !reader.TryReadUInt64(entryOffset + 8, out var info)
                    || !reader.TryReadInt64(entryOffset + 16, out var addend)
                    || !ElfParserUtilities.TryMultiply(entryIndex, relocationSection.EntrySize, out var sourceDelta)
                    || !TryAdd(relocationSection.Address, sourceDelta, out var relocationSourceAddress))
                {
                    complete = false;
                    break;
                }

                var relocation = new RelaRelocation(
                    targetAddress,
                    info,
                    addend,
                    relocationSourceAddress,
                    IsPlt: false);
                ElfSectionSymbolIdentity? symbol = null;
                if (relocation.SymbolIndex != 0)
                {
                    if (workBudget is not null
                        && !workBudget.TryCharge(
                            ElfConstants.SymbolEntrySize64,
                            "section RELA linked-symbol row read",
                            diagnostics,
                            relocationSection.Offset))
                    {
                        complete = false;
                        break;
                    }

                    if (!TryReadSymbol(
                            reader,
                            symbolTable,
                            stringTable,
                            relocation.SymbolIndex,
                            relocationSection.Link,
                            workBudget,
                            diagnostics,
                            out symbol))
                    {
                        complete = false;
                        break;
                    }
                }

                parsed.Add(new ElfSectionRelocation(
                    sectionIndex,
                    new FileOffset(relocationSection.Offset),
                    new VirtualAddress(relocationSection.Address),
                    relocationSection.Link,
                    relocationSection.Info,
                    relocation,
                    symbol));
            }

            if (!complete)
            {
                diagnostics.Warning(
                    DiagnosticCode.RelocationTableMalformed,
                    "A section-owned RELA table contains a truncated record, invalid linked symbol index, or overflowing source address; its owner facts were ignored.",
                    relocationSection.Offset);
                continue;
            }

            result.AddRange(parsed);
        }

        return Array.AsReadOnly(result
            .OrderBy(record => record.Relocation.Offset)
            .ThenBy(record => record.Relocation.Type)
            .ThenBy(record => record.RelocationSectionIndex)
            .ThenBy(record => record.Relocation.SourceAddress)
            .ToArray());
    }

    private static bool TryGetLinkedSymbolTable(
        SectionHeader relocationSection,
        IReadOnlyList<SectionHeader> sectionHeaders,
        BoundedReader reader,
        out SectionHeader symbolTable,
        out ReadOnlyMemory<byte> stringTable)
    {
        symbolTable = default;
        stringTable = default;
        if (relocationSection.Link >= (uint)sectionHeaders.Count)
        {
            return false;
        }

        symbolTable = sectionHeaders[checked((int)relocationSection.Link)];
        if (symbolTable.Type is not (ElfConstants.ShtSymTab or ElfConstants.ShtDynSym)
            || symbolTable.EntrySize != ElfConstants.SymbolEntrySize64
            || symbolTable.Size % ElfConstants.SymbolEntrySize64 != 0
            || !reader.Contains(symbolTable.Offset, symbolTable.Size)
            || symbolTable.Link >= (uint)sectionHeaders.Count)
        {
            return false;
        }

        var strings = sectionHeaders[checked((int)symbolTable.Link)];
        return strings.Type == ElfConstants.ShtStrTab
            && reader.TrySlice(strings.Offset, strings.Size, out stringTable);
    }

    private static bool TryReadSymbol(
        BoundedReader reader,
        SectionHeader symbolTable,
        ReadOnlyMemory<byte> stringTable,
        uint symbolIndex,
        uint symbolTableSectionIndex,
        ElfParserWorkBudget? workBudget,
        DiagnosticBag diagnostics,
        out ElfSectionSymbolIdentity? symbol)
    {
        symbol = null;
        var count = symbolTable.Size / ElfConstants.SymbolEntrySize64;
        if (symbolIndex >= count
            || !ElfParserUtilities.TryElementOffset(
                symbolTable.Offset,
                symbolTable.EntrySize,
                symbolIndex,
                out var symbolOffset)
            || !reader.TryReadUInt32(symbolOffset, out var nameOffset)
            || !reader.TryReadByte(symbolOffset + 4, out var info)
            || !reader.TryReadByte(symbolOffset + 5, out var other)
            || !reader.TryReadUInt16(symbolOffset + 6, out var sectionIndex)
            || !reader.TryReadUInt64(symbolOffset + 8, out var value)
            || !reader.TryReadUInt64(symbolOffset + 16, out var size)
            || !ElfParserUtilities.TryReadString(stringTable, nameOffset, out var name, workBudget, diagnostics))
        {
            return false;
        }

        symbol = new ElfSectionSymbolIdentity(
            symbolIndex,
            symbolTableSectionIndex,
            nameOffset,
            name,
            info,
            other,
            sectionIndex,
            value,
            size);
        return true;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        result = left + right;
        return result >= left;
    }
}
