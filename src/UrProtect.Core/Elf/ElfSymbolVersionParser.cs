using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using static UrProtect.Core.Elf.ElfParserUtilities;

namespace UrProtect.Core.Elf;

internal static class ElfSymbolVersionParser
{
    internal static ElfSymbolVersionMetadata Parse(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        ElfDynamicMetadata dynamicMetadata,
        IReadOnlyList<DynamicSymbol> dynamicSymbols,
        DiagnosticBag diagnostics)
    {
        var hasVersionTable = TryGetDynamicValue(
            dynamicEntries,
            ElfConstants.DtVersym,
            out var versionTableAddress);
        var hasVersionNeed = TryGetDynamicValue(
            dynamicEntries,
            ElfConstants.DtVerneed,
            out var versionNeedAddress);
        var hasVersionNeedCount = TryGetDynamicValue(
            dynamicEntries,
            ElfConstants.DtVerneedNum,
            out var versionNeedCount);
        var hasVersionDefinition = TryGetDynamicValue(
            dynamicEntries,
            ElfConstants.DtVerdef,
            out _);
        var hasVersionDefinitionCount = TryGetDynamicValue(
            dynamicEntries,
            ElfConstants.DtVerdefNum,
            out _);
        if (!hasVersionTable
            && !hasVersionNeed
            && !hasVersionNeedCount
            && !hasVersionDefinition
            && !hasVersionDefinitionCount)
        {
            return ElfSymbolVersionMetadata.Empty;
        }

        var versionIndices = new List<SymbolVersionIndex>();
        var versionTableBytes = ReadOnlyMemory<byte>.Empty;
        if (hasVersionTable)
        {
            if (dynamicSymbols.Count == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.SymbolVersionTableMalformed,
                    "DT_VERSYM is present but no bounded dynamic symbol table is available.",
                    versionTableAddress);
            }
            else if (!TryMultiply(
                         (ulong)dynamicSymbols.Count,
                         sizeof(ushort),
                         out var versionTableSize)
                || !TryResolveVirtualRange(
                    reader,
                    loadMap,
                    versionTableAddress,
                    versionTableSize,
                    out var versionTableFileOffset)
                || !reader.TrySlice(versionTableFileOffset, versionTableSize, out versionTableBytes))
            {
                diagnostics.Error(
                    DiagnosticCode.SymbolVersionTableMalformed,
                    "The DT_VERSYM table is outside file-backed memory.",
                    versionTableAddress);
            }
            else
            {
                for (ulong index = 0; index < (ulong)dynamicSymbols.Count; index++)
                {
                    if (!TryElementOffset(
                            versionTableFileOffset,
                            sizeof(ushort),
                            index,
                            out var entryOffset)
                        || !reader.TryReadUInt16(entryOffset, out var rawValue))
                    {
                        diagnostics.Error(
                            DiagnosticCode.SymbolVersionTableMalformed,
                            "The DT_VERSYM table contains a truncated entry.",
                            entryOffset);
                        versionIndices.Clear();
                        break;
                    }

                    versionIndices.Add(new SymbolVersionIndex(rawValue));
                }
            }
        }

        var neededVersions = new List<VersionNeed>();
        var versionNeedBytes = ReadOnlyMemory<byte>.Empty;
        ulong? rawVersionNeedStart = null;
        ulong rawVersionNeedEnd = 0;
        if (hasVersionNeed || hasVersionNeedCount)
        {
            if (!hasVersionNeed || !hasVersionNeedCount)
            {
                diagnostics.Error(
                    DiagnosticCode.VersionNeedTableMalformed,
                    "DT_VERNEED and DT_VERNEEDNUM must be provided together.",
                    hasVersionNeed ? versionNeedAddress : null);
            }
            else if (versionNeedCount > int.MaxValue
                || versionNeedCount > (ulong)reader.Length / 16)
            {
                diagnostics.Error(
                    DiagnosticCode.VersionNeedTableMalformed,
                    "The DT_VERNEED count exceeds the bounded input size.",
                    versionNeedAddress);
            }
            else
            {
                var currentAddress = versionNeedAddress;
                for (ulong index = 0; index < versionNeedCount; index++)
                {
                    if (!TryResolveVirtualRange(
                            reader,
                            loadMap,
                            currentAddress,
                            16,
                            out var recordFileOffset)
                        || !reader.TryReadUInt16(recordFileOffset, out var version)
                        || !reader.TryReadUInt16(recordFileOffset + 2, out var auxiliaryCount)
                        || !reader.TryReadUInt32(recordFileOffset + 4, out var fileNameOffset)
                        || !reader.TryReadUInt32(recordFileOffset + 8, out var auxiliaryOffset)
                        || !reader.TryReadUInt32(recordFileOffset + 12, out var nextOffset)
                        || !reader.TrySlice(recordFileOffset, 16, out var rawRecord))
                    {
                        diagnostics.Error(
                            DiagnosticCode.VersionNeedTableMalformed,
                            "The DT_VERNEED record is truncated or unmapped.",
                            currentAddress);
                        break;
                    }

                    if (!TryReadString(
                            dynamicMetadata.StringTable,
                            fileNameOffset,
                            out var fileName))
                    {
                        diagnostics.Error(
                            DiagnosticCode.VersionNeedTableMalformed,
                            $"The DT_VERNEED file-name offset {fileNameOffset} is outside the dynamic string table.",
                            currentAddress);
                        break;
                    }

                    UpdateRawRange(recordFileOffset, 16);
                    var auxiliaries = new List<VersionNeedAuxiliary>();
                    var currentAuxiliaryAddress = default(ulong);
                    if (auxiliaryCount > 0)
                    {
                        if (auxiliaryOffset == 0
                            || !TryAdd(currentAddress, auxiliaryOffset, out currentAuxiliaryAddress))
                        {
                            diagnostics.Error(
                                DiagnosticCode.VersionNeedTableMalformed,
                                "The DT_VERNEED auxiliary offset is invalid.",
                                currentAddress);
                            break;
                        }
                    }

                    var auxiliaryMalformed = false;
                    for (ulong auxiliaryIndex = 0; auxiliaryIndex < auxiliaryCount; auxiliaryIndex++)
                    {
                        if (!TryResolveVirtualRange(
                                reader,
                                loadMap,
                                currentAuxiliaryAddress,
                                16,
                                out var auxiliaryFileOffset)
                            || !reader.TryReadUInt32(auxiliaryFileOffset, out var hash)
                            || !reader.TryReadUInt16(auxiliaryFileOffset + 4, out var flags)
                            || !reader.TryReadUInt16(auxiliaryFileOffset + 6, out var other)
                            || !reader.TryReadUInt32(auxiliaryFileOffset + 8, out var nameOffset)
                            || !reader.TryReadUInt32(auxiliaryFileOffset + 12, out var nextAuxiliaryOffset)
                            || !reader.TrySlice(auxiliaryFileOffset, 16, out var rawAuxiliary)
                            || !TryReadString(dynamicMetadata.StringTable, nameOffset, out var name))
                        {
                            diagnostics.Error(
                                DiagnosticCode.VersionNeedTableMalformed,
                                "The DT_VERNEED auxiliary record is truncated, unmapped, or has an invalid name.",
                                currentAuxiliaryAddress);
                            auxiliaryMalformed = true;
                            break;
                        }

                        auxiliaries.Add(new VersionNeedAuxiliary(
                            hash,
                            flags,
                            other,
                            nameOffset,
                            name,
                            rawAuxiliary));
                        UpdateRawRange(auxiliaryFileOffset, 16);

                        if (auxiliaryIndex + 1 < auxiliaryCount)
                        {
                            if (nextAuxiliaryOffset == 0
                                || !TryAdd(
                                    currentAuxiliaryAddress,
                                    nextAuxiliaryOffset,
                                    out var nextAuxiliaryAddress)
                                || nextAuxiliaryAddress <= currentAuxiliaryAddress)
                            {
                                diagnostics.Error(
                                    DiagnosticCode.VersionNeedTableMalformed,
                                    "The DT_VERNEED auxiliary chain terminates or moves backwards before its declared count.",
                                    currentAuxiliaryAddress);
                                auxiliaryMalformed = true;
                                break;
                            }

                            currentAuxiliaryAddress = nextAuxiliaryAddress;
                        }
                        else if (nextAuxiliaryOffset != 0)
                        {
                            diagnostics.Error(
                                DiagnosticCode.VersionNeedTableMalformed,
                                "The DT_VERNEED auxiliary chain has entries beyond its declared count.",
                                currentAuxiliaryAddress);
                            auxiliaryMalformed = true;
                            break;
                        }
                    }

                    if (auxiliaryMalformed)
                    {
                        break;
                    }

                    neededVersions.Add(new VersionNeed(
                        version,
                        auxiliaryCount,
                        fileNameOffset,
                        auxiliaryOffset,
                        nextOffset,
                        fileName,
                        auxiliaries,
                        rawRecord));

                    if (index + 1 < versionNeedCount)
                    {
                        if (nextOffset == 0
                            || !TryAdd(currentAddress, nextOffset, out var nextAddress)
                            || nextAddress <= currentAddress)
                        {
                            diagnostics.Error(
                                DiagnosticCode.VersionNeedTableMalformed,
                                "The DT_VERNEED chain terminates or moves backwards before its declared count.",
                                currentAddress);
                            break;
                        }

                        currentAddress = nextAddress;
                    }
                    else if (nextOffset != 0)
                    {
                        diagnostics.Error(
                            DiagnosticCode.VersionNeedTableMalformed,
                            "The DT_VERNEED chain has entries beyond its declared count.",
                            currentAddress);
                        break;
                    }
                }
            }
        }

        if (rawVersionNeedStart is ulong start
            && rawVersionNeedEnd >= start
            && reader.TrySlice(start, rawVersionNeedEnd - start, out var rawVersionNeedBytes))
        {
            versionNeedBytes = rawVersionNeedBytes;
        }

        var definitions = ParseVersionDefinitions(
            reader,
            loadMap,
            dynamicEntries,
            dynamicMetadata,
            diagnostics);
        var metadata = new ElfSymbolVersionMetadata(
            versionTableAddress,
            versionTableBytes,
            versionIndices,
            versionNeedAddress,
            versionNeedBytes,
            neededVersions);
        return metadata with
        {
            VersionDefinitionAddress = new VirtualAddress(definitions.Address),
            VersionDefinitionBytes = definitions.RawBytes,
            DefinedVersions = definitions.Records,
        };

        void UpdateRawRange(ulong fileOffset, ulong size)
        {
            if (!TryAdd(fileOffset, size, out var end))
            {
                return;
            }

            rawVersionNeedStart = rawVersionNeedStart is ulong start
                ? Math.Min(start, fileOffset)
                : fileOffset;
            rawVersionNeedEnd = Math.Max(rawVersionNeedEnd, end);
        }
    }

    private static VersionDefinitionParseResult ParseVersionDefinitions(
        BoundedReader reader,
        LoadMap loadMap,
        IReadOnlyList<DynamicEntry> dynamicEntries,
        ElfDynamicMetadata dynamicMetadata,
        DiagnosticBag diagnostics)
    {
        var hasAddress = TryGetDynamicValue(
            dynamicEntries,
            ElfConstants.DtVerdef,
            out var address);
        var hasCount = TryGetDynamicValue(
            dynamicEntries,
            ElfConstants.DtVerdefNum,
            out var count);
        if (!hasAddress && !hasCount)
        {
            return new VersionDefinitionParseResult(
                0,
                ReadOnlyMemory<byte>.Empty,
                Array.Empty<VersionDefinition>());
        }

        if (!hasAddress || !hasCount || count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.VersionDefinitionTableMalformed,
                "DT_VERDEF and a nonzero DT_VERDEFNUM must be provided together.",
                hasAddress ? address : null);
            return new VersionDefinitionParseResult(
                address,
                ReadOnlyMemory<byte>.Empty,
                Array.Empty<VersionDefinition>());
        }

        var maximumDefinitions = (ulong)reader.Length / 20;
        var maximumAuxiliaries = (ulong)reader.Length / 8;
        if (count > int.MaxValue || count > maximumDefinitions)
        {
            diagnostics.Error(
                DiagnosticCode.VersionDefinitionTableMalformed,
                "The DT_VERDEF count exceeds the bounded input size.",
                address);
            return new VersionDefinitionParseResult(
                address,
                ReadOnlyMemory<byte>.Empty,
                Array.Empty<VersionDefinition>());
        }

        var definitions = new List<VersionDefinition>((int)count);
        ulong? rawTableStart = null;
        ulong rawTableEnd = 0;
        ulong currentAddress = address;
        ulong parsedAuxiliaryCount = 0;
        for (ulong index = 0; index < count; index++)
        {
            if (!TryResolveVirtualRange(
                    reader,
                    loadMap,
                    currentAddress,
                    20,
                    out var recordFileOffset)
                || !reader.TryReadUInt16(recordFileOffset, out var version)
                || !reader.TryReadUInt16(recordFileOffset + 2, out var flags)
                || !reader.TryReadUInt16(recordFileOffset + 4, out var versionIndex)
                || !reader.TryReadUInt16(recordFileOffset + 6, out var auxiliaryCount)
                || !reader.TryReadUInt32(recordFileOffset + 8, out var hash)
                || !reader.TryReadUInt32(recordFileOffset + 12, out var auxiliaryOffset)
                || !reader.TryReadUInt32(recordFileOffset + 16, out var nextOffset)
                || !reader.TrySlice(recordFileOffset, 20, out var rawRecord))
            {
                diagnostics.Error(
                    DiagnosticCode.VersionDefinitionTableMalformed,
                    "The DT_VERDEF record is truncated or unmapped.",
                    currentAddress);
                break;
            }

            if (version != 1 || versionIndex == 0 || auxiliaryCount == 0 || auxiliaryOffset == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.VersionDefinitionTableMalformed,
                    "The DT_VERDEF record has an unsupported version, zero index, or missing auxiliary name.",
                    currentAddress);
                break;
            }

            if (auxiliaryCount > maximumAuxiliaries
                || parsedAuxiliaryCount > maximumAuxiliaries - auxiliaryCount)
            {
                diagnostics.Error(
                    DiagnosticCode.VersionDefinitionTableMalformed,
                    "The DT_VERDEF auxiliary count exceeds the bounded input size.",
                    currentAddress);
                break;
            }

            if (auxiliaryOffset < 20)
            {
                diagnostics.Error(
                    DiagnosticCode.VersionDefinitionTableMalformed,
                    "The DT_VERDEF auxiliary offset overlaps its record.",
                    currentAddress);
                break;
            }

            if (!TryAdd(currentAddress, auxiliaryOffset, out var currentAuxiliaryAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.VersionDefinitionTableMalformed,
                    "The DT_VERDEF auxiliary offset overflows its virtual address.",
                    currentAddress);
                break;
            }

            var auxiliaries = new List<VersionDefinitionAuxiliary>(auxiliaryCount);
            var malformedAuxiliary = false;
            ulong lastAuxiliaryEndAddress = 0;
            for (ulong auxiliaryIndex = 0; auxiliaryIndex < auxiliaryCount; auxiliaryIndex++)
            {
                parsedAuxiliaryCount++;
                if (!TryResolveVirtualRange(
                        reader,
                        loadMap,
                        currentAuxiliaryAddress,
                        8,
                        out var auxiliaryFileOffset)
                    || !reader.TryReadUInt32(auxiliaryFileOffset, out var nameOffset)
                    || !reader.TryReadUInt32(auxiliaryFileOffset + 4, out var nextAuxiliaryOffset)
                    || !reader.TrySlice(auxiliaryFileOffset, 8, out var rawAuxiliary)
                    || !TryReadString(dynamicMetadata.StringTable, nameOffset, out var name)
                    || string.IsNullOrEmpty(name))
                {
                    diagnostics.Error(
                        DiagnosticCode.VersionDefinitionTableMalformed,
                        "The DT_VERDEF auxiliary record is truncated, unmapped, or has an invalid name.",
                        currentAuxiliaryAddress);
                    malformedAuxiliary = true;
                    break;
                }

                if (!TryAdd(currentAuxiliaryAddress, 8, out lastAuxiliaryEndAddress))
                {
                    diagnostics.Error(
                        DiagnosticCode.VersionDefinitionTableMalformed,
                        "The DT_VERDEF auxiliary record range overflows its virtual address.",
                        currentAuxiliaryAddress);
                    malformedAuxiliary = true;
                    break;
                }

                auxiliaries.Add(new VersionDefinitionAuxiliary(
                    nameOffset,
                    nextAuxiliaryOffset,
                    name,
                    rawAuxiliary));
                UpdateRawRange(ref rawTableStart, ref rawTableEnd, auxiliaryFileOffset, 8);

                if (auxiliaryIndex + 1 < auxiliaryCount)
                {
                    if (nextAuxiliaryOffset < 8
                        || !TryAdd(
                            currentAuxiliaryAddress,
                            nextAuxiliaryOffset,
                            out var nextAuxiliaryAddress)
                        || nextAuxiliaryAddress <= currentAuxiliaryAddress)
                    {
                        diagnostics.Error(
                            DiagnosticCode.VersionDefinitionTableMalformed,
                            "The DT_VERDEF auxiliary chain terminates, overlaps, or moves backwards before its declared count.",
                            currentAuxiliaryAddress);
                        malformedAuxiliary = true;
                        break;
                    }

                    currentAuxiliaryAddress = nextAuxiliaryAddress;
                }
                else if (nextAuxiliaryOffset != 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.VersionDefinitionTableMalformed,
                        "The DT_VERDEF auxiliary chain has entries beyond its declared count.",
                        currentAuxiliaryAddress);
                    malformedAuxiliary = true;
                    break;
                }
            }

            if (malformedAuxiliary)
            {
                break;
            }

            definitions.Add(new VersionDefinition(
                version,
                flags,
                versionIndex,
                auxiliaryCount,
                hash,
                auxiliaryOffset,
                nextOffset,
                auxiliaries[0].Name,
                auxiliaries,
                rawRecord));
            UpdateRawRange(ref rawTableStart, ref rawTableEnd, recordFileOffset, 20);

            if (index + 1 < count)
            {
                if (nextOffset == 0
                    || !TryAdd(currentAddress, nextOffset, out var nextAddress)
                    || nextAddress <= currentAddress)
                {
                    diagnostics.Error(
                        DiagnosticCode.VersionDefinitionTableMalformed,
                        "The DT_VERDEF chain terminates or moves backwards before its declared count.",
                        currentAddress);
                    break;
                }

                if (nextAddress < lastAuxiliaryEndAddress)
                {
                    diagnostics.Error(
                        DiagnosticCode.VersionDefinitionTableMalformed,
                        "The DT_VERDEF chain overlaps the current definition or its auxiliaries.",
                        currentAddress);
                    break;
                }

                currentAddress = nextAddress;
            }
            else if (nextOffset != 0)
            {
                diagnostics.Error(
                    DiagnosticCode.VersionDefinitionTableMalformed,
                    "The DT_VERDEF chain has entries beyond its declared count.",
                    currentAddress);
                break;
            }
        }

        var rawTable = ReadOnlyMemory<byte>.Empty;
        if (rawTableStart is ulong start
            && rawTableEnd >= start
            && reader.TrySlice(start, rawTableEnd - start, out var rawBytes))
        {
            rawTable = rawBytes;
        }

        return new VersionDefinitionParseResult(address, rawTable, definitions);

    }

    private static void UpdateRawRange(
        ref ulong? rawStart,
        ref ulong rawEnd,
        ulong fileOffset,
        ulong size)
    {
        if (!TryAdd(fileOffset, size, out var end))
        {
            return;
        }

        rawStart = rawStart is ulong start
            ? Math.Min(start, fileOffset)
            : fileOffset;
        rawEnd = Math.Max(rawEnd, end);
    }

    private readonly record struct VersionDefinitionParseResult(
        ulong Address,
        ReadOnlyMemory<byte> RawBytes,
        IReadOnlyList<VersionDefinition> Records);
}
