using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>The result of deriving one provider-table extension from pinned raw ELF bytes.</summary>
public sealed class SemanticExternalJumpTableProviderReadResult
{
    internal SemanticExternalJumpTableProviderReadResult(
        SemanticExternalJumpTableExtension? extension,
        IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        Extension = extension;
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
    }

    public SemanticExternalJumpTableExtension? Extension { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsSuccess => Extension is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);

    /// <summary>
    /// Projects only the provider-domain identity facts needed by the selected-
    /// consumer proof query. This does not admit protection/rehydration or add
    /// provider addresses to a consumer AddressMap.
    /// </summary>
    public Aarch64ExternalJumpTableProviderFacts? CreateConsumerProofInput()
    {
        if (!IsSuccess || Extension is not { } extension)
        {
            return null;
        }

        var targetsByIdentity = extension.TargetSymbols.ToDictionary(
            target => (target.SymbolTable, target.SymbolIndex));
        var targets = extension.Entries
            .OrderBy(entry => entry.Index)
            .Select(entry =>
            {
                var target = targetsByIdentity[(entry.TargetSymbolTable, entry.TargetSymbolIndex)];
                return new Aarch64ExternalProviderTargetIdentity(entry.Index, target.Name);
            })
            .ToArray();
        var tableBytesSha256 = Convert.ToHexString(SHA256.HashData(extension.TableBytesSpan))
            .ToLowerInvariant();
        return new Aarch64ExternalJumpTableProviderFacts(
            extension.TableIdentity.Value,
            extension.ProviderSoname,
            extension.ProviderBuildIdHex,
            extension.ProviderSha256,
            extension.TableObject.Name,
            extension.TableObject.Range.Size,
            tableBytesSha256,
            targets);
    }
}

/// <summary>
/// Bounded, side-effect-free derivation of the current SPS6 external provider
/// table facts. This is deliberately not a provider path loader or a general
/// ELF parser: structural facts and address conversion come from
/// <see cref="ElfParser"/> and <see cref="LoadMap"/>.
/// </summary>
public static class SemanticExternalJumpTableProviderReader
{
    public const int MaximumProviderElfBytes = 8 * 1024 * 1024;

    private const int MaximumProgramHeaders = 128;
    private const int MaximumSectionHeaders = 4096;
    private const int MaximumDynamicEntries = 4096;
    private const int RequiredEntryCount = 4;
    private const int RequiredTableByteCount = RequiredEntryCount * sizeof(int);
    private const uint GnuBuildIdNoteType = 3;
    private const ushort FirstReservedSectionIndex = 0xFF00;
    private const byte StbGlobal = 1;
    private const byte StvDefault = 0;
    private const uint KnownLoadFlags = ElfConstants.PfR | ElfConstants.PfW | ElfConstants.PfX;
    private static readonly byte[] GnuNoteName = "GNU\0"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly HashSet<uint> UnsupportedProviderRelocationSectionTypes = new()
    {
        ElfConstants.ShtRel,
        ElfConstants.ShtRela,
        ElfConstants.ShtRelr,
        ElfConstants.ShtAndroidRel,
        ElfConstants.ShtAndroidRela,
        ElfConstants.ShtAndroidRelr,
    };
    private static readonly HashSet<uint> UnsupportedProviderVersionSectionTypes = new()
    {
        ElfConstants.ShtGnuVerdef,
        ElfConstants.ShtGnuVerneed,
        ElfConstants.ShtGnuVersym,
    };
    private static readonly ulong[] UnsupportedProviderDynamicTags =
    {
        ElfConstants.DtNeeded,
        ElfConstants.DtRpath,
        ElfConstants.DtRunPath,
        ElfConstants.DtConfig,
        ElfConstants.DtAudit,
        ElfConstants.DtDepAudit,
        ElfConstants.DtAuxiliary,
        ElfConstants.DtFilter,
        ElfConstants.DtSymbolic,
        ElfConstants.DtRel,
        ElfConstants.DtRelSz,
        ElfConstants.DtRelEnt,
        ElfConstants.DtRelCount,
        ElfConstants.DtRelaCount,
        ElfConstants.DtRela,
        ElfConstants.DtRelaSz,
        ElfConstants.DtRelaEnt,
        ElfConstants.DtJmpRel,
        ElfConstants.DtPltRelSz,
        ElfConstants.DtPltRel,
        ElfConstants.DtRelr,
        ElfConstants.DtRelrSz,
        ElfConstants.DtRelrEnt,
        ElfConstants.DtAndroidRel,
        ElfConstants.DtAndroidRelsz,
        ElfConstants.DtAndroidRela,
        ElfConstants.DtAndroidRelasz,
        ElfConstants.DtAndroidRelr,
        ElfConstants.DtAndroidRelrsz,
        ElfConstants.DtAndroidRelrent,
        ElfConstants.DtAndroidRelrCount,
        ElfConstants.DtTextRel,
        ElfConstants.DtVersym,
        ElfConstants.DtVerneed,
        ElfConstants.DtVerneedNum,
        ElfConstants.DtVerdef,
        ElfConstants.DtVerdefNum,
    };

    private static readonly ElfParserLimits ProviderParseLimits = new(
        MaximumProviderElfBytes,
        MaximumProgramHeaders,
        MaximumSectionHeaders,
        MaximumDynamicEntries,
        MaximumDynamicEntries,
        SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols,
        SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols,
        MaximumDynamicEntries,
        MaximumDynamicEntries,
        MaximumDynamicEntries,
        SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes,
        SemanticPlanSnapshotLimits.MaximumStringBytes + 1,
        MaximumProviderElfBytes,
        new HashSet<ulong>(UnsupportedProviderDynamicTags),
        new Dictionary<ulong, ulong> { [ElfConstants.DtFlags] = ElfConstants.DfTextRel },
        RequireSingleDynamicWithoutInterpreter: true,
        RequireCompleteSectionHeaderTable: true);

    /// <summary>
    /// Derives provider facts only when the supplied bytes match the trusted
    /// SONAME, GNU build ID, and SHA-256 pins. The supplied canonical table
    /// identity is an opaque semantic label; the provider dynamic-symbol name is
    /// derived independently from the unique object satisfying the full contract.
    /// </summary>
    public static SemanticExternalJumpTableProviderReadResult Read(
        ReadOnlyMemory<byte> providerBytes,
        string expectedProviderSoname,
        string expectedBuildIdHex,
        string expectedSha256,
        SemanticExternalProviderTableIdentity tableIdentity)
    {
        ArgumentNullException.ThrowIfNull(expectedProviderSoname);
        ArgumentNullException.ThrowIfNull(expectedBuildIdHex);
        ArgumentNullException.ThrowIfNull(expectedSha256);

        var diagnostics = new DiagnosticBag();
        if (!IsCanonicalSoname(expectedProviderSoname)
            || !IsCanonicalTableIdentity(tableIdentity.Value)
            || !IsCanonicalHex(expectedBuildIdHex, minimumCharacters: 8, maximumCharacters: 128, evenLength: true)
            || !IsCanonicalHex(expectedSha256, minimumCharacters: 64, maximumCharacters: 64, evenLength: true))
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The pinned provider SONAME, GNU build ID, SHA-256, or canonical table identity is malformed.");
            return Failure(diagnostics);
        }

        if (providerBytes.Length > MaximumProviderElfBytes)
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                $"The raw provider ELF exceeds the {MaximumProviderElfBytes}-byte input limit.");
            return Failure(diagnostics);
        }

        // The caller may retain a writable alias to this memory. Hash, parse,
        // and derive every byte fact from one private bounded snapshot instead.
        var providerSnapshot = providerBytes.ToArray();
        return ReadSnapshot(providerSnapshot, expectedProviderSoname, expectedBuildIdHex, expectedSha256, tableIdentity);
    }

    /// <summary>
    /// Reads a byte array already owned as a private Infrastructure snapshot.
    /// This avoids a second full-size copy while preserving the public Read
    /// method's isolation for arbitrary caller-owned memory.
    /// </summary>
    internal static SemanticExternalJumpTableProviderReadResult ReadPrivateSnapshot(
        byte[] providerSnapshot,
        string expectedProviderSoname,
        string expectedBuildIdHex,
        string expectedSha256,
        SemanticExternalProviderTableIdentity tableIdentity)
    {
        ArgumentNullException.ThrowIfNull(providerSnapshot);
        ArgumentNullException.ThrowIfNull(expectedProviderSoname);
        ArgumentNullException.ThrowIfNull(expectedBuildIdHex);
        ArgumentNullException.ThrowIfNull(expectedSha256);

        var diagnostics = new DiagnosticBag();
        if (!IsCanonicalSoname(expectedProviderSoname)
            || !IsCanonicalTableIdentity(tableIdentity.Value)
            || !IsCanonicalHex(expectedBuildIdHex, minimumCharacters: 8, maximumCharacters: 128, evenLength: true)
            || !IsCanonicalHex(expectedSha256, minimumCharacters: 64, maximumCharacters: 64, evenLength: true))
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The pinned provider SONAME, GNU build ID, SHA-256, or canonical table identity is malformed.");
            return Failure(diagnostics);
        }

        if (providerSnapshot.Length > MaximumProviderElfBytes)
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                $"The raw provider ELF exceeds the {MaximumProviderElfBytes}-byte input limit.");
            return Failure(diagnostics);
        }

        return ReadSnapshot(providerSnapshot, expectedProviderSoname, expectedBuildIdHex, expectedSha256, tableIdentity);
    }

    private static SemanticExternalJumpTableProviderReadResult ReadSnapshot(
        byte[] providerSnapshot,
        string expectedProviderSoname,
        string expectedBuildIdHex,
        string expectedSha256,
        SemanticExternalProviderTableIdentity tableIdentity)
    {
        var diagnostics = new DiagnosticBag();
        var actualSha256Bytes = SHA256.HashData(providerSnapshot);
        var expectedSha256Bytes = Convert.FromHexString(expectedSha256);
        if (!CryptographicOperations.FixedTimeEquals(actualSha256Bytes, expectedSha256Bytes))
        {
            Error(
                diagnostics,
                DiagnosticCode.OutputIdentityMismatch,
                "The raw provider bytes do not match the host-pinned SHA-256.");
            return Failure(diagnostics);
        }

        var parse = ElfParser.Parse(providerSnapshot, ProviderParseLimits);
        diagnostics.AddRange(parse.Diagnostics);
        if (parse.File is not { } file || parse.Diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return Failure(diagnostics);
        }

        var reader = new BoundedReader(providerSnapshot);
        if (!ValidateProviderContainer(file, diagnostics)
            || diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        if (!TryGetBuildId(file, out var actualBuildId, out var buildIdOffset, diagnostics))
        {
            return Failure(diagnostics);
        }

        if (!string.Equals(actualBuildId, expectedBuildIdHex, StringComparison.Ordinal))
        {
            Error(
                diagnostics,
                DiagnosticCode.OutputIdentityMismatch,
                "The provider GNU build ID does not match the host-pinned build ID.",
                buildIdOffset);
            return Failure(diagnostics);
        }

        if (!TryReadDynamicTables(
                file,
                reader,
                out var stringTableOffset,
                out var stringTableSize,
                out var parsedDynamicSymbols,
                diagnostics)
            || diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        if (!TryGetDynamicValue(file.DynamicEntries, ElfConstants.DtSoname, out var sonameOffset)
            || !TryReadStrictString(
                reader,
                stringTableOffset,
                stringTableSize,
                sonameOffset,
                out var observedSoname,
                out _,
                out var sonameFileOffset)
            || !string.Equals(observedSoname, file.DynamicMetadata.Soname, StringComparison.Ordinal))
        {
            Error(
                diagnostics,
                DiagnosticCode.DynamicTableMalformed,
                "The provider DT_SONAME is not one exact bounded strict-UTF-8 dynamic string.");
            return Failure(diagnostics);
        }

        if (!string.Equals(observedSoname, expectedProviderSoname, StringComparison.Ordinal))
        {
            Error(
                diagnostics,
                DiagnosticCode.OutputIdentityMismatch,
                "The provider DT_SONAME does not match the host-pinned SONAME.",
                sonameFileOffset);
            return Failure(diagnostics);
        }

        if (!TryGetProviderTableCandidates(parsedDynamicSymbols, out var tableCandidates, diagnostics)
            || !TryGetBoundedProviderFunctionSymbols(file, diagnostics)
            || diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        if (tableCandidates.Count == 0)
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "The provider has no defined global/default 16-byte STT_OBJECT candidate for the signed-relative table contract.");
            return Failure(diagnostics);
        }

        var validExtensions = new List<SemanticExternalJumpTableExtension>(2);
        Diagnostic? firstCandidateFailure = null;
        foreach (var tableSymbol in tableCandidates)
        {
            var candidateDiagnostics = new DiagnosticBag();
            if (TryBuildProviderTableExtension(
                    file,
                    reader,
                    parsedDynamicSymbols,
                    tableIdentity,
                    observedSoname,
                    actualBuildId,
                    Convert.ToHexString(actualSha256Bytes).ToLowerInvariant(),
                    checked((ulong)providerSnapshot.Length),
                    tableSymbol,
                    out var candidateExtension,
                    candidateDiagnostics))
            {
                validExtensions.Add(candidateExtension!);
                if (validExtensions.Count > 1)
                {
                    break;
                }
            }
            else if (firstCandidateFailure is null && candidateDiagnostics.Count > 0)
            {
                firstCandidateFailure = candidateDiagnostics[0];
            }
        }

        if (validExtensions.Count == 0)
        {
            if (firstCandidateFailure is { } candidateFailure)
            {
                diagnostics.Add(candidateFailure);
            }

            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "No provider dynamic object satisfies the complete bounded table, range, bytes, and four-target contract.");
            return Failure(diagnostics);
        }

        if (validExtensions.Count != 1)
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "More than one provider dynamic object satisfies the complete bounded table contract; provider table identity is ambiguous.");
            return Failure(diagnostics);
        }

        return new SemanticExternalJumpTableProviderReadResult(validExtensions[0], diagnostics);
    }

    private static bool ValidateProviderContainer(ElfFile file, DiagnosticBag diagnostics)
    {
        if (file.Header.Type != ElfConstants.TypeDyn
            || file.Header.Machine != ElfConstants.MachineAarch64)
        {
            Error(
                diagnostics,
                DiagnosticCode.UnsupportedFileType,
                "The provider must be an AArch64 ET_DYN shared object.");
            return false;
        }

        if (file.ProgramHeaders.Count > MaximumProgramHeaders
            || file.SectionHeaders.Count > MaximumSectionHeaders
            || file.DynamicEntries.Count > MaximumDynamicEntries)
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                "The provider program-header, section-header, or dynamic-entry count exceeds the bounded reader limit.");
            return false;
        }

        if (file.ProgramHeaders.Count(header => header.Type == ElfConstants.PtDynamic) != 1
            || file.ProgramHeaders.Any(header => header.Type == ElfConstants.PtInterp))
        {
            Error(
                diagnostics,
                DiagnosticCode.InvalidProgramHeader,
                "The provider must have exactly one PT_DYNAMIC and no PT_INTERP.");
            return false;
        }

        if (file.DynamicEntries.Count == 0 || !file.DynamicEntries[^1].IsTerminator)
        {
            Error(
                diagnostics,
                DiagnosticCode.DynamicTableUnterminated,
                "The provider PT_DYNAMIC must contain one bounded DT_NULL-terminated table.");
            return false;
        }

        foreach (var tag in UnsupportedProviderDynamicTags)
        {
            if (HasDynamicTag(file.DynamicEntries, tag))
            {
                Error(
                    diagnostics,
                    DiagnosticCode.DynamicTableMalformed,
                    $"The provider contains forbidden dynamic tag 0x{tag:X} for the dependency-free external-table contract.");
                return false;
            }
        }

        if (file.DynamicMetadata.NeededLibraries.Count != 0
            || file.DynamicMetadata.Rpath is not null
            || file.DynamicMetadata.RunPath is not null
            || file.RelaRelocations.Count != 0
            || file.SectionRelocations.Count != 0
            || file.SectionHeaders.Any(section =>
                UnsupportedProviderRelocationSectionTypes.Contains(section.Type)
                || UnsupportedProviderVersionSectionTypes.Contains(section.Type))
            || file.RelrWords.Count != 0
            || file.AndroidPackedRelocations.Count != 0)
        {
            Error(
                diagnostics,
                DiagnosticCode.DynamicTableMalformed,
                "The provider must not carry dependencies, runtime search paths, dynamic relocation tables, section-owned REL/RELA/RELR tables, symbol-version metadata, or section relocation facts.");
            return false;
        }

        return true;
    }

    private static bool TryGetBuildId(
        ElfFile file,
        out string buildIdHex,
        out ulong? noteOffset,
        DiagnosticBag diagnostics)
    {
        buildIdHex = string.Empty;
        noteOffset = null;
        ElfNote? match = null;
        foreach (var note in file.Notes)
        {
            if (note.SegmentType != ElfConstants.PtNote
                || note.Type != GnuBuildIdNoteType
                || !note.Name.Span.SequenceEqual(GnuNoteName))
            {
                continue;
            }

            if (match is not null)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.NoteMalformed,
                    "The provider contains duplicate GNU build-ID notes.",
                    note.FileOffset);
                return false;
            }

            match = note;
        }

        if (match is not { } buildIdNote
            || buildIdNote.Descriptor.Length is < 4 or > 64)
        {
            Error(
                diagnostics,
                DiagnosticCode.NoteMalformed,
                "The provider must contain exactly one bounded GNU build-ID note.");
            return false;
        }

        buildIdHex = Convert.ToHexString(buildIdNote.Descriptor.Span).ToLowerInvariant();
        noteOffset = buildIdNote.FileOffset;
        return true;
    }

    private static bool TryReadDynamicTables(
        ElfFile file,
        BoundedReader reader,
        out ulong stringTableOffset,
        out ulong stringTableSize,
        out IReadOnlyList<ParsedProviderSymbol> parsedSymbols,
        DiagnosticBag diagnostics)
    {
        stringTableOffset = default;
        stringTableSize = default;
        parsedSymbols = Array.Empty<ParsedProviderSymbol>();

        if (!TryGetUniqueDynamicValue(file.DynamicEntries, ElfConstants.DtSoname, out _)
            || !TryGetUniqueDynamicValue(file.DynamicEntries, ElfConstants.DtStrTab, out var stringTableAddress)
            || !TryGetUniqueDynamicValue(file.DynamicEntries, ElfConstants.DtStrSz, out stringTableSize)
            || !TryGetUniqueDynamicValue(file.DynamicEntries, ElfConstants.DtSymTab, out var symbolTableAddress)
            || !TryGetUniqueDynamicValue(file.DynamicEntries, ElfConstants.DtSymEnt, out var symbolEntrySize))
        {
            Error(
                diagnostics,
                DiagnosticCode.DynamicTableMalformed,
                "The provider requires unique DT_SONAME, DT_STRTAB/DT_STRSZ, and DT_SYMTAB/DT_SYMENT entries.");
            return false;
        }

        var hasSysvHash = TryGetUniqueDynamicValue(file.DynamicEntries, ElfConstants.DtHash, out _);
        var hasGnuHash = TryGetUniqueDynamicValue(file.DynamicEntries, ElfConstants.DtGnuHash, out _);
        if (hasSysvHash == hasGnuHash
            || CountDynamicTag(file.DynamicEntries, ElfConstants.DtHash) > 1
            || CountDynamicTag(file.DynamicEntries, ElfConstants.DtGnuHash) > 1)
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "The provider must have exactly one parser-supported dynamic symbol-count hash table.");
            return false;
        }

        var stringTableFileOffset = default(FileOffset);
        if (symbolEntrySize != ElfConstants.SymbolEntrySize64
            || stringTableSize == 0
            || stringTableSize > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes
            || !TryGetUniqueProviderRange(
                file,
                reader,
                stringTableAddress,
                stringTableSize,
                out stringTableFileOffset,
                out _,
                diagnostics,
                "provider dynamic string table"))
        {
            if (!diagnostics.HasErrors)
            {
                Error(
                    diagnostics,
                    stringTableSize > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes
                        ? DiagnosticCode.SemanticPlanSnapshotLimitExceeded
                        : DiagnosticCode.DynamicTableMalformed,
                    "The provider dynamic symbol/string table layout is malformed or exceeds its bounded string-byte aggregate.",
                    stringTableAddress);
            }

            return false;
        }

        stringTableOffset = stringTableFileOffset.Value;
        if (!reader.TrySlice(stringTableOffset, stringTableSize, out var rawStringTable)
            || !rawStringTable.Span.SequenceEqual(file.DynamicMetadata.StringTable.Span))
        {
            Error(
                diagnostics,
                DiagnosticCode.DynamicTableMalformed,
                "The parsed provider dynamic string table differs from its exact bounded DT_STRTAB/DT_STRSZ bytes.",
                stringTableOffset);
            return false;
        }

        if (file.DynamicSymbols.Count is 0 or > SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols)
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                $"The provider dynamic-symbol count must be between 1 and {SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols}.",
                symbolTableAddress);
            return false;
        }

        if ((ulong)file.DynamicSymbols.Count > ulong.MaxValue / symbolEntrySize)
        {
            Error(
                diagnostics,
                DiagnosticCode.AddressOverflow,
                "The provider dynamic-symbol table size overflowed.",
                symbolTableAddress);
            return false;
        }

        var symbolTableSize = checked((ulong)file.DynamicSymbols.Count * symbolEntrySize);
        if (!TryGetUniqueProviderRange(
                file,
                reader,
                symbolTableAddress,
                symbolTableSize,
                out var symbolTableOffset,
                out _,
                diagnostics,
                "provider dynamic symbol table"))
        {
            return false;
        }

        var symbols = new List<ParsedProviderSymbol>(file.DynamicSymbols.Count);
        var stringBytesObserved = 0;
        var stringScanBytesObserved = 0;
        for (var index = 0; index < file.DynamicSymbols.Count; index++)
        {
            var rowOffsetDelta = checked((ulong)index * symbolEntrySize);
            if (!TryAdd(symbolTableOffset.Value, rowOffsetDelta, out var rowOffset)
                || !reader.TryReadUInt32(rowOffset, out var nameOffset)
                || !reader.TryReadByte(rowOffset + 4, out var info)
                || !reader.TryReadByte(rowOffset + 5, out var other)
                || !reader.TryReadUInt16(rowOffset + 6, out var sectionIndex)
                || !reader.TryReadUInt64(rowOffset + 8, out var value)
                || !reader.TryReadUInt64(rowOffset + 16, out var size))
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider dynamic-symbol row is truncated or outside the exact DT_SYMTAB range.",
                    rowOffset);
                return false;
            }

            var parsed = file.DynamicSymbols[index];
            if (parsed.Name != nameOffset
                || parsed.Info != info
                || parsed.Other != other
                || parsed.SectionIndex != sectionIndex
                || parsed.Value != value
                || parsed.Size != size)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider dynamic-symbol row differs from the row parsed by ElfParser.",
                    rowOffset);
                return false;
            }

            if ((other & 0xFC) != 0)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider dynamic-symbol row uses unsupported st_other bits.",
                    rowOffset + 5);
                return false;
            }

            if (nameOffset >= stringTableSize)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider dynamic-symbol name offset is outside its bounded string table.",
                    stringTableOffset);
                return false;
            }

            var nameScanBytes = (int)Math.Min(
                stringTableSize - nameOffset,
                (ulong)SemanticPlanSnapshotLimits.MaximumStringBytes + 1);
            if (nameScanBytes > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes - stringScanBytesObserved)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "Provider dynamic-symbol name scans exceed the aggregate string-work limit before the next scan.",
                    stringTableOffset + nameOffset);
                return false;
            }

            stringScanBytesObserved += nameScanBytes;
            if (!TryReadStrictString(
                    reader,
                    stringTableOffset,
                    stringTableSize,
                    nameOffset,
                    out var name,
                    out var nameByteCount,
                    out var nameFileOffset))
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider dynamic-symbol name is not a bounded strict-UTF-8 string.",
                    nameFileOffset);
                return false;
            }

            if (nameByteCount > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes - stringBytesObserved)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "Provider dynamic-symbol name work exceeds the aggregate string-byte limit.",
                    nameFileOffset);
                return false;
            }

            stringBytesObserved += nameByteCount;
            symbols.Add(new ParsedProviderSymbol(
                ElfSymbolTableKind.Dynamic,
                checked((uint)index),
                name,
                info,
                other,
                sectionIndex,
                value,
                size));
        }

        parsedSymbols = Array.AsReadOnly(symbols.ToArray());
        return true;
    }

    private static bool TryGetProviderTableCandidates(
        IReadOnlyList<ParsedProviderSymbol> parsedDynamicSymbols,
        out IReadOnlyList<ParsedProviderSymbol> candidates,
        DiagnosticBag diagnostics)
    {
        var matches = new List<ParsedProviderSymbol>();
        foreach (var symbol in parsedDynamicSymbols)
        {
            if (symbol.Type == ElfConstants.SttObject
                && symbol.Binding == StbGlobal
                && symbol.Other == StvDefault
                && symbol.SectionIndex is > 0 and < FirstReservedSectionIndex
                && symbol.Size == RequiredTableByteCount)
            {
                matches.Add(symbol);
            }
        }

        if (matches.Count > SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols)
        {
            candidates = Array.Empty<ParsedProviderSymbol>();
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                "The provider table-object candidate count exceeds the bounded dynamic-symbol limit.");
            return false;
        }

        candidates = Array.AsReadOnly(matches.ToArray());
        return true;
    }

    private static bool TryGetBoundedProviderFunctionSymbols(ElfFile file, DiagnosticBag diagnostics)
    {
        if (file.FunctionSymbols.Count > SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols)
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                $"The provider function-symbol inventory exceeds {SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols} rows.");
            return false;
        }

        return true;
    }

    private static bool TryBuildProviderTableExtension(
        ElfFile file,
        BoundedReader reader,
        IReadOnlyList<ParsedProviderSymbol> parsedDynamicSymbols,
        SemanticExternalProviderTableIdentity tableIdentity,
        string providerSoname,
        string providerBuildId,
        string providerSha256,
        ulong providerFileSize,
        ParsedProviderSymbol tableSymbol,
        out SemanticExternalJumpTableExtension? extension,
        DiagnosticBag diagnostics)
    {
        extension = null;
        if (tableSymbol.Value % sizeof(int) != 0)
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "A provider table-object candidate is not aligned for signed-32 relative entries.",
                tableSymbol.Value);
            return false;
        }

        if (!TryGetUniqueProviderRange(
                file,
                reader,
                tableSymbol.Value,
                RequiredTableByteCount,
                out var tableFileOffset,
                out var tableSegment,
                diagnostics,
                "provider table object"))
        {
            return false;
        }

        if (tableSegment.Flags != ElfConstants.PfR
            || (tableSegment.Flags & ~KnownLoadFlags) != 0)
        {
            Error(
                diagnostics,
                DiagnosticCode.InvalidSegment,
                "A provider table-object candidate must occupy a PF_R-only, non-writable, non-executable PT_LOAD range.",
                tableFileOffset.Value);
            return false;
        }

        if (!reader.TrySlice(tableFileOffset.Value, RequiredTableByteCount, out var rawTableBytes))
        {
            Error(
                diagnostics,
                DiagnosticCode.TableOutOfBounds,
                "A provider table-object candidate is not wholly available in the pinned provider file.",
                tableFileOffset.Value);
            return false;
        }

        var targets = new List<SemanticExternalProviderSymbol>(RequiredEntryCount);
        var entries = new List<SemanticExternalJumpTableEntryFact>(RequiredEntryCount);
        var targetAddresses = new HashSet<ulong>();
        for (var index = 0; index < RequiredEntryCount; index++)
        {
            var entryByteOffset = checked((ulong)index * sizeof(int));
            if (!TryAdd(tableFileOffset.Value, entryByteOffset, out var entryFileOffset)
                || !reader.TryReadInt32(entryFileOffset, out var displacement))
            {
                Error(
                    diagnostics,
                    DiagnosticCode.TableOutOfBounds,
                    "A signed-relative provider table candidate entry is truncated or outside the pinned file.",
                    tableFileOffset.Value);
                return false;
            }

            if (!TryApplySignedDisplacement(tableSymbol.Value, displacement, out var targetAddress))
            {
                Error(
                    diagnostics,
                    DiagnosticCode.AddressOverflow,
                    "A signed-relative provider table candidate entry overflows the provider virtual-address domain.",
                    entryFileOffset);
                return false;
            }

            if (!targetAddresses.Add(targetAddress))
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A provider table candidate contains duplicate target addresses; all four entries must identify distinct targets.",
                    entryFileOffset);
                return false;
            }

            if (!TryResolveProviderFunction(
                    file,
                    reader,
                    parsedDynamicSymbols,
                    targetAddress,
                    out var targetSymbol,
                    diagnostics))
            {
                return false;
            }

            targets.Add(targetSymbol);
            entries.Add(new SemanticExternalJumpTableEntryFact(
                index,
                displacement,
                targetSymbol.SymbolTable,
                targetSymbol.SymbolIndex));
        }

        var candidate = new SemanticExternalJumpTableExtension(
            tableIdentity,
            providerSoname,
            providerBuildId,
            providerSha256,
            providerFileSize,
            new SemanticExternalProviderSymbol(
                tableSymbol.Name,
                ElfSymbolTableKind.Dynamic,
                tableSymbol.Index,
                tableSymbol.Binding,
                tableSymbol.Type,
                tableSymbol.Visibility,
                tableSymbol.SectionIndex,
                new SemanticExternalProviderRange(
                    new SemanticExternalProviderFileOffset(tableFileOffset.Value),
                    new SemanticExternalProviderAddress(tableSymbol.Value),
                    tableSymbol.Size),
                tableSegment.Flags),
            targets,
            entries,
            rawTableBytes.ToArray());

        SemanticExternalJumpTableContract.ValidateExtensionFields(candidate, diagnostics);
        if (diagnostics.HasErrors)
        {
            return false;
        }

        extension = candidate;
        return true;
    }

    private static bool TryResolveProviderFunction(
        ElfFile file,
        BoundedReader reader,
        IReadOnlyList<ParsedProviderSymbol> parsedDynamicSymbols,
        ulong targetAddress,
        out SemanticExternalProviderSymbol target,
        DiagnosticBag diagnostics)
    {
        target = default!;
        ElfFunctionSymbol? selected = null;
        ParsedProviderSymbol? dynamicTarget = null;
        var dynamicMatches = 0;
        foreach (var symbol in parsedDynamicSymbols)
        {
            if (symbol.Type == ElfConstants.SttFunc && symbol.Value == targetAddress)
            {
                dynamicMatches++;
                if (dynamicMatches == 1)
                {
                    dynamicTarget = symbol;
                }
            }
        }

        if (dynamicMatches > 1)
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "A provider table target address has multiple dynamic STT_FUNC symbol identities.",
                targetAddress);
            return false;
        }

        if (dynamicTarget is { } dynamicSymbol)
        {
            if (dynamicSymbol.Size == 0)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider table target resolves only to a zero-sized dynamic STT_FUNC symbol.",
                    targetAddress);
                return false;
            }

            var dynamicFunctionMatches = 0;
            foreach (var symbol in file.FunctionSymbols)
            {
                if (symbol.Table == ElfSymbolTableKind.Dynamic
                    && symbol.TableIndex == dynamicSymbol.Index)
                {
                    dynamicFunctionMatches++;
                    if (dynamicFunctionMatches == 1)
                    {
                        selected = symbol;
                    }
                }
            }

            if (dynamicFunctionMatches != 1)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider dynamic STT_FUNC row does not have one matching ElfParser function-symbol identity.",
                    targetAddress);
                return false;
            }
        }
        else
        {
            var staticMatches = 0;
            foreach (var symbol in file.FunctionSymbols)
            {
                if (symbol.Table == ElfSymbolTableKind.Static && symbol.Value == targetAddress)
                {
                    staticMatches++;
                    if (staticMatches == 1)
                    {
                        selected = symbol;
                    }
                }
            }

            if (staticMatches > 1)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider table target address has multiple static STT_FUNC symbol identities.",
                    targetAddress);
                return false;
            }
        }

        if (selected is not { } function
            || function.Size == 0
            || function.Value != targetAddress
            || function.TableIndex == 0
            || function.SectionIndex == 0
            || function.SectionIndex >= FirstReservedSectionIndex
            || function.Binding > 2
            || (function.Other & 0xFC) != 0)
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "A signed-relative provider table entry does not resolve to one defined provider STT_FUNC symbol.",
                targetAddress);
            return false;
        }

        ParsedProviderSymbol providerSymbol;
        if (function.Table == ElfSymbolTableKind.Dynamic)
        {
            if (function.TableIndex >= (uint)parsedDynamicSymbols.Count)
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider function-symbol index is outside the parsed DT_SYMTAB inventory.",
                    targetAddress);
                return false;
            }

            providerSymbol = parsedDynamicSymbols[checked((int)function.TableIndex)];
            if ((providerSymbol.Info & 0x0F) != ElfConstants.SttFunc
                || !FunctionSymbolMatches(function, providerSymbol))
            {
                Error(
                    diagnostics,
                    DiagnosticCode.SymbolTableMalformed,
                    "A provider dynamic STT_FUNC identity differs from its exact DT_SYMTAB row.",
                    targetAddress);
                return false;
            }
        }
        else
        {
            if (!TryReadExactStaticFunctionSymbol(
                    file,
                    reader,
                    function,
                    out providerSymbol,
                    diagnostics))
            {
                return false;
            }
        }

        if (!TryGetUniqueProviderRange(
                file,
                reader,
                function.Value,
                function.Size,
                out var targetFileOffset,
                out var targetSegment,
                diagnostics,
                "provider target function"))
        {
            return false;
        }

        if ((targetSegment.Flags & ElfConstants.PfX) == 0
            || (targetSegment.Flags & ElfConstants.PfW) != 0
            || (targetSegment.Flags & ~KnownLoadFlags) != 0)
        {
            Error(
                diagnostics,
                DiagnosticCode.InvalidSegment,
                "A provider-local target STT_FUNC must occupy a bounded non-writable executable PT_LOAD range.",
                targetFileOffset.Value);
            return false;
        }

        target = new SemanticExternalProviderSymbol(
            function.Name,
            function.Table,
            function.TableIndex,
            function.Binding,
            (byte)(providerSymbol.Info & 0x0F),
            (byte)(providerSymbol.Other & 0x03),
            function.SectionIndex,
            new SemanticExternalProviderRange(
                new SemanticExternalProviderFileOffset(targetFileOffset.Value),
                new SemanticExternalProviderAddress(function.Value),
                function.Size),
            targetSegment.Flags);
        return true;
    }

    private static bool TryReadExactStaticFunctionSymbol(
        ElfFile file,
        BoundedReader reader,
        ElfFunctionSymbol function,
        out ParsedProviderSymbol parsed,
        DiagnosticBag diagnostics)
    {
        parsed = default!;
        SectionHeader symbolTable = default;
        var symbolTableCount = 0;
        foreach (var section in file.SectionHeaders)
        {
            if (section.Type == ElfConstants.ShtSymTab)
            {
                symbolTable = section;
                symbolTableCount++;
            }
        }

        if (symbolTableCount != 1
            || symbolTable.EntrySize != ElfConstants.SymbolEntrySize64
            || symbolTable.Size % symbolTable.EntrySize != 0
            || symbolTable.Size > (ulong)reader.Length
            || symbolTable.Link >= (uint)file.SectionHeaders.Count
            || function.TableIndex >= symbolTable.Size / symbolTable.EntrySize)
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "A static provider target requires one bounded, uniquely linked ELF64 SHT_SYMTAB.");
            return false;
        }

        var count = symbolTable.Size / symbolTable.EntrySize;
        if (count > SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols)
        {
            Error(
                diagnostics,
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                "The provider static symbol-table row count exceeds the bounded target-symbol limit.",
                symbolTable.Offset);
            return false;
        }

        var stringTable = file.SectionHeaders[checked((int)symbolTable.Link)];
        if (stringTable.Type != ElfConstants.ShtStrTab
            || stringTable.Size == 0
            || stringTable.Size > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes
            || !reader.Contains(stringTable.Offset, stringTable.Size))
        {
            Error(
                diagnostics,
                stringTable.Size > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes
                    ? DiagnosticCode.SemanticPlanSnapshotLimitExceeded
                    : DiagnosticCode.SymbolTableMalformed,
                "The provider static symbol string table is absent, out of range, or exceeds its byte limit.",
                stringTable.Offset);
            return false;
        }

        var rowDelta = checked((ulong)function.TableIndex * symbolTable.EntrySize);
        if (!TryAdd(symbolTable.Offset, rowDelta, out var rowOffset)
            || !reader.TryReadUInt32(rowOffset, out var nameOffset)
            || !reader.TryReadByte(rowOffset + 4, out var info)
            || !reader.TryReadByte(rowOffset + 5, out var other)
            || !reader.TryReadUInt16(rowOffset + 6, out var sectionIndex)
            || !reader.TryReadUInt64(rowOffset + 8, out var value)
            || !reader.TryReadUInt64(rowOffset + 16, out var size)
            || !TryReadStrictString(
                reader,
                stringTable.Offset,
                stringTable.Size,
                nameOffset,
                out var name,
                out _,
                out var nameOffsetInFile))
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "A provider static STT_FUNC row or its exact bounded name is malformed.",
                rowOffset);
            return false;
        }

        if ((info & 0x0F) != ElfConstants.SttFunc
            || (info >> 4) != function.Binding
            || other != function.Other
            || sectionIndex != function.SectionIndex
            || value != function.Value
            || size != function.Size
            || !string.Equals(name, function.Name, StringComparison.Ordinal))
        {
            Error(
                diagnostics,
                DiagnosticCode.SymbolTableMalformed,
                "A provider static STT_FUNC identity differs from its exact SHT_SYMTAB row.",
                nameOffsetInFile);
            return false;
        }

        parsed = new ParsedProviderSymbol(
            ElfSymbolTableKind.Static,
            function.TableIndex,
            name,
            info,
            other,
            sectionIndex,
            value,
            size);
        return true;
    }

    private static bool TryGetUniqueProviderRange(
        ElfFile file,
        BoundedReader reader,
        ulong virtualAddress,
        ulong size,
        out FileOffset fileOffset,
        out ProgramHeader owner,
        DiagnosticBag diagnostics,
        string description)
    {
        fileOffset = default;
        owner = default;
        if (size == 0 || virtualAddress > ulong.MaxValue - size)
        {
            Error(
                diagnostics,
                DiagnosticCode.AddressOverflow,
                $"The {description} provider virtual range is empty or overflows.",
                virtualAddress);
            return false;
        }

        var ownerCount = 0;
        ulong candidateOffset = 0;
        ProgramHeader candidateOwner = default;
        foreach (var header in file.ProgramHeaders)
        {
            if (header.Type != ElfConstants.PtLoad
                || virtualAddress < header.VirtualAddress
                || size > header.FileSize
                || virtualAddress - header.VirtualAddress > header.FileSize - size)
            {
                continue;
            }

            var delta = virtualAddress - header.VirtualAddress;
            if (header.Offset > ulong.MaxValue - delta)
            {
                continue;
            }

            var offset = header.Offset + delta;
            if (offset > (ulong)reader.Length
                || size > (ulong)reader.Length - offset
                || offset < header.Offset
                || offset - header.Offset > header.FileSize - size)
            {
                continue;
            }

            ownerCount++;
            candidateOffset = offset;
            candidateOwner = header;
            if (ownerCount > 1)
            {
                break;
            }
        }

        if (ownerCount != 1
            || !file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(virtualAddress),
                size,
                out var mappedOffset)
            || mappedOffset.Value != candidateOffset
            || !reader.Contains(candidateOffset, size))
        {
            Error(
                diagnostics,
                DiagnosticCode.AddressUnmapped,
                ownerCount > 1
                    ? $"The {description} provider range has ambiguous PT_LOAD ownership."
                    : $"The {description} provider range is not uniquely file-backed by PT_LOAD.",
                virtualAddress);
            return false;
        }

        fileOffset = mappedOffset;
        owner = candidateOwner;
        return true;
    }

    private static bool TryReadStrictString(
        BoundedReader reader,
        ulong tableFileOffset,
        ulong tableSize,
        ulong stringOffset,
        out string value,
        out int byteCount,
        out ulong errorOffset)
    {
        value = string.Empty;
        byteCount = 0;
        errorOffset = tableFileOffset;
        var sourceOffset = tableFileOffset;
        if (stringOffset >= tableSize
            || !TryAdd(tableFileOffset, stringOffset, out sourceOffset))
        {
            errorOffset = sourceOffset;
            return false;
        }

        var remaining = tableSize - stringOffset;
        var scanLength = Math.Min(remaining, (ulong)SemanticPlanSnapshotLimits.MaximumStringBytes + 1);
        if (!reader.TrySlice(sourceOffset, scanLength, out var bytes))
        {
            errorOffset = sourceOffset;
            return false;
        }

        var terminator = bytes.Span.IndexOf((byte)0);
        if (terminator < 0 || terminator > SemanticPlanSnapshotLimits.MaximumStringBytes)
        {
            errorOffset = sourceOffset;
            return false;
        }

        try
        {
            value = StrictUtf8.GetString(bytes.Span[..terminator]);
            byteCount = terminator;
            errorOffset = sourceOffset;
            return true;
        }
        catch (DecoderFallbackException)
        {
            errorOffset = sourceOffset;
            return false;
        }
    }

    private static bool TryGetUniqueDynamicValue(
        IReadOnlyList<DynamicEntry> entries,
        ulong tag,
        out ulong value)
    {
        value = default;
        var count = 0;
        foreach (var entry in entries)
        {
            if (entry.Tag != tag)
            {
                continue;
            }

            value = entry.Value;
            count++;
            if (count > 1)
            {
                value = default;
                return false;
            }
        }

        return count == 1;
    }

    private static bool TryGetDynamicValue(
        IReadOnlyList<DynamicEntry> entries,
        ulong tag,
        out ulong value) => TryGetUniqueDynamicValue(entries, tag, out value);

    private static int CountDynamicTag(IReadOnlyList<DynamicEntry> entries, ulong tag)
    {
        var count = 0;
        foreach (var entry in entries)
        {
            if (entry.Tag == tag && ++count > 1)
            {
                return count;
            }
        }

        return count;
    }

    private static bool HasDynamicTag(IReadOnlyList<DynamicEntry> entries, ulong tag)
    {
        foreach (var entry in entries)
        {
            if (entry.Tag == tag)
            {
                return true;
            }
        }

        return false;
    }

    private static bool FunctionSymbolMatches(ElfFunctionSymbol function, ParsedProviderSymbol symbol) =>
        function.Table == symbol.Table
        && function.TableIndex == symbol.Index
        && string.Equals(function.Name, symbol.Name, StringComparison.Ordinal)
        && function.Binding == (symbol.Info >> 4)
        && function.Other == symbol.Other
        && function.SectionIndex == symbol.SectionIndex
        && function.Value == symbol.Value
        && function.Size == symbol.Size;

    private static bool TryApplySignedDisplacement(ulong baseAddress, int displacement, out ulong targetAddress)
    {
        if (displacement < 0)
        {
            var magnitude = (ulong)(-(long)displacement);
            if (baseAddress < magnitude)
            {
                targetAddress = default;
                return false;
            }

            targetAddress = baseAddress - magnitude;
            return true;
        }

        var positive = (uint)displacement;
        if (positive > ulong.MaxValue - baseAddress)
        {
            targetAddress = default;
            return false;
        }

        targetAddress = baseAddress + positive;
        return true;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        if (right > ulong.MaxValue - left)
        {
            result = default;
            return false;
        }

        result = left + right;
        return true;
    }

    private static bool IsCanonicalSoname(string value) =>
        value.Length is > 0 and <= 255
        && value[0] != '.'
        && value.All(character =>
            character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '.' or '_' or '+' or '-');

    private static bool IsCanonicalTableIdentity(string? value) =>
        !string.IsNullOrEmpty(value)
        && value.Length <= 128
        && value[0] != '.'
        && value.All(character =>
            character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '.' or '_' or '-');

    private static bool IsCanonicalHex(string value, int minimumCharacters, int maximumCharacters, bool evenLength) =>
        value.Length >= minimumCharacters
        && value.Length <= maximumCharacters
        && (!evenLength || (value.Length & 1) == 0)
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void Error(
        DiagnosticBag diagnostics,
        DiagnosticCode code,
        string message,
        ulong? offset = null) =>
        diagnostics.Error(code, message, offset);

    private static SemanticExternalJumpTableProviderReadResult Failure(DiagnosticBag diagnostics) =>
        new(null, diagnostics.ToArray());


    private sealed record ParsedProviderSymbol(
        ElfSymbolTableKind Table,
        uint Index,
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
}
