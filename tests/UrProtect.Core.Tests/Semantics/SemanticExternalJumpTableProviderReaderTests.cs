using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Semantics;

public sealed class SemanticExternalJumpTableProviderReaderTests
{
    private static readonly string[] ExpectedProviderTargetNames = { "case_0", "case_1", "case_2", "case_3" };

    [Fact]
    public void ReaderDerivesTheTypedSps6ProviderTableFromPinnedBytes()
    {
        var fixture = ProviderElf.Create();

        var result = Read(fixture.Bytes);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var extension = Assert.IsType<SemanticExternalJumpTableExtension>(result.Extension);
        Assert.Equal(ProviderElf.Soname, extension.ProviderSoname);
        Assert.Equal(ProviderElf.BuildIdHex, extension.ProviderBuildIdHex);
        Assert.Equal(ProviderElf.Hash(fixture.Bytes), extension.ProviderSha256);
        Assert.Equal((ulong)fixture.Bytes.Length, extension.ProviderFileSize);
        Assert.Equal("external-provider-table", extension.TableIdentity.Value);
        Assert.Equal("urp_external_jump_table", extension.TableObject.Name);
        Assert.Equal(ElfSymbolTableKind.Dynamic, extension.TableObject.SymbolTable);
        Assert.Equal((uint)1, extension.TableObject.SymbolIndex);
        Assert.Equal((byte)1, extension.TableObject.Binding);
        Assert.Equal(ElfConstants.SttObject, extension.TableObject.Type);
        Assert.Equal((byte)0, extension.TableObject.Visibility);
        Assert.Equal((ushort)1, extension.TableObject.SectionIndex);
        Assert.Equal(ElfConstants.PfR, extension.TableObject.LoadSegmentFlags);
        Assert.Equal(new SemanticExternalProviderFileOffset(ProviderElf.TableFileOffset), extension.TableObject.Range.FileOffset);
        Assert.Equal(new SemanticExternalProviderAddress(ProviderElf.TableVirtualAddress), extension.TableObject.Range.VirtualAddress);
        Assert.Equal((ulong)(4 * sizeof(int)), extension.TableObject.Range.Size);
        Assert.Equal(fixture.Bytes.AsSpan(ProviderElf.TableFileOffset, 4 * sizeof(int)).ToArray(), extension.TableBytes);
        Assert.Equal(4, extension.Entries.Count);
        Assert.Equal(4, extension.TargetSymbols.Count);
        var proofInput = Assert.IsType<Aarch64ExternalJumpTableProviderFacts>(result.CreateConsumerProofInput());
        Assert.Equal(extension.TableIdentity.Value, proofInput.TableIdentity);
        Assert.Equal(extension.ProviderSoname, proofInput.ProviderSoname);
        Assert.Equal(extension.ProviderBuildIdHex, proofInput.ProviderBuildIdHex);
        Assert.Equal(extension.ProviderSha256, proofInput.ProviderSha256);
        Assert.Equal(extension.TableObject.Name, proofInput.TableObjectName);
        Assert.Equal((ulong)(4 * sizeof(int)), proofInput.TableObjectSize);
        Assert.Equal(ProviderElf.Hash(extension.TableBytes.ToArray()), proofInput.TableBytesSha256);
        Assert.Equal(ExpectedProviderTargetNames,
            proofInput.TargetSymbols.Select(target => target.SymbolName));

        for (var index = 0; index < 4; index++)
        {
            var target = extension.TargetSymbols[index];
            var entry = extension.Entries[index];
            Assert.Equal($"case_{index}", target.Name);
            Assert.Equal(ElfSymbolTableKind.Dynamic, target.SymbolTable);
            Assert.Equal((uint)(index + 2), target.SymbolIndex);
            Assert.Equal((byte)1, target.Binding);
            Assert.Equal(ElfConstants.SttFunc, target.Type);
            Assert.Equal((byte)2, target.Visibility);
            Assert.Equal((ushort)2, target.SectionIndex);
            Assert.Equal(ElfConstants.PfR | ElfConstants.PfX, target.LoadSegmentFlags);
            Assert.Equal(ProviderElf.TargetFileOffset(index), target.Range.FileOffset.Value);
            Assert.Equal(ProviderElf.TargetVirtualAddress(index), target.Range.VirtualAddress.Value);
            Assert.Equal((ulong)(2 * sizeof(uint)), target.Range.Size);
            Assert.Equal(index, entry.Index);
            Assert.Equal(target.SymbolTable, entry.TargetSymbolTable);
            Assert.Equal(target.SymbolIndex, entry.TargetSymbolIndex);
            Assert.Equal(ProviderElf.TargetVirtualAddress(index) - ProviderElf.TableVirtualAddress, (ulong)entry.SignedRelativeDisplacement);
        }
    }

    [Fact]
    public void ReaderDerivesProviderLocalStaticTargetSymbolRowsWhenDynamicSymbolsDoNotNameTargets()
    {
        var fixture = ProviderElf.Create(staticTargets: true);

        var result = Read(fixture.Bytes);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var extension = Assert.IsType<SemanticExternalJumpTableExtension>(result.Extension);
        for (var index = 0; index < extension.TargetSymbols.Count; index++)
        {
            var target = extension.TargetSymbols[index];
            Assert.Equal(ElfSymbolTableKind.Static, target.SymbolTable);
            Assert.Equal((uint)(index + 1), target.SymbolIndex);
            Assert.Equal((byte)0, target.Binding);
            Assert.Equal((byte)0, target.Visibility);
            Assert.Equal((ushort)3, target.SectionIndex);
            Assert.Equal($"case_{index}", target.Name);
        }
    }

    [Fact]
    public void ReaderSelectsTheSingleFullyValidCandidateAndKeepsCanonicalIdentityOpaque()
    {
        var fixture = ProviderElf.Create(additionalInvalidCandidate: true);

        var result = Read(fixture.Bytes);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var extension = Assert.IsType<SemanticExternalJumpTableExtension>(result.Extension);
        Assert.Equal(ProviderElf.TableIdentity, extension.TableIdentity);
        Assert.Equal("urp_external_jump_table", extension.TableObject.Name);
        Assert.Equal((uint)1, extension.TableObject.SymbolIndex);
    }

    [Fact]
    public void ReaderRejectsMultipleFullyValidProviderTableCandidates()
    {
        var fixture = ProviderElf.Create(duplicateTable: true);

        var result = Read(fixture.Bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("More than one provider dynamic object", StringComparison.Ordinal));
    }

    [Fact]
    public void ReaderHashesAndParsesOnePrivateSnapshotWhenCallerMemoryChangesOnASecondObservation()
    {
        var fixture = ProviderElf.Create();
        var expectedSha256 = ProviderElf.Hash(fixture.Bytes);
        using var callerMemory = new MutatingOnSecondSpanMemoryManager(fixture.Bytes);

        var result = SemanticExternalJumpTableProviderReader.Read(
            callerMemory.GetMemory(),
            ProviderElf.Soname,
            ProviderElf.BuildIdHex,
            expectedSha256,
            ProviderElf.TableIdentity);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var extension = Assert.IsType<SemanticExternalJumpTableExtension>(result.Extension);
        Assert.Equal(1, callerMemory.GetSpanCallCount);
        Assert.Equal((byte)0x7F, fixture.Bytes[0]);
        Assert.Equal(expectedSha256, extension.ProviderSha256);
        Assert.Equal((ulong)fixture.Bytes.Length, extension.ProviderFileSize);
        Assert.Equal(ProviderElf.TableIdentity, extension.TableIdentity);
        Assert.Equal(fixture.Bytes.AsSpan(ProviderElf.TableFileOffset, 4 * sizeof(int)).ToArray(), extension.TableBytes);
        Assert.Equal(
            Enumerable.Range(0, 4).Select(index => (uint)(index + 2)),
            extension.Entries.Select(entry => entry.TargetSymbolIndex));
        Assert.Equal(
            Enumerable.Range(0, 4).Select(ProviderElf.TargetVirtualAddress),
            extension.TargetSymbols.Select(symbol => symbol.Range.VirtualAddress.Value));
    }

    [Fact]
    public void ReaderRejectsProviderBytesBeforeParsingWhenSha256PinDoesNotMatch()
    {
        var fixture = ProviderElf.Create();
        var mutated = fixture.Bytes.ToArray();
        mutated[0] ^= 0x01; // Invalid ELF magic would be reported if parsing happened before identity verification.

        var result = SemanticExternalJumpTableProviderReader.Read(
            mutated,
            ProviderElf.Soname,
            ProviderElf.BuildIdHex,
            ProviderElf.Hash(fixture.Bytes),
            ProviderElf.TableIdentity);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.OutputIdentityMismatch);
        Assert.Null(result.CreateConsumerProofInput());
        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InvalidMagic);
    }

    [Theory]
    [InlineData("soname")]
    [InlineData("build-id")]
    public void ReaderRejectsPinnedIdentityMismatch(string identity)
    {
        var fixture = ProviderElf.Create();
        var result = SemanticExternalJumpTableProviderReader.Read(
            fixture.Bytes,
            identity == "soname" ? "libwrong-provider.so" : ProviderElf.Soname,
            identity == "build-id" ? "aabbccddeeff0011" : ProviderElf.BuildIdHex,
            ProviderElf.Hash(fixture.Bytes),
            ProviderElf.TableIdentity);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.OutputIdentityMismatch);
    }

    [Fact]
    public void ReaderRejectsProviderInputAboveItsRawByteLimitBeforeParsing()
    {
        using var oversizedMemory = new MutatingOnSecondSpanMemoryManager(
            new byte[SemanticExternalJumpTableProviderReader.MaximumProviderElfBytes + 1]);

        var result = SemanticExternalJumpTableProviderReader.Read(
            oversizedMemory.GetMemory(),
            ProviderElf.Soname,
            ProviderElf.BuildIdHex,
            new string('0', 64),
            ProviderElf.TableIdentity);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
        Assert.Equal(0, oversizedMemory.GetSpanCallCount);
    }

    [Theory]
    [InlineData("needed")]
    [InlineData("runpath")]
    [InlineData("config")]
    [InlineData("audit")]
    [InlineData("dep-audit")]
    [InlineData("auxiliary")]
    [InlineData("filter")]
    [InlineData("symbolic")]
    [InlineData("rel")]
    [InlineData("relsz")]
    [InlineData("relent")]
    [InlineData("rel-count")]
    [InlineData("rela")]
    [InlineData("relasz")]
    [InlineData("relaent")]
    [InlineData("rela-count")]
    [InlineData("jmprel")]
    [InlineData("pltrelsz")]
    [InlineData("pltrel")]
    [InlineData("relr")]
    [InlineData("relrsz")]
    [InlineData("relrent")]
    [InlineData("android-rel")]
    [InlineData("android-relsz")]
    [InlineData("android-rela")]
    [InlineData("android-relasz")]
    [InlineData("android-relr")]
    [InlineData("android-relrsz")]
    [InlineData("android-relrent")]
    [InlineData("android-relrcount")]
    [InlineData("textrel")]
    [InlineData("versym")]
    [InlineData("verneed")]
    [InlineData("verneed-count")]
    [InlineData("verdef")]
    [InlineData("verdef-count")]
    [InlineData("duplicate-soname")]
    public void ReaderRejectsProviderDynamicMetadataOutsideTheClosedContract(string tag)
    {
        var fixture = ProviderElf.Create();
        ProviderElf.WriteDynamicEntry(
            fixture.Bytes,
            ProviderElf.DynamicEntryOffset(6),
            tag switch
            {
                "needed" => ElfConstants.DtNeeded,
                "runpath" => ElfConstants.DtRunPath,
                "config" => ElfConstants.DtConfig,
                "audit" => ElfConstants.DtAudit,
                "dep-audit" => ElfConstants.DtDepAudit,
                "auxiliary" => ElfConstants.DtAuxiliary,
                "filter" => ElfConstants.DtFilter,
                "symbolic" => ElfConstants.DtSymbolic,
                "rel" => ElfConstants.DtRel,
                "relsz" => ElfConstants.DtRelSz,
                "relent" => ElfConstants.DtRelEnt,
                "rel-count" => ElfConstants.DtRelCount,
                "rela" => ElfConstants.DtRela,
                "relasz" => ElfConstants.DtRelaSz,
                "relaent" => ElfConstants.DtRelaEnt,
                "rela-count" => ElfConstants.DtRelaCount,
                "jmprel" => ElfConstants.DtJmpRel,
                "pltrelsz" => ElfConstants.DtPltRelSz,
                "pltrel" => ElfConstants.DtPltRel,
                "relr" => ElfConstants.DtRelr,
                "relrsz" => ElfConstants.DtRelrSz,
                "relrent" => ElfConstants.DtRelrEnt,
                "android-rel" => ElfConstants.DtAndroidRel,
                "android-relsz" => ElfConstants.DtAndroidRelsz,
                "android-rela" => ElfConstants.DtAndroidRela,
                "android-relasz" => ElfConstants.DtAndroidRelasz,
                "android-relr" => ElfConstants.DtAndroidRelr,
                "android-relrsz" => ElfConstants.DtAndroidRelrsz,
                "android-relrent" => ElfConstants.DtAndroidRelrent,
                "android-relrcount" => ElfConstants.DtAndroidRelrCount,
                "textrel" => ElfConstants.DtTextRel,
                "versym" => ElfConstants.DtVersym,
                "verneed" => ElfConstants.DtVerneed,
                "verneed-count" => ElfConstants.DtVerneedNum,
                "verdef" => ElfConstants.DtVerdef,
                "verdef-count" => ElfConstants.DtVerdefNum,
                _ => ElfConstants.DtSoname,
            },
            1);

        var result = Read(fixture.Bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        if (tag == "duplicate-soname")
        {
            Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.DynamicTableMalformed);
        }
        else
        {
            Assert.Contains(result.Diagnostics, diagnostic =>
                diagnostic.Code == DiagnosticCode.UnsupportedDynamicTag
                && diagnostic.Message.StartsWith(
                    "The bounded ELF parse policy rejects dynamic tag",
                    StringComparison.Ordinal));
            Assert.DoesNotContain(result.Diagnostics, diagnostic =>
                diagnostic.Code is DiagnosticCode.DynamicPointerUnmapped
                    or DiagnosticCode.RelocationTableMalformed
                    or DiagnosticCode.SymbolVersionTableMalformed
                    or DiagnosticCode.VersionNeedTableMalformed
                    or DiagnosticCode.VersionDefinitionTableMalformed);
        }
    }

    [Fact]
    public void ReaderRejectsTextRelocationFlagBeforeExpandedMetadataTraversal()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        ProviderElf.WriteDynamicEntry(
            bytes,
            ProviderElf.DynamicEntryOffset(6),
            ElfConstants.DtFlags,
            ElfConstants.DfTextRel);

        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.UnsupportedDynamicTag
            && diagnostic.Message.Contains("dynamic tag/value", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.Code is
            DiagnosticCode.DynamicPointerUnmapped or DiagnosticCode.RelocationTableMalformed);
    }

    [Fact]
    public void ReaderRejectsProgramHeaderCountAtParserBoundaryBeforeHeaderTraversal()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        Array.Resize(ref bytes, 0x3000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(ElfHeaderOffsets.ProgramHeaderCount), 129);

        AssertParserWorkLimit(Read(bytes));
    }

    [Fact]
    public void ReaderRejectsSectionHeaderCountAtParserBoundaryBeforeHeaderTraversal()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        Array.Resize(ref bytes, 0x600 + (4097 * ElfConstants.SectionHeaderSize64));
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(ElfHeaderOffsets.SectionHeaderOffset), 0x600);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(ElfHeaderOffsets.SectionHeaderCount), 4097);

        AssertParserWorkLimit(Read(bytes));
    }

    [Fact]
    public void ReaderRejectsDynamicEntryCountAtParserBoundaryBeforeDynamicTraversal()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        var dynamicTableSize = checked((ulong)(4097 * ElfConstants.DynamicEntrySize64));
        Array.Resize(ref bytes, checked((int)(ProviderElf.DynamicOffset + dynamicTableSize)));
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ProviderElf.DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize),
            dynamicTableSize);
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ProviderElf.DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize),
            dynamicTableSize);

        AssertParserWorkLimit(Read(bytes));
    }

    [Fact]
    public void ReaderRejectsDynamicSymbolCountAtHashBoundaryBeforeSymbolAllocation()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(ProviderElf.HashOffset + sizeof(uint)), 2049);

        AssertParserWorkLimit(Read(bytes));
    }

    [Fact]
    public void ReaderAcceptsProviderWithGnuHashSymbolCount()
    {
        var fixture = ProviderElf.Create(gnuHash: true);

        var result = Read(fixture.Bytes);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.Equal(ProviderElf.TableSymbolName, result.Extension!.TableObject.Name);
        Assert.Equal(4, result.Extension.TargetSymbols.Count);
    }

    [Fact]
    public void ReaderRejectsGnuHashBucketCountBeforeBucketOrChainTraversal()
    {
        var bytes = ProviderElf.Create(gnuHash: true).Bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(ProviderElf.HashOffset),
            checked((uint)(SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols + 1)));

        var result = Read(bytes);

        AssertParserWorkLimit(result);
        Assert.Contains("before bucket or chain traversal", result.Diagnostics[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReaderRejectsUnterminatedGnuHashChainAtItsBoundedTraversalLimit()
    {
        var bytes = ProviderElf.CreateUnterminatedGnuHashChain();

        var result = Read(bytes);

        AssertParserWorkLimit(result);
        Assert.Contains("GNU hash chain exceeds dynamic-symbol limit", result.Diagnostics[0].Message, StringComparison.Ordinal);
        Assert.Contains("before reading another chain entry", result.Diagnostics[0].Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReaderRejectsDuplicateDynamicHeadersBeforeExpandingEitherTable(bool malformedSecondTable)
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        ProviderElf.AddSecondDynamicHeader(bytes, malformedSecondTable);

        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticCode.InvalidProgramHeader, diagnostic.Code);
        Assert.Contains("exactly one PT_DYNAMIC and no PT_INTERP", diagnostic.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Diagnostics, item => item.Code is
            DiagnosticCode.UnsupportedDynamicTag
            or DiagnosticCode.DynamicTableMalformed
            or DiagnosticCode.DynamicTableUnterminated
            or DiagnosticCode.DynamicPointerUnmapped
            or DiagnosticCode.SymbolTableMalformed);
    }

    [Fact]
    public void ReaderRejectsMissingDynamicHeaderBeforeExpandingNotesOrDynamicMetadata()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(ProviderElf.DynamicProgramHeaderOffset),
            ElfConstants.PtNull);
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(ProviderElf.NoteOffset),
            uint.MaxValue);

        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticCode.InvalidProgramHeader, diagnostic.Code);
        Assert.Contains("exactly one PT_DYNAMIC and no PT_INTERP", diagnostic.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Diagnostics, item => item.Code is
            DiagnosticCode.NoteMalformed
            or DiagnosticCode.DynamicTableMalformed
            or DiagnosticCode.DynamicTableUnterminated
            or DiagnosticCode.DynamicPointerUnmapped
            or DiagnosticCode.UnsupportedDynamicTag
            or DiagnosticCode.RelocationTableMalformed
            or DiagnosticCode.SymbolTableMalformed);
    }

    [Fact]
    public void OrdinaryParserRetainsFirstDynamicTableSelectionOutsideProviderProfile()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        ProviderElf.AddSecondDynamicHeader(bytes, malformedTable: true);

        var result = ElfParser.Parse(bytes);

        Assert.NotNull(result.File);
        Assert.Equal(8, result.File.DynamicEntries.Count);
        Assert.DoesNotContain(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.InvalidProgramHeader
            && diagnostic.Message.Contains("exactly one PT_DYNAMIC", StringComparison.Ordinal));
    }

    [Fact]
    public void OrdinaryParserRetainsZeroDynamicHeaderBehaviorOutsideProviderProfile()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(ProviderElf.DynamicProgramHeaderOffset),
            ElfConstants.PtNull);

        var result = ElfParser.Parse(bytes);

        Assert.NotNull(result.File);
        Assert.Empty(result.File.DynamicEntries);
        Assert.DoesNotContain(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.InvalidProgramHeader
            && diagnostic.Message.Contains("exactly one PT_DYNAMIC and no PT_INTERP", StringComparison.Ordinal));
    }

    [Fact]
    public void OrdinaryParserRetainsOptionalSectionTableWarningOutsideProviderProfile()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ElfHeaderOffsets.SectionHeaderOffset),
            0x8C0);
        BinaryPrimitives.WriteUInt16LittleEndian(
            bytes.AsSpan(ElfHeaderOffsets.SectionHeaderCount),
            2);

        var result = ElfParser.Parse(bytes);

        Assert.NotNull(result.File);
        Assert.Empty(result.File.SectionHeaders);
        var diagnostic = Assert.Single(result.Diagnostics, item =>
            item.Code == DiagnosticCode.TableOutOfBounds);
        Assert.Equal(DiagnosticSeverity.Warning, diagnostic.Severity);
    }

    [Fact]
    public void ReaderRejectsInterpreterBeforeExpandingDynamicMetadata()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        ProviderElf.AddInterpreterHeader(bytes);

        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticCode.InvalidProgramHeader, diagnostic.Code);
        Assert.Contains("PT_INTERP", diagnostic.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Diagnostics, item => item.Code == DiagnosticCode.DynamicPointerUnmapped);
    }

    [Fact]
    public void ReaderRejectsOutOfBoundsDeclaredSectionTableAsErrorBeforeDynamicExpansion()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ElfHeaderOffsets.SectionHeaderOffset),
            0x8C0);
        BinaryPrimitives.WriteUInt16LittleEndian(
            bytes.AsSpan(ElfHeaderOffsets.SectionHeaderCount),
            2);

        // Read() recomputes the SHA-256 pin from these mutated bytes; the regression
        // is independent of stale/mismatched identity metadata.
        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticCode.TableOutOfBounds, diagnostic.Code);
        Assert.Contains("complete declared section-header table", diagnostic.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Diagnostics, item => item.Code is
            DiagnosticCode.DynamicPointerUnmapped or DiagnosticCode.SymbolTableMalformed);
    }

    [Fact]
    public void ReaderRejectsTlsTemplateWorkBeforeAllocatingTemplateBytes()
    {
        var bytes = ProviderElf.CreateOversizedTlsTemplate();

        var result = Read(bytes);

        AssertParserWorkLimit(result);
        Assert.Contains("PT_TLS template allocation", result.Diagnostics[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReaderRejectsOverLimitDynamicFunctionNameBeforeUtf8Decoding()
    {
        var bytes = ProviderElf.CreateOverlongDynamicFunctionName();

        var result = Read(bytes);

        AssertParserWorkLimit(result);
        Assert.Contains("4096-byte name limit", result.Diagnostics[0].Message, StringComparison.Ordinal);
        Assert.Contains("before UTF-8 decoding", result.Diagnostics[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReaderRejectsNoteRecordCountAboveCapBeforeAllocatingOverflowRecord()
    {
        var bytes = ProviderElf.CreateExcessNoteRecords(4097);

        var result = Read(bytes);

        AssertParserWorkLimit(result);
        Assert.Contains("note record count exceeds limit 4096 before allocation", result.Diagnostics[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReaderRejectsDynamicStringTableSizeBeforeStringTableTraversal()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        ProviderElf.WriteDynamicEntry(
            bytes,
            ProviderElf.DynamicEntryOffset(2),
            ElfConstants.DtStrSz,
            256UL * 1024 + 1);

        AssertParserWorkLimit(Read(bytes));
    }

    [Fact]
    public void ReaderRejectsAggregateParserWorkBeforeTraversingAnExpandedNoteRange()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        Array.Resize(ref bytes, SemanticExternalJumpTableProviderReader.MaximumProviderElfBytes);
        var originalProgramHeaders = bytes.AsSpan(ElfConstants.HeaderSize64, 4 * ElfConstants.ProgramHeaderSize64).ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(ElfHeaderOffsets.ProgramHeaderOffset), 0x1000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(ElfHeaderOffsets.ProgramHeaderCount), 128);
        originalProgramHeaders.CopyTo(bytes.AsSpan(0x1000));
        var noteBytes = checked((ulong)(bytes.Length - ProviderElf.NoteOffset));
        var relocatedNoteHeaderOffset = 0x1000
            + ProviderElf.NoteProgramHeaderOffset
            - ElfConstants.HeaderSize64;
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(relocatedNoteHeaderOffset + ElfProgramHeaderOffsets.FileSize),
            noteBytes);
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(relocatedNoteHeaderOffset + ElfProgramHeaderOffsets.MemorySize),
            noteBytes);

        AssertParserWorkLimit(Read(bytes));
    }

    [Fact]
    public void ReaderRejectsAggregateStaticSymbolCountBeforeStaticSymbolTraversal()
    {
        var bytes = ProviderElf.Create(staticTargets: true).Bytes.ToArray();
        var symbolTableSize = checked((ulong)(2049 * ElfConstants.SymbolEntrySize64));
        Array.Resize(ref bytes, checked((int)(0x540 + symbolTableSize)));
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ProviderElf.StaticSymbolTableHeaderOffset + 32),
            symbolTableSize);

        AssertParserWorkLimit(Read(bytes));
    }

    [Fact]
    public void ReaderRejectsDynamicRelocationTableTagsBeforeDeclaredRelocationTraversal()
    {
        var bytes = ProviderElf.Create().Bytes.ToArray();
        Array.Resize(
            ref bytes,
            Math.Max(bytes.Length, ProviderElf.DynamicOffset + (9 * ElfConstants.DynamicEntrySize64)));
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ProviderElf.DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize),
            9 * ElfConstants.DynamicEntrySize64);
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ProviderElf.DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize),
            9 * ElfConstants.DynamicEntrySize64);
        ProviderElf.WriteDynamicEntry(bytes, ProviderElf.DynamicEntryOffset(6), ElfConstants.DtRela, ulong.MaxValue);
        ProviderElf.WriteDynamicEntry(bytes, ProviderElf.DynamicEntryOffset(7), ElfConstants.DtRelaSz, ulong.MaxValue);
        ProviderElf.WriteDynamicEntry(bytes, ProviderElf.DynamicEntryOffset(8), ElfConstants.DtNull, 0);

        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedDynamicTag);
        Assert.DoesNotContain(result.Diagnostics, diagnostic =>
            diagnostic.Code is DiagnosticCode.DynamicPointerUnmapped or DiagnosticCode.RelocationTableMalformed);
    }

    [Fact]
    public void ReaderRejectsSectionRelocationRowCountAtParserBoundaryBeforeRelocationTraversal()
    {
        var bytes = ProviderElf.Create(staticTargets: true).Bytes.ToArray();
        ProviderElf.AddUnsupportedSectionRecord(bytes);
        var relocationSectionOffset = ProviderElf.SectionRelocationHeaderOffset;
        var relocationTableSize = checked((ulong)(4097 * ElfConstants.RelaEntrySize64));
        Array.Resize(ref bytes, checked((int)(0x1000 + relocationTableSize)));
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(relocationSectionOffset + 24), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(relocationSectionOffset + 32), relocationTableSize);

        AssertParserWorkLimit(Read(bytes));
    }

    [Theory]
    [InlineData(ElfConstants.ShtRel)]
    [InlineData(ElfConstants.ShtRela)]
    [InlineData(ElfConstants.ShtRelr)]
    [InlineData(ElfConstants.ShtAndroidRel)]
    [InlineData(ElfConstants.ShtAndroidRela)]
    [InlineData(ElfConstants.ShtAndroidRelr)]
    [InlineData(ElfConstants.ShtGnuVerdef)]
    [InlineData(ElfConstants.ShtGnuVerneed)]
    [InlineData(ElfConstants.ShtGnuVersym)]
    public void ReaderRejectsUnsupportedProviderSectionMetadataTypes(uint sectionType)
    {
        var bytes = ProviderElf.Create(staticTargets: true).Bytes.ToArray();
        ProviderElf.AddUnsupportedSectionRecord(bytes, sectionType);

        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.DynamicTableMalformed
            && diagnostic.Message.Contains("section-owned", StringComparison.Ordinal));
    }

    [Fact]
    public void ReaderRejectsAnyParsedSectionOwnedRelocationFact()
    {
        var bytes = ProviderElf.Create(staticTargets: true).Bytes.ToArray();
        ProviderElf.AddUnsupportedSectionRecord(bytes);

        var result = Read(bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.DynamicTableMalformed
            && diagnostic.Message.Contains("section-owned REL/RELA/RELR", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("wrong-type")]
    [InlineData("wrong-size")]
    [InlineData("duplicate-name")]
    public void ReaderRejectsMalformedProviderTableSymbol(string mutation)
    {
        var fixture = ProviderElf.Create();
        switch (mutation)
        {
            case "wrong-type":
                fixture.Bytes[ProviderElf.DynamicSymbolOffset(1) + 4] = 0x12; // global STT_FUNC
                break;
            case "wrong-size":
                BinaryPrimitives.WriteUInt64LittleEndian(
                    fixture.Bytes.AsSpan(ProviderElf.DynamicSymbolOffset(1) + 16),
                    12);
                break;
            case "duplicate-name":
                BinaryPrimitives.WriteUInt32LittleEndian(
                    fixture.Bytes.AsSpan(ProviderElf.DynamicSymbolOffset(2)),
                    ProviderElf.TableSymbolNameOffset);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var result = Read(fixture.Bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code is
            DiagnosticCode.SymbolTableMalformed or DiagnosticCode.SemanticPlanSnapshotMalformed);
    }

    [Theory]
    [InlineData("outside-file-backed-load")]
    [InlineData("writable-load")]
    public void ReaderRejectsProviderTableOutsideItsExactReadOnlyRange(string mutation)
    {
        var fixture = ProviderElf.Create();
        if (mutation == "outside-file-backed-load")
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                fixture.Bytes.AsSpan(ProviderElf.DynamicSymbolOffset(1) + 8),
                0x600);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                fixture.Bytes.AsSpan(ProviderElf.FirstLoadProgramHeaderOffset + 4),
                ElfConstants.PfR | ElfConstants.PfW);
        }

        var result = Read(fixture.Bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code is
            DiagnosticCode.AddressUnmapped or DiagnosticCode.InvalidSegment);
    }

    [Theory]
    [InlineData("target-not-a-symbol")]
    [InlineData("target-in-writable-segment")]
    public void ReaderRejectsMalformedProviderTargetBoundary(string mutation)
    {
        var fixture = ProviderElf.Create();
        if (mutation == "target-not-a-symbol")
        {
            var unrelatedExecutableAddress = 0x1844UL;
            var displacement = checked((int)(unrelatedExecutableAddress - ProviderElf.TableVirtualAddress));
            BinaryPrimitives.WriteInt32LittleEndian(
                fixture.Bytes.AsSpan(ProviderElf.TableFileOffset),
                displacement);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                fixture.Bytes.AsSpan(ProviderElf.ExecutableLoadProgramHeaderOffset + 4),
                ElfConstants.PfR | ElfConstants.PfW | ElfConstants.PfX);
        }

        var result = Read(fixture.Bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code is
            DiagnosticCode.SymbolTableMalformed or DiagnosticCode.InvalidSegment);
    }

    [Fact]
    public void ReaderRejectsDuplicateProviderTableTargets()
    {
        var fixture = ProviderElf.Create();
        BinaryPrimitives.WriteInt32LittleEndian(
            fixture.Bytes.AsSpan(ProviderElf.TableFileOffset + sizeof(int)),
            BinaryPrimitives.ReadInt32LittleEndian(fixture.Bytes.AsSpan(ProviderElf.TableFileOffset)));

        var result = Read(fixture.Bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("duplicate target addresses", StringComparison.Ordinal));
    }

    [Fact]
    public void ReaderRejectsTableEntryThatPointsInsideButNotAtAFunctionSymbol()
    {
        var fixture = ProviderElf.Create();
        var displacement = checked((int)(ProviderElf.TargetVirtualAddress(0) + sizeof(uint) - ProviderElf.TableVirtualAddress));
        BinaryPrimitives.WriteInt32LittleEndian(fixture.Bytes.AsSpan(ProviderElf.TableFileOffset), displacement);

        var result = Read(fixture.Bytes);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SymbolTableMalformed
            && diagnostic.Message.Contains("does not resolve", StringComparison.Ordinal));
    }

    [Fact]
    public void ReaderRejectsPathAsCanonicalTableIdentity()
    {
        var fixture = ProviderElf.Create();
        var result = SemanticExternalJumpTableProviderReader.Read(
            fixture.Bytes,
            ProviderElf.Soname,
            ProviderElf.BuildIdHex,
            ProviderElf.Hash(fixture.Bytes),
            new SemanticExternalProviderTableIdentity("/operator/provider.so"));

        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed);
    }

    private static SemanticExternalJumpTableProviderReadResult Read(byte[] bytes) =>
        SemanticExternalJumpTableProviderReader.Read(
            bytes,
            ProviderElf.Soname,
            ProviderElf.BuildIdHex,
            ProviderElf.Hash(bytes),
            ProviderElf.TableIdentity);

    private static string Describe(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(Environment.NewLine, diagnostics.Select(diagnostic => diagnostic.ToString()));

    private static void AssertParserWorkLimit(SemanticExternalJumpTableProviderReadResult result)
    {
        Assert.False(result.IsSuccess);
        Assert.Null(result.Extension);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticCode.ElfParserWorkLimitExceeded, diagnostic.Code);
        Assert.Contains("before", diagnostic.Message, StringComparison.Ordinal);
    }

    private sealed class MutatingOnSecondSpanMemoryManager : MemoryManager<byte>
    {
        private readonly byte[] _bytes;

        public MutatingOnSecondSpanMemoryManager(byte[] bytes)
        {
            _bytes = bytes;
        }

        public int GetSpanCallCount { get; private set; }

        public Memory<byte> GetMemory() => CreateMemory(_bytes.Length);

        public override Span<byte> GetSpan()
        {
            GetSpanCallCount++;
            if (GetSpanCallCount == 2 && _bytes.Length > 0)
            {
                _bytes[0] = 0;
            }

            return _bytes;
        }

        public override MemoryHandle Pin(int elementIndex = 0) =>
            throw new NotSupportedException("The test memory manager does not support pinning.");

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
        }
    }

    internal static class ProviderElf
    {
        public const string Soname = "libexternal-table.so";
        public const string BuildIdHex = "1122334455667788";
        public const int NoteOffset = 0x180;
        public const int DynamicOffset = 0x200;
        public const int StringTableOffset = 0x280;
        public const int HashOffset = 0x320;
        public const int DynamicSymbolsOffset = 0x380;
        private const int RequiredEntryCount = 4;
        public const int SectionRelocationHeaderOffset = 0x700;
        public const int StaticSymbolTableHeaderOffset = 0x780;
        public const int TableFileOffset = 0x440;
        public const ulong TableVirtualAddress = 0x440;
        public const int FirstLoadProgramHeaderOffset = ElfConstants.HeaderSize64;
        public const int ExecutableLoadProgramHeaderOffset = FirstLoadProgramHeaderOffset + ElfConstants.ProgramHeaderSize64;
        public const int DynamicProgramHeaderOffset = ExecutableLoadProgramHeaderOffset + ElfConstants.ProgramHeaderSize64;
        public const int NoteProgramHeaderOffset = DynamicProgramHeaderOffset + ElfConstants.ProgramHeaderSize64;
        public const string TableSymbolName = "urp_external_jump_table";
        public static SemanticExternalProviderTableIdentity TableIdentity { get; } = new("external-provider-table");
        public static uint TableSymbolNameOffset { get; private set; }

        public sealed record Fixture(byte[] Bytes);

        public static Fixture Create(
            bool staticTargets = false,
            bool duplicateTable = false,
            bool additionalInvalidCandidate = false,
            bool gnuHash = false)
        {
            const int fileSize = 0x900;
            const int dynamicEntryCount = 8;
            const int dynamicSymbolCount = 7;
            const int dynamicSegmentSize = dynamicEntryCount * ElfConstants.DynamicEntrySize64;
            var bytes = new byte[fileSize];
            var stringTable = new List<byte> { 0 };
            var sonameOffset = AddString(stringTable, Soname);
            TableSymbolNameOffset = AddString(stringTable, TableSymbolName);
            var targetNameOffsets = Enumerable.Range(0, 4)
                .Select(index => AddString(stringTable, $"case_{index}"))
                .ToArray();

            var span = bytes.AsSpan();
            span[0] = 0x7F;
            span[1] = (byte)'E';
            span[2] = (byte)'L';
            span[3] = (byte)'F';
            span[4] = ElfConstants.Class64;
            span[5] = ElfConstants.LittleEndian;
            span[6] = ElfConstants.IdentificationVersionCurrent;
            WriteUInt16(span, 16, ElfConstants.TypeDyn);
            WriteUInt16(span, 18, ElfConstants.MachineAarch64);
            WriteUInt32(span, 20, ElfConstants.HeaderVersionCurrent);
            WriteUInt64(span, 24, 0);
            WriteUInt64(span, 32, ElfConstants.HeaderSize64);
            WriteUInt64(span, 40, 0);
            WriteUInt16(span, 52, ElfConstants.HeaderSize64);
            WriteUInt16(span, 54, ElfConstants.ProgramHeaderSize64);
            WriteUInt16(span, 56, 4);
            WriteUInt16(span, 58, ElfConstants.SectionHeaderSize64);
            WriteUInt16(span, 60, 0);
            WriteUInt16(span, 62, 0);

            WriteProgramHeader(span, FirstLoadProgramHeaderOffset, ElfConstants.PtLoad, ElfConstants.PfR,
                0, 0, 0x500, 0x500, 0x1000);
            WriteProgramHeader(span, ExecutableLoadProgramHeaderOffset, ElfConstants.PtLoad,
                ElfConstants.PfR | ElfConstants.PfX, 0x800, 0x1800, 0x80, 0x80, 0x1000);
            WriteProgramHeader(span, DynamicProgramHeaderOffset, ElfConstants.PtDynamic, ElfConstants.PfR,
                DynamicOffset, DynamicOffset, (ulong)dynamicSegmentSize, (ulong)dynamicSegmentSize, 8);
            WriteProgramHeader(span, NoteProgramHeaderOffset, ElfConstants.PtNote, ElfConstants.PfR,
                NoteOffset, NoteOffset, 24, 24, 4);

            WriteUInt32(span, NoteOffset, 4);
            WriteUInt32(span, NoteOffset + 4, 8);
            WriteUInt32(span, NoteOffset + 8, 3);
            "GNU\0"u8.CopyTo(span[(NoteOffset + 12)..]);
            Convert.FromHexString(BuildIdHex).CopyTo(span[(NoteOffset + 16)..]);

            WriteDynamicEntry(
                span,
                DynamicEntryOffset(0),
                gnuHash ? ElfConstants.DtGnuHash : ElfConstants.DtHash,
                HashOffset);
            WriteDynamicEntry(span, DynamicEntryOffset(1), ElfConstants.DtStrTab, StringTableOffset);
            WriteDynamicEntry(span, DynamicEntryOffset(2), ElfConstants.DtStrSz, checked((ulong)stringTable.Count));
            WriteDynamicEntry(span, DynamicEntryOffset(3), ElfConstants.DtSymTab, DynamicSymbolsOffset);
            WriteDynamicEntry(span, DynamicEntryOffset(4), ElfConstants.DtSymEnt, ElfConstants.SymbolEntrySize64);
            WriteDynamicEntry(span, DynamicEntryOffset(5), ElfConstants.DtSoname, sonameOffset);
            WriteDynamicEntry(span, DynamicEntryOffset(6), ElfConstants.DtFlags1, ElfConstants.Df1Pie);
            WriteDynamicEntry(span, DynamicEntryOffset(7), ElfConstants.DtNull, 0);
            stringTable.ToArray().CopyTo(span[StringTableOffset..]);

            if (gnuHash)
            {
                WriteGnuHashTable(span, HashOffset, dynamicSymbolCount);
            }
            else
            {
                WriteUInt32(span, HashOffset, 1); // one SysV hash bucket
                WriteUInt32(span, HashOffset + 4, dynamicSymbolCount);
                WriteUInt32(span, HashOffset + 8, 1);
                for (var index = 0; index < dynamicSymbolCount; index++)
                {
                    WriteUInt32(span, HashOffset + 12 + (index * sizeof(uint)), 0);
                }
            }

            WriteSymbol(span, 1, TableSymbolNameOffset, info: 0x11, other: 0, sectionIndex: 1,
                TableVirtualAddress, 4 * sizeof(int));
            if (duplicateTable || additionalInvalidCandidate)
            {
                WriteSymbol(span, 6, TableSymbolNameOffset, info: 0x11, other: 0, sectionIndex: 1,
                    duplicateTable ? TableVirtualAddress : 0x460, 4 * sizeof(int));
            }

            for (var index = 0; index < 4; index++)
            {
                if (staticTargets)
                {
                    WriteSymbol(span, index + 2, 0, info: 0, other: 0, sectionIndex: 0, value: 0, size: 0);
                }
                else
                {
                    WriteSymbol(span, index + 2, targetNameOffsets[index], info: 0x12, other: 2, sectionIndex: 2,
                        TargetVirtualAddress(index), 2 * sizeof(uint));
                }

                var displacement = checked((int)(TargetVirtualAddress(index) - TableVirtualAddress));
                BinaryPrimitives.WriteInt32LittleEndian(
                    span.Slice(TableFileOffset + (index * sizeof(int)), sizeof(int)),
                    displacement);
                BinaryPrimitives.WriteUInt32LittleEndian(
                    span.Slice(0x800 + (index * 8), sizeof(uint)),
                    0xD503201Fu);
                BinaryPrimitives.WriteUInt32LittleEndian(
                    span.Slice(0x804 + (index * 8), sizeof(uint)),
                    0xD65F03C0u);
            }

            if (staticTargets)
            {
                WriteStaticTargetSymbols(span);
            }

            return new Fixture(bytes);
        }

        public static void AddSecondDynamicHeader(byte[] bytes, bool malformedTable)
        {
            var headerOffset = ElfConstants.HeaderSize64 + (4 * ElfConstants.ProgramHeaderSize64);
            var secondTableOffset = 0x8C0UL;
            var secondTableSize = malformedTable ? 15UL : 2 * ElfConstants.DynamicEntrySize64;
            WriteUInt16(bytes, ElfHeaderOffsets.ProgramHeaderCount, 5);
            WriteProgramHeader(
                bytes,
                headerOffset,
                ElfConstants.PtDynamic,
                ElfConstants.PfR,
                secondTableOffset,
                secondTableOffset,
                secondTableSize,
                secondTableSize,
                8);
            if (!malformedTable)
            {
                WriteDynamicEntry(bytes, checked((int)secondTableOffset), ElfConstants.DtNeeded, 0);
                WriteDynamicEntry(bytes, checked((int)secondTableOffset + ElfConstants.DynamicEntrySize64), ElfConstants.DtNull, 0);
            }
        }

        public static void AddInterpreterHeader(byte[] bytes)
        {
            var headerOffset = ElfConstants.HeaderSize64 + (4 * ElfConstants.ProgramHeaderSize64);
            WriteUInt16(bytes, ElfHeaderOffsets.ProgramHeaderCount, 5);
            WriteProgramHeader(
                bytes,
                headerOffset,
                ElfConstants.PtInterp,
                ElfConstants.PfR,
                0x8C0,
                0x8C0,
                1,
                1,
                1);
        }

        public static byte[] CreateUnterminatedGnuHashChain()
        {
            var bytes = Create(gnuHash: true).Bytes;
            Array.Resize(ref bytes, 0x6000);
            WriteDynamicEntry(bytes, DynamicEntryOffset(0), ElfConstants.DtGnuHash, 0x2000);
            WriteUInt64(
                bytes,
                ExecutableLoadProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize,
                0x5800);
            WriteUInt64(
                bytes,
                ExecutableLoadProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize,
                0x5800);
            WriteUInt32(bytes, 0x1000, 1);
            WriteUInt32(bytes, 0x1004, 1);
            WriteUInt32(bytes, 0x1008, 1);
            WriteUInt32(bytes, 0x100C, 0);
            WriteUInt64(bytes, 0x1010, 0);
            WriteUInt32(bytes, 0x1018, 1);
            for (var index = 0; index < 4096; index++)
            {
                WriteUInt32(bytes, 0x101C + (index * sizeof(uint)), 0);
            }

            return bytes;
        }

        public static byte[] CreateOversizedTlsTemplate()
        {
            var bytes = Create().Bytes;
            Array.Resize(ref bytes, SemanticExternalJumpTableProviderReader.MaximumProviderElfBytes);
            WriteUInt64(
                bytes,
                FirstLoadProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize,
                (ulong)bytes.Length);
            WriteUInt64(
                bytes,
                FirstLoadProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize,
                (ulong)bytes.Length);

            const ulong movedTargetBase = 0x1000000;
            WriteUInt64(
                bytes,
                ExecutableLoadProgramHeaderOffset + ElfProgramHeaderOffsets.VirtualAddress,
                movedTargetBase);
            WriteUInt64(
                bytes,
                ExecutableLoadProgramHeaderOffset + ElfProgramHeaderOffsets.PhysicalAddress,
                movedTargetBase);
            WriteUInt64(
                bytes,
                ExecutableLoadProgramHeaderOffset + ElfProgramHeaderOffsets.Alignment,
                1);
            for (var index = 0; index < RequiredEntryCount; index++)
            {
                var targetAddress = movedTargetBase + ((ulong)index * 2 * sizeof(uint));
                WriteUInt64(bytes, DynamicSymbolOffset(index + 2) + 8, targetAddress);
                BinaryPrimitives.WriteInt32LittleEndian(
                    bytes.AsSpan(TableFileOffset + (index * sizeof(int))),
                    checked((int)(targetAddress - TableVirtualAddress)));
            }

            WriteUInt16(bytes, ElfHeaderOffsets.ProgramHeaderCount, 5);
            WriteProgramHeader(
                bytes,
                ElfConstants.HeaderSize64 + (4 * ElfConstants.ProgramHeaderSize64),
                ElfConstants.PtTls,
                ElfConstants.PfR,
                0,
                0,
                (ulong)bytes.Length,
                (ulong)bytes.Length,
                1);
            return bytes;
        }

        public static byte[] CreateOverlongDynamicFunctionName()
        {
            var bytes = Create().Bytes;
            Array.Resize(ref bytes, 0x3000);
            const int stringTableFileOffset = 0x1000;
            const ulong stringTableAddress = 0x2000;
            const int overlongNameOffset = 100;
            var overlongNameLength = SemanticPlanSnapshotLimits.MaximumStringBytes + 1;
            var stringTableSize = overlongNameOffset + overlongNameLength + 1;
            var strings = bytes.AsSpan(stringTableFileOffset, stringTableSize);
            strings.Clear();
            WriteNullTerminatedString(strings, 1, Soname);
            WriteNullTerminatedString(strings, 32, TableSymbolName);
            WriteNullTerminatedString(strings, 64, "case_1");
            WriteNullTerminatedString(strings, 72, "case_2");
            WriteNullTerminatedString(strings, 80, "case_3");
            strings.Slice(overlongNameOffset, overlongNameLength).Fill((byte)'x');
            strings[overlongNameOffset + overlongNameLength] = 0;

            WriteUInt64(
                bytes,
                ExecutableLoadProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize,
                0x2800);
            WriteUInt64(
                bytes,
                ExecutableLoadProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize,
                0x2800);
            WriteDynamicEntry(bytes, DynamicEntryOffset(1), ElfConstants.DtStrTab, stringTableAddress);
            WriteDynamicEntry(bytes, DynamicEntryOffset(2), ElfConstants.DtStrSz, checked((ulong)stringTableSize));
            WriteDynamicEntry(bytes, DynamicEntryOffset(5), ElfConstants.DtSoname, 1);
            WriteUInt32(bytes, DynamicSymbolOffset(1), 32);
            WriteUInt32(bytes, DynamicSymbolOffset(2), overlongNameOffset);
            WriteUInt32(bytes, DynamicSymbolOffset(3), 64);
            WriteUInt32(bytes, DynamicSymbolOffset(4), 72);
            WriteUInt32(bytes, DynamicSymbolOffset(5), 80);
            return bytes;
        }

        public static byte[] CreateExcessNoteRecords(int recordCount)
        {
            var bytes = Create().Bytes;
            const int noteHeaderSize = 12;
            const int noteSegmentOffset = 0x1000;
            var noteSegmentSize = checked(recordCount * noteHeaderSize);
            Array.Resize(ref bytes, noteSegmentOffset + noteSegmentSize);
            WriteProgramHeader(
                bytes,
                NoteProgramHeaderOffset,
                ElfConstants.PtNote,
                ElfConstants.PfR,
                noteSegmentOffset,
                noteSegmentOffset,
                (ulong)noteSegmentSize,
                (ulong)noteSegmentSize,
                4);
            for (var index = 0; index < recordCount; index++)
            {
                var offset = noteSegmentOffset + (index * noteHeaderSize);
                WriteUInt32(bytes, offset, 0);
                WriteUInt32(bytes, offset + 4, 0);
                WriteUInt32(bytes, offset + 8, checked((uint)index));
            }

            return bytes;
        }

        public static int DynamicEntryOffset(int index) =>
            DynamicOffset + (index * ElfConstants.DynamicEntrySize64);

        public static int DynamicSymbolOffset(int index) =>
            DynamicSymbolsOffset + (index * ElfConstants.SymbolEntrySize64);

        public static ulong TargetVirtualAddress(int index) =>
            checked(0x1800UL + ((ulong)index * 2 * sizeof(uint)));

        public static ulong TargetFileOffset(int index) =>
            checked(0x800UL + ((ulong)index * 2 * sizeof(uint)));

        public static string Hash(ReadOnlySpan<byte> bytes) =>
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        public static void WriteDynamicEntry(Span<byte> bytes, int offset, ulong tag, ulong value)
        {
            WriteUInt64(bytes, offset, tag);
            WriteUInt64(bytes, offset + 8, value);
        }

        public static void AddUnsupportedSectionRecord(Span<byte> bytes, uint sectionType = ElfConstants.ShtRela)
        {
            const int relocatedSectionTableOffset = 0x600;
            const int previousSectionTableOffset = 0x700;
            const int sectionRelocationBytesOffset = 0x750;
            var entrySize = sectionType is ElfConstants.ShtRelr or ElfConstants.ShtAndroidRelr
                ? ElfConstants.RelrEntrySize64
                : ElfConstants.RelaEntrySize64;
            bytes.Slice(previousSectionTableOffset, 4 * ElfConstants.SectionHeaderSize64)
                .CopyTo(bytes[relocatedSectionTableOffset..]);
            WriteUInt64(bytes, ElfHeaderOffsets.SectionHeaderOffset, relocatedSectionTableOffset);
            WriteUInt16(bytes, ElfHeaderOffsets.SectionHeaderCount, 5);
            WriteSectionHeader(
                bytes,
                SectionRelocationHeaderOffset,
                sectionType,
                0,
                0x1800,
                sectionRelocationBytesOffset,
                entrySize,
                2,
                3,
                sizeof(ulong),
                entrySize);
            WriteUInt64(bytes, sectionRelocationBytesOffset, 0x1810);
            if (entrySize == ElfConstants.RelaEntrySize64)
            {
                WriteUInt64(bytes, sectionRelocationBytesOffset + 8, ElfConstants.RArm64None);
                WriteUInt64(bytes, sectionRelocationBytesOffset + 16, 0);
            }
        }

        private static void WriteGnuHashTable(Span<byte> bytes, int offset, int dynamicSymbolCount)
        {
            WriteUInt32(bytes, offset, 1); // one bucket
            WriteUInt32(bytes, offset + 4, 1); // first dynamic symbol covered by the chain
            WriteUInt32(bytes, offset + 8, 1); // one bloom word
            WriteUInt32(bytes, offset + 12, 0);
            WriteUInt64(bytes, offset + 16, 0);
            WriteUInt32(bytes, offset + 24, 1);
            for (var index = 0; index < dynamicSymbolCount - 1; index++)
            {
                WriteUInt32(
                    bytes,
                    offset + 28 + (index * sizeof(uint)),
                    index == dynamicSymbolCount - 2 ? 1u : 0u);
            }
        }

        private static void WriteNullTerminatedString(Span<byte> bytes, int offset, string value)
        {
            var encoded = Encoding.UTF8.GetBytes(value);
            encoded.CopyTo(bytes[offset..]);
            bytes[offset + encoded.Length] = 0;
        }

        private static uint AddString(List<byte> bytes, string value)
        {
            var offset = checked((uint)bytes.Count);
            bytes.AddRange(Encoding.UTF8.GetBytes(value));
            bytes.Add(0);
            return offset;
        }

        private static void WriteStaticTargetSymbols(Span<byte> bytes)
        {
            const int staticStringTableOffset = 0x500;
            const int staticSymbolTableOffset = 0x540;
            const int sectionHeaderOffset = 0x700;
            var strings = new List<byte> { 0 };
            var names = Enumerable.Range(0, 4).Select(index => AddString(strings, $"case_{index}")).ToArray();
            strings.ToArray().CopyTo(bytes[staticStringTableOffset..]);
            for (var index = 0; index < names.Length; index++)
            {
                var rowOffset = staticSymbolTableOffset + ((index + 1) * ElfConstants.SymbolEntrySize64);
                WriteUInt32(bytes, rowOffset, names[index]);
                bytes[rowOffset + 4] = 0x02; // STB_LOCAL | STT_FUNC
                WriteUInt16(bytes, rowOffset + 6, 3);
                WriteUInt64(bytes, rowOffset + 8, TargetVirtualAddress(index));
                WriteUInt64(bytes, rowOffset + 16, 2 * sizeof(uint));
            }

            WriteUInt64(bytes, ElfHeaderOffsets.SectionHeaderOffset, sectionHeaderOffset);
            WriteUInt16(bytes, ElfHeaderOffsets.SectionHeaderCount, 4);
            WriteUInt16(bytes, ElfHeaderOffsets.SectionNameIndex, 0);
            WriteSectionHeader(bytes, sectionHeaderOffset + ElfConstants.SectionHeaderSize64,
                ElfConstants.ShtStrTab, 0, 0, staticStringTableOffset, checked((ulong)strings.Count), 0, 0, 1, 0);
            WriteSectionHeader(bytes, sectionHeaderOffset + (2 * ElfConstants.SectionHeaderSize64),
                ElfConstants.ShtSymTab, 0, 0, staticSymbolTableOffset,
                5 * ElfConstants.SymbolEntrySize64, 1, 5, 8, ElfConstants.SymbolEntrySize64);
            WriteSectionHeader(bytes, sectionHeaderOffset + (3 * ElfConstants.SectionHeaderSize64),
                ElfConstants.ShtProgbits, ElfConstants.ShfExecInstr, 0x1800, 0x800, 0x80, 0, 0, 4, 0);
        }

        private static void WriteSectionHeader(
            Span<byte> bytes,
            int offset,
            uint type,
            ulong flags,
            ulong address,
            ulong fileOffset,
            ulong size,
            uint link,
            uint info,
            ulong alignment,
            ulong entrySize)
        {
            WriteUInt32(bytes, offset, 0);
            WriteUInt32(bytes, offset + 4, type);
            WriteUInt64(bytes, offset + 8, flags);
            WriteUInt64(bytes, offset + 16, address);
            WriteUInt64(bytes, offset + 24, fileOffset);
            WriteUInt64(bytes, offset + 32, size);
            WriteUInt32(bytes, offset + 40, link);
            WriteUInt32(bytes, offset + 44, info);
            WriteUInt64(bytes, offset + 48, alignment);
            WriteUInt64(bytes, offset + 56, entrySize);
        }

        private static void WriteSymbol(
            Span<byte> bytes,
            int index,
            uint name,
            byte info,
            byte other,
            ushort sectionIndex,
            ulong value,
            ulong size)
        {
            var offset = DynamicSymbolOffset(index);
            WriteUInt32(bytes, offset, name);
            bytes[offset + 4] = info;
            bytes[offset + 5] = other;
            WriteUInt16(bytes, offset + 6, sectionIndex);
            WriteUInt64(bytes, offset + 8, value);
            WriteUInt64(bytes, offset + 16, size);
        }

        private static void WriteProgramHeader(
            Span<byte> bytes,
            int offset,
            uint type,
            uint flags,
            ulong fileOffset,
            ulong virtualAddress,
            ulong fileSize,
            ulong memorySize,
            ulong alignment)
        {
            WriteUInt32(bytes, offset, type);
            WriteUInt32(bytes, offset + 4, flags);
            WriteUInt64(bytes, offset + 8, fileOffset);
            WriteUInt64(bytes, offset + 16, virtualAddress);
            WriteUInt64(bytes, offset + 24, virtualAddress);
            WriteUInt64(bytes, offset + 32, fileSize);
            WriteUInt64(bytes, offset + 40, memorySize);
            WriteUInt64(bytes, offset + 48, alignment);
        }

        private static void WriteUInt16(Span<byte> bytes, int offset, ushort value) =>
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.Slice(offset, sizeof(ushort)), value);

        private static void WriteUInt32(Span<byte> bytes, int offset, uint value) =>
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.Slice(offset, sizeof(uint)), value);

        private static void WriteUInt64(Span<byte> bytes, int offset, ulong value) =>
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.Slice(offset, sizeof(ulong)), value);
    }
}
