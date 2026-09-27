using System.Buffers.Binary;
using System.Text.Json;
using UrProtect.Cli;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Pipeline;

namespace UrProtect.Core.Tests;

public sealed class ElfSymbolVersionParserTests
{
    private const string FixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";
    private static readonly string[] ExpectedDefinitionNames =
        { "liburp-versioned.so", "URP_1.0", "URP_2.0" };
    private static readonly ushort[] ExpectedDefinitionIndices = { 1, 2, 3 };
    private static readonly ushort[] ExpectedAuxiliaryCounts = { 1, 1, 2 };

    [Fact]
    public void ParsesCompilerProducedVersionDefinitionsAsBoundedModelData()
    {
        var bytes = ReadVersionedFixture();
        var result = ElfParser.Parse(bytes);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        var file = result.File!;
        var metadata = file.SymbolVersions;
        Assert.Equal(new VirtualAddress(0x2D8), metadata.VersionDefinitionAddress);
        Assert.True(file.LoadMap.TryVirtualAddressToFileOffset(
            metadata.VersionDefinitionAddress,
            (ulong)metadata.VersionDefinitionBytes.Length,
            out FileOffset versionDefinitionOffset));
        Assert.Equal(
            file.Bytes.Slice(checked((int)versionDefinitionOffset.Value), metadata.VersionDefinitionBytes.Length).ToArray(),
            metadata.VersionDefinitionBytes.ToArray());
        Assert.Equal(ExpectedDefinitionNames,
            metadata.DefinedVersions.Select(definition => definition.Name));
        Assert.Equal(ExpectedDefinitionIndices, metadata.DefinedVersions.Select(definition => definition.Index));
        Assert.Equal(ExpectedAuxiliaryCounts, metadata.DefinedVersions.Select(definition => definition.AuxiliaryCount));
        Assert.All(metadata.DefinedVersions, definition =>
        {
            Assert.Equal((ushort)1, definition.Version);
            Assert.Equal(20, definition.RawBytes.Length);
            Assert.All(definition.Auxiliaries, auxiliary => Assert.Equal(8, auxiliary.RawBytes.Length));
        });
        Assert.Equal("URP_1.0", metadata.DefinedVersions[2].Auxiliaries[1].Name);
        Assert.True(file.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(metadata.VersionTableAddress),
            (ulong)metadata.VersionTableBytes.Length,
            out FileOffset versionTableOffset));
        Assert.Equal(
            file.Bytes.Slice(checked((int)versionTableOffset.Value), metadata.VersionTableBytes.Length).ToArray(),
            metadata.VersionTableBytes.ToArray());
    }

    [Fact]
    public void ProjectsDefinedVersionCountInStableReportSummary()
    {
        var bytes = ReadVersionedFixture();
        var validation = new NoOpPipeline().Validate(bytes, analyzeInstructions: false);
        var report = ProductReportFactory.Create(
            CliApplication.ToolVersion,
            bytes,
            validation,
            outputRequested: false,
            outputPublished: false);

        using var document = JsonDocument.Parse(ProductReportFactory.Serialize(report));
        Assert.Equal(
            3,
            document.RootElement
                .GetProperty("summary")
                .GetProperty("versionDefinitions")
                .GetInt32());
    }

    [Fact]
    public void LeavesVersionDefinitionModelEmptyForUnversionedElf()
    {
        var result = ElfParser.Parse(ElfFixture.MinimalPie());

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        Assert.Empty(result.File!.SymbolVersions.DefinedVersions);
        Assert.Empty(result.File.SymbolVersions.VersionDefinitionBytes.ToArray());
    }

    [Fact]
    public void RejectsUnmappedVersionDefinitionTableWithStableDiagnostic()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var pointerOffset = FindDynamicValueOffset(bytes, parsed.File!, ElfConstants.DtVerdef);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(pointerOffset), ulong.MaxValue);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.File);
        var diagnostic = Assert.Single(result.Diagnostics, item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Equal(ulong.MaxValue, diagnostic.Offset);
        Assert.Equal("The DT_VERDEF record is truncated or unmapped.", diagnostic.Message);
    }

    [Fact]
    public void RejectsVersionDefinitionChainShorterThanDeclaredCountWithStableDiagnostic()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var countOffset = FindDynamicValueOffset(bytes, parsed.File!, ElfConstants.DtVerdefNum);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(countOffset), 4);
        var expectedLastAddress = parsed.File.SymbolVersions.DefinedVersions
            .Aggregate(
                parsed.File.SymbolVersions.VersionDefinitionAddress.Value,
                (address, definition) => address + definition.NextOffset);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.File);
        Assert.Equal(3, result.File!.SymbolVersions.DefinedVersions.Count);
        Assert.Equal(
            new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.VersionDefinitionTableMalformed,
                "The DT_VERDEF chain terminates or moves backwards before its declared count.",
                expectedLastAddress),
            Assert.Single(result.Diagnostics, item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed));
    }

    [Fact]
    public void RejectsVersionDefinitionAuxiliaryThatOverlapsItsRecord()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var metadata = parsed.File!.SymbolVersions;
        var thirdAddress = metadata.VersionDefinitionAddress.Value
            + metadata.DefinedVersions[0].NextOffset
            + metadata.DefinedVersions[1].NextOffset;
        Assert.True(parsed.File.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(thirdAddress),
            20,
            out FileOffset recordOffset));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(checked((int)recordOffset.Value + 6)), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(checked((int)recordOffset.Value + 12)), 16);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal(thirdAddress, diagnostic.Offset);
        Assert.Equal("The DT_VERDEF auxiliary offset overlaps its record.", diagnostic.Message);
    }

    [Fact]
    public void RejectsVersionDefinitionChainThatOverlapsCurrentAuxiliaries()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        Assert.True(parsed.File!.LoadMap.TryVirtualAddressToFileOffset(
            parsed.File.SymbolVersions.VersionDefinitionAddress,
            20,
            out FileOffset recordOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(checked((int)recordOffset.Value + 16)), 20);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal("The DT_VERDEF chain overlaps the current definition or its auxiliaries.", diagnostic.Message);
    }

    [Fact]
    public void RejectsVersionDefinitionAuxiliaryChainThatOverlapsEntries()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var metadata = parsed.File!.SymbolVersions;
        var third = metadata.DefinedVersions[2];
        var thirdAddress = metadata.VersionDefinitionAddress.Value
            + metadata.DefinedVersions[0].NextOffset
            + metadata.DefinedVersions[1].NextOffset;
        var auxiliaryAddress = thirdAddress + third.AuxiliaryOffset;
        Assert.True(parsed.File.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(auxiliaryAddress),
            8,
            out FileOffset auxiliaryOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(checked((int)auxiliaryOffset.Value + 4)), 4);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal(
            "The DT_VERDEF auxiliary chain terminates, overlaps, or moves backwards before its declared count.",
            diagnostic.Message);
    }

    [Fact]
    public void RejectsVersionDefinitionCountBeyondInputLengthBeforeAllocation()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var countOffset = FindDynamicValueOffset(bytes, parsed.File!, ElfConstants.DtVerdefNum);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(countOffset), ulong.MaxValue);
        var definitionAddress = parsed.File.SymbolVersions.VersionDefinitionAddress.Value;

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Equal(definitionAddress, diagnostic.Offset);
        Assert.Equal("The DT_VERDEF count exceeds the bounded input size.", diagnostic.Message);
    }

    [Fact]
    public void RejectsVersionDefinitionAddressWithoutCountTag()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var countOffset = FindDynamicValueOffset(bytes, parsed.File!, ElfConstants.DtVerdefNum);
        var countEntryOffset = countOffset - sizeof(ulong);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(countEntryOffset), ElfConstants.DtNull);
        var definitionAddress = parsed.File.SymbolVersions.VersionDefinitionAddress.Value;

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Equal(definitionAddress, diagnostic.Offset);
        Assert.Equal(
            "DT_VERDEF and a nonzero DT_VERDEFNUM must be provided together.",
            diagnostic.Message);
    }

    [Fact]
    public void RejectsOutOfRangeVersionDefinitionAuxiliaryNameOffset()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var firstDefinition = parsed.File.SymbolVersions.DefinedVersions[0];
        var auxiliaryAddress = parsed.File.SymbolVersions.VersionDefinitionAddress.Value + firstDefinition.AuxiliaryOffset;
        Assert.True(parsed.File.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(auxiliaryAddress),
            8,
            out FileOffset auxiliaryOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(checked((int)auxiliaryOffset.Value)),
            uint.MaxValue);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(result.Diagnostics, item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Equal(auxiliaryAddress, diagnostic.Offset);
        Assert.Equal(
            "The DT_VERDEF auxiliary record is truncated, unmapped, or has an invalid name.",
            diagnostic.Message);
    }

    [Fact]
    public void RejectsEmptyVersionDefinitionAuxiliaryName()
    {
        var bytes = ReadVersionedFixture();
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var firstDefinition = parsed.File!.SymbolVersions.DefinedVersions[0];
        var auxiliaryAddress = parsed.File.SymbolVersions.VersionDefinitionAddress.Value
            + firstDefinition.AuxiliaryOffset;
        Assert.True(parsed.File.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(auxiliaryAddress),
            8,
            out FileOffset auxiliaryOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(checked((int)auxiliaryOffset.Value)),
            0);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(
            result.Diagnostics,
            item => item.Code == DiagnosticCode.VersionDefinitionTableMalformed);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Equal(auxiliaryAddress, diagnostic.Offset);
        Assert.Equal(
            "The DT_VERDEF auxiliary record is truncated, unmapped, or has an invalid name.",
            diagnostic.Message);
    }

    private static byte[] ReadVersionedFixture() =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixturePath));

    private static int FindDynamicValueOffset(byte[] bytes, ElfFile file, ulong tag)
    {
        var dynamicHeader = Assert.Single(file.ProgramHeaders, header => header.Type == ElfConstants.PtDynamic);
        var entryCount = dynamicHeader.FileSize / ElfConstants.DynamicEntrySize64;
        for (ulong index = 0; index < entryCount; index++)
        {
            var entryOffset = checked((int)(dynamicHeader.Offset + (index * ElfConstants.DynamicEntrySize64)));
            if (BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(entryOffset)) == tag)
            {
                return entryOffset + sizeof(ulong);
            }
        }

        throw new InvalidOperationException($"Dynamic tag 0x{tag:X} was not found in the fixture.");
    }
}
