using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class ElfParserTests
{
    [Fact]
    public void ParsesMinimalDynamicAarch64Pie()
    {
        var result = ElfParser.Parse(ElfFixture.MinimalPie());

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        Assert.Equal(ElfFileKind.PieExecutable, result.File!.Kind);
        Assert.Equal(4, result.File.ProgramHeaders.Count);
        Assert.Equal(2, result.File.LoadMap.Segments.Count);
        Assert.Single(result.File.LoadMap.Segments, segment => segment.IsExecutable);
        Assert.Empty(result.File.DynamicSymbols);
    }

    [Fact]
    public void RejectsUnsupportedElfIdentificationVersion()
    {
        var bytes = ElfFixture.MinimalPie();
        bytes[6] = 2;

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InvalidHeader);
    }

    [Fact]
    public void DistinguishesSharedObjectWithoutAnInterpreterFromPie()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(232), ElfConstants.PtNull);

        var result = ElfParser.Parse(bytes);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        Assert.Equal(ElfFileKind.SharedObject, result.File!.Kind);
    }

    [Fact]
    public void RejectsNonAarch64Machine()
    {
        var bytes = ElfFixture.MinimalPie();
        bytes[18] = 0;
        bytes[19] = 0x3E;

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedMachine);
    }

    [Fact]
    public void RejectsProgramHeaderTableOverflow()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(32), ulong.MaxValue);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TableOutOfBounds);
    }

    [Fact]
    public void RejectsTruncatedInput()
    {
        var bytes = ElfFixture.MinimalPie()[..32];

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InputTooSmall);
    }

    [Fact]
    public void RejectsPieEntryPointOutsideExecutableSegment()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(24), 0x100);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.AddressUnmapped);
    }

    [Fact]
    public void RejectsLoadSegmentWhoseFileSizeExceedsMemorySize()
    {
        var bytes = ElfFixture.MinimalPie();
        // PT_LOAD #1 p_filesz at 120 + 32, p_memsz at 120 + 40.
        bytes[152] = 8;
        bytes[160] = 4;

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InvalidSegment);
    }

    [Fact]
    public void LoadMapRoundTripsFileAndVirtualAddresses()
    {
        var result = ElfParser.Parse(ElfFixture.MinimalPie());
        Assert.NotNull(result.File);

        Assert.True(result.File!.LoadMap.TryFileOffsetToVirtualAddress(0x200, out var virtualAddress));
        Assert.Equal(0x1200UL, virtualAddress);
        Assert.True(result.File.LoadMap.TryVirtualAddressToFileOffset(0x1200, out var fileOffset));
        Assert.Equal(0x200UL, fileOffset);
    }

    [Fact]
    public void PreservesBoundedAndroidPackedRelocationTable()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x190), ElfConstants.DtAndroidRel);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x198), 0x1F0);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1A0), ElfConstants.DtAndroidRelsz);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1A8), 8);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1B0), ElfConstants.DtNull);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1B8), 0);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(176 + 32), 64);
        bytes[0x1F0] = 0x81;
        bytes[0x1F1] = 0x80;
        bytes[0x1F2] = 0x01;

        var result = ElfParser.Parse(bytes);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        var table = Assert.Single(result.File!.AndroidPackedRelocations);
        Assert.False(table.IsRela);
        Assert.Equal(0x1F0UL, table.Address);
        Assert.Equal(8UL, table.Size);
        Assert.Equal(bytes.AsSpan(0x1F0, 8).ToArray(), table.RawBytes.ToArray());
    }

    [Fact]
    public void PreservesUnknownDynamicTagsWithoutGuessing()
    {
        var bytes = ElfFixture.MinimalPie();
        const ulong unknownTag = 0x70000001;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x180), unknownTag);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x188), 0x1234);

        var result = ElfParser.Parse(bytes);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        Assert.Contains(result.File!.DynamicEntries, entry => entry.Tag == unknownTag && entry.Value == 0x1234);
    }
}
