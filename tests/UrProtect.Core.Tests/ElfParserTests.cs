using System.Buffers.Binary;
using System.Text;
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
    public void RejectsUnsupportedExtendedNumberingExplicitly()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(56), ElfConstants.PnXnum);

        var result = ElfParser.Parse(bytes);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedExtendedNumbering);
    }

    [Fact]
    public void PreservesUnknownProgramHeaderTypesAsWarnings()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(64), 0x60000000);

        var result = ElfParser.Parse(bytes);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        Assert.Equal(ProgramHeaderKind.Unknown, result.File!.ProgramHeaders[0].Kind);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnknownProgramHeaderType);
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

    [Fact]
    public void ParsesAlignedNotePayloadsFromNoteSegments()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(56), 5);
        var programHeaderOffset = 64 + (4 * ElfConstants.ProgramHeaderSize64);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(programHeaderOffset), ElfConstants.PtNote);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(programHeaderOffset + 4), ElfConstants.PfR);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(programHeaderOffset + 8), 0x1E0);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(programHeaderOffset + 16), 0x1E0);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(programHeaderOffset + 32), 20);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(programHeaderOffset + 40), 20);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(programHeaderOffset + 48), 4);

        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1E0), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1E4), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1E8), 5);
        Encoding.ASCII.GetBytes("GNU\0").CopyTo(bytes.AsSpan(0x1EC));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1F0), 0xB);

        var result = ElfParser.Parse(bytes);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        var note = Assert.Single(result.File!.Notes);
        Assert.Equal(ElfConstants.PtNote, note.SegmentType);
        Assert.Equal(5U, note.Type);
        Assert.Equal("GNU\0", Encoding.ASCII.GetString(note.Name.Span));
        Assert.Equal(0xBU, BinaryPrimitives.ReadUInt32LittleEndian(note.Descriptor.Span));
    }

    [Fact]
    public void ResolvesBoundedDynamicStringMetadata()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(232), ElfConstants.PtNull);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(176 + 32), 96);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x180), ElfConstants.DtStrTab);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x188), 0x1E0);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x190), ElfConstants.DtStrSz);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x198), 28);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1A0), ElfConstants.DtNeeded);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1A8), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1B0), ElfConstants.DtSoname);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1B8), 9);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1C0), ElfConstants.DtRunPath);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1C8), 23);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1D0), ElfConstants.DtNull);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x1D8), 0);
        Encoding.ASCII.GetBytes("\0libc.so\0libfixture.so\0/lib\0").CopyTo(bytes.AsSpan(0x1E0));

        var result = ElfParser.Parse(bytes);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.File);
        Assert.Equal("libc.so", Assert.Single(result.File!.DynamicMetadata.NeededLibraries));
        Assert.Equal("libfixture.so", result.File.DynamicMetadata.Soname);
        Assert.Equal("/lib", result.File.DynamicMetadata.RunPath);
        Assert.Null(result.File.DynamicMetadata.Rpath);
    }

    [Fact]
    public void ClassifiesCommonAarch64RelocationKindsWithoutApplyingThem()
    {
        var relative = new RelaRelocation(0, ElfConstants.RArm64Relative, 0, 0x1000, false);
        var branch = new RelaRelocation(0, ElfConstants.RArm64Call26, 0, 0x1004, false);
        var loadStore = new RelaRelocation(0, ElfConstants.RArm64Ldst64AbsLo12Nc, 0, 0x1008, false);
        var unknown = new RelaRelocation(0, 0xFFFF, 0, 0x100C, false);

        Assert.Equal(Aarch64RelocationKind.Relative, relative.Kind);
        Assert.Equal(Aarch64RelocationKind.Call26, branch.Kind);
        Assert.Equal(Aarch64RelocationKind.LoadStore, loadStore.Kind);
        Assert.Equal(Aarch64RelocationKind.Unknown, unknown.Kind);
    }
}
