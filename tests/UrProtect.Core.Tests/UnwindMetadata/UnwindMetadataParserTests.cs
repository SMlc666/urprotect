using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.UnwindMetadata;

namespace UrProtect.Core.Tests.UnwindMetadata;

public sealed class UnwindMetadataParserTests
{
    [Fact]
    public void ParsesGccShapedCieFdeAndEhFrameHeader()
    {
        var parsed = ElfParser.Parse(UnwindFixture.GccShapedElf());

        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var file = Assert.IsType<ElfFile>(parsed.File);

        var result = UnwindMetadataParser.Parse(file);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var model = Assert.IsType<UnwindMetadataModel>(result.Model);
        var cie = Assert.Single(model.Cies);
        var fde = Assert.Single(model.Fdes);
        var header = Assert.IsType<UnwindFrameHeader>(model.Header);

        Assert.Equal("zR", cie.Augmentation);
        Assert.Equal((byte)0x1B, cie.FdePointerEncoding!.Value.Raw);
        Assert.Equal(1L, cie.CodeAlignmentFactor);
        Assert.Equal(-8L, cie.DataAlignmentFactor);
        Assert.Equal(30UL, cie.ReturnAddressRegister);
        Assert.Equal(UnwindInstructionKind.DefCfa, Assert.Single(cie.Instructions).Kind);

        Assert.Equal(cie.EntryOffset, fde.CieEntryOffset);
        Assert.Equal(0x1400UL, fde.InitialLocation);
        Assert.Equal(0x20UL, fde.AddressRange);
        Assert.Equal(UnwindInstructionKind.DefCfa, Assert.Single(fde.Instructions).Kind);
        Assert.Equal(0x311UL, cie.Instructions[0].FileOffset);
        Assert.Equal(0x325UL, fde.Instructions[0].FileOffset);

        Assert.Equal((byte)0x1B, header.EhFramePointerEncoding.Raw);
        Assert.Equal(0x1300UL, header.EhFrameAddress);
        Assert.Equal(1UL, header.FdeCount);
        var entry = Assert.Single(header.Entries);
        Assert.Equal(0x1400UL, entry.InitialLocation);
        Assert.Equal(0x1314UL, entry.FdeAddress);
    }

    [Fact]
    public void RetainsRawCfiInstructionBytes()
    {
        var parsed = ElfParser.Parse(UnwindFixture.GccShapedElf());
        var model = UnwindMetadataParser.Parse(Assert.IsType<ElfFile>(parsed.File)).Model;

        var instruction = Assert.Single(Assert.Single(model!.Cies).Instructions);

        Assert.Equal(new byte[] { 0x0C, 0x1F, 0x00 }, instruction.RawBytes.ToArray());
    }

    [Fact]
    public void RejectsAnFdeThatReferencesAnUnknownCie()
    {
        var bytes = UnwindFixture.GccShapedElf();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(UnwindFixture.EhFrameOffset + 0x18), 0x100);

        var parsed = ElfParser.Parse(bytes);
        var result = UnwindMetadataParser.Parse(Assert.IsType<ElfFile>(parsed.File));

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.UnwindMetadataMalformed);
    }

    [Fact]
    public void RejectsAnEhFrameRecordThatRunsPastTheSection()
    {
        var bytes = UnwindFixture.GccShapedElf();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(UnwindFixture.EhFrameOffset), 0xFFFF);

        var parsed = ElfParser.Parse(bytes);
        var result = UnwindMetadataParser.Parse(Assert.IsType<ElfFile>(parsed.File));

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.UnwindMetadataMalformed);
    }

    [Fact]
    public void RejectsAHeaderWithAnOutOfRangeFdeCount()
    {
        var bytes = UnwindFixture.GccShapedElf();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(UnwindFixture.EhFrameHeaderOffset + 8), 2);

        var parsed = ElfParser.Parse(bytes);
        var result = UnwindMetadataParser.Parse(Assert.IsType<ElfFile>(parsed.File));

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.UnwindMetadataMalformed);
    }

    [Fact]
    public void ReportsSectionlessImagesAsUnavailable()
    {
        var parsed = ElfParser.Parse(ElfFixture.MinimalPie());

        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var result = UnwindMetadataParser.Parse(Assert.IsType<ElfFile>(parsed.File));

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.UnwindMetadataUnavailable);
    }

    internal static class UnwindFixture
    {
        public const int EhFrameHeaderOffset = 0x2C0;
        public const int EhFrameOffset = 0x300;

        public static byte[] GccShapedElf()
        {
            var bytes = ElfFixture.MinimalPie();
            Array.Resize(ref bytes, 0x800);

            BinaryPrimitives.WriteUInt64LittleEndian(
                bytes.AsSpan(ElfFixture.SecondProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize),
                0x300);
            BinaryPrimitives.WriteUInt64LittleEndian(
                bytes.AsSpan(ElfFixture.SecondProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize),
                0x300);

            var frame = new byte[]
            {
                0x10, 0x00, 0x00, 0x00, // CIE length
                0x00, 0x00, 0x00, 0x00, // CIE id
                0x01,                     // version
                (byte)'z', (byte)'R', 0x00,
                0x01,                     // code alignment
                0x78,                     // data alignment -8
                0x1E,                     // return register x30
                0x01, 0x1B,              // z augmentation: sdata4|pcrel
                0x0C, 0x1F, 0x00,        // def_cfa x31, 0
                0x10, 0x00, 0x00, 0x00,  // FDE length
                0x18, 0x00, 0x00, 0x00,  // CIE pointer
                0xE4, 0x00, 0x00, 0x00,  // pc = 0x1400, pcrel from 0x131C
                0x20, 0x00, 0x00, 0x00,  // range
                0x00,                     // empty FDE augmentation
                0x0C, 0x1F, 0x10,        // def_cfa x31, 16
                0x00, 0x00, 0x00, 0x00,  // terminator
            };
            frame.CopyTo(bytes, EhFrameOffset);

            var header = new byte[]
            {
                0x01, 0x1B, 0x03, 0x3B,
                0x3C, 0x00, 0x00, 0x00,  // .eh_frame = 0x1300
                0x01, 0x00, 0x00, 0x00,  // one FDE
                0x40, 0x01, 0x00, 0x00,  // initial location = 0x1400 (datarel)
                0x54, 0x00, 0x00, 0x00,  // FDE = 0x1314 (datarel)
            };
            header.CopyTo(bytes, EhFrameHeaderOffset);

            const int sectionNameOffset = 0x500;
            var names = "\0.shstrtab\0.eh_frame_hdr\0.eh_frame\0"u8;
            names.CopyTo(bytes.AsSpan(sectionNameOffset));

            const int sectionTableOffset = 0x600;
            BinaryPrimitives.WriteUInt64LittleEndian(
                bytes.AsSpan(ElfHeaderOffsets.SectionHeaderOffset),
                sectionTableOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(
                bytes.AsSpan(ElfHeaderOffsets.SectionHeaderEntrySize),
                ElfConstants.SectionHeaderSize64);
            BinaryPrimitives.WriteUInt16LittleEndian(
                bytes.AsSpan(ElfHeaderOffsets.SectionHeaderCount),
                4);
            BinaryPrimitives.WriteUInt16LittleEndian(
                bytes.AsSpan(ElfHeaderOffsets.SectionNameIndex),
                1);

            WriteSection(
                bytes,
                sectionTableOffset + ElfConstants.SectionHeaderSize64,
                1,
                ElfConstants.ShtStrTab,
                0,
                0,
                sectionNameOffset,
                (ulong)names.Length,
                0,
                0,
                1);
            WriteSection(
                bytes,
                sectionTableOffset + (2 * ElfConstants.SectionHeaderSize64),
                11,
                1,
                0,
                0x12C0,
                EhFrameHeaderOffset,
                (ulong)header.Length,
                0,
                0,
                4);
            WriteSection(
                bytes,
                sectionTableOffset + (3 * ElfConstants.SectionHeaderSize64),
                25,
                1,
                0,
                0x1300,
                EhFrameOffset,
                (ulong)frame.Length,
                0,
                0,
                8);
            return bytes;
        }

        private static void WriteSection(
            byte[] bytes,
            int offset,
            uint name,
            uint type,
            ulong flags,
            ulong address,
            ulong fileOffset,
            ulong size,
            uint link,
            uint info,
            ulong alignment)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), name);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 4), type);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 8), flags);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 16), address);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 24), fileOffset);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 32), size);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 40), link);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 44), info);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 48), alignment);
        }
    }
}
