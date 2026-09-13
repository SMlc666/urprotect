using System.Buffers.Binary;
using System.Text;
using UrProtect.Core.Elf;
using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

internal static class ElfFixture
{
    public static byte[] MinimalPie()
    {
        const int size = 0x204;
        var bytes = new byte[size];
        var span = bytes.AsSpan();
        span[0] = 0x7F;
        span[1] = (byte)'E';
        span[2] = (byte)'L';
        span[3] = (byte)'F';
        span[4] = ElfConstants.Class64;
        span[5] = ElfConstants.LittleEndian;
        span[6] = 1;
        WriteUInt16(span, 16, ElfConstants.TypeDyn);
        WriteUInt16(span, 18, ElfConstants.MachineAarch64);
        WriteUInt32(span, 20, 1);
        WriteUInt64(span, 24, 0x1200);
        WriteUInt64(span, 32, 64);
        WriteUInt64(span, 40, 0);
        WriteUInt32(span, 48, 0);
        WriteUInt16(span, 52, ElfConstants.HeaderSize64);
        WriteUInt16(span, 54, ElfConstants.ProgramHeaderSize64);
        WriteUInt16(span, 56, 4);
        WriteUInt16(span, 58, ElfConstants.SectionHeaderSize64);
        WriteUInt16(span, 60, 0);
        WriteUInt16(span, 62, 0);

        WriteProgramHeader(span, 64, ElfConstants.PtLoad, ElfConstants.PfR, 0, 0, 0x200, 0x200, 0x1000);
        WriteProgramHeader(span, 120, ElfConstants.PtLoad, ElfConstants.PfR | ElfConstants.PfX, 0x200, 0x1200, 4, 4, 0x1000);
        WriteProgramHeader(span, 176, ElfConstants.PtDynamic, ElfConstants.PfR, 0x180, 0x180, 32, 32, 8);
        const string interpreter = "/lib/ld-linux-aarch64.so.1\0";
        WriteUInt64(span, 0x180, ElfConstants.DtFlags1);
        WriteUInt64(span, 0x188, ElfConstants.Df1Pie);
        WriteUInt64(span, 0x190, ElfConstants.DtNull);
        WriteUInt64(span, 0x198, 0);

        WriteProgramHeader(
            span,
            232,
            ElfConstants.PtInterp,
            ElfConstants.PfR,
            0x1C0,
            0x1C0,
            (ulong)Encoding.ASCII.GetByteCount(interpreter),
            (ulong)Encoding.ASCII.GetByteCount(interpreter),
            1);
        Encoding.ASCII.GetBytes(interpreter).CopyTo(span[0x1C0..]);

        // NOP at the ET_DYN entry point.
        WriteUInt32(span, 0x200, 0xD503201F);
        return bytes;
    }

    public static byte[] StaticPieLauncher(bool includeMarker = true)
    {
        var bytes = MinimalPie();
        bytes.AsSpan(232, 56).Clear();
        if (!includeMarker)
        {
            return bytes;
        }

        return bytes.Concat(Encoding.ASCII.GetBytes(LauncherContract.Marker)).ToArray();
    }

    private static void WriteProgramHeader(
        Span<byte> destination,
        int offset,
        uint type,
        uint flags,
        ulong fileOffset,
        ulong virtualAddress,
        ulong fileSize,
        ulong memorySize,
        ulong alignment)
    {
        WriteUInt32(destination, offset, type);
        WriteUInt32(destination, offset + 4, flags);
        WriteUInt64(destination, offset + 8, fileOffset);
        WriteUInt64(destination, offset + 16, virtualAddress);
        WriteUInt64(destination, offset + 24, 0);
        WriteUInt64(destination, offset + 32, fileSize);
        WriteUInt64(destination, offset + 40, memorySize);
        WriteUInt64(destination, offset + 48, alignment);
    }

    private static void WriteUInt16(Span<byte> destination, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(destination[offset..], value);

    private static void WriteUInt32(Span<byte> destination, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination[offset..], value);

    private static void WriteUInt64(Span<byte> destination, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(destination[offset..], value);
}
