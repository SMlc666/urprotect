using System.Buffers.Binary;
using System.Text;
using SharpFuzz;
using UrProtect.Core.Elf;
using UrProtect.Core.Pack;

namespace UrProtect.Fuzz;

internal static class Program
{
    private const int DefaultMaximumInputBytes = 1 * 1024 * 1024;

    public static void Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--emit-seed")
        {
            File.WriteAllBytes(args[1], BuildMinimalElfSeed());
            return;
        }

        if (args.Length == 2 && args[0] == "--emit-frame-seed")
        {
            File.WriteAllBytes(args[1], BuildFrameSeed());
            return;
        }

        var mode = args.Length == 0 ? "elf" : args[0];
        if (mode is not ("elf" or "payload-frame"))
        {
            throw new ArgumentException($"Unknown fuzz target '{mode}'. Expected elf or payload-frame.");
        }

        Fuzzer.LibFuzzer.Run(data => Execute(mode, data));
    }

    private static void Execute(string mode, ReadOnlySpan<byte> data)
    {
        if (data.Length > DefaultMaximumInputBytes)
        {
            throw new InvalidDataException($"fuzz input exceeded {DefaultMaximumInputBytes} bytes");
        }

        if (mode == "elf")
        {
            _ = ElfParser.Parse(data.ToArray());
            return;
        }

        var limits = new PayloadFrameLimits(
            MaximumSourceBytes: 8 * 1024 * 1024,
            MaximumEncodedBytes: 8 * 1024 * 1024,
            MaximumWrapperBytes: 16 * 1024 * 1024,
            MaximumSourceNameBytes: 4096,
            MaximumEntryNameBytes: HostContextContract.MaximumEntryNameBytes);
        _ = PayloadFrameCodec.Decode(data, frameOffset: 0, limits);
        _ = PayloadFrameCodec.ReadWrapper(data, limits);
    }

    private static byte[] BuildMinimalElfSeed()
    {
        const int size = 0x204;
        var bytes = new byte[size];
        var span = bytes.AsSpan();
        "\x7FELF"u8.CopyTo(span[0..4]);
        span[4] = ElfConstants.Class64;
        span[5] = ElfConstants.LittleEndian;
        span[6] = ElfConstants.IdentificationVersionCurrent;
        WriteUInt16(span, 16, ElfConstants.TypeDyn);
        WriteUInt16(span, 18, ElfConstants.MachineAarch64);
        WriteUInt32(span, 20, ElfConstants.HeaderVersionCurrent);
        WriteUInt64(span, 24, 0x1200);
        WriteUInt64(span, 32, ElfConstants.HeaderSize64);
        WriteUInt16(span, 52, ElfConstants.HeaderSize64);
        WriteUInt16(span, 54, ElfConstants.ProgramHeaderSize64);
        WriteUInt16(span, 56, 4);
        WriteUInt16(span, 58, ElfConstants.SectionHeaderSize64);

        WriteProgramHeader(span, 64, ElfConstants.PtLoad, ElfConstants.PfR, 0, 0, 0x200, 0x200, 0x1000);
        WriteProgramHeader(span, 120, ElfConstants.PtLoad, ElfConstants.PfR | ElfConstants.PfX, 0x200, 0x1200, 4, 4, 0x1000);
        WriteProgramHeader(span, 176, ElfConstants.PtDynamic, ElfConstants.PfR, 0x180, 0x180, 32, 32, 8);
        WriteUInt64(span, 0x180, ElfConstants.DtFlags1);
        WriteUInt64(span, 0x188, ElfConstants.Df1Pie);
        WriteUInt64(span, 0x190, ElfConstants.DtNull);
        WriteProgramHeader(
            span,
            232,
            ElfConstants.PtInterp,
            ElfConstants.PfR,
            0x1C0,
            0x1C0,
            (ulong)Encoding.ASCII.GetByteCount("/lib/ld-linux-aarch64.so.1\0"),
            (ulong)Encoding.ASCII.GetByteCount("/lib/ld-linux-aarch64.so.1\0"),
            1);
        Encoding.ASCII.GetBytes("/lib/ld-linux-aarch64.so.1\0").CopyTo(span[0x1C0..]);
        WriteUInt32(span, 0x200, 0xD503201F);
        return bytes;
    }

    private static byte[] BuildFrameSeed()
    {
        var source = BuildMinimalElfSeed();
        if (!PayloadFrameCodec.TryEncode(
                source,
                frameOffset: 0,
                PayloadCompression.Deflate,
                new PayloadFrameLimits(),
                "seed",
                out var encoded,
                out var diagnostics))
        {
            throw new InvalidOperationException(string.Join(Environment.NewLine, diagnostics));
        }

        return encoded!.FrameBytes;
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
