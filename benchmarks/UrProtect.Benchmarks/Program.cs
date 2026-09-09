using System.Buffers.Binary;
using System.Diagnostics;
using UrProtect.Core.Pipeline;

var input = CreateFixture();
var pipeline = new NoOpPipeline();
const int iterations = 10_000;
var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
var stopwatch = Stopwatch.StartNew();
for (var index = 0; index < iterations; index++)
{
    var result = pipeline.Validate(input, emitOutput: false, analyzeInstructions: false);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException(string.Join(Environment.NewLine, result.Diagnostics));
    }
}

stopwatch.Stop();
var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
Console.WriteLine($"iterations={iterations}");
Console.WriteLine($"elapsed_ms={stopwatch.Elapsed.TotalMilliseconds:F2}");
Console.WriteLine($"allocations_bytes={allocated}");

static byte[] CreateFixture()
{
    const int size = 0x204;
    var bytes = new byte[size];
    var span = bytes.AsSpan();
    span[0] = 0x7F;
    span[1] = (byte)'E';
    span[2] = (byte)'L';
    span[3] = (byte)'F';
    span[4] = 2;
    span[5] = 1;
    span[6] = 1;
    WriteUInt16(span, 16, 3);
    WriteUInt16(span, 18, 183);
    WriteUInt32(span, 20, 1);
    WriteUInt64(span, 24, 0x1200);
    WriteUInt64(span, 32, 64);
    WriteUInt16(span, 52, 64);
    WriteUInt16(span, 54, 56);
    WriteUInt16(span, 56, 4);
    WriteUInt16(span, 58, 64);

    WriteProgramHeader(span, 64, 1, 4, 0, 0, 0x200, 0x200, 0x1000);
    WriteProgramHeader(span, 120, 1, 5, 0x200, 0x1200, 4, 4, 0x1000);
    WriteProgramHeader(span, 176, 2, 4, 0x180, 0x180, 16, 16, 8);
    WriteProgramHeader(span, 232, 3, 4, 0x1C0, 0x1C0, 28, 28, 1);
    "/lib/ld-linux-aarch64.so.1\0"u8.CopyTo(span[0x1C0..]);
    WriteUInt32(span, 0x200, 0xD503201F);
    return bytes;

    static void WriteProgramHeader(
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
        WriteUInt64(destination, offset + 32, fileSize);
        WriteUInt64(destination, offset + 40, memorySize);
        WriteUInt64(destination, offset + 48, alignment);
    }

    static void WriteUInt16(Span<byte> destination, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(destination[offset..], value);

    static void WriteUInt32(Span<byte> destination, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination[offset..], value);

    static void WriteUInt64(Span<byte> destination, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(destination[offset..], value);
}
