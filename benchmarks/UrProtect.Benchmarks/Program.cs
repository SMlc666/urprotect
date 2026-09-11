using System.Buffers.Binary;
using System.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Pipeline;

var input = CreateFixture();
var pipeline = new NoOpPipeline();
var iterations = ReadIterations(args);
var parsed = ElfParser.Parse(input);
if (!parsed.IsSuccess || parsed.File is null)
{
    throw new InvalidOperationException(string.Join(Environment.NewLine, parsed.Diagnostics));
}

var parsedFile = parsed.File!;
Console.WriteLine($"fixture_bytes={input.Length}");
Console.WriteLine($"iterations={iterations}");
Measure("parse", iterations, () => EnsureParseSuccess(ElfParser.Parse(input)));
Measure("load-map", iterations, () =>
{
    if (!parsedFile.LoadMap.TryFileOffsetToVirtualAddress(0x200, out var virtualAddress)
        || !parsedFile.LoadMap.TryVirtualAddressToFileOffset(virtualAddress, out var fileOffset)
        || fileOffset != 0x200)
    {
        throw new InvalidOperationException("LoadMap round trip failed.");
    }
});
Measure("validate-no-analysis", iterations, () => EnsureSuccess(
    pipeline.Validate(input, emitOutput: false, analyzeInstructions: false)));
Measure("validate-with-analysis", Math.Max(1, iterations / 10), () => EnsureSuccess(
    pipeline.Validate(input, emitOutput: false, analyzeInstructions: true)));
Measure("no-op-memory-copy", iterations, () =>
{
    var result = pipeline.Validate(input, emitOutput: true, analyzeInstructions: false);
    EnsureSuccess(result);
    if (result.OutputBytes is null || !input.AsSpan().SequenceEqual(result.OutputBytes))
    {
        throw new InvalidOperationException("No-op memory copy was not byte-identical.");
    }
});

var temporaryDirectory = Directory.CreateTempSubdirectory("urprotect-benchmark-");
try
{
    var inputPath = Path.Combine(temporaryDirectory.FullName, "input.elf");
    var outputPath = Path.Combine(temporaryDirectory.FullName, "output.elf");
    File.WriteAllBytes(inputPath, input);
    Measure("no-op-disk-copy", Math.Max(1, Math.Min(iterations, 100)), () =>
    {
        var result = pipeline.ValidateAndCopy(inputPath, outputPath, analyzeInstructions: false);
        EnsureSuccess(result);
        if (!input.AsSpan().SequenceEqual(File.ReadAllBytes(outputPath)))
        {
            throw new InvalidOperationException("No-op disk copy was not byte-identical.");
        }
    });
}
finally
{
    temporaryDirectory.Delete(recursive: true);
}

static int ReadIterations(string[] args)
{
    if (args.Length == 0)
    {
        return 10_000;
    }

    if (args.Length == 2 && args[0] == "--iterations" && int.TryParse(args[1], out var value)
        && value > 0 && value <= 1_000_000)
    {
        return value;
    }

    throw new ArgumentException("Usage: --iterations <positive number <= 1000000>");
}

static void EnsureSuccess(NoOpValidationResult result)
{
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException(string.Join(Environment.NewLine, result.Diagnostics));
    }
}

static void EnsureParseSuccess(ElfParseResult result)
{
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException(string.Join(Environment.NewLine, result.Diagnostics));
    }
}

static void Measure(string name, int iterations, Action action)
{
    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();

    using var process = Process.GetCurrentProcess();
    process.Refresh();
    var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
    var heapBefore = GC.GetTotalMemory(forceFullCollection: false);
    var peakWorkingSet = process.WorkingSet64;
    var stopwatch = Stopwatch.StartNew();
    for (var index = 0; index < iterations; index++)
    {
        action();
        if ((index & 0x3F) == 0)
        {
            process.Refresh();
            peakWorkingSet = Math.Max(peakWorkingSet, process.WorkingSet64);
        }
    }

    process.Refresh();
    peakWorkingSet = Math.Max(peakWorkingSet, process.WorkingSet64);
    stopwatch.Stop();
    var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
    var heapAfter = GC.GetTotalMemory(forceFullCollection: false);
    Console.WriteLine(
        $"benchmark={name} iterations={iterations} elapsed_ms={stopwatch.Elapsed.TotalMilliseconds:F2} "
        + $"allocations_bytes={allocated} heap_before_bytes={heapBefore} "
        + $"heap_after_bytes={heapAfter} peak_working_set_bytes={peakWorkingSet}");
}

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
