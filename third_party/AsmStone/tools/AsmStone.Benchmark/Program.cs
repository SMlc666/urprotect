using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using AsmStone.Decode;
using AsmStone.Encode;
using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone.Benchmark;

internal static class Program
{
    private const int DefaultOperations = 250_000;
    private const int DefaultWarmupOperations = 25_000;
    private const int DefaultSamples = 5;

    private static readonly A64FeatureSet AllFeatures = A64FeatureSet.All;
    private static readonly A64FeatureSet BaseFeatures = A64FeatureSet.Base;
    private static readonly A64FeatureSet NeonFeatures = A64FeatureSet.From(A64Feature.Neon);
    private static readonly A64FeatureSet SveFeatures = A64FeatureSet.From(A64Feature.Sve);

    private static readonly A64Instruction GeneratedAdd = new(
        A64InstructionId.Generated,
        "add",
        [
            new RegisterOperand(A64Register.X(0)),
            new RegisterOperand(A64Register.X(1)),
            new ImmediateOperand(42),
        ],
        0,
        0)
    {
        SourceName = "ADDXri",
    };

    private static readonly A64Instruction GeneratedLoad = DecodeRequired(
        0xB9401020u,
        4,
        BaseFeatures);

    private static readonly IReadOnlyDictionary<string, uint> RawAddFields =
        new Dictionary<string, uint>(StringComparer.Ordinal)
        {
            ["Rd"] = 0,
            ["Rn"] = 1,
            ["imm"] = 42,
        };
    private static readonly A64FieldValue[] RawAddFieldValues =
    [
        new("Rd", 0),
        new("Rn", 1),
        new("imm", 42),
    ];

    private static readonly byte[] LoadBytes = { 0x20, 0x10, 0x40, 0xB9 };
    private static readonly byte[] EncodeDestination = new byte[sizeof(uint)];
    private static readonly A64OperandView[] ViewOperands = new A64OperandView[8];
    private static uint sink;

    private static int Main(string[] args)
    {
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
        var options = ParseOptions(args);
        if (options.ShowHelp)
        {
            PrintUsage();
            return 0;
        }

        Console.WriteLine("AsmStone benchmark (manual Stopwatch harness)");
        Console.WriteLine($"Runtime: {Environment.Version}; OS: {Environment.OSVersion}");
        Console.WriteLine($"Operations: {options.Operations:N0}; warmup: {options.WarmupOperations:N0}; samples: {options.Samples}");
        Console.WriteLine($"Catalog: {A64InstructionCatalog.Count:N0} instructions, {A64InstructionCatalog.OperandTypeCount:N0} operand codecs");
        Console.WriteLine();
        Console.WriteLine("Benchmark                         ns/op       Mops/s       B/op");
        Console.WriteLine("-------------------------------------------------------------------");

        foreach (var benchmark in Benchmarks)
        {
            for (var i = 0; i < options.WarmupSamples; i++)
            {
                RunSample(benchmark.Operation, options.WarmupOperations, measure: false);
            }

            var samples = new Sample[options.Samples];
            for (var i = 0; i < samples.Length; i++)
            {
                ForceCollection();
                samples[i] = RunSample(benchmark.Operation, options.Operations, measure: true);
            }

            var medianNanoseconds = Median(samples.Select(sample => sample.NanosecondsPerOperation));
            var medianThroughput = Median(samples.Select(sample => sample.OperationsPerSecond)) / 1_000_000d;
            var medianAllocation = Median(samples.Select(sample => sample.BytesPerOperation));
            var checksum = samples[^1].Checksum;
            Console.WriteLine(
                $"{benchmark.Name,-32} {medianNanoseconds,10:N1} {medianThroughput,12:N2} {medianAllocation,11:N2}  0x{checksum:X8}");
        }

        Console.WriteLine();
        Console.WriteLine($"sink=0x{sink:X8}");
        return 0;
    }

    private static IReadOnlyList<BenchmarkCase> Benchmarks { get; } =
    [
        new("Decode / generated NOP", DecodeNop),
        new("Construct / A64Instruction", ConstructInstruction),
        new("Catalog / exact lookup", CatalogExactLookup),
        new("Decode raw / generated load", DecodeRawGeneratedLoad),
        new("Decode raw / generated NEON", DecodeRawGeneratedNeon),
        new("Decode view / generated load", DecodeViewGeneratedLoad),
        new("Decode view / generated NEON", DecodeViewGeneratedNeon),
        new("Decode / generated load", DecodeGeneratedLoad),
        new("Decode / generated NEON", DecodeGeneratedNeon),
        new("Decode / generated SVE", DecodeGeneratedSve),
        new("Catalog / lookup", CatalogLookup),
        new("Catalog / decode fields", CatalogDecodeFields),
        new("Encode / generated ADD", EncodeGeneratedAdd),
        new("Encode / generated load", EncodeGeneratedLoad),
        new("Encode / raw fields", EncodeRawFields),
        new("Encode / raw field span", EncodeRawFieldSpan),
        new("Decode / byte span", DecodeByteSpan),
        new("Encode / byte span", EncodeByteSpan),
    ];

    private static uint DecodeNop()
    {
        return A64Decoder.TryDecode(0xD503201Fu, 0, AllFeatures, out var instruction, out _)
            ? instruction.Encoding
            : 0;
    }

    private static uint ConstructInstruction()
    {
        var instruction = new A64Instruction(
            A64InstructionId.Generated,
            "hint",
            Array.Empty<A64Operand>(),
            0xD503201Fu,
            0);
        return instruction.Encoding;
    }

    private static uint CatalogExactLookup()
    {
        return A64InstructionCatalog.TryLookup(0xD503201Fu, AllFeatures, out var info)
            ? info.Value
            : 0;
    }

    private static uint DecodeGeneratedLoad()
    {
        return A64Decoder.TryDecode(0xB9401020u, 4, BaseFeatures, out var instruction, out _)
            ? instruction.Encoding ^ (uint)instruction.Operands.Count
            : 0;
    }

    private static uint DecodeRawGeneratedLoad()
    {
        return A64Decoder.TryDecodeRaw(0xB9401020u, 4, BaseFeatures, out var instruction, out _)
            ? instruction.Encoding ^ (uint)instruction.FieldCount
            : 0;
    }

    private static uint DecodeRawGeneratedNeon()
    {
        return A64Decoder.TryDecodeRaw(0x4EA28420u, 0, NeonFeatures, out var instruction, out _)
            ? instruction.Encoding ^ (uint)instruction.FieldCount
            : 0;
    }

    private static uint DecodeViewGeneratedLoad()
    {
        return A64Decoder.TryDecodeView(
                0xB9401020u,
                4,
                BaseFeatures,
                ViewOperands,
                out var instruction,
                out _)
            ? instruction.Encoding ^ (uint)instruction.OperandCount
            : 0;
    }

    private static uint DecodeViewGeneratedNeon()
    {
        return A64Decoder.TryDecodeView(
                0x4EA28420u,
                0,
                NeonFeatures,
                ViewOperands,
                out var instruction,
                out _)
            ? instruction.Encoding ^ (uint)instruction.OperandCount
            : 0;
    }

    private static uint DecodeGeneratedNeon()
    {
        return A64Decoder.TryDecode(0x4EA28420u, 0, NeonFeatures, out var instruction, out _)
            ? instruction.Encoding ^ (uint)instruction.Operands.Count
            : 0;
    }

    private static uint DecodeGeneratedSve()
    {
        return A64Decoder.TryDecode(0xA520E040u, 0, SveFeatures, out var instruction, out _)
            ? instruction.Encoding ^ (uint)instruction.Operands.Count
            : 0;
    }

    private static uint CatalogLookup()
    {
        return A64InstructionCatalog.TryLookup(0xB9401020u, BaseFeatures, out var info)
            ? info.Value
            : 0;
    }

    private static uint CatalogDecodeFields()
    {
        if (!A64InstructionCatalog.TryDecode(0xB9401020u, BaseFeatures, out var decoded))
        {
            return 0;
        }

        return decoded.Encoding.Value ^ (uint)decoded.Fields.Count;
    }

    private static uint EncodeGeneratedAdd()
    {
        return A64Encoder.TryEncode(GeneratedAdd, BaseFeatures, out var encoding, out _)
            ? encoding
            : 0;
    }

    private static uint EncodeGeneratedLoad()
    {
        return A64Encoder.TryEncode(GeneratedLoad, BaseFeatures, out var encoding, out _)
            ? encoding
            : 0;
    }

    private static uint EncodeRawFields()
    {
        return A64InstructionCatalog.TryEncodeFields(
                "ADDXri",
                RawAddFields,
                BaseFeatures,
                out var encoding,
                out _)
            ? encoding
            : 0;
    }

    private static uint EncodeRawFieldSpan()
    {
        return A64InstructionCatalog.TryEncodeFields(
                "ADDXri",
                RawAddFieldValues,
                BaseFeatures,
                out var encoding,
                out _)
            ? encoding
            : 0;
    }

    private static uint DecodeByteSpan()
    {
        return A64Decoder.TryDecode(LoadBytes, 4, BaseFeatures, out var instruction, out _)
            ? instruction.Encoding ^ (uint)instruction.Operands.Count
            : 0;
    }

    private static uint EncodeByteSpan()
    {
        if (!A64Encoder.TryEncode(GeneratedLoad, EncodeDestination, BaseFeatures, out _))
        {
            return 0;
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(EncodeDestination);
    }

    private static A64Instruction DecodeRequired(uint encoding, ulong address, A64FeatureSet features)
    {
        if (A64Decoder.TryDecode(encoding, address, features, out var instruction, out var diagnostic))
        {
            return instruction;
        }

        throw new InvalidOperationException($"Benchmark setup decode failed: {diagnostic}");
    }

    private static Sample RunSample(Func<uint> operation, int operations, bool measure)
    {
        var checksum = 0x811C9DC5u;
        var startAllocations = measure ? GC.GetAllocatedBytesForCurrentThread() : 0;
        var start = measure ? Stopwatch.GetTimestamp() : 0;
        for (var i = 0; i < operations; i++)
        {
            checksum = unchecked((checksum * 16777619u) ^ operation());
        }

        if (!measure)
        {
            sink ^= checksum;
            return default;
        }

        var elapsedTicks = Stopwatch.GetTimestamp() - start;
        var elapsedSeconds = elapsedTicks / (double)Stopwatch.Frequency;
        var allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - startAllocations;
        sink ^= checksum;
        return new Sample(
            elapsedSeconds * 1_000_000_000d / operations,
            operations / elapsedSeconds,
            allocatedBytes / (double)operations,
            checksum);
    }

    private static void ForceCollection()
    {
        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
    }

    private static double Median(IEnumerable<double> values)
    {
        var ordered = values.OrderBy(value => value).ToArray();
        var middle = ordered.Length / 2;
        return ordered.Length % 2 == 0
            ? (ordered[middle - 1] + ordered[middle]) / 2d
            : ordered[middle];
    }

    private static Options ParseOptions(string[] args)
    {
        var operations = DefaultOperations;
        var warmup = DefaultWarmupOperations;
        var samples = DefaultSamples;
        var warmupSamples = 1;
        var showHelp = false;

        foreach (var argument in args)
        {
            if (argument is "-h" or "--help")
            {
                showHelp = true;
                continue;
            }

            var separator = argument.IndexOf('=');
            if (separator < 0)
            {
                throw new ArgumentException($"Expected --name=value, got '{argument}'.");
            }

            var name = argument[..separator];
            if (!int.TryParse(argument[(separator + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
                || value < 1)
            {
                throw new ArgumentException($"Expected a positive integer for '{name}'.");
            }

            switch (name)
            {
                case "--operations":
                    operations = value;
                    break;
                case "--warmup":
                    warmup = value;
                    break;
                case "--samples":
                    samples = value;
                    break;
                case "--warmup-samples":
                    warmupSamples = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown option '{name}'.");
            }
        }

        return new Options(operations, warmup, samples, warmupSamples, showHelp);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: dotnet run --project tools/AsmStone.Benchmark -c Release -- [options]");
        Console.WriteLine("Options: --operations=N --warmup=N --samples=N --warmup-samples=N");
    }

    private readonly record struct BenchmarkCase(string Name, Func<uint> Operation);

    private readonly record struct Options(
        int Operations,
        int WarmupOperations,
        int Samples,
        int WarmupSamples,
        bool ShowHelp);

    private readonly record struct Sample(
        double NanosecondsPerOperation,
        double OperationsPerSecond,
        double BytesPerOperation,
        uint Checksum);
}
