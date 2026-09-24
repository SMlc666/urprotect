using System.Collections.Concurrent;
using UrProtect.Core.Elf;
using UrProtect.Core.Pack;
using UrProtect.Core.Pipeline;

namespace UrProtect.Core.Tests;

public sealed class ConcurrencyRegressionTests
{
    [Fact]
    [Trait("Category", "Concurrency")]
    public async Task ParserProducesTheSerialResultForSharedImmutableInput()
    {
        var input = ElfFixture.MinimalPie();
        var serial = ElfParser.Parse(input);
        var workers = ReadPositiveInt("URPROTECT_STRESS_WORKERS", 4, 32);
        var iterations = ReadPositiveInt("URPROTECT_STRESS_ITERATIONS", 8, 256);
        var failures = new ConcurrentQueue<string>();

        await Task.WhenAll(
            Enumerable.Range(0, workers).Select(worker => Task.Run(() =>
            {
                for (var iteration = 0; iteration < iterations; iteration++)
                {
                    var result = ElfParser.Parse(input);
                    var sameFileShape = serial.File is null
                        ? result.File is null
                        : result.File is not null
                            && serial.File.ProgramHeaders.SequenceEqual(result.File.ProgramHeaders);
                    if (!serial.Diagnostics.SequenceEqual(result.Diagnostics) || !sameFileShape)
                    {
                        failures.Enqueue($"worker={worker} iteration={iteration}");
                    }
                }
            })));

        Assert.Empty(failures);
    }

    [Fact]
    [Trait("Category", "Concurrency")]
    public async Task FrameEncodingIsDeterministicAcrossConcurrentCalls()
    {
        var source = ElfFixture.MinimalPie();
        var expected = Encode(source, frameOffset: 0x4000);
        var workers = ReadPositiveInt("URPROTECT_STRESS_WORKERS", 4, 32);
        var iterations = ReadPositiveInt("URPROTECT_STRESS_ITERATIONS", 8, 256);
        var failures = new ConcurrentQueue<string>();

        await Task.WhenAll(
            Enumerable.Range(0, workers).Select(worker => Task.Run(() =>
            {
                for (var iteration = 0; iteration < iterations; iteration++)
                {
                    var actual = Encode(source, frameOffset: 0x4000);
                    if (!expected.SequenceEqual(actual))
                    {
                        failures.Enqueue($"worker={worker} iteration={iteration}");
                    }
                }
            })));

        Assert.Empty(failures);
    }

    [Fact]
    [Trait("Category", "Concurrency")]
    public async Task NoOpPipelineKeepsIndependentOutputsByteIdentical()
    {
        var input = ElfFixture.MinimalPie();
        var workers = ReadPositiveInt("URPROTECT_STRESS_WORKERS", 4, 32);
        var iterations = ReadPositiveInt("URPROTECT_STRESS_ITERATIONS", 8, 256);
        var failures = new ConcurrentQueue<string>();

        await Task.WhenAll(
            Enumerable.Range(0, workers).Select(worker => Task.Run(() =>
            {
                for (var iteration = 0; iteration < iterations; iteration++)
                {
                    var result = new NoOpPipeline().Validate(input, emitOutput: true, analyzeInstructions: false);
                    if (!result.IsSuccess || result.OutputBytes is null || !input.SequenceEqual(result.OutputBytes))
                    {
                        failures.Enqueue($"worker={worker} iteration={iteration}");
                    }
                }
            })));

        Assert.Empty(failures);
    }

    private static byte[] Encode(byte[] source, ulong frameOffset)
    {
        var encoded = PayloadFrameCodec.TryEncode(
            source,
            frameOffset,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            out var frame,
            out var diagnostics);
        TestAssertions.Success(encoded, diagnostics, "concurrent frame encoding");
        return frame!.FrameBytes;
    }

    private static int ReadPositiveInt(string name, int fallback, int maximum)
    {
        return int.TryParse(Environment.GetEnvironmentVariable(name), out var value)
            ? Math.Clamp(value, 1, maximum)
            : fallback;
    }
}
