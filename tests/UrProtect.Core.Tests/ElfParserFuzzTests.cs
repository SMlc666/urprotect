using System.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class ElfParserFuzzTests
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParserNeverThrowsForBoundedRandomInputs()
    {
        var random = new Random(0xA64E1F);
        var stopwatch = Stopwatch.StartNew();
        var iterations = ReadIterationCount("URPROTECT_FUZZ_RANDOM_ITERATIONS", 512);

        for (var iteration = 0; iteration < iterations; iteration++)
        {
            var bytes = new byte[random.Next(0, 4097)];
            random.NextBytes(bytes);

            var exception = Record.Exception(() => ElfParser.Parse(bytes));

            Assert.Null(exception);
        }

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(10),
            $"bounded parser fuzz corpus exceeded the time budget: {stopwatch.Elapsed}");
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void ParserHandlesMutatedValidCorpusWithoutThrowing()
    {
        var random = new Random(0xE1F5AFE);
        var seed = ElfFixture.MinimalPie();
        var iterations = ReadIterationCount("URPROTECT_FUZZ_MUTATION_ITERATIONS", 256);

        for (var iteration = 0; iteration < iterations; iteration++)
        {
            var bytes = (byte[])seed.Clone();
            var mutationCount = random.Next(1, 16);
            for (var mutation = 0; mutation < mutationCount; mutation++)
            {
                bytes[random.Next(bytes.Length)] = (byte)random.Next(256);
            }

            var exception = Record.Exception(() => ElfParser.Parse(bytes));

            Assert.Null(exception);
        }
    }

    private static int ReadIterationCount(string variable, int fallback)
    {
        if (!int.TryParse(Environment.GetEnvironmentVariable(variable), out var value))
        {
            return fallback;
        }

        return Math.Clamp(value, 1, 100_000);
    }
}
