using System.Text.Json;
using UrProtect.Cli;
using UrProtect.Core.Aarch64;
using UrProtect.Core.Elf;
using UrProtect.Core.Pipeline;

namespace UrProtect.Core.Tests;

public sealed class GoldenReportTests
{
    [Fact]
    [Trait("Category", "Report")]
    public void ValidSyntheticReportMatchesGoldenFile()
    {
        var input = ElfFixture.MinimalPie();
        var result = new NoOpPipeline().Validate(input, analyzeInstructions: false);

        Assert.Equal(
            ReadGolden("valid-synthetic.json"),
            ProductReportFactory.Serialize(ProductReportFactory.Create(
                CliApplication.ToolVersion,
                input,
                result,
                outputRequested: false,
                outputPublished: false)));
    }

    [Fact]
    [Trait("Category", "Report")]
    public void SectionlessStrippedReportMatchesGoldenFile()
    {
        var input = ElfFixture.MinimalPie();
        var result = new NoOpPipeline().Validate(input, analyzeInstructions: false);

        Assert.Equal(
            ReadGolden("stripped-synthetic.json"),
            ProductReportFactory.Serialize(ProductReportFactory.Create(
                CliApplication.ToolVersion,
                input,
                result,
                outputRequested: false,
                outputPublished: false)));
    }

    [Fact]
    [Trait("Category", "Report")]
    public void InvalidReportMatchesGoldenFile()
    {
        var input = new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' };
        var result = new NoOpPipeline().Validate(input, analyzeInstructions: false);

        Assert.Equal(
            ReadGolden("invalid-truncated.json"),
            ProductReportFactory.Serialize(ProductReportFactory.Create(
                CliApplication.ToolVersion,
                input,
                result,
                outputRequested: false,
                outputPublished: false)));
    }

    [Fact]
    [Trait("Category", "Report")]
    public void WarningReportMatchesGoldenDiagnosticVector()
    {
        var input = ElfFixture.MinimalPie();
        var decoder = new AsmStoneAdapter((encoding, address) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.UnknownEncoding,
            null,
            $"Synthetic unknown instruction 0x{encoding:X8} at 0x{address:X}."));
        var result = new NoOpPipeline(decoder).Validate(input);
        var report = ProductReportFactory.Create(
            CliApplication.ToolVersion,
            input,
            result,
            outputRequested: false,
            outputPublished: false);
        using var expected = JsonDocument.Parse(ReadGolden("warning-unknown-instruction.json"));

        Assert.Equal(expected.RootElement.GetProperty("success").GetBoolean(), report.Success);
        var expectedCodes = expected.RootElement
            .GetProperty("diagnosticCodes")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ToArray();
        Assert.Equal(
            expectedCodes,
            report.Diagnostics.Select(diagnostic => diagnostic.Code).ToArray());
    }

    private static string ReadGolden(string fileName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "GoldenReports", fileName))
            .TrimEnd('\r', '\n');
}
