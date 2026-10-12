using System.Text.Json;
using UrProtect.Cli.Commands;
using UrProtect.Cli.Rendering;
using UrProtect.Core.Application.Validation;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Cli;

public sealed class ElfSymbolVersionReportTests
{
    private const string FixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";

    [Fact]
    public void ProjectsDefinedVersionCountInStableReportSummary()
    {
        var bytes = ReadVersionedFixture();
        var validation = new ValidationWorkflow().ValidateStructurally(bytes);
        var report = ProductReportFactory.Create(
            CliApplication.ToolVersion,
            bytes,
            validation,
            outputRequested: false,
            outputPublished: false);

        using var document = JsonDocument.Parse(ProductReportFactory.Serialize(report));
        Assert.Equal(
            3,
            document.RootElement
                .GetProperty("summary")
                .GetProperty("versionDefinitions")
                .GetInt32());
    }

    private static byte[] ReadVersionedFixture() => File.ReadAllBytes(FixturePath);
}
