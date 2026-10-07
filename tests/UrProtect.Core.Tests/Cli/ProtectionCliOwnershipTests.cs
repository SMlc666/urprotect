using System.Text.Json;
using UrProtect.Cli.Commands;

namespace UrProtect.Core.Tests.Cli;

public sealed class ProtectionCliOwnershipTests
{
    private const string VersionedFixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";

    [Fact]
    [Trait("Category", "Protect")]
    public void CliProtectPreservesExecutableModeAndPublishesReportAtomically()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var outputPath = directory.Path("protected.elf");
        var reportPath = directory.Path("protected.json");
        var source = WithProgramHeaderSlot(ReadVersionedFixture());
        File.WriteAllBytes(inputPath, source);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(inputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        var exitCode = CliApplication.Run(
            new[]
            {
                "protect", inputPath, "--output", outputPath,
                "--function-id", "symtab:23", "--pass", "control-flow-flattening",
                "--json", reportPath,
            },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.True(File.Exists(outputPath));
        Assert.True(File.Exists(reportPath));
        if (!OperatingSystem.IsWindows())
        {
            Assert.True((File.GetUnixFileMode(outputPath) & UnixFileMode.UserExecute) != 0);
        }

        using var report = JsonDocument.Parse(File.ReadAllText(reportPath));
        Assert.True(report.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(
            "table=symtab, index=23",
            report.RootElement.GetProperty("selectors")[0].GetString());
        Assert.True(report.RootElement.GetProperty("output").GetProperty("published").GetBoolean());
        var functionReport = Assert.Single(report.RootElement.GetProperty("functions").EnumerateArray());
        Assert.True(functionReport.GetProperty("resourcePlan").GetProperty("sufficient").GetBoolean());
        Assert.Empty(Directory.GetFiles(directory.RootPath, "*.tmp"));
    }

    private static byte[] ReadVersionedFixture() => File.ReadAllBytes(VersionedFixturePath);

    private static byte[] WithProgramHeaderSlot(byte[] source)
    {
        var result = source.ToArray();
        var noteHeaderOffset = UrProtect.Core.StructuralElf.ElfConstants.HeaderSize64
            + (3 * UrProtect.Core.StructuralElf.ElfConstants.ProgramHeaderSize64);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            result.AsSpan(noteHeaderOffset), UrProtect.Core.StructuralElf.ElfConstants.PtNull);
        return result;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-protect-");

        public string RootPath => directory.FullName;

        public string Path(string fileName) => System.IO.Path.Combine(directory.FullName, fileName);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
