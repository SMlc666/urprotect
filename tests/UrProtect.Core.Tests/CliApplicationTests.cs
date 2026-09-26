using System.Security.Cryptography;
using System.Text.Json;
using UrProtect.Cli;
using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

public sealed class CliApplicationTests
{
    private static readonly string[] UnknownArgumentArgs = { "validate", "input.elf", "--unknown" };
    private static readonly string[] MissingInputArgs = { "validate", "/tmp/urprotect-does-not-exist.elf" };
    private static readonly string[] ThreadLifetimeOuterArgs =
        { "pack", "missing.so", "--output", "out", "--launcher", "launcher", "--thread-lifetime" };

    [Fact]
    [Trait("Category", "Cli")]
    public void WritesSchemaVersionOneJsonToStdout()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var input = ElfFixture.MinimalPie();
        File.WriteAllBytes(inputPath, input);
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--json", "-", "--no-analysis" },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.Empty(stderr.ToString());
        using var document = JsonDocument.Parse(stdout.ToString());
        var root = document.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(CliApplication.ToolVersion, root.GetProperty("toolVersion").GetString());
        Assert.True(root.GetProperty("success").GetBoolean());
        Assert.Equal(input.Length, root.GetProperty("input").GetProperty("byteLength").GetInt32());
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant(),
            root.GetProperty("input").GetProperty("sha256").GetString());
        Assert.Equal("ET_DYN", root.GetProperty("elf").GetProperty("type").GetString());
        Assert.False(root.TryGetProperty("output", out _));
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void ReportsEtExecTypeAndKindInJsonAndHumanOutput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input-exec.elf");
        File.WriteAllBytes(inputPath, ElfFixture.DynamicExecPayload());
        using var jsonStdout = new StringWriter();
        using var jsonStderr = new StringWriter();

        var jsonExitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--json", "-", "--no-analysis" },
            jsonStdout,
            jsonStderr);

        Assert.Equal((int)ProductExitCode.Success, jsonExitCode);
        Assert.Empty(jsonStderr.ToString());
        using var document = JsonDocument.Parse(jsonStdout.ToString());
        Assert.Equal("ET_EXEC", document.RootElement.GetProperty("elf").GetProperty("type").GetString());
        Assert.Equal("DynamicExecutable", document.RootElement.GetProperty("elf").GetProperty("kind").GetString());

        using var humanStdout = new StringWriter();
        using var humanStderr = new StringWriter();
        var humanExitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--no-analysis" },
            humanStdout,
            humanStderr);

        Assert.Equal((int)ProductExitCode.Success, humanExitCode);
        Assert.Empty(humanStderr.ToString());
        Assert.Contains("Validated AArch64 ET_EXEC DynamicExecutable", humanStdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void WritesAtomicJsonReportAndByteIdenticalCopy()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var copyPath = directory.Path("copy.elf");
        var reportPath = directory.Path("report.json");
        var input = ElfFixture.MinimalPie();
        File.WriteAllBytes(inputPath, input);
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[]
            {
                "validate", inputPath, "--copy", copyPath, "--json", reportPath, "--no-analysis",
            },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.True(File.Exists(reportPath));
        Assert.Equal(input, File.ReadAllBytes(copyPath));
        using var document = JsonDocument.Parse(File.ReadAllText(reportPath));
        var output = document.RootElement.GetProperty("output");
        Assert.True(output.GetProperty("requested").GetBoolean());
        Assert.True(output.GetProperty("published").GetBoolean());
        Assert.True(output.GetProperty("byteIdentical").GetBoolean());
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant(),
            output.GetProperty("sha256").GetString());
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void EmitsFailureReportWithoutPublishingAReportFile()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("invalid.elf");
        File.WriteAllBytes(inputPath, new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' });
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--json", "-" },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Validation, exitCode);
        Assert.Empty(stderr.ToString());
        using var document = JsonDocument.Parse(stdout.ToString());
        Assert.False(document.RootElement.GetProperty("success").GetBoolean());
        Assert.Contains(
            document.RootElement.GetProperty("diagnostics").EnumerateArray(),
            diagnostic => diagnostic.GetProperty("code").GetString() == "InputTooSmall");
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void DoesNotPublishJsonFileForInvalidInput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("invalid.elf");
        var reportPath = directory.Path("report.json");
        File.WriteAllBytes(inputPath, new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' });
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--json", reportPath },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Validation, exitCode);
        Assert.False(File.Exists(reportPath));
        Assert.Contains("InputTooSmall", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void ReturnsUsageCodeForUnknownArguments()
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            UnknownArgumentArgs,
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Usage, exitCode);
        Assert.Contains("unknown argument", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Usage:", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void ThreadLifetimeFlagRequiresTheHostContextProfile()
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            ThreadLifetimeOuterArgs,
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Usage, exitCode);
        Assert.Contains("requires --profile host-context-entry", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void ReturnsFileSystemCodeForMissingInput()
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            MissingInputArgs,
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.FileSystem, exitCode);
        Assert.Contains("InputIoFailure", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void ReturnsUsageCodeWhenAnOptionValueIsMissing()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--json", "--no-analysis" },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Usage, exitCode);
        Assert.Contains("unknown argument", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void MapsUnexpectedOutputWriterFailureToInternalExitCode()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--no-analysis" },
            new ThrowingWriter(),
            stderr);

        Assert.Equal((int)ProductExitCode.Internal, exitCode);
        Assert.Contains("InternalFailure", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "PackCli")]
    public void PacksWithJsonReportUsingTheExplicitLauncher()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        var reportPath = directory.Path("pack.json");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[]
            {
                "pack", inputPath, "--output", outputPath, "--launcher", launcherPath,
                "--json", reportPath,
            },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.True(File.Exists(outputPath));
        using var document = JsonDocument.Parse(File.ReadAllText(reportPath));
        Assert.True(document.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("deflate", document.RootElement.GetProperty("payload").GetProperty("compression").GetString());
        Assert.True(document.RootElement.GetProperty("output").GetProperty("published").GetBoolean());
        Assert.Equal(LauncherContract.AbiVersion, document.RootElement.GetProperty("payload").GetProperty("launcherAbiVersion").GetInt32());
        Assert.Equal(PayloadFrameCodec.CurrentFormatVersion, document.RootElement.GetProperty("payload").GetProperty("frameVersion").GetInt32());
        Assert.Equal("outer-execveat", document.RootElement.GetProperty("payload").GetProperty("profile").GetString());
        Assert.Equal(LauncherContract.Marker, document.RootElement.GetProperty("payload").GetProperty("launcherMarker").GetString());
        Assert.False(string.IsNullOrWhiteSpace(document.RootElement.GetProperty("payload").GetProperty("launcherSha256").GetString()));
    }

    [Fact]
    [Trait("Category", "PackCli")]
    public void UsesProfileAwareHumanSummaryWhenPackingDynamicEtExec()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input-exec.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped-exec.elf");
        File.WriteAllBytes(inputPath, ElfFixture.DynamicExecPayload());
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "pack", inputPath, "--output", outputPath, "--launcher", launcherPath },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.Empty(stderr.ToString());
        Assert.Contains("Packed AArch64 payload for outer-execveat", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "PackCli")]
    public void RequiresTheNativeLauncherForPack()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "pack", inputPath, "--output", outputPath },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Validation, exitCode);
        Assert.Contains("LauncherUnavailable", stderr.ToString(), StringComparison.Ordinal);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    [Trait("Category", "PackCli")]
    public void DoesNotPublishWrapperForInvalidPackInput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("invalid.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' });
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "pack", inputPath, "--output", outputPath, "--launcher", launcherPath },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Validation, exitCode);
        Assert.False(File.Exists(outputPath));
        Assert.Contains("InputTooSmall", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Report")]
    public void SerializesTheSameReportForRepeatedRuns()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        var first = RunJson(inputPath);
        var second = RunJson(inputPath);

        Assert.Equal(first, second);
    }

    private static string RunJson(string inputPath)
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        var exitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--json", "-", "--no-analysis" },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        return stdout.ToString();
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-cli-");

        public string Path(string fileName) => System.IO.Path.Combine(directory.FullName, fileName);

        public void Dispose() => directory.Delete(recursive: true);
    }

    private sealed class ThrowingWriter : StringWriter
    {
        public override void WriteLine(string? value) => throw new InvalidOperationException("synthetic writer failure");
    }
}
