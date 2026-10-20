using System.Security.Cryptography;
using System.Text.Json;
using UrProtect.Cli.Commands;
using UrProtect.Core.ArtifactProtocol;

namespace UrProtect.Core.Tests.Cli;

public sealed class CliApplicationTests
{
    private const string VersionedFixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";
    private static readonly string[] UnknownArgumentArgs = { "validate", "input.elf", "--unknown" };
    private static readonly string[] MissingInputArgs = { "validate", "/tmp/urprotect-does-not-exist.elf" };
    private static readonly string[] ThreadLifetimeOuterArgs =
        { "pack", "missing.so", "--output", "out", "--launcher", "launcher", "--thread-lifetime" };
    private static readonly string[] HelpArgs = { "--help" };

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
            new[] { "validate", inputPath, "--json", "-" },
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
        Assert.Equal("structural", root.GetProperty("summary").GetProperty("analysisMode").GetString());
        Assert.Equal(0, root.GetProperty("summary").GetProperty("analysisCandidates").GetInt32());
        Assert.False(root.TryGetProperty("output", out _));
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void ObserveAnalysisFlagEnablesOnlyTheObservationPass()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[] { "validate", inputPath, "--json", "-", "--observe-analysis" },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.Empty(stderr.ToString());
        using var document = JsonDocument.Parse(stdout.ToString());
        var summary = document.RootElement.GetProperty("summary");
        Assert.Equal("observation-only", summary.GetProperty("analysisMode").GetString());
        Assert.True(summary.GetProperty("analysisCandidates").GetInt32() > 0);
    }

    [Fact]
    [Trait("Category", "Cli")]
    public void HelpNamesStructuralDefaultAndExplicitObservationMode()
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(HelpArgs, stdout, stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.Contains("--observe-analysis", stdout.ToString(), StringComparison.Ordinal);
        Assert.Contains("Structural validation is the default", stdout.ToString(), StringComparison.Ordinal);
        Assert.Contains("--provider-file", stdout.ToString(), StringComparison.Ordinal);
        Assert.Contains("--provider-sha256", stdout.ToString(), StringComparison.Ordinal);
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
            new[] { "validate", inputPath, "--json", "-" },
            jsonStdout,
            jsonStderr);

        Assert.Equal((int)ProductExitCode.Success, jsonExitCode);
        Assert.Empty(jsonStderr.ToString());
        using var document = JsonDocument.Parse(jsonStdout.ToString());
        Assert.Equal("ET_EXEC", document.RootElement.GetProperty("elf").GetProperty("type").GetString());
        Assert.Equal("DynamicExecutable", document.RootElement.GetProperty("elf").GetProperty("kind").GetString());
        Assert.Equal("structural", document.RootElement.GetProperty("summary").GetProperty("analysisMode").GetString());

        using var humanStdout = new StringWriter();
        using var humanStderr = new StringWriter();
        var humanExitCode = CliApplication.Run(
            new[] { "validate", inputPath },
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
                "validate", inputPath, "--copy", copyPath, "--json", reportPath,
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
    [Trait("Category", "ProtectedImageCli")]
    public void ProtectImagePublishesFocusedRoleStageAndChecksumEvidence()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var artifactPath = directory.Path("protected-image.bin");
        var rolePath = directory.Path("protected-image.json");
        var manifestPath = directory.Path("SHA256SUMS");
        var stagePath = directory.Path("stage.json");
        var input = File.ReadAllBytes(VersionedFixturePath);
        File.WriteAllBytes(inputPath, input);
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[]
            {
                "protect-image", inputPath,
                "--artifact", artifactPath,
                "--role", rolePath,
                "--manifest", manifestPath,
                "--stage", stagePath,
                "--unit", "unit.fixture",
                "--profile", "outer-execveat",
                "--function-id", "symtab:23",
                "--pass", "control-flow-flattening",
                "--json", "-",
            },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.Empty(stderr.ToString());
        Assert.True(File.Exists(artifactPath));
        Assert.True(File.Exists(rolePath));
        Assert.True(File.Exists(manifestPath));
        Assert.True(File.Exists(stagePath));
        using var report = JsonDocument.Parse(stdout.ToString());
        Assert.True(report.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("protected-image", report.RootElement.GetProperty("role").GetProperty("artifactRole").GetString());
        Assert.Equal("passed", report.RootElement.GetProperty("stage").GetProperty("status").GetString());
        var stage = report.RootElement.GetProperty("stage");
        Assert.True(stage.GetProperty("analysisDurationMilliseconds").GetInt64() >= 0);
        Assert.True(stage.GetProperty("emissionDurationMilliseconds").GetInt64() >= 0);
        Assert.Contains("stage.json", File.ReadAllText(manifestPath), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "ProtectedImageCli")]
    public void ProtectImageAcceptsAllPinnedProviderFlagsAndRejectsPartialProviderConfiguration()
    {
        using var directory = new TemporaryDirectory();
        var sourcePath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "ExternalJumpTable", "liburprotect-external-table-consumer.so");
        var providerPath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "ExternalJumpTable", "liburprotect-jump-table-provider.so.1");
        var source = File.ReadAllBytes(sourcePath);
        var provider = File.ReadAllBytes(providerPath);
        var artifactPath = directory.Path("external-protected.bin");
        var rolePath = directory.Path("external-protected.json");
        const string unitId = "external-provider-cli.fixture";
        const string producerId = "urprotect.tests.external-provider-producer";
        const string rehydratorId = "urprotect.tests.external-provider-rehydrator";
        var producerBuildSha256 = new string('1', 64);
        var sourceSha256 = Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant();
        var requestSha256 = UrProtect.Core.Application.Protection.ProtectedImageCodec.ComputeRequestSha256(
            new[] { UrProtect.Core.Application.Protection.FunctionSelector.ByName("urp_entry") },
            new[] { UrProtect.Core.Application.Protection.ProtectionPass.ControlFlowFlattening });
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var success = CliApplication.Run(
            new[]
            {
                "protect-image", sourcePath,
                "--artifact", artifactPath,
                "--role", rolePath,
                "--manifest", directory.Path("external.sha256"),
                "--stage", directory.Path("external-stage.json"),
                "--unit", unitId,
                "--profile", "outer-execveat",
                "--producer-id", producerId,
                "--producer-build-sha256", producerBuildSha256,
                "--rehydrator", rehydratorId,
                "--source-sha256", sourceSha256,
                "--request-sha256", requestSha256,
                "--function", "urp_entry",
                "--pass", "control-flow-flattening",
                "--provider-file", providerPath,
                "--provider-soname", "liburprotect-jump-table-provider.so.1",
                "--provider-build-id", "99ed42afaf9f2a6b87adebeffecb0ad95d4b5f66",
                "--provider-sha256", Convert.ToHexString(SHA256.HashData(provider)).ToLowerInvariant(),
            },
            stdout,
            stderr);

        Assert.True(
            success == (int)ProductExitCode.Success,
            $"Unexpected CLI failure ({success}). stdout: {stdout} stderr: {stderr}");
        Assert.Empty(stderr.ToString());
        Assert.True(File.Exists(artifactPath));
        Assert.True(File.Exists(rolePath));

        var nativeImagePath = directory.Path("external-native-image.so");
        var nativeRolePath = directory.Path("external-native-image.json");
        var recordPath = directory.Path("external-rehydration.json");
        using var rehydrateStdout = new StringWriter();
        using var rehydrateStderr = new StringWriter();
        var rehydrate = CliApplication.Run(
            new[]
            {
                "rehydrate-image", sourcePath,
                "--artifact", artifactPath,
                "--native-image", nativeImagePath,
                "--role", nativeRolePath,
                "--record", recordPath,
                "--unit", unitId,
                "--profile", "outer-execveat",
                "--source-sha256", sourceSha256,
                "--request-sha256", requestSha256,
                "--producer-id", producerId,
                "--producer-build-sha256", producerBuildSha256,
                "--consumer-id", rehydratorId,
                "--consumer-build-sha256", new string('2', 64),
                "--provider-file", providerPath,
                "--provider-soname", "liburprotect-jump-table-provider.so.1",
                "--provider-build-id", "99ed42afaf9f2a6b87adebeffecb0ad95d4b5f66",
                "--provider-sha256", Convert.ToHexString(SHA256.HashData(provider)).ToLowerInvariant(),
            },
            rehydrateStdout,
            rehydrateStderr);
        Assert.True(
            rehydrate == (int)ProductExitCode.Success,
            $"Unexpected rehydration CLI failure ({rehydrate}). stdout: {rehydrateStdout} stderr: {rehydrateStderr}");
        Assert.True(File.Exists(nativeImagePath));
        Assert.True(File.Exists(nativeRolePath));
        Assert.True(File.Exists(recordPath));

        using var invalidStdout = new StringWriter();
        using var invalidStderr = new StringWriter();
        var partial = CliApplication.Run(
            new[]
            {
                "protect-image", sourcePath,
                "--artifact", directory.Path("partial.bin"),
                "--role", directory.Path("partial-role.json"),
                "--manifest", directory.Path("partial.sha256"),
                "--stage", directory.Path("partial-stage.json"),
                "--unit", "external-provider-cli.fixture",
                "--profile", "outer-execveat",
                "--function", "urp_entry",
                "--pass", "control-flow-flattening",
                "--provider-file", providerPath,
            },
            invalidStdout,
            invalidStderr);

        Assert.Equal((int)ProductExitCode.Usage, partial);
        Assert.Contains("must be supplied all together", invalidStderr.ToString(), StringComparison.Ordinal);
        Assert.False(File.Exists(directory.Path("partial.bin")));

        var partialNativeImage = directory.Path("partial-native.so");
        using var partialRehydrateStdout = new StringWriter();
        using var partialRehydrateStderr = new StringWriter();
        var partialRehydrate = CliApplication.Run(
            new[]
            {
                "rehydrate-image", sourcePath,
                "--artifact", artifactPath,
                "--native-image", partialNativeImage,
                "--role", directory.Path("partial-native-role.json"),
                "--record", directory.Path("partial-rehydration.json"),
                "--unit", unitId,
                "--profile", "outer-execveat",
                "--source-sha256", sourceSha256,
                "--request-sha256", requestSha256,
                "--producer-id", producerId,
                "--producer-build-sha256", producerBuildSha256,
                "--consumer-id", rehydratorId,
                "--consumer-build-sha256", new string('2', 64),
                "--provider-file", providerPath,
            },
            partialRehydrateStdout,
            partialRehydrateStderr);

        Assert.Equal((int)ProductExitCode.Usage, partialRehydrate);
        Assert.Contains("must be supplied all together", partialRehydrateStderr.ToString(), StringComparison.Ordinal);
        Assert.False(File.Exists(partialNativeImage));
    }

    [Fact]
    [Trait("Category", "ProtectedImageCli")]
    public void ProtectImageRedactsProviderPathFromDiagnosticsAndReportText()
    {
        using var directory = new TemporaryDirectory();
        const string sentinel = "DO_NOT_REPORT_PROVIDER_PATH_9C41E2";
        var sourcePath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "ExternalJumpTable", "liburprotect-external-table-consumer.so");
        var providerFixturePath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "ExternalJumpTable", "liburprotect-jump-table-provider.so.1");
        var providerPath = directory.Path($"{sentinel}.so");
        var source = File.ReadAllBytes(sourcePath);
        var provider = File.ReadAllBytes(providerFixturePath);
        var artifactPath = directory.Path("redacted.bin");
        var rolePath = directory.Path("redacted-role.json");
        var stagePath = directory.Path("redacted-stage.json");
        const string unitId = "external-provider-redaction.fixture";
        const string producerId = "urprotect.tests.external-provider-producer";
        const string rehydratorId = "urprotect.tests.external-provider-rehydrator";
        var producerBuildSha256 = new string('1', 64);
        var sourceSha256 = Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant();
        var requestSha256 = UrProtect.Core.Application.Protection.ProtectedImageCodec.ComputeRequestSha256(
            new[] { UrProtect.Core.Application.Protection.FunctionSelector.ByName("urp_entry") },
            new[] { UrProtect.Core.Application.Protection.ProtectionPass.ControlFlowFlattening });
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[]
            {
                "protect-image", sourcePath,
                "--artifact", artifactPath,
                "--role", rolePath,
                "--manifest", directory.Path("redacted.sha256"),
                "--stage", stagePath,
                "--unit", unitId,
                "--profile", "outer-execveat",
                "--producer-id", producerId,
                "--producer-build-sha256", producerBuildSha256,
                "--rehydrator", rehydratorId,
                "--source-sha256", sourceSha256,
                "--request-sha256", requestSha256,
                "--function", "urp_entry",
                "--pass", "control-flow-flattening",
                "--provider-file", providerPath,
                "--provider-soname", "liburprotect-jump-table-provider.so.1",
                "--provider-build-id", "99ed42afaf9f2a6b87adebeffecb0ad95d4b5f66",
                "--provider-sha256", Convert.ToHexString(SHA256.HashData(provider)).ToLowerInvariant(),
                "--json", "-",
            },
            stdout,
            stderr);

        Assert.NotEqual((int)ProductExitCode.Success, exitCode);
        var stageReport = File.ReadAllText(stagePath);
        var reportText = stdout.ToString() + stderr.ToString() + stageReport;
        Assert.Contains("The bounded input could not be read.", reportText, StringComparison.Ordinal);
        Assert.DoesNotContain(sentinel, reportText, StringComparison.Ordinal);
        Assert.False(File.Exists(artifactPath));
    }

    [Fact]
    [Trait("Category", "ProtectedImageCli")]
    public void ProtectImageRetainsFailureStageWithoutPublishingPartialEvidence()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var artifactPath = directory.Path("protected-image.bin");
        var rolePath = directory.Path("protected-image.json");
        var manifestPath = directory.Path("SHA256SUMS");
        var stagePath = directory.Path("stage.json");
        File.WriteAllBytes(inputPath, File.ReadAllBytes(VersionedFixturePath));
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var exitCode = CliApplication.Run(
            new[]
            {
                "protect-image", inputPath,
                "--artifact", artifactPath,
                "--role", rolePath,
                "--manifest", manifestPath,
                "--stage", stagePath,
                "--unit", "unit.fixture",
                "--profile", "outer-execveat",
                "--source-sha256", new string('f', 64),
                "--function-id", "symtab:23",
                "--pass", "control-flow-flattening",
            },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Validation, exitCode);
        Assert.True(File.Exists(stagePath));
        Assert.False(File.Exists(artifactPath));
        Assert.False(File.Exists(rolePath));
        Assert.False(File.Exists(manifestPath));
        using var stage = JsonDocument.Parse(File.ReadAllText(stagePath));
        Assert.Equal("failed", stage.RootElement.GetProperty("status").GetString());
        Assert.Contains("ProtectedImageSourceMismatch", File.ReadAllText(stagePath), StringComparison.Ordinal);
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
            new[] { "validate", inputPath, "--json" },
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
            new[] { "validate", inputPath },
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
        Assert.Equal(PayloadFrameCodec.FormatVersion, document.RootElement.GetProperty("payload").GetProperty("frameVersion").GetInt32());
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
            new[] { "validate", inputPath, "--json", "-" },
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
