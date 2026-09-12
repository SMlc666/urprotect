using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Pipeline;

namespace UrProtect.Core.Tests;

public sealed class NoOpPipelineTests
{
    [Fact]
    public void EmitsByteIdenticalOutput()
    {
        var input = ElfFixture.MinimalPie();

        var result = new NoOpPipeline().Validate(
            input,
            emitOutput: true,
            analyzeInstructions: false);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.OutputBytes);
        Assert.Equal(input, result.OutputBytes);
    }

    [Fact]
    public void AnalyzesOnlyTheExecutableEntryRegionByDefault()
    {
        var result = new NoOpPipeline().Validate(ElfFixture.MinimalPie());

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.Analysis);
        Assert.Contains(result.Analysis!.Candidates, candidate => candidate.VirtualAddress == 0x1200);
    }

    [Fact]
    public void PreservesUnixModeForCopiedArtifact()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Directory.CreateTempSubdirectory("urprotect-mode-");
        try
        {
            var inputPath = Path.Combine(directory.FullName, "input.elf");
            var outputPath = Path.Combine(directory.FullName, "output.elf");
            File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
            var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(inputPath, mode);

            var result = new NoOpPipeline().ValidateAndCopy(inputPath, outputPath, analyzeInstructions: false);

            Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
            Assert.Equal(mode, File.GetUnixFileMode(outputPath));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void DecoderBackendFailureFailsClosed()
    {
        var decoder = new AsmStoneAdapter((encoding, address) =>
            Aarch64DecodeResult.BackendUnavailable(encoding, address));

        var result = new NoOpPipeline(decoder).Validate(ElfFixture.MinimalPie());

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.AsmStoneUnavailable);
    }

    [Fact]
    public void DoesNotWriteAnOutputForInvalidInput()
    {
        var result = new NoOpPipeline().Validate(
            new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' },
            emitOutput: true,
            analyzeInstructions: false);

        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
    }

    [Fact]
    public void CopiesValidatedInputThroughAnAtomicOutputPath()
    {
        var directory = Directory.CreateTempSubdirectory("urprotect-test-");
        try
        {
            var inputPath = Path.Combine(directory.FullName, "input.elf");
            var outputPath = Path.Combine(directory.FullName, "output.elf");
            var input = ElfFixture.MinimalPie();
            File.WriteAllBytes(inputPath, input);

            var result = new NoOpPipeline().ValidateAndCopy(inputPath, outputPath, analyzeInstructions: false);

            Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
            Assert.Equal(input, File.ReadAllBytes(outputPath));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void CopyPathCanUseTheAlreadyReadInputSnapshot()
    {
        var directory = Directory.CreateTempSubdirectory("urprotect-snapshot-");
        try
        {
            var inputPath = Path.Combine(directory.FullName, "input.elf");
            var outputPath = Path.Combine(directory.FullName, "output.elf");
            var source = ElfFixture.MinimalPie();
            File.WriteAllBytes(inputPath, source);

            var invalidSnapshot = new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' };
            var result = new NoOpPipeline().ValidateAndCopy(
                inputPath,
                outputPath,
                analyzeInstructions: false,
                inputOverride: invalidSnapshot);

            Assert.False(result.IsSuccess);
            Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InputTooSmall);
            Assert.False(File.Exists(outputPath));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
}
