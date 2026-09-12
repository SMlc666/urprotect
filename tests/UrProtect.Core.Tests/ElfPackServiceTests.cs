using UrProtect.Core.Diagnostics;
using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

public sealed class ElfPackServiceTests
{
    [Fact]
    [Trait("Category", "PackWrapper")]
    public void PacksValidatedPieIntoAWrapperAndPreservesSourcePayload()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        var source = ElfFixture.MinimalPie();
        var launcher = ElfFixture.StaticPieLauncher();
        File.WriteAllBytes(inputPath, source);
        File.WriteAllBytes(launcherPath, launcher);

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.Equal(outputPath, result.OutputPath);
        var wrapper = File.ReadAllBytes(outputPath);
        Assert.NotEqual(source, wrapper);
        Assert.Equal((ushort)1, result.LauncherAbiVersion);
        Assert.Equal((ushort)1, result.FrameVersion);
        Assert.NotNull(result.LauncherSha256);
        var payload = PayloadFrameCodec.ReadWrapper(wrapper, new PayloadFrameLimits());
        Assert.True(payload.IsSuccess, string.Join(Environment.NewLine, payload.Diagnostics));
        Assert.Equal(source, payload.SourceBytes);
    }

    [Fact]
    [Trait("Category", "PackWrapper")]
    public void ProducesDeterministicWrapperBytesForTheSameInputs()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var launcherPath = directory.Path("launcher.elf");
        var firstOutputPath = directory.Path("wrapped-first.elf");
        var secondOutputPath = directory.Path("wrapped-second.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var first = new ElfPackService().Pack(inputPath, firstOutputPath, launcherPath);
        var second = new ElfPackService().Pack(inputPath, secondOutputPath, launcherPath);

        Assert.True(first.IsSuccess, string.Join(Environment.NewLine, first.Diagnostics));
        Assert.True(second.IsSuccess, string.Join(Environment.NewLine, second.Diagnostics));
        Assert.Equal(File.ReadAllBytes(firstOutputPath), File.ReadAllBytes(secondOutputPath));
        Assert.Equal(first.WrapperSha256, second.WrapperSha256);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsSharedObjectInputWithoutPublishingOutput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.so");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, RemoveInterpreter(ElfFixture.MinimalPie()));
        File.WriteAllBytes(launcherPath, ElfFixture.MinimalPie());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedPackInput);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsAnUnmarkedStaticPieLauncherWithoutPublishingOutput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher(includeMarker: false));

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.LauncherUnavailable);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsDynamicLauncherWithoutPublishingOutput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        File.WriteAllBytes(launcherPath, ElfFixture.MinimalPie());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.LauncherUnavailable);
        Assert.False(File.Exists(outputPath));
    }


    [Fact]
    [Trait("Category", "PackCli")]
    public void RejectsConflictingOutputPathBeforeReadingInput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());

        var result = new ElfPackService().Pack(inputPath, inputPath, inputPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict);
    }

    private static byte[] RemoveInterpreter(byte[] source)
    {
        var copy = source.ToArray();
        copy.AsSpan(232, 56).Clear();
        copy.AsSpan(24, 8).Clear();
        return copy;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-pack-");

        public string Path(string name) => System.IO.Path.Combine(directory.FullName, name);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
