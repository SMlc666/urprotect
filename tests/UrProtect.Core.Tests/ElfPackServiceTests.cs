using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
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
        Assert.Equal(LauncherContract.AbiVersion, result.LauncherAbiVersion);
        Assert.Equal(PayloadFrameCodec.CurrentFormatVersion, result.FrameVersion);
        Assert.Equal(PayloadDispatchProfile.OuterExecveat, result.Profile);
        Assert.NotNull(result.LauncherSha256);
        var payload = PayloadFrameCodec.ReadWrapper(wrapper, new PayloadFrameLimits());
        Assert.True(payload.IsSuccess, string.Join(Environment.NewLine, payload.Diagnostics));
        Assert.Equal(source, payload.SourceBytes);
        Assert.NotNull(payload.Frame);
        Assert.Equal(PayloadFrameCodec.CurrentFormatVersion, payload.Frame!.FrameVersion);
        Assert.Equal(PayloadDispatchProfile.OuterExecveat, payload.Frame.Profile);
        Assert.Null(payload.Frame.HostContextMetadata);
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
    [Trait("Category", "PackHostContext")]
    public void PacksAHostContextEntryImageWithTheExplicitCurrentProfile()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("entry.so");
        var launcherPath = directory.Path("host-launcher.elf");
        var outputPath = directory.Path("host-packed.elf");
        File.WriteAllBytes(inputPath, RemoveInterpreter(ElfFixture.MinimalPie()));
        File.WriteAllBytes(
            launcherPath,
            ElfFixture.MinimalPie().Concat(System.Text.Encoding.ASCII.GetBytes(LauncherContract.HostContextMarker)).ToArray());

        var result = new ElfPackService().Pack(
            inputPath,
            outputPath,
            launcherPath,
            new ElfPackOptions(Profile: PayloadDispatchProfile.HostContextEntry));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.Equal(PayloadDispatchProfile.HostContextEntry, result.Profile);
        var payload = PayloadFrameCodec.ReadWrapper(File.ReadAllBytes(outputPath), new PayloadFrameLimits());
        Assert.True(payload.IsSuccess, string.Join(Environment.NewLine, payload.Diagnostics));
        Assert.Equal(PayloadDispatchProfile.HostContextEntry, payload.Frame!.Profile);
        Assert.Equal(HostContextContract.EntrySymbol, payload.Frame.HostContextMetadata!.EntryName);
        Assert.Equal(
            HostContextContract.MandatoryCapabilities,
            payload.Frame.HostContextMetadata.RequiredCapabilities);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void ThreadLifetimeOptInSetsOnlyTheRequiredFrameCapability()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("entry.so");
        var launcherPath = directory.Path("host-launcher.elf");
        var outputPath = directory.Path("host-threaded-packed.elf");
        File.WriteAllBytes(inputPath, RemoveInterpreter(ElfFixture.MinimalPie()));
        File.WriteAllBytes(
            launcherPath,
            ElfFixture.MinimalPie().Concat(System.Text.Encoding.ASCII.GetBytes(LauncherContract.HostContextMarker)).ToArray());

        var result = new ElfPackService().Pack(
            inputPath,
            outputPath,
            launcherPath,
            new ElfPackOptions(
                Profile: PayloadDispatchProfile.HostContextEntry,
                RequireThreadLifetime: true));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var payload = PayloadFrameCodec.ReadWrapper(File.ReadAllBytes(outputPath), new PayloadFrameLimits());
        Assert.True(payload.IsSuccess, string.Join(Environment.NewLine, payload.Diagnostics));
        Assert.Equal(
            HostContextContract.MandatoryCapabilities | HostContextCapability.ThreadLifetime,
            payload.Frame!.HostContextMetadata!.RequiredCapabilities);
    }

    [Fact]
    [Trait("Category", "PackWrapper")]
    public void RejectsThreadLifetimeOptInForOuterProfile()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var result = new ElfPackService().Pack(
            inputPath,
            outputPath,
            launcherPath,
            new ElfPackOptions(RequireThreadLifetime: true));

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedPackInput);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    [Trait("Category", "PackWrapper")]
    public void PacksStaticPieThroughTheOuterProfile()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("static-pie.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, ElfFixture.StaticPiePayload());
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var decoded = PayloadFrameCodec.ReadWrapper(File.ReadAllBytes(outputPath), new PayloadFrameLimits());
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        Assert.Equal(ElfFixture.StaticPiePayload(), decoded.SourceBytes);
        Assert.Equal(PayloadDispatchProfile.OuterExecveat, decoded.Frame!.Profile);
    }

    [Fact]
    [Trait("Category", "PackWrapper")]
    public void PacksDynamicEtExecThroughTheOuterProfile()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input-exec.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped-exec.elf");
        var source = ElfFixture.DynamicExecPayload();
        File.WriteAllBytes(inputPath, source);
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var decoded = PayloadFrameCodec.ReadWrapper(File.ReadAllBytes(outputPath), new PayloadFrameLimits());
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        Assert.Equal(source, decoded.SourceBytes);
        Assert.Equal(PayloadDispatchProfile.OuterExecveat, decoded.Frame!.Profile);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsStaticEtExecInputWithoutPublishingOutput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("static-exec.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, ElfFixture.StaticExecPayload());
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedPackInput);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsDynamicEtExecWithoutInterpreterWithoutPublishingOutput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("missing-interpreter.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        var source = ElfFixture.DynamicExecPayload();
        source.AsSpan(ElfFixture.InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        File.WriteAllBytes(inputPath, source);
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedPackInput);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsDynamicEtExecWithUnsupportedInterpreterWithoutPublishingOutput()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("unsupported-interpreter.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        var source = ElfFixture.DynamicExecPayload();
        var interpreterSize = checked((int)System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(
            source.AsSpan(ElfFixture.InterpreterProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize)));
        var replacement = System.Text.Encoding.ASCII.GetBytes("/lib/ld-invalid.so.1\0");
        Assert.True(replacement.Length <= interpreterSize);
        var interpreterBytes = source.AsSpan(ElfFixture.InterpreterOffset, interpreterSize);
        interpreterBytes.Clear();
        replacement.CopyTo(interpreterBytes);
        File.WriteAllBytes(inputPath, source);
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedInterpreter);
        Assert.False(File.Exists(outputPath));
    }

    [Theory]
    [InlineData(ElfConstants.DtRpath)]
    [InlineData(ElfConstants.DtRunPath)]
    [Trait("Category", "PackMalformed")]
    public void RejectsDynamicEtExecWithPayloadControlledSearchPathWithoutPublishingOutput(ulong searchPathTag)
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("path-search.elf");
        var launcherPath = directory.Path("launcher.elf");
        var outputPath = directory.Path("wrapped.elf");
        File.WriteAllBytes(inputPath, ElfFixture.DynamicExecWithSearchPath(searchPathTag));
        File.WriteAllBytes(launcherPath, ElfFixture.StaticPieLauncher());

        var result = new ElfPackService().Pack(inputPath, outputPath, launcherPath);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnsupportedPackInput);
        Assert.False(File.Exists(outputPath));
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
        copy.AsSpan(ElfFixture.InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        copy.AsSpan(ElfHeaderOffsets.Entry, sizeof(ulong)).Clear();
        return copy;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-pack-");

        public string Path(string name) => System.IO.Path.Combine(directory.FullName, name);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
