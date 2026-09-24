using System.Diagnostics;
using System.Text.Json;
using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

public sealed class ContractLayoutTests
{
    [Fact]
    [Trait("Category", "Contract")]
    public void NativeAndManagedFrameAndAbiContractsAgree()
    {
        var repositoryRoot = FindRepositoryRoot();
        var runtimeDirectory = Path.Combine(repositoryRoot, "native", "urprotect-runtime");
        var startInfo = new ProcessStartInfo
        {
            FileName = "make",
            Arguments = "-s contract-check",
            WorkingDirectory = runtimeDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(startInfo);
        Assert.NotNull(process);
        Assert.True(process!.WaitForExit(TimeSpan.FromSeconds(30)), "native contract probe timed out");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Assert.Equal(0, process.ExitCode);

        using var document = JsonDocument.Parse(output);
        var root = document.RootElement;
        Assert.Equal(
            HostContextContract.MinimumContextSize,
            root.GetProperty("hostContextSize").GetUInt32());
        Assert.Equal(
            HostContextContract.MinimumLaunchArgsSize,
            root.GetProperty("launchArgsSize").GetUInt32());
        Assert.Equal(
            HostContextContract.AbiVersion,
            root.GetProperty("hostAbiVersion").GetUInt32());
        Assert.Equal(
            PayloadFrameCodec.HeaderSize,
            root.GetProperty("frameV1HeaderSize").GetUInt16());
        Assert.Equal(
            PayloadFrameCodec.HostContextHeaderSize,
            root.GetProperty("frameV2HeaderSize").GetUInt16());
        Assert.Equal(
            PayloadFrameCodec.TrailerSize,
            root.GetProperty("frameTrailerSize").GetUInt16());
        Assert.Equal(
            PayloadFrameCodec.Sha256Size,
            root.GetProperty("frameSha256Size").GetUInt16());
        Assert.Equal(
            PayloadFrameCodec.HostContextAbiVersionOffset,
            root.GetProperty("v2AbiOffset").GetUInt16());
        Assert.Equal(
            PayloadFrameCodec.HostContextRequiredCapabilitiesOffset,
            root.GetProperty("v2CapabilitiesOffset").GetUInt16());
        Assert.Equal(
            PayloadFrameCodec.HostContextEntryNameSizeOffset,
            root.GetProperty("v2EntryNameSizeOffset").GetUInt16());

        Assert.True(
            string.IsNullOrWhiteSpace(error),
            $"native contract probe wrote stderr: {error}");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "UrProtect.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new InvalidOperationException("UrProtect.sln was not found from the test directory.");
    }
}
