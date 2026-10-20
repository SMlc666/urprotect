using System.Runtime.InteropServices;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using Xunit.Sdk;

namespace UrProtect.Core.Tests.Infrastructure;

public sealed class LinuxSafeFileInputTests
{
    [LinuxOnlyFact]
    public void ReadsRegularFileWithinExactLimitAndRejectsMaximumPlusOne()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("regular.bin");
        var bytes = new byte[] { 1, 2, 3, 4 };
        File.WriteAllBytes(inputPath, bytes);

        var exact = FileSystemAdapter.ReadBoundedPrivateSnapshot(inputPath, bytes.Length);
        var oversized = FileSystemAdapter.ReadBoundedPrivateSnapshot(inputPath, bytes.Length - 1);

        Assert.True(exact.IsSuccess, Describe(exact.Diagnostics));
        Assert.Equal(bytes, exact.Bytes);
        Assert.False(oversized.IsSuccess);
        Assert.Empty(oversized.Bytes);
        Assert.Contains(oversized.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
        AssertDiagnosticsDoNotContainPath(inputPath, exact.Diagnostics.Concat(oversized.Diagnostics));
    }

    [LinuxOnlyFact]
    public void RejectsDirectoryAndFinalSymlinkWithoutFollowingTheSymlink()
    {
        using var directory = new TemporaryDirectory();
        var targetPath = directory.Path("target.bin");
        var linkPath = directory.Path("provider-link.bin");
        File.WriteAllBytes(targetPath, new byte[] { 0x41, 0x42 });
        File.CreateSymbolicLink(linkPath, targetPath);

        var directoryResult = FileSystemAdapter.ReadBoundedPrivateSnapshot(directory.Root, 64);
        var symlinkResult = FileSystemAdapter.ReadBoundedPrivateSnapshot(linkPath, 64);

        AssertRejectedSanitized(directory.Root, directoryResult);
        AssertRejectedSanitized(linkPath, symlinkResult);
        Assert.Equal(new byte[] { 0x41, 0x42 }, File.ReadAllBytes(targetPath));
    }

    [LinuxOnlyFact]
    public void RejectsFifoPromptlyWithoutAnExternalWriter()
    {
        using var directory = new TemporaryDirectory();
        var fifoPath = directory.Path("provider.fifo");
        Assert.Equal(0, MakeFifo(fifoPath, 0x180)); // 0600

        var read = Task.Run(() => FileSystemAdapter.ReadBoundedPrivateSnapshot(fifoPath, 64));
        Assert.True(read.Wait(TimeSpan.FromSeconds(2)), "Opening a FIFO input must not block waiting for a writer.");
        AssertRejectedSanitized(fifoPath, read.GetAwaiter().GetResult());
    }

    [LinuxOnlyFact]
    public void RejectsCharacterDeviceInput()
    {
        const string nullDevice = "/dev/null";
        if (!File.Exists(nullDevice))
        {
            throw SkipException.ForSkip("The Linux host does not expose /dev/null for special-file validation.");
        }

        var result = FileSystemAdapter.ReadBoundedPrivateSnapshot(nullDevice, 64);
        AssertRejectedSanitized(nullDevice, result);
    }

    [LinuxOnlyFact]
    public void DescriptorRemainsBoundToOriginalRegularFileIfPathIsReplaced()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("provider.bin");
        var movedPath = directory.Path("original.bin");
        var originalBytes = new byte[] { 0x11, 0x22, 0x33 };
        var replacementBytes = new byte[] { 0xA1, 0xA2, 0xA3 };
        File.WriteAllBytes(inputPath, originalBytes);

        using var handle = LinuxSafeFileInput.OpenReadOnly(inputPath);
        var snapshot = LinuxSafeFileInput.ReadFromOpenedHandle(
            handle,
            maximumBytes: 16,
            fullPath: inputPath,
            afterInitialSizeValidation: () =>
            {
                File.Move(inputPath, movedPath);
                File.WriteAllBytes(inputPath, replacementBytes);
            });

        Assert.True(snapshot.IsSuccess, Describe(snapshot.Diagnostics));
        Assert.Equal(originalBytes, snapshot.Bytes);
        Assert.Equal(replacementBytes, File.ReadAllBytes(inputPath));
        Assert.Equal(originalBytes, File.ReadAllBytes(movedPath));
    }

    [LinuxOnlyFact]
    public void DetectsGrowthBetweenDescriptorSizeCheckAndBoundedRead()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("growing-provider.bin");
        File.WriteAllBytes(inputPath, new byte[] { 0x10, 0x20 });

        using var handle = LinuxSafeFileInput.OpenReadOnly(inputPath);
        var snapshot = LinuxSafeFileInput.ReadFromOpenedHandle(
            handle,
            maximumBytes: 2,
            fullPath: inputPath,
            afterInitialSizeValidation: () =>
            {
                using var writer = new FileStream(inputPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                writer.Write(new byte[] { 0x30, 0x40, 0x50 });
            });

        Assert.False(snapshot.IsSuccess);
        Assert.Empty(snapshot.Bytes);
        Assert.Contains(snapshot.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InputIoFailure);
        AssertDiagnosticsDoNotContainPath(inputPath, snapshot.Diagnostics);
    }

    [LinuxOnlyFact]
    public void DetectsTruncationBetweenDescriptorSizeCheckAndBoundedRead()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("shrinking-provider.bin");
        File.WriteAllBytes(inputPath, new byte[] { 0x10, 0x20 });

        using var handle = LinuxSafeFileInput.OpenReadOnly(inputPath);
        var snapshot = LinuxSafeFileInput.ReadFromOpenedHandle(
            handle,
            maximumBytes: 2,
            fullPath: inputPath,
            afterInitialSizeValidation: () =>
            {
                using var writer = new FileStream(inputPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                writer.SetLength(1);
            });

        AssertRejectedSanitized(inputPath, snapshot);
    }

    private static void AssertRejectedSanitized(string path, FileSnapshot result)
    {
        Assert.False(result.IsSuccess);
        Assert.Empty(result.Bytes);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InputIoFailure);
        AssertDiagnosticsDoNotContainPath(path, result.Diagnostics);
    }

    private static void AssertDiagnosticsDoNotContainPath(string path, IEnumerable<Diagnostic> diagnostics)
    {
        var diagnosticText = string.Join(Environment.NewLine, diagnostics.Select(diagnostic => diagnostic.Message));
        Assert.DoesNotContain(path, diagnosticText, StringComparison.Ordinal);
    }

    private static string Describe(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(Environment.NewLine, diagnostics.Select(diagnostic => diagnostic.Message));

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-safe-input-");

        public string Root => directory.FullName;

        public string Path(string name) => System.IO.Path.Combine(Root, name);

        public void Dispose() => directory.Delete(recursive: true);
    }

    private static int MakeFifo(string path, uint mode)
    {
        var utf8Path = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            return MakeFifoNative(utf8Path, mode);
        }
        finally
        {
            Marshal.FreeCoTaskMem(utf8Path);
        }
    }

    [DllImport("libc", EntryPoint = "mkfifo", SetLastError = true)]
    private static extern int MakeFifoNative(IntPtr path, uint mode);
}

public sealed class LinuxOnlyFactAttribute : FactAttribute
{
    public LinuxOnlyFactAttribute()
    {
        if (!OperatingSystem.IsLinux()
            || RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
        {
            Skip = "Requires Linux x86-64/AArch64 open/statx descriptor primitives.";
        }
    }
}
