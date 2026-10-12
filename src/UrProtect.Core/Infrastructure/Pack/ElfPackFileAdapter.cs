using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Infrastructure.Pack;

/// <summary>Input snapshot for the application pack use case.</summary>
public sealed record ElfPackFileSnapshot(
    string InputPath,
    string OutputPath,
    string LauncherPath,
    string SourceName,
    byte[] SourceBytes,
    byte[] LauncherBytes,
    UnixFileMode? LauncherMode,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>Filesystem adapter for pack input snapshots and wrapper publication.</summary>
public static class ElfPackFileAdapter
{
    public static ElfPackFileSnapshot Read(
        string inputPath,
        string outputPath,
        string launcherPath)
    {
        var diagnostics = new DiagnosticBag();
        string inputFullPath;
        string outputFullPath;
        string launcherFullPath;
        try
        {
            inputFullPath = Path.GetFullPath(inputPath);
            outputFullPath = Path.GetFullPath(outputPath);
            launcherFullPath = Path.GetFullPath(launcherPath);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, exception.Message);
            return new ElfPackFileSnapshot(
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                Array.Empty<byte>(),
                Array.Empty<byte>(),
                null,
                diagnostics.ToArray());
        }

        var comparer = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(inputFullPath, outputFullPath, comparer)
            || string.Equals(launcherFullPath, outputFullPath, comparer))
        {
            diagnostics.Error(
                DiagnosticCode.OutputPathConflict,
                "The wrapper output path must differ from the input and launcher paths.");
            return new ElfPackFileSnapshot(
                inputFullPath,
                outputFullPath,
                launcherFullPath,
                Path.GetFileName(inputFullPath),
                Array.Empty<byte>(),
                Array.Empty<byte>(),
                null,
                diagnostics.ToArray());
        }

        try
        {
            var sourceBytes = File.ReadAllBytes(inputFullPath);
            var launcherBytes = File.ReadAllBytes(launcherFullPath);
            UnixFileMode? launcherMode = null;
            if (!OperatingSystem.IsWindows())
            {
                launcherMode = File.GetUnixFileMode(launcherFullPath);
            }

            return new ElfPackFileSnapshot(
                inputFullPath,
                outputFullPath,
                launcherFullPath,
                Path.GetFileName(inputFullPath),
                sourceBytes,
                launcherBytes,
                launcherMode,
                diagnostics.ToArray());
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, exception.Message);
            return new ElfPackFileSnapshot(
                inputFullPath,
                outputFullPath,
                launcherFullPath,
                Path.GetFileName(inputFullPath),
                Array.Empty<byte>(),
                Array.Empty<byte>(),
                null,
                diagnostics.ToArray());
        }
    }

    public static FilePublicationResult Publish(
        ElfPackFileSnapshot snapshot,
        ReadOnlyMemory<byte> wrapper)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return FileSystemAdapter.PublishAtomic(
            snapshot.OutputPath,
            wrapper,
            snapshot.LauncherMode is { } mode
                ? mode | UnixFileMode.UserExecute
                : null);
    }
}
