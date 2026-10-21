using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Infrastructure;

/// <summary>Filesystem snapshot returned to application use cases.</summary>
public sealed record FileSnapshot(
    string FullPath,
    byte[] Bytes,
    UnixFileMode? SourceMode,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>Result of one verified atomic filesystem publication.</summary>
public sealed record FilePublicationResult(
    string? FullPath,
    byte[]? Bytes,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Bytes is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Owns bounded filesystem reads, path normalization, and atomic byte publication.
/// Application workflows consume snapshots and publication results rather than
/// calling filesystem APIs directly.
/// </summary>
public static class FileSystemAdapter
{
    /// <summary>
    /// Reads one private bounded input snapshot. The size is checked from the
    /// opened file before allocating or copying any input bytes; diagnostics do
    /// not disclose the host path or underlying exception text.
    /// </summary>
    public static FileSnapshot ReadBoundedPrivateSnapshot(string path, int maximumBytes)
    {
        var diagnostics = new DiagnosticBag();
        if (string.IsNullOrWhiteSpace(path) || maximumBytes < 0)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, "The bounded input path or byte limit is invalid.");
            return new FileSnapshot(string.Empty, Array.Empty<byte>(), null, diagnostics.ToArray());
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException or System.Security.SecurityException)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, "The bounded input path is invalid.");
            return new FileSnapshot(string.Empty, Array.Empty<byte>(), null, diagnostics.ToArray());
        }

        if (!OperatingSystem.IsLinux())
        {
            diagnostics.Error(
                DiagnosticCode.InputIoFailure,
                "Bounded private input reads are unavailable on this host.");
            return new FileSnapshot(fullPath, Array.Empty<byte>(), null, diagnostics.ToArray());
        }

        try
        {
            using var handle = LinuxSafeFileInput.OpenReadOnly(fullPath);
            return LinuxSafeFileInput.ReadFromOpenedHandle(handle, maximumBytes, fullPath);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException
                or System.Security.SecurityException or DllNotFoundException or EntryPointNotFoundException
                or BadImageFormatException)
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, "The bounded input could not be read.");
            return new FileSnapshot(fullPath, Array.Empty<byte>(), null, diagnostics.ToArray());
        }
    }

    public static FileSnapshot Read(string path, bool captureUnixMode = false)
    {
        var diagnostics = new DiagnosticBag();
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, exception.Message);
            return new FileSnapshot(string.Empty, Array.Empty<byte>(), null, diagnostics.ToArray());
        }

        try
        {
            var bytes = File.ReadAllBytes(fullPath);
            UnixFileMode? sourceMode = null;
            if (captureUnixMode && !OperatingSystem.IsWindows())
            {
                sourceMode = File.GetUnixFileMode(fullPath);
            }

            return new FileSnapshot(fullPath, bytes, sourceMode, diagnostics.ToArray());
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, exception.Message);
            return new FileSnapshot(fullPath, Array.Empty<byte>(), null, diagnostics.ToArray());
        }
    }

    public static bool TryNormalize(string path, out string fullPath, out Diagnostic? diagnostic)
    {
        try
        {
            fullPath = Path.GetFullPath(path);
            diagnostic = null;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            fullPath = string.Empty;
            diagnostic = new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.InvalidArgument, exception.Message);
            return false;
        }
    }

    public static IReadOnlyList<Diagnostic> ValidateDistinctPaths(
        IEnumerable<string> paths,
        string conflictMessage,
        string invalidPathMessage)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var diagnostics = new DiagnosticBag();
        var normalized = new List<string>();
        try
        {
            foreach (var path in paths)
            {
                normalized.Add(Path.GetFullPath(path));
            }
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException or System.Security.SecurityException)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, invalidPathMessage);
            return diagnostics.ToArray();
        }

        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        if (normalized.Distinct(comparer).Count() != normalized.Count)
        {
            diagnostics.Error(DiagnosticCode.OutputPathConflict, conflictMessage);
        }

        return diagnostics.ToArray();
    }

    public static FilePublicationResult PublishAtomic(
        string path,
        ReadOnlyMemory<byte> bytes,
        UnixFileMode? sourceMode = null,
        bool overwrite = true)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        var diagnostics = new DiagnosticBag();
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, exception.Message);
            return new FilePublicationResult(null, null, diagnostics.ToArray());
        }

        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, "The output directory does not exist.");
            return new FilePublicationResult(fullPath, null, diagnostics.ToArray());
        }

        var temporaryPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 64 * 1024,
                       options: FileOptions.SequentialScan))
            {
                stream.Write(bytes.Span);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows() && sourceMode is { } mode)
            {
                File.SetUnixFileMode(temporaryPath, mode);
            }

            var published = File.ReadAllBytes(temporaryPath);
            if (!published.AsSpan().SequenceEqual(bytes.Span))
            {
                diagnostics.Error(
                    DiagnosticCode.OutputIdentityMismatch,
                    "The published output changed before publication.");
                return new FilePublicationResult(fullPath, null, diagnostics.ToArray());
            }

            File.Move(temporaryPath, fullPath, overwrite);
            return new FilePublicationResult(fullPath, published, diagnostics.ToArray());
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, exception.Message);
            return new FilePublicationResult(fullPath, null, diagnostics.ToArray());
        }
        finally
        {
            TryDelete(temporaryPath);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Preserve the original publication result.
        }
    }
}
