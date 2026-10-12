using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Infrastructure;

/// <summary>Bounded input snapshot returned by the filesystem adapter.</summary>
public sealed record InputSnapshot(
    string InputPath,
    string OutputPath,
    byte[] Bytes,
    UnixFileMode? SourceMode,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>Result of verified atomic identity-copy publication.</summary>
public sealed record IdentityCopyResult(
    byte[]? OutputBytes,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => OutputBytes is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Owns filesystem reads and atomic byte publication for validation workflows.
/// Structural and semantic services consume snapshots and never call File APIs.
/// </summary>
public sealed class IdentityCopyPublisher
{
    public static InputSnapshot ReadInput(
        string inputPath,
        string outputPath,
        ReadOnlyMemory<byte>? inputOverride = null)
    {
        var diagnostics = new DiagnosticBag();
        string inputFullPath;
        string outputFullPath;
        try
        {
            inputFullPath = Path.GetFullPath(inputPath);
            outputFullPath = Path.GetFullPath(outputPath);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, exception.Message);
            return new InputSnapshot(string.Empty, string.Empty, Array.Empty<byte>(), null, diagnostics.ToArray());
        }

        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(inputFullPath, outputFullPath, pathComparison))
        {
            diagnostics.Error(
                DiagnosticCode.OutputPathConflict,
                "The identity-copy output path must differ from the input path.");
            return new InputSnapshot(inputFullPath, outputFullPath, Array.Empty<byte>(), null, diagnostics.ToArray());
        }

        byte[] input;
        try
        {
            input = inputOverride?.ToArray() ?? File.ReadAllBytes(inputFullPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, exception.Message);
            return new InputSnapshot(inputFullPath, outputFullPath, Array.Empty<byte>(), null, diagnostics.ToArray());
        }

        UnixFileMode? sourceMode = null;
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                sourceMode = File.GetUnixFileMode(inputFullPath);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                diagnostics.Error(DiagnosticCode.InputIoFailure, exception.Message);
            }
        }

        return new InputSnapshot(inputFullPath, outputFullPath, input, sourceMode, diagnostics.ToArray());
    }

    public static IdentityCopyResult Publish(
        string outputPath,
        ReadOnlyMemory<byte> bytes,
        UnixFileMode? sourceMode = null)
    {
        var diagnostics = new DiagnosticBag();
        string outputFullPath;
        try
        {
            outputFullPath = Path.GetFullPath(outputPath);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, exception.Message);
            return new IdentityCopyResult(null, diagnostics.ToArray());
        }

        var directory = Path.GetDirectoryName(outputFullPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, "The output directory does not exist.");
            return new IdentityCopyResult(null, diagnostics.ToArray());
        }

        var temporaryPath = outputFullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
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

            var output = File.ReadAllBytes(temporaryPath);
            if (!bytes.Span.SequenceEqual(output))
            {
                diagnostics.Error(
                    DiagnosticCode.OutputIdentityMismatch,
                    "The copied identity output differs from the input bytes.");
                return new IdentityCopyResult(null, diagnostics.ToArray());
            }

            File.Move(temporaryPath, outputFullPath, overwrite: true);
            return new IdentityCopyResult(output, diagnostics.ToArray());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, exception.Message);
            return new IdentityCopyResult(null, diagnostics.ToArray());
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
            // Preserve the original validation/publication outcome.
        }
    }
}
