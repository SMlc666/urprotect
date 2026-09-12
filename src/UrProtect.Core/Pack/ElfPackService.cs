using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Pipeline;

namespace UrProtect.Core.Pack;

public sealed record ElfPackOptions(
    PayloadCompression Compression = PayloadCompression.Deflate,
    PayloadFrameLimits? Limits = null,
    bool AnalyzeInstructions = false)
{
    public PayloadFrameLimits EffectiveLimits => Limits ?? new PayloadFrameLimits();
}

public sealed record ElfPackResult(
    string? OutputPath,
    ulong SourceSize,
    ulong EncodedSize,
    string? SourceSha256,
    string? EncodedSha256,
    string? WrapperSha256,
    IReadOnlyList<Diagnostic> Diagnostics,
    string? LauncherSha256 = null,
    ushort FrameVersion = PayloadFrameCodec.FormatVersion,
    ushort LauncherAbiVersion = LauncherContract.AbiVersion)
{
    public bool IsSuccess => OutputPath is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed class ElfPackService
{
    private readonly NoOpPipeline pipeline;

    public ElfPackService(NoOpPipeline? pipeline = null)
    {
        this.pipeline = pipeline ?? new NoOpPipeline();
    }

    public ElfPackResult Pack(
        string inputPath,
        string outputPath,
        string launcherPath,
        ElfPackOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(launcherPath);
        options ??= new ElfPackOptions();

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
            return Failure(diagnostics);
        }

        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(inputFullPath, outputFullPath, comparison)
            || string.Equals(launcherFullPath, outputFullPath, comparison))
        {
            diagnostics.Error(
                DiagnosticCode.OutputPathConflict,
                "The wrapper output path must differ from the input and launcher paths.");
            return Failure(diagnostics);
        }

        byte[] sourceBytes;
        byte[] launcherBytes;
        UnixFileMode? launcherMode = null;
        try
        {
            sourceBytes = File.ReadAllBytes(inputFullPath);
            launcherBytes = File.ReadAllBytes(launcherFullPath);
            if (!OperatingSystem.IsWindows())
            {
                launcherMode = File.GetUnixFileMode(launcherFullPath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, exception.Message);
            return Failure(diagnostics);
        }

        var sourceValidation = pipeline.Validate(sourceBytes, analyzeInstructions: options.AnalyzeInstructions);
        diagnostics.AddRange(sourceValidation.Diagnostics);
        if (!sourceValidation.IsSuccess || sourceValidation.File is null)
        {
            return Failure(diagnostics, sourceBytes.Length);
        }

        if (!IsPackableExecutable(sourceValidation.File, sourceBytes, diagnostics))
        {
            return Failure(diagnostics, sourceBytes.Length);
        }

        if (!LauncherContract.HasMarker(launcherBytes))
        {
            diagnostics.Error(
                DiagnosticCode.LauncherUnavailable,
                $"The launcher does not contain the Wrapper 0.2 ABI marker '{LauncherContract.Marker}'.");
            return Failure(diagnostics, sourceBytes.Length);
        }

        var launcherValidation = pipeline.Validate(launcherBytes, analyzeInstructions: false);
        if (!launcherValidation.IsSuccess || launcherValidation.File is null)
        {
            diagnostics.Error(DiagnosticCode.LauncherUnavailable, "The launcher is not a valid AArch64 ET_DYN executable.");
            diagnostics.AddRange(launcherValidation.Diagnostics);
            return Failure(diagnostics, sourceBytes.Length);
        }

        if (launcherValidation.File.Kind != ElfFileKind.StaticPieExecutable)
        {
            diagnostics.Error(DiagnosticCode.LauncherUnavailable, "The launcher is not a static ET_DYN PIE executable profile.");
            return Failure(diagnostics, sourceBytes.Length);
        }

        if (launcherValidation.File.DynamicEntries.Any(entry => entry.Tag == ElfConstants.DtNeeded))
        {
            diagnostics.Error(DiagnosticCode.LauncherUnavailable, "The launcher has an unexpected shared-library dependency.");
            return Failure(diagnostics, sourceBytes.Length);
        }

        if (!PayloadFrameCodec.TryEncode(
                sourceBytes,
                (ulong)launcherBytes.Length,
                options.Compression,
                options.EffectiveLimits,
                Path.GetFileName(inputFullPath),
                out var encoding,
                out var frameDiagnostics)
            || encoding is null)
        {
            diagnostics.AddRange(frameDiagnostics);
            return Failure(diagnostics, sourceBytes.Length);
        }

        diagnostics.AddRange(frameDiagnostics);
        var trailer = PayloadFrameCodec.CreateTrailer(
            (ulong)launcherBytes.Length,
            (ulong)encoding.FrameBytes.Length);
        var wrapperLength = checked(launcherBytes.Length + encoding.FrameBytes.Length + trailer.Length);
        if ((ulong)wrapperLength > options.EffectiveLimits.MaximumWrapperBytes)
        {
            diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The wrapper exceeds the configured size limit.");
            return Failure(diagnostics, sourceBytes.Length, encoding.EncodedSize, encoding);
        }

        var wrapper = new byte[wrapperLength];
        Buffer.BlockCopy(launcherBytes, 0, wrapper, 0, launcherBytes.Length);
        Buffer.BlockCopy(encoding.FrameBytes, 0, wrapper, launcherBytes.Length, encoding.FrameBytes.Length);
        Buffer.BlockCopy(trailer, 0, wrapper, launcherBytes.Length + encoding.FrameBytes.Length, trailer.Length);

        var wrapperValidation = pipeline.Validate(wrapper, analyzeInstructions: false);
        if (!wrapperValidation.IsSuccess || wrapperValidation.File?.Kind != ElfFileKind.StaticPieExecutable)
        {
            diagnostics.Error(DiagnosticCode.WrapperMalformed, "The generated wrapper is not a valid AArch64 PIE executable.");
            diagnostics.AddRange(wrapperValidation.Diagnostics);
            return Failure(diagnostics, sourceBytes.Length, encoding.EncodedSize, encoding);
        }

        var decoded = PayloadFrameCodec.ReadWrapper(wrapper, options.EffectiveLimits);
        if (!decoded.IsSuccess || decoded.SourceBytes is null || !decoded.SourceBytes.AsSpan().SequenceEqual(sourceBytes))
        {
            diagnostics.Error(DiagnosticCode.PayloadIntegrityMismatch, "The generated wrapper did not recover the source bytes exactly.");
            diagnostics.AddRange(decoded.Diagnostics);
            return Failure(diagnostics, sourceBytes.Length, encoding.EncodedSize, encoding);
        }

        var outputDirectory = Path.GetDirectoryName(outputFullPath);
        if (string.IsNullOrEmpty(outputDirectory) || !Directory.Exists(outputDirectory))
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, "The wrapper output directory does not exist.");
            return Failure(diagnostics, sourceBytes.Length, encoding.EncodedSize, encoding);
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
                stream.Write(wrapper);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows() && launcherMode is { } mode)
            {
                File.SetUnixFileMode(temporaryPath, mode | UnixFileMode.UserExecute);
            }

            var publishedBytes = File.ReadAllBytes(temporaryPath);
            if (!publishedBytes.AsSpan().SequenceEqual(wrapper))
            {
                diagnostics.Error(DiagnosticCode.OutputIdentityMismatch, "The generated wrapper changed before publication.");
                return Failure(diagnostics, sourceBytes.Length, encoding.EncodedSize, encoding);
            }

            File.Move(temporaryPath, outputFullPath, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            diagnostics.Error(DiagnosticCode.OutputIoFailure, exception.Message);
            return Failure(diagnostics, sourceBytes.Length, encoding.EncodedSize, encoding);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
            catch (IOException)
            {
                // Preserve the original publication failure.
            }
            catch (UnauthorizedAccessException)
            {
                // Preserve the original publication failure.
            }
        }

        var sourceHash = Convert.ToHexString(encoding.SourceSha256).ToLowerInvariant();
        var encodedHash = Convert.ToHexString(encoding.EncodedSha256).ToLowerInvariant();
        var wrapperHash = Convert.ToHexString(SHA256.HashData(wrapper)).ToLowerInvariant();
        var launcherHash = Convert.ToHexString(SHA256.HashData(launcherBytes)).ToLowerInvariant();
        return new ElfPackResult(
            outputFullPath,
            (ulong)sourceBytes.Length,
            encoding.EncodedSize,
            sourceHash,
            encodedHash,
            wrapperHash,
            diagnostics.ToArray(),
            launcherHash);
    }

    private static bool IsPackableExecutable(ElfFile file, byte[] source, DiagnosticBag diagnostics)
    {
        if (file.Kind != ElfFileKind.PieExecutable)
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedPackInput,
                "Only ET_DYN PIE executables with PT_INTERP can be packed; shared objects are not supported.");
            return false;
        }

        var interpreter = file.ProgramHeaders.FirstOrDefault(header => header.Type == ElfConstants.PtInterp);
        if (interpreter.Type != ElfConstants.PtInterp
            || interpreter.FileSize == 0
            || interpreter.FileSize > int.MaxValue
            || interpreter.Offset > (ulong)source.Length
            || interpreter.FileSize > (ulong)source.Length - interpreter.Offset)
        {
            diagnostics.Error(DiagnosticCode.InvalidProgramHeader, "The PT_INTERP range is invalid.");
            return false;
        }

        var bytes = source.AsSpan(checked((int)interpreter.Offset), checked((int)interpreter.FileSize));
        var terminator = bytes.IndexOf((byte)0);
        if (terminator <= 0)
        {
            diagnostics.Error(DiagnosticCode.UnsupportedInterpreter, "The PT_INTERP value is not a terminated path.");
            return false;
        }

        var path = Encoding.UTF8.GetString(bytes[..terminator]);
        if (path[0] != '/'
            || (!path.EndsWith("ld-linux-aarch64.so.1", StringComparison.Ordinal)
                && !path.EndsWith("ld-musl-aarch64.so.1", StringComparison.Ordinal)))
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedInterpreter,
                $"The interpreter '{path}' is outside the supported Linux ARM64 profiles.");
            return false;
        }

        if (file.DynamicMetadata.Rpath is not null || file.DynamicMetadata.RunPath is not null)
        {
            diagnostics.Error(
                DiagnosticCode.UnsupportedPackInput,
                "RPATH and RUNPATH inputs are not packable because temporary extraction changes their origin directory.");
            return false;
        }

        return true;
    }

    private static ElfPackResult Failure(
        DiagnosticBag diagnostics,
        int sourceSize = 0,
        ulong encodedSize = 0,
        PayloadFrameEncoding? encoding = null) =>
        new(
            null,
            (ulong)Math.Max(sourceSize, 0),
            encodedSize,
            encoding is null ? null : Convert.ToHexString(encoding.SourceSha256).ToLowerInvariant(),
            encoding is null ? null : Convert.ToHexString(encoding.EncodedSha256).ToLowerInvariant(),
            null,
            diagnostics.ToArray());
}
