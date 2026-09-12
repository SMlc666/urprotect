using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Pipeline;

public sealed record NoOpValidationResult(
    ElfFile? File,
    Aarch64AnalysisReport? Analysis,
    IReadOnlyList<Diagnostic> Diagnostics,
    byte[]? OutputBytes)
{
    public bool IsSuccess => File is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed class NoOpPipeline
{
    private readonly IAarch64Decoder decoder;

    public NoOpPipeline(IAarch64Decoder? decoder = null)
    {
        this.decoder = decoder ?? new AsmStoneAdapter();
    }

    public NoOpValidationResult Validate(
        ReadOnlyMemory<byte> input,
        bool emitOutput = false,
        bool analyzeInstructions = true)
    {
        var parse = ElfParser.Parse(input);
        var diagnostics = parse.Diagnostics.ToList();
        if (parse.File is null)
        {
            return new NoOpValidationResult(null, null, diagnostics, null);
        }

        Aarch64AnalysisReport? analysis = null;
        if (analyzeInstructions)
        {
            analysis = new Aarch64Analyzer(decoder).Analyze(parse.File);
            diagnostics.AddRange(analysis.Diagnostics);
        }

        byte[]? output = null;
        if (emitOutput && !diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            output = input.ToArray();
            if (!input.Span.SequenceEqual(output))
            {
                diagnostics.Add(new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.OutputIdentityMismatch,
                    "The no-op output differs from the input bytes."));
                output = null;
            }
        }

        return new NoOpValidationResult(parse.File, analysis, diagnostics, output);
    }

    public NoOpValidationResult ValidateAndCopy(
        string inputPath,
        string outputPath,
        bool analyzeInstructions = true,
        ReadOnlyMemory<byte>? inputOverride = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);

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
            return new NoOpValidationResult(null, null, diagnostics.ToArray(), null);
        }

        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(inputFullPath, outputFullPath, pathComparison))
        {
            diagnostics.Error(
                DiagnosticCode.OutputPathConflict,
                "The no-op output path must differ from the input path.");
            return new NoOpValidationResult(null, null, diagnostics.ToArray(), null);
        }

        byte[] input;
        if (inputOverride is { } providedInput)
        {
            input = providedInput.ToArray();
        }
        else
        {
            try
            {
                input = File.ReadAllBytes(inputFullPath);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                diagnostics.Error(DiagnosticCode.InputIoFailure, exception.Message);
                return new NoOpValidationResult(null, null, diagnostics.ToArray(), null);
            }
        }

        var result = Validate(input, emitOutput: false, analyzeInstructions);
        if (!result.IsSuccess)
        {
            return result;
        }

        UnixFileMode? sourceMode = null;
        var temporaryPath = outputFullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                sourceMode = File.GetUnixFileMode(inputFullPath);
            }

            var directory = Path.GetDirectoryName(outputFullPath);
            if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
            {
                return WithDiagnostic(
                    result,
                    new Diagnostic(
                        DiagnosticSeverity.Error,
                        DiagnosticCode.OutputIoFailure,
                        "The output directory does not exist."));
            }

            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 64 * 1024,
                       options: FileOptions.SequentialScan))
            {
                stream.Write(input);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows() && sourceMode is { } mode)
            {
                File.SetUnixFileMode(temporaryPath, mode);
            }

            var output = File.ReadAllBytes(temporaryPath);
            if (!input.AsSpan().SequenceEqual(output))
            {
                return WithDiagnostic(
                    result,
                    new Diagnostic(
                        DiagnosticSeverity.Error,
                        DiagnosticCode.OutputIdentityMismatch,
                        "The copied no-op output differs from the input bytes."));
            }

            File.Move(temporaryPath, outputFullPath, overwrite: true);
            return result with { OutputBytes = output };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return WithDiagnostic(
                result,
                new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.OutputIoFailure, exception.Message));
        }
        finally
        {
            TryDelete(temporaryPath);
        }
    }

    private static NoOpValidationResult WithDiagnostic(
        NoOpValidationResult result,
        Diagnostic diagnostic)
    {
        var diagnostics = result.Diagnostics.ToList();
        diagnostics.Add(diagnostic);
        return result with { Diagnostics = diagnostics };
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
        catch (IOException)
        {
            // A failed cleanup must not hide the original validation failure.
        }
        catch (UnauthorizedAccessException)
        {
            // A failed cleanup must not hide the original validation failure.
        }
    }
}
