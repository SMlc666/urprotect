using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Pipeline;

/// <summary>
/// Selects the scope of optional instruction inspection performed by
/// <see cref="NoOpPipeline"/>. Structural validation is the default and does
/// not decode executable bytes.
/// </summary>
public enum NoOpAnalysisMode
{
    StructuralOnly = 0,
    ObservationOnly = 1,
}

public sealed record NoOpValidationResult(
    ElfFile? File,
    Aarch64AnalysisReport? Analysis,
    IReadOnlyList<Diagnostic> Diagnostics,
    byte[]? OutputBytes)
{
    public bool IsSuccess => File is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);

    /// <summary>
    /// Gets the analysis scope used for this validation result. A structural
    /// result has no instruction-analysis dependency.
    /// </summary>
    public NoOpAnalysisMode AnalysisMode { get; init; } = NoOpAnalysisMode.StructuralOnly;
}

public sealed class NoOpPipeline
{
    private readonly IAarch64Decoder? decoder;

    public NoOpPipeline(IAarch64Decoder? decoder = null)
    {
        // Keep the decoder lazy: structural validation must remain independent
        // of decoder construction and backend availability.
        this.decoder = decoder;
    }

    /// <summary>
    /// Performs validation with the explicitly selected current analysis scope.
    /// </summary>
    private NoOpValidationResult ValidateCore(
        ReadOnlyMemory<byte> input,
        bool emitOutput,
        NoOpAnalysisMode analysisMode)
    {
        if (analysisMode is not (NoOpAnalysisMode.StructuralOnly or NoOpAnalysisMode.ObservationOnly))
        {
            throw new ArgumentOutOfRangeException(nameof(analysisMode));
        }

        var parse = ElfParser.Parse(input);
        var diagnostics = parse.Diagnostics.ToList();
        if (parse.File is null)
        {
            return new NoOpValidationResult(null, null, diagnostics, null)
            {
                AnalysisMode = analysisMode,
            };
        }

        Aarch64AnalysisReport? analysis = null;
        if (analysisMode == NoOpAnalysisMode.ObservationOnly)
        {
            var observationDecoder = decoder ?? new AsmStoneAdapter();
            analysis = new Aarch64ObservationAnalyzer(observationDecoder).Analyze(parse.File);
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

        return new NoOpValidationResult(parse.File, analysis, diagnostics, output)
        {
            AnalysisMode = analysisMode,
        };
    }

    /// <summary>
    /// Performs decoder-independent structural validation.
    /// </summary>
    public NoOpValidationResult ValidateStructurally(
        ReadOnlyMemory<byte> input,
        bool emitOutput = false) =>
        ValidateCore(input, emitOutput, NoOpAnalysisMode.StructuralOnly);

    /// <summary>
    /// Performs explicitly requested whole-image observation. This mode is not
    /// a protection or publication prerequisite and may report decoder facts.
    /// </summary>
    public NoOpValidationResult ValidateObservationOnly(
        ReadOnlyMemory<byte> input,
        bool emitOutput = false) =>
        ValidateCore(input, emitOutput, NoOpAnalysisMode.ObservationOnly);

    private NoOpValidationResult ValidateAndCopyCore(
        string inputPath,
        string outputPath,
        NoOpAnalysisMode analysisMode,
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
            return new NoOpValidationResult(null, null, diagnostics.ToArray(), null)
            {
                AnalysisMode = analysisMode,
            };
        }

        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(inputFullPath, outputFullPath, pathComparison))
        {
            diagnostics.Error(
                DiagnosticCode.OutputPathConflict,
                "The no-op output path must differ from the input path.");
            return new NoOpValidationResult(null, null, diagnostics.ToArray(), null)
            {
                AnalysisMode = analysisMode,
            };
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
                return new NoOpValidationResult(null, null, diagnostics.ToArray(), null)
                {
                    AnalysisMode = analysisMode,
                };
            }
        }

        var result = ValidateCore(
            input,
            emitOutput: false,
            analysisMode);
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

    /// <summary>
    /// Copies a validated ELF without instruction decoding.
    /// </summary>
    public NoOpValidationResult ValidateAndCopyStructurally(
        string inputPath,
        string outputPath,
        ReadOnlyMemory<byte>? inputOverride = null) =>
        ValidateAndCopyCore(
            inputPath,
            outputPath,
            NoOpAnalysisMode.StructuralOnly,
            inputOverride);

    /// <summary>
    /// Copies a validated ELF after explicitly requesting whole-image
    /// observation-only analysis.
    /// </summary>
    public NoOpValidationResult ValidateAndCopyObservationOnly(
        string inputPath,
        string outputPath,
        ReadOnlyMemory<byte>? inputOverride = null) =>
        ValidateAndCopyCore(
            inputPath,
            outputPath,
            NoOpAnalysisMode.ObservationOnly,
            inputOverride);


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
