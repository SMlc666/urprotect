using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Pipeline;

namespace UrProtect.Cli;

public enum ProductExitCode
{
    Success = 0,
    Usage = 2,
    FileSystem = 3,
    Validation = 4,
    OutputIdentity = 5,
    Internal = 10,
}

public sealed class CliApplication
{
    public const string ToolVersion = "0.1.0";

    public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        try
        {
            if (args.Length == 0 || args[0] is "-h" or "--help")
            {
                PrintUsage(stdout);
                return (int)ProductExitCode.Success;
            }

            if (!TryParseOptions(args, out var options, out var usageError))
            {
                stderr.WriteLine(usageError);
                PrintUsage(stderr);
                return (int)ProductExitCode.Usage;
            }

            return RunValidation(options, stdout, stderr);
        }
        catch (Exception exception)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            stderr.WriteLine(
                $"InternalFailure [{correlationId}]: {exception.GetType().Name}: {exception.Message}");
            return (int)ProductExitCode.Internal;
        }
    }

    public static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine("urprotect - conservative AArch64 ELF validator");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine("  urprotect validate <input> [--copy <output>] [--json <path|->] [--no-analysis]");
    }

    private static int RunValidation(CliOptions options, TextWriter stdout, TextWriter stderr)
    {
        if (HasConflictingOutputPaths(options, out var conflictMessage))
        {
            return WriteUsageFailure(options, conflictMessage, stdout, stderr);
        }

        byte[] input;
        try
        {
            input = File.ReadAllBytes(options.InputPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            var failureReport = ProductReportFactory.CreateFailure(
                ToolVersion,
                ProductDiagnosticReport.From(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.InputIoFailure.ToString(),
                    exception.Message));
            if (options.JsonPath == "-")
            {
                WriteJson(stdout, failureReport);
            }
            else
            {
                stderr.WriteLine($"InputIoFailure: {exception.Message}");
            }

            return (int)ProductExitCode.FileSystem;
        }

        var pipeline = new NoOpPipeline();
        var result = options.CopyPath is null
            ? pipeline.Validate(input, analyzeInstructions: options.Analyze)
            : pipeline.ValidateAndCopy(
                options.InputPath,
                options.CopyPath,
                options.Analyze,
                inputOverride: input);
        var outputRequested = options.CopyPath is not null;
        var outputPublished = outputRequested && result.OutputBytes is not null;
        var report = ProductReportFactory.Create(
            ToolVersion,
            input,
            result,
            outputRequested,
            outputPublished);

        if (options.JsonPath == "-")
        {
            WriteJson(stdout, report);
        }
        else
        {
            WriteHumanResult(result, options.CopyPath, stdout, stderr);
        }

        if (options.JsonPath is { Length: > 0 } and not "-" && result.IsSuccess)
        {
            try
            {
                WriteAtomicJson(options.JsonPath, report);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        return MapExitCode(result);
    }

    private static bool TryParseOptions(
        string[] args,
        out CliOptions options,
        out string error)
    {
        options = null!;
        error = string.Empty;
        if (!string.Equals(args[0], "validate", StringComparison.OrdinalIgnoreCase)
            || args.Length < 2
            || args[1].StartsWith('-'))
        {
            error = "Usage: the validate command requires an input path.";
            return false;
        }

        string? copyPath = null;
        string? jsonPath = null;
        var analyze = true;
        for (var index = 2; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--copy" when index + 1 < args.Length
                    && !args[index + 1].StartsWith('-'):
                    if (copyPath is not null)
                    {
                        error = "Usage: --copy may be specified only once.";
                        return false;
                    }

                    copyPath = args[++index];
                    break;
                case "--json" when index + 1 < args.Length
                    && (args[index + 1] == "-" || !args[index + 1].StartsWith('-')):
                    if (jsonPath is not null)
                    {
                        error = "Usage: --json may be specified only once.";
                        return false;
                    }

                    jsonPath = args[++index];
                    break;
                case "--no-analysis":
                    analyze = false;
                    break;
                case "-h":
                case "--help":
                    error = "Usage: help is only valid before the command.";
                    return false;
                default:
                    error = $"Usage: unknown argument '{args[index]}'.";
                    return false;
            }
        }

        if (copyPath is not null && string.IsNullOrWhiteSpace(copyPath))
        {
            error = "Usage: --copy requires a non-empty path.";
            return false;
        }

        if (jsonPath is not null && string.IsNullOrWhiteSpace(jsonPath))
        {
            error = "Usage: --json requires a path or '-'.";
            return false;
        }

        options = new CliOptions(args[1], copyPath, jsonPath, analyze);
        return true;
    }

    private static bool HasConflictingOutputPaths(CliOptions options, out string message)
    {
        message = string.Empty;
        try
        {
            var inputPath = Path.GetFullPath(options.InputPath);
            var copyPath = options.CopyPath is null ? null : Path.GetFullPath(options.CopyPath);
            var jsonPath = options.JsonPath is null or "-" ? null : Path.GetFullPath(options.JsonPath);
            var comparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            if (copyPath is not null && string.Equals(inputPath, copyPath, comparison))
            {
                message = "Usage: --copy must point to a path different from the input.";
                return true;
            }

            if (jsonPath is not null
                && (string.Equals(inputPath, jsonPath, comparison)
                    || string.Equals(copyPath, jsonPath, comparison)))
            {
                message = "Usage: --json must point to a path different from input and copy outputs.";
                return true;
            }
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            message = $"Usage: invalid output path: {exception.Message}";
            return true;
        }

        return false;
    }

    private static int WriteUsageFailure(
        CliOptions options,
        string message,
        TextWriter stdout,
        TextWriter stderr)
    {
        if (options.JsonPath == "-")
        {
            WriteJson(
                stdout,
                ProductReportFactory.CreateFailure(
                    ToolVersion,
                    ProductDiagnosticReport.From(DiagnosticSeverity.Error, "InvalidArgument", message)));
        }
        else
        {
            stderr.WriteLine(message);
            PrintUsage(stderr);
        }

        return (int)ProductExitCode.Usage;
    }

    private static int MapExitCode(NoOpValidationResult result)
    {
        if (result.IsSuccess)
        {
            return (int)ProductExitCode.Success;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.OutputIdentityMismatch))
        {
            return (int)ProductExitCode.OutputIdentity;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code is
            DiagnosticCode.InputIoFailure or DiagnosticCode.OutputIoFailure))
        {
            return (int)ProductExitCode.FileSystem;
        }

        return (int)ProductExitCode.Validation;
    }

    private static void WriteHumanResult(
        NoOpValidationResult result,
        string? copyPath,
        TextWriter stdout,
        TextWriter stderr)
    {
        foreach (var diagnostic in result.Diagnostics)
        {
            var writer = diagnostic.IsError ? stderr : stdout;
            writer.WriteLine(diagnostic);
        }

        if (result.File is not null)
        {
            stdout.WriteLine(
                $"Validated ET_DYN AArch64 {result.File.Kind}: "
                + $"{result.File.ProgramHeaders.Count} program headers, "
                + $"{result.File.DynamicEntries.Count} dynamic entries, "
                + $"{result.File.RelaRelocations.Count} RELA relocations.");
        }

        if (result.IsSuccess && copyPath is not null)
        {
            stdout.WriteLine($"Byte-identical output written to {copyPath}.");
        }
    }

    private static void WriteJson(TextWriter writer, ProductReport report)
    {
        writer.WriteLine(ProductReportFactory.Serialize(report));
    }

    private static void WriteAtomicJson(string path, ProductReport report)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"The report directory does not exist: {directory}");
        }

        var temporaryPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var reportBytes = Encoding.UTF8.GetBytes(ProductReportFactory.Serialize(report) + Environment.NewLine);
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 64 * 1024,
                       options: FileOptions.SequentialScan))
            {
                stream.Write(reportBytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, fullPath, overwrite: true);
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
                // Preserve the original report publication failure.
            }
            catch (UnauthorizedAccessException)
            {
                // Preserve the original report publication failure.
            }
        }
    }

    private sealed record CliOptions(
        string InputPath,
        string? CopyPath,
        string? JsonPath,
        bool Analyze);
}
