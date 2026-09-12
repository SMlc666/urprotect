using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Pack;
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
    private const int MaxCommandLineArguments = 4096;

    public static string ToolVersion =>
        typeof(CliApplication).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            .Split('+', 2)[0]
        ?? "0.1.0";

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

            if (string.Equals(args[0], "validate", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryParseValidationOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunValidation(options, stdout, stderr);
            }

            if (string.Equals(args[0], "pack", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryParsePackOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunPack(options, stdout, stderr);
            }

            stderr.WriteLine($"Usage: unknown command '{args[0]}'.");
            PrintUsage(stderr);
            return (int)ProductExitCode.Usage;
        }
        catch (Exception exception)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            stderr.WriteLine(
                $"InternalFailure [{correlationId}]: {exception.GetType().Name}: {exception.Message}");
            return (int)ProductExitCode.Internal;
        }
    }

    public static int? TryRunEmbeddedPayload()
    {
        if (!OperatingSystem.IsLinux() || string.IsNullOrWhiteSpace(Environment.ProcessPath))
        {
            return null;
        }

        byte[] wrapper;
        try
        {
            wrapper = File.ReadAllBytes(Environment.ProcessPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"InputIoFailure: could not inspect the launcher executable: {exception.Message}");
            return (int)ProductExitCode.FileSystem;
        }

        if (!PayloadFrameCodec.HasWrapperTrailer(wrapper))
        {
            if (PayloadFrameCodec.HasFrameHeader(wrapper))
            {
                Console.Error.WriteLine(
                    "WrapperMalformed: the embedded payload frame trailer is missing or truncated.");
                return (int)ProductExitCode.Validation;
            }

            return null;
        }

        var payload = PayloadFrameCodec.ReadWrapper(wrapper, new PayloadFrameLimits());
        if (!payload.IsSuccess || payload.SourceBytes is null)
        {
            foreach (var diagnostic in payload.Diagnostics)
            {
                Console.Error.WriteLine(diagnostic);
            }

            return payload.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.PayloadIntegrityMismatch)
                ? (int)ProductExitCode.OutputIdentity
                : (int)ProductExitCode.Validation;
        }

        var validation = new NoOpPipeline().Validate(payload.SourceBytes, analyzeInstructions: false);
        if (!validation.IsSuccess || validation.File?.Kind != ElfFileKind.PieExecutable)
        {
            foreach (var diagnostic in validation.Diagnostics)
            {
                Console.Error.WriteLine(diagnostic);
            }

            Console.Error.WriteLine(
                "UnsupportedPackInput: the recovered payload is not a valid AArch64 PIE executable.");
            return (int)ProductExitCode.Validation;
        }

        string temporaryDirectory;
        string temporaryPath;
        try
        {
            temporaryDirectory = Path.Combine(
                Path.GetTempPath(),
                $"urprotect-payload-{Environment.ProcessId}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(temporaryDirectory);
            File.SetUnixFileMode(
                temporaryDirectory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            temporaryPath = Path.Combine(temporaryDirectory, payload.Frame!.SourceName!);
            File.WriteAllBytes(temporaryPath, payload.SourceBytes);
            File.SetUnixFileMode(
                temporaryPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"OutputIoFailure: could not materialize the payload: {exception.Message}");
            return (int)ProductExitCode.FileSystem;
        }

        try
        {
            var commandLine = Environment.GetCommandLineArgs();
            if (commandLine.Length == 0 || commandLine.Length > MaxCommandLineArguments)
            {
                Console.Error.WriteLine("InvalidArgument: the command line is outside the supported bounds.");
                return (int)ProductExitCode.Usage;
            }

            commandLine[0] = payload.Frame?.SourceName ?? commandLine[0];

            var environment = Environment.GetEnvironmentVariables()
                .Cast<System.Collections.DictionaryEntry>()
                .Select(entry => $"{entry.Key}={entry.Value}")
                .ToArray();
            var nativePath = Marshal.StringToCoTaskMemUTF8(temporaryPath);
            using var nativeArguments = NativeStringArray.Create(commandLine);
            using var nativeEnvironment = NativeStringArray.Create(environment);
            try
            {
                var execResult = Execve(nativePath, nativeArguments.Pointer, nativeEnvironment.Pointer);
                if (execResult == 0)
                {
                    Console.Error.WriteLine("InternalFailure: execve returned success without replacing the process.");
                    return (int)ProductExitCode.Internal;
                }

                var error = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"OutputIoFailure: execve failed for the recovered payload (errno {error}).");
                return (int)ProductExitCode.FileSystem;
            }
            finally
            {
                Marshal.FreeCoTaskMem(nativePath);
            }
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
                // The payload path is best-effort cleanup after execve failure.
            }
            catch (UnauthorizedAccessException)
            {
                // The payload path is best-effort cleanup after execve failure.
            }

            try
            {
                if (Directory.Exists(temporaryDirectory))
                {
                    Directory.Delete(temporaryDirectory, recursive: true);
                }
            }
            catch (IOException)
            {
                // The payload directory is best-effort cleanup after execve failure.
            }
            catch (UnauthorizedAccessException)
            {
                // The payload directory is best-effort cleanup after execve failure.
            }
        }
    }

    [DllImport("libc", EntryPoint = "execve", SetLastError = true)]
    private static extern int Execve(IntPtr path, IntPtr argv, IntPtr environment);

    private sealed class NativeStringArray : IDisposable
    {
        private readonly IntPtr[] strings;

        private NativeStringArray(IntPtr pointer, IntPtr[] strings)
        {
            Pointer = pointer;
            this.strings = strings;
        }

        public IntPtr Pointer { get; }

        public static NativeStringArray Create(IEnumerable<string> values)
        {
            var strings = values.Select(Marshal.StringToCoTaskMemUTF8).ToArray();
            var pointer = Marshal.AllocHGlobal(checked((strings.Length + 1) * IntPtr.Size));
            for (var index = 0; index < strings.Length; index++)
            {
                Marshal.WriteIntPtr(pointer, index * IntPtr.Size, strings[index]);
            }

            Marshal.WriteIntPtr(pointer, strings.Length * IntPtr.Size, IntPtr.Zero);
            return new NativeStringArray(pointer, strings);
        }

        public void Dispose()
        {
            foreach (var value in strings)
            {
                Marshal.FreeCoTaskMem(value);
            }

            Marshal.FreeHGlobal(Pointer);
        }
    }

    public static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine("urprotect - conservative AArch64 ELF validator");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine("  urprotect validate <input> [--copy <output>] [--json <path|->] [--no-analysis]");
        writer.WriteLine("  urprotect pack <input> --output <wrapper> [--json <path|->] [--launcher <path>]");
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
                WriteJson(stdout, ProductReportFactory.Serialize(failureReport));
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
            WriteJson(stdout, ProductReportFactory.Serialize(report));
        }
        else
        {
            WriteHumanResult(result, options.CopyPath, stdout, stderr);
        }

        if (options.JsonPath is { Length: > 0 } and not "-" && result.IsSuccess)
        {
            try
            {
                WriteAtomicJson(options.JsonPath, ProductReportFactory.Serialize(report));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        return MapExitCode(result);
    }

    private static int RunPack(PackOptions options, TextWriter stdout, TextWriter stderr)
    {
        if (HasConflictingPackPaths(options, out var conflictMessage))
        {
            if (options.JsonPath == "-")
            {
                WriteJson(
                    stdout,
                    ProductReportFactory.Serialize(ProductReportFactory.CreateFailure(
                        ToolVersion,
                        ProductDiagnosticReport.From(DiagnosticSeverity.Error, "InvalidArgument", conflictMessage))));
            }
            else
            {
                stderr.WriteLine(conflictMessage);
                PrintUsage(stderr);
            }

            return (int)ProductExitCode.Usage;
        }

        var launcherPath = options.LauncherPath ?? Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(launcherPath))
        {
            return WritePackFailure(
                options,
                new ElfPackResult(
                    null,
                    0,
                    0,
                    null,
                    null,
                    null,
                    new[]
                    {
                        new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.LauncherUnavailable,
                            "The current process path is unavailable; pass --launcher explicitly."),
                    }),
                stdout,
                stderr);
        }

        if (options.LauncherPath is null
            && !string.Equals(
                Path.GetFileNameWithoutExtension(launcherPath),
                "urprotect",
                StringComparison.OrdinalIgnoreCase))
        {
            return WritePackFailure(
                options,
                new ElfPackResult(
                    null,
                    0,
                    0,
                    null,
                    null,
                    null,
                    new[]
                    {
                        new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.LauncherUnavailable,
                            "The default pack launcher must be the self-contained urprotect executable; pass --launcher explicitly otherwise."),
                    }),
                stdout,
                stderr);
        }

        var result = new ElfPackService().Pack(
            options.InputPath,
            options.OutputPath,
            launcherPath);
        return WritePackResult(options, result, stdout, stderr);
    }

    private static bool TryParseValidationOptions(
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

    private static bool TryParsePackOptions(
        string[] args,
        out PackOptions options,
        out string error)
    {
        options = null!;
        error = string.Empty;
        if (args.Length < 2 || args[1].StartsWith('-'))
        {
            error = "Usage: the pack command requires an input path.";
            return false;
        }

        string? outputPath = null;
        string? jsonPath = null;
        string? launcherPath = null;
        for (var index = 2; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--output" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (outputPath is not null)
                    {
                        error = "Usage: --output may be specified only once.";
                        return false;
                    }

                    outputPath = args[++index];
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
                case "--launcher" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (launcherPath is not null)
                    {
                        error = "Usage: --launcher may be specified only once.";
                        return false;
                    }

                    launcherPath = args[++index];
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

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            error = "Usage: pack requires --output <wrapper>.";
            return false;
        }

        options = new PackOptions(args[1], outputPath, jsonPath, launcherPath);
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

    private static bool HasConflictingPackPaths(PackOptions options, out string message)
    {
        message = string.Empty;
        try
        {
            var inputPath = Path.GetFullPath(options.InputPath);
            var outputPath = Path.GetFullPath(options.OutputPath);
            var jsonPath = options.JsonPath is null or "-" ? null : Path.GetFullPath(options.JsonPath);
            var launcherPath = options.LauncherPath is null ? null : Path.GetFullPath(options.LauncherPath);
            var comparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            if (string.Equals(inputPath, outputPath, comparison))
            {
                message = "Usage: --output must point to a path different from the input.";
                return true;
            }

            if (jsonPath is not null
                && (string.Equals(inputPath, jsonPath, comparison)
                    || string.Equals(outputPath, jsonPath, comparison)))
            {
                message = "Usage: --json must point to a path different from input and wrapper outputs.";
                return true;
            }

            if (launcherPath is not null && string.Equals(launcherPath, outputPath, comparison))
            {
                message = "Usage: --output must point to a path different from the launcher.";
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
                ProductReportFactory.Serialize(ProductReportFactory.CreateFailure(
                    ToolVersion,
                    ProductDiagnosticReport.From(DiagnosticSeverity.Error, "InvalidArgument", message))));
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

    private static int WritePackFailure(
        PackOptions options,
        ElfPackResult result,
        TextWriter stdout,
        TextWriter stderr) =>
        WritePackResult(options, result, stdout, stderr);

    private static int WritePackResult(
        PackOptions options,
        ElfPackResult result,
        TextWriter stdout,
        TextWriter stderr)
    {
        var report = ProductReportFactory.CreatePack(ToolVersion, result);
        if (options.JsonPath == "-")
        {
            WriteJson(stdout, ProductReportFactory.Serialize(report));
        }
        else
        {
            foreach (var diagnostic in result.Diagnostics)
            {
                var writer = diagnostic.IsError ? stderr : stdout;
                writer.WriteLine(diagnostic);
            }

            if (result.IsSuccess)
            {
                stdout.WriteLine(
                    $"Packed AArch64 ET_DYN PIE: {result.SourceSize} source bytes, "
                    + $"{result.EncodedSize} compressed bytes.");
                stdout.WriteLine($"Wrapper written to {result.OutputPath}.");
            }
        }

        if (options.JsonPath is { Length: > 0 } and not "-")
        {
            try
            {
                WriteAtomicJson(options.JsonPath, ProductReportFactory.Serialize(report));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        if (result.IsSuccess)
        {
            return (int)ProductExitCode.Success;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code is
            DiagnosticCode.OutputIoFailure or DiagnosticCode.InputIoFailure))
        {
            return (int)ProductExitCode.FileSystem;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code is
            DiagnosticCode.OutputIdentityMismatch or DiagnosticCode.PayloadIntegrityMismatch))
        {
            return (int)ProductExitCode.OutputIdentity;
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

    private static void WriteJson(TextWriter writer, string json)
    {
        writer.WriteLine(json);
    }

    private static void WriteAtomicJson(string path, string json)
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
            var reportBytes = Encoding.UTF8.GetBytes(json + Environment.NewLine);
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

    private sealed record PackOptions(
        string InputPath,
        string OutputPath,
        string? JsonPath,
        string? LauncherPath);
}
