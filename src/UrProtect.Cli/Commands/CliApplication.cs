using System.Reflection;
using UrProtect.Core.Application.Pack;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.Application.Validation;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using UrProtect.Core.Infrastructure.Native;
using UrProtect.Core.StructuralElf;
using UrProtect.Cli.Parsing;
using UrProtect.Cli.Rendering;

namespace UrProtect.Cli.Commands;

public enum ProductExitCode
{
    Success = 0,
    Usage = 2,
    FileSystem = 3,
    Validation = 4,
    OutputIdentity = 5,
    Internal = 10,
}

/// <summary>
/// The sole public CLI facade. It translates canonical options, dispatches
/// typed application use cases, renders reports, and maps diagnostics to exit
/// codes. Filesystem, process, digest, and publication details are delegated to
/// Core Application and Infrastructure owners.
/// </summary>
public sealed class CliApplication
{
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
                if (!CommandLineParser.TryParseValidationOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunValidation(options, stdout, stderr);
            }

            if (string.Equals(args[0], "pack", StringComparison.OrdinalIgnoreCase))
            {
                if (!CommandLineParser.TryParsePackOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunPack(options, stdout, stderr);
            }

            if (string.Equals(args[0], "protect", StringComparison.OrdinalIgnoreCase))
            {
                if (!CommandLineParser.TryParseProtectOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunProtect(options, stdout, stderr);
            }

            if (string.Equals(args[0], "protect-image", StringComparison.OrdinalIgnoreCase))
            {
                if (!CommandLineParser.TryParseProtectedImageOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunProtectedImage(options, stdout, stderr);
            }

            if (string.Equals(args[0], "rehydrate-image", StringComparison.OrdinalIgnoreCase))
            {
                if (!CommandLineParser.TryParseRehydrationOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunRehydration(options, stdout, stderr);
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

    public static int? TryRunEmbeddedPayload() => EmbeddedPayloadLauncher.Run();

    public static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine("urprotect - conservative AArch64 ELF validator");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine("  urprotect validate <input> [--copy <output>] [--json <path|->] [--observe-analysis]");
        writer.WriteLine("    Structural validation is the default; use --observe-analysis for explicit whole-image observation.");
        writer.WriteLine("  urprotect pack <input> --output <wrapper> [--json <path|->] [--launcher <path>] [--profile <outer-execveat|host-context-entry>] [--entry-symbol <name>] [--thread-lifetime] [--path-preserving]");
        writer.WriteLine("  urprotect protect <input> --output <protected> --function <name>|--function-id <symtab|dynsym>:<index>|--function-address <0xaddr> --pass <control-flow-flattening|register-permutation> [--pass <...>] [--json <path|->]");
        writer.WriteLine("  urprotect protect-image <input> --artifact <path> --role <path> --manifest <path> --stage <path> --unit <id> --profile <outer-execveat|host-context-entry> --function <name>|--function-id <symtab|dynsym>:<index>|--function-address <0xaddr> --pass <control-flow-flattening|register-permutation> [--producer-id <id>] [--producer-build-sha256 <sha256>] [--rehydrator <id>] [--source-sha256 <sha256>] [--request-sha256 <sha256>] [--provider-file <path> --provider-soname <soname> --provider-build-id <hex> --provider-sha256 <sha256>] [--json <path|->]");
        writer.WriteLine("  urprotect rehydrate-image <source> --artifact <path> --native-image <path> --role <path> --record <path> --unit <id> --profile <outer-execveat|host-context-entry> --source-sha256 <sha256> --request-sha256 <sha256> --producer-id <id> --producer-build-sha256 <sha256> --consumer-id <id> --consumer-build-sha256 <sha256> [--provider-file <path> --provider-soname <soname> --provider-build-id <hex> --provider-sha256 <sha256>] [--json <path|->]");
    }

    private static int RunValidation(CliOptions options, TextWriter stdout, TextWriter stderr)
    {
        var command = new ValidationCommandWorkflow().Execute(
            new ValidationCommandRequest(options.InputPath, options.CopyPath, options.JsonPath, options.AnalysisMode));
        if (command.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict))
        {
            return WriteUsageFailure(options, command.Diagnostics.First(diagnostic => diagnostic.IsError).Message, stdout, stderr);
        }

        if (command.InputBytes is null)
        {
            var diagnostic = command.Diagnostics.FirstOrDefault(diagnostic => diagnostic.IsError);
            if (!diagnostic.IsError)
            {
                diagnostic = new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.InputIoFailure, "The input could not be read.");
            }
            if (options.JsonPath == "-")
            {
                CommandOutputWriter.WriteJson(
                    stdout,
                    ProductReportFactory.Serialize(ProductReportFactory.CreateFailure(
                        ToolVersion,
                        ProductDiagnosticReport.From(diagnostic))));
            }
            else
            {
                stderr.WriteLine($"{diagnostic.Code}: {diagnostic.Message}");
            }

            return MapExitCode(command.Validation);
        }

        var report = ProductReportFactory.Create(
            ToolVersion,
            command.InputBytes,
            command.Validation,
            options.CopyPath is not null,
            command.OutputPublished);
        if (options.JsonPath == "-")
        {
            CommandOutputWriter.WriteJson(stdout, ProductReportFactory.Serialize(report));
        }
        else
        {
            WriteHumanResult(command.Validation, options.CopyPath, stdout, stderr);
        }

        if (options.JsonPath is { Length: > 0 } and not "-" && command.Validation.IsSuccess)
        {
            try
            {
                CommandOutputWriter.WriteAtomicJson(options.JsonPath, ProductReportFactory.Serialize(report));
            }
            catch (IOException exception)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        return MapExitCode(command.Validation);
    }

    private static int RunPack(PackOptions options, TextWriter stdout, TextWriter stderr)
    {
        if (string.IsNullOrWhiteSpace(options.LauncherPath))
        {
            return WritePackResult(
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
                            "pack requires --launcher <native-launcher>; the C# packer cannot be used as a native wrapper."),
                    }),
                stdout,
                stderr);
        }

        var result = new ElfPackService().Pack(
            options.InputPath,
            options.OutputPath,
            options.LauncherPath,
            new ElfPackOptions(
                Profile: options.Profile,
                EntrySymbol: options.EntrySymbol,
                RequireThreadLifetime: options.RequireThreadLifetime,
                AllowPathSensitiveOuter: options.AllowPathSensitiveOuter));
        if (result.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict))
        {
            var message = result.Diagnostics.First(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict).Message;
            if (options.JsonPath == "-")
            {
                CommandOutputWriter.WriteJson(
                    stdout,
                    ProductReportFactory.Serialize(ProductReportFactory.CreatePack(ToolVersion, result)));
            }
            else
            {
                stderr.WriteLine(message);
                PrintUsage(stderr);
            }

            return (int)ProductExitCode.Usage;
        }

        return WritePackResult(options, result, stdout, stderr);
    }

    private static int RunProtect(ProtectOptions options, TextWriter stdout, TextWriter stderr)
    {
        var command = new FunctionProtectionWorkflow().Execute(
            new FunctionProtectionCommandRequest(
                options.InputPath,
                options.OutputPath,
                options.JsonPath,
                new FunctionProtectionOptions(options.Functions, options.Passes)));
        if (command.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict))
        {
            return WriteProtectionUsageFailure(
                options,
                command.Diagnostics.First(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict).Message,
                stdout,
                stderr);
        }

        ProductProtectionReport report;
        if (command.InputBytes is null)
        {
            report = new ProductProtectionReport(
                1,
                ToolVersion,
                false,
                new ProductProtectionInputReport(null, null),
                options.Passes.Select(ProtectionPassOrdering.Describe).ToArray(),
                Array.Empty<ProductFunctionProtectionReport>(),
                new ProductProtectionOutputReport(false, null),
                command.Diagnostics.Select(ProductDiagnosticReport.From).ToArray())
            {
                Selectors = options.Functions.Select(selector => selector.ToDisplayString()).ToArray(),
            };
        }
        else
        {
            report = ProductReportFactory.CreateProtection(
                ToolVersion,
                command.InputBytes,
                command.Options,
                command.Protection);
        }

        var exitCode = command.Protection.IsSuccess && command.OutputPublished
            ? ProductExitCode.Success
            : command.Diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.InputIoFailure or DiagnosticCode.OutputIoFailure)
                ? ProductExitCode.FileSystem
                : ProductExitCode.Validation;
        return WriteProtectionResult(options, report, stdout, stderr, exitCode);
    }

    private static int RunProtectedImage(
        ProtectedImageOptions options,
        TextWriter stdout,
        TextWriter stderr)
    {
        var command = ProtectedImageCommandWorkflow.Execute(
            new ProtectedImageCommandRequest(
                options.InputPath,
                options.ArtifactPath,
                options.RolePath,
                options.ManifestPath,
                options.StagePath,
                options.JsonPath,
                options.UnitId,
                options.Profile,
                options.ProducerId,
                options.ProducerBuildSha256,
                options.RehydratorConsumerId,
                options.ExpectedSourceSha256,
                options.ExpectedRequestSha256,
                options.Functions,
                options.Passes,
                options.CommandArguments,
                ToolVersion)
            {
                ExternalJumpTableProviderInput = options.ExternalJumpTableProviderInput,
            });
        if (command.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict))
        {
            return WriteProtectedImageUsageFailure(
                options,
                command.Diagnostics.First(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict).Message,
                stdout,
                stderr);
        }

        var exitCode = command.IsSuccess
            ? ProductExitCode.Success
            : command.Diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.InputIoFailure or DiagnosticCode.OutputIoFailure)
                ? ProductExitCode.FileSystem
                : ProductExitCode.Validation;
        return WriteProtectedImageCommandResult(options, command, stdout, stderr, exitCode);
    }

    private static int RunRehydration(
        RehydrationCliOptions options,
        TextWriter stdout,
        TextWriter stderr)
    {
        var command = RehydrationCommandWorkflow.Execute(
            new RehydrationCommandRequest(
                options.InputPath,
                options.ArtifactPath,
                options.NativeImagePath,
                options.NativeImageRolePath,
                options.RecordPath,
                options.JsonPath,
                new RehydrationOptions(
                    options.SourceSha256,
                    options.RequestSha256,
                    options.UnitId,
                    options.Profile,
                    options.ProducerId,
                    options.ProducerBuildSha256,
                    options.ConsumerId,
                    options.ConsumerBuildSha256)
                {
                    ExternalJumpTableProviderInput = options.ExternalJumpTableProviderInput,
                }));
        if (command.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict))
        {
            stderr.WriteLine(command.Diagnostics.First(diagnostic => diagnostic.Code == DiagnosticCode.OutputPathConflict).Message);
            return (int)ProductExitCode.Usage;
        }

        var report = new RehydrationCommandReport(
            1,
            ToolVersion,
            command.IsSuccess,
            command.Record,
            command.IsSuccess ? command.NativeImage : null,
            command.Diagnostics.Select(ProductDiagnosticReport.From).ToArray());
        var reportWritten = WriteRehydrationCommandReport(options, report, stdout, stderr);
        if (!reportWritten)
        {
            return (int)ProductExitCode.FileSystem;
        }

        if (command.IsSuccess)
        {
            return (int)ProductExitCode.Success;
        }

        if (command.Diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.OutputIoFailure or DiagnosticCode.InputIoFailure))
        {
            return (int)ProductExitCode.FileSystem;
        }

        if (command.Diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.OutputIdentityMismatch or DiagnosticCode.ProtectedImageIntegrityMismatch))
        {
            return (int)ProductExitCode.OutputIdentity;
        }

        return (int)ProductExitCode.Validation;
    }

    private static bool WriteRehydrationCommandReport(
        RehydrationCliOptions options,
        RehydrationCommandReport report,
        TextWriter stdout,
        TextWriter stderr)
    {
        var json = RehydrationCommandReport.Serialize(report);
        if (options.JsonPath == "-")
        {
            CommandOutputWriter.WriteJson(stdout, json);
            return true;
        }

        foreach (var diagnostic in report.Diagnostics)
        {
            (diagnostic.Severity == nameof(DiagnosticSeverity.Error) ? stderr : stdout)
                .WriteLine($"{diagnostic.Severity} {diagnostic.Code}: {diagnostic.Message}");
        }

        if (report.Success)
        {
            stdout.WriteLine($"Native Image written to {options.NativeImagePath}.");
        }

        if (options.JsonPath is { Length: > 0 })
        {
            try
            {
                CommandOutputWriter.WriteAtomicJson(options.JsonPath, json);
            }
            catch (IOException exception)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return false;
            }
        }

        return true;
    }

    private static int WriteProtectedImageCommandResult(
        ProtectedImageOptions options,
        ProtectedImageCommandResult command,
        TextWriter stdout,
        TextWriter stderr,
        ProductExitCode exitCode)
    {
        var report = new ProtectedImageCommandReport(
            1,
            ToolVersion,
            exitCode == ProductExitCode.Success,
            command.Role,
            command.Stage,
            command.ArtifactPath,
            command.RolePath,
            command.ManifestPath,
            command.StagePath,
            command.Diagnostics.Select(ProductDiagnosticReport.From).ToArray());
        if (options.JsonPath == "-")
        {
            CommandOutputWriter.WriteJson(stdout, ProtectedImageCommandReport.Serialize(report));
        }
        else
        {
            foreach (var diagnostic in command.Diagnostics)
            {
                (diagnostic.IsError ? stderr : stdout).WriteLine(diagnostic);
            }

            if (exitCode == ProductExitCode.Success)
            {
                stdout.WriteLine($"Protected Image v1 written to {command.ArtifactPath}.");
                stdout.WriteLine($"Role record written to {command.RolePath}; stage record written to {command.StagePath}.");
            }
        }

        if (options.JsonPath is { Length: > 0 } and not "-")
        {
            try
            {
                CommandOutputWriter.WriteAtomicJson(options.JsonPath, ProtectedImageCommandReport.Serialize(report));
            }
            catch (IOException exception)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        return (int)exitCode;
    }

    private static int WriteUsageFailure(
        CliOptions options,
        string message,
        TextWriter stdout,
        TextWriter stderr)
    {
        if (options.JsonPath == "-")
        {
            CommandOutputWriter.WriteJson(
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

    private static int WriteProtectionUsageFailure(
        ProtectOptions options,
        string message,
        TextWriter stdout,
        TextWriter stderr)
    {
        if (options.JsonPath == "-")
        {
            var report = new ProductProtectionReport(
                1,
                ToolVersion,
                false,
                new ProductProtectionInputReport(null, null),
                options.Passes.Select(ProtectionPassOrdering.Describe).ToArray(),
                Array.Empty<ProductFunctionProtectionReport>(),
                new ProductProtectionOutputReport(false, null),
                new[] { ProductDiagnosticReport.From(DiagnosticSeverity.Error, "InvalidArgument", message) })
            {
                Selectors = options.Functions.Select(selector => selector.ToDisplayString()).ToArray(),
            };
            CommandOutputWriter.WriteJson(stdout, ProductReportFactory.Serialize(report));
        }
        else
        {
            stderr.WriteLine(message);
            PrintUsage(stderr);
        }

        return (int)ProductExitCode.Usage;
    }

    private static int WriteProtectedImageUsageFailure(
        ProtectedImageOptions options,
        string message,
        TextWriter stdout,
        TextWriter stderr)
    {
        if (options.JsonPath == "-")
        {
            var report = new ProtectedImageCommandReport(
                1,
                ToolVersion,
                false,
                null,
                null,
                options.ArtifactPath,
                options.RolePath,
                options.ManifestPath,
                options.StagePath,
                new[] { ProductDiagnosticReport.From(DiagnosticSeverity.Error, DiagnosticCode.InvalidArgument.ToString(), message) });
            CommandOutputWriter.WriteJson(stdout, ProtectedImageCommandReport.Serialize(report));
        }
        else
        {
            stderr.WriteLine(message);
            PrintUsage(stderr);
        }

        return (int)ProductExitCode.Usage;
    }

    private static int WritePackResult(
        PackOptions options,
        ElfPackResult result,
        TextWriter stdout,
        TextWriter stderr)
    {
        var report = ProductReportFactory.CreatePack(ToolVersion, result);
        if (options.JsonPath == "-")
        {
            CommandOutputWriter.WriteJson(stdout, ProductReportFactory.Serialize(report));
        }
        else
        {
            foreach (var diagnostic in result.Diagnostics)
            {
                (diagnostic.IsError ? stderr : stdout).WriteLine(diagnostic);
            }

            if (result.IsSuccess)
            {
                stdout.WriteLine(
                    $"Packed AArch64 payload for {result.Profile.ToCliValue()}: {result.SourceSize} source bytes, {result.EncodedSize} compressed bytes.");
                stdout.WriteLine($"Wrapper written to {result.OutputPath}.");
            }
        }

        if (options.JsonPath is { Length: > 0 } and not "-")
        {
            try
            {
                CommandOutputWriter.WriteAtomicJson(options.JsonPath, ProductReportFactory.Serialize(report));
            }
            catch (IOException exception)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        if (result.IsSuccess)
        {
            return (int)ProductExitCode.Success;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.OutputIoFailure or DiagnosticCode.InputIoFailure))
        {
            return (int)ProductExitCode.FileSystem;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.OutputIdentityMismatch or DiagnosticCode.PayloadIntegrityMismatch))
        {
            return (int)ProductExitCode.OutputIdentity;
        }

        return (int)ProductExitCode.Validation;
    }

    private static int WriteProtectionResult(
        ProtectOptions options,
        ProductProtectionReport report,
        TextWriter stdout,
        TextWriter stderr,
        ProductExitCode exitCode)
    {
        if (options.JsonPath == "-")
        {
            CommandOutputWriter.WriteJson(stdout, ProductReportFactory.Serialize(report));
        }
        else
        {
            foreach (var diagnostic in report.Diagnostics)
            {
                (diagnostic.Severity == nameof(DiagnosticSeverity.Error) ? stderr : stdout)
                    .WriteLine($"{diagnostic.Severity} {diagnostic.Code}: {diagnostic.Message}");
            }

            if (report.Success)
            {
                stdout.WriteLine($"Protected {report.Functions.Count(function => function.Transformed)} selected function(s).");
                stdout.WriteLine($"Protected output written to {options.OutputPath}.");
            }
        }

        if (options.JsonPath is { Length: > 0 } and not "-")
        {
            try
            {
                CommandOutputWriter.WriteAtomicJson(options.JsonPath, ProductReportFactory.Serialize(report));
            }
            catch (IOException exception)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        return (int)exitCode;
    }

    private static void WriteHumanResult(
        ValidationResult result,
        string? copyPath,
        TextWriter stdout,
        TextWriter stderr)
    {
        foreach (var diagnostic in result.Diagnostics)
        {
            (diagnostic.IsError ? stderr : stdout).WriteLine(diagnostic);
        }

        if (result.File is not null)
        {
            stdout.WriteLine(
                $"Validated AArch64 {result.File.Header.TypeName} {result.File.Kind}: "
                + $"{result.File.ProgramHeaders.Count} program headers, "
                + $"{result.File.DynamicEntries.Count} dynamic entries, "
                + $"{result.File.RelaRelocations.Count} RELA relocations.");
        }

        if (result.AnalysisMode == ValidationAnalysisMode.ObservationOnly)
        {
            stdout.WriteLine(
                $"Observation-only instruction analysis: {result.Analysis?.Candidates.Count ?? 0} candidate(s).");
        }

        if (result.IsSuccess && copyPath is not null)
        {
            stdout.WriteLine($"Byte-identical output written to {copyPath}.");
        }
    }

    private static int MapExitCode(ValidationResult result)
    {
        if (result.IsSuccess)
        {
            return (int)ProductExitCode.Success;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.OutputIdentityMismatch))
        {
            return (int)ProductExitCode.OutputIdentity;
        }

        if (result.Diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.InputIoFailure or DiagnosticCode.OutputIoFailure))
        {
            return (int)ProductExitCode.FileSystem;
        }

        return (int)ProductExitCode.Validation;
    }
}
