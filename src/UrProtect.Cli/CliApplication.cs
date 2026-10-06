using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Pack;
using UrProtect.Core.Pipeline;
using UrProtect.Core.Protect;
using UrProtect.Core.Rehydrate;

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
    private const uint MemfdCloexec = 1;

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

            if (string.Equals(args[0], "protect", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryParseProtectOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunProtect(options, stdout, stderr);
            }

            if (string.Equals(args[0], "protect-image", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryParseProtectedImageOptions(args, out var options, out var usageError))
                {
                    stderr.WriteLine(usageError);
                    PrintUsage(stderr);
                    return (int)ProductExitCode.Usage;
                }

                return RunProtectedImage(options, stdout, stderr);
            }

            if (string.Equals(args[0], "rehydrate-image", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryParseRehydrationOptions(args, out var options, out var usageError))
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

        int payloadFd;
        Microsoft.Win32.SafeHandles.SafeFileHandle? payloadHandle = null;
        FileStream? payloadStream = null;
        try
        {
            try
            {
                var payloadName = Marshal.StringToCoTaskMemUTF8("urprotect-payload");
                try
                {
                    payloadFd = MemfdCreate(payloadName, MemfdCloexec);
                }
                finally
                {
                    Marshal.FreeCoTaskMem(payloadName);
                }

                if (payloadFd < 0)
                {
                    Console.Error.WriteLine("OutputIoFailure: could not create an anonymous payload image.");
                    return (int)ProductExitCode.FileSystem;
                }

                payloadHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(
                    (IntPtr)payloadFd,
                    ownsHandle: true);
                payloadStream = new FileStream(payloadHandle, FileAccess.Write);
                payloadStream.Write(payload.SourceBytes);
                payloadStream.Flush(flushToDisk: true);
                if (Fchmod(payloadFd, 0x1C0) != 0)
                {
                    Console.Error.WriteLine("OutputIoFailure: could not make the anonymous payload executable.");
                    return (int)ProductExitCode.FileSystem;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                Console.Error.WriteLine($"OutputIoFailure: could not write the anonymous payload image: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }

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
            using var nativeArguments = NativeStringArray.Create(commandLine);
            using var nativeEnvironment = NativeStringArray.Create(environment);
            var emptyPath = Marshal.StringToCoTaskMemUTF8(string.Empty);
            try
            {
                var execResult = Execveat(
                    payloadFd,
                    emptyPath,
                    nativeArguments.Pointer,
                    nativeEnvironment.Pointer,
                    AtEmptyPath);
                if (execResult == 0)
                {
                    Console.Error.WriteLine("InternalFailure: execveat returned success without replacing the process.");
                    return (int)ProductExitCode.Internal;
                }

                var error = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"OutputIoFailure: execveat failed for the anonymous payload image (errno {error}).");
                return (int)ProductExitCode.FileSystem;
            }
            finally
            {
                Marshal.FreeCoTaskMem(emptyPath);
            }
        }
        catch (Exception exception) when (
            exception is DllNotFoundException
                or EntryPointNotFoundException
                or BadImageFormatException)
        {
            Console.Error.WriteLine(
                $"OutputIoFailure: the anonymous payload handoff is unavailable: {exception.Message}");
            return (int)ProductExitCode.FileSystem;
        }
        finally
        {
            payloadStream?.Dispose();
            payloadHandle?.Dispose();
        }
    }

    private const int AtEmptyPath = 0x1000;

    [DllImport("libc", EntryPoint = "memfd_create", SetLastError = true)]
    private static extern int MemfdCreate(
        IntPtr name,
        uint flags);

    [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
    private static extern int Fchmod(int fileDescriptor, uint mode);

    [DllImport("libc", EntryPoint = "execveat", SetLastError = true)]
    private static extern int Execveat(
        int directoryFileDescriptor,
        IntPtr path,
        IntPtr argv,
        IntPtr environment,
        int flags);

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
        writer.WriteLine("  urprotect pack <input> --output <wrapper> [--json <path|->] [--launcher <path>] [--profile <outer-execveat|host-context-entry>] [--entry-symbol <name>] [--thread-lifetime] [--path-preserving]");
        writer.WriteLine("  urprotect protect <input> --output <protected> --function <name>|--function-id <symtab|dynsym>:<index>|--function-address <0xaddr> --pass <control-flow-flattening|register-permutation> [--pass <...>] [--json <path|->]");
        writer.WriteLine("  urprotect protect-image <input> --artifact <path> --role <path> --manifest <path> --stage <path> --unit <id> --profile <outer-execveat|host-context-entry> --function <name>|--function-id <symtab|dynsym>:<index>|--function-address <0xaddr> --pass <control-flow-flattening|register-permutation> [--pass <...>] [--producer-id <id>] [--producer-build-sha256 <sha256>] [--rehydrator <id>] [--source-sha256 <sha256>] [--request-sha256 <sha256>] [--json <path|->]");
        writer.WriteLine("  urprotect rehydrate-image <source> --artifact <path> --native-image <path> --role <path> --record <path> --unit <id> --profile <outer-execveat|host-context-entry> --source-sha256 <sha256> --request-sha256 <sha256> --producer-id <id> --producer-build-sha256 <sha256> --consumer-id <id> --consumer-build-sha256 <sha256> [--json <path|->]");
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

        if (string.IsNullOrWhiteSpace(options.LauncherPath))
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
        return WritePackResult(options, result, stdout, stderr);
    }

    private static int RunProtect(ProtectOptions options, TextWriter stdout, TextWriter stderr)
    {
        if (HasConflictingProtectPaths(options, out var conflictMessage))
        {
            return WriteProtectionUsageFailure(options, conflictMessage, stdout, stderr);
        }

        byte[] input;
        try
        {
            input = File.ReadAllBytes(options.InputPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            var failureReport = new ProductProtectionReport(
                1,
                ToolVersion,
                false,
                new ProductProtectionInputReport(null, null),
                options.Passes.Select(pass => pass.ToString()).ToArray(),
                Array.Empty<ProductFunctionProtectionReport>(),
                new ProductProtectionOutputReport(false, null),
                new[]
                {
                    ProductDiagnosticReport.From(
                        DiagnosticSeverity.Error,
                        DiagnosticCode.InputIoFailure.ToString(),
                        exception.Message),
                });
            return WriteProtectionResult(options, failureReport, stdout, stderr, ProductExitCode.FileSystem);
        }

        var request = new FunctionProtectionOptions(options.Functions, options.Passes);
        var result = new FunctionProtectionService().Protect(input, request);
        var published = false;
        if (result.IsSuccess && result.OutputBytes is not null)
        {
            try
            {
                var sourceMode = OperatingSystem.IsWindows()
                    ? (UnixFileMode?)null
                    : File.GetUnixFileMode(options.InputPath);
                WriteAtomicBytes(options.OutputPath, result.OutputBytes, sourceMode);
                published = true;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                var diagnostics = result.Diagnostics.ToList();
                diagnostics.Add(new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.OutputIoFailure,
                    exception.Message));
                result = result with { OutputBytes = null, Diagnostics = diagnostics.ToArray() };
            }
        }

        var reportResult = result with { OutputBytes = published ? result.OutputBytes : null };
        var report = ProductReportFactory.CreateProtection(ToolVersion, input, request, reportResult);
        var exitCode = result.IsSuccess && published
            ? ProductExitCode.Success
            : result.Diagnostics.Any(diagnostic => diagnostic.Code is
                DiagnosticCode.InputIoFailure or DiagnosticCode.OutputIoFailure)
                ? ProductExitCode.FileSystem
                : ProductExitCode.Validation;
        return WriteProtectionResult(options, report, stdout, stderr, exitCode);
    }

    private static int RunProtectedImage(
        ProtectedImageOptions options,
        TextWriter stdout,
        TextWriter stderr)
    {
        if (HasConflictingProtectedImagePaths(options, out var conflictMessage))
        {
            return WriteProtectedImageUsageFailure(options, conflictMessage, stdout, stderr);
        }

        byte[] input;
        try
        {
            input = File.ReadAllBytes(options.InputPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            var diagnostics = new[]
            {
                new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.InputIoFailure,
                    exception.Message),
            };
            var stage = CreateProtectedImageStage(
                options,
                null,
                null,
                options.ProducerBuildSha256 ?? ComputeProducerBuildSha256(),
                null,
                "not-started",
                0,
                diagnostics,
                ProtectedImageStageRecord.FailedStatus,
                publicationComplete: false);
            var stageDiagnostics = WriteProtectedImageStage(options, stage);
            var allDiagnostics = diagnostics.Concat(stageDiagnostics).ToArray();
            return WriteProtectedImageCommandResult(
                options,
                null,
                stage with { Diagnostics = allDiagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray() },
                allDiagnostics,
                stdout,
                stderr,
                ProductExitCode.FileSystem);
        }

        var sourceSha256 = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        string? requestSha256 = null;
        try
        {
            requestSha256 = ProtectedImageCodec.ComputeRequestSha256(options.Functions, options.Passes);
        }
        catch (ArgumentException)
        {
            // The producer emits the stable request diagnostic; keep the stage
            // bounded even when the request cannot be represented.
        }

        var producerOptions = new ProtectedImageProducerOptions(
            options.UnitId,
            options.Profile,
            options.ProducerId,
            options.ProducerBuildSha256 ?? ComputeProducerBuildSha256(),
            options.RehydratorConsumerId,
            options.ExpectedSourceSha256,
            options.ExpectedRequestSha256);
        var request = new FunctionProtectionOptions(options.Functions, options.Passes);
        var emission = new ProtectedImageProducer().Emit(input, request, producerOptions);
        var transformedCount = emission.Functions.Count(function => function.Transformed);
        if (!emission.IsSuccess || emission.Role is null || emission.ArtifactBytes is null)
        {
            var failureStage = CreateProtectedImageStage(
                options,
                sourceSha256,
                requestSha256,
                emission.Role?.ProducerBuildSha256 ?? producerOptions.ProducerBuildSha256,
                null,
                emission.Functions.Count == 0 ? "not-started" : "failed",
                transformedCount,
                emission.Diagnostics,
                ProtectedImageStageRecord.FailedStatus,
                publicationComplete: false,
                analysisDurationMilliseconds: emission.AnalysisDurationMilliseconds,
                emissionDurationMilliseconds: emission.EmissionDurationMilliseconds);
            var stageDiagnostics = WriteProtectedImageStage(options, failureStage);
            var allDiagnostics = emission.Diagnostics.Concat(stageDiagnostics).ToArray();
            return WriteProtectedImageCommandResult(
                options,
                null,
                failureStage with { Diagnostics = allDiagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray() },
                allDiagnostics,
                stdout,
                stderr,
                ProductExitCode.Validation);
        }

        var successStage = CreateProtectedImageStage(
            options,
            emission.Role.SourceSha256,
            emission.Role.RequestSha256,
            emission.Role.ProducerBuildSha256,
            emission.Role,
            "passed",
            transformedCount,
            emission.Diagnostics,
            ProtectedImageStageRecord.PassedStatus,
            publicationComplete: true,
            analysisDurationMilliseconds: emission.AnalysisDurationMilliseconds,
            emissionDurationMilliseconds: emission.EmissionDurationMilliseconds);
        var publication = ProtectedImagePublisher.Publish(
            emission,
            options.ArtifactPath,
            options.RolePath,
            options.ManifestPath,
            options.StagePath,
            successStage);
        if (!publication.Published)
        {
            var diagnostics = emission.Diagnostics.Concat(publication.Diagnostics).ToArray();
            var failureStage = successStage with
            {
                Status = ProtectedImageStageRecord.FailedStatus,
                ArtifactSha256 = null,
                ArtifactSize = null,
                ArtifactRole = null,
                AbiId = null,
                AbiVersion = null,
                PublicationComplete = false,
                TransformationStatus = "publication-failed",
                Diagnostics = diagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray(),
            };
            var stageDiagnostics = WriteProtectedImageStage(options, failureStage);
            diagnostics = diagnostics.Concat(stageDiagnostics).ToArray();
            return WriteProtectedImageCommandResult(
                options,
                null,
                failureStage with { Diagnostics = diagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray() },
                diagnostics,
                stdout,
                stderr,
                diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.InputIoFailure or DiagnosticCode.OutputIoFailure)
                    ? ProductExitCode.FileSystem
                    : ProductExitCode.Validation);
        }

        var publishedRole = publication.Role ?? emission.Role;
        var publishedStage = successStage with
        {
            ArtifactPath = options.ArtifactPath,
            RolePath = options.RolePath,
            RawEvidenceManifestPath = options.ManifestPath,
            ArtifactSha256 = publishedRole.ArtifactSha256,
            ArtifactSize = publishedRole.ArtifactSize,
            Diagnostics = emission.Diagnostics.Select(ProtectedImageStageDiagnostic.From).ToArray(),
        };
        return WriteProtectedImageCommandResult(
            options,
            publishedRole,
            publishedStage,
            emission.Diagnostics,
            stdout,
            stderr,
            ProductExitCode.Success);
    }

    private static int RunRehydration(
        RehydrationCliOptions options,
        TextWriter stdout,
        TextWriter stderr)
    {
        if (HasConflictingRehydrationPaths(options, out var conflictMessage))
        {
            stderr.WriteLine(conflictMessage);
            return (int)ProductExitCode.Usage;
        }

        byte[] source;
        byte[] artifact;
        try
        {
            source = File.ReadAllBytes(options.InputPath);
            artifact = File.ReadAllBytes(options.ArtifactPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            var diagnostic = ProductDiagnosticReport.From(
                DiagnosticSeverity.Error,
                DiagnosticCode.InputIoFailure.ToString(),
                exception.Message);
            var failedReport = new RehydrationCommandReport(1, ToolVersion, false, null, null, new[] { diagnostic });
            WriteRehydrationCommandReport(options, failedReport, stdout, stderr);
            return (int)ProductExitCode.FileSystem;
        }

        var settings = new RehydrationOptions(
            options.SourceSha256,
            options.RequestSha256,
            options.UnitId,
            options.Profile,
            options.ProducerId,
            options.ProducerBuildSha256,
            options.ConsumerId,
            options.ConsumerBuildSha256);
        var result = GenericRehydrationEngine.Rehydrate(source, artifact, settings);
        var publication = RehydrationPublisher.Publish(
            result,
            options.NativeImagePath,
            options.NativeImageRolePath,
            options.RecordPath);
        var diagnostics = result.Diagnostics.Concat(publication.Diagnostics).ToList();
        var record = result.Record;
        if (!publication.Published && result.IsSuccess)
        {
            var publicationFailure = diagnostics.Where(diagnostic => diagnostic.IsError)
                .Select(diagnostic => (Diagnostic?)diagnostic)
                .LastOrDefault()
                ?? new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.OutputIoFailure, "Native Image publication failed.");
            record = record with
            {
                Status = RehydrationRecord.FailedStatus,
                NativeImageSha256 = null,
                NativeImageSize = null,
                MaterializationStatus = "failed",
                FirstFailureStage = RehydrationRecord.StageName,
                Diagnostics = record.Diagnostics.Concat(new[] { RehydrationDiagnostic.From(publicationFailure) })
                    .Take(RehydrationLimits.MaximumDiagnostics)
                    .ToArray(),
            };
            if (!RehydrationPublisher.WriteFailureRecord(record, options.RecordPath, out var writeDiagnostics))
            {
                diagnostics.AddRange(writeDiagnostics);
            }
        }

        var successfulPublication = publication.Published && result.IsSuccess;
        var report = new RehydrationCommandReport(
            1,
            ToolVersion,
            successfulPublication,
            record,
            successfulPublication ? publication.Descriptor ?? result.NativeImage?.Descriptor : null,
            diagnostics.Select(ProductDiagnosticReport.From).ToArray());
        var reportWritten = WriteRehydrationCommandReport(options, report, stdout, stderr);
        if (!reportWritten)
        {
            return (int)ProductExitCode.FileSystem;
        }

        if (successfulPublication)
        {
            return (int)ProductExitCode.Success;
        }

        if (diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.OutputIoFailure or DiagnosticCode.InputIoFailure))
        {
            return (int)ProductExitCode.FileSystem;
        }

        if (diagnostics.Any(diagnostic => diagnostic.Code is DiagnosticCode.OutputIdentityMismatch or DiagnosticCode.ProtectedImageIntegrityMismatch))
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
            WriteJson(stdout, json);
            return true;
        }

        var success = true;

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
                WriteAtomicJson(options.JsonPath, json);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                success = false;
            }
        }

        return success;
    }

    private static bool HasConflictingRehydrationPaths(RehydrationCliOptions options, out string message)
    {
        message = string.Empty;
        try
        {
            var paths = new List<string>
            {
                Path.GetFullPath(options.InputPath),
                Path.GetFullPath(options.ArtifactPath),
                Path.GetFullPath(options.NativeImagePath),
                Path.GetFullPath(options.NativeImageRolePath),
                Path.GetFullPath(options.RecordPath),
            };
            if (options.JsonPath is { Length: > 0 } and not "-")
            {
                paths.Add(Path.GetFullPath(options.JsonPath));
            }

            var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
            if (paths.Distinct(comparer).Count() != paths.Count)
            {
                message = "Usage: rehydrate-image input and evidence output paths must be distinct.";
                return true;
            }
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            message = $"Usage: invalid rehydration output path: {exception.Message}";
            return true;
        }

        return false;
    }

    private static ProtectedImageStageRecord CreateProtectedImageStage(
        ProtectedImageOptions options,
        string? sourceSha256,
        string? requestSha256,
        string producerBuildSha256,
        ProtectedImageRoleRecord? role,
        string transformationStatus,
        int transformedCount,
        IEnumerable<Diagnostic> diagnostics,
        string status,
        bool publicationComplete,
        long? analysisDurationMilliseconds = null,
        long? emissionDurationMilliseconds = null) =>
        ProtectedImageStageRecord.Create(
            status,
            options.UnitId,
            options.Profile,
            sourceSha256,
            requestSha256,
            options.ProducerId,
            producerBuildSha256,
            options.RehydratorConsumerId,
            role?.ArtifactSha256,
            role?.ArtifactSize,
            ComputeCommandDigest(options.CommandArguments),
            ComputeEnvironmentDigest(),
            options.ArtifactPath,
            options.RolePath,
            options.ManifestPath,
            transformationStatus,
            transformedCount,
            options.Functions.Select(selector => selector.ToDisplayString()).ToArray(),
            ProtectionPassOrdering.Normalize(options.Passes).Select(ProtectionPassOrdering.Describe).ToArray(),
            diagnostics,
            publicationComplete,
            analysisDurationMilliseconds,
            emissionDurationMilliseconds);

    private static IReadOnlyList<Diagnostic> WriteProtectedImageStage(
        ProtectedImageOptions options,
        ProtectedImageStageRecord stage)
    {
        if (ProtectedImagePublisher.WriteStage(options.StagePath, stage, out var diagnostics))
        {
            return diagnostics;
        }

        return diagnostics;
    }

    private static int WriteProtectedImageCommandResult(
        ProtectedImageOptions options,
        ProtectedImageRoleRecord? role,
        ProtectedImageStageRecord stage,
        IEnumerable<Diagnostic> diagnostics,
        TextWriter stdout,
        TextWriter stderr,
        ProductExitCode exitCode)
    {
        var diagnosticArray = diagnostics.ToArray();
        var report = new ProtectedImageCommandReport(
            1,
            ToolVersion,
            exitCode == ProductExitCode.Success,
            role,
            stage,
            options.ArtifactPath,
            options.RolePath,
            options.ManifestPath,
            options.StagePath,
            diagnosticArray.Select(ProductDiagnosticReport.From).ToArray());
        if (options.JsonPath == "-")
        {
            WriteJson(stdout, ProtectedImageCommandReport.Serialize(report));
        }
        else
        {
            foreach (var diagnostic in diagnosticArray)
            {
                (diagnostic.IsError ? stderr : stdout).WriteLine(diagnostic);
            }

            if (exitCode == ProductExitCode.Success)
            {
                stdout.WriteLine($"Protected Image v1 written to {options.ArtifactPath}.");
                stdout.WriteLine($"Role record written to {options.RolePath}; stage record written to {options.StagePath}.");
            }
        }

        if (options.JsonPath is { Length: > 0 } and not "-")
        {
            try
            {
                WriteAtomicJson(options.JsonPath, ProtectedImageCommandReport.Serialize(report));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        return (int)exitCode;
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
            WriteJson(stdout, ProtectedImageCommandReport.Serialize(report));
        }
        else
        {
            stderr.WriteLine(message);
            PrintUsage(stderr);
        }

        return (int)ProductExitCode.Usage;
    }

    private static bool HasConflictingProtectedImagePaths(ProtectedImageOptions options, out string message)
    {
        message = string.Empty;
        try
        {
            var paths = new List<string>
            {
                Path.GetFullPath(options.InputPath),
                Path.GetFullPath(options.ArtifactPath),
                Path.GetFullPath(options.RolePath),
                Path.GetFullPath(options.ManifestPath),
                Path.GetFullPath(options.StagePath),
            };
            if (options.JsonPath is { Length: > 0 } and not "-")
            {
                paths.Add(Path.GetFullPath(options.JsonPath));
            }
            var comparer = OperatingSystem.IsWindows()
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal;
            if (paths.Distinct(comparer).Count() != paths.Count)
            {
                message = "Usage: protect-image input and evidence output paths must be distinct.";
                return true;
            }
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            message = $"Usage: invalid Protected Image output path: {exception.Message}";
            return true;
        }

        return false;
    }

    private static string ComputeCommandDigest(IReadOnlyList<string> arguments) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join('\0', arguments.Select(argument => argument ?? string.Empty)) + '\0'))).ToLowerInvariant();

    private static string ComputeEnvironmentDigest()
    {
        var values = Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .Select(entry => $"{entry.Key}={entry.Value}")
            .OrderBy(value => value, StringComparer.Ordinal)
            .Take(ProtectedImageStageLimits.MaximumEnvironmentEntries)
            .ToArray();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\0', values) + '\0'))).ToLowerInvariant();
    }

    private static string ComputeProducerBuildSha256()
    {
        try
        {
            var location = typeof(CliApplication).Assembly.Location;
            if (!string.IsNullOrWhiteSpace(location) && File.Exists(location))
            {
                return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(location))).ToLowerInvariant();
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Fall through to the deterministic tool identity when the single-file
            // or test host does not expose a readable assembly path.
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"urprotect-cli:{ToolVersion}"))).ToLowerInvariant();
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
        var profile = PayloadDispatchProfile.OuterExecveat;
        var entrySymbol = HostContextContract.EntrySymbol;
        var requireThreadLifetime = false;
        var allowPathSensitiveOuter = false;
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
                case "--profile" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (!PayloadDispatchProfileExtensions.TryParse(args[++index], out profile))
                    {
                        error = "Usage: --profile must be outer-execveat or host-context-entry.";
                        return false;
                    }

                    break;
                case "--thread-lifetime":
                    if (requireThreadLifetime)
                    {
                        error = "Usage: --thread-lifetime may be specified only once.";
                        return false;
                    }
                    requireThreadLifetime = true;
                    break;
                case "--path-preserving":
                    if (allowPathSensitiveOuter)
                    {
                        error = "Usage: --path-preserving may be specified only once.";
                        return false;
                    }

                    allowPathSensitiveOuter = true;
                    break;
                case "--entry-symbol" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (entrySymbol != HostContextContract.EntrySymbol)
                    {
                        error = "Usage: --entry-symbol may be specified only once.";
                        return false;
                    }

                    entrySymbol = args[++index];
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

        if (profile == PayloadDispatchProfile.OuterExecveat && requireThreadLifetime)
        {
            error = "Usage: --thread-lifetime requires --profile host-context-entry.";
            return false;
        }

        if (profile == PayloadDispatchProfile.OuterExecveat
            && entrySymbol != HostContextContract.EntrySymbol)
        {
            error = "Usage: --entry-symbol requires --profile host-context-entry.";
            return false;
        }

        options = new PackOptions(args[1], outputPath, jsonPath, launcherPath, profile, entrySymbol, requireThreadLifetime, allowPathSensitiveOuter);
        return true;
    }

    private static bool TryParseRehydrationOptions(
        string[] args,
        out RehydrationCliOptions options,
        out string error)
    {
        options = null!;
        error = string.Empty;
        if (args.Length < 2 || args[1].StartsWith('-'))
        {
            error = "Usage: the rehydrate-image command requires a source image path.";
            return false;
        }

        string? artifactPath = null;
        string? nativeImagePath = null;
        string? nativeImageRolePath = null;
        string? recordPath = null;
        string? unitId = null;
        string? sourceSha256 = null;
        string? requestSha256 = null;
        string? producerId = null;
        string? producerBuildSha256 = null;
        string? consumerId = null;
        string? consumerBuildSha256 = null;
        string? jsonPath = null;
        var profile = default(ProtectedImageProfile);
        var profileSet = false;

        for (var index = 2; index < args.Length; index++)
        {
            var flag = args[index];
            if (index + 1 >= args.Length
                || (args[index + 1].StartsWith('-') && !(flag == "--json" && args[index + 1] == "-")))
            {
                error = $"Usage: {flag} requires a value.";
                return false;
            }

            var value = args[++index];
            switch (flag)
            {
                case "--artifact":
                    if (!SetOnce(ref artifactPath, value, flag, out error)) return false;
                    break;
                case "--native-image":
                    if (!SetOnce(ref nativeImagePath, value, flag, out error)) return false;
                    break;
                case "--role":
                    if (!SetOnce(ref nativeImageRolePath, value, flag, out error)) return false;
                    break;
                case "--record":
                    if (!SetOnce(ref recordPath, value, flag, out error)) return false;
                    break;
                case "--unit":
                    if (!SetOnce(ref unitId, value, flag, out error)) return false;
                    break;
                case "--profile":
                    if (profileSet || !ProtectedImageProfileExtensions.TryParse(value, out profile))
                    {
                        error = "Usage: --profile must be specified once as outer-execveat or host-context-entry.";
                        return false;
                    }

                    profileSet = true;
                    break;
                case "--source-sha256":
                    if (!SetOnce(ref sourceSha256, value, flag, out error)) return false;
                    break;
                case "--request-sha256":
                    if (!SetOnce(ref requestSha256, value, flag, out error)) return false;
                    break;
                case "--producer-id":
                    if (!SetOnce(ref producerId, value, flag, out error)) return false;
                    break;
                case "--producer-build-sha256":
                    if (!SetOnce(ref producerBuildSha256, value, flag, out error)) return false;
                    break;
                case "--consumer-id":
                    if (!SetOnce(ref consumerId, value, flag, out error)) return false;
                    break;
                case "--consumer-build-sha256":
                    if (!SetOnce(ref consumerBuildSha256, value, flag, out error)) return false;
                    break;
                case "--json":
                    if (!SetOnce(ref jsonPath, value, flag, out error)) return false;
                    break;
                default:
                    error = $"Usage: unknown rehydrate-image argument '{flag}'.";
                    return false;
            }
        }

        if (new[] { artifactPath, nativeImagePath, nativeImageRolePath, recordPath, unitId,
                sourceSha256, requestSha256, producerId, producerBuildSha256, consumerId, consumerBuildSha256 }
            .Any(string.IsNullOrWhiteSpace) || !profileSet)
        {
            error = "Usage: rehydrate-image requires artifact, output, record, unit, profile, digest, producer, and consumer bindings.";
            return false;
        }

        options = new RehydrationCliOptions(
            args[1], artifactPath!, nativeImagePath!, nativeImageRolePath!, recordPath!, jsonPath,
            unitId!, profile, sourceSha256!, requestSha256!, producerId!, producerBuildSha256!, consumerId!, consumerBuildSha256!);
        return true;

        static bool SetOnce(ref string? target, string value, string flag, out string usageError)
        {
            if (target is not null)
            {
                usageError = $"Usage: {flag} may be specified only once.";
                return false;
            }

            target = value;
            usageError = string.Empty;
            return true;
        }
    }

    private static bool TryParseProtectedImageOptions(
        string[] args,
        out ProtectedImageOptions options,
        out string error)
    {
        options = null!;
        error = string.Empty;
        if (args.Length < 2 || args[1].StartsWith('-'))
        {
            error = "Usage: the protect-image command requires an input path.";
            return false;
        }

        string? artifactPath = null;
        string? rolePath = null;
        string? manifestPath = null;
        string? stagePath = null;
        string? jsonPath = null;
        string? unitId = null;
        string? producerId = null;
        string? producerBuildSha256 = null;
        string? rehydratorConsumerId = null;
        string? expectedSourceSha256 = null;
        string? expectedRequestSha256 = null;
        ProtectedImageProfile profile = default;
        var profileSet = false;
        var functions = new List<FunctionSelector>();
        var passes = new List<ProtectionPass>();
        for (var index = 2; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--artifact":
                case "--artifact-path":
                case "--artifact-output":
                case "--output" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || artifactPath is not null)
                    {
                        error = "Usage: protect-image requires one --artifact <path>.";
                        return false;
                    }

                    artifactPath = args[++index];
                    break;
                case "--role":
                case "--role-path":
                case "--role-output" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || rolePath is not null)
                    {
                        error = "Usage: --role requires one output path and may be specified only once.";
                        return false;
                    }

                    rolePath = args[++index];
                    break;
                case "--manifest":
                case "--manifest-path":
                case "--manifest-output" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || manifestPath is not null)
                    {
                        error = "Usage: --manifest requires one output path and may be specified only once.";
                        return false;
                    }

                    manifestPath = args[++index];
                    break;
                case "--stage":
                case "--stage-path":
                case "--stage-output" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || stagePath is not null)
                    {
                        error = "Usage: --stage requires one output path and may be specified only once.";
                        return false;
                    }

                    stagePath = args[++index];
                    break;
                case "--unit" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (unitId is not null)
                    {
                        error = "Usage: --unit may be specified only once.";
                        return false;
                    }

                    unitId = args[++index];
                    break;
                case "--profile" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (profileSet || !ProtectedImageProfileExtensions.TryParse(args[index + 1], out profile))
                    {
                        error = "Usage: --profile must be outer-execveat or host-context-entry.";
                        return false;
                    }

                    profileSet = true;
                    index++;
                    break;
                case "--producer-id" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (producerId is not null)
                    {
                        error = "Usage: --producer-id may be specified only once.";
                        return false;
                    }

                    producerId = args[++index];
                    break;
                case "--producer-build-sha256":
                case "--producer-build" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || producerBuildSha256 is not null)
                    {
                        error = "Usage: --producer-build-sha256 requires one SHA-256 value.";
                        return false;
                    }

                    producerBuildSha256 = args[++index].ToLowerInvariant();
                    if (!IsSha256(producerBuildSha256))
                    {
                        error = "Usage: --producer-build-sha256 must contain exactly 64 hexadecimal characters.";
                        return false;
                    }

                    break;
                case "--rehydrator":
                case "--rehydrator-consumer" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || rehydratorConsumerId is not null)
                    {
                        error = "Usage: --rehydrator requires one consumer ID.";
                        return false;
                    }

                    rehydratorConsumerId = args[++index];
                    break;
                case "--source-sha256":
                case "--expected-source-sha256" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || expectedSourceSha256 is not null)
                    {
                        error = "Usage: --source-sha256 requires one SHA-256 value.";
                        return false;
                    }

                    expectedSourceSha256 = args[++index].ToLowerInvariant();
                    if (!IsSha256(expectedSourceSha256))
                    {
                        error = "Usage: --source-sha256 must contain exactly 64 hexadecimal characters.";
                        return false;
                    }

                    break;
                case "--request-sha256":
                case "--expected-request-sha256" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || expectedRequestSha256 is not null)
                    {
                        error = "Usage: --request-sha256 requires one SHA-256 value.";
                        return false;
                    }

                    expectedRequestSha256 = args[++index].ToLowerInvariant();
                    if (!IsSha256(expectedRequestSha256))
                    {
                        error = "Usage: --request-sha256 must contain exactly 64 hexadecimal characters.";
                        return false;
                    }

                    break;
                case "--function" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    functions.Add(FunctionSelector.ByName(args[++index]));
                    break;
                case "--function-id" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    var identity = args[++index].Split(':', 2);
                    if (identity.Length != 2
                        || !TryParseSymbolTable(identity[0], out var symbolTable)
                        || !uint.TryParse(
                            identity[1],
                            System.Globalization.NumberStyles.None,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out var symbolIndex))
                    {
                        error = "Usage: --function-id must be symtab:<decimal-index> or dynsym:<decimal-index>.";
                        return false;
                    }

                    if (!TryAddFunctionSelector(functions, new FunctionSelector(null, symbolTable, symbolIndex), out error))
                    {
                        return false;
                    }

                    break;
                case "--function-address" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    var addressText = args[++index];
                    if (!addressText.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        || !ulong.TryParse(
                            addressText[2..],
                            System.Globalization.NumberStyles.AllowHexSpecifier,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out var address))
                    {
                        error = "Usage: --function-address must be a hexadecimal virtual address such as 0x1234.";
                        return false;
                    }

                    if (!TryAddFunctionSelector(functions, new FunctionSelector(null, Address: address), out error))
                    {
                        return false;
                    }

                    break;
                case "--pass" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    var passValue = args[++index];
                    if (!TryParseProtectionPass(passValue, out var pass))
                    {
                        error = "Usage: --pass must be control-flow-flattening or register-permutation.";
                        return false;
                    }

                    if (!passes.Contains(pass))
                    {
                        passes.Add(pass);
                    }

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
                case "-h":
                case "--help":
                    error = "Usage: help is only valid before the command.";
                    return false;
                default:
                    error = $"Usage: unknown argument '{args[index]}'.";
                    return false;
            }
        }

        if (string.IsNullOrWhiteSpace(artifactPath)
            || string.IsNullOrWhiteSpace(rolePath)
            || string.IsNullOrWhiteSpace(manifestPath)
            || string.IsNullOrWhiteSpace(stagePath))
        {
            error = "Usage: protect-image requires --artifact, --role, --manifest, and --stage paths.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(unitId) || !profileSet)
        {
            error = "Usage: protect-image requires --unit and --profile.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(producerId))
        {
            producerId = "urprotect.cli.protect-image";
        }

        if (string.IsNullOrWhiteSpace(rehydratorConsumerId))
        {
            rehydratorConsumerId = ProtectedImageAbiV1.DefaultRehydratorConsumerId;
        }

        if (functions.Count == 0 || passes.Count == 0)
        {
            error = "Usage: protect-image requires at least one explicit function selector and one --pass.";
            return false;
        }

        options = new ProtectedImageOptions(
            args[1],
            artifactPath,
            rolePath,
            manifestPath,
            stagePath,
            jsonPath,
            unitId,
            profile,
            producerId,
            producerBuildSha256,
            rehydratorConsumerId,
            expectedSourceSha256,
            expectedRequestSha256,
            functions,
            passes,
            args.ToArray());
        return true;
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool TryParseProtectOptions(
        string[] args,
        out ProtectOptions options,
        out string error)
    {
        options = null!;
        error = string.Empty;
        if (args.Length < 2 || args[1].StartsWith('-'))
        {
            error = "Usage: the protect command requires an input path.";
            return false;
        }

        string? outputPath = null;
        string? jsonPath = null;
        var functions = new List<FunctionSelector>();
        var passes = new List<ProtectionPass>();
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
                case "--function" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    functions.Add(FunctionSelector.ByName(args[++index]));
                    break;
                case "--function-id" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    var identity = args[++index].Split(':', 2);
                    if (identity.Length != 2
                        || !TryParseSymbolTable(identity[0], out var symbolTable)
                        || !uint.TryParse(
                            identity[1],
                            System.Globalization.NumberStyles.None,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out var symbolIndex))
                    {
                        error = "Usage: --function-id must be symtab:<decimal-index> or dynsym:<decimal-index>.";
                        return false;
                    }

                    var identitySelector = new FunctionSelector(null, symbolTable, symbolIndex);
                    if (!TryAddFunctionSelector(
                            functions,
                            identitySelector,
                            out error))
                    {
                        return false;
                    }

                    break;
                case "--function-address" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    var addressText = args[++index];
                    if (!addressText.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        || !ulong.TryParse(
                            addressText[2..],
                            System.Globalization.NumberStyles.AllowHexSpecifier,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out var address))
                    {
                        error = "Usage: --function-address must be a hexadecimal virtual address such as 0x1234.";
                        return false;
                    }

                    if (!TryAddFunctionSelector(
                            functions,
                            new FunctionSelector(null, Address: address),
                            out error))
                    {
                        return false;
                    }

                    break;
                case "--pass" when index + 1 < args.Length && !args[index + 1].StartsWith('-'):
                    var passValue = args[++index];
                    if (!TryParseProtectionPass(passValue, out var pass))
                    {
                        error = "Usage: --pass must be control-flow-flattening or register-permutation.";
                        return false;
                    }

                    if (!passes.Contains(pass))
                    {
                        passes.Add(pass);
                    }
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
            error = "Usage: protect requires --output <protected>.";
            return false;
        }

        if (functions.Count == 0)
        {
            error = "Usage: protect requires at least one --function <name>.";
            return false;
        }

        if (passes.Count == 0)
        {
            error = "Usage: protect requires at least one --pass.";
            return false;
        }

        options = new ProtectOptions(args[1], outputPath, jsonPath, functions, passes);
        return true;
    }

    private static bool TryAddFunctionSelector(
        List<FunctionSelector> selectors,
        FunctionSelector disambiguator,
        out string error)
    {
        error = string.Empty;
        if (selectors.Count == 0)
        {
            selectors.Add(disambiguator);
            return true;
        }

        var lastIndex = selectors.Count - 1;
        var previous = selectors[lastIndex];
        var canRefinePrevious = previous.Name is not null
            || previous.Table.HasValue
            || previous.TableIndex.HasValue;
        if (!canRefinePrevious)
        {
            selectors.Add(disambiguator);
            return true;
        }

        if (disambiguator.Table.HasValue
            && previous.Table.HasValue
            && previous.Table.Value != disambiguator.Table.Value)
        {
            error = "Usage: a function selector cannot combine two different symbol tables.";
            return false;
        }

        if (disambiguator.TableIndex.HasValue
            && previous.TableIndex.HasValue
            && previous.TableIndex.Value != disambiguator.TableIndex.Value)
        {
            error = "Usage: a function selector cannot combine two different symbol indices.";
            return false;
        }

        if (disambiguator.Address.HasValue
            && previous.Address.HasValue
            && previous.Address.Value != disambiguator.Address.Value)
        {
            error = "Usage: a function selector cannot combine two different function addresses.";
            return false;
        }

        selectors[lastIndex] = previous with
        {
            Table = previous.Table ?? disambiguator.Table,
            TableIndex = previous.TableIndex ?? disambiguator.TableIndex,
            Address = previous.Address ?? disambiguator.Address,
        };
        return true;
    }

    private static bool TryParseSymbolTable(string value, out ElfSymbolTableKind table)
    {
        if (string.Equals(value, "symtab", StringComparison.Ordinal))
        {
            table = ElfSymbolTableKind.Static;
            return true;
        }

        if (string.Equals(value, "dynsym", StringComparison.Ordinal))
        {
            table = ElfSymbolTableKind.Dynamic;
            return true;
        }

        table = default;
        return false;
    }

    private static bool TryParseProtectionPass(string value, out ProtectionPass pass)
    {
        pass = value switch
        {
            "control-flow-flattening" => ProtectionPass.ControlFlowFlattening,
            "register-permutation" => ProtectionPass.RegisterPermutation,
            _ => default,
        };
        return value is "control-flow-flattening" or "register-permutation";
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

    private static bool HasConflictingProtectPaths(ProtectOptions options, out string message)
    {
        message = string.Empty;
        try
        {
            var input = Path.GetFullPath(options.InputPath);
            var output = Path.GetFullPath(options.OutputPath);
            var json = options.JsonPath is null or "-" ? null : Path.GetFullPath(options.JsonPath);
            var comparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            if (string.Equals(input, output, comparison))
            {
                message = "Usage: --output must point to a path different from the input.";
                return true;
            }

            if (json is not null
                && (string.Equals(input, json, comparison)
                    || string.Equals(output, json, comparison)))
            {
                message = "Usage: --json must point to a path different from input and protected output.";
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
                options.Passes.Select(pass => pass.ToString()).ToArray(),
                Array.Empty<ProductFunctionProtectionReport>(),
                new ProductProtectionOutputReport(false, null),
                new[] { ProductDiagnosticReport.From(DiagnosticSeverity.Error, "InvalidArgument", message) });
            WriteJson(stdout, ProductReportFactory.Serialize(report));
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
                    $"Packed AArch64 payload for {result.Profile.ToCliValue()}: {result.SourceSize} source bytes, "
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

    private static int WriteProtectionResult(
        ProtectOptions options,
        ProductProtectionReport report,
        TextWriter stdout,
        TextWriter stderr,
        ProductExitCode exitCode)
    {
        if (options.JsonPath == "-")
        {
            WriteJson(stdout, ProductReportFactory.Serialize(report));
        }
        else
        {
            foreach (var diagnostic in report.Diagnostics)
            {
                var writer = diagnostic.Severity == nameof(DiagnosticSeverity.Error) ? stderr : stdout;
                writer.WriteLine($"{diagnostic.Severity} {diagnostic.Code}: {diagnostic.Message}");
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
                WriteAtomicJson(options.JsonPath, ProductReportFactory.Serialize(report));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                stderr.WriteLine($"OutputIoFailure: {exception.Message}");
                return (int)ProductExitCode.FileSystem;
            }
        }

        return (int)exitCode;
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
                $"Validated AArch64 {result.File.Header.TypeName} {result.File.Kind}: "
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

    private static void WriteAtomicBytes(string path, byte[] bytes, UnixFileMode? sourceMode = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(bytes);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"The output directory does not exist: {directory}");
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
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (sourceMode is { } mode && !OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temporaryPath, mode);
            }

            var published = File.ReadAllBytes(temporaryPath);
            if (!published.AsSpan().SequenceEqual(bytes))
            {
                throw new IOException("The protected output changed before publication.");
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
                // Preserve the original publication error.
            }
            catch (UnauthorizedAccessException)
            {
                // Preserve the original publication error.
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
        string? LauncherPath,
        PayloadDispatchProfile Profile,
        string EntrySymbol,
        bool RequireThreadLifetime,
        bool AllowPathSensitiveOuter);

    private sealed record ProtectOptions(
        string InputPath,
        string OutputPath,
        string? JsonPath,
        IReadOnlyList<FunctionSelector> Functions,
        IReadOnlyList<ProtectionPass> Passes);

    private sealed record ProtectedImageOptions(
        string InputPath,
        string ArtifactPath,
        string RolePath,
        string ManifestPath,
        string StagePath,
        string? JsonPath,
        string UnitId,
        ProtectedImageProfile Profile,
        string ProducerId,
        string? ProducerBuildSha256,
        string RehydratorConsumerId,
        string? ExpectedSourceSha256,
        string? ExpectedRequestSha256,
        IReadOnlyList<FunctionSelector> Functions,
        IReadOnlyList<ProtectionPass> Passes,
        IReadOnlyList<string> CommandArguments);

    private sealed record RehydrationCliOptions(
        string InputPath,
        string ArtifactPath,
        string NativeImagePath,
        string NativeImageRolePath,
        string RecordPath,
        string? JsonPath,
        string UnitId,
        ProtectedImageProfile Profile,
        string SourceSha256,
        string RequestSha256,
        string ProducerId,
        string ProducerBuildSha256,
        string ConsumerId,
        string ConsumerBuildSha256);
}
