using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Application;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Validation;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Cli.Parsing;

/// <summary>
/// Canonical command grammar and argument-to-option translation.
/// </summary>
internal static class CommandLineParser
{
    internal static bool TryParseValidationOptions(
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
        var analysisMode = ValidationAnalysisMode.StructuralOnly;
        var analysisOption = false;
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
                case "--observe-analysis":
                    if (analysisOption)
                    {
                        error = "Usage: --observe-analysis may be specified only once.";
                        return false;
                    }

                    analysisMode = ValidationAnalysisMode.ObservationOnly;
                    analysisOption = true;
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

        options = new CliOptions(args[1], copyPath, jsonPath, analysisMode);
        return true;
    }

    internal static bool TryParsePackOptions(
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

    internal static bool TryParseRehydrationOptions(
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
        string? providerFile = null;
        string? providerSoname = null;
        string? providerBuildId = null;
        string? providerSha256 = null;
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
                case "--provider-file":
                    if (!SetOnce(ref providerFile, value, flag, out error)) return false;
                    break;
                case "--provider-soname":
                    if (!SetOnce(ref providerSoname, value, flag, out error)) return false;
                    break;
                case "--provider-build-id":
                    if (!SetOnce(ref providerBuildId, value, flag, out error)) return false;
                    break;
                case "--provider-sha256":
                    if (!SetOnce(ref providerSha256, value, flag, out error)) return false;
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

        if (!TryCreateExternalProviderInput(
                providerFile, providerSoname, providerBuildId, providerSha256,
                out var externalProviderInput, out error))
        {
            return false;
        }

        options = new RehydrationCliOptions(
            args[1], artifactPath!, nativeImagePath!, nativeImageRolePath!, recordPath!, jsonPath,
            unitId!, profile, sourceSha256!, requestSha256!, producerId!, producerBuildSha256!, consumerId!, consumerBuildSha256!)
        {
            ExternalJumpTableProviderInput = externalProviderInput,
        };
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

    internal static bool TryParseProtectedImageOptions(
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
        string? providerFile = null;
        string? providerSoname = null;
        string? providerBuildId = null;
        string? providerSha256 = null;
        ProtectedImageProfile profile = default;
        var profileSet = false;
        var functions = new List<FunctionSelector>();
        var passes = new List<ProtectionPass>();
        for (var index = 2; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--artifact":
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || artifactPath is not null)
                    {
                        error = "Usage: protect-image requires one --artifact <path>.";
                        return false;
                    }

                    artifactPath = args[++index];
                    break;
                case "--role":
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || rolePath is not null)
                    {
                        error = "Usage: --role requires one output path and may be specified only once.";
                        return false;
                    }

                    rolePath = args[++index];
                    break;
                case "--manifest":
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || manifestPath is not null)
                    {
                        error = "Usage: --manifest requires one output path and may be specified only once.";
                        return false;
                    }

                    manifestPath = args[++index];
                    break;
                case "--stage":
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
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || rehydratorConsumerId is not null)
                    {
                        error = "Usage: --rehydrator requires one consumer ID.";
                        return false;
                    }

                    rehydratorConsumerId = args[++index];
                    break;
                case "--source-sha256":
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
                case "--provider-file":
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || providerFile is not null)
                    {
                        error = "Usage: --provider-file requires one provider path and may be specified only once.";
                        return false;
                    }
                    providerFile = args[++index];
                    break;
                case "--provider-soname":
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || providerSoname is not null)
                    {
                        error = "Usage: --provider-soname requires one value and may be specified only once.";
                        return false;
                    }
                    providerSoname = args[++index];
                    break;
                case "--provider-build-id":
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || providerBuildId is not null)
                    {
                        error = "Usage: --provider-build-id requires one value and may be specified only once.";
                        return false;
                    }
                    providerBuildId = args[++index].ToLowerInvariant();
                    break;
                case "--provider-sha256":
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-') || providerSha256 is not null)
                    {
                        error = "Usage: --provider-sha256 requires one value and may be specified only once.";
                        return false;
                    }
                    providerSha256 = args[++index].ToLowerInvariant();
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

        if (!TryCreateExternalProviderInput(
                providerFile, providerSoname, providerBuildId, providerSha256,
                out var externalProviderInput, out error))
        {
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
            args.ToArray())
        {
            ExternalJumpTableProviderInput = externalProviderInput,
        };
        return true;
    }

    private static bool TryCreateExternalProviderInput(
        string? path,
        string? soname,
        string? buildId,
        string? sha256,
        out ExternalJumpTableProviderInput? input,
        out string error)
    {
        input = null;
        error = string.Empty;
        var values = new[] { path, soname, buildId, sha256 };
        if (values.All(value => value is null))
        {
            return true;
        }

        if (values.Any(string.IsNullOrWhiteSpace))
        {
            error = "Usage: --provider-file, --provider-soname, --provider-build-id, and --provider-sha256 must be supplied all together.";
            return false;
        }

        var normalizedBuildId = buildId!.ToLowerInvariant();
        var normalizedSha256 = sha256!.ToLowerInvariant();
        if (normalizedBuildId.Length is < 8 or > 128
            || (normalizedBuildId.Length & 1) != 0
            || !normalizedBuildId.All(Uri.IsHexDigit)
            || !IsSha256(normalizedSha256))
        {
            error = "Usage: provider build ID must be 8-128 even hexadecimal characters and provider SHA-256 exactly 64 hexadecimal characters.";
            return false;
        }

        input = new ExternalJumpTableProviderInput(path!, soname!, normalizedBuildId, normalizedSha256);
        return true;
    }

    internal static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    internal static bool TryParseProtectOptions(
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

    internal static bool TryAddFunctionSelector(
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

    internal static bool TryParseSymbolTable(string value, out ElfSymbolTableKind table)
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

    internal static bool TryParseProtectionPass(string value, out ProtectionPass pass)
    {
        pass = value switch
        {
            "control-flow-flattening" => ProtectionPass.ControlFlowFlattening,
            "register-permutation" => ProtectionPass.RegisterPermutation,
            _ => default,
        };
        return value is "control-flow-flattening" or "register-permutation";
    }

}
