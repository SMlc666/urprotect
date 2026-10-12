using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Validation;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Cli.Parsing;

internal sealed record CliOptions(
    string InputPath,
    string? CopyPath,
    string? JsonPath,
    ValidationAnalysisMode AnalysisMode);

internal sealed record PackOptions(
    string InputPath,
    string OutputPath,
    string? JsonPath,
    string? LauncherPath,
    PayloadDispatchProfile Profile,
    string EntrySymbol,
    bool RequireThreadLifetime,
    bool AllowPathSensitiveOuter);

internal sealed record ProtectOptions(
    string InputPath,
    string OutputPath,
    string? JsonPath,
    IReadOnlyList<FunctionSelector> Functions,
    IReadOnlyList<ProtectionPass> Passes);

internal sealed record ProtectedImageOptions(
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

internal sealed record RehydrationCliOptions(
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
