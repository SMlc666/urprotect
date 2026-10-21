using System.Security.Cryptography;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.SemanticPlanning;

namespace UrProtect.Core.Application.Protection;

/// <summary>Stable identity retained by every current protection workflow stage.</summary>
public static class ProtectionWorkflowIdentity
{
    public const string Owner = "urprotect.core.protection-workflow.v1";
}

/// <summary>Named application stages used for deterministic first-failure evidence.</summary>
public enum ProtectionWorkflowStage
{
    RequestNormalization = 1,
    StructuralIndex = 2,
    SelectedFunctionPlanning = 3,
    SemanticPlan = 4,
    PhysicalLayout = 5,
    Materialization = 6,
    ReparseValidation = 7,
    Publication = 8,
    Evidence = 9,
}

/// <summary>One normalized, typed current protection request.</summary>
public sealed record ProtectionWorkflowRequest(
    ReadOnlyMemory<byte> Source,
    FunctionProtectionOptions Protection,
    ProtectedImageProfile Profile = ProtectedImageProfile.OuterExecveat,
    string UnitId = "urprotect.protect",
    string ProducerId = ProtectionWorkflowIdentity.Owner,
    string? ProducerBuildSha256 = null,
    string RehydratorConsumerId = ProtectedImageAbiV1.DefaultRehydratorConsumerId,
    string? ExpectedSourceSha256 = null,
    string? ExpectedRequestSha256 = null,
    bool Materialize = true);

/// <summary>Result of the shared selector/semantic planning seam.</summary>
public sealed record ProtectionWorkflowPlan(
    FunctionProtectionOptions Options,
    FunctionProtectionPlanResult FunctionPlan,
    string WorkflowOwner,
    IReadOnlyList<Diagnostic> Diagnostics,
    ProtectionWorkflowStage? FirstFailureStage = null)
{
    public bool IsSuccess => FunctionPlan.IsSuccess && !Diagnostics.Any(diagnostic => diagnostic.IsError);
}

/// <summary>Aggregated output of the current producer/materializer workflow.</summary>
public sealed record ProtectionWorkflowResult(
    FunctionProtectionOptions Options,
    ProtectedImageEmissionResult? Emission,
    RehydrationResult? Rehydration,
    FunctionProtectionResult? Protection,
    string WorkflowOwner,
    ProtectionWorkflowStage? FirstFailureStage,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Protection?.IsSuccess == true
        && (Rehydration is null || Rehydration.IsSuccess)
        && !Diagnostics.Any(diagnostic => diagnostic.IsError);
}

/// <summary>
/// The single Core owner for current protection planning, Protected Image emission,
/// profile-aware materialization, and the final-output facade. Command workflows
/// only translate paths and publish the typed result through Infrastructure.
/// </summary>
public sealed class ProtectionWorkflow
{
    public const string Owner = ProtectionWorkflowIdentity.Owner;

    private readonly FunctionProtectionService planningService;

    public ProtectionWorkflow(FunctionProtectionService? planningService = null)
    {
        this.planningService = planningService ?? new FunctionProtectionService();
    }

    /// <summary>Normalizes selectors and pass order before any structural work.</summary>
    public static bool TryNormalize(
        FunctionProtectionOptions options,
        out FunctionProtectionOptions normalized,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(options);
        var bag = new DiagnosticBag();
        normalized = options;
        if (options.Selectors is null || options.Selectors.Count == 0)
        {
            bag.Error(DiagnosticCode.InvalidArgument, "At least one explicit function selector is required for protection.");
        }
        else if (options.Selectors.Count > ProtectedImageLimits.MaximumSelectorCount)
        {
            bag.Error(DiagnosticCode.ProtectedImageLimitExceeded, "The protection request contains too many function selectors.");
        }

        if (options.Passes is null || options.Passes.Count == 0)
        {
            bag.Error(DiagnosticCode.InvalidArgument, "At least one protection pass is required for protection.");
        }
        else if (options.Passes.Count > 2)
        {
            bag.Error(DiagnosticCode.ProtectedImageLimitExceeded, "The protection request contains too many protection passes.");
        }
        else if (options.Passes.Any(pass => pass is not (
                     ProtectionPass.ControlFlowFlattening or ProtectionPass.RegisterPermutation)))
        {
            bag.Error(DiagnosticCode.InvalidArgument, "The protection request contains an unknown pass.");
        }

        if (!bag.HasErrors)
        {
            normalized = new FunctionProtectionOptions(
                options.Selectors!.ToArray(),
                ProtectionPassOrdering.Normalize(options.Passes!));
        }

        diagnostics = bag.ToArray();
        return !bag.HasErrors;
    }

    /// <summary>Runs the one selected-function planner and semantic/code emitter.</summary>
    public ProtectionWorkflowPlan Plan(
        ReadOnlyMemory<byte> source,
        FunctionProtectionOptions options,
        Aarch64HostContextProofContext? proofContext = null) =>
        PlanCore(source, options, proofContext, externalProviderFacts: null, externalProviderExtension: null);

    internal ProtectionWorkflowPlan PlanWithExternalProvider(
        ReadOnlyMemory<byte> source,
        FunctionProtectionOptions options,
        Aarch64HostContextProofContext? proofContext,
        Aarch64ExternalJumpTableProviderFacts externalProviderFacts,
        SemanticExternalJumpTableExtension externalProviderExtension)
    {
        ArgumentNullException.ThrowIfNull(externalProviderFacts);
        ArgumentNullException.ThrowIfNull(externalProviderExtension);
        return PlanCore(source, options, proofContext, externalProviderFacts, externalProviderExtension);
    }

    private ProtectionWorkflowPlan PlanCore(
        ReadOnlyMemory<byte> source,
        FunctionProtectionOptions options,
        Aarch64HostContextProofContext? proofContext,
        Aarch64ExternalJumpTableProviderFacts? externalProviderFacts,
        SemanticExternalJumpTableExtension? externalProviderExtension)
    {
        var diagnostics = new DiagnosticBag();
        if (!TryNormalize(options, out var normalized, out var normalizationDiagnostics))
        {
            diagnostics.AddRange(normalizationDiagnostics);
            var failed = new FunctionProtectionPlanResult(
                null,
                Array.Empty<FunctionProtectionFunctionResult>(),
                diagnostics.ToArray());
            return new ProtectionWorkflowPlan(
                normalized,
                failed,
                Owner,
                diagnostics.ToArray(),
                ProtectionWorkflowStage.RequestNormalization);
        }

        var plan = externalProviderFacts is null || externalProviderExtension is null
            ? planningService.Plan(source, normalized, proofContext)
            : planningService.PlanWithExternalProvider(
                source,
                normalized,
                proofContext,
                externalProviderFacts,
                externalProviderExtension);
        diagnostics.AddRange(plan.Diagnostics);
        return new ProtectionWorkflowPlan(
            normalized,
            plan,
            Owner,
            diagnostics.ToArray(),
            plan.IsSuccess ? null : ProtectionWorkflowStage.SelectedFunctionPlanning);
    }

    /// <summary>Emits the current Protected Image operation stream through this workflow.</summary>
    public ProtectedImageEmissionResult Emit(
        ReadOnlyMemory<byte> source,
        FunctionProtectionOptions options,
        ProtectedImageProducerOptions producerOptions)
    {
        ArgumentNullException.ThrowIfNull(producerOptions);
        if (!TryNormalize(options, out var normalized, out var normalizationDiagnostics))
        {
            return new ProtectedImageEmissionResult(
                null,
                null,
                Array.Empty<FunctionProtectionFunctionResult>(),
                normalizationDiagnostics);
        }

        return new ProtectedImageProducer(this).Emit(source, normalized, producerOptions);
    }

    /// <summary>
    /// Materializes an authenticated Protected Image using the profile-aware
    /// materializer. The implementation lives at the rehydration boundary, while
    /// this method remains the application owner used by all command facades.
    /// </summary>
    public RehydrationResult Materialize(
        ReadOnlyMemory<byte> source,
        ReadOnlyMemory<byte> protectedArtifact,
        RehydrationOptions options,
        IResourceSampler? resourceSampler = null)
    {
        _ = planningService;
        return GenericRehydrationEngine.Rehydrate(source, protectedArtifact, options, resourceSampler);
    }

    /// <summary>
    /// Executes the final-output facade by composing the same producer and
    /// profile-aware materializer used by protect-image and rehydrate-image.
    /// </summary>
    public ProtectionWorkflowResult Execute(ProtectionWorkflowRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!TryNormalize(request.Protection, out var normalized, out var normalizationDiagnostics))
        {
            var failed = new FunctionProtectionResult(
                null,
                Array.Empty<FunctionProtectionFunctionResult>(),
                normalizationDiagnostics)
            {
                WorkflowOwner = Owner,
                FirstFailureStage = ProtectionWorkflowStage.RequestNormalization.ToString(),
            };
            return new ProtectionWorkflowResult(
                normalized,
                null,
                null,
                failed,
                Owner,
                ProtectionWorkflowStage.RequestNormalization,
                normalizationDiagnostics);
        }

        var sourceBytes = request.Source.ToArray();
        var sourceHash = Sha256(sourceBytes);
        var producerBuild = request.ProducerBuildSha256 is { Length: > 0 }
            ? request.ProducerBuildSha256.ToLowerInvariant()
            : CommandEvidenceAdapter.ComputeAssemblyBuildSha256(
                typeof(ProtectionWorkflow).Assembly,
                Owner);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(
            normalized.Selectors,
            normalized.Passes);
        var producerOptions = new ProtectedImageProducerOptions(
            request.UnitId,
            request.Profile,
            request.ProducerId,
            producerBuild,
            request.RehydratorConsumerId,
            request.ExpectedSourceSha256 ?? sourceHash,
            request.ExpectedRequestSha256 ?? requestHash);
        var emission = Emit(sourceBytes, normalized, producerOptions);
        var diagnostics = new DiagnosticBag();
        diagnostics.AddRange(emission.Diagnostics);
        if (!emission.IsSuccess || emission.Role is null || emission.ArtifactBytes is null || !request.Materialize)
        {
                var failedProtection = ToProtectionResult(
                emission,
                diagnostics,
                emission.IsSuccess ? null : ProtectionWorkflowStage.SemanticPlan);
            ProtectionWorkflowStage? firstFailure;
            if (failedProtection.FirstFailureStage is null)
            {
                firstFailure = request.Materialize ? ProtectionWorkflowStage.Materialization : null;
            }
            else if (Enum.TryParse<ProtectionWorkflowStage>(failedProtection.FirstFailureStage, out var parsedFailure))
            {
                firstFailure = parsedFailure;
            }
            else
            {
                firstFailure = ProtectionWorkflowStage.SemanticPlan;
            }
            return new ProtectionWorkflowResult(
                normalized,
                emission,
                null,
                failedProtection,
                Owner,
                firstFailure,
                diagnostics.ToArray());
        }

        var rehydrationOptions = new RehydrationOptions(
            emission.Role.SourceSha256,
            emission.Role.RequestSha256,
            emission.Role.UnitId,
            request.Profile,
            emission.Role.ProducerId,
            emission.Role.ProducerBuildSha256,
            emission.Role.RehydratorConsumerId,
            CommandEvidenceAdapter.ComputeAssemblyBuildSha256(
                typeof(ProtectionWorkflow).Assembly,
                $"{Owner}:consumer"));
        var rehydration = Materialize(sourceBytes, emission.ArtifactBytes, rehydrationOptions);
        diagnostics.AddRange(rehydration.Diagnostics);
        var protection = ToProtectionResult(
            emission,
            diagnostics,
            rehydration.IsSuccess ? null : ProtectionWorkflowStage.Materialization,
            rehydration.NativeImage?.Bytes,
            rehydration.NativeImage?.LayoutEvidence);
        ProtectionWorkflowStage? failureStage;
        if (rehydration.IsSuccess)
        {
            failureStage = null;
        }
        else if (Enum.TryParse<ProtectionWorkflowStage>(rehydration.Record.FirstFailureStage, out var parsedMaterializationFailure))
        {
            failureStage = parsedMaterializationFailure;
        }
        else
        {
            failureStage = ProtectionWorkflowStage.Materialization;
        }
        return new ProtectionWorkflowResult(
            normalized,
            emission,
            rehydration,
            protection,
            Owner,
            failureStage,
            diagnostics.ToArray());
    }

    /// <summary>Convenience projection retained for the final-output CLI facade.</summary>
    public FunctionProtectionResult ExecuteFinal(
        ReadOnlyMemory<byte> source,
        FunctionProtectionOptions options) =>
        Execute(new ProtectionWorkflowRequest(source, options)).Protection
        ?? new FunctionProtectionResult(
            null,
            Array.Empty<FunctionProtectionFunctionResult>(),
            new[]
            {
                new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionPassFailed,
                    "The protection workflow did not produce a typed result."),
            });

    private static FunctionProtectionResult ToProtectionResult(
        ProtectedImageEmissionResult emission,
        DiagnosticBag diagnostics,
        ProtectionWorkflowStage? failureStage,
        byte[]? output = null,
        ElfLayoutEvidence? layoutEvidence = null)
    {
        return new FunctionProtectionResult(
            output,
            emission.Functions,
            diagnostics.ToArray())
        {
            LayoutEvidence = layoutEvidence,
            WorkflowOwner = Owner,
            FirstFailureStage = failureStage?.ToString(),
        };
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
