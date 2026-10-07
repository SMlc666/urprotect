using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Application.Validation;

/// <summary>
/// Coordinates structural validation, explicit whole-image observation, and
/// identity-copy publication. It contains no parser or writer implementation;
/// those responsibilities belong to the typed seams it composes.
/// </summary>
public sealed class ValidationWorkflow
{
    private readonly Func<ReadOnlyMemory<byte>, StructuralValidationResult> structuralValidation =
        StructuralValidationService.Validate;
    private readonly WholeImageObservationService observationService;

    public ValidationWorkflow(IAarch64Decoder? decoder = null)
    {
        observationService = new WholeImageObservationService(decoder ?? new AsmStoneAdapter());
    }

    /// <summary>Performs decoder-independent structural validation.</summary>
    public ValidationResult ValidateStructurally(
        ReadOnlyMemory<byte> input,
        bool emitOutput = false)
    {
        var result = ValidateStructuralCore(input);
        if (!emitOutput || !result.IsSuccess)
        {
            return result;
        }

        // In-memory identity output is a projection only. Filesystem
        // publication is available through the path-based workflow below.
        return result with { OutputBytes = input.ToArray() };
    }

    /// <summary>
    /// Performs explicitly requested whole-image observation. Observation is
    /// not a protection or publication prerequisite.
    /// </summary>
    public ValidationResult ValidateObservationOnly(
        ReadOnlyMemory<byte> input,
        bool emitOutput = false)
    {
        var structural = structuralValidation(input);
        var diagnostics = structural.Diagnostics.ToList();
        Aarch64AnalysisReport? analysis = null;
        if (structural.File is not null && !diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            analysis = observationService.Observe(structural.File);
            diagnostics.AddRange(analysis.Diagnostics);
        }

        return new ValidationResult(
            structural.File,
            analysis,
            diagnostics.ToArray(),
            emitOutput && !diagnostics.Any(diagnostic => diagnostic.IsError) ? input.ToArray() : null)
        {
            AnalysisMode = ValidationAnalysisMode.ObservationOnly,
        };
    }

    /// <summary>Validates and atomically publishes a structural identity copy.</summary>
    public ValidationResult ValidateAndCopyStructurally(
        string inputPath,
        string outputPath,
        ReadOnlyMemory<byte>? inputOverride = null) =>
        ValidateAndCopy(inputPath, outputPath, ValidationAnalysisMode.StructuralOnly, inputOverride);

    /// <summary>Observes and atomically publishes an identity copy on request.</summary>
    public ValidationResult ValidateAndCopyObservationOnly(
        string inputPath,
        string outputPath,
        ReadOnlyMemory<byte>? inputOverride = null) =>
        ValidateAndCopy(inputPath, outputPath, ValidationAnalysisMode.ObservationOnly, inputOverride);

    private ValidationResult ValidateAndCopy(
        string inputPath,
        string outputPath,
        ValidationAnalysisMode mode,
        ReadOnlyMemory<byte>? inputOverride)
    {
        var snapshot = IdentityCopyPublisher.ReadInput(inputPath, outputPath, inputOverride);
        if (!snapshot.IsSuccess)
        {
            return new ValidationResult(
                null,
                null,
                snapshot.Diagnostics,
                null)
            {
                AnalysisMode = mode,
            };
        }

        var result = mode == ValidationAnalysisMode.ObservationOnly
            ? ValidateObservationOnly(snapshot.Bytes)
            : ValidateStructurally(snapshot.Bytes);
        if (!result.IsSuccess)
        {
            return result;
        }

        var publication = IdentityCopyPublisher.Publish(outputPath, snapshot.Bytes, snapshot.SourceMode);
        var diagnostics = result.Diagnostics.Concat(publication.Diagnostics).ToArray();
        return result with
        {
            Diagnostics = diagnostics,
            OutputBytes = publication.IsSuccess ? publication.OutputBytes : null,
        };
    }

    private ValidationResult ValidateStructuralCore(ReadOnlyMemory<byte> input)
    {
        var result = structuralValidation(input);
        return new ValidationResult(result.File, null, result.Diagnostics, null);
    }
}
