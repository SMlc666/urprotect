using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Application.Validation;

/// <summary>
/// Application projection of validation and optional observation. Structural
/// parsing remains owned by <see cref="StructuralValidationService"/>; this
/// record only combines the explicitly requested stage results.
/// </summary>
public sealed record ValidationResult(
    ElfFile? File,
    Aarch64AnalysisReport? Analysis,
    IReadOnlyList<Diagnostic> Diagnostics,
    byte[]? OutputBytes)
{
    public bool IsSuccess => File is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);

    public ValidationAnalysisMode AnalysisMode { get; init; } = ValidationAnalysisMode.StructuralOnly;
}
