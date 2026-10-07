using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.StructuralElf;

/// <summary>
/// Identifies the explicitly requested validation scope. Structural validation
/// never constructs a decoder; observation is a separate, non-gating operation.
/// </summary>
public enum ValidationAnalysisMode
{
    StructuralOnly = 0,
    ObservationOnly = 1,
}

/// <summary>Result of bounded, decoder-independent structural validation.</summary>
public sealed record StructuralValidationResult(
    ElfFile? File,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => File is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Owns decoder-independent ELF model validation. It is the only service that
/// turns arbitrary input bytes into the structural ELF model.
/// </summary>
public static class StructuralValidationService
{
    public static StructuralValidationResult Validate(ReadOnlyMemory<byte> input)
    {
        var parse = ElfParser.Parse(input);
        return new StructuralValidationResult(parse.File, parse.Diagnostics.ToArray());
    }
}
