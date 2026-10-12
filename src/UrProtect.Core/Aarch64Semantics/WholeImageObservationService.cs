using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

/// <summary>
/// Explicit, observation-only whole-image instruction inspection. Structural
/// validation and publication workflows do not call this service implicitly.
/// </summary>
public sealed class WholeImageObservationService
{
    private readonly Aarch64ObservationAnalyzer analyzer;

    public WholeImageObservationService(IAarch64Decoder decoder)
    {
        analyzer = new Aarch64ObservationAnalyzer(decoder);
    }

    public Aarch64AnalysisReport Observe(ElfFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        return analyzer.Analyze(file);
    }
}
