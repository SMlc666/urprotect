using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Application.Protection;

/// <summary>Immutable output of selected-function resolution and bounded analysis.</summary>
internal sealed record SelectedFunctionProtectionPlan(
    ElfFile File,
    IReadOnlyList<ElfFunctionSymbol> Functions,
    IReadOnlyList<Aarch64FunctionAnalysis> Analyses,
    IReadOnlyList<FunctionProtectionFunctionResult> FunctionResults,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => !Diagnostics.Any(diagnostic => diagnostic.IsError);
}

/// <summary>
/// Owns request-to-function selection and selected-root semantic analysis. It
/// never emits bytes or chooses a physical ELF layout.
/// </summary>
internal sealed class SelectedFunctionProtectionPlanner
{
    private readonly AsmStoneAdapter decoder;

    public SelectedFunctionProtectionPlanner(AsmStoneAdapter decoder)
    {
        this.decoder = decoder ?? throw new ArgumentNullException(nameof(decoder));
    }

    public SelectedFunctionProtectionPlan Analyze(
        ReadOnlyMemory<byte> input,
        IReadOnlyList<FunctionSelector> selectors,
        IReadOnlyList<ProtectionPass> passes,
        Aarch64HostContextProofContext? proofContext = null,
        Aarch64ExternalJumpTableProviderFacts? externalProviderFacts = null)
    {
        ArgumentNullException.ThrowIfNull(selectors);
        ArgumentNullException.ThrowIfNull(passes);
        var diagnostics = new DiagnosticBag();
        var functions = new List<FunctionProtectionFunctionResult>();
        var source = input.ToArray();
        var parsed = ElfParser.Parse(source);
        diagnostics.AddRange(parsed.Diagnostics);
        if (parsed.File is null || diagnostics.HasErrors)
        {
            return new SelectedFunctionProtectionPlan(
                parsed.File!,
                Array.Empty<ElfFunctionSymbol>(),
                Array.Empty<Aarch64FunctionAnalysis>(),
                functions,
                diagnostics.ToArray());
        }

        var selection = FunctionSelectorResolver.Resolve(parsed.File, selectors);
        diagnostics.AddRange(selection.Diagnostics);
        if (!selection.IsSuccess)
        {
            return new SelectedFunctionProtectionPlan(
                parsed.File,
                Array.Empty<ElfFunctionSymbol>(),
                Array.Empty<Aarch64FunctionAnalysis>(),
                functions,
                diagnostics.ToArray());
        }

        FunctionProtectionSelectionValidator.ValidateSelectedRanges(parsed.File, selection.Functions, diagnostics);
        if (diagnostics.HasErrors)
        {
            return new SelectedFunctionProtectionPlan(
                parsed.File,
                selection.Functions,
                Array.Empty<Aarch64FunctionAnalysis>(),
                functions,
                diagnostics.ToArray());
        }

        var analyses = new List<Aarch64FunctionAnalysis>();
        var orderedPasses = ProtectionPassOrdering.Normalize(passes);
        var hasFlattening = orderedPasses.Contains(ProtectionPass.ControlFlowFlattening);
        var hasPermutation = orderedPasses.Contains(ProtectionPass.RegisterPermutation);
        foreach (var function in selection.Functions)
        {
            var functionProofContext = proofContext is not null && proofContext.MatchesEntry(function)
                ? proofContext
                : null;
            var analyzer = new Aarch64FunctionAnalyzer(decoder);
            var analysis = externalProviderFacts is null
                ? analyzer.Analyze(parsed.File, function, functionProofContext)
                : analyzer.AnalyzeWithExternalProvider(parsed.File, function, externalProviderFacts, functionProofContext);
            analyses.Add(analysis);
            if (!analysis.IsComplete)
            {
                var analysisErrors = analysis.Diagnostics
                    .Where(diagnostic => diagnostic.IsError)
                    .ToArray();
                if (analysisErrors.Length == 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.FunctionAnalysisIncomplete,
                        $"Function '{function.Name}' cannot be transformed because analysis is incomplete.",
                        function.Value);
                }
                else
                {
                    diagnostics.AddRange(analysisErrors);
                }

                functions.Add(new FunctionProtectionFunctionResult(
                    function,
                    true,
                    false,
                    Array.Empty<ProtectionPass>(),
                    analysis.Diagnostics));
                continue;
            }

            var resourcePlan = Aarch64RegisterResourcePlanner.Plan(
                analysis,
                decoder,
                hasFlattening,
                hasPermutation);
            if (!resourcePlan.IsSufficient)
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionResourceUnavailable,
                    resourcePlan.FailureReason ?? "The selected function has insufficient register resources.",
                    function.Value);
                functions.Add(new FunctionProtectionFunctionResult(
                    function,
                    true,
                    false,
                    Array.Empty<ProtectionPass>(),
                    new[]
                    {
                        new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.FunctionResourceUnavailable,
                            resourcePlan.FailureReason
                                ?? "The selected function has insufficient register resources.",
                            function.Value),
                    })
                {
                    ResourcePlan = resourcePlan,
                });
            }
        }

        return new SelectedFunctionProtectionPlan(
            parsed.File,
            selection.Functions,
            analyses,
            functions,
            diagnostics.ToArray());
    }
}
