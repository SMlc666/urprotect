using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;
namespace UrProtect.Core.Application.Protection;

public enum ProtectionPass
{
    ControlFlowFlattening,
    RegisterPermutation,
}

public static class ProtectionPassOrdering
{
    public static IReadOnlyList<ProtectionPass> Normalize(IReadOnlyList<ProtectionPass> passes)
    {
        ArgumentNullException.ThrowIfNull(passes);
        var normalized = new List<ProtectionPass>(2);
        if (passes.Contains(ProtectionPass.ControlFlowFlattening))
        {
            normalized.Add(ProtectionPass.ControlFlowFlattening);
        }

        if (passes.Contains(ProtectionPass.RegisterPermutation))
        {
            normalized.Add(ProtectionPass.RegisterPermutation);
        }

        return normalized;
    }

    public static string Describe(ProtectionPass pass) => pass switch
    {
        ProtectionPass.ControlFlowFlattening => "control-flow-flattening",
        ProtectionPass.RegisterPermutation => "register-permutation",
        _ => pass.ToString(),
    };
}

public sealed record FunctionProtectionOptions(
    IReadOnlyList<FunctionSelector> Selectors,
    IReadOnlyList<ProtectionPass> Passes);

public sealed record FunctionProtectionFunctionResult(
    ElfFunctionSymbol Function,
    bool Selected,
    bool Transformed,
    IReadOnlyList<ProtectionPass> AppliedPasses,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public Aarch64RegisterResourcePlan? ResourcePlan { get; init; }
}

public sealed record FunctionProtectionResult(
    byte[]? OutputBytes,
    IReadOnlyList<FunctionProtectionFunctionResult> Functions,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public ElfLayoutEvidence? LayoutEvidence { get; init; }

    public bool IsSuccess => OutputBytes is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed partial class FunctionProtectionService
{
    private const ulong SegmentAlignment = 0x1000;
    private const byte StateRegister = 16;
    private static readonly IReadOnlyDictionary<byte, byte> RegisterPermutation =
        new Dictionary<byte, byte> { [9] = 10, [10] = 9 };

    private readonly AsmStoneAdapter decoder;

    public FunctionProtectionService(AsmStoneAdapter? decoder = null)
    {
        this.decoder = decoder ?? new AsmStoneAdapter();
    }

    /// <summary>
    /// Coordinates validated selected-function analysis, code emission, physical
    /// layout adaptation, and output validation for the direct protect use case.
    /// The Protected Image producer uses <see cref="Plan"/> for a layout-neutral
    /// plan and never invokes this direct writer path.
    /// </summary>
    public FunctionProtectionResult Protect(
        ReadOnlyMemory<byte> input,
        FunctionProtectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var diagnostics = new DiagnosticBag();
        var functionResults = new List<FunctionProtectionFunctionResult>();
        if (!FunctionProtectionRequestValidator.TryValidate(
                options,
                diagnostics,
                out var selectorSnapshot,
                out var passSnapshot))
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        var selectedPlan = new SelectedFunctionProtectionPlanner(decoder).Analyze(
            input,
            selectorSnapshot,
            passSnapshot);
        diagnostics.AddRange(selectedPlan.Diagnostics);
        functionResults.AddRange(selectedPlan.FunctionResults);
        if (!selectedPlan.IsSuccess)
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        var orderedPasses = ProtectionPassOrdering.Normalize(passSnapshot);
        var parse = selectedPlan.File;
        var analyses = selectedPlan.Analyses;
        var selection = selectedPlan.Functions;
        if (!TryGetCodeBase(parse, out var codeBase))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectionLayoutUnavailable,
                "The executable load-map virtual range cannot be represented by the protection layout planner.");
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        ProtectedCode rewritten = default!;
        IReadOnlyList<FunctionProtectionFunctionResult> transformedResults = Array.Empty<FunctionProtectionFunctionResult>();
        ElfLayoutPlan? layoutPlan = null;
        ElfLayoutEvidence? layoutEvidence = null;
        byte[]? output = null;
        IReadOnlyList<Diagnostic> planningDiagnostics = Array.Empty<Diagnostic>();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (!TryBuildProtectedCode(
                    parse,
                    analyses,
                    orderedPasses,
                    out rewritten,
                    out transformedResults,
                    out var rewriteDiagnostics,
                    codeBaseOverride: codeBase))
            {
                diagnostics.AddRange(rewriteDiagnostics);
                functionResults.AddRange(transformedResults);
                return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
            }

            var planning = PlanProtectedCode(parse, rewritten);
            if (planning.Plan is null || planning.Diagnostics.Any(diagnostic => diagnostic.IsError))
            {
                diagnostics.AddRange(planning.Diagnostics);
                functionResults.AddRange(transformedResults);
                return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
            }

            var plannedCodeBase = planning.Plan.Placements
                .Select(placement => placement.VirtualAddress.Value)
                .DefaultIfEmpty(0UL)
                .Min();
            planningDiagnostics = planning.Diagnostics;
            if (plannedCodeBase != rewritten.VirtualAddress && attempt == 0)
            {
                codeBase = plannedCodeBase;
                continue;
            }

            if (plannedCodeBase != rewritten.VirtualAddress)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectionLayoutUnavailable,
                    "The semantic code base does not agree with the selected physical ELF layout.");
                functionResults.AddRange(transformedResults);
                return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
            }

            var materialized = ElfLayoutMaterializer.Materialize(parse.Bytes, parse, planning.Plan);
            if (materialized.Bytes is null || materialized.ParsedOutput is null || materialized.Plan is null)
            {
                diagnostics.AddRange(materialized.Diagnostics);
                functionResults.AddRange(transformedResults);
                return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
            }

            diagnostics.AddRange(planningDiagnostics);
            diagnostics.AddRange(materialized.Diagnostics);
            layoutPlan = materialized.Plan;
            layoutEvidence = materialized.Evidence;
            output = materialized.Bytes;
            break;
        }

        if (output is null || layoutPlan is null)
        {
            diagnostics.Error(DiagnosticCode.ProtectionLayoutUnavailable, "The shared ELF layout planner did not produce a materialized output.");
            functionResults.AddRange(transformedResults);
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        functionResults.AddRange(transformedResults);
        var outputParse = ElfParser.Parse(output);
        diagnostics.AddRange(outputParse.Diagnostics);
        if (outputParse.File is null || diagnostics.HasErrors)
        {
            diagnostics.Error(
                DiagnosticCode.WrapperMalformed,
                "The protected ELF did not pass a second structural parse.");
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        if (!ValidateRewrittenOutput(
                parse,
                outputParse.File,
                output,
                rewritten,
                layoutPlan,
                selection,
                diagnostics))
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        return new FunctionProtectionResult(output, functionResults, diagnostics.ToArray())
        {
            LayoutEvidence = layoutEvidence,
        };
    }

}
