using System.Buffers.Binary;
using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Protect;

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

public sealed class FunctionProtectionService
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
    /// Builds the layout-neutral protection plan used by the Protected Image
    /// producer. Unlike <see cref="Protect"/>, this method never searches for a
    /// PT_NULL slot and never emits final ELF bytes.
    /// </summary>
    public FunctionProtectionPlanResult Plan(
        ReadOnlyMemory<byte> input,
        FunctionProtectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var diagnostics = new DiagnosticBag();
        var functionResults = new List<FunctionProtectionFunctionResult>();
        if (options.Selectors is null || options.Selectors.Count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "At least one explicit function selector is required for protection.");
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        if (options.Passes is null || options.Passes.Count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "At least one protection pass is required for protection.");
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        if (options.Selectors.Count > ProtectedImageLimits.MaximumSelectorCount)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "The protection request contains too many function selectors.");
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        if (options.Passes.Count > 2)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "The protection request contains too many protection passes.");
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var selectorSnapshot = options.Selectors.ToArray();
        var passSnapshot = options.Passes.ToArray();
        if (passSnapshot.Any(pass => pass is not (
                ProtectionPass.ControlFlowFlattening
                or ProtectionPass.RegisterPermutation)))
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "The protection request contains an unknown pass.");
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var sourceSnapshot = input.ToArray();
        var orderedPasses = ProtectionPassOrdering.Normalize(passSnapshot);
        var parse = ElfParser.Parse(sourceSnapshot);
        diagnostics.AddRange(parse.Diagnostics);
        if (parse.File is null || diagnostics.HasErrors)
        {
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var selection = FunctionSelectorResolver.Resolve(parse.File, selectorSnapshot);
        diagnostics.AddRange(selection.Diagnostics);
        if (!selection.IsSuccess)
        {
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        ValidateSelectedRanges(parse.File, selection.Functions, diagnostics);
        if (diagnostics.HasErrors)
        {
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var analyses = new List<Aarch64FunctionAnalysis>();
        var hasFlattening = orderedPasses.Contains(ProtectionPass.ControlFlowFlattening);
        var hasPermutation = orderedPasses.Contains(ProtectionPass.RegisterPermutation);
        foreach (var function in selection.Functions)
        {
            var analysis = new Aarch64FunctionAnalyzer(decoder).Analyze(parse.File, function);
            analyses.Add(analysis);
            if (!analysis.IsComplete)
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionAnalysisIncomplete,
                    $"Function '{function.Name}' cannot be transformed because analysis is incomplete.",
                    function.Value);
                functionResults.Add(new FunctionProtectionFunctionResult(
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
                functionResults.Add(new FunctionProtectionFunctionResult(
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

        if (diagnostics.HasErrors)
        {
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        if (!TryBuildProtectedCode(
                parse.File,
                analyses,
                orderedPasses,
                out var protectedCode,
                out var transformedResults,
                out var rewriteDiagnostics,
                codeBaseOverride: 0))
        {
            diagnostics.AddRange(rewriteDiagnostics);
            functionResults.AddRange(transformedResults);
            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        functionResults.AddRange(transformedResults);
        var regions = new List<ProtectedImageEmitRegion>(protectedCode.Patches.Count);
        var fixups = new List<ProtectedImageEntryBranchFixup>(protectedCode.Patches.Count);
        for (var index = 0; index < protectedCode.Patches.Count; index++)
        {
            var patch = protectedCode.Patches[index];
            if (patch.TargetAddress > uint.MaxValue
                || patch.OutputSize > int.MaxValue
                || patch.TargetAddress > ulong.MaxValue - patch.OutputSize
                || patch.TargetAddress + patch.OutputSize > (ulong)protectedCode.Bytes.Length)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageLimitExceeded,
                    "The layout-neutral protected code region exceeds the Protected Image bounds.",
                    patch.SourceAddress);
                continue;
            }

            var regionId = checked((uint)index + 1);
            var generated = protectedCode.Bytes.AsSpan(
                checked((int)patch.TargetAddress),
                checked((int)patch.OutputSize)).ToArray();
            regions.Add(new ProtectedImageEmitRegion(
                regionId,
                new VirtualAddress(patch.SourceAddress),
                patch.SourceSize,
                generated));
            fixups.Add(new ProtectedImageEntryBranchFixup(
                regionId,
                regionId,
                new VirtualAddress(patch.SourceAddress),
                0,
                0,
                ProtectedImageFixupKind.Aarch64Branch26));
        }

        if (diagnostics.HasErrors || regions.Count != protectedCode.Patches.Count)
        {
            if (!diagnostics.HasErrors)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageMalformed,
                    "The layout-neutral protection plan did not bind every transformed function.");
            }

            return new FunctionProtectionPlanResult(null, functionResults, diagnostics.ToArray());
        }

        var plan = new ProtectionPlan(
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(sourceSnapshot)).ToLowerInvariant(),
            regions,
            fixups,
            functionResults);
        return new FunctionProtectionPlanResult(plan, functionResults, diagnostics.ToArray());
    }

    public FunctionProtectionResult Protect(
        ReadOnlyMemory<byte> input,
        FunctionProtectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var diagnostics = new DiagnosticBag();
        var functionResults = new List<FunctionProtectionFunctionResult>();
        if (options.Selectors is null || options.Selectors.Count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "At least one explicit function selector is required for protection.");
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        if (options.Passes is null || options.Passes.Count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "At least one protection pass is required.");
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        if (options.Passes.Any(pass => pass is not (
                ProtectionPass.ControlFlowFlattening
                or ProtectionPass.RegisterPermutation)))
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "The protection request contains an unknown pass.");
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        var orderedPasses = ProtectionPassOrdering.Normalize(options.Passes);
        var parse = ElfParser.Parse(input);
        diagnostics.AddRange(parse.Diagnostics);
        if (parse.File is null || diagnostics.HasErrors)
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        var selection = FunctionSelectorResolver.Resolve(parse.File, options.Selectors);
        diagnostics.AddRange(selection.Diagnostics);
        if (!selection.IsSuccess)
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        ValidateSelectedRanges(parse.File, selection.Functions, diagnostics);
        if (diagnostics.HasErrors)
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        var analyses = new List<Aarch64FunctionAnalysis>();
        var hasFlattening = orderedPasses.Contains(ProtectionPass.ControlFlowFlattening);
        var hasPermutation = orderedPasses.Contains(ProtectionPass.RegisterPermutation);
        foreach (var function in selection.Functions)
        {
            var analysis = new Aarch64FunctionAnalyzer(decoder).Analyze(parse.File, function);
            analyses.Add(analysis);
            if (!analysis.IsComplete)
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionAnalysisIncomplete,
                    $"Function '{function.Name}' cannot be transformed because analysis is incomplete.",
                    function.Value);
                functionResults.Add(new FunctionProtectionFunctionResult(
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
                functionResults.Add(new FunctionProtectionFunctionResult(
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

        if (diagnostics.HasErrors)
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        if (!TryGetCodeBase(parse.File, out var codeBase))
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
                    parse.File,
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

            var planning = PlanProtectedCode(parse.File, rewritten);
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

            var materialized = ElfLayoutMaterializer.Materialize(parse.File.Bytes, parse.File, planning.Plan);
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
                parse.File,
                outputParse.File,
                output,
                rewritten,
                layoutPlan,
                selection.Functions,
                diagnostics))
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        return new FunctionProtectionResult(output, functionResults, diagnostics.ToArray())
        {
            LayoutEvidence = layoutEvidence,
        };
    }

    private static ulong AlignUp(ulong value, ulong alignment)
    {
        var remainder = value % alignment;
        return remainder == 0 ? value : checked(value + alignment - remainder);
    }

    private static bool TryGetCodeBase(ElfFile file, out ulong codeBase)
    {
        try
        {
            var highestVirtualEnd = file.LoadMap.Segments
                .Select(segment => checked(segment.VirtualAddress + segment.MemorySize))
                .DefaultIfEmpty(0UL)
                .Max();
            codeBase = AlignUp(highestVirtualEnd, SegmentAlignment);
            return true;
        }
        catch (OverflowException)
        {
            codeBase = 0;
            return false;
        }
    }

    private static ElfLayoutPlanningResult PlanProtectedCode(ElfFile file, ProtectedCode code)
    {
        var regions = new List<ElfLayoutRegionRequest>(code.Patches.Count);
        var branches = new List<ElfLayoutBranchRequest>(code.Patches.Count);
        for (var index = 0; index < code.Patches.Count; index++)
        {
            var patch = code.Patches[index];
            if (patch.TargetAddress < code.VirtualAddress
                || patch.OutputSize > (ulong)code.Bytes.Length
                || patch.TargetAddress - code.VirtualAddress > (ulong)code.Bytes.Length - patch.OutputSize
                || patch.OutputSize == 0
                || patch.OutputSize > int.MaxValue)
            {
                return new ElfLayoutPlanningResult(
                    null,
                    null,
                    new[]
                    {
                        new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.ProtectionLayoutUnavailable,
                            "A protected code patch is outside the emitted code buffer.",
                            patch.TargetAddress),
                    });
            }

            var regionIdentity = $"function:{index:D8}:{patch.SourceAddress:X}";
            var codeOffset = checked((int)(patch.TargetAddress - code.VirtualAddress));
            var codeBytes = code.Bytes.AsSpan(codeOffset, checked((int)patch.OutputSize)).ToArray();
            regions.Add(new ElfLayoutRegionRequest(
                regionIdentity,
                regionIdentity,
                new VirtualAddress(patch.SourceAddress),
                patch.SourceSize,
                codeBytes));
            branches.Add(new ElfLayoutBranchRequest(
                $"entry:{index}:{patch.SourceAddress:X}",
                regionIdentity,
                regionIdentity,
                new VirtualAddress(patch.SourceAddress),
                0,
                0));
        }

        var options = new ElfLayoutOptions(
            MaximumOutputBytes: ElfLayoutLimits.DefaultMaximumOutputBytes,
            MaximumProgramHeaderCount: ElfLayoutLimits.DefaultMaximumProgramHeaderCount,
            MaximumGeneratedCodeBytes: ProtectedImageLimits.MaximumAggregateCodeBytes,
            MaximumVeneerCount: ElfLayoutLimits.DefaultMaximumVeneerCount,
            MaximumEditCount: ElfLayoutLimits.DefaultMaximumEditCount,
            MaximumPaddingBytes: ElfLayoutLimits.DefaultMaximumPaddingBytes,
            SegmentAlignment: SegmentAlignment,
            CodeAlignment: ElfLayoutLimits.DefaultCodeAlignment,
            MaximumAlignment: ElfLayoutLimits.DefaultMaximumAlignment);
        return ElfLayoutPlanner.Plan(file.Bytes, file, regions, branches, options);
    }

    private static void ValidateSelectedRanges(
        ElfFile file,
        IReadOnlyList<ElfFunctionSymbol> selected,
        DiagnosticBag diagnostics)
    {
        for (var index = 0; index < selected.Count; index++)
        {
            var function = selected[index];
            if (!function.TryGetEnd(out var end))
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionResourceUnavailable,
                    $"Function '{function.Name}' has an overflowing symbol range.",
                    function.Value);
                continue;
            }

            var segments = file.LoadMap.Segments
                .Where(segment => segment.IsExecutable && segment.ContainsVirtualAddress(function.Value, function.Size))
                .ToArray();
            if (segments.Length != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionResourceUnavailable,
                    $"Function '{function.Name}' must be wholly contained in exactly one executable load segment.",
                    function.Value);
            }

            for (var otherIndex = index + 1; otherIndex < selected.Count; otherIndex++)
            {
                var other = selected[otherIndex];
                if (!other.TryGetEnd(out var otherEnd))
                {
                    continue;
                }

                if (function.Value < otherEnd
                    && other.Value < end
                    && !(function.Value == other.Value && function.Size == other.Size))
                {
                    diagnostics.Error(
                        DiagnosticCode.FunctionResourceUnavailable,
                        $"Selected function ranges '{function.Name}' and '{other.Name}' overlap.",
                        function.Value);
                }
            }

            foreach (var other in file.FunctionSymbols)
            {
                if (other.Table == function.Table && other.TableIndex == function.TableIndex
                    || !other.TryGetEnd(out var otherEnd)
                    || (function.Value == other.Value && function.Size == other.Size))
                {
                    continue;
                }

                if (function.Value < otherEnd && other.Value < end)
                {
                    diagnostics.Error(
                        DiagnosticCode.FunctionResourceUnavailable,
                        $"Selected function '{function.Name}' overlaps an unselected symbol '{other.Name}'; transformation would change an unselected function.",
                        function.Value);
                }
            }
        }
    }

    private bool TryBuildProtectedCode(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionAnalysis> analyses,
        IReadOnlyList<ProtectionPass> passes,
        out ProtectedCode code,
        out IReadOnlyList<FunctionProtectionFunctionResult> results,
        out IReadOnlyList<Diagnostic> diagnostics,
        ulong? codeBaseOverride = null)
    {
        var diagnosticBag = new DiagnosticBag();
        var resultList = new List<FunctionProtectionFunctionResult>();
        var builders = new List<ProtectedFunctionBuilder>();
        var hasFlattening = passes.Contains(ProtectionPass.ControlFlowFlattening);
        var hasPermutation = passes.Contains(ProtectionPass.RegisterPermutation);
        var analysisGroups = analyses
            .GroupBy(analysis => (analysis.Function.Value, analysis.Function.Size))
            .ToArray();
        foreach (var group in analysisGroups)
        {
            var analysis = group.First();
            var resourcePlan = Aarch64RegisterResourcePlanner.Plan(
                analysis,
                decoder,
                hasFlattening,
                hasPermutation);
            if (!TryBuildFunction(
                    analysis,
                    hasFlattening,
                    hasPermutation,
                    resourcePlan,
                    out var builder,
                    out var functionDiagnostic))
            {
                diagnosticBag.Error(
                    functionDiagnostic.Code,
                    functionDiagnostic.Message,
                    functionDiagnostic.Offset);
                foreach (var alias in group)
                {
                    resultList.Add(new FunctionProtectionFunctionResult(
                        alias.Function,
                        true,
                        false,
                        Array.Empty<ProtectionPass>(),
                        new[] { functionDiagnostic })
                    {
                        ResourcePlan = resourcePlan,
                    });
                }

                continue;
            }

            builders.Add(builder);
        }

        if (diagnosticBag.HasErrors)
        {
            code = default!;
            results = resultList;
            diagnostics = diagnosticBag.ToArray();
            return false;
        }

        if (codeBaseOverride is not { } codeBase
            && !TryGetCodeBase(file, out codeBase))
        {
            diagnosticBag.Error(
                DiagnosticCode.ProtectionLayoutUnavailable,
                "The executable load-map virtual range cannot be represented by the protection layout planner.");
            code = default!;
            results = resultList;
            diagnostics = diagnosticBag.ToArray();
            return false;
        }

        var emitter = new CodeEmitter(codeBase);
        foreach (var builder in builders)
        {
            var resourcePlan = Aarch64RegisterResourcePlanner.Plan(
                builder.Source,
                decoder,
                hasFlattening,
                hasPermutation);
            var start = emitter.PositionAddress;
            if (!builder.Emit(emitter, decoder, diagnosticBag))
            {
                foreach (var alias in analysisGroups.First(group =>
                             group.Any(analysis => analysis.Function.Value == builder.Source.Function.Value
                                 && analysis.Function.Size == builder.Source.Function.Size)))
                {
                    resultList.Add(new FunctionProtectionFunctionResult(
                        alias.Function,
                        true,
                        false,
                        Array.Empty<ProtectionPass>(),
                        diagnosticBag.ToArray())
                    {
                        ResourcePlan = resourcePlan,
                    });
                }

                continue;
            }

            builder.OutputAddress = start;
            builder.OutputSize = emitter.PositionAddress - start;
            foreach (var alias in analysisGroups.First(group =>
                         group.Any(analysis => analysis.Function.Value == builder.Source.Function.Value
                             && analysis.Function.Size == builder.Source.Function.Size)))
            {
                resultList.Add(new FunctionProtectionFunctionResult(
                    alias.Function,
                    true,
                    true,
                    passes.ToArray(),
                    Array.Empty<Diagnostic>())
                {
                    ResourcePlan = resourcePlan,
                });
            }
        }

        if (diagnosticBag.HasErrors)
        {
            code = default!;
            results = resultList;
            diagnostics = diagnosticBag.ToArray();
            return false;
        }

        byte[] emitted;
        try
        {
            emitted = emitter.ToBytes();
        }
        catch (Exception exception) when (exception is InvalidOperationException or OverflowException)
        {
            diagnosticBag.Error(
                DiagnosticCode.ProtectionBranchOutOfRange,
                exception.Message);
            code = default!;
            results = resultList;
            diagnostics = diagnosticBag.ToArray();
            return false;
        }

        code = new ProtectedCode(
            codeBase,
            emitted,
            builders.Select(builder => new FunctionPatch(
                builder.Source.Function.Value,
                builder.OutputAddress,
                builder.Source.Function.Size,
                builder.OutputSize)).ToArray());
        results = resultList;
        diagnostics = diagnosticBag.ToArray();
        return true;
    }

    private bool TryBuildFunction(
        Aarch64FunctionAnalysis analysis,
        bool flatten,
        bool permutation,
        Aarch64RegisterResourcePlan resourcePlan,
        out ProtectedFunctionBuilder builder,
        out Diagnostic diagnostic)
    {
        diagnostic = default;
        builder = default!;
        if (!resourcePlan.IsSufficient)
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.FunctionResourceUnavailable,
                resourcePlan.FailureReason ?? "The selected function has insufficient register resources.",
                analysis.Function.Value);
            return false;
        }
        if (analysis.Blocks.Count == 0)
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.FunctionAnalysisIncomplete,
                "The selected function has no basic blocks.",
                analysis.Function.Value);
            return false;
        }

        if (!analysis.Instructions.Any(instruction =>
                instruction.Decode.Instruction?.ControlFlow == Aarch64ControlFlowKind.Return))
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.ProtectionUnsupportedInstruction,
                "The selected function has no return instruction in its bounded CFG.",
                analysis.Function.Value);
            return false;
        }

        var scratchRegister = flatten && permutation ? (byte)17 : (byte)16;
        foreach (var instruction in analysis.Instructions)
        {
            if (decoder.UsesGeneralRegister(instruction.Encoding, instruction.Address, StateRegister)
                || (permutation
                    && decoder.UsesGeneralRegister(instruction.Encoding, instruction.Address, scratchRegister)))
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.FunctionResourceUnavailable,
                    flatten
                        ? "The selected function uses a reserved control-flow state or permutation scratch register."
                        : "The selected function uses the reserved permutation scratch register.",
                    instruction.FileOffset);
                return false;
            }

            var controlFlow = instruction.Decode.Instruction?.ControlFlow;
            var isTerminalBranch = controlFlow is Aarch64ControlFlowKind.DirectBranch
                or Aarch64ControlFlowKind.ConditionalBranch;
            if ((instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true
                    && !isTerminalBranch)
                || controlFlow is Aarch64ControlFlowKind.DirectCall
                    or Aarch64ControlFlowKind.IndirectBranch)
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionUnsupportedInstruction,
                    "The selected function contains a call, indirect branch, or PC-relative instruction outside the initial rewrite subset.",
                    instruction.FileOffset);
                return false;
            }

            if (!flatten
                && isTerminalBranch)
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionUnsupportedInstruction,
                    "Register permutation without flattening cannot relocate a function with branches.",
                    instruction.FileOffset);
                return false;
            }
        }

        if (flatten && analysis.Blocks.Count > 4096)
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.FunctionResourceUnavailable,
                "The selected function has too many basic blocks for the bounded dispatcher state.",
                analysis.Function.Value);
            return false;
        }

        foreach (var block in analysis.Blocks)
        {
            var last = block.Instructions[^1];
            if (last.Decode.Instruction?.ControlFlow == Aarch64ControlFlowKind.ConditionalBranch
                && !last.Decode.Instruction.Properties.HasFlag(Aarch64InstructionProperties.ReadsNzcv))
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionUnsupportedInstruction,
                    "Only NZCV-based b.cond branches are supported by the initial flattening pass.",
                    last.FileOffset);
                return false;
            }

            if (last.Decode.Instruction?.ControlFlow == Aarch64ControlFlowKind.ConditionalBranch
                && !block.Instructions
                    .Take(block.Instructions.Count - 1)
                    .Any(instruction => instruction.Decode.Instruction?.Properties
                        .HasFlag(Aarch64InstructionProperties.WritesNzcv) == true))
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionUnsupportedInstruction,
                    "A flattened conditional branch depends on NZCV state not produced within its block.",
                    last.FileOffset);
                return false;
            }
        }

        if (analysis.Function.Size < sizeof(uint))
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.FunctionResourceUnavailable,
                "The selected function is too small for an entry trampoline.",
                analysis.Function.Value);
            return false;
        }

        if (permutation
            && !analysis.Instructions.Any(instruction =>
                decoder.UsesGeneralRegister(instruction.Encoding, instruction.Address, 9)
                || decoder.UsesGeneralRegister(instruction.Encoding, instruction.Address, 10)))
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.FunctionResourceUnavailable,
                "The selected function has no eligible x9/x10 register values for permutation.",
                analysis.Function.Value);
            return false;
        }

        builder = new ProtectedFunctionBuilder(analysis, flatten, permutation);
        return true;
    }

    private bool ValidateRewrittenOutput(
        ElfFile source,
        ElfFile rewrittenFile,
        byte[] rewrittenBytes,
        ProtectedCode protectedCode,
        ElfLayoutPlan layoutPlan,
        IReadOnlyList<ElfFunctionSymbol> selected,
        DiagnosticBag diagnostics)
    {
        var changedRanges = selected
            .Where(function => function.TryGetEnd(out _))
            .Select(function =>
            {
                source.LoadMap.TryVirtualAddressToFileOffset(function.Value, function.Size, out var offset);
                return new FileRange(offset, function.Size);
            })
            .ToArray();
        var layoutRanges = layoutPlan.Edits
            .Where(edit => edit.Offset.Value < (ulong)source.Bytes.Length)
            .Select(edit => new FileRange(
                edit.Offset.Value,
                Math.Min((ulong)edit.Bytes.Length, (ulong)source.Bytes.Length - edit.Offset.Value)))
            .ToArray();
        var sourceSpan = source.Bytes.Span;
        var rewrittenSpan = rewrittenBytes.AsSpan();
        if (rewrittenSpan.Length < sourceSpan.Length)
        {
            diagnostics.Error(
                DiagnosticCode.WrapperMalformed,
                "The protected ELF is shorter than the source image.");
            return false;
        }

        for (ulong offset = 0; offset < (ulong)sourceSpan.Length; offset++)
        {
            if (changedRanges.Any(range => range.Contains(offset))
                || layoutRanges.Any(range => range.Contains(offset)))
            {
                continue;
            }

            if (sourceSpan[checked((int)offset)] != rewrittenSpan[checked((int)offset)])
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "The protected layout changed bytes outside selected functions and its planned layout edits.",
                    offset);
                return false;
            }
        }

        foreach (var patch in protectedCode.Patches)
        {
            if (!rewrittenFile.LoadMap.TryVirtualAddressToFileOffset(
                    patch.SourceAddress,
                    patch.SourceSize,
                    out var sourceOffset)
                || sourceOffset > int.MaxValue
                || sourceOffset + patch.SourceSize > (ulong)rewrittenSpan.Length)
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "A transformed function is not file-backed in the rewritten image.",
                    patch.SourceAddress);
                return false;
            }

            var firstWord = BinaryPrimitives.ReadUInt32LittleEndian(
                rewrittenSpan.Slice(checked((int)sourceOffset), sizeof(uint)));
            var decoded = decoder.Decode(firstWord, patch.SourceAddress);
            if (!decoded.IsSuccess
                || decoded.Instruction?.ControlFlow != Aarch64ControlFlowKind.DirectBranch
                || decoded.Instruction.DirectTarget != patch.TargetAddress)
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "A transformed function does not contain the expected entry branch.",
                    patch.SourceAddress);
                return false;
            }

            for (ulong offset = 0; offset < patch.SourceSize; offset += sizeof(uint))
            {
                var instructionEncoding = BinaryPrimitives.ReadUInt32LittleEndian(
                    rewrittenSpan.Slice(checked((int)(sourceOffset + offset)), sizeof(uint)));
                var instruction = decoder.Decode(instructionEncoding, patch.SourceAddress + offset);
                if (!instruction.IsSuccess)
                {
                    diagnostics.Error(
                        DiagnosticCode.WrapperMalformed,
                        "A transformed function could not be decoded after emission.",
                        patch.SourceAddress + offset);
                    return false;
                }
            }
        }

        if (!rewrittenFile.LoadMap.TryVirtualAddressToFileOffset(
                protectedCode.VirtualAddress,
                checked((ulong)protectedCode.Bytes.Length),
                out var protectedOffset)
            || protectedOffset > int.MaxValue
            || protectedOffset + (ulong)protectedCode.Bytes.Length > (ulong)rewrittenSpan.Length)
        {
            diagnostics.Error(
                DiagnosticCode.WrapperMalformed,
                "The emitted protected code is not file-backed in the rewritten image.",
                protectedCode.VirtualAddress);
            return false;
        }

        for (var index = 0; index < protectedCode.Bytes.Length; index += sizeof(uint))
        {
            var encoding = BinaryPrimitives.ReadUInt32LittleEndian(
                rewrittenSpan.Slice(checked((int)protectedOffset + index), sizeof(uint)));
            var address = protectedCode.VirtualAddress + checked((ulong)index);
            if (!decoder.Decode(encoding, address).IsSuccess)
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "The emitted protected code could not be decoded after publication.",
                    address);
                return false;
            }
        }

        return true;
    }

    private sealed class ProtectedFunctionBuilder
    {
        public ProtectedFunctionBuilder(Aarch64FunctionAnalysis source, bool flatten, bool permutation)
        {
            Source = source;
            Flatten = flatten;
            Permutation = permutation;
        }

        public Aarch64FunctionAnalysis Source { get; }

        public bool Flatten { get; }

        public bool Permutation { get; }

        public ulong OutputAddress { get; set; }

        public ulong OutputSize { get; set; }

        public bool Emit(
            CodeEmitter emitter,
            AsmStoneAdapter decoder,
            DiagnosticBag diagnostics)
        {
            var scratchRegister = Flatten && Permutation ? (byte)17 : (byte)16;
            if (Permutation)
            {
                EmitRegisterSwap(emitter, scratchRegister);
            }

            if (!Flatten)
            {
                foreach (var instruction in Source.Instructions)
                {
                    if (Permutation
                        && instruction.Decode.Instruction?.ControlFlow == Aarch64ControlFlowKind.Return)
                    {
                        // The inverse shuffle restores the caller-visible values
                        // before the function returns.
                        EmitRegisterSwap(emitter, scratchRegister);
                    }

                    if (!EmitSourceInstruction(emitter, decoder, instruction, diagnostics))
                    {
                        return false;
                    }
                }

                return true;
            }

            var blockIds = Source.Blocks
                .Select((block, index) => (block.StartAddress, Id: index))
                .ToDictionary(value => value.StartAddress, value => value.Id);
            emitter.MarkLabel($"entry-{Source.Function.Value:X}");
            emitter.EmitWord(EncodeMovW(StateRegister, 0));
            emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
            foreach (var block in Source.Blocks)
            {
                emitter.MarkLabel(BlockLabel(block.StartAddress));
                var last = block.Instructions[^1];
                for (var index = 0; index < block.Instructions.Count - 1; index++)
                {
                    var instruction = block.Instructions[index];
                    if (instruction.Decode.Instruction!.ControlFlow != Aarch64ControlFlowKind.None
                        || instruction.Decode.Instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            "A non-terminal control-flow or PC-relative instruction is not supported.",
                            instruction.FileOffset);
                        return false;
                    }

                    if (!EmitSourceInstruction(emitter, decoder, instruction, diagnostics))
                    {
                        return false;
                    }
                }

                if (last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.Return)
                {
                    if (Permutation)
                    {
                        EmitRegisterSwap(emitter, scratchRegister);
                    }

                    if (!EmitSourceInstruction(emitter, decoder, last, diagnostics))
                    {
                        return false;
                    }

                    continue;
                }

                if (last.Decode.Instruction.ControlFlow == Aarch64ControlFlowKind.ConditionalBranch)
                {
                    var edges = block.Successors
                        .Where(edge => edge.Kind is Aarch64ControlFlowEdgeKind.ConditionalBranch or Aarch64ControlFlowEdgeKind.Fallthrough)
                        .ToArray();
                    if (edges.Length != 2
                        || edges.Any(edge => edge.TargetAddress is not { } target || !blockIds.ContainsKey(target)))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            "A conditional block does not have two in-function successor states.",
                            last.FileOffset);
                        return false;
                    }

                    var trueEdge = edges.First(edge => edge.Kind == Aarch64ControlFlowEdgeKind.ConditionalBranch);
                    var falseEdge = edges.First(edge => edge.Kind == Aarch64ControlFlowEdgeKind.Fallthrough);
                    var trueLabel = $"set-{Source.Function.Value:X}-{blockIds[trueEdge.TargetAddress!.Value]}";
                    emitter.EmitConditionalBranch(last.Encoding & 0xF, trueLabel);
                    emitter.EmitWord(EncodeMovW(StateRegister, checked((uint)blockIds[falseEdge.TargetAddress!.Value])));
                    emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
                    emitter.MarkLabel(trueLabel);
                    emitter.EmitWord(EncodeMovW(StateRegister, checked((uint)blockIds[trueEdge.TargetAddress!.Value])));
                    emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
                    continue;
                }

                var next = block.Successors.FirstOrDefault(edge => edge.TargetAddress is { } target && blockIds.ContainsKey(target));
                if (next?.TargetAddress is not { } nextTarget)
                {
                    diagnostics.Error(
                        DiagnosticCode.ProtectionUnsupportedInstruction,
                        "A non-return block has no in-function successor state.",
                        last.FileOffset);
                    return false;
                }

                emitter.EmitWord(EncodeMovW(StateRegister, checked((uint)blockIds[nextTarget])));
                emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
            }

            emitter.MarkLabel($"dispatcher-{Source.Function.Value:X}");
            foreach (var block in Source.Blocks)
            {
                emitter.EmitWord(EncodeCmpW(StateRegister, checked((uint)blockIds[block.StartAddress])));
                emitter.EmitConditionalBranch(0, BlockLabel(block.StartAddress));
            }

            emitter.EmitWord(0xD65F03C0); // RET: unreachable invalid-state guard.
            return true;
        }

        private bool EmitSourceInstruction(
            CodeEmitter emitter,
            AsmStoneAdapter decoder,
            Aarch64FunctionInstruction instruction,
            DiagnosticBag diagnostics)
        {
            if (!Permutation)
            {
                emitter.EmitWord(instruction.Encoding);
                return true;
            }

            var result = decoder.TryPermuteGeneralRegisters(
                instruction.Encoding,
                instruction.Address,
                RegisterPermutation);
            if (!result.IsSuccess)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectionUnsupportedInstruction,
                    result.Diagnostic,
                    instruction.FileOffset);
                return false;
            }

            emitter.EmitWord(result.Encoding);
            return true;
        }

        private static void EmitRegisterSwap(CodeEmitter emitter, byte scratchRegister)
        {
            emitter.EmitWord(EncodeMovX(scratchRegister, 9));
            emitter.EmitWord(EncodeMovX(9, 10));
            emitter.EmitWord(EncodeMovX(10, scratchRegister));
        }

        private static string BlockLabel(ulong address) => $"block-{address:X}";

        private static uint EncodeMovW(byte register, uint immediate) =>
            0x52800000u | ((immediate & 0xFFFF) << 5) | register;

        private static uint EncodeMovX(byte destination, byte source) =>
            0xAA0003E0u | ((uint)source << 16) | destination;

        private static uint EncodeCmpW(byte register, uint immediate) =>
            0x7100001Fu | ((immediate & 0xFFF) << 10) | ((uint)register << 5);
    }

    private sealed record ProtectedCode(
        ulong VirtualAddress,
        byte[] Bytes,
        IReadOnlyList<FunctionPatch> Patches);

    private readonly record struct FunctionPatch(
        ulong SourceAddress,
        ulong TargetAddress,
        ulong SourceSize,
        ulong OutputSize);

    private sealed class CodeEmitter
    {
        private readonly ulong baseAddress;
        private readonly List<uint> words = new();
        private readonly Dictionary<string, int> labels = new(StringComparer.Ordinal);
        private readonly List<BranchPatch> branches = new();

        public CodeEmitter(ulong baseAddress)
        {
            this.baseAddress = baseAddress;
        }

        public ulong PositionAddress => baseAddress + checked((ulong)words.Count * sizeof(uint));

        public void MarkLabel(string label) => labels[label] = words.Count;

        public void EmitWord(uint word) => words.Add(word);

        public void EmitBranch(string label)
        {
            branches.Add(new BranchPatch(words.Count, label, false, 0));
            words.Add(0x14000000);
        }

        public void EmitConditionalBranch(uint condition, string label)
        {
            branches.Add(new BranchPatch(words.Count, label, true, condition & 0xF));
            words.Add(0x54000000u | (condition & 0xF));
        }

        public byte[] ToBytes()
        {
            foreach (var patch in branches)
            {
                if (!labels.TryGetValue(patch.Label, out var targetIndex))
                {
                    throw new InvalidOperationException($"Missing protected-code label '{patch.Label}'.");
                }

                var source = baseAddress + checked((ulong)patch.Index * sizeof(uint));
                var target = baseAddress + checked((ulong)targetIndex * sizeof(uint));
                if (!TrySignedDifference(source, target, out var displacement))
                {
                    throw new InvalidOperationException("Protected-code branch address overflowed.");
                }
                if ((displacement & 3) != 0
                    || (patch.Conditional
                        ? displacement < -(1L << 20) || displacement >= (1L << 20)
                        : displacement < -(128L * 1024 * 1024) || displacement >= 128L * 1024 * 1024))
                {
                    throw new InvalidOperationException("Protected-code branch is out of range.");
                }

                words[patch.Index] = patch.Conditional
                    ? 0x54000000u
                        | (uint)((displacement >> 2) & 0x7FFFF) << 5
                        | patch.Condition
                    : 0x14000000u | (uint)((displacement >> 2) & 0x03FFFFFF);
            }

            var bytes = new byte[checked(words.Count * sizeof(uint))];
            for (var index = 0; index < words.Count; index++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(index * sizeof(uint)), words[index]);
            }

            return bytes;
        }

        private static bool TrySignedDifference(ulong source, ulong target, out long difference)
        {
            if (target >= source)
            {
                var delta = target - source;
                if (delta > long.MaxValue)
                {
                    difference = default;
                    return false;
                }

                difference = (long)delta;
                return true;
            }

            var reverse = source - target;
            if (reverse > (ulong)long.MaxValue)
            {
                difference = default;
                return false;
            }

            difference = -(long)reverse;
            return true;
        }

        private readonly record struct BranchPatch(
            int Index,
            string Label,
            bool Conditional,
            uint Condition);
    }
}
