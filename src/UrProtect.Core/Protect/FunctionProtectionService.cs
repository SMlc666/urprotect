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
    public bool IsSuccess => OutputBytes is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed class FunctionProtectionService
{
    private const uint PtNull = ElfConstants.PtNull;
    private const uint PtLoad = ElfConstants.PtLoad;
    private const uint PfRead = ElfConstants.PfR;
    private const uint PfExecute = ElfConstants.PfX;
    private const ulong SegmentAlignment = 0x1000;
    private const byte StateRegister = 16;
    private static readonly IReadOnlyDictionary<byte, byte> RegisterPermutation =
        new Dictionary<byte, byte> { [9] = 10, [10] = 9 };

    private readonly AsmStoneAdapter decoder;

    public FunctionProtectionService(AsmStoneAdapter? decoder = null)
    {
        this.decoder = decoder ?? new AsmStoneAdapter();
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

        if (!TryFindRewriteSlot(parse.File, out var rewriteSlotIndex))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectionLayoutUnavailable,
                "The ELF has no spare PT_NULL program-header slot for protected code.");
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        if (!TryBuildProtectedCode(
                parse.File,
                analyses,
                orderedPasses,
                out var rewritten,
                out var transformedResults,
                out var rewriteDiagnostics))
        {
            diagnostics.AddRange(rewriteDiagnostics);
            functionResults.AddRange(transformedResults);
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        if (!TryAppendExecutableSegment(
                parse.File,
                rewriteSlotIndex,
                rewritten,
                out var output,
                out var layoutDiagnostic))
        {
            diagnostics.Add(layoutDiagnostic);
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
                rewriteSlotIndex,
                selection.Functions,
                diagnostics))
        {
            return new FunctionProtectionResult(null, functionResults, diagnostics.ToArray());
        }

        return new FunctionProtectionResult(output, functionResults, diagnostics.ToArray());
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
        out IReadOnlyList<Diagnostic> diagnostics)
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

        var codeBase = AlignUp(
            file.LoadMap.Segments.Max(segment => checked(segment.VirtualAddress + segment.MemorySize)),
            SegmentAlignment);

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
                builder.Source.Function.Size)).ToArray());
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
        int rewriteSlotIndex,
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
        var programHeaderOffset = source.Header.ProgramHeaderOffset
            + checked((ulong)rewriteSlotIndex * source.Header.ProgramHeaderEntrySize);
        var programHeaderRange = new FileRange(programHeaderOffset, ElfConstants.ProgramHeaderSize64);
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
                || programHeaderRange.Contains(offset))
            {
                continue;
            }

            if (sourceSpan[checked((int)offset)] != rewrittenSpan[checked((int)offset)])
            {
                diagnostics.Error(
                    DiagnosticCode.WrapperMalformed,
                    "The protected writer changed bytes outside selected functions and its reserved program-header slot.",
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

    private static bool TryFindRewriteSlot(ElfFile file, out int index)
    {
        for (var current = 0; current < file.ProgramHeaders.Count; current++)
        {
            if (file.ProgramHeaders[current].Type == PtNull)
            {
                index = current;
                return true;
            }
        }

        index = -1;
        return false;
    }

    private static bool TryAppendExecutableSegment(
        ElfFile file,
        int rewriteSlotIndex,
        ProtectedCode code,
        out byte[] output,
        out Diagnostic diagnostic)
    {
        var fileOffset = AlignUp((ulong)file.Bytes.Length, SegmentAlignment);
        if (fileOffset > int.MaxValue)
        {
            output = Array.Empty<byte>();
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.ProtectionLayoutUnavailable,
                "The protected code file offset exceeds the supported writer range.");
            return false;
        }

        var totalLength = checked(fileOffset + (ulong)code.Bytes.Length);
        if (totalLength > int.MaxValue)
        {
            output = Array.Empty<byte>();
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.ProtectionLayoutUnavailable,
                "The protected ELF exceeds the supported writer range.");
            return false;
        }

        output = new byte[(int)totalLength];
        file.Bytes.Span.CopyTo(output);
        code.Bytes.CopyTo(output.AsSpan((int)fileOffset));
        foreach (var patch in code.Patches)
        {
            if (!file.LoadMap.TryVirtualAddressToFileOffset(
                    patch.SourceAddress,
                    4,
                    out var patchOffset)
                || !TryEncodeBranch(patch.SourceAddress, patch.TargetAddress, out var branch))
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionBranchOutOfRange,
                    "A protected function entry cannot reach its generated code.",
                    patch.SourceAddress);
                return false;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(
                output.AsSpan(checked((int)patchOffset), sizeof(uint)),
                branch);
            var remaining = patch.SourceSize - sizeof(uint);
            for (ulong offset = 0; offset < remaining; offset += sizeof(uint))
            {
                BinaryPrimitives.WriteUInt32LittleEndian(
                    output.AsSpan(checked((int)(patchOffset + sizeof(uint) + offset)), sizeof(uint)),
                    0xD503201F);
            }
        }

        var programHeaderOffset = checked(file.Header.ProgramHeaderOffset
            + (ulong)rewriteSlotIndex * file.Header.ProgramHeaderEntrySize);
        if (programHeaderOffset > int.MaxValue
            || programHeaderOffset + ElfConstants.ProgramHeaderSize64 > (ulong)output.Length)
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.ProtectionLayoutUnavailable,
                "The spare program-header slot is outside the output.");
            return false;
        }

        var program = output.AsSpan((int)programHeaderOffset, ElfConstants.ProgramHeaderSize64);
        program.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(program, PtLoad);
        BinaryPrimitives.WriteUInt32LittleEndian(program[4..], PfRead | PfExecute);
        BinaryPrimitives.WriteUInt64LittleEndian(program[8..], fileOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(program[16..], code.VirtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(program[24..], code.VirtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(program[32..], (ulong)code.Bytes.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(program[40..], (ulong)code.Bytes.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(program[48..], SegmentAlignment);
        diagnostic = default;
        return true;
    }

    private static bool TryEncodeBranch(ulong source, ulong target, out uint encoding)
    {
        long displacement;
        if (target >= source)
        {
            var delta = target - source;
            if (delta > long.MaxValue)
            {
                encoding = 0;
                return false;
            }

            displacement = (long)delta;
        }
        else
        {
            var delta = source - target;
            if (delta > (ulong)long.MaxValue)
            {
                encoding = 0;
                return false;
            }

            displacement = -(long)delta;
        }

        if ((displacement & 3) != 0
            || displacement < -(128L * 1024 * 1024)
            || displacement >= 128L * 1024 * 1024)
        {
            encoding = 0;
            return false;
        }

        encoding = 0x14000000u | (uint)((displacement >> 2) & 0x03FFFFFF);
        return true;
    }

    private static ulong AlignUp(ulong value, ulong alignment)
    {
        var remainder = value % alignment;
        return remainder == 0 ? value : checked(value + alignment - remainder);
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
        ulong SourceSize);

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
