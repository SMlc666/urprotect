using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

/// <summary>
/// Options for constructing a semantic plan from one analyzed AArch64 function.
/// </summary>
/// <remarks>
/// <see cref="PlannedAddressMap"/> is supplied by a future layout planner. When
/// it is omitted, the factory creates an identity source/output map suitable for
/// analysis-time resolution. The factory never chooses a physical ELF placement.
/// </remarks>
public sealed class Aarch64SemanticPlanFactoryOptions
{
    public Aarch64SemanticPlanFactoryOptions(
        AddressMap? plannedAddressMap = null,
        LoadMap? loadMap = null,
        IEnumerable<ISemanticPlanExtension>? extensions = null)
    {
        PlannedAddressMap = plannedAddressMap;
        LoadMap = loadMap;
        Extensions = Array.AsReadOnly(
            (extensions ?? Array.Empty<ISemanticPlanExtension>()).ToArray());
    }

    /// <summary>
    /// Gets the source-to-output map supplied by the physical layout child.
    /// </summary>
    public AddressMap? PlannedAddressMap { get; }

    /// <summary>
    /// Alias that makes the output-placement role explicit at call sites.
    /// </summary>
    public AddressMap? OutputMap => PlannedAddressMap;

    /// <summary>
    /// Gets the authoritative load map used to discover file-backed literal and
    /// relocation-site ranges outside the selected function.
    /// </summary>
    public LoadMap? LoadMap { get; }

    /// <summary>
    /// Gets immutable extension records owned by sibling semantic children.
    /// </summary>
    public IReadOnlyList<ISemanticPlanExtension> Extensions { get; }
}

/// <summary>
/// Describes an unresolved or runtime-owned semantic reference retained for a
/// sibling resolver instead of being guessed by the function factory.
/// </summary>
public sealed record SemanticUnresolvedReferenceExtension : ISemanticPlanExtension
{
    public SemanticUnresolvedReferenceExtension(
        SemanticEntityId sourceInstruction,
        VirtualAddress sourceAddress,
        SemanticReferenceKind referenceKind,
        SemanticTarget target,
        string diagnostic)
    {
        if (string.IsNullOrWhiteSpace(diagnostic))
        {
            throw new ArgumentException(
                "An unresolved semantic reference requires a diagnostic.",
                nameof(diagnostic));
        }

        SourceInstruction = sourceInstruction;
        SourceAddress = sourceAddress;
        ReferenceKind = referenceKind;
        Target = target ?? throw new ArgumentNullException(nameof(target));
        Diagnostic = diagnostic;
    }

    public SemanticEntityId SourceInstruction { get; }

    public VirtualAddress SourceAddress { get; }

    public SemanticReferenceKind ReferenceKind { get; }

    public SemanticTarget Target { get; }

    public string Diagnostic { get; }

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.UnresolvedReference;
}

/// <summary>
/// Keeps an indirect control-flow target visible to the indirect-target child.
/// </summary>
public sealed record SemanticIndirectTargetExtension : ISemanticPlanExtension
{
    public SemanticIndirectTargetExtension(
        SemanticEntityId sourceInstruction,
        VirtualAddress sourceAddress,
        SemanticTarget target,
        string diagnostic)
    {
        if (string.IsNullOrWhiteSpace(diagnostic))
        {
            throw new ArgumentException(
                "An indirect target extension requires a diagnostic.",
                nameof(diagnostic));
        }

        SourceInstruction = sourceInstruction;
        SourceAddress = sourceAddress;
        Target = target ?? throw new ArgumentNullException(nameof(target));
        Diagnostic = diagnostic;
    }

    public SemanticEntityId SourceInstruction { get; }

    public VirtualAddress SourceAddress { get; }

    public SemanticTarget Target { get; }

    public string Diagnostic { get; }

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.IndirectTargets;
}

/// <summary>
/// Preserves a relocation binding whose source range is outside the currently
/// discoverable file-backed map. A layout or ELF-metadata child can attach the
/// missing placement later without losing the original RELA record.
/// </summary>
public sealed record SemanticRelocationBindingExtension : ISemanticPlanExtension
{
    public SemanticRelocationBindingExtension(
        SemanticEntityId relocationSite,
        RelocationBinding binding,
        string diagnostic)
    {
        if (string.IsNullOrWhiteSpace(diagnostic))
        {
            throw new ArgumentException(
                "An unmapped relocation requires a diagnostic.",
                nameof(diagnostic));
        }

        RelocationSite = relocationSite;
        Binding = binding ?? throw new ArgumentNullException(nameof(binding));
        Diagnostic = diagnostic;
    }

    public SemanticEntityId RelocationSite { get; }

    public RelocationBinding Binding { get; }

    public string Diagnostic { get; }

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.RelocationBinding;
}

/// <summary>
/// Builds the shared semantic rewrite plan for one completed function analysis.
/// </summary>
/// <remarks>
/// This is the integration boundary between <see cref="Aarch64FunctionAnalyzer"/>
/// and the project-owned semantic IR. It projects through
/// <see cref="Aarch64SemanticInstructionProjector"/>, retains symbolic targets,
/// and delegates physical placement to the supplied address map. It does not
/// copy or write instruction bytes.
/// </remarks>
public static class Aarch64SemanticPlanFactory
{
    private const ulong InstructionSize = sizeof(uint);

    /// <summary>
    /// Creates a semantic plan for a completed function analysis.
    /// </summary>
    public static SemanticRewritePlanResult Create(
        Aarch64FunctionAnalysis analysis,
        IEnumerable<RelaRelocation>? relocations = null,
        Aarch64SemanticPlanFactoryOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        options ??= new Aarch64SemanticPlanFactoryOptions();

        var diagnostics = new DiagnosticBag();
        AddAnalysisDiagnostics(analysis, diagnostics);
        if (!TryValidateAnalysis(analysis, options.LoadMap, diagnostics, out var layout))
        {
            return Failure(diagnostics);
        }

        var relocationArray = (relocations ?? Array.Empty<RelaRelocation>()).ToArray();
        if (!ValidateRelocationSites(relocationArray, diagnostics))
        {
            return Failure(diagnostics);
        }

        var relocationsByOffset = GroupRelocations(relocationArray);
        var projections = new List<ProjectedInstruction>(layout.Instructions.Count);
        var projectedInstructions = new List<SemanticInstruction>(layout.Instructions.Count);
        var fixups = new List<SemanticFixup>();

        foreach (var sourceInstruction in layout.Instructions)
        {
            relocationsByOffset.TryGetValue(sourceInstruction.Address, out var matchingRelocations);
            var projection = Aarch64SemanticInstructionProjector.Project(
                sourceInstruction,
                matchingRelocations);
            diagnostics.AddRange(projection.Diagnostics);

            if (projection.Instruction is not { } instruction)
            {
                continue;
            }

            var projectedFixups = projection.Fixups;
            if (TryNormalizeUndiscoverableLiteral(
                    instruction,
                    projectedFixups,
                    options.LoadMap,
                    out var normalizedInstruction,
                    out var normalizedFixups))
            {
                instruction = normalizedInstruction;
                projectedFixups = normalizedFixups;
            }

            projections.Add(new ProjectedInstruction(
                sourceInstruction,
                instruction,
                projectedFixups));
            projectedInstructions.Add(instruction);
            fixups.AddRange(projectedFixups);
        }

        if (diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        var extensions = new List<ISemanticPlanExtension>();
        extensions.AddRange(options.Extensions);
        var mapEntries = new List<AddressMapEntry>();
        AddFunctionAndBlockEntries(layout, mapEntries, diagnostics);
        AddInstructionEntries(layout, mapEntries, diagnostics);
        AddReferenceEntries(
            layout,
            projections,
            relocationArray,
            options,
            mapEntries,
            extensions,
            diagnostics);

        AddUnmappedRelocationFixups(
            layout,
            relocationArray,
            projections,
            options,
            fixups,
            mapEntries,
            extensions,
            diagnostics);

        if (diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        var addressMap = CreateAddressMap(
            mapEntries,
            options.PlannedAddressMap,
            diagnostics);
        if (addressMap is null || diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        var planResult = SemanticRewritePlanBuilder.Build(
            addressMap,
            projectedInstructions,
            fixups,
            extensions,
            diagnostics.ToArray());
        if (!planResult.IsSuccess)
        {
            return Failure(planResult.Diagnostics);
        }

        return planResult;
    }

    /// <summary>
    /// Alias for callers that use build terminology for an analysis-time plan.
    /// </summary>
    public static SemanticRewritePlanResult Build(
        Aarch64FunctionAnalysis analysis,
        IEnumerable<RelaRelocation>? relocations = null,
        Aarch64SemanticPlanFactoryOptions? options = null) =>
        Create(analysis, relocations, options);

    /// <summary>
    /// Creates a plan using a layout-owned map and an optional load map.
    /// </summary>
    public static SemanticRewritePlanResult CreateWithPlacement(
        Aarch64FunctionAnalysis analysis,
        AddressMap plannedAddressMap,
        IEnumerable<RelaRelocation>? relocations = null,
        LoadMap? loadMap = null,
        IEnumerable<ISemanticPlanExtension>? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(plannedAddressMap);
        return Create(
            analysis,
            relocations,
            new Aarch64SemanticPlanFactoryOptions(
                plannedAddressMap,
                loadMap,
                extensions));
    }

    private static void AddAnalysisDiagnostics(
        Aarch64FunctionAnalysis analysis,
        DiagnosticBag diagnostics)
    {
        if (analysis.Diagnostics is not null)
        {
            diagnostics.AddRange(analysis.Diagnostics);
        }
    }

    private static bool TryValidateAnalysis(
        Aarch64FunctionAnalysis analysis,
        LoadMap? loadMap,
        DiagnosticBag diagnostics,
        out AnalysisLayout layout)
    {
        layout = default!;
        var function = analysis.Function;
        if (analysis.Status != Aarch64FunctionAnalysisStatus.Complete)
        {
            diagnostics.Error(
                DiagnosticCode.FunctionAnalysisIncomplete,
                $"Function '{function.Name}' is not complete and cannot produce a semantic rewrite plan.",
                function.Value);
            return false;
        }

        if (diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return false;
        }

        if (analysis.Instructions is null || analysis.Blocks is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "A complete AArch64 function analysis is missing its instruction or basic-block collection.",
                function.Value);
            return false;
        }

        var instructions = analysis.Instructions.ToArray();
        var blocks = analysis.Blocks.ToArray();
        if (function.Size == 0
            || function.Value % InstructionSize != 0
            || function.Size % InstructionSize != 0
            || !function.TryGetEnd(out var functionEnd))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"Function '{function.Name}' has an invalid aligned source range.",
                function.Value);
            return false;
        }

        var expectedInstructionCount = function.Size / InstructionSize;
        if (expectedInstructionCount != (ulong)instructions.Length || instructions.Length == 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"Function '{function.Name}' instruction coverage does not match its symbol range.",
                function.Value);
            return false;
        }

        var firstFileOffset = instructions[0].FileOffset;
        var instructionsByAddress = new Dictionary<ulong, Aarch64FunctionInstruction>();
        var valid = true;
        for (var index = 0; index < instructions.Length; index++)
        {
            var instruction = instructions[index];
            if (!TryMultiply((ulong)index, InstructionSize, out var delta)
                || !TryAdd(function.Value, delta, out var expectedAddress)
                || !TryAdd(firstFileOffset, delta, out var expectedFileOffset)
                || instruction.Address != expectedAddress
                || instruction.FileOffset != expectedFileOffset
                || instruction.Address % InstructionSize != 0
                || instruction.FileOffset % InstructionSize != 0
                || !instructionsByAddress.TryAdd(instruction.Address, instruction))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    $"Function '{function.Name}' contains a duplicate, discontiguous, or unaligned instruction source range.",
                    instruction.FileOffset);
                valid = false;
                continue;
            }

            if (instruction.Address < function.Value
                || instruction.Address > functionEnd - InstructionSize)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    $"Function '{function.Name}' contains an instruction outside its symbol range.",
                    instruction.FileOffset);
                valid = false;
            }
        }

        if (!TryAdd(firstFileOffset, function.Size, out _))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapOverflow,
                $"Function '{function.Name}' file range overflows the file-offset domain.",
                firstFileOffset);
            valid = false;
        }

        if (loadMap is not null
            && !ValidateSourceRangesAgainstLoadMap(
                function,
                instructions,
                loadMap,
                diagnostics))
        {
            valid = false;
        }

        var seenBlockInstructions = new HashSet<ulong>();
        var blockStarts = new HashSet<ulong>();
        foreach (var block in blocks)
        {
            if (block is null || block.Instructions is null || block.Instructions.Count == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    $"Function '{function.Name}' contains an empty or null basic block.",
                    function.Value);
                valid = false;
                continue;
            }

            var blockInstructions = block.Instructions;
            if (block.StartAddress != blockInstructions[0].Address
                || !blockStarts.Add(block.StartAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    $"Function '{function.Name}' contains a basic block with a duplicate or mismatched start address.",
                    block.StartAddress);
                valid = false;
            }

            for (var index = 0; index < blockInstructions.Count; index++)
            {
                var blockInstruction = blockInstructions[index];
                if (!instructionsByAddress.TryGetValue(blockInstruction.Address, out var sourceInstruction)
                    || sourceInstruction.FileOffset != blockInstruction.FileOffset
                    || sourceInstruction.Encoding != blockInstruction.Encoding
                    || (index > 0
                        && (!TryAdd(blockInstructions[index - 1].Address, InstructionSize, out var expectedNext)
                            || blockInstruction.Address != expectedNext))
                    || !seenBlockInstructions.Add(blockInstruction.Address))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanMalformed,
                        $"Function '{function.Name}' contains a basic block with incomplete or overlapping instruction coverage.",
                        blockInstruction.FileOffset);
                    valid = false;
                }
            }
        }

        if (seenBlockInstructions.Count != instructions.Length)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"Function '{function.Name}' basic blocks do not cover every analyzed instruction exactly once.",
                function.Value);
            valid = false;
        }

        if (!valid)
        {
            return false;
        }

        layout = new AnalysisLayout(
            function,
            Array.AsReadOnly(instructions),
            Array.AsReadOnly(blocks),
            new FileOffset(firstFileOffset),
            new VirtualAddress(function.Value),
            function.Size,
            functionEnd);
        return true;
    }

    private static bool ValidateSourceRangesAgainstLoadMap(
        ElfFunctionSymbol function,
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        LoadMap loadMap,
        DiagnosticBag diagnostics)
    {
        var executableSegments = loadMap.Segments
            .Where(segment =>
                segment.IsExecutable
                && segment.ContainsVirtualAddress(function.Value, function.Size))
            .ToArray();
        var valid = executableSegments.Length == 1;
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapMissing,
                $"Function '{function.Name}' does not occupy exactly one executable, file-backed load range in the supplied load map.",
                function.Value);
        }

        if (!loadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(function.Value),
                function.Size,
                out var mappedFunctionFileOffset)
            || mappedFunctionFileOffset.Value != instructions[0].FileOffset)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"Function '{function.Name}' source range does not agree with the supplied load map.",
                function.Value);
            valid = false;
        }

        foreach (var instruction in instructions)
        {
            if (!loadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(instruction.Address),
                    InstructionSize,
                    out var mappedFileOffset)
                || mappedFileOffset.Value != instruction.FileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    $"Instruction 0x{instruction.Address:X} is not mapped to its analyzed file offset by the supplied load map.",
                    instruction.FileOffset);
                valid = false;
            }
        }

        return valid;
    }

    private static void AddFunctionAndBlockEntries(
        AnalysisLayout layout,
        List<AddressMapEntry> entries,
        DiagnosticBag diagnostics)
    {
        var functionIdentity = GetFunctionIdentity(layout.Function);
        if (TryCreateRange(
                layout.FunctionFileOffset,
                layout.FunctionStart,
                layout.FunctionSize,
                out var functionRange))
        {
            entries.Add(new AddressMapEntry(
                SemanticEntityId.Function(functionIdentity),
                functionRange,
                functionRange));
        }
        else
        {
            diagnostics.Error(
                DiagnosticCode.SemanticAddressMapOverflow,
                "The selected function source range cannot be represented in the address map.",
                layout.FunctionFileOffset.Value);
        }

        foreach (var block in layout.Blocks)
        {
            var first = block.Instructions[0];
            var blockSize = checked((ulong)block.Instructions.Count * InstructionSize);
            if (!TryCreateRange(
                    new FileOffset(first.FileOffset),
                    new VirtualAddress(first.Address),
                    blockSize,
                    out var blockRange))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapOverflow,
                    "A basic-block source range cannot be represented in the address map.",
                    first.FileOffset);
                continue;
            }

            entries.Add(new AddressMapEntry(
                SemanticEntityId.BasicBlock(FormatAddress(first.Address)),
                blockRange,
                blockRange));
        }
    }

    private static void AddInstructionEntries(
        AnalysisLayout layout,
        List<AddressMapEntry> entries,
        DiagnosticBag diagnostics)
    {
        foreach (var instruction in layout.Instructions)
        {
            if (!TryCreateRange(
                    new FileOffset(instruction.FileOffset),
                    new VirtualAddress(instruction.Address),
                    InstructionSize,
                    out var range))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapOverflow,
                    "An instruction source range cannot be represented in the address map.",
                    instruction.FileOffset);
                continue;
            }

            entries.Add(new AddressMapEntry(
                SemanticEntityId.Instruction(new VirtualAddress(instruction.Address)),
                range,
                range));
        }
    }

    private static bool TryNormalizeUndiscoverableLiteral(
        SemanticInstruction instruction,
        IReadOnlyList<SemanticFixup> fixups,
        LoadMap? loadMap,
        out SemanticInstruction normalizedInstruction,
        out IReadOnlyList<SemanticFixup> normalizedFixups)
    {
        normalizedInstruction = instruction;
        normalizedFixups = fixups;
        if (instruction.LiteralReference is not { } literal
            || literal.Target.Resolution != SemanticTargetResolution.Exact
            || literal.Target.SourceAddress is not { } targetAddress)
        {
            return false;
        }

        if (literal.PoolRange is { } poolRange)
        {
            if (poolRange.Size == 0
                || !poolRange.TryGetFileEnd(out _)
                || !poolRange.TryGetVirtualEnd(out _))
            {
                // Leave malformed explicit ranges for the plan builder's stable
                // structural diagnostic instead of converting them to an
                // unresolved sibling extension.
                return false;
            }

            if (loadMap is null)
            {
                return false;
            }

            if (loadMap.TryVirtualAddressToFileOffset(
                    poolRange.VirtualAddress,
                    poolRange.Size,
                    out var mappedPoolFileOffset)
                && mappedPoolFileOffset.Value == poolRange.FileOffset.Value)
            {
                return false;
            }
        }
        else if (loadMap is not null
            && loadMap.TryVirtualAddressToFileOffset(
                targetAddress,
                (ulong)Math.Max(1, literal.AccessSize),
                out _))
        {
            return false;
        }

        var unresolvedTarget = SemanticTarget.Unresolved(
            "The literal target has no discoverable file-backed pool range.");
        var normalizedLiteral = literal with { Target = unresolvedTarget };
        var normalizedExpression = instruction.PcRelativeExpression is { } expression
            ? expression with { Target = unresolvedTarget }
            : null;
        var normalizedReferences = instruction.References
            .Select(reference => reference.Kind is
                    SemanticReferenceKind.Literal
                    or SemanticReferenceKind.PcRelative
                ? reference with
                {
                    Target = unresolvedTarget,
                    PcRelative = reference.PcRelative is { } referenceExpression
                        ? referenceExpression with { Target = unresolvedTarget }
                        : null,
                    Literal = reference.Literal is { } referenceLiteral
                        ? referenceLiteral with { Target = unresolvedTarget }
                        : null,
                }
                : reference)
            .ToArray();
        normalizedInstruction = new SemanticInstruction(
            instruction.SourceVirtualAddress,
            instruction.SourceFileOffset,
            instruction.Encoding,
            instruction.Mnemonic,
            instruction.SourceRange,
            instruction.Operands,
            instruction.RegisterEffects,
            instruction.FlagEffects,
            instruction.ControlFlow,
            instruction.ControlFlowTarget,
            normalizedExpression,
            normalizedLiteral,
            instruction.Relocations,
            normalizedReferences,
            instruction.OpaquePreservation);
        normalizedFixups = fixups
            .Select(fixup => fixup.Kind == SemanticFixupKind.Literal19
                && fixup.Target == literal.Target
                ? new SemanticFixup(
                    fixup.Kind,
                    fixup.SourceAddress,
                    fixup.SourceFileOffset,
                    fixup.OriginalEncoding,
                    unresolvedTarget,
                    fixup.SourceRange,
                    fixup.Expression is { } fixupExpression
                        ? fixupExpression with { Target = unresolvedTarget }
                        : null,
                    fixup.Relocation,
                    fixup.Relaxation,
                    fixup.RelaxationOptions)
                : fixup)
            .ToArray();
        return true;
    }

    private static void AddReferenceEntries(
        AnalysisLayout layout,
        IReadOnlyList<ProjectedInstruction> projections,
        IReadOnlyList<RelaRelocation> relocations,
        Aarch64SemanticPlanFactoryOptions options,
        List<AddressMapEntry> entries,
        List<ISemanticPlanExtension> extensions,
        DiagnosticBag diagnostics)
    {
        var literalRanges = new Dictionary<ulong, LiteralRangeCandidate>();
        var relocationTargets = new HashSet<ulong>();

        foreach (var projection in projections)
        {
            var instructionIdentity = SemanticEntityId.Instruction(
                new VirtualAddress(projection.Source.Address));
            foreach (var reference in projection.Instruction.References)
            {
                if (reference.Literal is null
                    && (reference.Target.IsUnresolved
                        || reference.Target.IsRuntimeResolved
                        || reference.Target.IsBoundedSet))
                {
                    AddUnresolvedReferenceExtension(
                        instructionIdentity,
                        projection.Source.Address,
                        reference,
                        extensions);
                }

                if (reference.Literal is { } literalReference)
                {
                    AddLiteralCandidate(
                        layout,
                        options,
                        literalReference,
                        literalRanges,
                        instructionIdentity,
                        projection.Source.Address,
                        extensions,
                        diagnostics);
                }

                if (reference.Relocation is { } relocation)
                {
                    AddRelocationTargetCandidate(
                        layout,
                        options,
                        relocation,
                        relocationTargets,
                        entries,
                        diagnostics);
                }
            }
        }

        foreach (var literal in literalRanges.Values)
        {
            if (!TryCreateRange(
                    literal.FileOffset,
                    literal.VirtualAddress,
                    literal.Size,
                    out var literalRange))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapOverflow,
                    "A literal source range cannot be represented in the address map.",
                    literal.FileOffset.Value);
                continue;
            }

            entries.Add(new AddressMapEntry(
                SemanticEntityId.Literal(FormatAddress(literal.VirtualAddress.Value)),
                literalRange,
                literalRange));
        }

        foreach (var relocation in relocations)
        {
            AddRelocationSiteEntry(
                layout,
                options,
                relocation,
                entries,
                extensions,
                diagnostics);
        }
    }

    private static void AddUnmappedRelocationFixups(
        AnalysisLayout layout,
        IReadOnlyList<RelaRelocation> relocations,
        IReadOnlyList<ProjectedInstruction> projections,
        Aarch64SemanticPlanFactoryOptions options,
        List<SemanticFixup> fixups,
        List<AddressMapEntry> entries,
        List<ISemanticPlanExtension> extensions,
        DiagnosticBag diagnostics)
    {
        var projectedFixupKeys = projections
            .SelectMany(projection => projection.Fixups)
            .Where(fixup => fixup.Relocation is not null)
            .Select(fixup => (fixup.SourceAddress, fixup.Relocation!.Kind))
            .ToHashSet();

        foreach (var relocation in relocations)
        {
            var kind = relocation.Kind;
            var writeSize = SemanticFixup.GetRelocationWriteSize(kind);
            if (writeSize == 0 || projectedFixupKeys.Contains((new VirtualAddress(relocation.Offset), kind)))
            {
                continue;
            }

            var binding = CreateRelocationBinding(relocation, null);
            if (!TryGetSourceFileOffset(
                    layout,
                    options.LoadMap,
                    new VirtualAddress(relocation.Offset),
                    writeSize,
                    out var fileOffset))
            {
                extensions.Add(new SemanticRelocationBindingExtension(
                    SemanticEntityId.RelocationSite(FormatAddress(relocation.Offset)),
                    binding,
                    "The relocation site is not file-backed in the selected analysis map."));
                continue;
            }

            var siteIdentity = SemanticEntityId.RelocationSite(FormatAddress(relocation.Offset));
            var siteRange = new SemanticSourceRange(
                fileOffset,
                new VirtualAddress(relocation.Offset),
                writeSize);
            entries.Add(new AddressMapEntry(siteIdentity, siteRange, siteRange));
            fixups.Add(SemanticFixup.FromRelocation(
                new VirtualAddress(relocation.Offset),
                fileOffset,
                0,
                binding,
                siteRange));
        }
    }

    private static void AddLiteralCandidate(
        AnalysisLayout layout,
        Aarch64SemanticPlanFactoryOptions options,
        LiteralReference literal,
        IDictionary<ulong, LiteralRangeCandidate> candidates,
        SemanticEntityId sourceInstruction,
        ulong sourceAddress,
        List<ISemanticPlanExtension> extensions,
        DiagnosticBag diagnostics)
    {
        if (literal.Target.Resolution != SemanticTargetResolution.Exact
            || literal.Target.SourceAddress is not { } targetAddress)
        {
            AddUnresolvedReferenceExtension(
                sourceInstruction,
                sourceAddress,
                new SemanticReference(
                    SemanticReferenceKind.Literal,
                    literal.Target,
                    Literal: literal),
                extensions);
            return;
        }

        if (literal.PoolRange is { } poolRange
            && (poolRange.Size == 0
                || !poolRange.TryGetVirtualEnd(out _)
                || targetAddress.Value < poolRange.VirtualAddress.Value
                || targetAddress.Value - poolRange.VirtualAddress.Value >= poolRange.Size))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                "A literal target is outside its declared file-backed pool range.",
                sourceAddress);
            return;
        }

        var size = literal.PoolRange?.Size ?? (ulong)Math.Max(1, literal.AccessSize);
        var fileOffset = literal.PoolRange?.FileOffset;
        var virtualAddress = literal.PoolRange?.VirtualAddress ?? targetAddress;
        if (fileOffset is null)
        {
            if (options.LoadMap is null
                || !options.LoadMap.TryVirtualAddressToFileOffset(
                    targetAddress,
                    size,
                    out var discoveredFileOffset))
            {
                AddUnresolvedReferenceExtension(
                    sourceInstruction,
                    sourceAddress,
                    new SemanticReference(
                        SemanticReferenceKind.Literal,
                        literal.Target,
                        Literal: literal),
                    extensions,
                    "The literal target is decoded but has no discoverable file-backed pool range.");
                return;
            }

            fileOffset = discoveredFileOffset;
        }
        if (candidates.TryGetValue(targetAddress.Value, out var existing))
        {
            if (existing.FileOffset != fileOffset.Value
                || existing.VirtualAddress != virtualAddress
                || existing.Size != size)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapDuplicate,
                    "Literal references at one source address have conflicting typed ranges.",
                    sourceAddress);
            }

            return;
        }

        candidates.Add(
            targetAddress.Value,
            new LiteralRangeCandidate(fileOffset.Value, virtualAddress, size));
    }

    private static void AddRelocationTargetCandidate(
        AnalysisLayout layout,
        Aarch64SemanticPlanFactoryOptions options,
        RelocationBinding binding,
        HashSet<ulong> knownTargets,
        List<AddressMapEntry> entries,
        DiagnosticBag diagnostics)
    {
        if (binding.Target.Resolution != SemanticTargetResolution.Exact
            || binding.Target.SourceAddress is not { } targetAddress
            || !knownTargets.Add(targetAddress.Value)
            || !TryGetSourceFileOffset(
                layout,
                options.LoadMap,
                targetAddress,
                InstructionSize,
                out var fileOffset)
            || !TryCreateRange(fileOffset, targetAddress, InstructionSize, out var targetRange))
        {
            return;
        }

        entries.Add(new AddressMapEntry(
            SemanticEntityId.RelocationTarget(FormatAddress(targetAddress.Value)),
            targetRange,
            targetRange));
    }

    private static void AddRelocationSiteEntry(
        AnalysisLayout layout,
        Aarch64SemanticPlanFactoryOptions options,
        RelaRelocation relocation,
        List<AddressMapEntry> entries,
        List<ISemanticPlanExtension> extensions,
        DiagnosticBag diagnostics)
    {
        var writeSize = SemanticFixup.GetRelocationWriteSize(relocation.Kind);
        if (writeSize == 0)
        {
            extensions.Add(new SemanticRelocationBindingExtension(
                SemanticEntityId.RelocationSite(FormatAddress(relocation.Offset)),
                CreateRelocationBinding(relocation, null),
                $"The AArch64 relocation type {relocation.Type} has no project-owned write width."));
            return;
        }

        if (!TryGetSourceFileOffset(
                layout,
                options.LoadMap,
                new VirtualAddress(relocation.Offset),
                writeSize,
                out var fileOffset))
        {
            extensions.Add(new SemanticRelocationBindingExtension(
                SemanticEntityId.RelocationSite(FormatAddress(relocation.Offset)),
                CreateRelocationBinding(relocation, null),
                "The relocation site is not file-backed in the selected analysis map."));
            return;
        }

        var range = new SemanticSourceRange(
            fileOffset,
            new VirtualAddress(relocation.Offset),
            writeSize);
        entries.Add(new AddressMapEntry(
            SemanticEntityId.RelocationSite(FormatAddress(relocation.Offset)),
            range,
            range));
    }

    private static AddressMap? CreateAddressMap(
        IReadOnlyList<AddressMapEntry> generatedEntries,
        AddressMap? plannedAddressMap,
        DiagnosticBag diagnostics)
    {
        if (plannedAddressMap is not null)
        {
            foreach (var generatedEntry in generatedEntries)
            {
                if (!plannedAddressMap.TryGet(generatedEntry.Identity, out var plannedEntry))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        $"The supplied output address map is missing '{generatedEntry.Identity.Kind}:{generatedEntry.Identity.Value}'.",
                        generatedEntry.SourceFileOffset.Value);
                    continue;
                }

                if (plannedEntry.SourceRange != generatedEntry.SourceRange)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMalformed,
                        $"The supplied output address map changes the source range for '{generatedEntry.Identity.Kind}:{generatedEntry.Identity.Value}'.",
                        generatedEntry.SourceFileOffset.Value);
                }

                if ((generatedEntry.Identity.Kind is
                        SemanticEntityKind.Instruction
                        or SemanticEntityKind.RelocationSite)
                    && (plannedEntry.OutputRange.Size != generatedEntry.SourceRange.Size
                        || plannedEntry.OutputRange.FileOffset.Value % generatedEntry.SourceRange.Size != 0
                        || plannedEntry.OutputRange.VirtualAddress.Value % generatedEntry.SourceRange.Size != 0))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMalformed,
                        $"The supplied output address map does not preserve the aligned write range for '{generatedEntry.Identity.Kind}:{generatedEntry.Identity.Value}'.",
                        generatedEntry.SourceFileOffset.Value);
                }
            }

            return diagnostics.HasErrors ? null : plannedAddressMap;
        }

        var result = AddressMap.Create(generatedEntries);
        diagnostics.AddRange(result.Diagnostics);
        return result.Map;
    }

    private static void AddUnresolvedReferenceExtension(
        SemanticEntityId sourceInstruction,
        ulong sourceAddress,
        SemanticReference reference,
        List<ISemanticPlanExtension> extensions,
        string? diagnosticOverride = null)
    {
        var diagnostic = diagnosticOverride
            ?? reference.Target.Diagnostic
            ?? "The semantic reference requires a sibling resolver before final encoding.";
        if (reference.Kind == SemanticReferenceKind.ControlFlowTarget)
        {
            extensions.Add(new SemanticIndirectTargetExtension(
                sourceInstruction,
                new VirtualAddress(sourceAddress),
                reference.Target,
                diagnostic));
            return;
        }

        extensions.Add(new SemanticUnresolvedReferenceExtension(
            sourceInstruction,
            new VirtualAddress(sourceAddress),
            reference.Kind,
            reference.Target,
            diagnostic));
    }

    private static bool ValidateRelocationSites(
        IReadOnlyList<RelaRelocation> relocations,
        DiagnosticBag diagnostics)
    {
        var valid = true;
        foreach (var group in relocations.GroupBy(relocation => relocation.Offset))
        {
            if (group.Skip(1).Any())
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapDuplicate,
                    $"Multiple AArch64 relocation records target source site 0x{group.Key:X}.",
                    group.Key);
                valid = false;
            }
        }

        return valid;
    }

    private static Dictionary<ulong, IReadOnlyList<RelaRelocation>> GroupRelocations(
        IReadOnlyList<RelaRelocation> relocations)
    {
        var grouped = new Dictionary<ulong, List<RelaRelocation>>();
        foreach (var relocation in relocations)
        {
            if (!grouped.TryGetValue(relocation.Offset, out var matching))
            {
                matching = new List<RelaRelocation>();
                grouped.Add(relocation.Offset, matching);
            }

            matching.Add(relocation);
        }

        return grouped.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<RelaRelocation>)Array.AsReadOnly(pair.Value.ToArray()));
    }

    private static RelocationBinding CreateRelocationBinding(
        RelaRelocation relocation,
        ulong? directTarget)
    {
        SemanticTarget target;
        if (relocation.IsPlt)
        {
            target = SemanticTarget.RuntimeResolved($"plt:symbol:{relocation.SymbolIndex}");
        }
        else if (relocation.Kind == Aarch64RelocationKind.Relative)
        {
            target = SemanticTarget.RuntimeResolved("image-base");
        }
        else if (relocation.Kind is Aarch64RelocationKind.GlobalData or Aarch64RelocationKind.JumpSlot)
        {
            target = SemanticTarget.RuntimeResolved(
                $"dynamic:{relocation.Kind}:symbol:{relocation.SymbolIndex}");
        }
        else if (relocation.SymbolIndex != 0)
        {
            target = SemanticTarget.RuntimeResolved(
                $"relocation:type:{relocation.Type}:symbol:{relocation.SymbolIndex}");
        }
        else if (directTarget is { } targetAddress)
        {
            target = SemanticTarget.Exact(new VirtualAddress(targetAddress));
        }
        else
        {
            target = SemanticTarget.Unresolved(
                $"The AArch64 relocation target for symbol {relocation.SymbolIndex} requires a symbol resolver.");
        }

        return RelocationBinding.FromRelocation(relocation, target);
    }

    private static bool TryGetSourceFileOffset(
        AnalysisLayout layout,
        LoadMap? loadMap,
        VirtualAddress address,
        ulong size,
        out FileOffset fileOffset)
    {
        if (size == 0)
        {
            fileOffset = default;
            return false;
        }

        if (loadMap is not null)
        {
            if (loadMap.TryVirtualAddressToFileOffset(address, size, out fileOffset))
            {
                return true;
            }

            fileOffset = default;
            return false;
        }

        if (address.Value < layout.FunctionStart.Value
            || address.Value - layout.FunctionStart.Value > layout.FunctionSize
            || size > layout.FunctionSize - (address.Value - layout.FunctionStart.Value))
        {
            fileOffset = default;
            return false;
        }

        var delta = address.Value - layout.FunctionStart.Value;
        if (!TryAdd(layout.FunctionFileOffset.Value, delta, out var rawFileOffset))
        {
            fileOffset = default;
            return false;
        }

        fileOffset = new FileOffset(rawFileOffset);
        return true;
    }

    private static bool TryCreateRange(
        FileOffset fileOffset,
        VirtualAddress virtualAddress,
        ulong size,
        out SemanticSourceRange range)
    {
        range = new SemanticSourceRange(fileOffset, virtualAddress, size);
        return size != 0
            && range.TryGetFileEnd(out _)
            && range.TryGetVirtualEnd(out _);
    }

    private static string GetFunctionIdentity(ElfFunctionSymbol function) =>
        string.IsNullOrWhiteSpace(function.Name)
            ? $"{function.Table}:{function.TableIndex}:{FormatAddress(function.Value)}"
            : function.Name;

    private static string FormatAddress(ulong address) => $"0x{address:X}";

    private static bool TryMultiply(ulong left, ulong right, out ulong result)
    {
        if (left != 0 && right > ulong.MaxValue / left)
        {
            result = default;
            return false;
        }

        result = left * right;
        return true;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        if (left > ulong.MaxValue - right)
        {
            result = default;
            return false;
        }

        result = left + right;
        return true;
    }

    private static SemanticRewritePlanResult Failure(IEnumerable<Diagnostic> diagnostics) =>
        new(null, diagnostics);

    private sealed record AnalysisLayout(
        ElfFunctionSymbol Function,
        IReadOnlyList<Aarch64FunctionInstruction> Instructions,
        IReadOnlyList<Aarch64BasicBlock> Blocks,
        FileOffset FunctionFileOffset,
        VirtualAddress FunctionStart,
        ulong FunctionSize,
        ulong FunctionEnd);

    private sealed record ProjectedInstruction(
        Aarch64FunctionInstruction Source,
        SemanticInstruction Instruction,
        IReadOnlyList<SemanticFixup> Fixups);

    private readonly record struct LiteralRangeCandidate(
        FileOffset FileOffset,
        VirtualAddress VirtualAddress,
        ulong Size);
}
