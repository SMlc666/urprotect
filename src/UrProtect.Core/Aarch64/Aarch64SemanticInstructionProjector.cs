using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

/// <summary>
/// The result of projecting one decoder-owned instruction into the semantic IR.
/// </summary>
public sealed record SemanticInstructionProjectionResult
{
    public SemanticInstructionProjectionResult(
        SemanticInstruction? instruction,
        IEnumerable<SemanticFixup> fixups,
        IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(fixups);
        ArgumentNullException.ThrowIfNull(diagnostics);
        Instruction = instruction;
        Fixups = Array.AsReadOnly(fixups.ToArray());
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
    }

    public SemanticInstruction? Instruction { get; }

    public IReadOnlyList<SemanticFixup> Fixups { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsSuccess => Instruction is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// The result of projecting a sequence of decoder-owned instructions.
/// </summary>
public sealed record SemanticInstructionProjectionBatchResult
{
    public SemanticInstructionProjectionBatchResult(
        IEnumerable<SemanticInstruction> instructions,
        IEnumerable<SemanticFixup> fixups,
        IEnumerable<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(fixups);
        ArgumentNullException.ThrowIfNull(diagnostics);
        Instructions = Array.AsReadOnly(instructions.ToArray());
        Fixups = Array.AsReadOnly(fixups.ToArray());
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
    }

    public IReadOnlyList<SemanticInstruction> Instructions { get; }

    public IReadOnlyList<SemanticFixup> Fixups { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Projects the existing AArch64 decoder records into the project-owned
/// semantic rewrite model.
/// </summary>
/// <remarks>
/// This class deliberately owns no instruction encoder and performs no physical
/// ELF placement. It carries symbolic targets and fixups forward to the
/// address-map and layout consumers. AsmStone remains behind
/// <see cref="AsmStoneAdapter"/>; this projector consumes only the project
/// records exposed by that adapter.
/// </remarks>
public static class Aarch64SemanticInstructionProjector
{
    private const int InstructionSize = sizeof(uint);

    /// <summary>
    /// Projects one decoded function instruction. Relocations are matched by
    /// their ELF relocation offset, which is the relocated virtual address.
    /// </summary>
    public static SemanticInstructionProjectionResult Project(
        Aarch64FunctionInstruction instruction,
        IEnumerable<RelaRelocation>? relocations = null)
    {
        var diagnostics = new DiagnosticBag();
        if (!TryGetDecodedInstruction(instruction, diagnostics, out var decoded))
        {
            return new SemanticInstructionProjectionResult(
                null,
                Array.Empty<SemanticFixup>(),
                diagnostics.ToArray());
        }

        if (!ValidateSourceInstruction(instruction, decoded, diagnostics))
        {
            return new SemanticInstructionProjectionResult(
                null,
                Array.Empty<SemanticFixup>(),
                diagnostics.ToArray());
        }

        var decodedOperands = decoded.Operands ?? Array.Empty<Aarch64SemanticOperand>();
        var projectedOperands = new List<SemanticOperand>(decodedOperands.Count);
        foreach (var operand in decodedOperands)
        {
            if (operand is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticInstructionMalformed,
                    "A decoded AArch64 instruction contains a null operand.",
                    instruction.FileOffset);
                continue;
            }

            if (TryProjectOperand(operand, diagnostics, instruction.FileOffset, out var projectedOperand))
            {
                projectedOperands.Add(projectedOperand!);
            }
        }

        var targetOperand = FindTargetOperand(decoded, out var targetOperandIndex);
        var controlFlowTarget = ProjectControlFlowTarget(decoded, instruction.FileOffset);
        var classification = Aarch64SemanticInstructionClassifier.Classify(decoded, targetOperand);
        var relocationBindings = ProjectRelocations(
            instruction,
            decoded,
            relocations,
            diagnostics);
        var relocationExpression = FindRelocationExpression(
            relocationBindings,
            classification);
        var relocationExpressionTarget = relocationExpression?.Target;
        if (relocationExpressionTarget is { } resolvedRelocationTarget
            && classification is
            {
                Kind: PcRelativeExpressionKind.Branch26
                    or PcRelativeExpressionKind.Call26
                    or PcRelativeExpressionKind.ConditionalBranch19
                    or PcRelativeExpressionKind.TestBranch14
            })
        {
            controlFlowTarget = resolvedRelocationTarget;
        }

        var expressionTarget = relocationExpressionTarget
            ?? (decoded.DirectTarget is { } directTarget
                ? SemanticTarget.Exact(new VirtualAddress(directTarget))
                : CreateMissingPcRelativeTarget(classification, instruction.FileOffset));

        if (controlFlowTarget is { IsUnresolved: true, Diagnostic: { } controlFlowDiagnostic })
        {
            diagnostics.Warning(
                DiagnosticCode.SemanticTargetUnresolved,
                controlFlowDiagnostic,
                instruction.FileOffset);
        }

        if (controlFlowTarget is null
            && expressionTarget is { IsUnresolved: true, Diagnostic: { } expressionDiagnostic })
        {
            diagnostics.Warning(
                DiagnosticCode.SemanticTargetUnresolved,
                expressionDiagnostic,
                instruction.FileOffset);
        }

        PcRelativeExpression? expression = null;
        LiteralReference? literalReference = null;
        if (classification is { } knownClassification && expressionTarget is not null)
        {
            expression = new PcRelativeExpression(
                knownClassification.Kind,
                new VirtualAddress(instruction.Address),
                expressionTarget,
                knownClassification.Scale,
                knownClassification.IsPageRelative,
                relocationExpression?.Addend ?? 0);

            if (knownClassification.IsLiteral)
            {
                literalReference = new LiteralReference(
                    expressionTarget,
                    GetLiteralAccessSize(decoded),
                    decoded.Properties.HasFlag(Aarch64InstructionProperties.Load));
            }
        }
        else if (decoded.Properties.HasFlag(Aarch64InstructionProperties.PcRelative))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupUnsupported,
                $"The AArch64 PC-relative instruction '{decoded.SourceName}' is outside the promoted semantic families and has no opaque-preservation contract.",
                instruction.FileOffset);
        }

        var references = new List<SemanticReference>();
        if (controlFlowTarget is { } projectedControlFlowTarget)
        {
            references.Add(new SemanticReference(
                SemanticReferenceKind.ControlFlowTarget,
                projectedControlFlowTarget,
                targetOperandIndex,
                Description: "AArch64 control-flow target."));
        }

        if (expression is { } projectedExpression)
        {
            references.Add(new SemanticReference(
                SemanticReferenceKind.PcRelative,
                projectedExpression.Target,
                targetOperandIndex,
                projectedExpression,
                Description: "AArch64 PC-relative expression."));
        }

        if (literalReference is { } projectedLiteralReference)
        {
            references.Add(new SemanticReference(
                SemanticReferenceKind.Literal,
                projectedLiteralReference.Target,
                targetOperandIndex,
                Literal: projectedLiteralReference,
                Description: "AArch64 literal-pool reference."));
        }

        foreach (var relocation in relocationBindings)
        {
            references.Add(new SemanticReference(
                SemanticReferenceKind.Relocation,
                relocation.Target,
                Relocation: relocation,
                Description: "ELF RELA relocation binding."));
        }

        var semanticInstruction = new SemanticInstruction(
            new VirtualAddress(instruction.Address),
            new FileOffset(instruction.FileOffset),
            instruction.Encoding,
            decoded.Mnemonic,
            new SemanticSourceRange(
                new FileOffset(instruction.FileOffset),
                new VirtualAddress(instruction.Address),
                InstructionSize),
            projectedOperands,
            ProjectRegisterEffects(decodedOperands),
            ProjectFlagEffects(decoded.Properties),
            decoded.ControlFlow,
            controlFlowTarget,
            expression,
            literalReference,
            relocationBindings,
            references);

        var fixups = CreateFixups(
            instruction,
            semanticInstruction,
            expression,
            relocationBindings,
            diagnostics);

        return new SemanticInstructionProjectionResult(
            semanticInstruction,
            fixups,
            diagnostics.ToArray());
    }

    /// <summary>
    /// Projects a sequence of decoded instructions and matches the supplied
    /// RELA records to instruction virtual addresses.
    /// </summary>
    public static SemanticInstructionProjectionBatchResult Project(
        IEnumerable<Aarch64FunctionInstruction> instructions,
        IEnumerable<RelaRelocation>? relocations = null)
    {
        ArgumentNullException.ThrowIfNull(instructions);

        var relocationByOffset = new Dictionary<ulong, List<RelaRelocation>>();
        if (relocations is not null)
        {
            foreach (var relocation in relocations)
            {
                if (!relocationByOffset.TryGetValue(relocation.Offset, out var matching))
                {
                    matching = new List<RelaRelocation>();
                    relocationByOffset.Add(relocation.Offset, matching);
                }

                matching.Add(relocation);
            }
        }

        var projectedInstructions = new List<SemanticInstruction>();
        var fixups = new List<SemanticFixup>();
        var diagnostics = new DiagnosticBag();
        foreach (var instruction in instructions)
        {
            relocationByOffset.TryGetValue(instruction.Address, out var matchingRelocations);
            var result = Project(instruction, matchingRelocations);
            diagnostics.AddRange(result.Diagnostics);
            if (result.Instruction is { } projectedInstruction)
            {
                projectedInstructions.Add(projectedInstruction);
            }

            fixups.AddRange(result.Fixups);
        }

        return new SemanticInstructionProjectionBatchResult(
            projectedInstructions,
            fixups,
            diagnostics.ToArray());
    }

    public static SemanticInstructionProjectionResult ProjectInstruction(
        Aarch64FunctionInstruction instruction,
        IEnumerable<RelaRelocation>? relocations = null) =>
        Project(instruction, relocations);

    public static SemanticInstructionProjectionBatchResult ProjectInstructions(
        IEnumerable<Aarch64FunctionInstruction> instructions,
        IEnumerable<RelaRelocation>? relocations = null) =>
        Project(instructions, relocations);

    private static bool TryGetDecodedInstruction(
        Aarch64FunctionInstruction source,
        DiagnosticBag diagnostics,
        out Aarch64Instruction decoded)
    {
        decoded = default!;
        if (!source.Decode.IsSuccess || source.Decode.Instruction is null)
        {
            var message = string.IsNullOrWhiteSpace(source.Decode.Diagnostic)
                ? "The AArch64 decoder did not produce a semantic instruction."
                : source.Decode.Diagnostic;
            diagnostics.Error(
                GetDecodeDiagnosticCode(source.Decode.Status),
                message,
                source.FileOffset);
            return false;
        }

        decoded = source.Decode.Instruction!;
        return true;
    }

    internal static DiagnosticCode GetDecodeDiagnosticCode(Aarch64DecodeStatus status) => status switch
    {
        Aarch64DecodeStatus.BackendUnavailable => DiagnosticCode.AsmStoneUnavailable,
        Aarch64DecodeStatus.UnsupportedFeature => DiagnosticCode.UnsupportedInstructionFeature,
        Aarch64DecodeStatus.UnknownEncoding => DiagnosticCode.UnknownInstruction,
        _ => DiagnosticCode.SemanticInstructionMalformed,
    };

    private static bool ValidateSourceInstruction(
        Aarch64FunctionInstruction source,
        Aarch64Instruction decoded,
        DiagnosticBag diagnostics)
    {
        var valid = true;
        if (source.Address % InstructionSize != 0 || source.FileOffset % InstructionSize != 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticInstructionMalformed,
                "A semantic AArch64 instruction source range is not instruction-aligned.",
                source.FileOffset);
            valid = false;
        }

        if (source.Address > ulong.MaxValue - InstructionSize
            || source.FileOffset > ulong.MaxValue - InstructionSize)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticInstructionMalformed,
                "A semantic AArch64 instruction source range overflows its address domain.",
                source.FileOffset);
            valid = false;
        }

        if (decoded.Address != source.Address || decoded.Encoding != source.Encoding)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticInstructionMalformed,
                "The decoded AArch64 instruction does not match its source address or encoding.",
                source.FileOffset);
            valid = false;
        }

        if (string.IsNullOrWhiteSpace(decoded.SourceName)
            || string.IsNullOrWhiteSpace(decoded.Mnemonic))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticInstructionMalformed,
                "A decoded AArch64 instruction has no source name or mnemonic.",
                source.FileOffset);
            valid = false;
        }

        return valid;
    }

    private static bool TryProjectOperand(
        Aarch64SemanticOperand operand,
        DiagnosticBag diagnostics,
        ulong diagnosticOffset,
        out SemanticOperand? projected)
    {
        projected = null;
        if (string.IsNullOrWhiteSpace(operand.Name)
            || string.IsNullOrWhiteSpace(operand.Codec)
            || string.IsNullOrWhiteSpace(operand.SemanticDomain))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticInstructionMalformed,
                "A decoded AArch64 operand has an invalid project-owned identity.",
                diagnosticOffset);
            return false;
        }

        projected = new SemanticOperand(
            operand.Name,
            operand.Kind,
            operand.Direction,
            operand.IsImplicit,
            operand.Codec,
            operand.TiedTo,
            operand.Register,
            operand.Registers,
            operand.Memory,
            operand.Immediate,
            operand.Target,
            operand.RegisterConstraint,
            operand.RegisterWidth,
            operand.FieldWidth,
            operand.ElementWidth,
            operand.AllowsStackPointer,
            operand.AllowsZeroRegister,
            operand.IsPageRelative,
            operand.SemanticDomain);
        return true;
    }

    private static List<SemanticRegisterEffect> ProjectRegisterEffects(
        IReadOnlyList<Aarch64SemanticOperand> operands)
    {
        var effects = new List<SemanticRegisterEffect>();
        foreach (var operand in operands)
        {
            if (operand is null)
            {
                continue;
            }

            var effectKind = MapRegisterEffectKind(operand.Direction);
            if (operand.Register is { } register)
            {
                effects.Add(new SemanticRegisterEffect(register, effectKind, operand.IsImplicit));
            }

            foreach (var listRegister in operand.Registers ?? Array.Empty<Aarch64RegisterView>())
            {
                effects.Add(new SemanticRegisterEffect(listRegister, effectKind, operand.IsImplicit));
            }

            if (operand.Memory is { } memory)
            {
                var addressEffect = memory.WritesBack
                    ? SemanticRegisterEffectKind.ReadWrite
                    : SemanticRegisterEffectKind.Read;
                effects.Add(new SemanticRegisterEffect(memory.Base, addressEffect, operand.IsImplicit));
                if (memory.Index is { } index)
                {
                    effects.Add(new SemanticRegisterEffect(index, SemanticRegisterEffectKind.Read, operand.IsImplicit));
                }
            }
        }

        return effects;
    }

    private static SemanticRegisterEffectKind MapRegisterEffectKind(
        Aarch64OperandDirection direction) => direction switch
        {
            Aarch64OperandDirection.Output => SemanticRegisterEffectKind.Write,
            Aarch64OperandDirection.InputOutput => SemanticRegisterEffectKind.ReadWrite,
            _ => SemanticRegisterEffectKind.Read,
        };

    private static SemanticFlagEffects ProjectFlagEffects(
        Aarch64InstructionProperties properties)
    {
        var effects = SemanticFlagEffects.None;
        if (properties.HasFlag(Aarch64InstructionProperties.ReadsNzcv))
        {
            effects |= SemanticFlagEffects.ReadNzcv;
        }

        if (properties.HasFlag(Aarch64InstructionProperties.WritesNzcv))
        {
            effects |= SemanticFlagEffects.WriteNzcv;
        }

        return effects;
    }

    private static Aarch64SemanticOperand? FindTargetOperand(
        Aarch64Instruction instruction,
        out int operandIndex)
    {
        var operands = instruction.Operands ?? Array.Empty<Aarch64SemanticOperand>();
        for (var index = 0; index < operands.Count; index++)
        {
            var operand = operands[index];
            if (operand is not null
                && operand.Kind == Aarch64OperandKind.Target
                && operand.Target is not null)
            {
                operandIndex = index;
                return operand;
            }
        }

        operandIndex = -1;
        return null;
    }

    private static SemanticTarget? ProjectControlFlowTarget(
        Aarch64Instruction instruction,
        ulong diagnosticOffset)
    {
        switch (instruction.ControlFlow)
        {
            case Aarch64ControlFlowKind.DirectBranch:
            case Aarch64ControlFlowKind.DirectCall:
            case Aarch64ControlFlowKind.ConditionalBranch:
                if (instruction.DirectTarget is { } directTarget)
                {
                    return SemanticTarget.Exact(new VirtualAddress(directTarget));
                }

                return MissingTarget(
                    "A direct AArch64 control-flow instruction has no decoded target.",
                    diagnosticOffset);
            case Aarch64ControlFlowKind.IndirectBranch:
                return MissingTarget(
                    "An indirect AArch64 control-flow target requires an indirect-target resolver.",
                    diagnosticOffset);
            case Aarch64ControlFlowKind.Return:
                return SemanticTarget.RuntimeResolved("aarch64:link-register");
            default:
                return null;
        }
    }

    private static SemanticTarget? CreateMissingPcRelativeTarget(
        Aarch64SemanticInstructionClassification? classification,
        ulong diagnosticOffset)
    {
        return classification is null
            ? null
            : MissingTarget(
                $"The AArch64 {classification.Value.Kind} target was not decoded.",
                diagnosticOffset);
    }

    private static SemanticTarget MissingTarget(string message, ulong diagnosticOffset)
    {
        _ = diagnosticOffset;
        return SemanticTarget.Unresolved(message);
    }

    private static int GetLiteralAccessSize(Aarch64Instruction instruction)
    {
        var sourceName = instruction.SourceName ?? string.Empty;
        if (sourceName.Contains("LDRSW", StringComparison.OrdinalIgnoreCase)
            || sourceName.Contains("LDRW", StringComparison.OrdinalIgnoreCase)
            || sourceName.Contains("LDRS", StringComparison.OrdinalIgnoreCase))
        {
            return sizeof(uint);
        }

        if (sourceName.Contains("LDRQ", StringComparison.OrdinalIgnoreCase))
        {
            return 16;
        }

        if (sourceName.Contains("LDRD", StringComparison.OrdinalIgnoreCase))
        {
            return sizeof(ulong);
        }

        var destination = (instruction.Operands ?? Array.Empty<Aarch64SemanticOperand>())
            .FirstOrDefault(operand => operand is not null
                && (operand.Direction is Aarch64OperandDirection.Output
                    or Aarch64OperandDirection.InputOutput)
                && operand.RegisterWidth > 0);
        if (destination is { RegisterWidth: > 0 })
        {
            return Math.Max(1, destination.RegisterWidth / 8);
        }

        return 1;
    }

    private static RelocationBinding? FindRelocationExpression(
        IReadOnlyList<RelocationBinding> relocations,
        Aarch64SemanticInstructionClassification? classification)
    {
        if (classification is not { } knownClassification)
        {
            return null;
        }

        foreach (var relocation in relocations)
        {
            var matches = knownClassification.Kind switch
            {
                PcRelativeExpressionKind.Branch26 => relocation.Kind == Aarch64RelocationKind.Jump26,
                PcRelativeExpressionKind.Call26 => relocation.Kind == Aarch64RelocationKind.Call26,
                PcRelativeExpressionKind.ConditionalBranch19 =>
                    relocation.Kind == Aarch64RelocationKind.ConditionalBranch19,
                PcRelativeExpressionKind.TestBranch14 =>
                    relocation.Kind == Aarch64RelocationKind.TestBranch14,
                PcRelativeExpressionKind.AdrPrelLo21 =>
                    relocation.Kind == Aarch64RelocationKind.AdrPrelLo21,
                PcRelativeExpressionKind.AdrPrelPgHi21 =>
                    relocation.Kind == Aarch64RelocationKind.AdrPrelPgHi21,
                PcRelativeExpressionKind.Literal19 =>
                    relocation.Kind == Aarch64RelocationKind.Literal19,
                _ => false,
            };
            if (matches)
            {
                return relocation;
            }
        }

        return null;
    }

    private static IReadOnlyList<RelocationBinding> ProjectRelocations(
        Aarch64FunctionInstruction instruction,
        Aarch64Instruction decoded,
        IEnumerable<RelaRelocation>? relocations,
        DiagnosticBag diagnostics)
    {
        if (relocations is null)
        {
            return Array.Empty<RelocationBinding>();
        }

        var bindings = new List<RelocationBinding>();
        foreach (var relocation in relocations)
        {
            if (relocation.Offset != instruction.Address)
            {
                continue;
            }

            var target = CreateRelocationTarget(relocation, decoded);
            var binding = RelocationBinding.FromRelocation(relocation, target);
            bindings.Add(binding);

            if (relocation.Kind == Aarch64RelocationKind.Unknown)
            {
                diagnostics.Warning(
                    DiagnosticCode.SemanticFixupUnsupported,
                    $"The AArch64 relocation type {relocation.Type} is preserved as an unsupported semantic binding.",
                    instruction.FileOffset);
            }
        }

        return bindings;
    }

    private static SemanticTarget CreateRelocationTarget(
        RelaRelocation relocation,
        Aarch64Instruction instruction)
    {
        if (relocation.IsPlt)
        {
            return SemanticTarget.RuntimeResolved($"plt:symbol:{relocation.SymbolIndex}");
        }

        if (relocation.Kind == Aarch64RelocationKind.Relative)
        {
            return SemanticTarget.RuntimeResolved("image-base");
        }

        if (relocation.Kind is Aarch64RelocationKind.GlobalData or Aarch64RelocationKind.JumpSlot)
        {
            return SemanticTarget.RuntimeResolved(
                $"dynamic:{relocation.Kind}:symbol:{relocation.SymbolIndex}");
        }

        // A non-zero symbol index is a symbolic relocation even when the
        // instruction's current immediate happens to decode to an address. Do
        // not turn that stale/addend-bearing immediate into an exact target.
        if (relocation.SymbolIndex != 0)
        {
            return SemanticTarget.RuntimeResolved(
                $"relocation:type:{relocation.Type}:symbol:{relocation.SymbolIndex}");
        }

        if (instruction.DirectTarget is { } directTarget)
        {
            return SemanticTarget.Exact(new VirtualAddress(directTarget));
        }

        return SemanticTarget.Unresolved(
            $"The AArch64 relocation target for symbol {relocation.SymbolIndex} requires a symbol resolver.");
    }

    private static List<SemanticFixup> CreateFixups(
        Aarch64FunctionInstruction source,
        SemanticInstruction instruction,
        PcRelativeExpression? expression,
        IReadOnlyList<RelocationBinding> relocations,
        DiagnosticBag diagnostics)
    {
        var fixups = new List<SemanticFixup>();
        var effectiveRelocations = relocations
            .Where(relocation => relocation.Kind != Aarch64RelocationKind.None)
            .ToArray();

        if (expression is not null)
        {
            var matchingRelocations = effectiveRelocations
                .Where(relocation => MatchesExpression(expression.Kind, relocation.Kind))
                .ToArray();
            if (matchingRelocations.Length > 1)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A PC-relative instruction has multiple matching AArch64 relocation bindings.",
                    source.FileOffset);
                return fixups;
            }

            if (matchingRelocations.Length == 1)
            {
                if (effectiveRelocations.Length != 1)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A PC-relative instruction has relocation bindings from more than one semantic family.",
                        source.FileOffset);
                    return fixups;
                }

                var relocation = matchingRelocations[0];
                if (SemanticFixup.GetRelocationWriteSize(relocation.Kind) != InstructionSize)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        $"The {relocation.Kind} relocation cannot be applied to an instruction-word source range.",
                        source.FileOffset);
                    return fixups;
                }

                fixups.Add(SemanticFixup.FromRelocation(
                    instruction.SourceVirtualAddress,
                    instruction.SourceFileOffset,
                    instruction.Encoding,
                    relocation,
                    instruction.SourceRange));
                return fixups;
            }

            if (effectiveRelocations.Length > 0)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "An AArch64 relocation binding does not match the instruction's PC-relative expression family.",
                    source.FileOffset);
                return fixups;
            }

            if (SemanticFixup.FromInstruction(instruction) is { } instructionFixup)
            {
                fixups.Add(instructionFixup);
            }

            return fixups;
        }

        foreach (var relocation in effectiveRelocations)
        {
            if (!IsInstructionWordRelocation(relocation.Kind))
            {
                diagnostics.Warning(
                    DiagnosticCode.SemanticFixupUnsupported,
                    $"The {relocation.Kind} relocation binding is retained without an instruction-word fixup.",
                    source.FileOffset);
                continue;
            }

            fixups.Add(SemanticFixup.FromRelocation(
                instruction.SourceVirtualAddress,
                instruction.SourceFileOffset,
                instruction.Encoding,
                relocation,
                instruction.SourceRange));
        }

        return fixups;
    }

    private static bool IsInstructionWordRelocation(Aarch64RelocationKind kind) =>
        SemanticFixup.GetRelocationWriteSize(kind) == InstructionSize;

    private static bool MatchesExpression(
        PcRelativeExpressionKind expressionKind,
        Aarch64RelocationKind relocationKind) => (expressionKind, relocationKind) switch
        {
            (PcRelativeExpressionKind.Branch26, Aarch64RelocationKind.Jump26) => true,
            (PcRelativeExpressionKind.Call26, Aarch64RelocationKind.Call26) => true,
            (PcRelativeExpressionKind.ConditionalBranch19, Aarch64RelocationKind.ConditionalBranch19) => true,
            (PcRelativeExpressionKind.TestBranch14, Aarch64RelocationKind.TestBranch14) => true,
            (PcRelativeExpressionKind.AdrPrelLo21, Aarch64RelocationKind.AdrPrelLo21) => true,
            (PcRelativeExpressionKind.AdrPrelPgHi21, Aarch64RelocationKind.AdrPrelPgHi21) => true,
            (PcRelativeExpressionKind.Literal19, Aarch64RelocationKind.Literal19) => true,
            _ => false,
        };
}

/// <summary>
/// The promoted PC-relative family identified from project-owned decoder
/// names, operand codecs, and properties.
/// </summary>
internal static class Aarch64SemanticInstructionClassifier
{
    public static Aarch64SemanticInstructionClassification? Classify(
        Aarch64Instruction instruction,
        Aarch64SemanticOperand? targetOperand)
    {
        var sourceName = instruction.SourceName ?? string.Empty;
        var targetCodec = targetOperand?.Codec ?? string.Empty;

        if (instruction.ControlFlow == Aarch64ControlFlowKind.DirectCall)
        {
            return new Aarch64SemanticInstructionClassification(
                PcRelativeExpressionKind.Call26,
                Scale: InstructionSize,
                IsPageRelative: false,
                IsLiteral: false);
        }

        if (instruction.ControlFlow == Aarch64ControlFlowKind.DirectBranch)
        {
            return new Aarch64SemanticInstructionClassification(
                PcRelativeExpressionKind.Branch26,
                Scale: InstructionSize,
                IsPageRelative: false,
                IsLiteral: false);
        }

        if (instruction.ControlFlow == Aarch64ControlFlowKind.ConditionalBranch)
        {
            var isTestBranch = string.Equals(targetCodec, "am_tbrcond", StringComparison.OrdinalIgnoreCase)
                || sourceName.StartsWith("TB", StringComparison.OrdinalIgnoreCase)
                || sourceName.StartsWith("TBN", StringComparison.OrdinalIgnoreCase);
            return new Aarch64SemanticInstructionClassification(
                isTestBranch
                    ? PcRelativeExpressionKind.TestBranch14
                    : PcRelativeExpressionKind.ConditionalBranch19,
                Scale: InstructionSize,
                IsPageRelative: false,
                IsLiteral: false);
        }

        if (instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
            && string.Equals(sourceName, "ADR", StringComparison.OrdinalIgnoreCase))
        {
            return new Aarch64SemanticInstructionClassification(
                PcRelativeExpressionKind.AdrPrelLo21,
                Scale: 1,
                IsPageRelative: false,
                IsLiteral: false);
        }

        if (instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
            && string.Equals(sourceName, "ADRP", StringComparison.OrdinalIgnoreCase))
        {
            return new Aarch64SemanticInstructionClassification(
                PcRelativeExpressionKind.AdrPrelPgHi21,
                Scale: 0x1000,
                IsPageRelative: true,
                IsLiteral: false);
        }

        var isLiteral = string.Equals(targetCodec, "am_ldrlit", StringComparison.OrdinalIgnoreCase)
            && instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
            && instruction.Properties.HasFlag(Aarch64InstructionProperties.Load);
        if (isLiteral)
        {
            return new Aarch64SemanticInstructionClassification(
                PcRelativeExpressionKind.Literal19,
                Scale: InstructionSize,
                IsPageRelative: false,
                IsLiteral: true);
        }

        return null;
    }

    private const int InstructionSize = sizeof(uint);
}

internal readonly record struct Aarch64SemanticInstructionClassification(
    PcRelativeExpressionKind Kind,
    int Scale,
    bool IsPageRelative,
    bool IsLiteral);
