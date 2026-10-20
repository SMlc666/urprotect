using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;

namespace UrProtect.Core.Application.Protection;

public sealed partial class FunctionProtectionService
{
    /// <summary>
    /// Re-emits the bounded external consumer from independently decoded source
    /// analysis at its final address. Publication uses the existing emitter's
    /// complete control flow and instruction offsets, never snapshot assertions,
    /// to distinguish the live dispatch from a self-consistent dead copy.
    /// </summary>
    internal bool TryReemitExternalConsumer(
        ElfFile source,
        Aarch64FunctionAnalysis analysis,
        ulong outputAddress,
        out byte[] bytes,
        out IReadOnlyDictionary<ulong, ulong> instructionOffsets)
    {
        bytes = Array.Empty<byte>();
        instructionOffsets = new Dictionary<ulong, ulong>();
        if (!analysis.IsComplete
            || analysis.ExternalJumpTableConsumerProofs.Count != 1
            || !TryBuildProtectedCode(
                source,
                new[] { analysis },
                new[] { ProtectionPass.ControlFlowFlattening },
                out var code,
                out _,
                out _,
                codeBaseOverride: outputAddress)
            || code.Patches.Count != 1)
        {
            return false;
        }

        bytes = code.Bytes;
        instructionOffsets = code.Patches[0].InstructionOutputOffsets;
        return true;
    }

    private bool TryBuildProtectedCode(
        ElfFile sourceFile,
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
                    sourceFile,
                    analysis,
                    analyses,
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

        var codeBase = codeBaseOverride ?? 0UL;
        var emitter = new CodeEmitter(codeBase, encoder);
        foreach (var builder in builders)
        {
            var resourcePlan = Aarch64RegisterResourcePlanner.Plan(
                builder.Source,
                decoder,
                hasFlattening,
                hasPermutation);
            var start = emitter.PositionAddress;
            if (!builder.Emit(emitter, encoder, diagnosticBag))
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

        if (!emitter.TryToBytes(out var emitted, out var emissionDiagnostic))
        {
            diagnosticBag.Add(emissionDiagnostic);
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
                builder.OutputSize,
                new Dictionary<ulong, ulong>(builder.InstructionOutputOffsets))).ToArray());
        results = resultList;
        diagnostics = diagnosticBag.ToArray();
        return true;
    }

    private bool TryBuildFunction(
        ElfFile sourceFile,
        Aarch64FunctionAnalysis analysis,
        IReadOnlyList<Aarch64FunctionAnalysis> selectedAnalyses,
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
        var tlsFacts = sourceFile.TlsMetadata.StaticRelocations
            .Concat(sourceFile.TlsMetadata.Dynamic.Relocations)
            .Where(fact => fact.Relocation.Offset >= analysis.Function.Value
                && analysis.Function.TryGetEnd(out var functionEnd)
                && fact.Relocation.Offset < functionEnd)
            .ToArray();
        var hasTlsIeAdrLd64 = Aarch64TlsInstructionSemantics.IsSupportedInitialExecAdrLd64EmitterSequence(
            analysis.Instructions,
            tlsFacts);
        var hasTlsIeLdGotPrel19 = Aarch64TlsInstructionSemantics.IsSupportedInitialExecLdGotPrel19EmitterSequence(
            analysis.Instructions,
            tlsFacts);
        var tlsIePcRelativeLoadAddress = tlsFacts.Length switch
        {
            1 when hasTlsIeLdGotPrel19 => tlsFacts[0].Relocation.Offset,
            2 when hasTlsIeAdrLd64 => tlsFacts
                .OrderBy(fact => fact.Relocation.Offset)
                .First()
                .Relocation.Offset,
            _ => (ulong?)null,
        };
        var tlsIeRegisterOffsetAccessAddress = hasTlsIeAdrLd64
            && tlsIePcRelativeLoadAddress is { } tlsIePairAddress
            && tlsIePairAddress <= ulong.MaxValue - (3UL * sizeof(uint))
            ? analysis.Instructions
                .Where(instruction => instruction.Address == tlsIePairAddress + (3UL * sizeof(uint)))
                .Where(instruction => instruction.Decode.Instruction?.Mnemonic.Equals("ldr", StringComparison.OrdinalIgnoreCase) == true)
                .Where(instruction => instruction.Decode.Instruction?.Operands.Any(operand =>
                    operand.Memory is { Index: not null, Offset: 0, WritesBack: false }) == true)
                .Select(instruction => (ulong?)instruction.Address)
                .FirstOrDefault()
            : null;
        var hasTlsLdShape = tlsFacts.Length == 4
            && tlsFacts[0].Relocation.Type == ElfConstants.RArm64TlsLdAdrPage21
            && tlsFacts[1].Relocation.Type == ElfConstants.RArm64TlsLdAddLo12Nc
            && tlsFacts[2].Relocation.Type == ElfConstants.RArm64TlsLdAddDtprelHi12
            && tlsFacts[3].Relocation.Type is
                ElfConstants.RArm64TlsLdAddDtprelLo12
                or ElfConstants.RArm64TlsLdAddDtprelLo12Nc;
        var hasTlsGdShape = tlsFacts.Length == 2
            && tlsFacts.Select(fact => fact.Relocation.Type).SequenceEqual(new[]
            {
                ElfConstants.RArm64TlsGdAdrPage21,
                ElfConstants.RArm64TlsGdAddLo12Nc,
            });
        var orderedTlsDescFacts = tlsFacts
            .OrderBy(fact => fact.Relocation.Offset)
            .ToArray();
        var hasTlsDescShape = orderedTlsDescFacts.Length == 4
            && orderedTlsDescFacts.Select(fact => fact.Relocation.Type).SequenceEqual(new[]
            {
                ElfConstants.RArm64TlsDescAdrPage21,
                ElfConstants.RArm64TlsDescLd64Lo12,
                ElfConstants.RArm64TlsDescAddLo12,
                ElfConstants.RArm64TlsDescCall,
            });
        TlsDescriptorOwnerBinding? tlsDescOwner = null;
        if (hasTlsDescShape
            && TlsStructuralAdapter.CreateImageModule(sourceFile).Value is { } tlsModule
            && TlsStructuralAdapter.ProjectSymbol(orderedTlsDescFacts[0].Symbol) is { } tlsSymbol)
        {
            var descriptorProjection = TlsStructuralAdapter.ProjectDescriptorOwner(
                sourceFile,
                tlsModule,
                tlsSymbol,
                orderedTlsDescFacts[0].Relocation.Addend);
            if (descriptorProjection.IsSuccess)
            {
                tlsDescOwner = descriptorProjection.Value;
            }
        }
        var tlsDescCoreInstructions = hasTlsDescShape
            ? analysis.Instructions
                .Where(instruction => instruction.Address >= orderedTlsDescFacts[0].Relocation.Offset)
                .TakeWhile((instruction, index) =>
                    index == 0
                    || analysis.Instructions
                        .Where(candidate => candidate.Address >= orderedTlsDescFacts[0].Relocation.Offset)
                        .Take(index)
                        .Last()
                        .Decode.Instruction?.ControlFlow != Aarch64ControlFlowKind.Return)
                .ToArray()
            : Array.Empty<Aarch64FunctionInstruction>();
        var supportsTlsDesc = hasTlsDescShape
            && tlsDescCoreInstructions.Length >= 8
            && tlsDescOwner is { } descriptorOwner
            && Aarch64TlsInstructionSemantics.IsSupportedTlsDescWordSequence(
                tlsDescCoreInstructions
                    .Select(instruction => instruction.Encoding)
                    .ToArray(),
                descriptorOwner,
                tlsDescCoreInstructions[0].Address);
        var tlsDescModuleAddress = supportsTlsDesc
            ? orderedTlsDescFacts[0].Relocation.Offset
            : (ulong?)null;
        var tlsDescCallAddress = supportsTlsDesc
            ? orderedTlsDescFacts[3].Relocation.Offset
            : (ulong?)null;
        var dynamicTlsShape = hasTlsLdShape || hasTlsGdShape;
        var exactResolverCallAddresses = dynamicTlsShape
            ? analysis.Instructions
                .Where(instruction => instruction.Decode.Instruction?.ControlFlow == Aarch64ControlFlowKind.DirectCall)
                .Where(instruction => TlsStructuralAdapter.IsExactResolverCall(
                    sourceFile,
                    new SemanticSourceRange(
                        new FileOffset(instruction.FileOffset),
                        new VirtualAddress(instruction.Address),
                        sizeof(uint))))
                .Select(instruction => instruction.Address)
                .Distinct()
                .ToArray()
            : Array.Empty<ulong>();
        var tlsLdResolverCallAddress = exactResolverCallAddresses.Length == 1
            ? exactResolverCallAddresses[0]
            : (ulong?)null;
        var stableDirectCallAddresses = new HashSet<ulong>();
        var tlsLdModuleAddressCandidates = tlsLdResolverCallAddress is not null
            ? tlsFacts
                .Where(fact => fact.Relocation.Type is ElfConstants.RArm64TlsLdAdrPage21 or ElfConstants.RArm64TlsGdAdrPage21)
                .Select(fact => fact.Relocation.Offset)
                .Take(2)
                .ToArray()
            : Array.Empty<ulong>();
        var tlsLdModuleAddress = tlsLdModuleAddressCandidates.Length == 1
            ? tlsLdModuleAddressCandidates[0]
            : (ulong?)null;
        var supportsTlsIePcRelativeLoad = tlsIePcRelativeLoadAddress is not null;
        var supportsTlsLdResolverCall = tlsLdResolverCallAddress is not null;
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
            var isTlsLdResolverCall = supportsTlsLdResolverCall
                && tlsLdResolverCallAddress is { } resolverCallAddress
                && instruction.Address == resolverCallAddress
                && controlFlow == Aarch64ControlFlowKind.DirectCall;
            var isTlsLdModuleAddress = tlsLdModuleAddress is { } moduleAddress
                && instruction.Address == moduleAddress
                && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
            var isTlsDescCall = tlsDescCallAddress is { } descriptorCallAddress
                && instruction.Address == descriptorCallAddress
                && controlFlow == Aarch64ControlFlowKind.IndirectBranch;
            var isResolvedIndirectTarget = analysis.IndirectTargetResolutions.Any(
                resolution => resolution.SourceAddress == instruction.Address)
                || analysis.JumpTableResolutions.Any(
                    resolution => resolution.SourceAddress == instruction.Address)
                || analysis.ExternalJumpTableConsumerProofs.Any(
                    proof => proof.BranchAddress == instruction.Address);
            var isRuntimeIndirectCall = analysis.RuntimeIndirectCallResolutions.Any(
                resolution => resolution.SourceAddress == instruction.Address);
            var isStaticFunctionPointerCall = analysis.StaticFunctionPointerCallResolutions.Any(
                resolution => resolution.SourceAddress == instruction.Address);
            var isJumpTableProducer = analysis.JumpTableResolutions.Any(
                resolution => resolution.ProducerAddresses.Contains(instruction.Address));
            var isAddressReferenceProducer = analysis.AddressReferences.Any(
                reference => reference.PageProducerAddress == instruction.Address);
            var isTlsDescModuleAddress = tlsDescModuleAddress is { } descriptorModuleAddress
                && instruction.Address == descriptorModuleAddress
                && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
            var isStableDirectCall = controlFlow == Aarch64ControlFlowKind.DirectCall
                && IsStableExternalDirectCall(sourceFile, instruction, selectedAnalyses);
            if (isStableDirectCall)
            {
                stableDirectCallAddresses.Add(instruction.Address);
            }

            if ((instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true
                    && !isTerminalBranch
                    && !(supportsTlsIePcRelativeLoad
                        && tlsIePcRelativeLoadAddress is { } pcRelativeLoadAddress
                        && instruction.Address == pcRelativeLoadAddress)
                    && !(tlsIeRegisterOffsetAccessAddress is { } registerOffsetAddress
                        && instruction.Address == registerOffsetAddress)
                    && !isTlsLdResolverCall
                    && !isTlsLdModuleAddress
                    && !isTlsDescModuleAddress
                    && !isJumpTableProducer
                    && !isAddressReferenceProducer
                    && !isStableDirectCall)
                || (controlFlow is Aarch64ControlFlowKind.DirectCall
                    && !isTlsLdResolverCall
                    && !isStableDirectCall)
                || (controlFlow == Aarch64ControlFlowKind.IndirectBranch
                    && !isTlsDescCall
                    && !isResolvedIndirectTarget
                    && !isRuntimeIndirectCall
                    && !isStaticFunctionPointerCall))
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

        if ((analysis.IndirectTargetResolutions.Count > 0
                || analysis.JumpTableResolutions.Count > 0
                || analysis.ExternalJumpTableConsumerProofs.Count > 0)
            && (!flatten || permutation))
        {
            var indirect = analysis.IndirectTargetResolutions.Count > 0
                ? analysis.IndirectTargetResolutions[0]
                : null;
            var sourceAddress = indirect?.SourceAddress
                ?? (analysis.JumpTableResolutions.Count > 0
                    ? analysis.JumpTableResolutions[0].SourceAddress
                    : (ulong?)null)
                ?? (analysis.ExternalJumpTableConsumerProofs.Count > 0
                    ? analysis.ExternalJumpTableConsumerProofs[0].BranchAddress
                    : (ulong?)null)
                ?? analysis.Function.Value;
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.IndirectTargetUnsupported,
                "The exact indirect-target slice requires control-flow flattening without register permutation so its producer chain can be retargeted through the shared dispatcher.",
                sourceAddress);
            return false;
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
            var isConditionalBranch = last.Decode.Instruction?.ControlFlow == Aarch64ControlFlowKind.ConditionalBranch;
            var isRegisterConditionalBranch = last.Decode.Instruction is { } conditionalInstruction
                && IsRegisterConditionalBranch(conditionalInstruction.Mnemonic);
            if (isConditionalBranch
                && !last.Decode.Instruction!.Properties.HasFlag(Aarch64InstructionProperties.ReadsNzcv)
                && !isRegisterConditionalBranch)
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionUnsupportedInstruction,
                    "The conditional branch is neither an NZCV-based b.cond nor a supported CBZ/CBNZ/TBZ/TBNZ form.",
                    last.FileOffset);
                return false;
            }

            if (isConditionalBranch
                && last.Decode.Instruction!.Properties.HasFlag(Aarch64InstructionProperties.ReadsNzcv)
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

        builder = new ProtectedFunctionBuilder(
            analysis,
            flatten,
            permutation,
            supportsTlsIePcRelativeLoad,
            tlsIePcRelativeLoadAddress,
            tlsLdResolverCallAddress,
            tlsLdModuleAddress,
            tlsDescCallAddress,
            tlsDescModuleAddress,
            stableDirectCallAddresses);
        return true;
    }

    private static bool IsRegisterConditionalBranch(string mnemonic) =>
        mnemonic.StartsWith("cbz", StringComparison.OrdinalIgnoreCase)
        || mnemonic.StartsWith("cbnz", StringComparison.OrdinalIgnoreCase)
        || mnemonic.StartsWith("tbz", StringComparison.OrdinalIgnoreCase)
        || mnemonic.StartsWith("tbnz", StringComparison.OrdinalIgnoreCase);

    private static bool IsStableExternalDirectCall(
        ElfFile sourceFile,
        Aarch64FunctionInstruction instruction,
        IReadOnlyList<Aarch64FunctionAnalysis> selectedAnalyses)
    {
        if (instruction.Decode.Instruction is not
            {
                ControlFlow: Aarch64ControlFlowKind.DirectCall,
                DirectTarget: { } target
            }
            || target % sizeof(uint) != 0
            || selectedAnalyses.Any(analysis =>
                analysis.Function.TryGetEnd(out var end)
                && target >= analysis.Function.Value
                && target < end))
        {
            return false;
        }

        var executableOwners = sourceFile.LoadMap.Segments.Count(segment =>
            segment.IsExecutable
            && segment.ContainsVirtualAddress(target, sizeof(uint)));
        return executableOwners == 1
            && sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(target),
                sizeof(uint),
                out _);
    }

    private sealed class ProtectedFunctionBuilder
    {
        public ProtectedFunctionBuilder(
            Aarch64FunctionAnalysis source,
            bool flatten,
            bool permutation,
            bool supportsTlsIePcRelativeLoad,
            ulong? tlsIePcRelativeLoadAddress,
            ulong? tlsLdResolverCallAddress,
            ulong? tlsLdModuleAddress,
            ulong? tlsDescCallAddress,
            ulong? tlsDescModuleAddress,
            IReadOnlySet<ulong> stableDirectCallAddresses)
        {
            Source = source;
            Flatten = flatten;
            Permutation = permutation;
            SupportsTlsIePcRelativeLoad = supportsTlsIePcRelativeLoad;
            TlsIePcRelativeLoadAddress = tlsIePcRelativeLoadAddress;
            TlsLdResolverCallAddress = tlsLdResolverCallAddress;
            TlsLdModuleAddress = tlsLdModuleAddress;
            TlsDescCallAddress = tlsDescCallAddress;
            TlsDescModuleAddress = tlsDescModuleAddress;
            StableDirectCallAddresses = new HashSet<ulong>(stableDirectCallAddresses);
        }

        public Aarch64FunctionAnalysis Source { get; }

        public bool Flatten { get; }

        public bool Permutation { get; }

        public bool SupportsTlsIePcRelativeLoad { get; }

        public ulong? TlsIePcRelativeLoadAddress { get; }
        public ulong? TlsLdResolverCallAddress { get; }
        public ulong? TlsLdModuleAddress { get; }
        public ulong? TlsDescCallAddress { get; }
        public ulong? TlsDescModuleAddress { get; }

        public HashSet<ulong> StableDirectCallAddresses { get; }

        public ulong OutputAddress { get; set; }

        public ulong OutputSize { get; set; }

        public Dictionary<ulong, ulong> InstructionOutputOffsets { get; } = new();

        public bool Emit(
            CodeEmitter emitter,
            IAarch64InstructionEncoder encoder,
            DiagnosticBag diagnostics)
        {
            OutputAddress = emitter.PositionAddress;
            var scratchRegister = Flatten && Permutation ? (byte)17 : (byte)16;
            if (Permutation
                && !EmitRegisterSwap(emitter, scratchRegister, diagnostics))
            {
                return false;
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
                        if (!EmitRegisterSwap(emitter, scratchRegister, diagnostics))
                        {
                            return false;
                        }
                    }

                    if (!EmitSourceInstruction(emitter, encoder, instruction, diagnostics))
                    {
                        return false;
                    }
                }

                return true;
            }

            var emittableBlocks = Source.Blocks
                .Where(block => !IsTrailingAlignmentPadding(block))
                .ToArray();
            var blockIds = emittableBlocks
                .Select((block, index) => (block.StartAddress, Id: index))
                .ToDictionary(value => value.StartAddress, value => value.Id);
            emitter.MarkLabel($"entry-{Source.Function.Value:X}");
            if (!EmitState(emitter, 0, diagnostics))
            {
                return false;
            }

            emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
            foreach (var block in emittableBlocks)
            {
                emitter.MarkLabel(BlockLabel(block.StartAddress));
                var last = block.Instructions[^1];
                for (var index = 0; index < block.Instructions.Count - 1; index++)
                {
                    var instruction = block.Instructions[index];
                    var isTlsLdResolverCall = TlsLdResolverCallAddress is { } resolverCallAddress
                        && instruction.Address == resolverCallAddress
                        && instruction.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.DirectCall;
                    var isTlsLdModuleAddress = TlsLdModuleAddress is { } moduleAddress
                        && instruction.Address == moduleAddress
                        && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
                    var isTlsDescCall = TlsDescCallAddress is { } descriptorCallAddress
                        && instruction.Address == descriptorCallAddress
                        && instruction.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.IndirectBranch;
                    var isResolvedIndirectTarget = Source.IndirectTargetResolutions.Any(
                        resolution => resolution.SourceAddress == instruction.Address)
                        || Source.JumpTableResolutions.Any(
                            resolution => resolution.SourceAddress == instruction.Address)
                        || Source.ExternalJumpTableConsumerProofs.Any(
                            proof => proof.BranchAddress == instruction.Address);
                    var isRuntimeIndirectCall = Source.RuntimeIndirectCallResolutions.Any(
                        resolution => resolution.SourceAddress == instruction.Address);
                    var isStaticFunctionPointerCall = Source.StaticFunctionPointerCallResolutions.Any(
                        resolution => resolution.SourceAddress == instruction.Address);
                    var isJumpTableProducer = Source.JumpTableResolutions.Any(
                        resolution => resolution.ProducerAddresses.Contains(instruction.Address));
                    var isAddressReferenceProducer = Source.AddressReferences.Any(
                        reference => reference.PageProducerAddress == instruction.Address);
                    var isTlsDescModuleAddress = TlsDescModuleAddress is { } descriptorModuleAddress
                        && instruction.Address == descriptorModuleAddress
                        && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
                    if ((instruction.Decode.Instruction!.ControlFlow != Aarch64ControlFlowKind.None
                            && !isTlsLdResolverCall
                            && !isTlsDescCall
                            && !isResolvedIndirectTarget
                            && !isRuntimeIndirectCall
                            && !isStaticFunctionPointerCall
                            && !StableDirectCallAddresses.Contains(instruction.Address))
                        || (instruction.Decode.Instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
                            && !(SupportsTlsIePcRelativeLoad
                                && TlsIePcRelativeLoadAddress is { } pcRelativeLoadAddress
                                && instruction.Address == pcRelativeLoadAddress)
                            && !isTlsLdResolverCall
                            && !isTlsLdModuleAddress
                            && !isTlsDescModuleAddress
                            && !isJumpTableProducer
                            && !isAddressReferenceProducer))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            "A non-terminal control-flow or PC-relative instruction is not supported.",
                            instruction.FileOffset);
                        return false;
                    }

                    if (!EmitSourceInstruction(emitter, encoder, instruction, diagnostics))
                    {
                        return false;
                    }
                }

                var isTlsLdResolverCallTerminator = TlsLdResolverCallAddress is { } tlsLdResolverAddress
                    && last.Address == tlsLdResolverAddress
                    && last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.DirectCall;
                var isTlsDescCallTerminator = TlsDescCallAddress is { } terminatorAddress
                    && last.Address == terminatorAddress
                    && last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.IndirectBranch;
                var isRuntimeIndirectCallTerminator = Source.RuntimeIndirectCallResolutions.Any(
                    resolution => resolution.SourceAddress == last.Address);
                var isStaticFunctionPointerCallTerminator = Source.StaticFunctionPointerCallResolutions.Any(
                    resolution => resolution.SourceAddress == last.Address);
                var isExternalJumpTableConsumerTerminator = Source.ExternalJumpTableConsumerProofs.Any(
                    proof => proof.BranchAddress == last.Address);
                var isStableDirectCallTerminator = StableDirectCallAddresses.Contains(last.Address);
                if (last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
                    && !isTlsDescCallTerminator
                    && !isRuntimeIndirectCallTerminator
                    && !isStaticFunctionPointerCallTerminator)
                {
                    InstructionOutputOffsets[last.Address] = emitter.PositionAddress - OutputAddress;
                    if (isExternalJumpTableConsumerTerminator)
                    {
                        // Provider addresses remain in the provider ELF identity domain.
                        // Keep the source BR and move only its consumer-owned GOT producer.
                        if (!EmitSourceInstruction(emitter, encoder, last, diagnostics))
                        {
                            return false;
                        }

                        continue;
                    }

                    if (Source.JumpTableResolutions.Any(
                            resolution => resolution.SourceAddress == last.Address))
                    {
                        // The source instructions already load and compute the selected
                        // table target. Keep the terminal BR so execution consumes the
                        // cloned, retargeted table rather than replacing its semantics
                        // with an immediate-comparison dispatcher.
                        if (!EmitSourceInstruction(emitter, encoder, last, diagnostics))
                        {
                            return false;
                        }

                        continue;
                    }

                    if (Source.IndirectTargetResolutions.FirstOrDefault(
                            resolution => resolution.SourceAddress == last.Address) is { } indirectResolution)
                    {
                        if (!blockIds.TryGetValue(indirectResolution.TargetAddress.Value, out var targetBlockId)
                            || !EmitState(emitter, checked((uint)targetBlockId), diagnostics))
                        {
                            diagnostics.Error(
                                DiagnosticCode.IndirectTargetUnresolved,
                                "The resolved indirect target is not a selected-function basic-block boundary.",
                                last.FileOffset);
                            return false;
                        }

                        emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
                        continue;
                    }
                }

                if (isTlsLdResolverCallTerminator
                    || isTlsDescCallTerminator
                    || isRuntimeIndirectCallTerminator
                    || isStaticFunctionPointerCallTerminator
                    || isStableDirectCallTerminator)
                {
                    var fallthrough = block.Successors.SingleOrDefault(edge =>
                        edge.Kind == Aarch64ControlFlowEdgeKind.Fallthrough);
                    if (fallthrough?.TargetAddress is not { } fallthroughTarget
                        || !blockIds.ContainsKey(fallthroughTarget))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            isTlsLdResolverCallTerminator
                                ? "The TLSLD resolver call does not have one in-function fallthrough successor."
                                : isTlsDescCallTerminator
                                    ? "The TLSDESC resolver call does not have one in-function fallthrough successor."
                                    : isRuntimeIndirectCallTerminator || isStaticFunctionPointerCallTerminator
                                    ? "The validated indirect call does not have one in-function fallthrough successor."
                                    : "The direct call does not have one in-function fallthrough successor.",
                            last.FileOffset);
                        return false;
                    }

                    if (!EmitSourceInstruction(emitter, encoder, last, diagnostics))
                    {
                        return false;
                    }

                    // Validated indirect calls return to the next emitted word.
                    // Keep their proven fallthrough block adjacent.
                    continue;
                }

                if (last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.Return)
                {
                    if (Permutation
                        && !EmitRegisterSwap(emitter, scratchRegister, diagnostics))
                    {
                        return false;
                    }

                    if (!EmitSourceInstruction(emitter, encoder, last, diagnostics))
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
                    InstructionOutputOffsets[last.Address] = emitter.PositionAddress - OutputAddress;
                    var trueLabel = $"set-{Source.Function.Value:X}-{blockIds[trueEdge.TargetAddress!.Value]}";
                    if (last.Decode.Instruction.Properties.HasFlag(Aarch64InstructionProperties.ReadsNzcv))
                    {
                        emitter.EmitConditionalBranch((int)(last.Encoding & 0xF), trueLabel);
                    }
                    else if (last.Decode.Instruction is { } conditionalInstruction
                        && IsRegisterConditionalBranch(conditionalInstruction.Mnemonic))
                    {
                        var branchEncoding = last.Encoding;
                        if (Permutation)
                        {
                            var permuted = encoder.TryPermuteGeneralRegisters(
                                branchEncoding,
                                last.Address,
                                RegisterPermutation);
                            if (!permuted.IsSuccess)
                            {
                                diagnostics.Error(
                                    DiagnosticCode.ProtectionUnsupportedInstruction,
                                    permuted.Diagnostic,
                                    last.FileOffset);
                                return false;
                            }

                            branchEncoding = permuted.Encoding;
                        }

                        var family = conditionalInstruction.Mnemonic.StartsWith("tb", StringComparison.OrdinalIgnoreCase)
                            ? Aarch64InstructionEncodingFamily.TestBranch14
                            : Aarch64InstructionEncodingFamily.ConditionalBranch19;
                        emitter.EmitSourceConditionalBranch(
                            branchEncoding,
                            last.Address,
                            family,
                            trueLabel);
                    }
                    else
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            "A flattened conditional branch does not match its proved branch semantic domain.",
                            last.FileOffset);
                        return false;
                    }

                    if (!EmitState(emitter, checked((uint)blockIds[falseEdge.TargetAddress!.Value]), diagnostics))
                    {
                        return false;
                    }

                    emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
                    emitter.MarkLabel(trueLabel);
                    if (!EmitState(emitter, checked((uint)blockIds[trueEdge.TargetAddress!.Value]), diagnostics))
                    {
                        return false;
                    }

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

                InstructionOutputOffsets[last.Address] = emitter.PositionAddress - OutputAddress;
                if (!EmitState(emitter, checked((uint)blockIds[nextTarget]), diagnostics))
                {
                    return false;
                }

                emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
            }

            emitter.MarkLabel($"dispatcher-{Source.Function.Value:X}");
            foreach (var block in emittableBlocks)
            {
                if (!emitter.TryEmitCreate(new Aarch64InstructionBuildRequest(
                        Aarch64InstructionEncodingFamily.CompareImmediate,
                        emitter.PositionAddress,
                        checked((uint)blockIds[block.StartAddress]),
                        BaseRegister: StateRegister,
                        DestinationWidth: 32),
                    diagnostics))
                {
                    return false;
                }

                emitter.EmitConditionalBranch(0, BlockLabel(block.StartAddress));
            }

            if (!emitter.TryEmitCreate(new Aarch64InstructionBuildRequest(
                    Aarch64InstructionEncodingFamily.Return,
                    emitter.PositionAddress,
                    0),
                diagnostics))
            {
                return false;
            }

            foreach (var paddingBlock in Source.Blocks.Where(IsTrailingAlignmentPadding))
            {
                foreach (var paddingInstruction in paddingBlock.Instructions)
                {
                    if (!EmitSourceInstruction(emitter, encoder, paddingInstruction, diagnostics))
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        private bool EmitSourceInstruction(
            CodeEmitter emitter,
            IAarch64InstructionEncoder encoder,
            Aarch64FunctionInstruction instruction,
            DiagnosticBag diagnostics)
        {
            InstructionOutputOffsets[instruction.Address] = emitter.PositionAddress - OutputAddress;
            if (StableDirectCallAddresses.Contains(instruction.Address))
            {
                if (instruction.Decode.Instruction?.DirectTarget is not { } callTarget)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticTargetUnresolved,
                        "A selected direct call lost its decoded source target.",
                        instruction.FileOffset);
                    return false;
                }

                var sourceEncoding = instruction.Encoding;
                if (Permutation)
                {
                    var permuted = encoder.TryPermuteGeneralRegisters(
                        sourceEncoding,
                        instruction.Address,
                        RegisterPermutation);
                    if (!permuted.IsSuccess)
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            permuted.Diagnostic,
                            instruction.FileOffset);
                        return false;
                    }

                    sourceEncoding = permuted.Encoding;
                }

                var encodedCall = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                    sourceEncoding,
                    instruction.Address,
                    emitter.PositionAddress,
                    Aarch64InstructionEncodingFamily.Call26,
                    callTarget));
                if (!encodedCall.IsSuccess)
                {
                    diagnostics.Error(
                        DiagnosticCode.ProtectionUnsupportedInstruction,
                        encodedCall.Diagnostic,
                        instruction.FileOffset);
                    return false;
                }

                emitter.EmitWord(encodedCall.Encoding);
                return true;
            }

            var addressReferencePages = Source.AddressReferences
                .Where(reference => reference.PageProducerAddress == instruction.Address)
                .Select(reference => reference.PageAddress.Value)
                .Distinct()
                .ToArray();
            var staticFunctionPointerTargets = Source.StaticFunctionPointerCallResolutions
                .Where(resolution => resolution.ProducerAddresses.Count > 0
                    && resolution.ProducerAddresses[0] == instruction.Address)
                .Select(resolution => resolution.TargetAddress)
                .Distinct()
                .ToArray();
            if (addressReferencePages.Length > 0 || staticFunctionPointerTargets.Length > 0)
            {
                if (addressReferencePages.Length != 1
                    || staticFunctionPointerTargets.Length > 1
                    || instruction.Decode.Instruction?.Mnemonic.Equals("adrp", StringComparison.OrdinalIgnoreCase) != true
                    || staticFunctionPointerTargets.Length == 1
                        && (staticFunctionPointerTargets[0] & ~0xFFFUL) != addressReferencePages[0])
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMalformed,
                        "One selected-function ADRP producer maps to conflicting decoded page targets.",
                        instruction.FileOffset);
                    return false;
                }

                var sourceEncoding = instruction.Encoding;
                if (Permutation)
                {
                    var permuted = encoder.TryPermuteGeneralRegisters(
                        sourceEncoding,
                        instruction.Address,
                        RegisterPermutation);
                    if (!permuted.IsSuccess)
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            permuted.Diagnostic,
                            instruction.FileOffset);
                        return false;
                    }

                    sourceEncoding = permuted.Encoding;
                }

                var encodedPage = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                    sourceEncoding,
                    instruction.Address,
                    emitter.PositionAddress,
                    Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
                    staticFunctionPointerTargets.Length == 1
                        ? staticFunctionPointerTargets[0]
                        : addressReferencePages[0]));
                if (!encodedPage.IsSuccess)
                {
                    diagnostics.Error(
                        DiagnosticCode.IndirectTargetUnresolved,
                        encodedPage.Diagnostic,
                        instruction.FileOffset);
                    return false;
                }

                emitter.EmitWord(encodedPage.Encoding);
                return true;
            }

            var jumpTableTargetBaseProducer = Source.JumpTableResolutions
                .FirstOrDefault(resolution => resolution.ProducerAddresses.Contains(instruction.Address));
            if (jumpTableTargetBaseProducer is not null
                && string.Equals(
                    instruction.Decode.Instruction?.Mnemonic,
                    "adr",
                    StringComparison.OrdinalIgnoreCase))
            {
                if (Flatten)
                {
                    if (!Source.Blocks.Any(block =>
                            block.StartAddress == jumpTableTargetBaseProducer.TargetBaseAddress.Value
                            && !IsTrailingAlignmentPadding(block)))
                    {
                        diagnostics.Error(
                            DiagnosticCode.IndirectTargetUnresolved,
                            "The jump-table target base has no emitted dispatcher block.",
                            instruction.FileOffset);
                        return false;
                    }

                    emitter.EmitSourceAdr(
                        instruction.Encoding,
                        instruction.Address,
                        BlockLabel(jumpTableTargetBaseProducer.TargetBaseAddress.Value),
                        null);
                }
                else
                {
                    var targetBase = jumpTableTargetBaseProducer.TargetBaseAddress.Value;
                    if (targetBase < Source.Function.Value
                        || targetBase - Source.Function.Value >= Source.Function.Size
                        || OutputAddress > ulong.MaxValue - (targetBase - Source.Function.Value))
                    {
                        diagnostics.Error(
                            DiagnosticCode.IndirectTargetUnresolved,
                            "The jump-table target base is outside the selected function output range.",
                            instruction.FileOffset);
                        return false;
                    }

                    emitter.EmitSourceAdr(
                        instruction.Encoding,
                        instruction.Address,
                        null,
                        OutputAddress + (targetBase - Source.Function.Value));
                }

                return true;
            }

            if (!Permutation)
            {
                var table = Source.JumpTableResolutions
                    .FirstOrDefault(resolution => resolution.ProducerAddresses.Contains(instruction.Address));
                if (table is not null
                    && instruction.Decode.Instruction is { } tableInstruction
                    && tableInstruction.Mnemonic is "adrp" or "adr")
                {
                    var family = tableInstruction.Mnemonic.Equals("adrp", StringComparison.OrdinalIgnoreCase)
                        ? Aarch64InstructionEncodingFamily.AdrPrelPgHi21
                        : Aarch64InstructionEncodingFamily.AdrPrelLo21;
                    if (family == Aarch64InstructionEncodingFamily.AdrPrelLo21)
                    {
                        if (Flatten)
                        {
                            if (!Source.Blocks.Any(block =>
                                    block.StartAddress == table.TargetBaseAddress.Value
                                    && !IsTrailingAlignmentPadding(block)))
                            {
                                diagnostics.Error(
                                    DiagnosticCode.IndirectTargetUnresolved,
                                    "The jump-table target base has no emitted dispatcher block.",
                                    instruction.FileOffset);
                                return false;
                            }

                            emitter.EmitSourceAdr(
                                instruction.Encoding,
                                instruction.Address,
                                BlockLabel(table.TargetBaseAddress.Value),
                                null);
                        }
                        else
                        {
                            if (table.TargetBaseAddress.Value < Source.Function.Value
                                || table.TargetBaseAddress.Value - Source.Function.Value >= Source.Function.Size
                                || OutputAddress > ulong.MaxValue - (table.TargetBaseAddress.Value - Source.Function.Value))
                            {
                                diagnostics.Error(
                                    DiagnosticCode.IndirectTargetUnresolved,
                                    "The jump-table target base is outside the selected function output range.",
                                    instruction.FileOffset);
                                return false;
                            }

                            emitter.EmitSourceAdr(
                                instruction.Encoding,
                                instruction.Address,
                                null,
                                OutputAddress + (table.TargetBaseAddress.Value - Source.Function.Value));
                        }

                        return true;
                    }

                    var target = table.TableBase.Value;
                    var encoded = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                        instruction.Encoding,
                        instruction.Address,
                        emitter.PositionAddress,
                        family,
                        target));
                    if (!encoded.IsSuccess)
                    {
                        diagnostics.Error(
                            DiagnosticCode.IndirectTargetUnsupported,
                            encoded.Diagnostic,
                            instruction.FileOffset);
                        return false;
                    }

                    emitter.EmitWord(encoded.Encoding);
                    return true;
                }

                var producer = Source.IndirectTargetResolutions
                    .FirstOrDefault(resolution => resolution.ProducerAddresses.Contains(instruction.Address));
                if (producer is not null)
                {
                    var decoded = instruction.Decode.Instruction!;
                    var immediate = decoded.Operands
                        .Where(operand => operand.Kind == Aarch64OperandKind.Immediate)
                        .Select(operand => operand.Immediate)
                        .LastOrDefault();
                    if (immediate is null
                        || immediate.Value is < 0 or > 48
                        || immediate.Value % 16 != 0
                        || !emitter.EmitMoveWideTarget(
                            instruction,
                            producer.TargetAddress.Value,
                            Flatten ? BlockLabel(producer.TargetAddress.Value) : null,
                            Flatten
                                ? null
                                : checked(OutputAddress
                                    + (producer.TargetAddress.Value - Source.Function.Value)),
                            checked((int)immediate.Value),
                            decoded.Mnemonic.StartsWith("MOVN", StringComparison.OrdinalIgnoreCase),
                            diagnostics))
                    {
                        diagnostics.Error(
                            DiagnosticCode.IndirectTargetUnsupported,
                            "The exact indirect producer chain is not encodable at its relocated output address.",
                            instruction.FileOffset);
                        return false;
                    }

                    return true;
                }

                emitter.EmitWord(instruction.Encoding);
                return true;
            }

            var result = encoder.TryPermuteGeneralRegisters(
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

        private static bool IsTrailingAlignmentPadding(Aarch64BasicBlock block) =>
            block.Successors.Count == 0
            && block.Instructions.Count > 0
            && block.Instructions.All(instruction => instruction.Encoding == 0xD503201Fu);

        private static bool EmitState(
            CodeEmitter emitter,
            uint state,
            DiagnosticBag diagnostics) => emitter.TryEmitCreate(
                new Aarch64InstructionBuildRequest(
                    Aarch64InstructionEncodingFamily.MoveWideImmediate,
                    emitter.PositionAddress,
                    state,
                    DestinationRegister: StateRegister,
                    DestinationWidth: 32),
                diagnostics);

        private static bool EmitRegisterSwap(
            CodeEmitter emitter,
            byte scratchRegister,
            DiagnosticBag diagnostics) =>
            emitter.TryEmitCreate(
                    new Aarch64InstructionBuildRequest(
                        Aarch64InstructionEncodingFamily.MoveRegister,
                        emitter.PositionAddress,
                        0,
                        DestinationRegister: scratchRegister,
                        DestinationWidth: 64,
                        SourceRegister: 9),
                    diagnostics)
                && emitter.TryEmitCreate(
                    new Aarch64InstructionBuildRequest(
                        Aarch64InstructionEncodingFamily.MoveRegister,
                        emitter.PositionAddress,
                        0,
                        DestinationRegister: 9,
                        DestinationWidth: 64,
                        SourceRegister: 10),
                    diagnostics)
                && emitter.TryEmitCreate(
                    new Aarch64InstructionBuildRequest(
                        Aarch64InstructionEncodingFamily.MoveRegister,
                        emitter.PositionAddress,
                        0,
                        DestinationRegister: 10,
                        DestinationWidth: 64,
                        SourceRegister: scratchRegister),
                    diagnostics);

        private static string BlockLabel(ulong address) => $"block-{address:X}";
    }

    private sealed record ProtectedCode(
        ulong VirtualAddress,
        byte[] Bytes,
        IReadOnlyList<FunctionPatch> Patches);

    private readonly record struct FunctionPatch(
        ulong SourceAddress,
        ulong TargetAddress,
        ulong SourceSize,
        ulong OutputSize,
        IReadOnlyDictionary<ulong, ulong> InstructionOutputOffsets);

    private sealed class CodeEmitter
    {
        private readonly ulong baseAddress;
        private readonly IAarch64InstructionEncoder encoder;
        private readonly List<uint> words = new();
        private readonly Dictionary<string, int> labels = new(StringComparer.Ordinal);
        private readonly List<BranchPatch> branches = new();
        private readonly List<SourceConditionalPatch> sourceConditionalPatches = new();
        private readonly List<MoveWidePatch> moveWidePatches = new();
        private readonly List<SourceAdrPatch> sourceAdrPatches = new();

        public CodeEmitter(ulong baseAddress, IAarch64InstructionEncoder encoder)
        {
            this.baseAddress = baseAddress;
            this.encoder = encoder ?? throw new ArgumentNullException(nameof(encoder));
        }

        public ulong PositionAddress => baseAddress + checked((ulong)words.Count * sizeof(uint));

        public void MarkLabel(string label) => labels[label] = words.Count;

        public void EmitWord(uint word) => words.Add(word);

        public bool TryEmitCreate(
            Aarch64InstructionBuildRequest request,
            DiagnosticBag diagnostics)
        {
            var result = encoder.TryCreate(request);
            if (!result.IsSuccess)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectionUnsupportedInstruction,
                    $"The AArch64 encoder rejected generated {request.Family}: {result.Diagnostic}");
                return false;
            }

            words.Add(result.Encoding);
            return true;
        }

        public void EmitBranch(string label)
        {
            branches.Add(new BranchPatch(words.Count, label, false, 0));
            words.Add(0);
        }

        public void EmitConditionalBranch(int condition, string label)
        {
            if ((uint)condition > 15)
            {
                throw new ArgumentOutOfRangeException(nameof(condition));
            }

            branches.Add(new BranchPatch(words.Count, label, true, condition));
            words.Add(0);
        }

        public void EmitSourceAdr(
            uint sourceEncoding,
            ulong sourceAddress,
            string? targetLabel,
            ulong? fixedTargetAddress)
        {
            if ((targetLabel is null) == (fixedTargetAddress is null))
            {
                throw new ArgumentException("An ADR patch requires exactly one output target binding.");
            }

            sourceAdrPatches.Add(new SourceAdrPatch(
                words.Count,
                sourceEncoding,
                sourceAddress,
                targetLabel,
                fixedTargetAddress));
            words.Add(sourceEncoding);
        }

        public void EmitSourceConditionalBranch(
            uint sourceEncoding,
            ulong sourceAddress,
            Aarch64InstructionEncodingFamily family,
            string label)
        {
            if (family is not (Aarch64InstructionEncodingFamily.ConditionalBranch19
                or Aarch64InstructionEncodingFamily.TestBranch14))
            {
                throw new ArgumentOutOfRangeException(nameof(family));
            }

            sourceConditionalPatches.Add(new SourceConditionalPatch(
                words.Count,
                label,
                sourceEncoding,
                sourceAddress,
                family));
            words.Add(0);
        }

        public bool EmitMoveWideTarget(
            Aarch64FunctionInstruction instruction,
            ulong targetAddress,
            string? targetLabel,
            ulong? fixedTargetAddress,
            int immediateShift,
            bool complementImmediate,
            DiagnosticBag diagnostics)
        {
            if (targetLabel is null && fixedTargetAddress is null)
            {
                diagnostics.Error(
                    DiagnosticCode.IndirectTargetUnresolved,
                    "An indirect move-wide producer has no output target binding.",
                    instruction.FileOffset);
                return false;
            }

            moveWidePatches.Add(new MoveWidePatch(
                words.Count,
                instruction.Encoding,
                instruction.Address,
                targetLabel,
                fixedTargetAddress,
                immediateShift,
                complementImmediate));
            words.Add(instruction.Encoding);
            return true;
        }

        public bool TryToBytes(out byte[] bytes, out Diagnostic diagnostic)
        {
            bytes = Array.Empty<byte>();
            diagnostic = default;
            try
            {
                foreach (var patch in branches)
                {
                    if (!labels.TryGetValue(patch.Label, out var targetIndex))
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            $"Missing protected-code label '{patch.Label}'.");
                        return false;
                    }

                    var source = baseAddress + checked((ulong)patch.Index * sizeof(uint));
                    var target = baseAddress + checked((ulong)targetIndex * sizeof(uint));
                    var family = patch.Conditional
                        ? Aarch64InstructionEncodingFamily.ConditionalBranch19
                        : Aarch64InstructionEncodingFamily.Branch26;
                    var result = encoder.TryCreate(new Aarch64InstructionBuildRequest(
                        family,
                        source,
                        target,
                        ConditionCode: patch.Condition));
                    if (!result.IsSuccess)
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.ProtectionBranchOutOfRange,
                            $"The AArch64 encoder rejected protected-code {family}: {result.Diagnostic}",
                            source);
                        return false;
                    }

                    words[patch.Index] = result.Encoding;
                }

                foreach (var patch in sourceConditionalPatches)
                {
                    if (!labels.TryGetValue(patch.Label, out var targetIndex))
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            $"Missing protected-code label '{patch.Label}'.");
                        return false;
                    }

                    var outputAddress = baseAddress + checked((ulong)patch.Index * sizeof(uint));
                    var targetAddress = baseAddress + checked((ulong)targetIndex * sizeof(uint));
                    var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                        patch.SourceEncoding,
                        patch.SourceAddress,
                        outputAddress,
                        patch.Family,
                        targetAddress));
                    if (!result.IsSuccess)
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.ProtectionBranchOutOfRange,
                            $"The AArch64 encoder rejected protected-code {patch.Family}: {result.Diagnostic}",
                            outputAddress);
                        return false;
                    }

                    words[patch.Index] = result.Encoding;
                }

                foreach (var patch in sourceAdrPatches)
                {
                    ulong target;
                    if (patch.TargetLabel is { } targetLabel)
                    {
                        if (!labels.TryGetValue(targetLabel, out var targetIndex))
                        {
                            diagnostic = new Diagnostic(
                                DiagnosticSeverity.Error,
                                DiagnosticCode.IndirectTargetUnresolved,
                                $"Missing ADR target label '{targetLabel}'.");
                            return false;
                        }

                        target = baseAddress + checked((ulong)targetIndex * sizeof(uint));
                    }
                    else if (patch.FixedTargetAddress is { } fixedTarget)
                    {
                        target = fixedTarget;
                    }
                    else
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.IndirectTargetUnresolved,
                            "An ADR patch has no output target binding.");
                        return false;
                    }

                    var outputAddress = baseAddress + checked((ulong)patch.Index * sizeof(uint));
                    var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                        patch.SourceEncoding,
                        patch.SourceAddress,
                        outputAddress,
                        Aarch64InstructionEncodingFamily.AdrPrelLo21,
                        target));
                    if (!result.IsSuccess)
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.IndirectTargetUnsupported,
                            result.Diagnostic,
                            outputAddress);
                        return false;
                    }

                    words[patch.Index] = result.Encoding;
                }

                foreach (var patch in moveWidePatches)
                {
                    ulong target;
                    if (patch.TargetLabel is { } targetLabel)
                    {
                        if (!labels.TryGetValue(targetLabel, out var targetIndex))
                        {
                            diagnostic = new Diagnostic(
                                DiagnosticSeverity.Error,
                                DiagnosticCode.IndirectTargetUnresolved,
                                $"Missing indirect target label '{targetLabel}'.");
                            return false;
                        }

                        target = baseAddress + checked((ulong)targetIndex * sizeof(uint));
                    }
                    else if (patch.FixedTargetAddress is { } fixedTarget)
                    {
                        target = fixedTarget;
                    }
                    else
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.IndirectTargetUnresolved,
                            "An indirect target patch has no output address.");
                        return false;
                    }

                    var halfword = (target >> patch.ImmediateShift) & ushort.MaxValue;
                    if (patch.ComplementImmediate)
                    {
                        halfword = (~halfword) & ushort.MaxValue;
                    }

                    var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                        patch.SourceEncoding,
                        patch.SourceAddress,
                        baseAddress + checked((ulong)patch.Index * sizeof(uint)),
                        Aarch64InstructionEncodingFamily.MoveWideImmediate,
                        halfword,
                        RegisterWidth: 64));
                    if (!result.IsSuccess)
                    {
                        diagnostic = new Diagnostic(
                            DiagnosticSeverity.Error,
                            DiagnosticCode.IndirectTargetUnsupported,
                            result.Diagnostic,
                            patch.SourceAddress);
                        return false;
                    }

                    words[patch.Index] = result.Encoding;
                }

                bytes = new byte[checked(words.Count * sizeof(uint))];
                for (var index = 0; index < words.Count; index++)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(
                        bytes.AsSpan(index * sizeof(uint)),
                        words[index]);
                }

                return true;
            }
            catch (Exception exception) when (exception is OverflowException or ArgumentOutOfRangeException)
            {
                diagnostic = new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectionBranchOutOfRange,
                    exception.Message);
                return false;
            }
        }

        private readonly record struct BranchPatch(
            int Index,
            string Label,
            bool Conditional,
            int Condition);

        private readonly record struct SourceAdrPatch(
            int Index,
            uint SourceEncoding,
            ulong SourceAddress,
            string? TargetLabel,
            ulong? FixedTargetAddress);

        private readonly record struct SourceConditionalPatch(
            int Index,
            string Label,
            uint SourceEncoding,
            ulong SourceAddress,
            Aarch64InstructionEncodingFamily Family);

        private readonly record struct MoveWidePatch(
            int Index,
            uint SourceEncoding,
            ulong SourceAddress,
            string? TargetLabel,
            ulong? FixedTargetAddress,
            int ImmediateShift,
            bool ComplementImmediate);
    }
}
