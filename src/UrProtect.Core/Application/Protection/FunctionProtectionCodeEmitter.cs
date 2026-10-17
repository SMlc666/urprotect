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
            && tlsFacts.Select(fact => fact.Relocation.Type).SequenceEqual(new[]
            {
                ElfConstants.RArm64TlsLdAdrPage21,
                ElfConstants.RArm64TlsLdAddLo12Nc,
                ElfConstants.RArm64TlsLdAddDtprelHi12,
                ElfConstants.RArm64TlsLdAddDtprelLo12Nc,
            });
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
        var supportsTlsDesc = hasTlsDescShape
            && tlsDescOwner is { } descriptorOwner
            && Aarch64TlsInstructionSemantics.IsSupportedTlsDescWordSequence(
                analysis.Instructions.Select(instruction => instruction.Encoding).ToArray(),
                descriptorOwner,
                analysis.Function.Value);
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
                    resolution => resolution.SourceAddress == instruction.Address);
            var isRuntimeIndirectCall = analysis.RuntimeIndirectCallResolutions.Any(
                resolution => resolution.SourceAddress == instruction.Address);
            var isJumpTableProducer = analysis.JumpTableResolutions.Any(
                resolution => resolution.ProducerAddresses.Contains(instruction.Address));
            var isTlsDescModuleAddress = tlsDescModuleAddress is { } descriptorModuleAddress
                && instruction.Address == descriptorModuleAddress
                && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
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
                    && !isJumpTableProducer)
                || (controlFlow is Aarch64ControlFlowKind.DirectCall && !isTlsLdResolverCall)
                || (controlFlow == Aarch64ControlFlowKind.IndirectBranch
                    && !isTlsDescCall
                    && !isResolvedIndirectTarget
                    && !isRuntimeIndirectCall))
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
                || analysis.JumpTableResolutions.Count > 0)
            && (!flatten || permutation))
        {
            var indirect = analysis.IndirectTargetResolutions.Count > 0
                ? analysis.IndirectTargetResolutions[0]
                : null;
            var sourceAddress = indirect?.SourceAddress
                ?? analysis.JumpTableResolutions[0].SourceAddress;
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

        builder = new ProtectedFunctionBuilder(
            analysis,
            flatten,
            permutation,
            supportsTlsIePcRelativeLoad,
            tlsIePcRelativeLoadAddress,
            tlsLdResolverCallAddress,
            tlsLdModuleAddress,
            tlsDescCallAddress,
            tlsDescModuleAddress);
        return true;
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
            ulong? tlsDescModuleAddress)
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
                            resolution => resolution.SourceAddress == instruction.Address);
                    var isRuntimeIndirectCall = Source.RuntimeIndirectCallResolutions.Any(
                        resolution => resolution.SourceAddress == instruction.Address);
                    var isJumpTableProducer = Source.JumpTableResolutions.Any(
                        resolution => resolution.ProducerAddresses.Contains(instruction.Address));
                    var isTlsDescModuleAddress = TlsDescModuleAddress is { } descriptorModuleAddress
                        && instruction.Address == descriptorModuleAddress
                        && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
                    if ((instruction.Decode.Instruction!.ControlFlow != Aarch64ControlFlowKind.None
                            && !isTlsLdResolverCall
                            && !isTlsDescCall
                            && !isResolvedIndirectTarget
                            && !isRuntimeIndirectCall)
                        || (instruction.Decode.Instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
                            && !(SupportsTlsIePcRelativeLoad
                                && TlsIePcRelativeLoadAddress is { } pcRelativeLoadAddress
                                && instruction.Address == pcRelativeLoadAddress)
                            && !isTlsLdResolverCall
                            && !isTlsLdModuleAddress
                            && !isTlsDescModuleAddress
                            && !isJumpTableProducer))
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

                var isTlsDescCallTerminator = TlsDescCallAddress is { } terminatorAddress
                    && last.Address == terminatorAddress
                    && last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.IndirectBranch;
                var isRuntimeIndirectCallTerminator = Source.RuntimeIndirectCallResolutions.Any(
                    resolution => resolution.SourceAddress == last.Address);
                if (last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
                    && !isTlsDescCallTerminator
                    && !isRuntimeIndirectCallTerminator)
                {
                    InstructionOutputOffsets[last.Address] = emitter.PositionAddress - OutputAddress;
                    if (Source.JumpTableResolutions.FirstOrDefault(
                            resolution => resolution.SourceAddress == last.Address) is { } jumpTable)
                    {
                        if (!EmitJumpTableDispatch(
                                emitter,
                                jumpTable,
                                blockIds,
                                diagnostics))
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

                if (isTlsDescCallTerminator || isRuntimeIndirectCallTerminator)
                {
                    var fallthrough = block.Successors.SingleOrDefault(edge =>
                        edge.Kind == Aarch64ControlFlowEdgeKind.Fallthrough);
                    if (fallthrough?.TargetAddress is not { } fallthroughTarget
                        || !blockIds.ContainsKey(fallthroughTarget))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            isTlsDescCallTerminator
                                ? "The TLSDESC resolver call does not have one in-function fallthrough successor."
                                : "The runtime indirect call does not have one in-function fallthrough successor.",
                            last.FileOffset);
                        return false;
                    }

                    if (!EmitSourceInstruction(emitter, encoder, last, diagnostics))
                    {
                        return false;
                    }

                    // Runtime-owned calls return to the next emitted word. Keep
                    // their proven fallthrough block adjacent.
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
                    emitter.EmitConditionalBranch((int)(last.Encoding & 0xF), trueLabel);
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

                // Direct B branches are replaced by the state transition;
                // bind their semantic instruction identity to that emitted
                // transition. A plain fallthrough block instead retains its
                // *last instruction* before the transition: otherwise its
                // register/memory effects would be silently discarded.
                var lastFlow = last.Decode.Instruction.ControlFlow;
                if (lastFlow == Aarch64ControlFlowKind.None)
                {
                    if (!EmitSourceInstruction(emitter, encoder, last, diagnostics))
                    {
                        return false;
                    }
                }
                else if (lastFlow == Aarch64ControlFlowKind.DirectBranch)
                {
                    InstructionOutputOffsets[last.Address] =
                        emitter.PositionAddress - OutputAddress;
                }
                else
                {
                    diagnostics.Error(
                        DiagnosticCode.ProtectionUnsupportedInstruction,
                        "The last instruction requires an unsupported direct-call or indirect-flow rewrite.",
                        last.FileOffset);
                    return false;
                }

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
                    var target = family == Aarch64InstructionEncodingFamily.AdrPrelPgHi21
                        ? table.TableBase.Value
                        : table.TargetBaseAddress.Value;
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

        private bool EmitJumpTableDispatch(
            CodeEmitter emitter,
            Aarch64JumpTableResolution table,
            Dictionary<ulong, int> blockIds,
            DiagnosticBag diagnostics)
        {
            var labels = new List<(int Index, string Label, int BlockId)>(table.Entries.Count);
            foreach (var entry in table.Entries.OrderBy(entry => entry.Index))
            {
                if (entry.Index is < 0 or > 4095
                    || !blockIds.TryGetValue(entry.TargetAddress.Value, out var blockId))
                {
                    diagnostics.Error(
                        DiagnosticCode.IndirectTargetUnresolved,
                        "A bounded jump-table entry has no encodable dispatcher state or selected block binding.",
                        entry.SourceFileOffset.Value);
                    return false;
                }

                var label = $"table-{Source.Function.Value:X}-{table.SourceAddress:X}-{entry.Index}";
                if (!emitter.TryEmitCreate(new Aarch64InstructionBuildRequest(
                        Aarch64InstructionEncodingFamily.CompareImmediate,
                        emitter.PositionAddress,
                        checked((uint)entry.Index),
                        BaseRegister: table.IndexRegister.Index,
                        DestinationWidth: table.IndexRegister.Width),
                    diagnostics))
                {
                    return false;
                }

                emitter.EmitConditionalBranch(0, label);
                labels.Add((entry.Index, label, blockId));
            }

            if (!blockIds.TryGetValue(table.DefaultTargetAddress.Value, out var defaultBlockId)
                || !EmitState(emitter, checked((uint)defaultBlockId), diagnostics))
            {
                diagnostics.Error(
                    DiagnosticCode.IndirectTargetUnresolved,
                    "The bounded jump-table default target has no selected dispatcher state.",
                    table.SourceAddress);
                return false;
            }

            emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
            foreach (var (_, label, blockId) in labels)
            {
                emitter.MarkLabel(label);
                if (!EmitState(emitter, checked((uint)blockId), diagnostics))
                {
                    return false;
                }

                emitter.EmitBranch($"dispatcher-{Source.Function.Value:X}");
            }

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
        private readonly List<MoveWidePatch> moveWidePatches = new();

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
