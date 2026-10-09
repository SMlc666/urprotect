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
            var isTlsDescModuleAddress = tlsDescModuleAddress is { } descriptorModuleAddress
                && instruction.Address == descriptorModuleAddress
                && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
            if ((instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true
                    && !isTerminalBranch
                    && !(supportsTlsIePcRelativeLoad
                        && tlsIePcRelativeLoadAddress is { } pcRelativeLoadAddress
                        && instruction.Address == pcRelativeLoadAddress)
                    && !isTlsLdResolverCall
                    && !isTlsLdModuleAddress
                    && !isTlsDescModuleAddress)
                || (controlFlow is Aarch64ControlFlowKind.DirectCall && !isTlsLdResolverCall)
                || (controlFlow == Aarch64ControlFlowKind.IndirectBranch && !isTlsDescCall))
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
            AsmStoneAdapter decoder,
            DiagnosticBag diagnostics)
        {
            OutputAddress = emitter.PositionAddress;
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
                    var isTlsLdResolverCall = TlsLdResolverCallAddress is { } resolverCallAddress
                        && instruction.Address == resolverCallAddress
                        && instruction.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.DirectCall;
                    var isTlsLdModuleAddress = TlsLdModuleAddress is { } moduleAddress
                        && instruction.Address == moduleAddress
                        && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
                    var isTlsDescCall = TlsDescCallAddress is { } descriptorCallAddress
                        && instruction.Address == descriptorCallAddress
                        && instruction.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.IndirectBranch;
                    var isTlsDescModuleAddress = TlsDescModuleAddress is { } descriptorModuleAddress
                        && instruction.Address == descriptorModuleAddress
                        && instruction.Decode.Instruction?.Properties.HasFlag(Aarch64InstructionProperties.PcRelative) == true;
                    if ((instruction.Decode.Instruction!.ControlFlow != Aarch64ControlFlowKind.None
                            && !isTlsLdResolverCall
                            && !isTlsDescCall)
                        || (instruction.Decode.Instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
                            && !(SupportsTlsIePcRelativeLoad
                                && TlsIePcRelativeLoadAddress is { } pcRelativeLoadAddress
                                && instruction.Address == pcRelativeLoadAddress)
                            && !isTlsLdResolverCall
                            && !isTlsLdModuleAddress
                            && !isTlsDescModuleAddress))
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

                var isTlsDescCallTerminator = TlsDescCallAddress is { } terminatorAddress
                    && last.Address == terminatorAddress
                    && last.Decode.Instruction!.ControlFlow == Aarch64ControlFlowKind.IndirectBranch;
                if (isTlsDescCallTerminator)
                {
                    var fallthrough = block.Successors.SingleOrDefault(edge =>
                        edge.Kind == Aarch64ControlFlowEdgeKind.Fallthrough);
                    if (fallthrough?.TargetAddress is not { } fallthroughTarget
                        || !blockIds.ContainsKey(fallthroughTarget))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ProtectionUnsupportedInstruction,
                            "The TLSDESC resolver call does not have one in-function fallthrough successor.",
                            last.FileOffset);
                        return false;
                    }

                    if (!EmitSourceInstruction(emitter, decoder, last, diagnostics))
                    {
                        return false;
                    }

                    // BLR returns to the next emitted word; keep the fallthrough
                    // block adjacent so the TLSDESC eight-word sequence remains contiguous.
                    continue;
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
            InstructionOutputOffsets[instruction.Address] = emitter.PositionAddress - OutputAddress;
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
        ulong OutputSize,
        IReadOnlyDictionary<ulong, ulong> InstructionOutputOffsets);

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
    }}
