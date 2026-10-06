using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class Aarch64SemanticInstructionProjectorTests
{
    [Fact]
    public void ProjectsPromotedPcRelativeFamiliesAndGeneratesFixups()
    {
        var cases = new[]
        {
            (Encoding: 0x14000004u, Kind: PcRelativeExpressionKind.Branch26, Target: 0x1010UL),
            (Encoding: 0x94000004u, Kind: PcRelativeExpressionKind.Call26, Target: 0x1010UL),
            (Encoding: 0x54000040u, Kind: PcRelativeExpressionKind.ConditionalBranch19, Target: 0x1008UL),
            (Encoding: 0xB4000040u, Kind: PcRelativeExpressionKind.ConditionalBranch19, Target: 0x1008UL),
            (Encoding: 0x36000040u, Kind: PcRelativeExpressionKind.TestBranch14, Target: 0x1008UL),
            (Encoding: 0x10000040u, Kind: PcRelativeExpressionKind.AdrPrelLo21, Target: 0x1008UL),
            (Encoding: 0xB0000000u, Kind: PcRelativeExpressionKind.AdrPrelPgHi21, Target: 0x2000UL),
            (Encoding: 0x58000040u, Kind: PcRelativeExpressionKind.Literal19, Target: 0x1008UL),
        };

        foreach (var testCase in cases)
        {
            var source = Decode(testCase.Encoding);
            var result = Aarch64SemanticInstructionProjector.Project(source);

            Assert.True(result.IsSuccess, Describe(result.Diagnostics));
            Assert.NotNull(result.Instruction);
            var instruction = result.Instruction!;
            Assert.NotNull(instruction.PcRelativeExpression);
            var expression = instruction.PcRelativeExpression!;
            Assert.Equal(testCase.Kind, expression.Kind);
            Assert.NotNull(expression.Target.SourceAddress);
            Assert.Equal(new VirtualAddress(testCase.Target), expression.Target.SourceAddress!.Value);
            Assert.Single(result.Fixups);
            Assert.Equal(
                testCase.Kind switch
                {
                    PcRelativeExpressionKind.Branch26 => SemanticFixupKind.Branch26,
                    PcRelativeExpressionKind.Call26 => SemanticFixupKind.Call26,
                    PcRelativeExpressionKind.ConditionalBranch19 => SemanticFixupKind.ConditionalBranch19,
                    PcRelativeExpressionKind.TestBranch14 => SemanticFixupKind.TestBranch14,
                    PcRelativeExpressionKind.AdrPrelLo21 => SemanticFixupKind.AdrPrelLo21,
                    PcRelativeExpressionKind.AdrPrelPgHi21 => SemanticFixupKind.AdrPrelPgHi21,
                    PcRelativeExpressionKind.Literal19 => SemanticFixupKind.Literal19,
                    _ => throw new ArgumentOutOfRangeException(),
                },
                result.Fixups[0].Kind);
        }
    }

    [Fact]
    public void PreservesTypedRangesOperandsRegisterEffectsAndFlags()
    {
        var conditional = Decode(0x54000040u);
        var conditionalResult = Aarch64SemanticInstructionProjector.Project(conditional);

        Assert.True(conditionalResult.IsSuccess, Describe(conditionalResult.Diagnostics));
        Assert.NotNull(conditionalResult.Instruction);
        var conditionalInstruction = conditionalResult.Instruction!;
        Assert.Equal(new VirtualAddress(0x1000), conditionalInstruction.SourceVirtualAddress);
        Assert.Equal(new FileOffset(0x200), conditionalInstruction.SourceFileOffset);
        Assert.Equal(new VirtualAddress(0x1000), conditionalInstruction.SourceRange.VirtualAddress);
        Assert.Equal(new FileOffset(0x200), conditionalInstruction.SourceRange.FileOffset);
        Assert.Equal((ulong)sizeof(uint), conditionalInstruction.SourceRange.Size);
        Assert.Contains(conditionalInstruction.Operands, operand => operand.Kind == Aarch64OperandKind.Target);
        Assert.True(conditionalInstruction.FlagEffects.HasFlag(SemanticFlagEffects.ReadNzcv));
        Assert.Contains(
            conditionalInstruction.References,
            reference => reference.Kind == SemanticReferenceKind.ControlFlowTarget
                && reference.Target.IsExact);

        var add = Decode(0x8B090149u);
        var addResult = Aarch64SemanticInstructionProjector.Project(add);
        Assert.True(addResult.IsSuccess, Describe(addResult.Diagnostics));
        Assert.NotNull(addResult.Instruction);
        var addInstruction = addResult.Instruction!;
        Assert.Contains(
            addInstruction.RegisterEffects,
            effect => effect.Register.Class == Aarch64RegisterClass.General
                && effect.Register.Index == 9
                && effect.Kind == SemanticRegisterEffectKind.Read);
        Assert.Contains(
            addInstruction.RegisterEffects,
            effect => effect.Register.Class == Aarch64RegisterClass.General
                && effect.Register.Index == 9
                && effect.Kind == SemanticRegisterEffectKind.Write);
    }

    [Fact]
    public void RoundTripsAProjectedBranchThroughTheSemanticEncoder()
    {
        var projected = Aarch64SemanticInstructionProjector.Project(Decode(0x14000004u));
        Assert.True(projected.IsSuccess, Describe(projected.Diagnostics));

        var mapResult = AddressMap.Create(new[]
        {
            Mapping(SemanticEntityId.Instruction(new VirtualAddress(0x1000)), 0x1000, 0x200, 0x5000, 0x800),
            Mapping(SemanticEntityId.BasicBlock("target"), 0x1010, 0x210, 0x5010, 0x810),
        });
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));

        var planResult = SemanticRewritePlanBuilder.Build(
            mapResult.Map!,
            new[] { projected.Instruction! },
            projected.Fixups);
        Assert.True(planResult.IsSuccess, Describe(planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        Assert.True(resolution.IsSuccess, Describe(resolution.Diagnostics));
        var resolved = Assert.Single(resolution.Fixups);
        Assert.Equal(new VirtualAddress(0x5000), resolved.OutputSourceAddress);
        Assert.Equal(new VirtualAddress(0x5010), resolved.OutputTargetAddress);

        var decoded = new AsmStoneAdapter().Decode(
            resolved.InstructionEncoding!.Value,
            resolved.OutputSourceAddress!.Value.Value);
        Assert.True(decoded.IsSuccess, decoded.Diagnostic);
        Assert.Equal(0x5010UL, decoded.Instruction!.DirectTarget);
    }

    [Fact]
    public void KeepsIndirectControlFlowExplicitlyUnresolved()
    {
        const uint encoding = 0xD61F0000;
        var source = new Aarch64FunctionInstruction(
            0x200,
            0x1000,
            encoding,
            new Aarch64DecodeResult(
                Aarch64DecodeStatus.Decoded,
                new Aarch64Instruction(
                    0x1000,
                    encoding,
                    "BR",
                    Aarch64InstructionProperties.Branch | Aarch64InstructionProperties.Terminator,
                    Aarch64ControlFlowKind.IndirectBranch,
                    null),
                string.Empty));

        var result = Aarch64SemanticInstructionProjector.Project(source);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Instruction);
        var instruction = result.Instruction!;
        Assert.True(instruction.ControlFlowTarget!.IsUnresolved);
        Assert.Contains(
            instruction.References,
            reference => reference.Kind == SemanticReferenceKind.ControlFlowTarget
                && reference.Target.IsUnresolved);
        Assert.Empty(result.Fixups);
    }

    [Fact]
    public void RelocationTargetOverridesDecodedCallImmediateAndPreservesRawType()
    {
        const uint symbolIndex = 3;
        var relocationType = ElfConstants.RArm64Call26;
        var relocation = new RelaRelocation(
            0x1000,
            ((ulong)symbolIndex << 32) | relocationType,
            4,
            0x3000,
            false);

        var result = Aarch64SemanticInstructionProjector.Project(
            Decode(0x94000004u),
            new[] { relocation });

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Instruction);
        var instruction = result.Instruction!;
        Assert.NotNull(instruction.PcRelativeExpression);
        Assert.Equal("bl", instruction.Mnemonic, ignoreCase: true);
        Assert.True(Assert.Single(instruction.Relocations).IsExternalBinding);
        var expression = instruction.PcRelativeExpression!;
        Assert.Equal(SemanticTargetResolution.RuntimeResolved, expression.Target.Resolution);
        Assert.Equal($"relocation:type:{relocationType}:symbol:{symbolIndex}", expression.Target.RuntimeBinding);
        Assert.Equal(4, expression.Addend);

        var fixup = Assert.Single(result.Fixups);
        Assert.Equal(SemanticFixupKind.Relocation, fixup.Kind);
        Assert.Equal((uint?)relocationType, fixup.Relocation!.RelocationType);
        Assert.Equal(relocation.Info, fixup.Relocation.RawInfo);
        Assert.Equal(new VirtualAddress(relocation.Offset), fixup.Relocation.RelocationAddress);
        Assert.Equal(new VirtualAddress(relocation.SourceAddress), fixup.Relocation.RelocationTableAddress);
        Assert.Equal(expression.Target, fixup.Target);
    }

    [Fact]
    public void RejectsMultipleRelocationFamiliesAtOnePcRelativeInstruction()
    {
        var call = new RelaRelocation(
            0x1000,
            ElfConstants.RArm64Call26,
            0,
            0x3000,
            false);
        var add = new RelaRelocation(
            0x1000,
            ElfConstants.RArm64AddAbsLo12Nc,
            0,
            0x3000,
            false);

        var result = Aarch64SemanticInstructionProjector.Project(
            Decode(0x94000004u),
            new[] { call, add });

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed
                && diagnostic.Message.Contains("more than one semantic family", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(result.Fixups);
    }

    [Fact]
    public void ProjectsRelocationBindingAndRelocationFixupForNonPcRelativeInstruction()
    {
        var relocation = new RelaRelocation(
            0x1000,
            ElfConstants.RArm64AddAbsLo12Nc,
            0,
            0x3000,
            false);
        var result = Aarch64SemanticInstructionProjector.Project(
            Decode(0x91000000u),
            new[] { relocation });

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Instruction);
        var instruction = result.Instruction!;
        var binding = Assert.Single(instruction.Relocations);
        Assert.Equal(Aarch64RelocationKind.AddAbsLo12, binding.Kind);
        Assert.Equal((uint?)ElfConstants.RArm64AddAbsLo12Nc, binding.RelocationType);
        Assert.Contains(
            instruction.References,
            reference => reference.Kind == SemanticReferenceKind.Relocation
                && reference.Relocation == binding);
        Assert.Equal(SemanticFixupKind.Relocation, Assert.Single(result.Fixups).Kind);
    }

    [Fact]
    public void RejectsUnpromotedPcRelativeInstructionWithoutOpaqueContract()
    {
        const uint encoding = 0xD8000000;
        var source = new Aarch64FunctionInstruction(
            0x200,
            0x1000,
            encoding,
            new Aarch64DecodeResult(
                Aarch64DecodeStatus.Decoded,
                new Aarch64Instruction(
                    0x1000,
                    encoding,
                    "PRFML",
                    Aarch64InstructionProperties.PcRelative | Aarch64InstructionProperties.SideEffects,
                    Aarch64ControlFlowKind.None,
                    0x1008)
                {
                    Operands = new[]
                    {
                        new Aarch64SemanticOperand(
                            "label",
                            Aarch64OperandKind.Target,
                            Aarch64OperandDirection.Input,
                            false,
                            "am_ldrlit",
                            null,
                            null,
                            Array.Empty<Aarch64RegisterView>(),
                            null,
                            null,
                            0x1008,
                            new Aarch64RegisterConstraint(0, 31, 1, 0),
                            0,
                            19,
                            1,
                            false,
                            false,
                            false,
                            "pc-relative"),
                    },
                },
                string.Empty));

        var result = Aarch64SemanticInstructionProjector.Project(source);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupUnsupported);
    }

    [Fact]
    public void PreservesUnknownRelocationWithoutInventingAnInstructionWriteWidth()
    {
        const uint rawType = 0xFFFF;
        var relocation = new RelaRelocation(
            0x1000,
            rawType,
            0,
            0x3000,
            false);

        var result = Aarch64SemanticInstructionProjector.Project(
            Decode(0xD503201Fu),
            new[] { relocation });

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.Empty(result.Fixups);
        var binding = Assert.Single(result.Instruction!.Relocations);
        Assert.Equal(Aarch64RelocationKind.Unknown, binding.Kind);
        Assert.Equal((uint?)rawType, binding.RelocationType);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupUnsupported);
    }

    [Fact]
    public void RejectsUnalignedOrMismatchedSourceProjection()
    {
        var decoded = new AsmStoneAdapter().Decode(0xD503201Fu, 0x1000);
        var unaligned = new Aarch64FunctionInstruction(0x202, 0x1000, 0xD503201F, decoded);
        var unalignedResult = Aarch64SemanticInstructionProjector.Project(unaligned);

        Assert.False(unalignedResult.IsSuccess);
        Assert.Contains(
            unalignedResult.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticInstructionMalformed);
        Assert.Null(unalignedResult.Instruction);

        var mismatched = new Aarch64FunctionInstruction(0x200, 0x1000, 0xD503201F, decoded with
        {
            Instruction = decoded.Instruction! with { Address = 0x1004 },
        });
        var mismatchedResult = Aarch64SemanticInstructionProjector.Project(mismatched);

        Assert.False(mismatchedResult.IsSuccess);
        Assert.Contains(
            mismatchedResult.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticInstructionMalformed);
    }

    private static Aarch64FunctionInstruction Decode(
        uint encoding,
        ulong address = 0x1000,
        ulong fileOffset = 0x200)
    {
        var adapter = new AsmStoneAdapter();
        return new Aarch64FunctionInstruction(
            fileOffset,
            address,
            encoding,
            adapter.Decode(encoding, address));
    }

    private static AddressMapEntry Mapping(
        SemanticEntityId identity,
        ulong sourceAddress,
        ulong sourceFileOffset,
        ulong outputAddress,
        ulong outputFileOffset) =>
        new(
            identity,
            new SemanticSourceRange(
                new FileOffset(sourceFileOffset),
                new VirtualAddress(sourceAddress),
                sizeof(uint)),
            new SemanticSourceRange(
                new FileOffset(outputFileOffset),
                new VirtualAddress(outputAddress),
                sizeof(uint)));

    private static string Describe(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(Environment.NewLine, diagnostics);
}
