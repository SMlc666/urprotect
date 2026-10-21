using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;

namespace UrProtect.Core.Tests.Semantics;

public sealed class AsmStoneAdapterTests
{
    [Fact]
    public void KeepsTheProjectOwnedAdapterBoundary()
    {
        var adapter = new AsmStoneAdapter((encoding, address) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.Decoded,
            new Aarch64Instruction(
                address,
                encoding,
                "nop",
                Aarch64InstructionProperties.None,
                Aarch64ControlFlowKind.None,
                null),
            string.Empty));

        var result = adapter.Decode(0xD503201F, 0x1200);

        Assert.True(result.IsSuccess);
        Assert.Equal("nop", result.Instruction!.SourceName);
    }

    [Fact]
    public void PinnedAsmStoneBackendDecodesNop()
    {
        var result = new AsmStoneAdapter().Decode(0xD503201F, 0x1000);

        Assert.Equal(Aarch64DecodeStatus.Decoded, result.Status);
        Assert.True(result.IsSuccess);
        Assert.Equal("NOP", result.Instruction!.SourceName);
    }

    [Fact]
    public void AdapterPreservesDirectBranchTarget()
    {
        var result = new AsmStoneAdapter().Decode(0x14000004, 0x1000);

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.Equal(Aarch64ControlFlowKind.DirectBranch, result.Instruction!.ControlFlow);
        Assert.Equal(0x1010UL, result.Instruction.DirectTarget);
    }

    [Fact]
    public void AdapterDistinguishesDirectBlFromIndirectBlr()
    {
        var directCall = new AsmStoneAdapter().Decode(0x94000004u, 0x1000);
        Assert.True(directCall.IsSuccess, directCall.Diagnostic);
        Assert.Equal(Aarch64ControlFlowKind.DirectCall, directCall.Instruction!.ControlFlow);
        Assert.Equal(0x1010UL, directCall.Instruction.DirectTarget);

        var indirectCall = new AsmStoneAdapter().Decode(0xD63F0000u, 0x1000);
        Assert.True(indirectCall.IsSuccess, indirectCall.Diagnostic);
        Assert.Equal(Aarch64ControlFlowKind.IndirectBranch, indirectCall.Instruction!.ControlFlow);
        Assert.Null(indirectCall.Instruction.DirectTarget);
    }

    [Fact]
    public void AdapterCoversProjectInstructionContractVectors()
    {
        var vectors = new[]
        {
            (Encoding: 0x54000040u, Address: 0x1000UL, Kind: Aarch64ControlFlowKind.ConditionalBranch, Target: (ulong?)0x1008),
            (Encoding: 0xB4000040u, Address: 0x1000UL, Kind: Aarch64ControlFlowKind.ConditionalBranch, Target: (ulong?)0x1008),
            (Encoding: 0x10000040u, Address: 0x1000UL, Kind: Aarch64ControlFlowKind.None, Target: (ulong?)0x1008),
            (Encoding: 0xB0000000u, Address: 0x1000UL, Kind: Aarch64ControlFlowKind.None, Target: (ulong?)0x2000),
            (Encoding: 0x58000040u, Address: 0x1000UL, Kind: Aarch64ControlFlowKind.None, Target: (ulong?)0x1008),
            (Encoding: 0xF9400020u, Address: 0x1000UL, Kind: Aarch64ControlFlowKind.None, Target: (ulong?)null),
            (Encoding: 0xF9000020u, Address: 0x1000UL, Kind: Aarch64ControlFlowKind.None, Target: (ulong?)null),
        };

        foreach (var vector in vectors)
        {
            var result = new AsmStoneAdapter().Decode(vector.Encoding, vector.Address);

            Assert.True(result.IsSuccess, $"0x{vector.Encoding:X8}: {result.Diagnostic}");
            Assert.Equal(vector.Kind, result.Instruction!.ControlFlow);
            Assert.Equal(vector.Target, result.Instruction.DirectTarget);
        }

        var adr = new AsmStoneAdapter().Decode(0x10000040, 0x1000);
        Assert.True(adr.Instruction!.Properties.HasFlag(Aarch64InstructionProperties.PcRelative));

        var adrp = new AsmStoneAdapter().Decode(0xB0000000, 0x1000);
        Assert.True(adrp.Instruction!.Properties.HasFlag(Aarch64InstructionProperties.PcRelative));

        var literal = new AsmStoneAdapter().Decode(0x58000040, 0x1000);
        Assert.True(literal.Instruction!.Properties.HasFlag(Aarch64InstructionProperties.Load));

        var load = new AsmStoneAdapter().Decode(0xF9400020, 0x1000);
        Assert.True(load.Instruction!.Properties.HasFlag(Aarch64InstructionProperties.Load));

        var store = new AsmStoneAdapter().Decode(0xF9000020, 0x1000);
        Assert.True(store.Instruction!.Properties.HasFlag(Aarch64InstructionProperties.Store));
    }

    [Fact]
    public void AdapterFailsClosedForImplicitMemoryEffectsWithoutInvalidatingKnownSystemReads()
    {
        const uint dcZvaX9 = 0xD50B7429u; // GNU as: DC ZVA, X9.
        var dcZva = new AsmStoneAdapter().Decode(dcZvaX9, 0x1000);

        Assert.True(dcZva.IsSuccess, dcZva.Diagnostic);
        Assert.DoesNotContain(dcZva.Instruction!.Operands, operand => operand.Memory is not null);
        Assert.True(dcZva.Instruction.Properties.HasFlag(Aarch64InstructionProperties.Load));
        Assert.True(dcZva.Instruction.Properties.HasFlag(Aarch64InstructionProperties.Store));
        Assert.True(dcZva.Instruction.Properties.HasFlag(Aarch64InstructionProperties.SideEffects));
        Assert.Equal(Aarch64MemoryEffect.Unclassified, dcZva.Instruction.MemoryEffect);

        var mrs = new AsmStoneAdapter().Decode(0xD53BD040u, 0x1000); // MRS X0, TPIDR_EL0.
        Assert.True(mrs.IsSuccess, mrs.Diagnostic);
        Assert.DoesNotContain(mrs.Instruction!.Operands, operand => operand.Memory is not null);
        Assert.Equal(Aarch64MemoryEffect.None, mrs.Instruction.MemoryEffect);

        var dmb = new AsmStoneAdapter().Decode(0xD5033F9Fu, 0x1000); // DMB ISH.
        Assert.True(dmb.IsSuccess, dmb.Diagnostic);
        Assert.DoesNotContain(dmb.Instruction!.Operands, operand => operand.Memory is not null);
        Assert.True(dmb.Instruction.Properties.HasFlag(Aarch64InstructionProperties.SideEffects));
        Assert.Equal(Aarch64MemoryEffect.None, dmb.Instruction.MemoryEffect);
    }

    [Fact]
    public void AdapterProjectsGnuSwpFamilyAsBoundedAtomicReadModifyWrite()
    {
        var vectors = new[]
        {
            (0xF82A812Bu, "swp", 8),
            (0xF8EA812Bu, "swpal", 8),
            (0xF82A813Fu, "swp", 8),
            (0xF8EA813Fu, "swpal", 8),
            (0xB82A812Bu, "swp", 4),
            (0xB8AA812Bu, "swpa", 4),
            (0xB86A812Bu, "swpl", 4),
            (0xB8EA812Bu, "swpal", 4),
            (0x382A812Bu, "swpb", 1),
            (0x38AA812Bu, "swpab", 1),
            (0x386A812Bu, "swplb", 1),
            (0x38EA812Bu, "swpalb", 1),
            (0x782A812Bu, "swph", 2),
            (0x78AA812Bu, "swpah", 2),
            (0x786A812Bu, "swplh", 2),
            (0x78EA812Bu, "swpalh", 2),
        };

        foreach (var (encoding, mnemonic, accessSize) in vectors)
        {
            var result = new AsmStoneAdapter().Decode(encoding, 0x1000);

            Assert.True(result.IsSuccess, $"GNU as oracle 0x{encoding:X8}: {result.Diagnostic}");
            Assert.Equal(mnemonic, result.Instruction!.Mnemonic);
            Assert.Equal(Aarch64MemoryEffect.ReadModifyWrite, result.Instruction.MemoryEffect);
            var memory = Assert.Single(result.Instruction.Operands, operand => operand.Memory is not null);
            Assert.Equal(Aarch64OperandDirection.Input, memory.Direction);
            Assert.Equal(accessSize, memory.Memory!.AccessSize);
            var explicitRegisters = result.Instruction.Operands
                .Where(operand => operand.Kind == Aarch64OperandKind.Register && !operand.IsImplicit)
                .ToArray();
            Assert.Contains(explicitRegisters, operand => operand.Direction == Aarch64OperandDirection.Input);
            Assert.Contains(explicitRegisters, operand => operand.Direction == Aarch64OperandDirection.Output);
        }
    }

    [Fact]
    public void AdapterPreservesSwapSourceAndReturnedOldOperandRoles()
    {
        var adapter = new AsmStoneAdapter();
        var storeUnknownAndDiscardOld = adapter.Decode(0xF8EA813Fu, 0x1000); // SWPAL X10, XZR, [X9].
        Assert.True(storeUnknownAndDiscardOld.IsSuccess, storeUnknownAndDiscardOld.Diagnostic);
        Assert.Contains(storeUnknownAndDiscardOld.Instruction!.Operands, operand =>
            operand.Kind == Aarch64OperandKind.Register
            && operand.Direction == Aarch64OperandDirection.Input
            && operand.Register is { Class: Aarch64RegisterClass.General, Index: 10, Width: 64, Role: Aarch64RegisterRole.None });
        Assert.Contains(storeUnknownAndDiscardOld.Instruction.Operands, operand =>
            operand.Kind == Aarch64OperandKind.Register
            && operand.Direction == Aarch64OperandDirection.Output
            && operand.Register is { Class: Aarch64RegisterClass.General, Role: Aarch64RegisterRole.Zero });

        var storeZeroAndReturnOld = adapter.Decode(0xF8FF812Au, 0x1000); // SWPAL XZR, X10, [X9].
        Assert.True(storeZeroAndReturnOld.IsSuccess, storeZeroAndReturnOld.Diagnostic);
        Assert.Contains(storeZeroAndReturnOld.Instruction!.Operands, operand =>
            operand.Kind == Aarch64OperandKind.Register
            && operand.Direction == Aarch64OperandDirection.Input
            && operand.Register is { Class: Aarch64RegisterClass.General, Role: Aarch64RegisterRole.Zero });
        Assert.Contains(storeZeroAndReturnOld.Instruction.Operands, operand =>
            operand.Kind == Aarch64OperandKind.Register
            && operand.Direction == Aarch64OperandDirection.Output
            && operand.Register is { Class: Aarch64RegisterClass.General, Index: 10, Width: 64, Role: Aarch64RegisterRole.None });
    }

    [Fact]
    public void AdapterDistinguishesPlainWritesConditionalWritesAndRmwControls()
    {
        var vectors = new[]
        {
            (0xC89FFD3Fu, Aarch64MemoryEffect.PlainWrite), // GNU as: STLR XZR, [X9]
            (0xC80A7D3Fu, Aarch64MemoryEffect.ConditionalWrite), // GNU as: STXR W10, XZR, [X9]
            (0xC80AFD3Fu, Aarch64MemoryEffect.ConditionalWrite), // GNU as: STLXR W10, XZR, [X9]
            (0xC8AA7D2Bu, Aarch64MemoryEffect.ConditionalWrite), // GNU as: CAS X10, X11, [X9]
            (0xC8EAFD2Bu, Aarch64MemoryEffect.ConditionalWrite), // GNU as: CASAL X10, X11, [X9]
            (0xF82A012Bu, Aarch64MemoryEffect.ReadModifyWrite), // GNU as: LDADD X10, X11, [X9]
            (0xF8EA012Bu, Aarch64MemoryEffect.ReadModifyWrite), // GNU as: LDADDAL X10, X11, [X9]
            (0xF900012Au, Aarch64MemoryEffect.PlainWrite), // GNU as: STR X10, [X9]
            (0xF9400020u, Aarch64MemoryEffect.Read), // ordinary LDR control
        };

        foreach (var (encoding, expectedEffect) in vectors)
        {
            var result = new AsmStoneAdapter().Decode(encoding, 0x1000);

            Assert.True(result.IsSuccess, $"0x{encoding:X8}: {result.Diagnostic}");
            Assert.True(
                expectedEffect == result.Instruction!.MemoryEffect,
                $"GNU as oracle 0x{encoding:X8} ({result.Instruction.Mnemonic}): expected {expectedEffect}, found {result.Instruction.MemoryEffect}.");
        }
    }

    [Fact]
    public void AdapterNormalizesAdrpTargetUsingTheSourcePage()
    {
        const ulong instructionAddress = 0x1B50;
        var result = new AsmStoneAdapter().Decode(0xB0000000, instructionAddress);

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.Equal(0x2000UL, result.Instruction!.DirectTarget);
        var pageOperand = Assert.Single(result.Instruction.Operands, operand => operand.IsPageRelative);
        Assert.Equal(Aarch64OperandKind.Target, pageOperand.Kind);
        Assert.Equal(0x2000UL, pageOperand.Target);
    }

    [Fact]
    public void AdapterRejectsAdrpTargetWhoseSourceDisplacementWrapsAddressSpace()
    {
        const ulong instructionAddress = 0xFFFFFFFFFFFFF800;
        var result = new AsmStoneAdapter().Decode(0xB0000000, instructionAddress);

        Assert.Equal(Aarch64DecodeStatus.UnknownEncoding, result.Status);
        Assert.Null(result.Instruction);
        Assert.Contains("checked source/displacement arithmetic", result.Diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public void AsmStoneEncoderPermutesGeneralRegistersThroughTheProjectAdapter()
    {
        const uint addX9X10X9 = 0x8B090149;
        var adapter = new AsmStoneAdapter();

        var result = adapter.TryPermuteGeneralRegisters(
            addX9X10X9,
            0x1000,
            new Dictionary<byte, byte> { [9] = 10, [10] = 9 });

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.NotEqual(addX9X10X9, result.Encoding);
        var decoded = adapter.Decode(result.Encoding, 0x1000);
        Assert.True(decoded.IsSuccess, decoded.Diagnostic);
        Assert.Contains(decoded.Instruction!.Operands, operand =>
            operand.Register is { Class: Aarch64RegisterClass.General, Index: 10 });
    }

    [Fact]
    public void AdapterRetainsImplicitAndSpecialRegisterSemantics()
    {
        var adapter = new AsmStoneAdapter();
        var addSp = adapter.Decode(0x910003E0, 0x1000);

        Assert.True(addSp.IsSuccess, addSp.Diagnostic);
        Assert.Contains(addSp.Instruction!.Operands, operand =>
            operand.Register is { Role: Aarch64RegisterRole.StackPointer });

        var zeroRegister = adapter.Decode(0x8B0903E0, 0x1000);
        Assert.True(zeroRegister.IsSuccess, zeroRegister.Diagnostic);
        Assert.Contains(zeroRegister.Instruction!.Operands, operand =>
            operand.Register is { Role: Aarch64RegisterRole.Zero });
    }
}
