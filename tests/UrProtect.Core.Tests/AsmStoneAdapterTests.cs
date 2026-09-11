using UrProtect.Core.Aarch64;

namespace UrProtect.Core.Tests;

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
}
