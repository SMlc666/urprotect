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
}
