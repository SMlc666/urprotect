using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Semantics;

public sealed class Aarch64InstructionEncoderTests
{
    [Fact]
    public void ReencodesDynamicTlsModuleAndDtprelWordsThroughAdapter()
    {
        var encoder = new Aarch64InstructionEncoder();
        var sourceAdr = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            0x1600,
            0,
            DestinationRegister: 16));
        var sourceAdd = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.AddImmediate,
            0x1604,
            0x2A0,
            DestinationRegister: 16,
            BaseRegister: 16));
        var sourceDtpRel = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.AddImmediate,
            0x160C,
            0,
            DestinationRegister: 0,
            BaseRegister: 0,
            ShiftedImmediate: true));
        Assert.True(sourceAdr.IsSuccess, sourceAdr.Diagnostic);
        Assert.True(sourceAdd.IsSuccess, sourceAdd.Diagnostic);
        Assert.True(sourceDtpRel.IsSuccess, sourceDtpRel.Diagnostic);
        Assert.True(Aarch64TlsInstructionSemantics.TryEncodeLocalDynamicModulePair(
            sourceAdr.Encoding,
            sourceAdd.Encoding,
            sourceAdr.Encoding,
            sourceAdd.Encoding,
            ElfConstants.RArm64TlsLdAddLo12Nc,
            0x1600,
            0x1600,
            0x2A0,
            0,
            out var encodedAdr,
            out var encodedAdd));
        Assert.Equal(sourceAdr.Encoding, encodedAdr);
        Assert.Equal(sourceAdd.Encoding, encodedAdd);
        Assert.True(Aarch64TlsInstructionSemantics.TryEncodeLocalDynamicDtprel(
            ElfConstants.RArm64TlsLdAddDtprelHi12,
            sourceDtpRel.Encoding,
            sourceDtpRel.Encoding,
            0x160C,
            0x160C,
            out var encodedHi));
        Assert.Equal(sourceDtpRel.Encoding, encodedHi);
    }

    [Fact]
    public void BuildsAndRoundTripsPcRelativeInstructionThroughAsmStone()
    {
        var encoder = new Aarch64InstructionEncoder();

        var created = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Call26,
            Address: 0x1000,
            TargetOrImmediate: 0x1010));

        Assert.True(created.IsSuccess, created.Diagnostic);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.None, created.DiagnosticCode);
        Assert.Equal(0x94000004u, created.Encoding);
        Assert.Equal(0x1010UL, created.Instruction!.DirectTarget);
    }

    [Fact]
    public void ReencodesAdrpWithMappedPageTargetAndRoundTrips()
    {
        var encoder = new Aarch64InstructionEncoder();
        var source = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            Address: 0x1000,
            TargetOrImmediate: 0x2000,
            DestinationRegister: 9));
        Assert.True(source.IsSuccess, source.Diagnostic);

        var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x5000,
            Family: Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            TargetOrImmediate: 0x6000));

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.Equal(0x6000UL, result.Instruction!.DirectTarget);
    }

    [Fact]
    public void RejectsNearestNegativeBranchRangeAndAlignment()
    {
        var encoder = new Aarch64InstructionEncoder();
        var source = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Branch26,
            Address: 0x1000,
            TargetOrImmediate: 0x1010));
        Assert.True(source.IsSuccess, source.Diagnostic);

        var outOfRange = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x5000,
            Family: Aarch64InstructionEncodingFamily.Branch26,
            TargetOrImmediate: 0x1000 + (1UL << 28)));
        Assert.False(outOfRange.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.TargetOutOfRange, outOfRange.DiagnosticCode);

        var misaligned = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x5000,
            Family: Aarch64InstructionEncodingFamily.Branch26,
            TargetOrImmediate: 0x1012));
        Assert.False(misaligned.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.TargetMisaligned, misaligned.DiagnosticCode);
    }

    [Fact]
    public void RejectsNearestNegativeLoadStoreScaleAndWidth()
    {
        var encoder = new Aarch64InstructionEncoder();
        var source = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
            Address: 0x1000,
            TargetOrImmediate: 4,
            DestinationRegister: 0,
            BaseRegister: 9,
            AccessWidth: 32));
        Assert.True(source.IsSuccess, source.Diagnostic);

        var badScale = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x5000,
            Family: Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
            TargetOrImmediate: 2,
            AccessWidth: 32));
        Assert.False(badScale.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.InvalidOperand, badScale.DiagnosticCode);

        var badWidth = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x5000,
            Family: Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
            TargetOrImmediate: 4,
            AccessWidth: 64));
        Assert.False(badWidth.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.OperandWidthMismatch, badWidth.DiagnosticCode);
    }
}
