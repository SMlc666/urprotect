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
    public void BuildsAndRoundTripsConditionalBranchWithConditionCode()
    {
        var encoder = new Aarch64InstructionEncoder();

        var result = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.ConditionalBranch19,
            Address: 0x1000,
            TargetOrImmediate: 0x1010,
            ConditionCode: 1));

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.Equal(0x54000081u, result.Encoding);
        Assert.Equal(0x1010UL, result.Instruction!.DirectTarget);
        Assert.Equal(Aarch64ControlFlowKind.ConditionalBranch, result.Instruction.ControlFlow);
        Assert.Equal(1L, result.Instruction.Operands
            .Single(operand => operand.Name == "cond")
            .Immediate);
    }

    [Fact]
    public void RejectsConditionalBranchConditionOutsideArchitecturalDomain()
    {
        var encoder = new Aarch64InstructionEncoder();

        var result = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.ConditionalBranch19,
            Address: 0x1000,
            TargetOrImmediate: 0x1010,
            ConditionCode: 16));

        Assert.False(result.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.InvalidOperand, result.DiagnosticCode);
        Assert.Equal(0u, result.Encoding);
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
    public void BuildsAndRoundTripsMoveWideImmediate()
    {
        var encoder = new Aarch64InstructionEncoder();

        var result = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveWideImmediate,
            Address: 0x1000,
            TargetOrImmediate: 0x1234,
            DestinationRegister: 16,
            DestinationWidth: 32,
            ImmediateShift: 16));

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.Equal(0x52A24690u, result.Encoding);
        Assert.Equal("MOVZWi", result.Instruction!.SourceName);
        Assert.Equal(32, result.Instruction.Operands[0].Register!.Value.Width);
        Assert.Equal(0x1234L, result.Instruction.Operands[1].Immediate!.Value);
        Assert.Equal(16L, result.Instruction.Operands[2].Immediate!.Value);
    }

    [Fact]
    public void BuildsAndRoundTripsMoveRegister()
    {
        var encoder = new Aarch64InstructionEncoder();

        var result = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveRegister,
            Address: 0x1000,
            TargetOrImmediate: 0,
            DestinationRegister: 17,
            DestinationWidth: 32,
            SourceRegister: 9));

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.Equal(0x2A0903F1u, result.Encoding);
        Assert.Equal("ORRWrs", result.Instruction!.SourceName);
        Assert.Equal(32, result.Instruction.Operands[0].Register!.Value.Width);
        Assert.Equal(17, result.Instruction.Operands[0].Register!.Value.Index);
        Assert.Equal(9, result.Instruction.Operands[2].Register!.Value.Index);
    }

    [Fact]
    public void BuildsAndRoundTripsCompareImmediateAndReturn()
    {
        var encoder = new Aarch64InstructionEncoder();

        var compare = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            Address: 0x1000,
            TargetOrImmediate: 7,
            BaseRegister: 3,
            DestinationWidth: 32));

        Assert.True(compare.IsSuccess, compare.Diagnostic);
        Assert.Equal(0x71001C7Fu, compare.Encoding);
        Assert.Equal("SUBSWri", compare.Instruction!.SourceName);
        Assert.Equal("SUBSWri", compare.Instruction.SourceName);

        var ret = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Return,
            Address: 0x1004,
            TargetOrImmediate: 0));

        Assert.True(ret.IsSuccess, ret.Diagnostic);
        Assert.Equal(0xD65F03C0u, ret.Encoding);
        Assert.Equal("RET", ret.Instruction!.SourceName);
        Assert.Equal("RET", ret.Instruction.SourceName);
    }

    [Fact]
    public void RejectsInvalidGeneratedInstructionOperands()
    {
        var encoder = new Aarch64InstructionEncoder();

        var badMoveWidth = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveWideImmediate,
            Address: 0x1000,
            TargetOrImmediate: 1,
            DestinationWidth: 16));
        Assert.False(badMoveWidth.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.InvalidOperand, badMoveWidth.DiagnosticCode);
        Assert.Equal(0u, badMoveWidth.Encoding);

        var badMoveShift = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveWideImmediate,
            Address: 0x1000,
            TargetOrImmediate: 1,
            DestinationWidth: 32,
            ImmediateShift: 32));
        Assert.False(badMoveShift.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.InvalidOperand, badMoveShift.DiagnosticCode);

        var badMoveRegister = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveRegister,
            Address: 0x1000,
            TargetOrImmediate: 0,
            DestinationWidth: 64));
        Assert.False(badMoveRegister.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.InvalidRequest, badMoveRegister.DiagnosticCode);

        var badCompareImmediate = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            Address: 0x1000,
            TargetOrImmediate: 0x1001_000,
            DestinationWidth: 32));
        Assert.False(badCompareImmediate.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.InvalidOperand, badCompareImmediate.DiagnosticCode);
    }

    [Fact]
    public void ReencodesMoveWideUsingTheSourceImmediateAndOutputTemplate()
    {
        var encoder = new Aarch64InstructionEncoder();

        var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            SourceEncoding: 0x52800021u,
            SourceAddress: 0x1000,
            OutputAddress: 0x2000,
            Family: Aarch64InstructionEncodingFamily.MoveWideImmediate,
            TargetOrImmediate: 0,
            OutputTemplateEncoding: 0x52800042u,
            PreserveSourceImmediate: true,
            RegisterWidth: 32));

        Assert.True(result.IsSuccess, result.Diagnostic);
        Assert.Equal(0x52800022u, result.Encoding);
        Assert.Equal(2, result.Instruction!.Operands[0].Register!.Value.Index);
        Assert.Equal(1L, result.Instruction.Operands[1].Immediate!.Value);
    }

    [Fact]
    public void RejectsMoveWideTemplateFormMismatch()
    {
        var encoder = new Aarch64InstructionEncoder();
        var source = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveWideImmediate,
            Address: 0x1000,
            TargetOrImmediate: 1,
            DestinationRegister: 0,
            DestinationWidth: 32));
        var template = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveWideImmediate,
            Address: 0x1004,
            TargetOrImmediate: 2,
            DestinationRegister: 0,
            DestinationWidth: 64));

        Assert.True(source.IsSuccess, source.Diagnostic);
        Assert.True(template.IsSuccess, template.Diagnostic);

        var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x2000,
            Family: Aarch64InstructionEncodingFamily.MoveWideImmediate,
            TargetOrImmediate: 3,
            OutputTemplateEncoding: template.Encoding,
            RegisterWidth: 32));

        Assert.False(result.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.OperandWidthMismatch, result.DiagnosticCode);
        Assert.Equal(0u, result.Encoding);
    }

    [Fact]
    public void ReencodesMoveNotAndMoveKeepWithoutChangingTheirForms()
    {
        var encoder = new Aarch64InstructionEncoder();

        var movn = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            SourceEncoding: 0x12A00021u,
            SourceAddress: 0x1000,
            OutputAddress: 0x2000,
            Family: Aarch64InstructionEncodingFamily.MoveWideImmediate,
            TargetOrImmediate: 2,
            RegisterWidth: 32));
        Assert.True(movn.IsSuccess, movn.Diagnostic);
        Assert.Equal("MOVNWi", movn.Instruction!.SourceName);
        Assert.Equal(2L, movn.Instruction.Operands[1].Immediate!.Value);
        Assert.Equal(16L, movn.Instruction.Operands[2].Immediate!.Value);

        var movk = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            SourceEncoding: 0xF2F579A2u,
            SourceAddress: 0x1000,
            OutputAddress: 0x2000,
            Family: Aarch64InstructionEncodingFamily.MoveWideImmediate,
            TargetOrImmediate: 0x1234,
            RegisterWidth: 64));
        Assert.True(movk.IsSuccess, movk.Diagnostic);
        Assert.Equal("MOVKXi", movk.Instruction!.SourceName);
        Assert.Equal(0x1234L, movk.Instruction.Operands[2].Immediate!.Value);
        Assert.Equal(48L, movk.Instruction.Operands[3].Immediate!.Value);
    }

    [Fact]
    public void RejectsMoveRegisterTemplateFamilyMismatch()
    {
        var encoder = new Aarch64InstructionEncoder();
        var source = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveRegister,
            Address: 0x1000,
            TargetOrImmediate: 0,
            DestinationRegister: 1,
            DestinationWidth: 64,
            SourceRegister: 2));
        var ret = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Return,
            Address: 0x1004,
            TargetOrImmediate: 0));

        Assert.True(source.IsSuccess, source.Diagnostic);
        Assert.True(ret.IsSuccess, ret.Diagnostic);

        var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x2000,
            Family: Aarch64InstructionEncodingFamily.MoveRegister,
            TargetOrImmediate: 0,
            OutputTemplateEncoding: ret.Encoding,
            RegisterWidth: 64));

        Assert.False(result.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily, result.DiagnosticCode);
        Assert.Equal(0u, result.Encoding);
    }

    [Fact]
    public void RejectsReturnTemplateThatIsNotCanonicalRet()
    {
        var encoder = new Aarch64InstructionEncoder();
        var source = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Return,
            Address: 0x1000,
            TargetOrImmediate: 0));
        var other = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveRegister,
            Address: 0x1004,
            TargetOrImmediate: 0,
            DestinationRegister: 1,
            DestinationWidth: 64,
            SourceRegister: 2));

        Assert.True(source.IsSuccess, source.Diagnostic);
        Assert.True(other.IsSuccess, other.Diagnostic);

        var result = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
            source.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x2000,
            Family: Aarch64InstructionEncodingFamily.Return,
            TargetOrImmediate: 0,
            OutputTemplateEncoding: other.Encoding,
            RegisterWidth: 64));

        Assert.False(result.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.UnsupportedInstructionFamily, result.DiagnosticCode);
        Assert.Equal(0u, result.Encoding);
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
