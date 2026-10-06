using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class Aarch64SemanticPlanValidatorTests
{
    [Fact]
    public void ValidatesFinalInstructionRoundTripAtPlannedOutputAddress()
    {
        var (plan, resolution) = CreateBranchPlan();

        var result = Aarch64SemanticPlanValidator.Validate(
            plan,
            resolution,
            new AsmStoneAdapter());

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var validation = Assert.Single(result.Fixups);
        Assert.True(validation.IsValidated, Describe(validation.Diagnostics));
        Assert.Empty(result.Diagnostics);
    }

    [Fact]
    public void ReportsDecoderFailureWithoutProducingAValidationSuccess()
    {
        var (plan, resolution) = CreateBranchPlan();
        var decoder = new AsmStoneAdapter((_, _) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.UnknownEncoding,
            null,
            "synthetic decoder failure"));

        var result = Aarch64SemanticPlanValidator.Validate(plan, resolution, decoder);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.UnknownInstruction);
        Assert.False(Assert.Single(result.Fixups).IsValidated);
    }

    [Fact]
    public void ReportsPostEncodeTargetMismatch()
    {
        var (plan, resolution) = CreateBranchPlan();
        var decoder = new AsmStoneAdapter((encoding, address) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.Decoded,
            new Aarch64Instruction(
                address,
                encoding,
                "B",
                Aarch64InstructionProperties.Branch
                    | Aarch64InstructionProperties.PcRelative
                    | Aarch64InstructionProperties.Terminator,
                Aarch64ControlFlowKind.DirectBranch,
                0x5020),
            string.Empty));

        var result = Aarch64SemanticPlanValidator.Validate(plan, resolution, decoder);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed
                && diagnostic.Message.Contains("target", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RejectsPostEncodePcRelativeInstructionWithoutDecodedTarget()
    {
        var (plan, resolution) = CreateBranchPlan();
        var decoder = new AsmStoneAdapter((encoding, address) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.Decoded,
            new Aarch64Instruction(
                address,
                encoding,
                "B",
                Aarch64InstructionProperties.Branch
                    | Aarch64InstructionProperties.PcRelative
                    | Aarch64InstructionProperties.Terminator,
                Aarch64ControlFlowKind.DirectBranch,
                null),
            string.Empty));

        var result = Aarch64SemanticPlanValidator.Validate(plan, resolution, decoder);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticTargetUnresolved);
        Assert.False(Assert.Single(result.Fixups).IsValidated);
    }

    [Fact]
    public void RejectsPostEncodeInstructionFamilyMismatch()
    {
        var (plan, resolution) = CreateBranchPlan();
        var decoder = new AsmStoneAdapter((encoding, address) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.Decoded,
            new Aarch64Instruction(
                address,
                encoding,
                "ADR",
                Aarch64InstructionProperties.PcRelative,
                Aarch64ControlFlowKind.None,
                0x5010)
            {
                Mnemonic = "adr",
            },
            string.Empty));

        var result = Aarch64SemanticPlanValidator.Validate(plan, resolution, decoder);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed
                && diagnostic.Message.Contains("instruction family", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RejectsResolutionTargetThatIsNotMappedByThePlan()
    {
        var (plan, resolution) = CreateBranchPlan();
        var original = Assert.Single(resolution.Fixups);
        var forged = new SemanticFixupResolution(
            original.Fixup,
            original.IsSuccess,
            original.IsDeferred,
            original.OutputSourceAddress,
            new VirtualAddress(0x5020),
            original.InstructionEncoding,
            original.RelocationValue,
            original.Diagnostics);
        var forgedResolution = new SemanticPlanResolutionResult(
            new[] { forged },
            resolution.Diagnostics);

        var result = Aarch64SemanticPlanValidator.Validate(
            plan,
            forgedResolution,
            new AsmStoneAdapter());

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanMalformed
                && diagnostic.Message.Contains("address map", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RejectsStaleSourceTargetAfterOutputRelocation()
    {
        var (plan, resolution) = CreateBranchPlan();
        var decoder = new AsmStoneAdapter((encoding, address) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.Decoded,
            new Aarch64Instruction(
                address,
                encoding,
                "B",
                Aarch64InstructionProperties.Branch
                    | Aarch64InstructionProperties.PcRelative
                    | Aarch64InstructionProperties.Terminator,
                Aarch64ControlFlowKind.DirectBranch,
                0x1010),
            string.Empty));

        var result = Aarch64SemanticPlanValidator.Validate(plan, resolution, decoder);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed
                && diagnostic.Message.Contains("resolved output target", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ReportsDeferredResolutionWithoutCallingTheDecoder()
    {
        var addressMapResult = AddressMap.Create(new[]
        {
            Mapping(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                0x1000,
                0x200,
                0x5000,
                0x800),
            Mapping(
                SemanticEntityId.BasicBlock("target-a"),
                0x1010,
                0x210,
                0x5010,
                0x810),
            Mapping(
                SemanticEntityId.BasicBlock("target-b"),
                0x1020,
                0x220,
                0x5020,
                0x820),
        });
        Assert.True(addressMapResult.IsSuccess, Describe(addressMapResult.Diagnostics));

        var target = SemanticTarget.BoundedSet(new[]
        {
            new VirtualAddress(0x1010),
            new VirtualAddress(0x1020),
        });
        var fixup = new SemanticFixup(
            SemanticFixupKind.Branch26,
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x14000000,
            target,
            expression: new PcRelativeExpression(
                PcRelativeExpressionKind.Branch26,
                new VirtualAddress(0x1000),
                target,
                Scale: sizeof(uint)));
        var planResult = SemanticRewritePlanBuilder.Build(
            addressMapResult.Map!,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });
        Assert.True(planResult.IsSuccess, Describe(planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        var decodeCalls = 0;
        var decoder = new AsmStoneAdapter((_, _) =>
        {
            decodeCalls++;
            return new Aarch64DecodeResult(
                Aarch64DecodeStatus.UnknownEncoding,
                null,
                "decoder must not be called for deferred fixups");
        });

        var result = Aarch64SemanticPlanValidator.Validate(
            planResult.Plan,
            resolution,
            decoder);

        Assert.False(result.IsSuccess);
        Assert.True(result.HasDeferredFixups);
        Assert.Equal(0, decodeCalls);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupDeferred);
        Assert.True(Assert.Single(result.DeferredFixups).IsDeferred);
    }

    [Fact]
    public void ValidatesRelocationOnlyWidthAlignmentAndDomainWithoutDecoding()
    {
        var addressMapResult = AddressMap.Create(new[]
        {
            Mapping(
                SemanticEntityId.RelocationSite("site"),
                0x1000,
                0x200,
                0x5000,
                0x800,
                size: sizeof(ulong)),
            Mapping(
                SemanticEntityId.RelocationTarget("target"),
                0x1010,
                0x210,
                0x6010,
                0x810,
                size: sizeof(ulong)),
        });
        Assert.True(addressMapResult.IsSuccess, Describe(addressMapResult.Diagnostics));

        var binding = new RelocationBinding(
            Aarch64RelocationKind.Absolute64,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            Addend: 4);
        var fixup = SemanticFixup.FromRelocation(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0,
            binding);
        var planResult = SemanticRewritePlanBuilder.Build(
            addressMapResult.Map!,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });
        Assert.True(planResult.IsSuccess, Describe(planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        var decodeCalls = 0;
        var decoder = new AsmStoneAdapter((_, _) =>
        {
            decodeCalls++;
            return new Aarch64DecodeResult(
                Aarch64DecodeStatus.UnknownEncoding,
                null,
                "relocation-only fixups do not decode");
        });

        var result = Aarch64SemanticPlanValidator.Validate(
            planResult.Plan,
            resolution,
            decoder);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.Equal(0, decodeCalls);
        var validation = Assert.Single(result.Fixups);
        Assert.Null(validation.Resolution.InstructionEncoding);
        Assert.Equal(0x6014UL, validation.Resolution.RelocationValue);

        var original = Assert.Single(resolution.Fixups);
        var forgedInstructionEncoding = new SemanticFixupResolution(
            original.Fixup,
            original.IsSuccess,
            original.IsDeferred,
            original.OutputSourceAddress,
            original.OutputTargetAddress,
            0xD503201Fu,
            original.RelocationValue,
            original.Diagnostics);
        var forgedEncodingValidation = Aarch64SemanticPlanValidator.Validate(
            planResult.Plan,
            new SemanticPlanResolutionResult(
                new[] { forgedInstructionEncoding },
                resolution.Diagnostics),
            decoder);

        Assert.False(forgedEncodingValidation.IsSuccess);
        Assert.Contains(
            forgedEncodingValidation.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed
                && diagnostic.Message.Contains("cannot carry an instruction encoding", StringComparison.OrdinalIgnoreCase));

        var forged = new SemanticFixupResolution(
            original.Fixup,
            original.IsSuccess,
            original.IsDeferred,
            original.OutputSourceAddress,
            original.OutputTargetAddress,
            original.InstructionEncoding,
            0xDEAD_BEEFUL,
            original.Diagnostics);
        var forgedResult = Aarch64SemanticPlanValidator.Validate(
            planResult.Plan,
            new SemanticPlanResolutionResult(new[] { forged }, resolution.Diagnostics),
            decoder);

        Assert.False(forgedResult.IsSuccess);
        Assert.Contains(
            forgedResult.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanMalformed
                && diagnostic.Message.Contains("symbolic relocation value", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidatesInstructionRelocationImmediateWithoutWritingElfBytes()
    {
        var mapResult = AddressMap.Create(new[]
        {
            Mapping(
                SemanticEntityId.RelocationSite("site"),
                0x1000,
                0x200,
                0x5000,
                0x800),
            Mapping(
                SemanticEntityId.RelocationTarget("target"),
                0x1010,
                0x210,
                0x6010,
                0x810),
        });
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));

        var binding = new RelocationBinding(
            Aarch64RelocationKind.AddAbsLo12,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            RelocationType: ElfConstants.RArm64AddAbsLo12Nc);
        var fixup = SemanticFixup.FromRelocation(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x91000000,
            binding);
        var planResult = SemanticRewritePlanBuilder.Build(
            mapResult.Map!,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });
        Assert.True(planResult.IsSuccess, Describe(planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        var validation = Aarch64SemanticPlanValidator.Validate(
            planResult.Plan,
            resolution,
            new AsmStoneAdapter());
        Assert.True(validation.IsSuccess, Describe(validation.Diagnostics));

        var resolved = Assert.Single(resolution.Fixups);
        var forged = new SemanticFixupResolution(
            resolved.Fixup,
            resolved.IsSuccess,
            resolved.IsDeferred,
            resolved.OutputSourceAddress,
            resolved.OutputTargetAddress,
            0x91008000u,
            resolved.RelocationValue,
            resolved.Diagnostics);
        var forgedValidation = Aarch64SemanticPlanValidator.Validate(
            planResult.Plan,
            new SemanticPlanResolutionResult(new[] { forged }, resolution.Diagnostics),
            new AsmStoneAdapter());

        Assert.False(forgedValidation.IsSuccess);
        Assert.Contains(
            forgedValidation.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed
                && diagnostic.Message.Contains("low-12 immediate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidationCollectionsAreDefensivelyCopied()
    {
        var (plan, resolution) = CreateBranchPlan();
        var result = Aarch64SemanticPlanValidator.Validate(
            plan,
            resolution,
            new AsmStoneAdapter());

        Assert.Throws<NotSupportedException>(() =>
            ((IList<SemanticFixupValidationResult>)result.Fixups)[0] =
                Assert.Single(result.Fixups));
        Assert.Throws<NotSupportedException>(() =>
            ((IList<Diagnostic>)result.Diagnostics).Add(
                new Diagnostic(DiagnosticSeverity.Info, DiagnosticCode.None, "mutation")));
    }

    private static (SemanticRewritePlan Plan, SemanticPlanResolutionResult Resolution) CreateBranchPlan()
    {
        var mapResult = AddressMap.Create(new[]
        {
            Mapping(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                0x1000,
                0x200,
                0x5000,
                0x800),
            Mapping(
                SemanticEntityId.BasicBlock("target"),
                0x1010,
                0x210,
                0x5010,
                0x810),
        });
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));

        var target = SemanticTarget.Exact(new VirtualAddress(0x1010));
        var fixup = new SemanticFixup(
            SemanticFixupKind.Branch26,
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x14000000,
            target,
            expression: new PcRelativeExpression(
                PcRelativeExpressionKind.Branch26,
                new VirtualAddress(0x1000),
                target,
                Scale: sizeof(uint)));
        var planResult = SemanticRewritePlanBuilder.Build(
            mapResult.Map!,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });
        Assert.True(planResult.IsSuccess, Describe(planResult.Diagnostics));

        var plan = planResult.Plan!;
        return (plan, plan.ResolveFixups());
    }

    private static AddressMapEntry Mapping(
        SemanticEntityId identity,
        ulong sourceAddress,
        ulong sourceFileOffset,
        ulong outputAddress,
        ulong outputFileOffset,
        ulong size = sizeof(uint)) =>
        new(
            identity,
            new SemanticSourceRange(
                new FileOffset(sourceFileOffset),
                new VirtualAddress(sourceAddress),
                size),
            new SemanticSourceRange(
                new FileOffset(outputFileOffset),
                new VirtualAddress(outputAddress),
                size));

    private static string Describe(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(Environment.NewLine, diagnostics);
}
