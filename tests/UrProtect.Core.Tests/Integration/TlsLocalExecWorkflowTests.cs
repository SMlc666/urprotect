using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Infrastructure.Rehydration;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Tests.Structural;

namespace UrProtect.Core.Tests.Integration;

public sealed class TlsLocalExecWorkflowTests
{
    private static readonly string ProducerBuild = new('a', 64);
    private static readonly string ConsumerBuild = new('b', 64);
    private static readonly int[] PairOrdinals = { 0, 1 };
    private static readonly uint[] LocalExecMovwRelocationTypes =
    {
        ElfConstants.RArm64TlsLeMovwTprelG1,
        ElfConstants.RArm64TlsLeMovwTprelG0Nc,
    };
    private static readonly uint[] LocalExecLdst32RelocationTypes =
    {
        ElfConstants.RArm64TlsLeAddTprelHi12,
        ElfConstants.RArm64TlsLeLdst32TprelLo12Nc,
    };

    private static readonly uint[] InitialExecMovwRelocationTypes =
    {
        ElfConstants.RArm64TlsIeMovwGottprelG1,
        ElfConstants.RArm64TlsIeMovwGottprelG0Nc,
    };

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void SelectedLocalExecFunctionFlowsThroughSnapshotSharedLayoutAndReparse()
    {
        var setup = CreateEmission();
        var planning = new FunctionProtectionService().Plan(setup.Source, setup.Request);

        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        var semanticSnapshot = Assert.IsType<SemanticPlanSnapshot>(planning.Plan!.SemanticSnapshot);
        var binding = Assert.IsType<SemanticTlsBindingExtension>(Assert.Single(
            semanticSnapshot.Extensions.OfType<SemanticTlsBindingExtension>())).Binding;
        Assert.Equal(TlsAccessModel.LocalExec, binding.AccessModel);
        Assert.Equal(TlsAddressExpressionKind.ThreadPointerRelative, binding.AddressExpression.Kind);
        Assert.Equal(4UL, binding.Module.Template!.ZeroFillSize);
        Assert.Equal(2, TlsSemanticFixupPlanner.Build(semanticSnapshot.Plan).Fixups.Count);

        var artifact = ProtectedImageCodec.Decode(
            setup.Emission.ArtifactBytes!,
            setup.SourceHash,
            setup.RequestHash);
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));
        Assert.Single(artifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());

        var rehydration = GenericRehydrationEngine.Rehydrate(
            setup.Source,
            setup.Emission.ArtifactBytes!,
            setup.RehydrationOptions);

        Assert.True(rehydration.IsSuccess, string.Join(Environment.NewLine, rehydration.Diagnostics));
        var sourceFile = Assert.IsType<ElfFile>(ElfParser.Parse(setup.Source).File);
        var outputFile = rehydration.NativeImage!.ParsedImage;
        var sourceTls = Assert.Single(sourceFile.TlsMetadata.Segments);
        var outputTls = Assert.Single(outputFile.TlsMetadata.Segments);
        Assert.Equal(sourceTls.FileSize, outputTls.FileSize);
        Assert.Equal(sourceTls.MemorySize, outputTls.MemorySize);
        Assert.Equal(sourceTls.ZeroFillSize, outputTls.ZeroFillSize);
        Assert.Equal(sourceTls.Alignment, outputTls.Alignment);
        Assert.Equal(sourceTls.InitializedTemplate.ToArray(), outputTls.InitializedTemplate.ToArray());
        Assert.Equal(sourceFile.TlsMetadata.StaticRelocations, outputFile.TlsMetadata.StaticRelocations);
        Assert.Equal(2, rehydration.NativeImage.LayoutEvidence!.TlsFixups.Count);

        foreach (var fixup in rehydration.NativeImage.LayoutEvidence.TlsFixups)
        {
            Assert.Equal(TlsAccessModel.LocalExec, fixup.Fixup.AccessModel);
            Assert.Equal(TlsAddressExpressionKind.ThreadPointerRelative, fixup.Fixup.AddressExpression.Kind);
            Assert.True(outputFile.LoadMap.TryVirtualAddressToFileOffset(
                fixup.OutputVirtualAddress,
                sizeof(uint),
                out var outputOffset));
            Assert.Equal(fixup.OutputFileOffset, outputOffset);
            Assert.Equal(fixup.OutputEncoding, BinaryPrimitives.ReadUInt32LittleEndian(
                rehydration.NativeImage.Bytes.AsSpan(checked((int)outputOffset.Value), sizeof(uint))));
        }
    }

    [Fact]
    [Trait("Category", "TlsInitialExec")]
    public void SelectedInitialExecMovwPairFlowsThroughSnapshotSharedLayoutGotPreservationAndReparse()
    {
        var setup = CreateEmission(
            ElfFixture.TlsInitialExecMovwFunctionPie(),
            "tls.initial-exec.fixture",
            "tls.initial-exec.producer");
        var planning = new FunctionProtectionService().Plan(setup.Source, setup.Request);

        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        var snapshot = Assert.IsType<SemanticPlanSnapshot>(planning.Plan!.SemanticSnapshot);
        var binding = Assert.IsType<SemanticTlsBindingExtension>(Assert.Single(
            snapshot.Extensions.OfType<SemanticTlsBindingExtension>())).Binding;
        Assert.Equal(TlsAccessModel.InitialExec, binding.AccessModel);
        Assert.Equal(InitialExecMovwRelocationTypes, binding.RelocationSites.Select(site => site.Binding.RelocationType!.Value));
        Assert.NotNull(binding.GotEntry);
        Assert.Equal(ElfConstants.RArm64TlsTprel64, binding.GotEntry!.Relocation.RelocationType);
        Assert.Equal(2, TlsSemanticFixupPlanner.Build(snapshot.Plan).Fixups.Count);

        Assert.Single(ProtectedImageCodec.Decode(
            setup.Emission.ArtifactBytes!,
            setup.SourceHash,
            setup.RequestHash).Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var rehydration = GenericRehydrationEngine.Rehydrate(
            setup.Source,
            setup.Emission.ArtifactBytes!,
            setup.RehydrationOptions);

        Assert.True(rehydration.IsSuccess, string.Join(Environment.NewLine, rehydration.Diagnostics));
        var sourceFile = Assert.IsType<ElfFile>(ElfParser.Parse(setup.Source).File);
        var outputFile = rehydration.NativeImage!.ParsedImage;
        Assert.Equal(sourceFile.TlsMetadata.StaticRelocations, outputFile.TlsMetadata.StaticRelocations);
        Assert.Equal(2, rehydration.NativeImage.LayoutEvidence!.TlsFixups.Count);
        Assert.All(rehydration.NativeImage.LayoutEvidence.TlsFixups, fixup =>
        {
            Assert.Equal(TlsAccessModel.InitialExec, fixup.Fixup.AccessModel);
            Assert.Equal(ElfConstants.RArm64TlsTprel64, fixup.Fixup.GotEntry!.Relocation.RelocationType);
        });

        Assert.True(outputFile.LoadMap.TryVirtualAddressToFileOffset(
            binding.GotEntry.SourceRange.VirtualAddress,
            sizeof(ulong),
            out var outputGotOffset));
        Assert.Equal(binding.GotEntry.SourceRange.FileOffset, outputGotOffset);
        Assert.Equal(
            setup.Source.AsSpan(checked((int)binding.GotEntry.SourceRange.FileOffset.Value), sizeof(ulong)).ToArray(),
            rehydration.NativeImage.Bytes.AsSpan(checked((int)outputGotOffset.Value), sizeof(ulong)).ToArray());
    }

    [Fact]
    [Trait("Category", "TlsInitialExec")]
    public void RejectsInitialExecAdrGotprelFormBeforePlanning()
    {
        var source = ElfFixture.TlsInitialExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(
            source.AsSpan(0x620),
            (1UL << 32) | ElfConstants.RArm64TlsIeAdrGottprelPage21);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSemanticsUnsupported);
    }

    [Theory]
    [InlineData(ElfConstants.RArm64TlsIeMovwGottprelG0Nc, ElfConstants.RArm64TlsIeMovwGottprelG1)]
    [Trait("Category", "TlsInitialExec")]
    public void RejectsInitialExecWrongPairOrderBeforePlanning(uint firstType, uint secondType)
    {
        var source = ElfFixture.TlsInitialExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(source.AsSpan(0x620), (1UL << 32) | firstType);
        BinaryPrimitives.WriteUInt64LittleEndian(source.AsSpan(0x638), (1UL << 32) | secondType);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSemanticsUnsupported);
    }

    [Theory]
    [InlineData(0x200, 0xD2A0000Au)]
    [InlineData(0x204, 0xF280000Au)]
    [InlineData(0x210, 0xF9400128u)]
    [Trait("Category", "TlsInitialExec")]
    public void RejectsInitialExecWrongMovwOpcodeShiftOrRegister(uint fileOffset, uint encoding)
    {
        var source = ElfFixture.TlsInitialExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(checked((int)fileOffset)), encoding);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsInitialExec")]
    public void RejectsInitialExecMissingOrOverlappingGotOwnership()
    {
        var missing = ElfFixture.TlsInitialExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(missing.AsSpan(0x608), (1UL << 32) | ElfConstants.RArm64Abs64);
        var missingPlan = new FunctionProtectionService().Plan(
            missing,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));
        Assert.False(missingPlan.IsSuccess);
        Assert.Contains(missingPlan.Diagnostics, diagnostic => diagnostic.Code is DiagnosticCode.TlsBindingUnresolved or DiagnosticCode.TlsSemanticsUnsupported);

        var overlapping = ElfFixture.TlsInitialExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(overlapping.AsSpan(0x600), 0x1200);
        var overlappingPlan = new FunctionProtectionService().Plan(
            overlapping,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));
        Assert.False(overlappingPlan.IsSuccess);
        Assert.Contains(overlappingPlan.Diagnostics, diagnostic => diagnostic.Code is DiagnosticCode.TlsMetadataMalformed or DiagnosticCode.TlsBindingUnresolved);
    }

    [Theory]
    [InlineData(ElfConstants.RArm64TlsLeLdst32TprelLo12, ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)]
    [Trait("Category", "TlsLocalExec")]
    public void UnsupportedLocalExecLoadStorePairsFailBeforeArtifactEmission(
        uint firstRelocationType,
        uint secondRelocationType)
    {
        var source = ElfFixture.TlsLocalExecFunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(
            source.AsSpan(0x608),
            (1UL << 32) | firstRelocationType);
        BinaryPrimitives.WriteUInt64LittleEndian(
            source.AsSpan(0x620),
            (1UL << 32) | secondRelocationType);
        var selectors = new[] { FunctionSelector.ByName("tls_fixture") };
        var passes = new[] { ProtectionPass.RegisterPermutation };
        var request = new FunctionProtectionOptions(selectors, passes);
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(selectors, passes);

        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            new ProtectedImageProducerOptions(
                "tls.local-exec.unsupported",
                ProtectedImageProfile.OuterExecveat,
                "tls.local-exec.producer",
                ProducerBuild,
                ProtectedImageAbiV1.DefaultRehydratorConsumerId,
                sourceHash,
                requestHash));

        Assert.False(emission.IsSuccess);
        Assert.Null(emission.ArtifactBytes);
        Assert.Contains(emission.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSemanticsUnsupported);
    }

    [Theory]
    [InlineData(1L, false)]
    [InlineData(-1L, true)]
    [Trait("Category", "TlsLocalExec")]
    public void SelectedLocalExecMovwPairFlowsThroughCanonicalSnapshotSharedLayoutAndReparse(
        long addend,
        bool useMovn)
    {
        var setup = CreateEmission(ElfFixture.TlsLocalExecMovwFunctionPie(addend, useMovn));
        var planning = new FunctionProtectionService().Plan(setup.Source, setup.Request);

        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        var semanticSnapshot = Assert.IsType<SemanticPlanSnapshot>(planning.Plan!.SemanticSnapshot);
        var binding = Assert.IsType<SemanticTlsBindingExtension>(Assert.Single(
            semanticSnapshot.Extensions.OfType<SemanticTlsBindingExtension>())).Binding;
        Assert.Equal(TlsAccessModel.LocalExec, binding.AccessModel);
        Assert.Equal(TlsAddressExpressionKind.ThreadPointerRelative, binding.AddressExpression.Kind);
        Assert.Equal(addend, binding.Addend);
        Assert.Equal(LocalExecMovwRelocationTypes, binding.RelocationSites.Select(site => site.Binding.RelocationType!.Value));
        Assert.Equal(PairOrdinals, binding.RelocationSites.Select(site => site.PairOrdinal));
        Assert.All(binding.RelocationSites, site => Assert.Equal(addend, site.Binding.Addend));
        Assert.Equal(2, TlsSemanticFixupPlanner.Build(semanticSnapshot.Plan).Fixups.Count);

        var artifact = ProtectedImageCodec.Decode(
            setup.Emission.ArtifactBytes!,
            setup.SourceHash,
            setup.RequestHash);
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));
        Assert.Single(artifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());

        var rehydration = GenericRehydrationEngine.Rehydrate(
            setup.Source,
            setup.Emission.ArtifactBytes!,
            setup.RehydrationOptions);

        Assert.True(rehydration.IsSuccess, string.Join(Environment.NewLine, rehydration.Diagnostics));
        var sourceFile = Assert.IsType<ElfFile>(ElfParser.Parse(setup.Source).File);
        var outputFile = rehydration.NativeImage!.ParsedImage;
        var sourceTls = Assert.Single(sourceFile.TlsMetadata.Segments);
        var outputTls = Assert.Single(outputFile.TlsMetadata.Segments);
        Assert.Equal(sourceTls.InitializedTemplate.ToArray(), outputTls.InitializedTemplate.ToArray());
        Assert.Equal(sourceTls.ZeroFillSize, outputTls.ZeroFillSize);
        Assert.Equal(sourceTls.Alignment, outputTls.Alignment);
        Assert.Equal(sourceFile.TlsMetadata.StaticRelocations, outputFile.TlsMetadata.StaticRelocations);

        var fixups = rehydration.NativeImage.LayoutEvidence!.TlsFixups
            .OrderBy(fixup => fixup.Fixup.PairOrdinal)
            .ToArray();
        Assert.Equal(2, fixups.Length);
        Assert.Equal(PairOrdinals, fixups.Select(fixup => fixup.Fixup.PairOrdinal));
        Assert.Equal(addend, fixups[0].Fixup.Addend);
        Assert.Equal(addend, fixups[1].Fixup.Addend);
        const uint immediateMask = 0x001F_FFE0;
        const uint opcodeAndShiftMask = 0xFFE0_0000;
        var sourceFirst = BinaryPrimitives.ReadUInt32LittleEndian(setup.Source.AsSpan(0x200, sizeof(uint)));
        var sourceSecond = BinaryPrimitives.ReadUInt32LittleEndian(setup.Source.AsSpan(0x204, sizeof(uint)));
        var outputFirst = fixups[0].OutputEncoding;
        var outputSecond = fixups[1].OutputEncoding;
        Assert.Equal(sourceFirst & immediateMask, outputFirst & immediateMask);
        Assert.Equal(sourceSecond & immediateMask, outputSecond & immediateMask);
        Assert.Equal(sourceFirst & opcodeAndShiftMask, outputFirst & opcodeAndShiftMask);
        Assert.Equal(sourceSecond & opcodeAndShiftMask, outputSecond & opcodeAndShiftMask);
        Assert.Equal((byte)(outputFirst & 0x1F), (byte)(outputSecond & 0x1F));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("Category", "TlsLocalExec")]
    public void SelectedLocalExecLdst32PairFlowsThroughCanonicalSnapshotSharedLayoutAndReparse(bool useStore)
    {
        var setup = CreateEmission(ElfFixture.TlsLocalExecLdst32FunctionPie(useStore));
        var planning = new FunctionProtectionService().Plan(setup.Source, setup.Request);

        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        var semanticSnapshot = Assert.IsType<SemanticPlanSnapshot>(planning.Plan!.SemanticSnapshot);
        var binding = Assert.IsType<SemanticTlsBindingExtension>(Assert.Single(
            semanticSnapshot.Extensions.OfType<SemanticTlsBindingExtension>())).Binding;
        Assert.Equal(TlsAccessModel.LocalExec, binding.AccessModel);
        Assert.Equal(TlsRelocationFamily.Tprel, binding.RelocationFamily);
        Assert.Equal(TlsAddressExpressionKind.ThreadPointerRelative, binding.AddressExpression.Kind);
        Assert.Equal(4UL, binding.Module.Template!.ZeroFillSize);
        Assert.Equal(
            LocalExecLdst32RelocationTypes,
            binding.RelocationSites.Select(site => site.Binding.RelocationType!.Value));
        Assert.Equal(PairOrdinals, binding.RelocationSites.Select(site => site.PairOrdinal));
        Assert.Equal(2, TlsSemanticFixupPlanner.Build(semanticSnapshot.Plan).Fixups.Count);

        var artifact = ProtectedImageCodec.Decode(
            setup.Emission.ArtifactBytes!,
            setup.SourceHash,
            setup.RequestHash);
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));
        Assert.Single(artifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());

        var rehydration = GenericRehydrationEngine.Rehydrate(
            setup.Source,
            setup.Emission.ArtifactBytes!,
            setup.RehydrationOptions);

        Assert.True(rehydration.IsSuccess, string.Join(Environment.NewLine, rehydration.Diagnostics));
        var sourceFile = Assert.IsType<ElfFile>(ElfParser.Parse(setup.Source).File);
        var outputFile = rehydration.NativeImage!.ParsedImage;
        var sourceTls = Assert.Single(sourceFile.TlsMetadata.Segments);
        var outputTls = Assert.Single(outputFile.TlsMetadata.Segments);
        Assert.Equal(sourceTls.InitializedTemplate.ToArray(), outputTls.InitializedTemplate.ToArray());
        Assert.Equal(sourceTls.ZeroFillSize, outputTls.ZeroFillSize);
        Assert.Equal(sourceTls.Alignment, outputTls.Alignment);
        Assert.Equal(sourceFile.TlsMetadata.StaticRelocations, outputFile.TlsMetadata.StaticRelocations);

        var fixups = rehydration.NativeImage.LayoutEvidence!.TlsFixups
            .OrderBy(fixup => fixup.Fixup.PairOrdinal)
            .ToArray();
        Assert.Equal(2, fixups.Length);
        Assert.Equal(PairOrdinals, fixups.Select(fixup => fixup.Fixup.PairOrdinal));
        Assert.Equal(
            LocalExecLdst32RelocationTypes,
            fixups.Select(fixup => fixup.Fixup.Relocation.RelocationType!.Value));

        var sourceAdd = BinaryPrimitives.ReadUInt32LittleEndian(setup.Source.AsSpan(0x204, sizeof(uint)));
        var sourceLdst = BinaryPrimitives.ReadUInt32LittleEndian(setup.Source.AsSpan(0x208, sizeof(uint)));
        var outputAdd = fixups[0].OutputEncoding;
        var outputLdst = fixups[1].OutputEncoding;
        const uint immediateMask = 0x003F_FC00;
        const uint ldstOpcodeMask = 0x3FC0_0000;
        Assert.Equal(sourceAdd & immediateMask, outputAdd & immediateMask);
        Assert.Equal(sourceLdst & immediateMask, outputLdst & immediateMask);
        Assert.Equal(1u, (sourceLdst >> 10) & 0xFFF);
        Assert.Equal(sourceLdst & ldstOpcodeMask, outputLdst & ldstOpcodeMask);
        Assert.Equal((byte)(outputAdd & 0x1F), (byte)((outputLdst >> 5) & 0x1F));
    }

    [Theory]
    [InlineData(0xF9400520u)] // LDR X0: width/scale eight, not LDST32.
    [InlineData(0x39400520u)] // LDRB W0: width/scale one, not LDST32.
    [InlineData(0xB8400520u)] // LDUR W0: unscaled opcode, not unsigned-immediate LDST32.
    [InlineData(0xB9400100u)] // LDR W0, [X8]: base register is not the ADD destination.
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecLdst32WrongWidthScaleOrOpcode(uint encoding)
    {
        var source = ElfFixture.TlsLocalExecLdst32FunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(0x208), encoding);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecLdst32WhenTheScaledLowImmediateDoesNotMatchTheTlsOffset()
    {
        var source = ElfFixture.TlsLocalExecLdst32FunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(0x208), 0xB9400120u);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecLdst32CheckedWidthUntilItsOwnPairIsImplemented()
    {
        var source = ElfFixture.TlsLocalExecLdst32FunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(
            source.AsSpan(0x620),
            (1UL << 32) | ElfConstants.RArm64TlsLeLdst64TprelLo12Nc);
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(0x208), 0xF9400520u);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSemanticsUnsupported);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecLdst32UnalignedSymbolAndAddend()
    {
        var source = ElfFixture.TlsLocalExecLdst32FunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(source.AsSpan(0x520), 1);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecLdst32PairOrderAndAddendMismatch()
    {
        var reversed = ElfFixture.TlsLocalExecLdst32FunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(
            reversed.AsSpan(0x608),
            (1UL << 32) | ElfConstants.RArm64TlsLeLdst32TprelLo12Nc);
        BinaryPrimitives.WriteUInt64LittleEndian(
            reversed.AsSpan(0x620),
            (1UL << 32) | ElfConstants.RArm64TlsLeAddTprelHi12);
        var reversedPlan = new FunctionProtectionService().Plan(
            reversed,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));
        Assert.False(reversedPlan.IsSuccess);
        Assert.Null(reversedPlan.Plan);
        Assert.Contains(reversedPlan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);

        var mismatchedAddend = ElfFixture.TlsLocalExecLdst32FunctionPie();
        BinaryPrimitives.WriteInt64LittleEndian(mismatchedAddend.AsSpan(0x628), 1);
        var addendPlan = new FunctionProtectionService().Plan(
            mismatchedAddend,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));
        Assert.False(addendPlan.IsSuccess);
        Assert.Null(addendPlan.Plan);
        Assert.Contains(addendPlan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Theory]
    [InlineData(0x208UL, 4UL)]
    [InlineData(0x208UL, 8UL)]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecLdst32SourceToSnapshotMismatch(ulong relocationOffset, ulong addend)
    {
        var setup = CreateEmission(ElfFixture.TlsLocalExecLdst32FunctionPie());
        var changedSource = setup.Source.ToArray();
        var relocationEntry = relocationOffset == 0x208UL ? 1UL : 0UL;
        BinaryPrimitives.WriteInt64LittleEndian(
            changedSource.AsSpan(0x600 + checked((int)(relocationEntry * ElfConstants.RelaEntrySize64)) + 16),
            checked((long)addend));
        var changedHash = Sha256(changedSource);
        var image = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image! with
        {
            SourceSha256 = changedHash,
        };
        var artifact = ProtectedImageCodec.Encode(image);
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));

        var result = GenericRehydrationEngine.Rehydrate(
            changedSource,
            artifact.ArtifactBytes!,
            setup.RehydrationOptions with { ExpectedSourceSha256 = changedHash });

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsBindingUnresolved);
    }

    [Theory]
    [InlineData(ElfConstants.RArm64TlsLeMovwTprelG2, ElfConstants.RArm64TlsLeMovwTprelG0Nc)]
    [InlineData(ElfConstants.RArm64TlsLeMovwTprelG1Nc, ElfConstants.RArm64TlsLeMovwTprelG0Nc)]
    [InlineData(ElfConstants.RArm64TlsLeMovwTprelG1, ElfConstants.RArm64TlsLeMovwTprelG0)]
    [Trait("Category", "TlsLocalExec")]
    public void UnsupportedLocalExecMovwRelocationFormsFailClosed(
        uint firstRelocationType,
        uint secondRelocationType)
    {
        var source = ElfFixture.TlsLocalExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(source.AsSpan(0x608), (1UL << 32) | firstRelocationType);
        BinaryPrimitives.WriteUInt64LittleEndian(source.AsSpan(0x620), (1UL << 32) | secondRelocationType);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSemanticsUnsupported);
    }

    [Theory]
    [InlineData(0x200, 0xF2A00009u)]
    [InlineData(0x200, 0xD2800009u)]
    [InlineData(0x204, 0xD2800009u)]
    [InlineData(0x204, 0xF2A00009u)]
    [InlineData(0x204, 0xF280000Au)]
    [InlineData(0x208, 0xD53BD04Bu)]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecMovwOpcodeShiftOrRegisterMismatch(int fileOffset, uint encoding)
    {
        var source = ElfFixture.TlsLocalExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(fileOffset), encoding);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsInterleavedLocalExecMovwRelocationPair()
    {
        var source = ElfFixture.TlsLocalExecMovwFunctionPie(interleavePair: true);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecMovwPairWhenTpAndTprelRegistersAlias()
    {
        var source = ElfFixture.TlsLocalExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(0x208), 0xD53BD049u); // MRS x9, TPIDR_EL0
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(0x20C), 0x8B090129u); // ADD x9, x9, x9
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecMovwPairWhenSecondRelocationLosesSymbolIdentity()
    {
        var source = ElfFixture.TlsLocalExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt64LittleEndian(
            source.AsSpan(0x620),
            ElfConstants.RArm64TlsLeMovwTprelG0Nc);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsBindingUnresolved);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecMovwRelocationPairWithMismatchedAddends()
    {
        var source = ElfFixture.TlsLocalExecMovwFunctionPie(1);
        BinaryPrimitives.WriteInt64LittleEndian(source.AsSpan(0x600 + ElfConstants.RelaEntrySize64 + 16), -1);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsCanonicalLocalExecMovwSnapshotWithMismatchedPairDestination()
    {
        var setup = CreateEmission(ElfFixture.TlsLocalExecMovwFunctionPie());
        var artifact = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var snapshot = SemanticPlanSnapshotCodec.Decode(
            artifact.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().Single().CanonicalBytes).Snapshot!;
        var original = snapshot.Extensions.OfType<SemanticTlsBindingExtension>().Single().Binding;
        var instructions = original.InstructionSequence.Instructions.ToArray();
        instructions[1] = instructions[1] with { Encoding = 0xF280000A };
        var invalidBinding = new TlsBinding(
            original.AccessModel,
            original.RelocationFamily,
            original.SourceIdentity,
            original.SourceRange,
            original.InstructionSequence with { Instructions = instructions },
            original.Module,
            original.Symbol,
            original.Addend,
            original.RelocationSites,
            original.AccessSize,
            original.AddressExpression,
            original.ProfileRequirements,
            original.RuntimeRequirements);
        var invalidPlan = new SemanticRewritePlan(
            snapshot.AddressMap,
            snapshot.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Extensions
                .Where(extension => extension is not SemanticTlsBindingExtension)
                .Append(new SemanticTlsBindingExtension(invalidBinding)),
            snapshot.Diagnostics);

        var encoded = SemanticPlanSnapshotCodec.Create(invalidPlan);

        Assert.False(encoded.IsSuccess);
        Assert.Contains(encoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecLdst32FixupWithMismatchBetweenSemanticAndRequestedOutputOffsets()
    {
        var setup = CreateEmission(ElfFixture.TlsLocalExecLdst32FunctionPie());
        var artifact = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var snapshot = SemanticPlanSnapshotCodec.Decode(
            artifact.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().Single().CanonicalBytes).Snapshot!;
        var fixup = TlsSemanticFixupPlanner.Build(snapshot.Plan).Fixups[0];
        var regions = artifact.Operations.OfType<ProtectedImageEmitRegion>().ToArray();
        var regionRequests = regions.Select(region => new ElfLayoutRegionRequest(
            RegionIdentity(region.RegionId),
            RegionIdentity(region.RegionId),
            region.SourceAddress,
            region.SourceSize,
            region.CodeBytes)).ToArray();
        var branches = artifact.Operations.OfType<ProtectedImageEntryBranchFixup>()
            .Select(branch => new ElfLayoutBranchRequest(
                $"entry:{branch.SourceRegionId}:{branch.SourceOffset}",
                RegionIdentity(branch.SourceRegionId),
                RegionIdentity(branch.TargetRegionId),
                branch.SourceAddress,
                branch.SourceOffset,
                branch.TargetOffset))
            .ToArray();
        var parsed = ElfParser.Parse(setup.Source);
        Assert.NotNull(parsed.File);

        var planning = ElfLayoutPlanner.Plan(
            setup.Source,
            parsed.File!,
            regionRequests,
            branches,
            ElfLayoutOptions.Default,
            new[] { new ElfLayoutTlsFixupRequest(RegionIdentity(regions[0].RegionId), 0, fixup) });

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsLayoutMismatch);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecMovwFixupWithMismatchBetweenSemanticAndRequestedOutputOffsets()
    {
        var setup = CreateEmission(ElfFixture.TlsLocalExecMovwFunctionPie());
        var artifact = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var snapshot = SemanticPlanSnapshotCodec.Decode(
            artifact.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().Single().CanonicalBytes).Snapshot!;
        var fixup = TlsSemanticFixupPlanner.Build(snapshot.Plan).Fixups[0];
        var regions = artifact.Operations.OfType<ProtectedImageEmitRegion>().ToArray();
        var regionRequests = regions.Select(region => new ElfLayoutRegionRequest(
            RegionIdentity(region.RegionId),
            RegionIdentity(region.RegionId),
            region.SourceAddress,
            region.SourceSize,
            region.CodeBytes)).ToArray();
        var branches = artifact.Operations.OfType<ProtectedImageEntryBranchFixup>()
            .Select(branch => new ElfLayoutBranchRequest(
                $"entry:{branch.SourceRegionId}:{branch.SourceOffset}",
                RegionIdentity(branch.SourceRegionId),
                RegionIdentity(branch.TargetRegionId),
                branch.SourceAddress,
                branch.SourceOffset,
                branch.TargetOffset))
            .ToArray();
        var parsed = ElfParser.Parse(setup.Source);
        Assert.NotNull(parsed.File);

        var planning = ElfLayoutPlanner.Plan(
            setup.Source,
            parsed.File!,
            regionRequests,
            branches,
            ElfLayoutOptions.Default,
            new[] { new ElfLayoutTlsFixupRequest(RegionIdentity(regions[0].RegionId), 0, fixup) });

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsLayoutMismatch);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsIncompleteLocalExecAddPairAtSharedLayoutBoundary()
    {
        var setup = CreateEmission();
        var artifact = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var snapshot = SemanticPlanSnapshotCodec.Decode(
            artifact.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().Single().CanonicalBytes).Snapshot!;
        var fixup = TlsSemanticFixupPlanner.Build(snapshot.Plan).Fixups
            .Single(item => item.Relocation.RelocationType == ElfConstants.RArm64TlsLeAddTprelHi12);
        var regions = artifact.Operations.OfType<ProtectedImageEmitRegion>().ToArray();
        var regionRequests = regions.Select(region => new ElfLayoutRegionRequest(
            RegionIdentity(region.RegionId),
            RegionIdentity(region.RegionId),
            region.SourceAddress,
            region.SourceSize,
            region.CodeBytes)).ToArray();
        var branches = artifact.Operations.OfType<ProtectedImageEntryBranchFixup>()
            .Select(branch => new ElfLayoutBranchRequest(
                $"entry:{branch.SourceRegionId}:{branch.SourceOffset}",
                RegionIdentity(branch.SourceRegionId),
                RegionIdentity(branch.TargetRegionId),
                branch.SourceAddress,
                branch.SourceOffset,
                branch.TargetOffset))
            .ToArray();
        var parsed = ElfParser.Parse(setup.Source);
        Assert.NotNull(parsed.File);
        var outputOffset = checked(
            fixup.RelocationOutputRange.FileOffset.Value
            - fixup.SequenceOutputRange.FileOffset.Value);

        var planning = ElfLayoutPlanner.Plan(
            setup.Source,
            parsed.File!,
            regionRequests,
            branches,
            ElfLayoutOptions.Default,
            new[] { new ElfLayoutTlsFixupRequest(
                RegionIdentity(regions[0].RegionId),
                outputOffset,
                fixup) });

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsLayoutMismatch);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecMovwReferenceToUndefinedTlsSymbol()
    {
        var source = ElfFixture.TlsLocalExecMovwFunctionPie();
        BinaryPrimitives.WriteUInt16LittleEndian(source.AsSpan(0x500 + ElfConstants.SymbolEntrySize64 + 6), 0);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsBindingUnresolved);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsLocalExecRelocationPairWithMismatchedAddends()
    {
        var source = ElfFixture.TlsLocalExecFunctionPie();
        BinaryPrimitives.WriteInt64LittleEndian(source.AsSpan(0x600 + 16), 4);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsTprelAddRelocationAttachedToNonAddInstructionBeforePlanning()
    {
        var source = ElfFixture.TlsLocalExecFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(0x204), 0xD503201F);
        var plan = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(plan.IsSuccess);
        Assert.Null(plan.Plan);
        Assert.Contains(plan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsTprelAddSequenceWithWrongWidthOrAddressRegisterOwnership()
    {
        var wrongWidth = ElfFixture.TlsLocalExecFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(wrongWidth.AsSpan(0x204), 0x11400000u); // ADD w0, w0, #0, LSL #12
        var widthPlan = new FunctionProtectionService().Plan(
            wrongWidth,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(widthPlan.IsSuccess);
        Assert.Null(widthPlan.Plan);
        Assert.Contains(widthPlan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);

        var wrongAddressRegister = ElfFixture.TlsLocalExecFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(wrongAddressRegister.AsSpan(0x204), 0x91400001u); // ADD x1, x0, #0, LSL #12
        BinaryPrimitives.WriteUInt32LittleEndian(wrongAddressRegister.AsSpan(0x208), 0x91000021u); // ADD x1, x1, #0
        var addressPlan = new FunctionProtectionService().Plan(
            wrongAddressRegister,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByName("tls_fixture") },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(addressPlan.IsSuccess);
        Assert.Null(addressPlan.Plan);
        Assert.Contains(addressPlan.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsModelAndRelocationFamilyMismatchInTheCanonicalSnapshot()
    {
        var setup = CreateEmission();
        var artifact = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var snapshot = SemanticPlanSnapshotCodec.Decode(
            artifact.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().Single().CanonicalBytes).Snapshot!;
        var original = snapshot.Extensions.OfType<SemanticTlsBindingExtension>().Single().Binding;
        var mismatchedBinding = new TlsBinding(
            TlsAccessModel.InitialExec,
            TlsRelocationFamily.GotTprel,
            original.SourceIdentity,
            original.SourceRange,
            original.InstructionSequence,
            original.Module,
            original.Symbol,
            original.Addend,
            original.RelocationSites,
            original.AccessSize,
            original.AddressExpression,
            original.ProfileRequirements,
            original.RuntimeRequirements);
        var mismatchedPlan = new SemanticRewritePlan(
            snapshot.AddressMap,
            snapshot.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Extensions
                .Where(extension => extension is not SemanticTlsBindingExtension)
                .Append(new SemanticTlsBindingExtension(mismatchedBinding)),
            snapshot.Diagnostics);

        var encoded = SemanticPlanSnapshotCodec.Create(mismatchedPlan);

        Assert.False(encoded.IsSuccess);
        Assert.Contains(encoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsCanonicalLocalExecSnapshotWithMismatchedInstructionOpcode()
    {
        var setup = CreateEmission();
        var image = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var snapshot = SemanticPlanSnapshotCodec.Decode(
            image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().Single().CanonicalBytes).Snapshot!;
        var original = snapshot.Extensions.OfType<SemanticTlsBindingExtension>().Single().Binding;
        var instructions = original.InstructionSequence.Instructions.ToArray();
        instructions[1] = instructions[1] with { Encoding = 0xD503201F, Mnemonic = "nop" };
        var invalidBinding = new TlsBinding(
            original.AccessModel,
            original.RelocationFamily,
            original.SourceIdentity,
            original.SourceRange,
            original.InstructionSequence with { Instructions = instructions },
            original.Module,
            original.Symbol,
            original.Addend,
            original.RelocationSites,
            original.AccessSize,
            original.AddressExpression,
            original.ProfileRequirements,
            original.RuntimeRequirements);
        var invalidPlan = new SemanticRewritePlan(
            snapshot.AddressMap,
            snapshot.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Extensions
                .Where(extension => extension is not SemanticTlsBindingExtension)
                .Append(new SemanticTlsBindingExtension(invalidBinding)),
            snapshot.Diagnostics);

        var encoded = SemanticPlanSnapshotCodec.Create(invalidPlan);

        Assert.False(encoded.IsSuccess);
        Assert.Contains(encoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsMissingSnapshotBeforeMaterialization()
    {
        var setup = CreateEmission();
        var image = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var withoutSnapshot = image with
        {
            Operations = image.Operations
                .Where(operation => operation is not ProtectedImageSemanticPlanSnapshot)
                .ToArray(),
        };
        var encoded = ProtectedImageCodec.Encode(withoutSnapshot);
        Assert.True(encoded.IsSuccess, string.Join(Environment.NewLine, encoded.Diagnostics));

        var result = GenericRehydrationEngine.Rehydrate(
            setup.Source,
            encoded.ArtifactBytes!,
            setup.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsBindingUnresolved);
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsRelocationSourceMismatchWithoutPublishingANativeImage()
    {
        var setup = CreateEmission();
        var changedSource = setup.Source.ToArray();
        BinaryPrimitives.WriteInt64LittleEndian(changedSource.AsSpan(0x600 + 16), 4);
        var changedHash = Sha256(changedSource);
        var image = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image! with
        {
            SourceSha256 = changedHash,
        };
        var artifact = ProtectedImageCodec.Encode(image);
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));
        var options = setup.RehydrationOptions with { ExpectedSourceSha256 = changedHash };

        var result = GenericRehydrationEngine.Rehydrate(changedSource, artifact.ArtifactBytes!, options);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsBindingUnresolved);
        var directory = Directory.CreateTempSubdirectory("urprotect-tls-local-exec-failure-");
        try
        {
            var publication = RehydrationPublisher.Publish(
                result,
                Path.Combine(directory.FullName, "native-image.bin"),
                Path.Combine(directory.FullName, "native-image.json"),
                Path.Combine(directory.FullName, "rehydration.json"));
            Assert.True(publication.Published, string.Join(Environment.NewLine, publication.Diagnostics));
            Assert.True(File.Exists(Path.Combine(directory.FullName, "rehydration.json")));
            Assert.False(File.Exists(Path.Combine(directory.FullName, "native-image.bin")));
            Assert.False(File.Exists(Path.Combine(directory.FullName, "native-image.json")));
            Assert.Empty(Directory.GetFiles(directory.FullName, "*.tmp", SearchOption.AllDirectories));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "TlsLocalExec")]
    public void RejectsOutOfRangeLocalExecFixupInTheSharedLayoutPlanner()
    {
        var setup = CreateEmission();
        var image = ProtectedImageCodec.Decode(setup.Emission.ArtifactBytes!).Image!;
        var snapshot = SemanticPlanSnapshotCodec.Decode(
            image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>().Single().CanonicalBytes).Snapshot!;
        var fixup = TlsSemanticFixupPlanner.Build(snapshot.Plan).Fixups[0];
        var regions = image.Operations.OfType<ProtectedImageEmitRegion>().ToArray();
        var regionRequests = regions.Select(region => new ElfLayoutRegionRequest(
            RegionIdentity(region.RegionId),
            RegionIdentity(region.RegionId),
            region.SourceAddress,
            region.SourceSize,
            region.CodeBytes)).ToArray();
        var branches = image.Operations.OfType<ProtectedImageEntryBranchFixup>()
            .Select(branch => new ElfLayoutBranchRequest(
                $"entry:{branch.SourceRegionId}:{branch.SourceOffset}",
                RegionIdentity(branch.SourceRegionId),
                RegionIdentity(branch.TargetRegionId),
                branch.SourceAddress,
                branch.SourceOffset,
                branch.TargetOffset))
            .ToArray();
        var parsed = ElfParser.Parse(setup.Source);
        Assert.NotNull(parsed.File);
        var invalidTlsFixup = new ElfLayoutTlsFixupRequest(
            RegionIdentity(Assert.Single(regions).RegionId),
            ulong.MaxValue,
            fixup);

        var planning = ElfLayoutPlanner.Plan(
            setup.Source,
            parsed.File!,
            regionRequests,
            branches,
            ElfLayoutOptions.Default,
            new[] { invalidTlsFixup });

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsLayoutMismatch);
    }

    private static (byte[] Source, FunctionProtectionOptions Request, ProtectedImageEmissionResult Emission, string SourceHash, string RequestHash, RehydrationOptions RehydrationOptions) CreateEmission(
        byte[]? sourceOverride = null,
        string unitId = "tls.local-exec.fixture",
        string producerId = "tls.local-exec.producer")
    {
        var source = sourceOverride ?? ElfFixture.TlsLocalExecFunctionPie();
        var selectors = new[] { FunctionSelector.ByName("tls_fixture") };
        var passes = new[] { ProtectionPass.RegisterPermutation };
        var request = new FunctionProtectionOptions(selectors, passes);
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(selectors, passes);
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            new ProtectedImageProducerOptions(
                unitId,
                ProtectedImageProfile.OuterExecveat,
                producerId,
                ProducerBuild,
                ProtectedImageAbiV1.DefaultRehydratorConsumerId,
                sourceHash,
                requestHash));
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));
        return (
            source,
            request,
            emission,
            sourceHash,
            requestHash,
            new RehydrationOptions(
                sourceHash,
                requestHash,
                unitId,
                ProtectedImageProfile.OuterExecveat,
                producerId,
                ProducerBuild,
                ProtectedImageAbiV1.DefaultRehydratorConsumerId,
                ConsumerBuild));
    }

    private static string RegionIdentity(uint regionId) => $"region:{regionId:D10}";

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
