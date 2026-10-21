using System.Buffers.Binary;
using System.Text.Json;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Application.Protection;

namespace UrProtect.Core.Tests.Application;

public sealed class FunctionProtectionTests
{
    private const string VersionedFixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";

    private static ElfFunctionSymbol HostContextEntryFunction(ElfFile file, ulong? size = null) =>
        Assert.Single(file.FunctionSymbols, function =>
            function.IsDynamic
            && function.Name == HostContextContract.EntrySymbol
            && (!size.HasValue || function.Size == size.Value));

    private static Aarch64HostContextProofContext CreateHostContextProofContext(ElfFile file) =>
        HostContextProofContextFactory.TryCreate(
            file,
            ProtectedImageProfile.HostContextEntry,
            HostContextContract.EntrySymbol)
        ?? throw new InvalidOperationException("The fixture does not establish a HostContext entry proof context.");

    [Fact]
    [Trait("Category", "Protect")]
    public void NameSelectionRejectsAmbiguousStaticAndDynamicIdentities()
    {
        var parse = ElfParser.Parse(ReadVersionedFixture());
        Assert.NotNull(parse.File);

        var result = FunctionSelectorResolver.Resolve(
            parse.File!,
            new[] { FunctionSelector.ByName("urp_api_v1") });

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticCode.FunctionSelectorAmbiguous, diagnostic.Code);
        Assert.Contains("dynsym[3]", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("symtab[23]", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ExplicitIdentityDisambiguationTransformsOnlyTheSelectedRange()
    {
        var source = WithProgramHeaderSlot(ReadVersionedFixture());
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var selected = Assert.Single(parse.File!.FunctionSymbols, function =>
            function.Table == ElfSymbolTableKind.Static && function.TableIndex == 23);
        var untouched = Assert.Single(parse.File.FunctionSymbols, function =>
            function.Table == ElfSymbolTableKind.Static && function.TableIndex == 21);

        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.OutputBytes);
        Assert.Contains(result.Functions, function =>
            function.Function.Table == ElfSymbolTableKind.Static
            && function.Function.TableIndex == 23
            && function.Transformed);

        Assert.True(parse.File.LoadMap.TryVirtualAddressToFileOffset(untouched.Value, untouched.Size, out var untouchedOffset));
        var output = result.OutputBytes!;
        Assert.Equal(
            source.AsSpan(checked((int)untouchedOffset), checked((int)untouched.Size)).ToArray(),
            output.AsSpan(checked((int)untouchedOffset), checked((int)untouched.Size)).ToArray());
        Assert.True(parse.File.LoadMap.TryVirtualAddressToFileOffset(selected.Value, selected.Size, out var selectedOffset));
        Assert.NotEqual(
            source.AsSpan(checked((int)selectedOffset), checked((int)selected.Size)).ToArray(),
            output.AsSpan(checked((int)selectedOffset), checked((int)selected.Size)).ToArray());
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ProtectionAnalysisDecodesOnlyTheExplicitlySelectedFunction()
    {
        var source = WithProgramHeaderSlot(ReadVersionedFixture());
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var selected = Assert.Single(parse.File!.FunctionSymbols, function =>
            function.Table == ElfSymbolTableKind.Static && function.TableIndex == 23);
        Assert.True(selected.TryGetEnd(out var selectedEnd));
        var observedAddresses = new List<ulong>();
        var fallback = new AsmStoneAdapter();
        var decoder = new AsmStoneAdapter((encoding, address) =>
        {
            observedAddresses.Add(address);
            return fallback.Decode(encoding, address);
        });

        var result = new FunctionProtectionService(decoder).Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotEmpty(observedAddresses);
        Assert.All(observedAddresses, address => Assert.InRange(address, selected.Value, selectedEnd - 1));
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ExactSelectedIndirectBranchFlowsThroughFlatteningAndSemanticSnapshot()
    {
        var source = ElfFixture.ExactIndirectBranchFunctionPie();
        var parse = ElfParser.Parse(source);
        Assert.True(parse.IsSuccess, string.Join(Environment.NewLine, parse.Diagnostics));

        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByAddress(0x1200) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.OutputBytes);
        Assert.Contains(
            result.Functions,
            function => function.Transformed && function.Function.Value == 0x1200);
    }

    [Theory]
    [InlineData(0xB4000040u)]
    [InlineData(0x36000040u)]
    [Trait("Category", "Protect")]
    public void FlattensRegisterConditionalBranchesWithTypedSourceEncoding(uint branchEncoding)
    {
        var source = ElfFixture.ConditionalRegisterBranchFunctionPie(branchEncoding);
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByAddress(0x1200) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.OutputBytes);
        Assert.Contains(result.Functions, function => function.Transformed && function.Function.Value == 0x1200);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void RelativeJumpTableFlowsThroughBoundedResolutionAndSnapshot()
    {
        var source = ElfFixture.RelativeJumpTableFunctionPie();
        var parse = ElfParser.Parse(source);
        Assert.True(parse.IsSuccess, string.Join(Environment.NewLine, parse.Diagnostics));
        var selected = Assert.Single(
            parse.File!.FunctionSymbols,
            function => function.Table == ElfSymbolTableKind.Static
                && function.Value == 0x1200);

        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, selected.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var table = Assert.Single(
            result.Plan!.SemanticSnapshot!.Extensions.OfType<SemanticJumpTableExtension>());
        Assert.Equal(4, table.Entries.Count);
        Assert.Equal(4, table.EntrySize);
        Assert.True(table.IsSigned);
        Assert.Equal(0, table.LowerBound);
        Assert.Equal(3, table.UpperBound);
        Assert.Equal(SemanticJumpTableOwnership.Ambiguous, table.Ownership);
        Assert.Equal(SemanticJumpTableRewritePolicy.CopiedAndRetargeted, table.RewritePolicy);
        Assert.Equal(2, table.TableReferenceProducers.Count);
        Assert.False(table.OwnerInventoryComplete);
        Assert.NotEqual(table.TableRange.VirtualAddress, table.OutputRange!.Value.VirtualAddress);
        Assert.Equal(4, result.Plan.SemanticSnapshot.AddressMap.TableEntries.Count);
        Assert.Equal((ushort)6, SemanticPlanSnapshotCodec.Version);
        Assert.Equal("URP-SPS6", SemanticPlanSnapshotCodec.MagicText);

        var decoded = SemanticPlanSnapshotCodec.Decode(result.Plan.SemanticSnapshot.CanonicalBytes!);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var roundTripped = Assert.Single(decoded.Snapshot!.Extensions.OfType<SemanticJumpTableExtension>());
        Assert.Equal(table.TableReferenceProducers, roundTripped.TableReferenceProducers);
        Assert.Equal(table.OwnerReferences, roundTripped.OwnerReferences);
        Assert.Equal(table.OwnerInventoryComplete, roundTripped.OwnerInventoryComplete);
        Assert.Equal(table.Ownership, roundTripped.Ownership);
        Assert.Equal(table.RewritePolicy, roundTripped.RewritePolicy);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void RelativeJumpTableWithCheckedIndexClobberedByTableBaseFailsClosedBeforePublication()
    {
        using var temporary = new TemporaryDirectory();
        var inputPath = temporary.Path("input.elf");
        var outputPath = temporary.Path("protected.elf");
        var source = ElfFixture.RelativeJumpTableFunctionPie(clobberCheckedIndexWithTableBase: true);
        File.WriteAllBytes(inputPath, source);

        var result = new FunctionProtectionWorkflow().Execute(
            new FunctionProtectionCommandRequest(
                inputPath,
                outputPath,
                null,
                new FunctionProtectionOptions(
                    new[] { FunctionSelector.ByAddress(0x1200) },
                    new[] { ProtectionPass.ControlFlowFlattening })));

        Assert.False(result.Protection.IsSuccess);
        Assert.False(result.OutputPublished);
        Assert.Null(result.Protection.OutputBytes);
        Assert.False(File.Exists(outputPath));
        var diagnostic = Assert.Single(result.Diagnostics, candidate =>
            candidate.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.Contains("overwritten between B.HI and the indexed LDRSW", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void FlatteningPreservesFallthroughLastInstructionAndMapsRewrittenDirectBranch()
    {
        // The selected relative jump table supplies case0/case1. Make case0's
        // RET a direct B to case1's RET, splitting case1 after its ordinary
        // MOV. A plain block-final MOV must not be silently discarded while
        // its successor becomes a dispatcher state transition.
        var source = ElfFixture.RelativeJumpTableFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(
            source.AsSpan(0x200 + (9 * sizeof(uint)), sizeof(uint)),
            0x14000002u); // B +8 from VA 0x1224 to 0x122C

        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByAddress(0x1200) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var plan = Assert.IsType<ProtectionPlan>(result.Plan);
        var region = Assert.Single(plan.Regions);
        var map = Assert.IsType<SemanticPlanSnapshot>(plan.SemanticSnapshot)
            .AddressMap;
        Assert.NotNull(map);

        var ordinary = Assert.Single(map.Entries, entry =>
            entry.Identity.Kind == SemanticEntityKind.Instruction
            && entry.SourceAddress.Value == 0x1228);
        var branch = Assert.Single(map.Entries, entry =>
            entry.Identity.Kind == SemanticEntityKind.Instruction
            && entry.SourceAddress.Value == 0x1224);

        var ordinaryOffset = checked((int)(ordinary.OutputAddress.Value - 0x1200));
        var branchOffset = checked((int)(branch.OutputAddress.Value - 0x1200));
        Assert.InRange(ordinaryOffset, 0, region.CodeBytes.Length - sizeof(uint));
        Assert.InRange(branchOffset, 0, region.CodeBytes.Length - sizeof(uint));
        // The synthetic case1 instruction must really be present in the
        // output, not merely represented by an invented semantic binding.
        Assert.Equal(
            0x52800CE0u,
            BinaryPrimitives.ReadUInt32LittleEndian(
                region.CodeBytes.AsSpan(ordinaryOffset, sizeof(uint))));
        // The direct source branch is intentionally rewritten to a real
        // dispatcher state instruction rather than copied as an old PC-relative B.
        Assert.NotEqual(
            0x14000002u,
            BinaryPrimitives.ReadUInt32LittleEndian(
                region.CodeBytes.AsSpan(branchOffset, sizeof(uint))));
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void JumpTableWhoseIndexIsClobberedThroughXRegisterFailsClosed()
    {
        // The bounds check proves W0 in [0,3], but ADRP/ADD now write X0
        // before LDRSW indexes the table using W0. W0 and X0 alias.
        // Without the cross-width clobber guard this source may be wrongly
        // promoted as a bounded jump table.
        var source = ElfFixture.RelativeJumpTableFunctionPie();
        BinaryPrimitives.WriteUInt32LittleEndian(
            source.AsSpan(0x200 + 8, sizeof(uint)), 0x90000000u); // ADRP X0
        BinaryPrimitives.WriteUInt32LittleEndian(
            source.AsSpan(0x200 + 12, sizeof(uint)), 0x91092000u); // ADD X0,X0,#0x248
        BinaryPrimitives.WriteUInt32LittleEndian(
            source.AsSpan(0x200 + 16, sizeof(uint)), 0xB8A05802u); // LDRSW X2,[X0,W0,UXTW#2]

        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByAddress(0x1200) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Message.Contains("overwritten", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("ldrsw-index-alias")]
    [InlineData("target-add-index-alias")]
    [InlineData("adr-overwrites-displacement")]
    [Trait("Category", "Protect")]
    public void RelativeJumpTableRejectsPostLoadArchitecturalRegisterAliases(string mutation)
    {
        var source = ElfFixture.RelativeJumpTableFunctionPie();
        switch (mutation)
        {
            case "ldrsw-index-alias":
            {
                var offset = 0x200 + (4 * sizeof(uint));
                var encoding = BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(offset, sizeof(uint)));
                BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(offset, sizeof(uint)), encoding & ~0x1Fu);
                BinaryPrimitives.WriteUInt32LittleEndian(
                    source.AsSpan(0x200 + (6 * sizeof(uint)), sizeof(uint)),
                    0x8B000061u); // ADD X1, X3, X0 keeps the recognized chain while aliasing W0.
                break;
            }
            case "target-add-index-alias":
                BinaryPrimitives.WriteUInt32LittleEndian(
                    source.AsSpan(0x200 + (6 * sizeof(uint)), sizeof(uint)),
                    0x8B020060u); // ADD X0, X3, X2
                BinaryPrimitives.WriteUInt32LittleEndian(
                    source.AsSpan(0x200 + (7 * sizeof(uint)), sizeof(uint)),
                    0xD61F0000u); // BR X0
                break;
            case "adr-overwrites-displacement":
            {
                var offset = 0x200 + (5 * sizeof(uint));
                var encoding = BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(offset, sizeof(uint)));
                BinaryPrimitives.WriteUInt32LittleEndian(
                    source.AsSpan(offset, sizeof(uint)),
                    (encoding & ~0x1Fu) | 2u); // ADR X2 aliases the LDRSW destination.
                BinaryPrimitives.WriteUInt32LittleEndian(
                    source.AsSpan(0x200 + (6 * sizeof(uint)), sizeof(uint)),
                    0x8B020041u); // ADD X1, X2, X2 keeps the recognized chain.
                break;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByAddress(0x1200) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.False(result.IsSuccess);
        Assert.Null(result.Plan);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Message.Contains("overwrit", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void RelativeJumpTableWithOutOfClosureEntryFailsClosed()
    {
        var source = ElfFixture.RelativeJumpTableFunctionPie(malformedTableEntry: true);
        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByAddress(0x1200) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.False(result.IsSuccess);
        Assert.Null(result.Plan);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
                && diagnostic.Message == "A signed relative jump-table entry resolves outside the selected function closure.");
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void RelativeJumpTableWithTargetOutsideExecutableLoadRangeFailsBeforePublication()
    {
        using var temporary = new TemporaryDirectory();
        var inputPath = temporary.Path("input.elf");
        var outputPath = temporary.Path("protected.elf");
        var source = ElfFixture.RelativeJumpTableFunctionPie(outOfExecutableLoadRangeTableEntry: true);
        File.WriteAllBytes(inputPath, source);

        var result = new FunctionProtectionWorkflow().Execute(
            new FunctionProtectionCommandRequest(
                inputPath,
                outputPath,
                null,
                new FunctionProtectionOptions(
                    new[] { FunctionSelector.ByAddress(0x1200) },
                    new[] { ProtectionPass.ControlFlowFlattening })));

        Assert.False(result.Protection.IsSuccess);
        Assert.False(result.OutputPublished);
        Assert.Null(result.Protection.OutputBytes);
        Assert.False(File.Exists(outputPath));
        var diagnostic = Assert.Single(result.Diagnostics, candidate =>
            candidate.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.Equal(
            "A signed relative jump-table entry resolves outside an executable PT_LOAD range.",
            diagnostic.Message);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void IndirectCallRemainsFailClosedWithStableDiagnostic()
    {
        var source = ElfFixture.ExactIndirectBranchFunctionPie(useIndirectCall: true);
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByAddress(0x1200) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void SelectedFunctionAnalysisDoesNotAssumeHostContextRootByDefault()
    {
        var source = ElfFixture.HostContextJoinCallbackIntactPie();
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var entry = HostContextEntryFunction(parse.File!, 18 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer().Analyze(parse.File!, entry);

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Empty(analysis.RuntimeIndirectCallResolutions);
        Assert.Contains(analysis.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void IntactHostContextEntryCallbackUsesApplicationMappedProofContext()
    {
        using var temporary = new TemporaryDirectory();
        var sourcePath = temporary.Path("input.elf");
        var artifactPath = temporary.Path("protected-image.bin");
        var rolePath = temporary.Path("protected-image.json");
        var manifestPath = temporary.Path("SHA256SUMS");
        var stagePath = temporary.Path("stage.json");
        var source = ElfFixture.HostContextJoinCallbackIntactPie();
        File.WriteAllBytes(sourcePath, source);
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var entry = HostContextEntryFunction(parse.File!, 18 * sizeof(uint));
        var proofContext = CreateHostContextProofContext(parse.File!);
        var analysis = new Aarch64FunctionAnalyzer().Analyze(parse.File!, entry, proofContext);

        var command = ProtectedImageCommandWorkflow.Execute(new ProtectedImageCommandRequest(
            sourcePath,
            artifactPath,
            rolePath,
            manifestPath,
            stagePath,
            null,
            "host-context-entry-proof",
            ProtectedImageProfile.HostContextEntry,
            "host-context-proof-test",
            null,
            "urprotect.rehydrator.v1",
            null,
            null,
            new[] { FunctionSelector.ByIdentity(entry.Table, entry.TableIndex) },
            new[] { ProtectionPass.ControlFlowFlattening },
            Array.Empty<string>(),
            "test"));

        Assert.Equal(Aarch64FunctionAnalysisStatus.Complete, analysis.Status);
        var callback = Assert.Single(analysis.RuntimeIndirectCallResolutions);
        Assert.Equal(Aarch64RuntimeIndirectCallOwnerKind.HostContextCallback, callback.OwnerKind);
        Assert.Equal(HostContextContract.JoinImageThreadCallbackOffset, callback.HostContextFieldOffset);
        Assert.True(command.IsSuccess, string.Join(Environment.NewLine, command.Diagnostics));
        Assert.True(command.Published);
        Assert.True(File.Exists(artifactPath));
    }

    [Theory]
    [InlineData(0, true)] // B.EQ skips the call for null; fallthrough proves non-null.
    [InlineData(1, false)] // B.NE skips the call for non-null; fallthrough is unsafe.
    [Trait("Category", "Protect")]
    public void HostContextCallbackCompareBranchGuardUsesTheNonNullEdge(int conditionCode, bool expectedSuccess)
    {
        var source = ElfFixture.HostContextJoinCallbackCmpBranchPie(conditionCode);
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var entry = HostContextEntryFunction(parse.File!, 18 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File!,
            entry,
            CreateHostContextProofContext(parse.File!));

        Assert.Equal(expectedSuccess, analysis.Status == Aarch64FunctionAnalysisStatus.Complete);
        if (expectedSuccess)
        {
            var callback = Assert.Single(analysis.RuntimeIndirectCallResolutions);
            Assert.Equal(Aarch64RuntimeIndirectCallOwnerKind.HostContextCallback, callback.OwnerKind);
            Assert.Equal(HostContextContract.JoinImageThreadCallbackOffset, callback.HostContextFieldOffset);
        }
        else
        {
            Assert.Empty(analysis.RuntimeIndirectCallResolutions);
            Assert.Contains(analysis.Diagnostics, diagnostic =>
                diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
                && diagnostic.Message.Contains("non-null", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void HostContextProfileDoesNotApplyEntryProofToNonEntrySymbolIdentity()
    {
        using var temporary = new TemporaryDirectory();
        var sourcePath = temporary.Path("input.elf");
        var artifactPath = temporary.Path("protected-image.bin");
        var rolePath = temporary.Path("protected-image.json");
        var manifestPath = temporary.Path("SHA256SUMS");
        var stagePath = temporary.Path("stage.json");
        var source = ElfFixture.HostContextJoinCallbackIntactPie();
        File.WriteAllBytes(sourcePath, source);
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var entry = HostContextEntryFunction(parse.File!);
        var nonEntry = Assert.Single(parse.File.FunctionSymbols, function =>
            !function.IsDynamic
            && function.Value == entry.Value
            && function.Size == entry.Size);
        var proofContext = CreateHostContextProofContext(parse.File!);

        var analysis = new Aarch64FunctionAnalyzer().Analyze(parse.File!, nonEntry, proofContext);
        var command = ProtectedImageCommandWorkflow.Execute(new ProtectedImageCommandRequest(
            sourcePath,
            artifactPath,
            rolePath,
            manifestPath,
            stagePath,
            null,
            "host-context-non-entry-proof",
            ProtectedImageProfile.HostContextEntry,
            "host-context-proof-test",
            null,
            "urprotect.rehydrator.v1",
            null,
            null,
            new[] { FunctionSelector.ByIdentity(nonEntry.Table, nonEntry.TableIndex) },
            new[] { ProtectionPass.ControlFlowFlattening },
            Array.Empty<string>(),
            "test"));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Empty(analysis.RuntimeIndirectCallResolutions);
        Assert.Contains(analysis.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.False(command.IsSuccess);
        Assert.False(command.Published);
        Assert.Null(command.Role);
        Assert.False(File.Exists(artifactPath));
        Assert.False(File.Exists(rolePath));
        Assert.Contains(command.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void HostContextProofContextCannotBeReusedForDifferentSourceBytes()
    {
        var original = ElfFixture.HostContextJoinCallbackIntactPie();
        var originalParse = ElfParser.Parse(original);
        Assert.NotNull(originalParse.File);
        var proofContext = CreateHostContextProofContext(originalParse.File!);
        var changedSource = original.ToArray();
        changedSource[^1] ^= 1;
        var changedParse = ElfParser.Parse(changedSource);
        Assert.NotNull(changedParse.File);
        var entry = HostContextEntryFunction(changedParse.File!);
        Assert.Equal(proofContext.EntryFunction, entry);

        var analysis = new Aarch64FunctionAnalyzer().Analyze(changedParse.File!, entry, proofContext);

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Empty(analysis.RuntimeIndirectCallResolutions);
        Assert.Contains(analysis.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void StoreInvalidatesHostContextComparisonUsedForLaterSizeGuard()
    {
        var source = ElfFixture.HostContextSizeStoreAfterComparisonPie();
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!, 20 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File,
            function,
            CreateHostContextProofContext(parse.File));
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Contains(analysis.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Message.Contains("lacks dominating table-size", StringComparison.Ordinal));
        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
    }

    [Theory]
    [InlineData(0xF83F813Fu)] // GNU as: SWP XZR, XZR, [X9] stores zero and discards the old value.
    [InlineData(0xF8EA813Fu)] // GNU as: SWPAL X10, XZR, [X9] stores X10 and discards the old value.
    [InlineData(0xF8FF812Au)] // GNU as: SWPAL XZR, X10, [X9] stores zero and returns the old value in X10.
    [Trait("Category", "Protect")]
    public void AtomicSwapOperandsAfterJoinGuardFailClosedBeforePublication(uint swapEncoding)
    {
        var source = ElfFixture.HostContextJoinCallbackAddressBearingMutationPie(swapEncoding);
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!, 18 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File,
            function,
            CreateHostContextProofContext(parse.File));
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        var diagnostic = Assert.Single(analysis.Diagnostics, candidate =>
            candidate.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.Equal((ulong?)0x1238, diagnostic.Offset);
        Assert.Contains("lacks dominating", diagnostic.Message, StringComparison.Ordinal);
        Assert.Empty(analysis.RuntimeIndirectCallResolutions);
        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ImplicitAddressBearingMemoryWriteFailsClosedBeforePublication()
    {
        const uint dcZvaX9 = 0xD50B7429u; // GNU as: DC ZVA, X9; backend provides no explicit Memory operand.
        var source = ElfFixture.HostContextJoinCallbackAddressBearingMutationPie(dcZvaX9);
        var parsed = ElfParser.Parse(source);
        Assert.NotNull(parsed.File);
        var function = HostContextEntryFunction(parsed.File!, 18 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parsed.File,
            function,
            CreateHostContextProofContext(parsed.File));
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        var diagnostic = Assert.Single(analysis.Diagnostics, candidate =>
            candidate.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.Equal((ulong?)0x1238, diagnostic.Offset);
        Assert.Contains("lacks dominating", diagnostic.Message, StringComparison.Ordinal);
        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void UnclassifiedMemoryEffectFailsClosedBeforePublication()
    {
        var source = ElfFixture.HostContextJoinCallbackAddressBearingMutationPie(0xC89FFD3Fu);
        var backend = new AsmStoneAdapter();
        var decoder = new AsmStoneAdapter((encoding, address) =>
        {
            var decoded = backend.Decode(encoding, address);
            return address == 0x1230 && decoded.Instruction is { } instruction
                ? new Aarch64DecodeResult(
                    decoded.Status,
                    instruction with { MemoryEffect = Aarch64MemoryEffect.Unclassified },
                    decoded.Diagnostic)
                : decoded;
        });
        var parsed = ElfParser.Parse(source);
        Assert.NotNull(parsed.File);
        var function = HostContextEntryFunction(parsed.File!, 18 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer(decoder).Analyze(
            parsed.File,
            function,
            CreateHostContextProofContext(parsed.File));
        var result = new ProtectionWorkflow(new FunctionProtectionService(decoder)).ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Contains(analysis.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Offset == 0x1238);
        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ReleaseStoreAfterJoinGuardFailsClosedBeforePublication()
    {
        var source = ElfFixture.HostContextJoinClearedByReleaseStorePie();
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!, 18 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File,
            function,
            CreateHostContextProofContext(parse.File));
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Contains(analysis.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Offset == 0x1238);
        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ProducerOverflowPropagatesAcrossControlFlowMerge()
    {
        var parse = ElfParser.Parse(ElfFixture.HostContextCallbackProducerMergePie());
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!);
        var proofContext = CreateHostContextProofContext(parse.File!);

        var analysis = new Aarch64FunctionAnalyzer().Analyze(parse.File!, function, proofContext);

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Contains(analysis.Diagnostics, candidate =>
            candidate.Code == DiagnosticCode.IndirectTargetUnresolved
            && candidate.Message.Contains("64-producer", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void UnprovenThreadPointerStoreInvalidatesHostContextGuards()
    {
        var source = ElfFixture.HostContextCallbackWithUnrelatedTlsStorePie();
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!);

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File,
            function,
            CreateHostContextProofContext(parse.File));
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.Contains(analysis.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
    }

    [Theory]
    [InlineData(62, true)]
    [InlineData(63, false)]
    [Trait("Category", "Protect")]
    public void ProducerChainLimitIsExactAndOverflowFailsClosed(int moveAliasCount, bool expectedSuccess)
    {
        var parse = ElfParser.Parse(ElfFixture.HostContextCallbackProducerChainPie(moveAliasCount));
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!);

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File,
            function,
            CreateHostContextProofContext(parse.File));

        Assert.Equal(expectedSuccess, analysis.Status == Aarch64FunctionAnalysisStatus.Complete);
        if (expectedSuccess)
        {
            var call = Assert.Single(analysis.RuntimeIndirectCallResolutions);
            Assert.Equal(64, call.ProducerAddresses.Count);
        }
        else
        {
            var diagnostic = Assert.Single(analysis.Diagnostics, candidate =>
                candidate.Code == DiagnosticCode.IndirectTargetUnresolved);
            Assert.Contains("64-producer", diagnostic.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void UnknownCallInvalidatesEarlierHostContextGuardsForReloadedCallback()
    {
        var source = ElfFixture.HostContextCallbackAfterUnknownCallPie();
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!, 19 * sizeof(uint));

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File,
            function,
            CreateHostContextProofContext(parse.File));
        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
        var diagnostic = Assert.Single(
            analysis.Diagnostics,
            candidate => candidate.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.Equal((ulong?)0x123C, diagnostic.Offset);
        Assert.Contains("lacks dominating table-size", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void HostCallbackInvalidatesEscapedStackFactsBeyondItsOutputSlot()
    {
        const ulong functionSize = 34 * sizeof(uint);
        var parse = ElfParser.Parse(ElfFixture.HostContextCallbackWithEscapedStackArgumentPie());
        Assert.NotNull(parse.File);
        var function = HostContextEntryFunction(parse.File!, functionSize);

        var analysis = new Aarch64FunctionAnalyzer().Analyze(
            parse.File,
            function,
            CreateHostContextProofContext(parse.File));

        Assert.Equal(Aarch64FunctionAnalysisStatus.IncompleteControlFlow, analysis.Status);
        var diagnostic = Assert.Single(
            analysis.Diagnostics,
            candidate => candidate.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.Equal((ulong?)0x1278, diagnostic.Offset);
        Assert.Contains("target provenance is missing", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void CombinedPassesUseTheRequiredFlattenThenPermutationOrder()
    {
        var order = ProtectionPassOrdering.Normalize(new[]
        {
            ProtectionPass.RegisterPermutation,
            ProtectionPass.ControlFlowFlattening,
            ProtectionPass.RegisterPermutation,
        });

        Assert.Equal(
            new[] { ProtectionPass.ControlFlowFlattening, ProtectionPass.RegisterPermutation },
            order);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void FailedSelectedTransformationIsAtomic()
    {
        var source = WithProgramHeaderSlot(ReadVersionedFixture());

        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.FunctionResourceUnavailable);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void OccupiedProgramHeaderTableUsesSharedLayoutPlanner()
    {
        var source = ReadVersionedFixture();

        var result = new ProtectionWorkflow().ExecuteFinal(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.OutputBytes);
        Assert.NotNull(result.LayoutEvidence);
        Assert.Equal(ElfLayoutStrategy.RelocatedProgramHeaderTable, result.LayoutEvidence!.Strategy);
        var parsed = ElfParser.Parse(result.OutputBytes!);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        Assert.True(parsed.File!.Header.ProgramHeaderOffset >= (ulong)source.Length);
        Assert.True(parsed.File.Header.ProgramHeaderCount > ElfParser.Parse(source).File!.Header.ProgramHeaderCount);
    }

    private static byte[] ReadVersionedFixture() => File.ReadAllBytes(VersionedFixturePath);

    private static byte[] WithProgramHeaderSlot(byte[] source)
    {
        var result = source.ToArray();
        var noteHeaderOffset = ElfConstants.HeaderSize64 + (3 * ElfConstants.ProgramHeaderSize64);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(noteHeaderOffset), ElfConstants.PtNull);
        return result;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-protect-");

        public string RootPath => directory.FullName;

        public string Path(string fileName) => System.IO.Path.Combine(directory.FullName, fileName);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
