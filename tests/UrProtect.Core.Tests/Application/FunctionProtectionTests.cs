using System.Buffers.Binary;
using System.Text.Json;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Application.Protection;

namespace UrProtect.Core.Tests.Application;

public sealed class FunctionProtectionTests
{
    private const string VersionedFixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";

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
        Assert.Equal(SemanticJumpTableOwnership.SelectedFunctionPrivate, table.Ownership);
        Assert.Equal(SemanticJumpTableRewritePolicy.InPlace, table.RewritePolicy);
        Assert.Equal(4, result.Plan.SemanticSnapshot.AddressMap.TableEntries.Count);
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
            diagnostic => diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
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
            diagnostic => diagnostic.Code == DiagnosticCode.IndirectTargetUnsupported);
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
