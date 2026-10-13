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
