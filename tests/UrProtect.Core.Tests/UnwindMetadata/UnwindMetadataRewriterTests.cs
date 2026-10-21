using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.SemanticPlanning;
using CoreUnwind = UrProtect.Core.UnwindMetadata;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.UnwindMetadata;

public sealed class UnwindMetadataRewriterTests
{
    [Fact]
    public void IdentityMapProducesNoMetadataEditsAndPreservesAllRecords()
    {
        var parsed = ElfParser.Parse(UnwindMetadataParserTests.UnwindFixture.GccShapedElf());
        var file = Assert.IsType<ElfFile>(parsed.File);
        var model = Assert.IsType<CoreUnwind.UnwindMetadataModel>(
            CoreUnwind.UnwindMetadataParser.Parse(file).Model);

        var map = IdentityMap(model);
        var result = CoreUnwind.UnwindMetadataRewriter.Rewrite(file, map);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.Equal(model.EhFrameBytes.ToArray(), result.EhFrameBytes);
        Assert.Equal(model.EhFrameHeaderBytes.ToArray(), result.EhFrameHeaderBytes);
        Assert.Empty(result.Edits);
        Assert.All(result.FdeRewrites, rewrite => Assert.False(rewrite.IsChanged));
    }

    [Fact]
    public void PiecewiseMapRewritesFdeLocationAndHeaderEntries()
    {
        var parsed = ElfParser.Parse(UnwindMetadataParserTests.UnwindFixture.GccShapedElf());
        var file = Assert.IsType<ElfFile>(parsed.File);
        var source = CoreUnwind.UnwindMetadataParser.Parse(file);
        var model = Assert.IsType<CoreUnwind.UnwindMetadataModel>(source.Model);
        var fde = Assert.Single(model.Fdes);
        var sourceRange = new SemanticSourceRange(
            new FileOffset(0x400),
            new VirtualAddress(fde.InitialLocation),
            fde.AddressRange);
        var outputRange = new SemanticSourceRange(
            new FileOffset(0x500),
            new VirtualAddress(0x1800),
            fde.AddressRange);
        var identity = SemanticEntityId.Function("unwind-fixture");
        var mapResult = AddressMap.Create(new[]
        {
            new AddressMapEntry(identity, sourceRange, outputRange),
        });
        Assert.True(mapResult.IsSuccess, string.Join(Environment.NewLine, mapResult.Diagnostics));

        var result = CoreUnwind.UnwindMetadataRewriter.Rewrite(
            file,
            Assert.IsType<AddressMap>(mapResult.Map));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var rewrite = Assert.Single(result.FdeRewrites);
        Assert.True(rewrite.IsChanged);
        Assert.Equal(0x1800UL, rewrite.OutputCodeRange.VirtualAddress.Value);
        Assert.Contains(result.Edits, edit => edit.Kind == ElfLayoutEditKind.UnwindMetadata);

        var output = file.Bytes.ToArray();
        foreach (var edit in result.Edits)
        {
            edit.Bytes.CopyTo(output, checked((int)edit.Offset.Value));
        }

        var reparsed = ElfParser.Parse(output);
        Assert.True(reparsed.IsSuccess, string.Join(Environment.NewLine, reparsed.Diagnostics));
        var reparsedUnwind = CoreUnwind.UnwindMetadataParser.Parse(
            Assert.IsType<ElfFile>(reparsed.File));
        Assert.True(reparsedUnwind.IsSuccess, string.Join(Environment.NewLine, reparsedUnwind.Diagnostics));
        Assert.Equal(
            0x1800UL,
            Assert.Single(reparsedUnwind.Model!.Fdes).InitialLocation);
    }

    [Fact]
    public void CanonicalNopEffectReplacesAnExistingInstructionWithoutChangingRecordLength()
    {
        var parsed = ElfParser.Parse(UnwindMetadataParserTests.UnwindFixture.GccShapedElf());
        var file = Assert.IsType<ElfFile>(parsed.File);
        var model = Assert.IsType<CoreUnwind.UnwindMetadataModel>(
            CoreUnwind.UnwindMetadataParser.Parse(file).Model);
        var fde = Assert.Single(model.Fdes);
        var range = new SemanticSourceRange(
            new FileOffset(0x400),
            new VirtualAddress(fde.InitialLocation),
            fde.AddressRange);
        var map = Assert.IsType<AddressMap>(AddressMap.Create(new[]
        {
            new AddressMapEntry(SemanticEntityId.Function("nop-effect"), range, range),
        }).Map);
        var effect = new SemanticCfiEffectExtension(
            SemanticEntityId.Instruction(new VirtualAddress(fde.InitialLocation)),
            new SemanticSourceRange(new FileOffset(0x400), new VirtualAddress(fde.InitialLocation), sizeof(uint)),
            "cfa=sp+0");

        var result = CoreUnwind.UnwindMetadataRewriter.Rewrite(file, map, new[] { effect });

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.Contains(result.Edits, edit => edit.Kind == ElfLayoutEditKind.UnwindMetadata);
        Assert.Equal(model.EhFrameBytes.Length, result.EhFrameBytes!.Length);
    }

    [Fact]
    public void ExternalCallTargetMappingDoesNotSelectAnUnrelatedFde()
    {
        var parsed = ElfParser.Parse(UnwindMetadataParserTests.UnwindFixture.GccShapedElf());
        var file = Assert.IsType<ElfFile>(parsed.File);
        var model = Assert.IsType<CoreUnwind.UnwindMetadataModel>(
            CoreUnwind.UnwindMetadataParser.Parse(file).Model);
        var fde = Assert.Single(model.Fdes);
        Assert.True(file.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(fde.InitialLocation),
            sizeof(uint),
            out var targetOffset));
        var targetRange = new SemanticSourceRange(
            targetOffset,
            new VirtualAddress(fde.InitialLocation),
            sizeof(uint));
        var map = Assert.IsType<AddressMap>(AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.RelocationTarget("external-call-target"),
                targetRange,
                targetRange),
        }).Map);

        var result = CoreUnwind.UnwindMetadataRewriter.Rewrite(file, map);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.Empty(result.FdeRewrites);
        Assert.Empty(result.Edits);
    }

    [Fact]
    public void MissingMappingForSelectedFdeFailsClosed()
    {
        var parsed = ElfParser.Parse(UnwindMetadataParserTests.UnwindFixture.GccShapedElf());
        var file = Assert.IsType<ElfFile>(parsed.File);
        var model = Assert.IsType<CoreUnwind.UnwindMetadataModel>(
            CoreUnwind.UnwindMetadataParser.Parse(file).Model);
        var fde = Assert.Single(model.Fdes);
        var range = new SemanticSourceRange(
            new FileOffset(0x400),
            new VirtualAddress(fde.InitialLocation),
            fde.AddressRange);
        var mapResult = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Function("partial"),
                range with { Size = 4 },
                range with { Size = 4 }),
        });
        Assert.True(mapResult.IsSuccess);

        var result = CoreUnwind.UnwindMetadataRewriter.Rewrite(
            file,
            Assert.IsType<AddressMap>(mapResult.Map));

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.UnwindAddressMapMissing);
        Assert.Null(result.EhFrameBytes);
        Assert.Empty(result.Edits);
    }

    [Fact]
    public void LayoutPlannerAndMaterializerOwnUnwindEditsAtomically()
    {
        var source = UnwindMetadataParserTests.UnwindFixture.GccShapedElf();
        source.AsSpan(ElfFixture.InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        var parsed = ElfParser.Parse(source);
        var file = Assert.IsType<ElfFile>(parsed.File);
        var model = Assert.IsType<CoreUnwind.UnwindMetadataModel>(
            CoreUnwind.UnwindMetadataParser.Parse(file).Model);
        var fde = Assert.Single(model.Fdes);
        var range = new SemanticSourceRange(
            new FileOffset(0x400),
            new VirtualAddress(fde.InitialLocation),
            fde.AddressRange);
        var map = Assert.IsType<AddressMap>(AddressMap.Create(new[]
        {
            new AddressMapEntry(SemanticEntityId.Function("layout-unwind"), range, range),
        }).Map);
        var effect = new SemanticCfiEffectExtension(
            SemanticEntityId.Instruction(new VirtualAddress(fde.InitialLocation)),
            new SemanticSourceRange(new FileOffset(0x400), new VirtualAddress(fde.InitialLocation), sizeof(uint)),
            "cfa=sp+0");
        var rewrite = CoreUnwind.UnwindMetadataRewriter.Rewrite(file, map, new[] { effect });
        Assert.True(rewrite.IsSuccess, string.Join(Environment.NewLine, rewrite.Diagnostics));

        var region = new ElfLayoutRegionRequest(
            "region:unwind",
            "function:unwind",
            new VirtualAddress(0x1200),
            sizeof(uint),
            new byte[] { 0x1F, 0x20, 0x03, 0xD5 });
        var planning = ElfLayoutPlanner.Plan(
            source,
            file,
            new[] { region },
            Array.Empty<ElfLayoutBranchRequest>(),
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.AvailableProgramHeaderSlot),
            unwindEdits: rewrite.Edits);
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        Assert.NotEmpty(planning.Plan!.UnwindEdits);

        var materialized = ElfLayoutMaterializer.Materialize(source, file, planning.Plan);
        Assert.True(materialized.IsSuccess, string.Join(Environment.NewLine, materialized.Diagnostics));
        var reparsed = CoreUnwind.UnwindMetadataParser.Parse(materialized.ParsedOutput!);
        Assert.True(reparsed.IsSuccess, string.Join(Environment.NewLine, reparsed.Diagnostics));
    }

    [Fact]
    public void UnsupportedCfiEffectDoesNotPublishPartialBytes()
    {
        var parsed = ElfParser.Parse(UnwindMetadataParserTests.UnwindFixture.GccShapedElf());
        var file = Assert.IsType<ElfFile>(parsed.File);
        var model = Assert.IsType<CoreUnwind.UnwindMetadataModel>(
            CoreUnwind.UnwindMetadataParser.Parse(file).Model);
        var fde = Assert.Single(model.Fdes);
        var sourceRange = new SemanticSourceRange(
            new FileOffset(0x400),
            new VirtualAddress(fde.InitialLocation),
            fde.AddressRange);
        var mapResult = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Function("unsupported"),
                sourceRange,
                sourceRange),
        });
        var effect = new SemanticCfiEffectExtension(
            SemanticEntityId.Instruction(new VirtualAddress(0x1404)),
            new SemanticSourceRange(
                new FileOffset(0x404),
                new VirtualAddress(0x1400),
                sizeof(uint)),
            "expression[0]");

        var result = CoreUnwind.UnwindMetadataRewriter.Rewrite(
            file,
            Assert.IsType<AddressMap>(mapResult.Map),
            new[] { effect });

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.UnwindMetadataUnsupported);
        Assert.Null(result.EhFrameBytes);
        Assert.Empty(result.Edits);
    }

    private static AddressMap IdentityMap(CoreUnwind.UnwindMetadataModel model)
    {
        var entries = model.Fdes.Select((fde, index) =>
        {
            var fileOffset = new FileOffset(
                0x400UL + checked((ulong)(index * 0x40)));
            return new AddressMapEntry(
                SemanticEntityId.Function($"fde-{index}"),
                new SemanticSourceRange(fileOffset, new VirtualAddress(fde.InitialLocation), fde.AddressRange),
                new SemanticSourceRange(fileOffset, new VirtualAddress(fde.InitialLocation), fde.AddressRange));
        });
        return Assert.IsType<AddressMap>(AddressMap.Create(entries).Map);
    }
}
