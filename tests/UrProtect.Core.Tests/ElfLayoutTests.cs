using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class ElfLayoutTests
{
    [Fact]
    [Trait("Category", "ElfLayout")]
    public void ExistingExecutableLoadExtensionUsesTheSharedPlanner()
    {
        var source = ElfFixture.MinimalPie();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));

        var requests = Requests(new VirtualAddress(0x1200));
        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            requests.Regions,
            requests.Branches,
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.ExistingExecutableLoadExtension));

        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        Assert.Equal(ElfLayoutStrategy.ExistingExecutableLoadExtension, planning.Plan!.Strategy);
        var materialized = ElfLayoutMaterializer.Materialize(source, parsed.File!, planning.Plan);

        Assert.True(materialized.IsSuccess, string.Join(Environment.NewLine, materialized.Diagnostics));
        Assert.NotNull(materialized.Evidence);
        Assert.Equal(source.Length + 4, materialized.Bytes!.Length);
        Assert.Equal(parsed.File!.ProgramHeaders.Count, materialized.ParsedOutput!.ProgramHeaders.Count);
        Assert.Equal(8UL, materialized.ParsedOutput.ProgramHeaders[1].FileSize);
        Assert.Equal("existing-rx-load-extension", materialized.Evidence!.StrategyValue);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void AvailableProgramHeaderSlotIsAnOrdinaryCandidate()
    {
        var source = ElfFixture.MinimalPie();
        source.AsSpan(ElfFixture.InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));

        var requests = Requests(new VirtualAddress(0x1200));
        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            requests.Regions,
            requests.Branches,
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.AvailableProgramHeaderSlot));
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));

        var materialized = ElfLayoutMaterializer.Materialize(source, parsed.File!, planning.Plan!);
        Assert.True(materialized.IsSuccess, string.Join(Environment.NewLine, materialized.Diagnostics));
        Assert.Equal(ElfLayoutStrategy.AvailableProgramHeaderSlot, planning.Plan!.Strategy);
        var output = materialized.ParsedOutput!;
        Assert.Equal(parsed.File!.ProgramHeaders.Count, output.ProgramHeaders.Count);
        Assert.Equal(ElfConstants.PtLoad, output.ProgramHeaders[3].Type);
        Assert.Equal(ElfConstants.PfR | ElfConstants.PfX, output.ProgramHeaders[3].Flags);
        Assert.True(output.ProgramHeaders[3].Offset >= (ulong)source.Length);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void OccupiedTableUsesRelocatedProgramHeaderTableAndPreservesSectionMetadata()
    {
        var source = ElfFixture.MinimalPie();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));

        var requests = Requests(new VirtualAddress(0x1200));
        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            requests.Regions,
            requests.Branches,
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable));
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));

        var materialized = ElfLayoutMaterializer.Materialize(source, parsed.File!, planning.Plan!);
        Assert.True(materialized.IsSuccess, string.Join(Environment.NewLine, materialized.Diagnostics));
        var output = materialized.ParsedOutput!;
        Assert.Equal((ushort)(parsed.File!.Header.ProgramHeaderCount + 1), output.Header.ProgramHeaderCount);
        Assert.True(output.Header.ProgramHeaderOffset >= (ulong)source.Length);
        Assert.Equal(parsed.File.Header.SectionHeaderOffset, output.Header.SectionHeaderOffset);
        Assert.Equal(ElfConstants.PtLoad, output.ProgramHeaders[^1].Type);
        Assert.Equal(planning.Plan!.NewProgramHeaderTable.Size, (ulong)output.Header.ProgramHeaderCount * ElfConstants.ProgramHeaderSize64);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void RelocatedTableUpdatesPtPhdrAndAcceptsNonPageSizedCongruentAlignment()
    {
        var source = ElfFixture.CongruentNonPageSizedLoadAlignmentPie();
        var phdrOffset = ElfFixture.InterpreterProgramHeaderOffset;
        WriteProgramHeader(
            source,
            phdrOffset,
            ElfConstants.PtPhdr,
            ElfConstants.PfR,
            ElfFixture.FirstProgramHeaderOffset,
            ElfFixture.FirstProgramHeaderOffset,
            (ulong)(4 * ElfConstants.ProgramHeaderSize64),
            (ulong)(4 * ElfConstants.ProgramHeaderSize64),
            8);
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));

        var requests = Requests(new VirtualAddress(0x1200));
        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            requests.Regions,
            requests.Branches,
            new ElfLayoutOptions(
                RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable,
                SegmentAlignment: 0x200,
                MaximumAlignment: 0x200));
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));

        var materialized = ElfLayoutMaterializer.Materialize(source, parsed.File!, planning.Plan!);
        Assert.True(materialized.IsSuccess, string.Join(Environment.NewLine, materialized.Diagnostics));
        var outputPhdr = materialized.ParsedOutput!.ProgramHeaders.Single(header => header.Type == ElfConstants.PtPhdr);
        Assert.Equal(planning.Plan!.NewProgramHeaderTable.FileOffset.Value, outputPhdr.Offset);
        Assert.Equal(planning.Plan.NewProgramHeaderTable.VirtualAddress.Value, outputPhdr.VirtualAddress);
        var outputLoad = materialized.ParsedOutput.ProgramHeaders[^1];
        Assert.Equal(0x200UL, outputLoad.Alignment);
        Assert.Equal(outputLoad.Offset % outputLoad.Alignment, outputLoad.VirtualAddress % outputLoad.Alignment);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void BranchRangeOverflowProducesStableDiagnosticAndNoMaterializedBytes()
    {
        var source = CreateFarBranchSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var requests = Requests(new VirtualAddress(0x130));

        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            requests.Regions,
            requests.Branches,
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable));

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ElfLayoutBranchOutOfRange);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void MissingTypedLongBranchReplacementFailsClosed()
    {
        var source = CreateFarBranchSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var requests = Requests(new VirtualAddress(0x130));
        var longBranch = new ElfLayoutLongBranchRequest(
            "long:missing-replacement",
            new byte[] { 0x1F, 0x20, 0x03, 0xD5 });
        var branch = new ElfLayoutBranchRequest(
            "branch:1",
            "region:1",
            "region:1",
            new VirtualAddress(0x130),
            0,
            0,
            LongBranch: longBranch);

        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            requests.Regions,
            new[] { branch },
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable));

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ElfLayoutMalformed);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void WritableGeneratedRegionIsRejectedInsteadOfChangingSegmentPermissions()
    {
        var source = ElfFixture.MinimalPie();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var requests = Requests(new VirtualAddress(0x1200));
        var writable = new ElfLayoutRegionRequest(
            "region:1",
            "region:1",
            new VirtualAddress(0x1200),
            sizeof(uint),
            new byte[] { 0x1F, 0x20, 0x03, 0xD5 },
            ElfConstants.PfR | ElfConstants.PfW | ElfConstants.PfX);

        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            new[] { writable },
            requests.Branches,
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable));

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ElfLayoutMalformed);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void OverlappingSourceRegionsAreRejectedBeforePlacement()
    {
        var source = ElfFixture.MinimalPie();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var first = new ElfLayoutRegionRequest(
            "region:1",
            "source:1",
            new VirtualAddress(0x1200),
            sizeof(uint),
            new byte[] { 0x1F, 0x20, 0x03, 0xD5 });
        var second = new ElfLayoutRegionRequest(
            "region:2",
            "source:2",
            new VirtualAddress(0x1200),
            sizeof(uint),
            new byte[] { 0x1F, 0x20, 0x03, 0xD5 });
        var branches = new[]
        {
            new ElfLayoutBranchRequest("branch:1", "region:1", "region:1", new VirtualAddress(0x1200), 0, 0),
            new ElfLayoutBranchRequest("branch:2", "region:2", "region:2", new VirtualAddress(0x1200), 0, 0),
        };

        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File!,
            new[] { first, second },
            branches,
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable));

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ElfLayoutMalformed);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void TypedLongBranchPlacementRemainsDeterministic()
    {
        var source = CreateFarBranchSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var requests = Requests(new VirtualAddress(0x130), includeLongBranch: true);
        var options = new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable);

        var firstPlan = ElfLayoutPlanner.Plan(source, parsed.File!, requests.Regions, requests.Branches, options);
        var secondPlan = ElfLayoutPlanner.Plan(source, parsed.File!, requests.Regions, requests.Branches, options);
        Assert.True(firstPlan.IsSuccess, string.Join(Environment.NewLine, firstPlan.Diagnostics));
        Assert.True(secondPlan.IsSuccess, string.Join(Environment.NewLine, secondPlan.Diagnostics));
        Assert.Equal(firstPlan.Plan!.Strategy, secondPlan.Plan!.Strategy);
        Assert.Equal(firstPlan.Plan.OutputLength, secondPlan.Plan.OutputLength);
        Assert.Equal(firstPlan.Plan.Edits.Count, secondPlan.Plan.Edits.Count);
        for (var index = 0; index < firstPlan.Plan.Edits.Count; index++)
        {
            Assert.Equal(firstPlan.Plan.Edits[index].Offset, secondPlan.Plan.Edits[index].Offset);
            Assert.Equal(firstPlan.Plan.Edits[index].Kind, secondPlan.Plan.Edits[index].Kind);
            Assert.Equal(firstPlan.Plan.Edits[index].Bytes, secondPlan.Plan.Edits[index].Bytes);
        }

        var first = ElfLayoutMaterializer.Materialize(source, parsed.File!, firstPlan.Plan!);
        var second = ElfLayoutMaterializer.Materialize(source, parsed.File!, secondPlan.Plan!);
        Assert.True(first.IsSuccess, string.Join(Environment.NewLine, first.Diagnostics));
        Assert.True(second.IsSuccess, string.Join(Environment.NewLine, second.Diagnostics));
        Assert.Equal(first.Bytes, second.Bytes);
        Assert.Contains(first.Plan!.BranchDecisions, decision => decision.Decision == ElfLayoutBranchDecision.LongAddress);
    }

    private static (ElfLayoutRegionRequest[] Regions, ElfLayoutBranchRequest[] Branches) Requests(
        VirtualAddress sourceAddress,
        bool includeLongBranch = false)
    {
        var region = new ElfLayoutRegionRequest(
            "region:1",
            "region:1",
            sourceAddress,
            sizeof(uint),
            new byte[] { 0x1F, 0x20, 0x03, 0xD5 });
        var longBranch = includeLongBranch
            ? new ElfLayoutLongBranchRequest(
                "long:1",
                new byte[] { 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5 },
                new byte[] { 0x1F, 0x20, 0x03, 0xD5 })
            : null;
        var branch = new ElfLayoutBranchRequest(
            "branch:1",
            "region:1",
            "region:1",
            sourceAddress,
            0,
            0,
            LongBranch: longBranch);
        return (new[] { region }, new[] { branch });
    }

    private static byte[] CreateFarBranchSource()
    {
        var bytes = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(ElfFixture.FirstProgramHeaderOffset + ElfProgramHeaderOffsets.Flags, sizeof(uint)),
            ElfConstants.PfR | ElfConstants.PfX);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(ElfHeaderOffsets.Entry, sizeof(ulong)), 0x130);
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(ElfFixture.SecondProgramHeaderOffset + ElfProgramHeaderOffsets.VirtualAddress, sizeof(ulong)),
            0x20000200);
        return bytes;
    }

    private static void WriteProgramHeader(
        byte[] bytes,
        int offset,
        uint type,
        uint flags,
        ulong fileOffset,
        ulong virtualAddress,
        ulong fileSize,
        ulong memorySize,
        ulong alignment)
    {
        var span = bytes.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], type);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(offset + 4)..], flags);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(offset + 8)..], fileOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(offset + 16)..], virtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(offset + 24)..], virtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(offset + 32)..], fileSize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(offset + 40)..], memorySize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(offset + 48)..], alignment);
    }
}
