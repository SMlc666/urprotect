using System.Buffers.Binary;
using System.Text.Json;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Layout;

public sealed class ElfLayoutTests
{
    private static readonly JsonSerializerOptions LayoutEvidenceJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

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
    public void MaterializerPreservesTlsTemplateZeroFillAndSectionOwnedRelocations()
    {
        var source = ElfFixture.TlsStaticRelocationPie();
        source.AsSpan(ElfFixture.InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        Assert.Single(parsed.File!.TlsMetadata.Segments);
        Assert.Single(parsed.File.TlsMetadata.StaticRelocations);

        var region = new ElfLayoutRegionRequest(
            "region:tls-preservation",
            "function:tls-fixture",
            new VirtualAddress(0x1200),
            sizeof(uint),
            new byte[] { 0x1F, 0x20, 0x03, 0xD5 });
        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File,
            new[] { region },
            Array.Empty<ElfLayoutBranchRequest>(),
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.AvailableProgramHeaderSlot));
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));

        var materialized = ElfLayoutMaterializer.Materialize(source, parsed.File, planning.Plan!);
        Assert.True(materialized.IsSuccess, string.Join(Environment.NewLine, materialized.Diagnostics));
        var sourceTls = Assert.Single(parsed.File.TlsMetadata.Segments);
        var outputTls = Assert.Single(materialized.ParsedOutput!.TlsMetadata.Segments);
        Assert.Equal(sourceTls.FileSize, outputTls.FileSize);
        Assert.Equal(sourceTls.ZeroFillSize, outputTls.ZeroFillSize);
        Assert.Equal(sourceTls.Alignment, outputTls.Alignment);
        Assert.Equal(sourceTls.InitializedTemplate.ToArray(), outputTls.InitializedTemplate.ToArray());
        Assert.Equal(
            parsed.File.TlsMetadata.StaticRelocations,
            materialized.ParsedOutput.TlsMetadata.StaticRelocations);
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
    public void RelativeJumpTableEvidenceCarriesPlannerDerivedPerTargetOutputMappings()
    {
        var (source, sourceFile, planning) = PlanRelativeJumpTableLayout();
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        Assert.Equal(3, ElfLayoutEvidence.CurrentSchemaVersion);
        Assert.Equal(ElfLayoutEvidence.CurrentSchemaVersion, planning.Evidence!.SchemaVersion);
        Assert.Equal(4, planning.Evidence.JumpTableTargetBindings.Count);
        Assert.Single(planning.Evidence.JumpTableClones);

        var materialized = ElfLayoutMaterializer.Materialize(source, sourceFile, planning.Plan!);
        Assert.True(materialized.IsSuccess, string.Join(Environment.NewLine, materialized.Diagnostics));
        Assert.Equal(ElfLayoutEvidence.CurrentSchemaVersion, materialized.Evidence!.SchemaVersion);

        var bindings = materialized.Evidence.JumpTableTargetBindings.OrderBy(binding => binding.EntryIndex).ToArray();
        Assert.Equal(4, bindings.Length);
        Assert.Equal(4, materialized.Evidence.JumpTableEdits.Count);
        var clone = Assert.Single(materialized.Evidence.JumpTableClones);
        Assert.Equal(ElfConstants.PfR, clone.Permissions);
        Assert.NotEqual(clone.SourceTableRange.VirtualAddress, clone.OutputRange.VirtualAddress);
        Assert.Equal(
            source.AsSpan(checked((int)clone.SourceTableRange.FileOffset.Value), checked((int)clone.SourceTableRange.Size)).ToArray(),
            materialized.Bytes!.AsSpan(checked((int)clone.SourceTableRange.FileOffset.Value), checked((int)clone.SourceTableRange.Size)).ToArray());
        Assert.Equal(planning.Evidence.JumpTableTargetBindings, materialized.Evidence.JumpTableTargetBindings);
        for (var index = 0; index < bindings.Length; index++)
        {
            var binding = bindings[index];
            Assert.Equal(index, binding.EntryIndex);
            Assert.Equal(SemanticEntityKind.TableEntry, binding.EntryIdentity.Kind);
            Assert.Equal(SemanticEntityKind.BasicBlock, binding.TargetIdentity.Kind);
            Assert.Equal(4, binding.EntryWidth);
            Assert.True(binding.IsSigned);
            Assert.Equal(
                checked((long)(binding.OutputTargetAddress.Value - binding.OutputTargetBaseAddress.Value)),
                binding.OutputEncodedValue);
            Assert.True(materialized.ParsedOutput!.LoadMap.TryVirtualAddressToFileOffset(
                binding.OutputTargetAddress,
                sizeof(uint),
                out var mappedTargetOffset));
            Assert.Contains(materialized.ParsedOutput.LoadMap.Segments, segment =>
                segment.IsExecutable
                && segment.ContainsVirtualAddress(binding.OutputTargetAddress.Value, sizeof(uint))
                && segment.ContainsFileOffset(mappedTargetOffset.Value, sizeof(uint)));
        }
    }

    [Theory]
    [InlineData(SemanticJumpTableOwnership.Ambiguous, 0)]
    [InlineData(SemanticJumpTableOwnership.SelectedFunctionPrivate, 1)]
    [InlineData(SemanticJumpTableOwnership.Shared, 2)]
    [InlineData(SemanticJumpTableOwnership.External, 3)]
    [InlineData(SemanticJumpTableOwnership.RuntimeOwned, 4)]
    [Trait("Category", "ElfLayout")]
    public void LayoutEvidenceJsonSerializesStableV3OwnershipOrdinals(
        SemanticJumpTableOwnership ownership,
        int expectedWireOrdinal)
    {
        var (_, _, planning) = PlanRelativeJumpTableLayout();
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        Assert.Equal(3, ElfLayoutEvidence.CurrentSchemaVersion);
        Assert.Equal(1, (int)SemanticJumpTableOwnership.Shared);

        var clone = Assert.Single(planning.Evidence!.JumpTableClones);
        var evidence = planning.Evidence with
        {
            JumpTableClones = new[] { clone with { Ownership = ownership } },
        };
        var json = JsonSerializer.Serialize(evidence, LayoutEvidenceJsonOptions);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(3, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(
            expectedWireOrdinal,
            root.GetProperty("jumpTableClones")[0].GetProperty("ownership").GetInt32());

    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void RelativeJumpTablePlannerFailsClosedWhenTargetHasNoOutputAddressMapping()
    {
        var (source, sourceFile, _) = PlanRelativeJumpTableLayout();
        var function = Assert.Single(sourceFile.FunctionSymbols, symbol =>
            symbol.Table == ElfSymbolTableKind.Static && symbol.Value == 0x1200);
        var (region, table) = BuildRelativeJumpTableRequests(source, function, narrowRegion: true);

        var planning = ElfLayoutPlanner.Plan(
            source,
            sourceFile,
            new[] { region },
            Array.Empty<ElfLayoutBranchRequest>(),
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable),
            jumpTableRequests: new[] { table });

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapMissing);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void RelativeJumpTablePlannerRejectsCloneRangeAliasingItsSourceTable()
    {
        var (source, sourceFile, _) = PlanRelativeJumpTableLayout();
        var function = Assert.Single(sourceFile.FunctionSymbols, symbol =>
            symbol.Table == ElfSymbolTableKind.Static && symbol.Value == 0x1200);
        var (region, request) = BuildRelativeJumpTableRequests(source, function, narrowRegion: false);
        var overlappingClone = request with
        {
            RequestedOutputRange = request.TableRange,
        };

        var planning = ElfLayoutPlanner.Plan(
            source,
            sourceFile,
            new[] { region },
            Array.Empty<ElfLayoutBranchRequest>(),
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable),
            jumpTableRequests: new[] { overlappingClone });

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ElfLayoutUnsupported);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void RelativeJumpTablePlannerRejectsTargetBaseBeyondSelectedOutputRange()
    {
        var (source, sourceFile, _) = PlanRelativeJumpTableLayout();
        var function = Assert.Single(sourceFile.FunctionSymbols, symbol =>
            symbol.Table == ElfSymbolTableKind.Static && symbol.Value == 0x1200);
        var (region, request) = BuildRelativeJumpTableRequests(source, function, narrowRegion: false);
        var selectedOutput = Assert.IsType<SemanticSourceRange>(request.SelectedFunctionOutputRange);
        var outOfRangeTargetBase = request with
        {
            OutputTargetBaseAddress = new VirtualAddress(
                checked(selectedOutput.VirtualAddress.Value + selectedOutput.Size)),
        };

        var planning = ElfLayoutPlanner.Plan(
            source,
            sourceFile,
            new[] { region },
            Array.Empty<ElfLayoutBranchRequest>(),
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable),
            jumpTableRequests: new[] { outOfRangeTargetBase });

        Assert.False(planning.IsSuccess);
        Assert.Null(planning.Plan);
        Assert.Contains(planning.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ElfLayoutUnsupported);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void MaterializerRejectsTamperedOrDuplicateJumpTableTargetBindings()
    {
        var (source, sourceFile, planning) = PlanRelativeJumpTableLayout();
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        var original = planning.Plan!;

        var changed = original.JumpTableTargetBindings.ToArray();
        changed[0] = changed[0] with
        {
            OutputTargetAddress = new VirtualAddress(changed[0].OutputTargetAddress.Value + sizeof(uint)),
        };
        var tamperedAddress = ElfLayoutMaterializer.Materialize(
            source,
            sourceFile,
            original with { JumpTableTargetBindings = changed });
        Assert.False(tamperedAddress.IsSuccess);
        Assert.Null(tamperedAddress.Bytes);
        Assert.Contains(tamperedAddress.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.ElfLayoutPostValidationFailed);

        var changedAddressMap = original.AddressMap.ToArray();
        changedAddressMap[0] = changedAddressMap[0] with
        {
            OutputRange = changedAddressMap[0].OutputRange with
            {
                FileOffset = new FileOffset(changedAddressMap[0].OutputRange.FileOffset.Value + sizeof(uint)),
            },
        };
        var mismatchedOutputFileOffset = ElfLayoutMaterializer.Materialize(
            source,
            sourceFile,
            original with { AddressMap = changedAddressMap });
        Assert.False(mismatchedOutputFileOffset.IsSuccess);
        Assert.Null(mismatchedOutputFileOffset.Bytes);
        Assert.Contains(mismatchedOutputFileOffset.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.ElfLayoutPostValidationFailed);

        var duplicated = original.JumpTableTargetBindings.ToArray();
        duplicated[^1] = duplicated[^1] with { EntryIndex = duplicated[^2].EntryIndex };
        var duplicateEntry = ElfLayoutMaterializer.Materialize(
            source,
            sourceFile,
            original with { JumpTableTargetBindings = duplicated });
        Assert.False(duplicateEntry.IsSuccess);
        Assert.Null(duplicateEntry.Bytes);
        Assert.Contains(duplicateEntry.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.ElfLayoutPostValidationFailed);

        var nonCanonical = original.JumpTableTargetBindings.ToArray();
        nonCanonical[0] = nonCanonical[0] with
        {
            EntryIdentity = SemanticEntityId.TableEntry("forged-entry-identity"),
        };
        var nonCanonicalEntry = ElfLayoutMaterializer.Materialize(
            source,
            sourceFile,
            original with { JumpTableTargetBindings = nonCanonical });
        Assert.False(nonCanonicalEntry.IsSuccess);
        Assert.Null(nonCanonicalEntry.Bytes);
        Assert.Contains(nonCanonicalEntry.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.ElfLayoutPostValidationFailed);
    }

    [Fact]
    [Trait("Category", "ElfLayout")]
    public void MaterializerRejectsDuplicateBindingsThatLeaveAnotherTableEditUnbound()
    {
        var (source, sourceFile, planning) = PlanRelativeJumpTableLayout();
        Assert.True(planning.IsSuccess, string.Join(Environment.NewLine, planning.Diagnostics));
        var original = planning.Plan!;
        var first = original.JumpTableTargetBindings[0];
        var duplicatedRanges = original.JumpTableTargetBindings
            .Select((_, index) => first with
            {
                TableIdentity = SemanticEntityId.Table($"forged-table-{index}"),
                SourceTableRange = first.SourceEntryRange,
                EntryIdentity = SemanticEntityId.TableEntry($"forged-table-{index}:0"),
                EntryIndex = 0,
            })
            .ToArray();

        var result = ElfLayoutMaterializer.Materialize(
            source,
            sourceFile,
            original with { JumpTableTargetBindings = duplicatedRanges });

        Assert.False(result.IsSuccess);
        Assert.Null(result.Bytes);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.ElfLayoutPostValidationFailed);
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

    private static (byte[] Source, ElfFile SourceFile, ElfLayoutPlanningResult Planning) PlanRelativeJumpTableLayout()
    {
        var source = ElfFixture.RelativeJumpTableFunctionPie();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var function = Assert.Single(parsed.File!.FunctionSymbols, symbol =>
            symbol.Table == ElfSymbolTableKind.Static && symbol.Value == 0x1200);
        var (region, table) = BuildRelativeJumpTableRequests(source, function, narrowRegion: false);
        var planning = ElfLayoutPlanner.Plan(
            source,
            parsed.File,
            new[] { region },
            Array.Empty<ElfLayoutBranchRequest>(),
            new ElfLayoutOptions(RequestedStrategy: ElfLayoutStrategy.RelocatedProgramHeaderTable),
            jumpTableRequests: new[] { table });
        return (source, parsed.File, planning);
    }

    private static (ElfLayoutRegionRequest Region, ElfLayoutJumpTableEditRequest Table)
        BuildRelativeJumpTableRequests(
            byte[] source,
            ElfFunctionSymbol function,
            bool narrowRegion)
    {
        var protection = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(function.Table, function.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));
        Assert.True(protection.IsSuccess, string.Join(Environment.NewLine, protection.Diagnostics));
        var protectedRegion = Assert.Single(protection.Plan!.Regions);
        var snapshot = protection.Plan.SemanticSnapshot!;
        var jumpTable = Assert.Single(snapshot.Extensions.OfType<SemanticJumpTableExtension>());
        var selectedFunctionMapping = Assert.Single(snapshot.Plan.AddressMap.Entries, entry =>
            entry.Identity.Kind == SemanticEntityKind.Function
            && entry.SourceRange.VirtualAddress.Value == function.Value
            && entry.SourceRange.Size == function.Size);
        var targetBaseMapping = Assert.Single(snapshot.Plan.AddressMap.Entries, entry =>
            entry.Identity.Kind == SemanticEntityKind.BasicBlock
            && jumpTable.TargetBaseAddress is { } targetBase
            && targetBase.Value >= entry.SourceRange.VirtualAddress.Value
            && targetBase.Value - entry.SourceRange.VirtualAddress.Value < entry.SourceRange.Size);
        var outputEntryBindings = jumpTable.Entries.Select(entry =>
        {
            var targetIdentity = entry.Target.Identity!.Value;
            var targetMapping = Assert.Single(snapshot.Plan.AddressMap.Entries, mapping => mapping.Identity == targetIdentity);
            return new ElfLayoutJumpTableEntryOutputBinding(
                entry.EntryIdentity,
                targetIdentity,
                targetMapping.OutputRange.VirtualAddress);
        }).ToArray();

        var regionAddress = narrowRegion
            ? new VirtualAddress(function.Value + function.Size - sizeof(uint))
            : protectedRegion.SourceAddress;
        var regionSize = narrowRegion ? (ulong)sizeof(uint) : protectedRegion.SourceSize;
        var codeBytes = narrowRegion
            ? new byte[] { 0x1F, 0x20, 0x03, 0xD5 }
            : protectedRegion.CodeBytes;
        var region = new ElfLayoutRegionRequest(
            "region:jump-table-targets",
            "function:jump-table-targets",
            regionAddress,
            regionSize,
            codeBytes);
        var table = new ElfLayoutJumpTableEditRequest(
            jumpTable.TableIdentity,
            jumpTable.TableRange,
            jumpTable.TargetBaseAddress!.Value,
            jumpTable.EntrySize,
            jumpTable.IsSigned,
            jumpTable.Scale,
            jumpTable.Addend,
            jumpTable.RewritePolicy,
            jumpTable.Entries,
            jumpTable.Ownership,
            jumpTable.OutputRange,
            jumpTable.TableReferenceProducers,
            jumpTable.OwnerReferences,
            jumpTable.OwnerInventoryComplete,
            selectedFunctionMapping.SourceRange,
            selectedFunctionMapping.OutputRange,
            targetBaseMapping.Identity,
            targetBaseMapping.OutputRange.VirtualAddress,
            outputEntryBindings);
        return (region, table);
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
