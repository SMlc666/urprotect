using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Integration;

public sealed class SharedJumpTableOwnerWorkflowTests
{
    private const string FixturePath = "Fixtures/SharedJumpTable/liburp-shared-jump-table.so";
    private const string UnitId = "shared-jump-table.owner-section.glibc.host-context-entry";
    private const string ProducerId = "gcc-aarch64-shared-jump-table-fixture";
    private const string ConsumerId = "urprotect.rehydrator.v1";
    private static readonly string ProducerBuild = new('a', 64);
    private static readonly string ConsumerBuild = new('b', 64);

    [Fact]
    [Trait("Category", "Protect")]
    public void SharedJumpTableOwnersRetainExactExecutableFunctionSectionFacts()
    {
        var source = ReadSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var selected = Assert.Single(parsed.File!.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Dynamic, selected.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var snapshot = result.Plan!.SemanticSnapshot!;
        var table = Assert.Single(snapshot.Extensions.OfType<SemanticJumpTableExtension>());
        Assert.Equal(SemanticJumpTableOwnership.Shared, table.Ownership);
        Assert.Equal(4, table.OwnerReferences.Count);
        foreach (var owner in table.OwnerReferences)
        {
            Assert.Equal(owner.TargetSectionIndex, owner.OwnerFunctionSectionIndex);
            var section = parsed.File.SectionHeaders[checked((int)owner.OwnerFunctionSectionIndex)];
            Assert.Equal(section, owner.OwnerFunctionSection);
            Assert.NotEqual(ElfConstants.ShtNobits, section.Type);
            Assert.NotEqual(0UL, section.Flags & ElfConstants.ShfExecInstr);
            Assert.Contains(parsed.File.FunctionSymbols, function =>
                function.Name == owner.OwnerFunctionName
                && function.Value == owner.OwnerFunctionStart
                && function.Size == owner.OwnerFunctionSize
                && function.SectionIndex == owner.OwnerFunctionSectionIndex);
            Assert.True(owner.InstructionAddress >= owner.OwnerFunctionStart);
            Assert.True(owner.InstructionAddress + sizeof(uint)
                <= owner.OwnerFunctionStart + owner.OwnerFunctionSize);
        }

        var mismatch = table.OwnerReferences[0] with
        {
            TargetSectionIndex = checked(table.OwnerReferences[0].TargetSectionIndex + 1),
        };
        var invalidTable = CopyTable(table, table.OwnerReferences
            .Select((owner, index) => index == 0 ? mismatch : owner));
        var invalidPlan = new SemanticRewritePlan(
            snapshot.Plan.AddressMap,
            snapshot.Plan.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Plan.Extensions.Select(extension => extension is SemanticJumpTableExtension ? invalidTable : extension),
            snapshot.Plan.Diagnostics);

        var invalidSnapshot = SemanticPlanSnapshotCodec.Create(invalidPlan);

        Assert.False(invalidSnapshot.IsSuccess);
        Assert.Contains(invalidSnapshot.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("target section", StringComparison.OrdinalIgnoreCase));

        var originalOwner = table.OwnerReferences[0];
        var sectionOutsideFunction = originalOwner with
        {
            OwnerFunctionSection = originalOwner.OwnerFunctionSection with
            {
                Address = originalOwner.OwnerFunctionStart + originalOwner.OwnerFunctionSize,
            },
        };
        var invalidContainmentTable = CopyTable(table, table.OwnerReferences
            .Select((owner, index) => index == 0 ? sectionOutsideFunction : owner));
        var invalidContainmentPlan = new SemanticRewritePlan(
            snapshot.Plan.AddressMap,
            snapshot.Plan.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Plan.Extensions.Select(extension => extension is SemanticJumpTableExtension
                ? invalidContainmentTable
                : extension),
            snapshot.Plan.Diagnostics);
        var invalidContainmentSnapshot = SemanticPlanSnapshotCodec.Create(invalidContainmentPlan);

        Assert.False(invalidContainmentSnapshot.IsSuccess);
        Assert.Contains(invalidContainmentSnapshot.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("section", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void PriorV4SharedOrdinalIsRejectedRatherThanReinterpreted()
    {
        var source = ReadSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var selected = Assert.Single(parsed.File!.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Dynamic, selected.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));

        var snapshot = result.Plan!.SemanticSnapshot!;
        var table = Assert.Single(snapshot.Extensions.OfType<SemanticJumpTableExtension>());
        Assert.Equal(SemanticJumpTableOwnership.Shared, table.Ownership);
        Assert.Equal((byte)1, checked((byte)table.Ownership));
        var priorV4Bytes = snapshot.CanonicalBytes!;
        Assert.Equal("URP-SPS6", Encoding.ASCII.GetString(priorV4Bytes, 0, 8));

        // The payload's Shared ordinal 1 matches the historical v4 value. Only
        // the nested header and digest are changed to the prior strict contract.
        Encoding.ASCII.GetBytes("URP-SPS4").CopyTo(priorV4Bytes, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(priorV4Bytes.AsSpan(8, sizeof(ushort)), 4);
        RefreshSnapshotDigest(priorV4Bytes);

        var rejected = SemanticPlanSnapshotCodec.Decode(priorV4Bytes);

        Assert.False(rejected.IsSuccess);
        Assert.Null(rejected.Snapshot);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void SectionMismatchedShInfoDiscardsTheCompleteSharedOwnerProof()
    {
        var source = ReadSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var file = parsed.File!;
        var relocation = file.SectionRelocations[0];
        var functionSectionIndex = Assert.Single(file.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry").SectionIndex;
        var replacementSectionIndex = Enumerable.Range(1, file.SectionHeaders.Count - 1)
            .Select(index => (uint)index)
            .First(index => index != functionSectionIndex);
        var sectionHeaderOffset = file.Header.SectionHeaderOffset
            + checked((ulong)relocation.RelocationSectionIndex * file.Header.SectionHeaderEntrySize)
            + 44;
        BinaryPrimitives.WriteUInt32LittleEndian(
            source.AsSpan(checked((int)sectionHeaderOffset), sizeof(uint)),
            replacementSectionIndex);

        var mutatedParse = ElfParser.Parse(source);
        Assert.True(mutatedParse.IsSuccess, string.Join(Environment.NewLine, mutatedParse.Diagnostics));
        Assert.All(mutatedParse.File!.SectionRelocations, row =>
            Assert.Equal(replacementSectionIndex, row.TargetSectionIndex));
        var selected = Assert.Single(mutatedParse.File.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var result = new FunctionProtectionService().Plan(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Dynamic, selected.TableIndex) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var table = Assert.Single(result.Plan!.SemanticSnapshot!.Extensions.OfType<SemanticJumpTableExtension>());
        Assert.Equal(SemanticJumpTableOwnership.Ambiguous, table.Ownership);
        Assert.Empty(table.OwnerReferences);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void GlobalDefaultVisibleTableWithOnlySelectedOwnerEvidenceRemainsAmbiguousAndIsCopied()
    {
        var source = MakeGlobalVisibleWithSelectedOwnerEvidenceOnly(ReadSource());
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var tableSymbols = parsed.File!.SectionRelocations
            .Select(row => row.Symbol)
            .Where(symbol => symbol?.Name == "urp_shared_jump_table")
            .DistinctBy(symbol => (symbol!.SymbolTableSectionIndex, symbol.SymbolIndex))
            .ToArray();
        var tableSymbol = Assert.Single(tableSymbols);
        Assert.Equal(1, tableSymbol!.Binding);
        Assert.Equal(0, tableSymbol.Visibility);

        var scenario = CreateScenario(source);
        var image = ProtectedImageCodec.Decode(scenario.Artifact, scenario.SourceSha256, scenario.RequestSha256);
        Assert.True(image.IsSuccess, string.Join(Environment.NewLine, image.Diagnostics));
        var snapshotOperation = Assert.Single(image.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshotResult = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(snapshotResult.IsSuccess, string.Join(Environment.NewLine, snapshotResult.Diagnostics));
        var table = Assert.Single(snapshotResult.Snapshot!.Extensions.OfType<SemanticJumpTableExtension>());
        Assert.Equal(SemanticJumpTableOwnership.Ambiguous, table.Ownership);
        Assert.NotEqual(SemanticJumpTableOwnership.Shared, table.Ownership);
        Assert.NotEqual(SemanticJumpTableOwnership.SelectedFunctionPrivate, table.Ownership);
        Assert.False(table.OwnerInventoryComplete);
        Assert.Equal(2, table.OwnerReferences.Count);
        Assert.All(table.OwnerReferences, owner => Assert.True(owner.IsSelectedFunction));

        AssertClonePreservesSourceAndRetargetsSelectedReference(scenario, image.Image, snapshotResult.Snapshot!);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void StrippedOwnerEvidenceRemainsAmbiguousAndUsesTheReadOnlyClone()
    {
        var source = ReadSource();
        StripSectionHeaders(source);
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        Assert.Empty(parsed.File!.SectionHeaders);
        Assert.Empty(parsed.File.SectionRelocations);

        var scenario = CreateScenario(source);
        var image = ProtectedImageCodec.Decode(scenario.Artifact, scenario.SourceSha256, scenario.RequestSha256);
        Assert.True(image.IsSuccess, string.Join(Environment.NewLine, image.Diagnostics));
        var snapshotOperation = Assert.Single(image.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshotResult = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(snapshotResult.IsSuccess, string.Join(Environment.NewLine, snapshotResult.Diagnostics));
        var table = Assert.Single(snapshotResult.Snapshot!.Extensions.OfType<SemanticJumpTableExtension>());
        Assert.Equal(SemanticJumpTableOwnership.Ambiguous, table.Ownership);
        Assert.Empty(table.OwnerReferences);
        Assert.False(table.OwnerInventoryComplete);

        AssertClonePreservesSourceAndRetargetsSelectedReference(scenario, image.Image, snapshotResult.Snapshot!);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ConflictingSelectedReferenceRelocationFailsBeforeProtectedArtifactPublication()
    {
        var source = ReadSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var selected = Assert.Single(parsed.File!.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var addRelocation = Assert.Single(parsed.File.SectionRelocations, row =>
            row.Relocation.Offset >= selected.Value
            && row.Relocation.Offset - selected.Value < selected.Size
            && row.Relocation.Type == ElfConstants.RArm64AddAbsLo12Nc);
        var relocationInfoOffset = GetSectionRelocationFileOffset(parsed.File, addRelocation) + 8;
        var conflictingInfo = ((ulong)addRelocation.Relocation.SymbolIndex << 32)
            | ElfConstants.RArm64AdrPrelPgHi21;
        BinaryPrimitives.WriteUInt64LittleEndian(
            source.AsSpan(checked((int)relocationInfoOffset), sizeof(ulong)),
            conflictingInfo);

        var changedParse = ElfParser.Parse(source);
        Assert.True(changedParse.IsSuccess, string.Join(Environment.NewLine, changedParse.Diagnostics));
        var changedEntry = Assert.Single(changedParse.File!.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Dynamic, changedEntry.TableIndex) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        var emitted = new ProtectedImageProducer().Emit(
            source,
            request,
            new ProtectedImageProducerOptions(
                UnitId,
                ProtectedImageProfile.HostContextEntry,
                ProducerId,
                ProducerBuild,
                ConsumerId,
                sourceHash,
                requestHash));

        Assert.False(emitted.IsSuccess);
        Assert.Null(emitted.ArtifactBytes);
        Assert.Contains(emitted.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Message.Contains("conflicting or malformed section-linked relocation evidence", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationRejectsSelectedReferenceSiteTamperingAfterSnapshotReencoding()
    {
        var scenario = CreateScenario();
        var (image, snapshot) = DecodeSnapshot(scenario);
        var original = Assert.Single(snapshot.Extensions.OfType<SemanticJumpTableExtension>());
        var originalAdd = Assert.Single(original.TableReferenceProducers, producer =>
            producer.Kind == Aarch64JumpTableReferenceKind.AddLow12);
        var alternateAdd = Assert.Single(snapshot.Plan.Instructions, instruction =>
            instruction.Mnemonic.Equals("ADD", StringComparison.OrdinalIgnoreCase)
            && instruction.SourceVirtualAddress.Value != originalAdd.InstructionAddress
            && instruction.Operands.Any(operand =>
                operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null));
        var producers = original.TableReferenceProducers.Select(producer =>
            producer.Kind == Aarch64JumpTableReferenceKind.AddLow12
                ? producer with { InstructionAddress = alternateAdd.SourceVirtualAddress.Value }
                : producer);
        var owners = original.OwnerReferences.Where(owner =>
            !(owner.IsSelectedFunction && owner.RelocationType == ElfConstants.RArm64AddAbsLo12Nc));
        var forgedTable = CopyTable(original, owners, producers);
        var forgedArtifact = EncodeWithTable(scenario, image, snapshot, forgedTable);
        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            forgedArtifact,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("rederived jump-table ownership or selected source reference differs", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationRejectsOmittedOwnerEvidenceAfterSnapshotReencoding()
    {
        var scenario = CreateScenario();
        var (image, snapshot) = DecodeSnapshot(scenario);
        var original = Assert.Single(snapshot.Extensions.OfType<SemanticJumpTableExtension>());
        var omitted = Assert.Single(original.OwnerReferences, owner =>
            owner.IsSelectedFunction && owner.RelocationType == ElfConstants.RArm64AddAbsLo12Nc);
        var forgedTable = CopyTable(original, original.OwnerReferences.Where(owner => owner != omitted));
        var forgedArtifact = EncodeWithTable(scenario, image, snapshot, forgedTable);

        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            forgedArtifact,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("rederived jump-table ownership", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationCrossChecksSelfReportedOwnerSectionAgainstSourceElf()
    {
        var scenario = CreateScenario();
        var decodedImage = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256);
        Assert.True(decodedImage.IsSuccess, string.Join(Environment.NewLine, decodedImage.Diagnostics));
        var image = decodedImage.Image!;
        var snapshotOperation = Assert.Single(image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decodedSnapshot = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(decodedSnapshot.IsSuccess, string.Join(Environment.NewLine, decodedSnapshot.Diagnostics));
        var snapshot = decodedSnapshot.Snapshot!;
        var original = Assert.Single(snapshot.Extensions.OfType<SemanticJumpTableExtension>());
        var forgedOwners = original.OwnerReferences.Select(owner => owner with
        {
            TargetSectionIndex = checked(owner.OwnerFunctionSectionIndex + 1),
            OwnerFunctionSectionIndex = checked(owner.OwnerFunctionSectionIndex + 1),
        }).ToArray();
        var forgedTable = CopyTable(original, forgedOwners);
        var forgedPlan = new SemanticRewritePlan(
            snapshot.Plan.AddressMap,
            snapshot.Plan.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Plan.Extensions.Select(extension => extension is SemanticJumpTableExtension ? forgedTable : extension),
            snapshot.Plan.Diagnostics);
        var forgedSnapshot = SemanticPlanSnapshotCodec.Create(forgedPlan);
        Assert.True(forgedSnapshot.IsSuccess, string.Join(Environment.NewLine, forgedSnapshot.Diagnostics));
        var operations = image.Operations.Select(operation => operation is ProtectedImageSemanticPlanSnapshot
            ? new ProtectedImageSemanticPlanSnapshot(forgedSnapshot.Snapshot!)
            : operation).ToArray();
        var forgedArtifact = ProtectedImageCodec.Encode(image with { Operations = operations });
        Assert.True(forgedArtifact.IsSuccess, string.Join(Environment.NewLine, forgedArtifact.Diagnostics));

        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            forgedArtifact.ArtifactBytes!,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("source section header", StringComparison.Ordinal));
    }

    private static byte[] MakeGlobalVisibleWithSelectedOwnerEvidenceOnly(byte[] source)
    {
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var tableSymbol = Assert.Single(parsed.File!.SectionRelocations
            .Select(row => row.Symbol)
            .Where(symbol => symbol?.Name == "urp_shared_jump_table")
            .DistinctBy(symbol => (symbol!.SymbolTableSectionIndex, symbol.SymbolIndex)));
        var symbolOffset = GetSectionSymbolFileOffset(parsed.File, tableSymbol!);
        var info = source[checked((int)symbolOffset + 4)];
        source[checked((int)symbolOffset + 4)] = (byte)((info & 0x0F) | 0x10);
        source[checked((int)symbolOffset + 5)] = 0;

        var globalParsed = ElfParser.Parse(source);
        Assert.True(globalParsed.IsSuccess, string.Join(Environment.NewLine, globalParsed.Diagnostics));
        var selected = Assert.Single(globalParsed.File!.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var observer = Assert.Single(globalParsed.File.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_observer");
        var observerRows = globalParsed.File.SectionRelocations.Where(row =>
            row.Symbol?.Name == "urp_shared_jump_table"
            && row.Relocation.Offset >= observer.Value
            && row.Relocation.Offset - observer.Value < observer.Size).ToArray();
        Assert.Equal(2, observerRows.Length);
        foreach (var row in observerRows)
        {
            var infoOffset = GetSectionRelocationFileOffset(globalParsed.File, row) + 8;
            BinaryPrimitives.WriteUInt64LittleEndian(
                source.AsSpan(checked((int)infoOffset), sizeof(ulong)),
                row.Relocation.Type);
        }

        var reparsed = ElfParser.Parse(source);
        Assert.True(reparsed.IsSuccess, string.Join(Environment.NewLine, reparsed.Diagnostics));
        var selectedReferences = reparsed.File!.SectionRelocations
            .Where(row => row.Symbol?.Name == "urp_shared_jump_table")
            .ToArray();
        Assert.Equal(2, selectedReferences.Length);
        Assert.All(selectedReferences, row =>
        {
            Assert.Equal(1, row.Symbol!.Binding);
            Assert.Equal(0, row.Symbol.Visibility);
            Assert.InRange(row.Relocation.Offset, selected.Value, selected.Value + selected.Size - sizeof(uint));
        });
        return source;
    }

    private static void StripSectionHeaders(byte[] source)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(source.AsSpan(40, sizeof(ulong)), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(source.AsSpan(60, sizeof(ushort)), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(source.AsSpan(62, sizeof(ushort)), 0);
    }

    private static ulong GetSectionSymbolFileOffset(ElfFile file, ElfSectionSymbolIdentity symbol)
    {
        var table = file.SectionHeaders[checked((int)symbol.SymbolTableSectionIndex)];
        var offset = checked(table.Offset + (ulong)symbol.SymbolIndex * table.EntrySize);
        Assert.True(offset <= (ulong)file.Bytes.Length);
        Assert.True(ElfConstants.SymbolEntrySize64 <= (ulong)file.Bytes.Length - offset);
        return offset;
    }

    private static ulong GetSectionRelocationFileOffset(ElfFile file, ElfSectionRelocation relocation)
    {
        var section = file.SectionHeaders[relocation.RelocationSectionIndex];
        Assert.True(relocation.RelocationSourceAddress.Value >= section.Address);
        var delta = relocation.RelocationSourceAddress.Value - section.Address;
        Assert.True(delta <= section.Size);
        Assert.True(ElfConstants.RelaEntrySize64 <= section.Size - delta);
        var offset = checked(section.Offset + delta);
        Assert.True(offset <= (ulong)file.Bytes.Length);
        Assert.True(ElfConstants.RelaEntrySize64 <= (ulong)file.Bytes.Length - offset);
        return offset;
    }

    private static void AssertClonePreservesSourceAndRetargetsSelectedReference(
        Scenario scenario,
        ProtectedImageDocument image,
        SemanticPlanSnapshot snapshot)
    {
        var sourceParse = ElfParser.Parse(scenario.Source);
        Assert.True(sourceParse.IsSuccess, string.Join(Environment.NewLine, sourceParse.Diagnostics));
        var source = sourceParse.File!;
        var table = Assert.Single(snapshot.Extensions.OfType<SemanticJumpTableExtension>());
        var rehydrated = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            scenario.Artifact,
            scenario.RehydrationOptions);
        Assert.True(rehydrated.IsSuccess, string.Join(Environment.NewLine, rehydrated.Diagnostics));
        var native = rehydrated.NativeImage!;
        var layout = Assert.IsType<UrProtect.Core.ElfLayout.ElfLayoutEvidence>(native.LayoutEvidence);
        var clone = Assert.Single(layout.JumpTableClones);
        Assert.Equal(table.Ownership, clone.Ownership);
        Assert.Equal(SemanticJumpTableRewritePolicy.CopiedAndRetargeted, clone.RewritePolicy);
        Assert.Equal(ElfConstants.PfR, clone.Permissions);
        Assert.NotEqual(clone.SourceTableRange.VirtualAddress, clone.OutputRange.VirtualAddress);
        Assert.NotEqual(clone.SourceTableRange.FileOffset, clone.OutputRange.FileOffset);
        Assert.Equal(table.TableRange.Size, clone.OutputRange.Size);
        var readOnlySegments = native.ParsedImage.LoadMap.Segments.Where(segment =>
            segment.Flags == ElfConstants.PfR
            && segment.ContainsVirtualAddress(clone.OutputRange.VirtualAddress.Value, clone.OutputRange.Size)
            && segment.ContainsFileOffset(clone.OutputRange.FileOffset.Value, clone.OutputRange.Size)).ToArray();
        Assert.Single(readOnlySegments);

        var originalTableBytes = scenario.Source.AsSpan(
            checked((int)table.TableRange.FileOffset.Value),
            checked((int)table.TableRange.Size)).ToArray();
        Assert.Equal(originalTableBytes, native.Bytes.AsSpan(
            checked((int)table.TableRange.FileOffset.Value),
            checked((int)table.TableRange.Size)).ToArray());

        var observer = Assert.Single(source.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_observer");
        Assert.True(source.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(observer.Value),
            observer.Size,
            out var observerOffset));
        Assert.Equal(scenario.Source.AsSpan(checked((int)observerOffset.Value), checked((int)observer.Size)).ToArray(),
            native.Bytes.AsSpan(checked((int)observerOffset.Value), checked((int)observer.Size)).ToArray());

        var selected = Assert.Single(source.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var region = Assert.Single(image.Operations.OfType<ProtectedImageEmitRegion>(), candidate =>
            candidate.SourceAddress.Value == selected.Value && candidate.SourceSize == selected.Size);
        var functionMap = Assert.Single(snapshot.Plan.AddressMap.Entries, entry =>
            entry.Identity.Kind == SemanticEntityKind.Function
            && entry.SourceRange.VirtualAddress.Value == selected.Value
            && entry.SourceRange.Size == selected.Size);
        var placementIdentity = $"region:{region.RegionId:D10}";
        var placement = Assert.Single(layout.Placements, candidate =>
            candidate.Identity == placementIdentity && candidate.SourceIdentity == placementIdentity);
        var decoder = new AsmStoneAdapter();
        var observedTableAddress = new VirtualAddress(0);
        foreach (var producer in table.TableReferenceProducers)
        {
            Assert.True(snapshot.Plan.AddressMap.TryGet(
                SemanticEntityId.Instruction(new VirtualAddress(producer.InstructionAddress)),
                out var instructionMap));
            Assert.True(instructionMap.OutputRange.VirtualAddress.Value >= functionMap.OutputRange.VirtualAddress.Value);
            var relativeOffset = instructionMap.OutputRange.VirtualAddress.Value
                - functionMap.OutputRange.VirtualAddress.Value;
            Assert.True(relativeOffset <= placement.Size);
            Assert.True(sizeof(uint) <= placement.Size - relativeOffset);
            var outputAddress = checked(placement.VirtualAddress.Value + relativeOffset);
            Assert.True(native.ParsedImage.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(outputAddress),
                sizeof(uint),
                out var outputOffset));
            var word = BinaryPrimitives.ReadUInt32LittleEndian(
                native.Bytes.AsSpan(checked((int)outputOffset.Value), sizeof(uint)));
            var decoded = decoder.Decode(word, outputAddress);
            Assert.True(decoded.IsSuccess, decoded.Diagnostic);
            if (producer.Kind == Aarch64JumpTableReferenceKind.AdrpPage)
            {
                Assert.Equal("ADRP", decoded.Instruction!.Mnemonic.ToUpperInvariant());
                Assert.Equal(clone.OutputRange.VirtualAddress.Value & ~0xFFFUL, decoded.Instruction.DirectTarget);
                observedTableAddress = new VirtualAddress(decoded.Instruction.DirectTarget!.Value);
            }
            else
            {
                Assert.Equal("ADD", decoded.Instruction!.Mnemonic.ToUpperInvariant());
                var immediate = ((ulong)(word >> 10) & 0xFFFUL) << (((word >> 22) & 1) == 0 ? 0 : 12);
                observedTableAddress = new VirtualAddress(observedTableAddress.Value + immediate);
            }
        }

        Assert.Equal(clone.OutputRange.VirtualAddress, observedTableAddress);
    }

    private static (ProtectedImageDocument Image, SemanticPlanSnapshot Snapshot) DecodeSnapshot(Scenario scenario)
    {
        var decodedImage = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256);
        Assert.True(decodedImage.IsSuccess, string.Join(Environment.NewLine, decodedImage.Diagnostics));
        var image = decodedImage.Image!;
        var operation = Assert.Single(image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decodedSnapshot = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decodedSnapshot.IsSuccess, string.Join(Environment.NewLine, decodedSnapshot.Diagnostics));
        return (image, decodedSnapshot.Snapshot!);
    }

    private static byte[] EncodeWithTable(
        Scenario scenario,
        ProtectedImageDocument image,
        SemanticPlanSnapshot snapshot,
        SemanticJumpTableExtension replacement)
    {
        var plan = new SemanticRewritePlan(
            snapshot.Plan.AddressMap,
            snapshot.Plan.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Plan.Extensions.Select(extension => extension is SemanticJumpTableExtension ? replacement : extension),
            snapshot.Plan.Diagnostics);
        var encodedSnapshot = SemanticPlanSnapshotCodec.Create(plan);
        Assert.True(encodedSnapshot.IsSuccess, string.Join(Environment.NewLine, encodedSnapshot.Diagnostics));
        var operations = image.Operations.Select(operation => operation is ProtectedImageSemanticPlanSnapshot
            ? new ProtectedImageSemanticPlanSnapshot(encodedSnapshot.Snapshot!)
            : operation).ToArray();
        var encodedArtifact = ProtectedImageCodec.Encode(image with { Operations = operations });
        Assert.True(encodedArtifact.IsSuccess, string.Join(Environment.NewLine, encodedArtifact.Diagnostics));
        return encodedArtifact.ArtifactBytes!;
    }

    private static SemanticJumpTableExtension CopyTable(
        SemanticJumpTableExtension table,
        IEnumerable<Aarch64JumpTableOwnerReference> owners,
        IEnumerable<Aarch64JumpTableReferenceProducer>? producers = null) =>
        new(
            table.TableIdentity,
            table.TableRange,
            table.EntrySize,
            table.Targets,
            table.Encoding,
            table.BaseAddress,
            table.TargetBaseAddress,
            table.SourceInstruction,
            table.IsSigned,
            table.Scale,
            table.Addend,
            table.LowerBound,
            table.UpperBound,
            table.DefaultTarget,
            table.Ownership,
            table.RewritePolicy,
            table.OutputRange,
            table.Entries,
            table.Diagnostic,
            producers ?? table.TableReferenceProducers,
            owners,
            table.OwnerInventoryComplete);

    private static byte[] ReadSource() =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixturePath));

    private static Scenario CreateScenario(byte[]? sourceOverride = null)
    {
        var source = sourceOverride?.ToArray() ?? ReadSource();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var selected = Assert.Single(parsed.File!.FunctionSymbols, function =>
            function.IsDynamic && function.Name == "urp_entry");
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Dynamic, selected.TableIndex) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        var emitted = new ProtectedImageProducer().Emit(
            source,
            request,
            new ProtectedImageProducerOptions(
                UnitId,
                ProtectedImageProfile.HostContextEntry,
                ProducerId,
                ProducerBuild,
                ConsumerId,
                sourceHash,
                requestHash));
        Assert.True(emitted.IsSuccess, string.Join(Environment.NewLine, emitted.Diagnostics));
        return new Scenario(
            source,
            sourceHash,
            requestHash,
            emitted.ArtifactBytes!,
            new RehydrationOptions(
                sourceHash,
                emitted.Role!.RequestSha256,
                UnitId,
                ProtectedImageProfile.HostContextEntry,
                ProducerId,
                ProducerBuild,
                ConsumerId,
                ConsumerBuild));
    }

    private static void RefreshSnapshotDigest(byte[] bytes)
    {
        var digestOffset = bytes.Length - 32;
        SHA256.HashData(bytes.AsSpan(0, digestOffset)).CopyTo(bytes.AsSpan(digestOffset));
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record Scenario(
        byte[] Source,
        string SourceSha256,
        string RequestSha256,
        byte[] Artifact,
        RehydrationOptions RehydrationOptions);
}
