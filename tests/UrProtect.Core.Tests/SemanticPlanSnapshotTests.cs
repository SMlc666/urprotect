using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class SemanticPlanSnapshotTests
{
    [Fact]
    public void EquivalentPlansUseDeterministicEntityFixupAndExtensionOrdering()
    {
        var first = CreatePlan(reverseOrder: false);
        var second = CreatePlan(reverseOrder: true);

        var firstSnapshot = SemanticPlanSnapshotCodec.Create(first);
        var secondSnapshot = SemanticPlanSnapshotProjector.Project(second);

        Assert.True(firstSnapshot.IsSuccess, Describe(firstSnapshot.Diagnostics));
        Assert.True(secondSnapshot.IsSuccess, Describe(secondSnapshot.Diagnostics));
        Assert.Equal(firstSnapshot.PlanSha256, secondSnapshot.PlanSha256);
        Assert.Equal(firstSnapshot.CanonicalBytes, secondSnapshot.CanonicalBytes);
        Assert.Equal(
            firstSnapshot.Snapshot!.AddressMapEntries.Select(entry => entry.Identity),
            secondSnapshot.Snapshot!.AddressMapEntries.Select(entry => entry.Identity));
        Assert.Equal(
            firstSnapshot.Snapshot.Fixups.Select(fixup => fixup.SourceAddress),
            secondSnapshot.Snapshot.Fixups.Select(fixup => fixup.SourceAddress));
    }

    [Fact]
    public void EquivalentPlansWithTargetSortKeyPrefixesUseDeterministicOrdering()
    {
        var firstExtensions = new ISemanticPlanExtension[]
        {
            new SemanticJumpTableExtension(
                SemanticEntityId.Table("canonical-table"),
                Range(0x4000, 0x700, sizeof(uint)),
                sizeof(uint),
                new[]
                {
                    SemanticTarget.BoundedSet(new[] { new VirtualAddress(0x1010) }),
                    SemanticTarget.BoundedSet(new[] { new VirtualAddress(0x1000) }),
                }),
        };
        var secondExtensions = new ISemanticPlanExtension[]
        {
            new SemanticJumpTableExtension(
                SemanticEntityId.Table("canonical-table"),
                Range(0x4000, 0x700, sizeof(uint)),
                sizeof(uint),
                new[]
                {
                    SemanticTarget.BoundedSet(new[] { new VirtualAddress(0x1000) }),
                    SemanticTarget.BoundedSet(new[] { new VirtualAddress(0x1010) }),
                }),
        };

        var first = SemanticPlanSnapshotCodec.Create(CreatePlan(extensions: firstExtensions));
        var second = SemanticPlanSnapshotCodec.Create(CreatePlan(extensions: secondExtensions));

        Assert.True(first.IsSuccess, Describe(first.Diagnostics));
        Assert.True(second.IsSuccess, Describe(second.Diagnostics));
        Assert.Equal(first.PlanSha256, second.PlanSha256);
        Assert.Equal(first.CanonicalBytes, second.CanonicalBytes);
    }

    [Fact]
    public void DuplicateTargetCandidatesAreRejectedBeforeSnapshotPublication()
    {
        var target = SemanticTarget.BoundedSet(
            new[] { new VirtualAddress(0x1010), new VirtualAddress(0x1010) });
        var mapResult = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                Range(0x1000, 0x200, sizeof(uint)),
                Range(0x5000, 0x800, sizeof(uint))),
        });
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));

        var planResult = SemanticRewritePlanBuilder.Build(
            mapResult.Map!,
            Array.Empty<SemanticInstruction>(),
            new[]
            {
                new SemanticFixup(
                    SemanticFixupKind.Branch26,
                    new VirtualAddress(0x1000),
                    new FileOffset(0x200),
                    0x14000000,
                    target,
                    expression: new PcRelativeExpression(
                        PcRelativeExpressionKind.Branch26,
                        new VirtualAddress(0x1000),
                        target,
                        Scale: sizeof(uint))),
            });

        Assert.False(planResult.IsSuccess);
        Assert.Contains(
            planResult.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanMalformed
                && diagnostic.Message.Contains("duplicate candidate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EquivalentPlansWithNestedRelocationAndReferenceDifferencesUseDeterministicOrdering()
    {
        var target = SemanticTarget.Exact(new VirtualAddress(0x1010));
        var relocations = new[]
        {
            new RelocationBinding(
                Aarch64RelocationKind.Call26,
                target,
                Addend: 1,
                RelocationType: ElfConstants.RArm64Call26),
            new RelocationBinding(
                Aarch64RelocationKind.Call26,
                target,
                Addend: 2,
                RelocationType: ElfConstants.RArm64Call26),
        };
        var references = new[]
        {
            new SemanticReference(
                SemanticReferenceKind.PcRelative,
                target,
                PcRelative: new PcRelativeExpression(
                    PcRelativeExpressionKind.Branch26,
                    new VirtualAddress(0x1000),
                    target,
                    Scale: sizeof(uint),
                    Addend: 1),
                Description: "same-reference"),
            new SemanticReference(
                SemanticReferenceKind.PcRelative,
                target,
                PcRelative: new PcRelativeExpression(
                    PcRelativeExpressionKind.Branch26,
                    new VirtualAddress(0x1000),
                    target,
                    Scale: sizeof(uint),
                    Addend: 2),
                Description: "same-reference"),
        };

        var first = SemanticPlanSnapshotCodec.Create(
            CreatePlan(instructionRelocations: relocations, references: references));
        var second = SemanticPlanSnapshotCodec.Create(
            CreatePlan(
                instructionRelocations: relocations.Reverse(),
                references: references.Reverse()));

        Assert.True(first.IsSuccess, Describe(first.Diagnostics));
        Assert.True(second.IsSuccess, Describe(second.Diagnostics));
        Assert.Equal(first.PlanSha256, second.PlanSha256);
        Assert.Equal(first.CanonicalBytes, second.CanonicalBytes);
    }

    [Fact]
    public void EmptyEntityIdentityIsRejectedBySnapshotValidation()
    {
        var target = SemanticTarget.Exact(
            new SemanticEntityId(SemanticEntityKind.RelocationTarget, string.Empty));
        var mapResult = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                Range(0x1000, 0x200, sizeof(uint)),
                Range(0x5000, 0x800, sizeof(uint))),
        });
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));

        var plan = new SemanticRewritePlan(
            mapResult.Map!,
            Array.Empty<SemanticInstruction>(),
            new[]
            {
                new SemanticFixup(
                    SemanticFixupKind.Branch26,
                    new VirtualAddress(0x1000),
                    new FileOffset(0x200),
                    0x14000000,
                    target,
                    expression: new PcRelativeExpression(
                        PcRelativeExpressionKind.Branch26,
                        new VirtualAddress(0x1000),
                        target,
                        Scale: sizeof(uint))),
            });

        var result = SemanticPlanSnapshotCodec.Create(plan);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Snapshot);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed);
    }

    [Fact]
    public void CanonicalBytesRoundTripAndRetainRawRelocationMetadata()
    {
        var snapshotResult = SemanticPlanSnapshotCodec.Create(CreatePlan());
        Assert.True(snapshotResult.IsSuccess, Describe(snapshotResult.Diagnostics));

        var decoded = SemanticPlanSnapshotCodec.Decode(snapshotResult.CanonicalBytes!);

        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        Assert.Equal(snapshotResult.PlanSha256, decoded.PlanSha256);
        Assert.Equal(snapshotResult.CanonicalBytes, decoded.CanonicalBytes);
        var relocation = Assert.Single(
            decoded.Snapshot!.Plan.Fixups,
            fixup => fixup.Relocation?.RelocationType == ElfConstants.RArm64Call26).Relocation!;
        Assert.Equal(ElfConstants.RArm64Call26, relocation.RelocationType);
        Assert.Equal(0x0000_0012_0000_011BuL, relocation.RawInfo);
        Assert.Equal(new VirtualAddress(0x4800), relocation.RelocationTableAddress);
    }

    [Fact]
    public void CanonicalExtensionRecordsRoundTripWithoutDroppingSiblingDomains()
    {
        var extensions = new ISemanticPlanExtension[]
        {
            new SemanticIndirectTargetExtension(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                new VirtualAddress(0x1000),
                SemanticTarget.RuntimeResolved("indirect:resolver"),
                "indirect target is owned by the sibling resolver"),
            new SemanticUnresolvedReferenceExtension(
                SemanticEntityId.Instruction(new VirtualAddress(0x1004)),
                new VirtualAddress(0x1004),
                SemanticReferenceKind.Memory,
                SemanticTarget.Unresolved("memory target is not modeled yet"),
                "memory target requires a sibling resolver"),
            new SemanticRelocationBindingExtension(
                SemanticEntityId.RelocationSite("extension-site"),
                new RelocationBinding(
                    Aarch64RelocationKind.Absolute64,
                    SemanticTarget.Exact(new VirtualAddress(0x1010)),
                    RelocationType: ElfConstants.RArm64Abs64),
                "relocation site is owned by the layout child"),
            new SemanticTlsBindingExtension(
                SemanticEntityId.RelocationSite("tls-site"),
                Range(0x3000, 0x600, sizeof(ulong)),
                new RelocationBinding(
                    Aarch64RelocationKind.ThreadLocal,
                    SemanticTarget.RuntimeResolved("tls:module"),
                    RelocationType: ElfConstants.RArm64TlsTprel64),
                "initial-exec"),
            new SemanticJumpTableExtension(
                SemanticEntityId.Table("jump-table"),
                Range(0x4000, 0x700, 16),
                sizeof(uint),
                new[]
                {
                    SemanticTarget.BoundedSet(new[] { new VirtualAddress(0x1004), new VirtualAddress(0x1000) }),
                    SemanticTarget.Exact(new VirtualAddress(0x1000)),
                },
                "relative-u32"),
            new SemanticCfiEffectExtension(
                SemanticEntityId.Instruction(new VirtualAddress(0x1004)),
                Range(0x1004, 0x204, sizeof(uint)),
                "cfa=sp+16",
                new[]
                {
                    new SemanticRegisterEffect(
                        new Aarch64RegisterView(
                            Aarch64RegisterClass.General,
                            0,
                            64,
                            Aarch64RegisterRole.None),
                        SemanticRegisterEffectKind.Read,
                        IsImplicit: true),
                },
                "CFI emission is owned by the unwind child"),
        };

        var result = SemanticPlanSnapshotCodec.Create(CreatePlan(extensions: extensions));
        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var decoded = SemanticPlanSnapshotCodec.Decode(result.CanonicalBytes!);

        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        Assert.Equal(
            new[]
            {
                SemanticPlanExtensionKind.IndirectTargets,
                SemanticPlanExtensionKind.TlsBinding,
                SemanticPlanExtensionKind.JumpTable,
                SemanticPlanExtensionKind.CfiEffect,
                SemanticPlanExtensionKind.RelocationBinding,
                SemanticPlanExtensionKind.UnresolvedReference,
            },
            decoded.Snapshot!.Extensions.Select(extension => extension.Kind));
        Assert.Equal("initial-exec", Assert.IsType<SemanticTlsBindingExtension>(
            decoded.Snapshot.Extensions.Single(extension => extension.Kind == SemanticPlanExtensionKind.TlsBinding)).Model);
        Assert.Equal("cfa=sp+16", Assert.IsType<SemanticCfiEffectExtension>(
            decoded.Snapshot.Extensions.Single(extension => extension.Kind == SemanticPlanExtensionKind.CfiEffect)).Effect);
    }

    [Fact]
    public void MutatedCanonicalBytesFailDigestValidationBeforeProjection()
    {
        var snapshotResult = SemanticPlanSnapshotCodec.Create(CreatePlan());
        Assert.True(snapshotResult.IsSuccess, Describe(snapshotResult.Diagnostics));

        var mutated = snapshotResult.CanonicalBytes!;
        mutated[mutated.Length / 2] ^= 0x01;
        var result = SemanticPlanSnapshotCodec.Decode(mutated);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Snapshot);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotIntegrityMismatch);
    }

    [Fact]
    public void OversizedMetadataIsRejectedWithoutCreatingASnapshot()
    {
        var oversizedMnemonic = new string('m', SemanticPlanSnapshotLimits.MaximumStringBytes + 1);
        var plan = CreatePlan(instructionMnemonic: oversizedMnemonic);

        var result = SemanticPlanSnapshotCodec.Create(plan);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Snapshot);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
    }

    [Theory]
    [InlineData("bounded")]
    [InlineData("runtime")]
    [InlineData("unresolved")]
    public void SnapshotRetainsDeferredAndUnresolvedFixupClassification(string classification)
    {
        var target = classification switch
        {
            "bounded" => SemanticTarget.BoundedSet(new[] { new VirtualAddress(0x1010) }),
            "runtime" => SemanticTarget.RuntimeResolved("plt:TARGET"),
            _ => SemanticTarget.Unresolved("indirect target requires sibling resolver"),
        };
        var result = SemanticPlanSnapshotCodec.Create(CreateFixupPlan(target));

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var fixup = Assert.Single(result.Snapshot!.Fixups);
        Assert.Equal(
            classification == "unresolved"
                ? SemanticFixupResolutionState.Unresolved
                : SemanticFixupResolutionState.Deferred,
            fixup.ResolutionState);
        Assert.Equal(target.Resolution, fixup.Target.Resolution);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code is DiagnosticCode.SemanticFixupDeferred
                or DiagnosticCode.SemanticTargetUnresolved);
    }

    [Fact]
    public void SnapshotCollectionsAndBytesAreDefensiveCopies()
    {
        var result = SemanticPlanSnapshotCodec.Create(CreatePlan());
        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var snapshot = result.Snapshot!;

        Assert.Throws<NotSupportedException>(() =>
            ((IList<SemanticInstruction>)snapshot.Instructions).Clear());
        Assert.Throws<NotSupportedException>(() =>
            ((IList<SemanticFixupSnapshot>)snapshot.Fixups).Clear());
        var bytes = snapshot.CanonicalBytes;
        var originalFirstByte = bytes[0];
        bytes[0] ^= 0xFF;
        Assert.Equal(originalFirstByte, snapshot.CanonicalBytes[0]);
        Assert.Equal(snapshot.PlanSha256, SemanticPlanSnapshotCodec.ComputeSha256(snapshot.CanonicalBytes));
    }

    [Fact]
    public void DuplicateExtensionIdentityIsRejected()
    {
        var plan = CreatePlan(
            extensions: new ISemanticPlanExtension[]
            {
                new SemanticTlsBindingExtension(
                    SemanticEntityId.RelocationSite("tls-site"),
                    Range(0x3000, 0x600, 8),
                    new RelocationBinding(
                        Aarch64RelocationKind.ThreadLocal,
                        SemanticTarget.RuntimeResolved("tls:module"),
                        RelocationType: ElfConstants.RArm64TlsTprel64),
                    "initial-exec"),
                new SemanticTlsBindingExtension(
                    SemanticEntityId.RelocationSite("tls-site"),
                    Range(0x3000, 0x600, 8),
                    new RelocationBinding(
                        Aarch64RelocationKind.ThreadLocal,
                        SemanticTarget.RuntimeResolved("tls:module"),
                        RelocationType: ElfConstants.RArm64TlsTprel64),
                    "initial-exec"),
            });

        var result = SemanticPlanSnapshotCodec.Create(plan);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
                && diagnostic.Message.Contains("duplicate extension", StringComparison.OrdinalIgnoreCase));
    }

    private static SemanticRewritePlan CreatePlan(
        bool reverseOrder = false,
        string instructionMnemonic = "nop",
        IEnumerable<ISemanticPlanExtension>? extensions = null,
        IEnumerable<RelocationBinding>? instructionRelocations = null,
        IEnumerable<SemanticReference>? references = null)
    {
        var instructions = new[]
        {
            new SemanticInstruction(
                new VirtualAddress(0x1000),
                new FileOffset(0x200),
                0xD503201F,
                instructionMnemonic,
                Range(0x1000, 0x200, sizeof(uint)),
                relocations: instructionRelocations,
                references: references),
            new SemanticInstruction(
                new VirtualAddress(0x1004),
                new FileOffset(0x204),
                0xD503201F,
                "nop",
                Range(0x1004, 0x204, sizeof(uint))),
        };
        var relocationTarget = SemanticTarget.Exact(new VirtualAddress(0x1010));
        var relocations = new[]
        {
            SemanticFixup.FromRelocation(
                new VirtualAddress(0x2000),
                new FileOffset(0x500),
                0,
                new RelocationBinding(
                    Aarch64RelocationKind.Call26,
                    relocationTarget,
                    Addend: 4,
                    SymbolIndex: 0x12,
                    IsPlt: true,
                    SymbolName: "TARGET",
                    RelocationType: ElfConstants.RArm64Call26,
                    RelocationAddress: new VirtualAddress(0x2000),
                    RelocationTableAddress: new VirtualAddress(0x4800))
                {
                    RawInfo = 0x0000_0012_0000_011BuL,
                }),
            SemanticFixup.FromRelocation(
                new VirtualAddress(0x2010),
                new FileOffset(0x510),
                0,
                new RelocationBinding(
                    Aarch64RelocationKind.Absolute64,
                    SemanticTarget.Exact(new VirtualAddress(0x1010)),
                    Addend: 8,
                    RelocationType: ElfConstants.RArm64Abs64,
                    RelocationAddress: new VirtualAddress(0x2010))),
        };

        var entries = new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                Range(0x1000, 0x200, sizeof(uint)),
                Range(0x5000, 0x800, sizeof(uint))),
            new AddressMapEntry(
                SemanticEntityId.Instruction(new VirtualAddress(0x1004)),
                Range(0x1004, 0x204, sizeof(uint)),
                Range(0x5004, 0x804, sizeof(uint))),
            new AddressMapEntry(
                SemanticEntityId.RelocationSite("0x2000"),
                Range(0x2000, 0x500, sizeof(uint)),
                Range(0x6000, 0x900, sizeof(uint))),
            new AddressMapEntry(
                SemanticEntityId.RelocationSite("0x2010"),
                Range(0x2010, 0x510, sizeof(ulong)),
                Range(0x6010, 0x910, sizeof(ulong))),
            new AddressMapEntry(
                SemanticEntityId.RelocationTarget("0x1010"),
                Range(0x1010, 0x210, sizeof(uint)),
                Range(0x5010, 0x810, sizeof(uint))),
        };

        var orderedInstructions = reverseOrder ? instructions.Reverse() : instructions;
        var orderedRelocations = reverseOrder ? relocations.Reverse() : relocations;
        var orderedEntries = reverseOrder ? entries.Reverse() : entries;
        var mapResult = AddressMap.Create(orderedEntries);
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));
        var planResult = SemanticRewritePlanBuilder.Build(
            mapResult.Map!,
            orderedInstructions,
            orderedRelocations,
            extensions);
        Assert.True(planResult.IsSuccess, Describe(planResult.Diagnostics));
        return planResult.Plan!;
    }

    private static SemanticRewritePlan CreateFixupPlan(SemanticTarget target)
    {
        var mapResult = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                Range(0x1000, 0x200, sizeof(uint)),
                Range(0x5000, 0x800, sizeof(uint))),
        });
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));
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
        return planResult.Plan!;
    }

    private static SemanticSourceRange Range(ulong virtualAddress, ulong fileOffset, ulong size) =>
        new(new FileOffset(fileOffset), new VirtualAddress(virtualAddress), size);

    private static string Describe(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(Environment.NewLine, diagnostics);
}
