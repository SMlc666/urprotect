using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Semantics;

public sealed class SemanticPlanSnapshotTests
{
    [Fact]
    public void EquivalentPlansUseDeterministicEntityFixupAndExtensionOrdering()
    {
        var first = CreatePlan(reverseOrder: false);
        var second = CreatePlan(reverseOrder: true);

        var firstSnapshot = SemanticPlanSnapshotCodec.Create(first);
        var secondSnapshot = SemanticPlanSnapshotCodec.Create(second);

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
            new SemanticTlsBindingExtension(CreateTlsBinding(TlsAccessModel.InitialExec)),
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
        Assert.Equal(TlsAccessModel.InitialExec, Assert.IsType<SemanticTlsBindingExtension>(
            decoded.Snapshot.Extensions.Single(extension => extension.Kind == SemanticPlanExtensionKind.TlsBinding)).Model);
        Assert.Equal("cfa=sp+16", Assert.IsType<SemanticCfiEffectExtension>(
            decoded.Snapshot.Extensions.Single(extension => extension.Kind == SemanticPlanExtensionKind.CfiEffect)).Effect);
    }

    [Theory]
    [InlineData(TlsAccessModel.LocalExec)]
    [InlineData(TlsAccessModel.InitialExec)]
    [InlineData(TlsAccessModel.LocalDynamic)]
    [InlineData(TlsAccessModel.GeneralDynamic)]
    [InlineData(TlsAccessModel.TlsDesc)]
    public void EveryTlsModelHasTypedCanonicalSnapshotCoverage(TlsAccessModel model)
    {
        var result = SemanticPlanSnapshotCodec.Create(CreatePlan(
            extensions: new ISemanticPlanExtension[]
            {
                new SemanticTlsBindingExtension(CreateTlsBinding(model)),
            }));

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        var decoded = SemanticPlanSnapshotCodec.Decode(result.CanonicalBytes!);
        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        var binding = Assert.IsType<SemanticTlsBindingExtension>(
            Assert.Single(decoded.Snapshot!.Extensions, extension => extension.Kind == SemanticPlanExtensionKind.TlsBinding));
        Assert.Equal(model, binding.Model);
        Assert.Equal(result.PlanSha256, decoded.PlanSha256);
        Assert.Equal(result.CanonicalBytes, decoded.CanonicalBytes);

        var mappingPlan = CreateTlsMappingPlan(binding.Binding);
        var fixupPlan = TlsSemanticFixupPlanner.Build(mappingPlan);
        Assert.True(fixupPlan.IsSuccess, Describe(fixupPlan.Diagnostics));
        var expectedFixupCount = binding.Binding.RelocationSites.Count
            + (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic ? 1 : 0);
        Assert.Equal(expectedFixupCount, fixupPlan.Fixups.Count);
        Assert.All(fixupPlan.Fixups, fixup =>
        {
            Assert.Equal(model, fixup.AccessModel);
            Assert.Equal(binding.Binding.Symbol, fixup.Symbol);
            Assert.Equal(binding.Binding.AddressExpression, fixup.AddressExpression);
            Assert.NotEqual(fixup.RelocationSourceRange, fixup.RelocationOutputRange);
        });
        if (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic)
        {
            var resolverFixup = Assert.Single(fixupPlan.Fixups, fixup => fixup.PairOrdinal < 0);
            Assert.Equal(Aarch64RelocationKind.Call26, resolverFixup.Relocation.Kind);
            Assert.Equal("__tls_get_addr", resolverFixup.Relocation.SymbolName);
            Assert.Equal(binding.Binding.ResolverCall, resolverFixup.ResolverCall);
        }
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
                new SemanticTlsBindingExtension(CreateTlsBinding(TlsAccessModel.InitialExec)),
                new SemanticTlsBindingExtension(CreateTlsBinding(TlsAccessModel.InitialExec)),
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

    private static SemanticRewritePlan CreateTlsMappingPlan(TlsBinding binding)
    {
        var mapEntries = new List<AddressMapEntry>
        {
            new(
                SemanticEntityId.Function("tls-function"),
                binding.SourceRange,
                Range(
                    binding.SourceRange.VirtualAddress.Value + 0x1000,
                    binding.SourceRange.FileOffset.Value + 0x1000,
                    binding.SourceRange.Size)),
        };
        for (var index = 0; index < binding.RelocationSites.Count; index++)
        {
            var site = binding.RelocationSites[index];
            mapEntries.Add(new AddressMapEntry(
                SemanticEntityId.RelocationSite($"tls-site-{index}"),
                site.SourceRange,
                Range(
                    site.SourceRange.VirtualAddress.Value + 0x2000,
                    site.SourceRange.FileOffset.Value + 0x2000,
                    site.SourceRange.Size)));
        }

        var map = AddressMap.Create(mapEntries);
        Assert.True(map.IsSuccess, Describe(map.Diagnostics));
        Assert.True(map.Map!.TryMapSourceRange(binding.SourceRange, out _));
        var plan = SemanticRewritePlanBuilder.Build(
            map.Map!,
            Array.Empty<SemanticInstruction>(),
            Array.Empty<SemanticFixup>(),
            new[] { new SemanticTlsBindingExtension(binding) });
        Assert.True(plan.IsSuccess, Describe(plan.Diagnostics));
        return plan.Plan!;
    }

    private static TlsBinding CreateTlsBinding(TlsAccessModel model)
    {
        var module = new TlsModuleIdentity(
            TlsModuleIdentityKind.ImageLocal,
            "image:tls-fixture",
            "libtls-fixture.so",
            null,
            new TlsTemplateContract(
                new FileOffset(0x700),
                new VirtualAddress(0x4000),
                4,
                12,
                4,
                ElfConstants.PfR | ElfConstants.PfW,
                0,
                new string('0', 64)));
        var symbol = new TlsSymbolIdentity(1, "tls_value", 1, ElfConstants.SttTls, 0, 1, 4, 4, true);
        var x0 = new Aarch64RegisterView(Aarch64RegisterClass.General, 0, 64, Aarch64RegisterRole.None);
        var x1 = new Aarch64RegisterView(Aarch64RegisterClass.General, 1, 64, Aarch64RegisterRole.None);
        var roles = model switch
        {
            TlsAccessModel.LocalExec => new[]
            {
                TlsInstructionRole.ThreadPointerRead,
                TlsInstructionRole.AddressFormation,
                TlsInstructionRole.AddressFormation,
                TlsInstructionRole.TlsMemoryAccess,
            },
            TlsAccessModel.InitialExec => new[]
            {
                TlsInstructionRole.SequencePreservation,
                TlsInstructionRole.SequencePreservation,
                TlsInstructionRole.ThreadPointerRead,
                TlsInstructionRole.AddressFormation,
                TlsInstructionRole.GotEntryLoad,
                TlsInstructionRole.AddressFormation,
                TlsInstructionRole.TlsMemoryAccess,
                TlsInstructionRole.SequencePreservation,
            },
            TlsAccessModel.LocalDynamic => new[]
            {
                TlsInstructionRole.ModuleLookup,
                TlsInstructionRole.AddressFormation,
                TlsInstructionRole.ResolverCall,
                TlsInstructionRole.SymbolOffsetFormation,
                TlsInstructionRole.SymbolOffsetFormation,
                TlsInstructionRole.TlsMemoryAccess,
            },
            TlsAccessModel.GeneralDynamic => new[]
            {
                TlsInstructionRole.ModuleLookup,
                TlsInstructionRole.ResolverCall,
                TlsInstructionRole.TlsMemoryAccess,
            },
            TlsAccessModel.TlsDesc => new[]
            {
                TlsInstructionRole.AddressFormation,
                TlsInstructionRole.DescriptorLoad,
                TlsInstructionRole.AddressFormation,
                TlsInstructionRole.DescriptorCall,
                TlsInstructionRole.AddressFinalization,
            },
            _ => throw new ArgumentOutOfRangeException(nameof(model)),
        };
        var sourceRange = Range(0x3000, 0x600, checked((ulong)roles.Length * sizeof(uint)));
        var resolverKind = model switch
        {
            TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic => TlsResolverKind.TlsGetAddr,
            TlsAccessModel.TlsDesc => TlsResolverKind.TlsDesc,
            _ => TlsResolverKind.None,
        };
        var instructionRecords = roles.Select((role, index) =>
        {
            var (encoding, mnemonic) = model switch
            {
                TlsAccessModel.LocalExec => role switch
                {
                    TlsInstructionRole.ThreadPointerRead => (0xD53BD040u, "mrs"),
                    TlsInstructionRole.AddressFormation => (index == 1 ? 0x91400000u : 0x91000000u, "add"),
                    TlsInstructionRole.TlsMemoryAccess => (0xB9400009u, "ldr"),
                    _ => (0xD503201Fu, "nop"),
                },
                TlsAccessModel.InitialExec => index switch
                {
                    0 => (0xD2A00009u, "movz"),
                    1 => (0xF2800009u, "movk"),
                    2 => (0xD53BD04Au, "mrs"),
                    3 => (0x8B090149u, "add"),
                    4 => (0xF9400129u, "ldr"),
                    5 => (0x8B090149u, "add"),
                    6 => (0xB9400120u, "ldr"),
                    _ => (0xD65F03C0u, "ret"),
                },
                TlsAccessModel.LocalDynamic => index switch
                {
                    0 => (0x90000000u, "adrp"),
                    1 => (0x91000000u, "add"),
                    2 => (0x94000000u, "bl"),
                    3 => (0x91400000u, "add"),
                    4 => (0x91000000u, "add"),
                    5 => (0xB9400000u, "ldr"),
                    _ => (0xD503201Fu, "nop"),
                },
                _ => (0xD503201Fu, "nop"),
            };
            return new TlsInstructionRecord(
                Range(sourceRange.VirtualAddress.Value + checked((ulong)index * sizeof(uint)),
                    sourceRange.FileOffset.Value + checked((ulong)index * sizeof(uint)), sizeof(uint)),
                encoding,
                mnemonic,
                role,
                role == TlsInstructionRole.TlsMemoryAccess ? new[] { x0 } : Array.Empty<Aarch64RegisterView>(),
                role == TlsInstructionRole.ThreadPointerRead ? new[] { x1 } : Array.Empty<Aarch64RegisterView>(),
                Array.Empty<SemanticRegisterEffect>(),
                IsCall: role == TlsInstructionRole.ResolverCall || role == TlsInstructionRole.DescriptorCall,
                IsResolverCall: role == TlsInstructionRole.ResolverCall || role == TlsInstructionRole.DescriptorCall);
        }).ToArray();
        var relocationSpecs = model switch
        {
            TlsAccessModel.LocalExec => new[]
            {
                (ElfConstants.RArm64TlsLeAddTprelHi12, TlsRelocationFamily.Tprel, 0x3004UL, 0x604UL),
                (ElfConstants.RArm64TlsLeAddTprelLo12Nc, TlsRelocationFamily.Tprel, 0x3008UL, 0x608UL),
            },
            TlsAccessModel.InitialExec => new[]
            {
                (ElfConstants.RArm64TlsIeMovwGottprelG1, TlsRelocationFamily.GotTprel, 0x3000UL, 0x600UL),
                (ElfConstants.RArm64TlsIeMovwGottprelG0Nc, TlsRelocationFamily.GotTprel, 0x3004UL, 0x604UL),
            },
            TlsAccessModel.LocalDynamic => new[]
            {
                (ElfConstants.RArm64TlsLdAdrPage21, TlsRelocationFamily.Dtpmod, 0x3000UL, 0x600UL),
                (ElfConstants.RArm64TlsLdAddLo12Nc, TlsRelocationFamily.Dtpmod, 0x3004UL, 0x604UL),
                (ElfConstants.RArm64TlsLdAddDtprelHi12, TlsRelocationFamily.Dtprel, 0x300CUL, 0x60CUL),
                (ElfConstants.RArm64TlsLdAddDtprelLo12Nc, TlsRelocationFamily.Dtprel, 0x3010UL, 0x610UL),
            },
            TlsAccessModel.GeneralDynamic => new[]
            {
                (ElfConstants.RArm64TlsGdAdrPage21, TlsRelocationFamily.Dtpmod, 0x3000UL, 0x600UL),
                (ElfConstants.RArm64TlsGdAddLo12Nc, TlsRelocationFamily.Dtpmod, 0x3004UL, 0x604UL),
                (ElfConstants.RArm64TlsDtpMod64, TlsRelocationFamily.Dtpmod, 0x4000UL, 0x700UL),
                (ElfConstants.RArm64TlsDtpRel64, TlsRelocationFamily.Dtprel, 0x4008UL, 0x708UL),
            },
            TlsAccessModel.TlsDesc => new[]
            {
                (ElfConstants.RArm64TlsDescAdrPage21, TlsRelocationFamily.TlsDesc, 0x3000UL, 0x600UL),
                (ElfConstants.RArm64TlsDescLd64Lo12, TlsRelocationFamily.TlsDesc, 0x3004UL, 0x604UL),
                (ElfConstants.RArm64TlsDescAddLo12, TlsRelocationFamily.TlsDesc, 0x3008UL, 0x608UL),
                (ElfConstants.RArm64TlsDescCall, TlsRelocationFamily.TlsDesc, 0x300CUL, 0x60CUL),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(model)),
        };
        var sites = relocationSpecs.Select((spec, index) =>
        {
            var relocationTarget = SemanticTarget.RuntimeResolved($"tls:{symbol.Name}");
            var addend = spec.Item1 is ElfConstants.RArm64TlsLdAddDtprelHi12
                or ElfConstants.RArm64TlsLdAddDtprelLo12Nc
                ? 4L
                : 0L;
            var relocation = new RelocationBinding(
                Aarch64RelocationKind.ThreadLocal,
                relocationTarget,
                addend,
                SymbolIndex: 1,
                SymbolName: symbol.Name,
                RelocationType: spec.Item1,
                RelocationAddress: new VirtualAddress(spec.Item3),
                RelocationTableAddress: new VirtualAddress(0x4800));
            return new TlsRelocationSite(
                spec.Item2,
                Range(spec.Item3, spec.Item4, TlsRelocationClassifier.GetWriteSize(spec.Item1)),
                relocation,
                index,
                model is TlsAccessModel.InitialExec or TlsAccessModel.TlsDesc);
        }).ToArray();
        var primaryFamily = model switch
        {
            TlsAccessModel.LocalExec => TlsRelocationFamily.Tprel,
            TlsAccessModel.InitialExec => TlsRelocationFamily.GotTprel,
            TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic => TlsRelocationFamily.Dtpmod,
            TlsAccessModel.TlsDesc => TlsRelocationFamily.TlsDesc,
            _ => throw new ArgumentOutOfRangeException(nameof(model)),
        };
        var expressionKind = model switch
        {
            TlsAccessModel.LocalExec or TlsAccessModel.InitialExec => TlsAddressExpressionKind.ThreadPointerRelative,
            TlsAccessModel.LocalDynamic => TlsAddressExpressionKind.ModuleRelative,
            TlsAccessModel.GeneralDynamic => TlsAddressExpressionKind.ResolverReturned,
            TlsAccessModel.TlsDesc => TlsAddressExpressionKind.DescriptorMediated,
            _ => throw new ArgumentOutOfRangeException(nameof(model)),
        };
        var resolverTarget = resolverKind switch
        {
            TlsResolverKind.TlsGetAddr => SemanticTarget.RuntimeResolved("symbol:__tls_get_addr"),
            TlsResolverKind.TlsDesc => SemanticTarget.RuntimeResolved("tlsdesc:resolver"),
            _ => null,
        };
        TlsGotEntryBinding? gotEntry = null;
        TlsResolverCallBinding? resolverCall = null;
        TlsModuleOwnerBinding? moduleOwner = null;
        TlsDtpRelOwnerBinding? dtpRelOwner = null;
        if (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic)
        {
            var callRelocation = new RelocationBinding(
                Aarch64RelocationKind.Call26,
                SemanticTarget.RuntimeResolved("symbol:__tls_get_addr"),
                SymbolIndex: 2,
                SymbolName: "__tls_get_addr",
                RelocationType: ElfConstants.RArm64Call26,
                RelocationAddress: new VirtualAddress(0x3008),
                RelocationTableAddress: new VirtualAddress(0x4800));
            resolverCall = new TlsResolverCallBinding(Range(0x3008, 0x608, sizeof(uint)), callRelocation);
            var ownerRelocation = new RelocationBinding(
                Aarch64RelocationKind.ThreadLocal,
                SemanticTarget.RuntimeResolved($"tls-module:{module.Identity}"),
                RelocationType: ElfConstants.RArm64TlsDtpMod64,
                RelocationAddress: new VirtualAddress(0x5000),
                RelocationTableAddress: new VirtualAddress(0x4800));
            moduleOwner = new TlsModuleOwnerBinding(
                SemanticEntityId.RelocationSite("tls-module-owner:5000"),
                Range(0x5000, 0x900, sizeof(ulong)),
                ownerRelocation);
        }
        if (model == TlsAccessModel.GeneralDynamic)
        {
            var ownerRelocation = new RelocationBinding(
                Aarch64RelocationKind.ThreadLocal,
                SemanticTarget.RuntimeResolved($"tls-module:{module.Identity}:tls_value"),
                SymbolIndex: symbol.SymbolIndex,
                SymbolName: symbol.Name,
                RelocationType: ElfConstants.RArm64TlsDtpMod64,
                RelocationAddress: new VirtualAddress(0x5000),
                RelocationTableAddress: new VirtualAddress(0x4800));
            moduleOwner = new TlsModuleOwnerBinding(
                SemanticEntityId.RelocationSite("tls-module-owner:5000"),
                Range(0x5000, 0x900, sizeof(ulong)),
                ownerRelocation);
            var dtpRelocation = new RelocationBinding(
                Aarch64RelocationKind.ThreadLocal,
                SemanticTarget.RuntimeResolved($"tls-symbol:{module.Identity}:tls_value"),
                SymbolIndex: symbol.SymbolIndex,
                SymbolName: symbol.Name,
                RelocationType: ElfConstants.RArm64TlsDtpRel64,
                RelocationAddress: new VirtualAddress(0x5008),
                RelocationTableAddress: new VirtualAddress(0x4800));
            dtpRelOwner = new TlsDtpRelOwnerBinding(
                SemanticEntityId.RelocationSite("tls-dtprel-owner:5008"),
                Range(0x5008, 0x908, sizeof(ulong)),
                dtpRelocation);
        }
        if (model == TlsAccessModel.InitialExec)
        {
            var gotRelocation = new RelocationBinding(
                Aarch64RelocationKind.ThreadLocal,
                SemanticTarget.RuntimeResolved("tls-got:image:tls-fixture:tls_value"),
                SymbolIndex: symbol.SymbolIndex,
                SymbolName: symbol.Name,
                RelocationType: ElfConstants.RArm64TlsTprel64,
                RelocationAddress: new VirtualAddress(0x5000),
                RelocationTableAddress: new VirtualAddress(0x4800))
            {
                RawInfo = ((ulong)symbol.SymbolIndex << 32) | ElfConstants.RArm64TlsTprel64,
            };
            gotEntry = new TlsGotEntryBinding(
                SemanticEntityId.RelocationSite("tls-got:5000"),
                Range(0x5000, 0x900, sizeof(ulong)),
                gotRelocation,
                symbol,
                0);
        }

        return new TlsBinding(
            model,
            primaryFamily,
            SemanticEntityId.RelocationSite("tls-site"),
            sourceRange,
            new TlsInstructionSequence(sourceRange, instructionRecords, resolverKind, resolverTarget),
            module,
            symbol,
            0,
            sites,
            4,
            new TlsAddressExpression(expressionKind, module, symbol, x1, x0, 0),
            new[]
            {
                new TlsProfileRequirement(TlsProfile.OuterExecveat, false),
                new TlsProfileRequirement(TlsProfile.HostContextEntry, true),
            },
            Enum.GetValues<TlsRuntime>()
                .Where(runtime => runtime != TlsRuntime.Aarch64SystemLoader)
                .SelectMany(runtime => new[]
                {
                    new TlsRuntimeRequirement(runtime, TlsRuntimeRequirementKind.LoaderAllocatedTlsModule, true),
                    new TlsRuntimeRequirement(runtime, TlsRuntimeRequirementKind.CurrentThreadLifecycle, true),
                    new TlsRuntimeRequirement(runtime, TlsRuntimeRequirementKind.RegisteredWorkerLifecycle, false),
                }),
            gotEntry,
            resolverCall,
            moduleOwner,
            dtpRelOwner);
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
