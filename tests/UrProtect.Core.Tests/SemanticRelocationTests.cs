using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class SemanticRelocationTests
{
    [Fact]
    public void ExactTargetMapsSourceAndEncodesBranch26()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            0x14000000);

        var planResult = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        Assert.True(planResult.IsSuccess, string.Join(Environment.NewLine, planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        Assert.True(resolution.IsSuccess, string.Join(Environment.NewLine, resolution.Diagnostics));
        var resolved = Assert.Single(resolution.Fixups);
        Assert.True(resolved.IsFinal);
        Assert.Equal(new VirtualAddress(0x5000), resolved.OutputSourceAddress);
        Assert.Equal(new VirtualAddress(0x5010), resolved.OutputTargetAddress);
        Assert.Equal(0x14000004u, resolved.InstructionEncoding);
    }

    [Fact]
    public void Branch26NegativeOffsetUsesSignedImmediateBits()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.BasicBlock, 0x0FFC, 0x210, 0x4FFC, 0x810));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.Exact(new VirtualAddress(0x0FFC)),
            0x14000000);

        var result = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        var resolution = result.Plan!.ResolveFixups();

        Assert.True(resolution.IsSuccess, string.Join(Environment.NewLine, resolution.Diagnostics));
        Assert.Equal(0x17FFFFFFu, Assert.Single(resolution.Fixups).InstructionEncoding);
    }

    [Fact]
    public void BoundedTargetSetIsDeferredWithoutSelectingAnArbitraryTarget()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target-a", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810),
            Mapping("target-b", SemanticEntityKind.BasicBlock, 0x1020, 0x220, 0x5020, 0x820));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.BoundedSet(new[]
            {
                new VirtualAddress(0x1010),
                new VirtualAddress(0x1020),
            }),
            0x14000000);

        var planResult = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        Assert.True(planResult.IsSuccess, string.Join(Environment.NewLine, planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        var resolved = Assert.Single(resolution.Fixups);
        Assert.False(resolution.IsSuccess);
        Assert.True(resolved.IsSuccess);
        Assert.True(resolved.IsDeferred);
        Assert.Null(resolved.InstructionEncoding);
        Assert.Contains(resolved.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupDeferred);
    }

    [Fact]
    public void BoundedTargetRemainsDeferredWhenOneCandidateMapsToOneOutputAddress()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target-a", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.BoundedSet(new[] { new VirtualAddress(0x1010) }),
            0x14000000);

        var planResult = SemanticRewritePlanBuilder.Build(
            addressMap,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });
        Assert.True(planResult.IsSuccess, string.Join(Environment.NewLine, planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        var resolved = Assert.Single(resolution.Fixups);
        Assert.False(resolution.IsSuccess);
        Assert.True(resolved.IsDeferred);
        Assert.Null(resolved.InstructionEncoding);
        Assert.Equal(new VirtualAddress(0x5010), resolved.OutputTargetAddress);
        Assert.Contains(
            resolved.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupDeferred);
    }

    [Fact]
    public void RuntimeResolvedTargetIsDeferredWithBindingDiagnostic()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Call26,
            PcRelativeExpressionKind.Call26,
            SemanticTarget.RuntimeResolved("plt:TARGET"),
            0x94000000);

        var planResult = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        Assert.True(planResult.IsSuccess, string.Join(Environment.NewLine, planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        var resolved = Assert.Single(resolution.Fixups);
        Assert.False(resolution.IsSuccess);
        Assert.True(resolved.IsDeferred);
        Assert.Contains(resolved.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupDeferred);
    }

    [Fact]
    public void UnresolvedTargetFailsBeforeAnEncodingIsProduced()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.Unresolved("indirect target requires sibling resolver"),
            0x14000000);

        var planResult = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        Assert.True(planResult.IsSuccess, string.Join(Environment.NewLine, planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        var resolved = Assert.Single(resolution.Fixups);
        Assert.False(resolution.IsSuccess);
        Assert.False(resolved.IsSuccess);
        Assert.Null(resolved.InstructionEncoding);
        Assert.Contains(resolved.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticTargetUnresolved);
    }

    [Fact]
    public void AddressMapRejectsDuplicateIdentityAndDuplicateSourceAddress()
    {
        var duplicateIdentity = AddressMap.Create(new[]
        {
            Mapping("same", SemanticEntityKind.Function, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("same", SemanticEntityKind.Function, 0x1010, 0x210, 0x5010, 0x810),
        });
        Assert.False(duplicateIdentity.IsSuccess);
        Assert.Null(duplicateIdentity.Map);
        Assert.Contains(
            duplicateIdentity.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapDuplicate);

        var duplicateAddress = AddressMap.Create(new[]
        {
            Mapping("first", SemanticEntityKind.Function, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("second", SemanticEntityKind.Function, 0x1000, 0x200, 0x6000, 0x900),
        });
        Assert.False(duplicateAddress.IsSuccess);
        Assert.Contains(
            duplicateAddress.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapDuplicate);
    }

    [Fact]
    public void AddressMapRejectsSourceAndOutputRangeOverflow()
    {
        var sourceOverflow = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Function("source-overflow"),
                new SemanticSourceRange(new FileOffset(ulong.MaxValue), new VirtualAddress(0x1000), 2),
                new SemanticSourceRange(new FileOffset(0x800), new VirtualAddress(0x5000), 2)),
        });
        Assert.False(sourceOverflow.IsSuccess);
        Assert.Contains(
            sourceOverflow.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapOverflow);

        var outputOverflow = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Function("output-overflow"),
                new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), 2),
                new SemanticSourceRange(new FileOffset(ulong.MaxValue), new VirtualAddress(0x5000), 2)),
        });
        Assert.False(outputOverflow.IsSuccess);
        Assert.Contains(
            outputOverflow.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapOverflow);
    }

    [Fact]
    public void PlanRejectsDuplicateInstructionsAndMismatchedFixupKinds()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810));
        var instruction = new SemanticInstruction(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0xD503201F,
            "nop",
            new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), sizeof(uint)));
        var mismatchedFixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.ConditionalBranch19,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            0x14000000);

        var result = SemanticRewritePlanBuilder.Build(
            addressMap,
            new[] { instruction, instruction },
            new[] { mismatchedFixup });

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanMalformed);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed);
    }

    [Fact]
    public void LiteralReferenceCreatesLiteralLoadFixupWhenExpressionIsOmitted()
    {
        var target = SemanticTarget.Exact(new VirtualAddress(0x1010));
        var instruction = new SemanticInstruction(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x58000000,
            "ldr",
            new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), sizeof(uint)),
            literalReference: new LiteralReference(target, sizeof(ulong)));

        var fixup = SemanticFixup.FromInstruction(instruction);

        Assert.NotNull(fixup);
        Assert.Equal(SemanticFixupKind.Literal19, fixup!.Kind);
        Assert.Equal(PcRelativeExpressionKind.Literal19, fixup.Expression!.Kind);
        Assert.Equal(target, fixup.Target);
    }

    [Fact]
    public void PlanRejectsInstructionWithoutAddressMapEntry()
    {
        var map = CreateMap(
            Mapping("target", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810));
        var instruction = new SemanticInstruction(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0xD503201F,
            "nop",
            new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), sizeof(uint)));

        var result = SemanticRewritePlanBuilder.Build(
            map,
            new[] { instruction },
            Array.Empty<SemanticFixup>());

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapMissing);
    }

    [Fact]
    public void PlanRejectsAnAnnotatedPcRelativeInstructionWithoutAFixup()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810));
        var target = SemanticTarget.Exact(new VirtualAddress(0x1010));
        var instruction = new SemanticInstruction(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x14000000,
            "b",
            new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), sizeof(uint)),
            pcRelativeExpression: new PcRelativeExpression(
                PcRelativeExpressionKind.Branch26,
                new VirtualAddress(0x1000),
                target,
                Scale: sizeof(uint)));

        var result = SemanticRewritePlanBuilder.Build(
            addressMap,
            new[] { instruction },
            Array.Empty<SemanticFixup>());

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanMalformed);
    }

    [Fact]
    public void PlanRejectsPcRelativeScaleMismatch()
    {
        var map = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810));
        var fixup = new SemanticFixup(
            SemanticFixupKind.Branch26,
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x14000000,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            expression: new PcRelativeExpression(
                PcRelativeExpressionKind.Branch26,
                new VirtualAddress(0x1000),
                SemanticTarget.Exact(new VirtualAddress(0x1010)),
                Scale: 1));

        var result = SemanticRewritePlanBuilder.Build(
            map,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed);
    }

    [Fact]
    public void PlanRejectsFixupTargetThatDiffersFromItsExpressionTarget()
    {
        var map = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target-a", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5010, 0x810),
            Mapping("target-b", SemanticEntityKind.BasicBlock, 0x1020, 0x220, 0x5020, 0x820));
        var fixupTarget = SemanticTarget.Exact(new VirtualAddress(0x1010));
        var expressionTarget = SemanticTarget.Exact(new VirtualAddress(0x1020));
        var fixup = new SemanticFixup(
            SemanticFixupKind.Branch26,
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x14000000,
            fixupTarget,
            expression: new PcRelativeExpression(
                PcRelativeExpressionKind.Branch26,
                new VirtualAddress(0x1000),
                expressionTarget,
                Scale: sizeof(uint)));

        var result = SemanticRewritePlanBuilder.Build(
            map,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed
                && diagnostic.Message.Contains("expression target", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RelocationCall26UsesTheMappedTargetAndAddend()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.RelocationSite, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.RelocationTarget, 0x1010, 0x210, 0x5010, 0x810));
        var binding = new RelocationBinding(
            Aarch64RelocationKind.Call26,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            Addend: 4,
            SymbolName: "TARGET");
        var fixup = SemanticFixup.FromRelocation(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x94000000,
            binding);

        var planResult = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        Assert.True(planResult.IsSuccess, string.Join(Environment.NewLine, planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        Assert.True(resolution.IsSuccess, string.Join(Environment.NewLine, resolution.Diagnostics));
        var resolved = Assert.Single(resolution.Fixups);
        Assert.Equal(0x94000005u, resolved.InstructionEncoding);
        Assert.Equal(new VirtualAddress(0x5010), resolved.OutputTargetAddress);
    }

    [Fact]
    public void AddressMapRejectsZeroSizedLookupRange()
    {
        var map = CreateMap(
            Mapping("function", SemanticEntityKind.Function, 0x1000, 0x200, 0x5000, 0x900));

        Assert.False(map.TryMapSourceRange(
            new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), 0),
            out _));
    }

    [Fact]
    public void AddressMapTranslatesFileAndVirtualDeltasTogether()
    {
        var result = AddressMap.Create(new[]
        {
            new AddressMapEntry(
                SemanticEntityId.Function("function"),
                new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), 8),
                new SemanticSourceRange(new FileOffset(0x900), new VirtualAddress(0x5000), 8)),
        });
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));

        var sourceRange = new SemanticSourceRange(
            new FileOffset(0x204),
            new VirtualAddress(0x1004),
            sizeof(uint));
        Assert.True(result.Map!.TryMapSourceRange(sourceRange, out var outputRange));
        Assert.Equal(new FileOffset(0x904), outputRange.FileOffset);
        Assert.Equal(new VirtualAddress(0x5004), outputRange.VirtualAddress);
    }

    [Fact]
    public void BranchRangeWithoutRelaxationProducesStableFailure()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("far-target", SemanticEntityKind.BasicBlock, 0x2000_0000, 0x210, 0x2000_0000, 0x810));
        var fixup = new SemanticFixup(
            SemanticFixupKind.Branch26,
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x14000000,
            SemanticTarget.Exact(new VirtualAddress(0x2000_0000)),
            expression: new PcRelativeExpression(
                PcRelativeExpressionKind.Branch26,
                new VirtualAddress(0x1000),
                SemanticTarget.Exact(new VirtualAddress(0x2000_0000)),
                Scale: sizeof(uint)),
            relaxationOptions: new[] { SemanticRelaxationKind.None });

        var planResult = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        Assert.True(planResult.IsSuccess, string.Join(Environment.NewLine, planResult.Diagnostics));

        var resolution = planResult.Plan!.ResolveFixups();
        Assert.False(resolution.IsSuccess);
        Assert.Contains(resolution.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupOutOfRange);
        Assert.DoesNotContain(resolution.Fixups, fixupResult => fixupResult.IsFinal);
    }

    [Fact]
    public void EncodesConditionalTestAdrAdrpAndLiteralFamilies()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("branch-target", SemanticEntityKind.BasicBlock, 0x0FFC, 0x210, 0x4FFC, 0x810),
            Mapping("adr-target", SemanticEntityKind.Literal, 0x0FF8, 0x220, 0x4FF8, 0x820),
            Mapping("adrp-target", SemanticEntityKind.Literal, 0x0000, 0x230, 0x4000, 0x830));

        var cases = new[]
        {
            (SemanticFixupKind.ConditionalBranch19, PcRelativeExpressionKind.ConditionalBranch19,
                SemanticTarget.Exact(new VirtualAddress(0x0FFC)), 0x54000000u, 0x54FFFFE0u),
            (SemanticFixupKind.TestBranch14, PcRelativeExpressionKind.TestBranch14,
                SemanticTarget.Exact(new VirtualAddress(0x0FFC)), 0x37000000u, 0x3707FFE0u),
            (SemanticFixupKind.AdrPrelLo21, PcRelativeExpressionKind.AdrPrelLo21,
                SemanticTarget.Exact(new VirtualAddress(0x0FF8)), 0x10000000u, 0x10FFFFC0u),
            (SemanticFixupKind.AdrPrelPgHi21, PcRelativeExpressionKind.AdrPrelPgHi21,
                SemanticTarget.Exact(new VirtualAddress(0x0000)), 0x90000000u, 0xF0FFFFE0u),
            (SemanticFixupKind.Literal19, PcRelativeExpressionKind.Literal19,
                SemanticTarget.Exact(new VirtualAddress(0x0FFC)), 0x58000000u, 0x58FFFFE0u),
        };

        foreach (var (fixupKind, expressionKind, target, originalEncoding, expectedEncoding) in cases)
        {
            var fixup = CreatePcRelativeFixup(fixupKind, expressionKind, target, originalEncoding);
            var result = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
            Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));

            var resolution = result.Plan!.ResolveFixups();
            Assert.True(resolution.IsSuccess, string.Join(Environment.NewLine, resolution.Diagnostics));
            Assert.Equal(expectedEncoding, Assert.Single(resolution.Fixups).InstructionEncoding);
        }
    }

    [Fact]
    public void BranchRangeWithRelaxationOptionsRemainsDeferredForLayout()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("far-target", SemanticEntityKind.BasicBlock, 0x2000_0000, 0x210, 0x2000_0000, 0x810));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.Exact(new VirtualAddress(0x2000_0000)),
            0x14000000);

        var planResult = SemanticRewritePlanBuilder.Build(
            addressMap,
            Array.Empty<SemanticInstruction>(),
            new[] { fixup });
        var resolution = planResult.Plan!.ResolveFixups();

        Assert.False(resolution.IsSuccess);
        var resolved = Assert.Single(resolution.Fixups);
        Assert.True(resolved.IsDeferred);
        Assert.Contains(SemanticRelaxationKind.NearVeneer, resolved.Fixup.RelaxationOptions);
        Assert.Contains(SemanticRelaxationKind.LongAddress, resolved.Fixup.RelaxationOptions);
        Assert.Contains(
            resolved.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupDeferred);
        Assert.Null(resolved.InstructionEncoding);
    }

    [Fact]
    public void BranchRangeDiagnosticRetainsFixupFileOffset()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("far-target", SemanticEntityKind.BasicBlock, 0x2000_0000, 0x210, 0x2000_0000, 0x810));
        var fixup = new SemanticFixup(
            SemanticFixupKind.Branch26,
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x14000000,
            SemanticTarget.Exact(new VirtualAddress(0x2000_0000)),
            expression: new PcRelativeExpression(
                PcRelativeExpressionKind.Branch26,
                new VirtualAddress(0x1000),
                SemanticTarget.Exact(new VirtualAddress(0x2000_0000)),
                Scale: sizeof(uint)),
            relaxationOptions: new[] { SemanticRelaxationKind.None });

        var result = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        var resolution = result.Plan!.ResolveFixups();

        var diagnostic = Assert.Single(
            resolution.Diagnostics,
            item => item.Code == DiagnosticCode.SemanticFixupOutOfRange);
        Assert.Equal(0x200UL, diagnostic.Offset);
    }

    [Fact]
    public void UnalignedPlannedInstructionAddressIsRejected()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5002, 0x802),
            Mapping("target", SemanticEntityKind.BasicBlock, 0x1010, 0x210, 0x5012, 0x812));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            0x14000000);

        var result = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        var resolution = result.Plan!.ResolveFixups();

        Assert.False(resolution.IsSuccess);
        Assert.Contains(
            resolution.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed);
    }

    [Fact]
    public void UnalignedBranchTargetIsMalformedInsteadOfRelaxed()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.Instruction, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("unaligned-target", SemanticEntityKind.BasicBlock, 0x1006, 0x210, 0x5006, 0x810));
        var fixup = CreatePcRelativeFixup(
            SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Branch26,
            SemanticTarget.Exact(new VirtualAddress(0x1006)),
            0x14000000);

        var result = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        var resolution = result.Plan!.ResolveFixups();

        Assert.False(resolution.IsSuccess);
        var resolved = Assert.Single(resolution.Fixups);
        Assert.False(resolved.IsDeferred);
        Assert.Contains(
            resolution.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed);
    }

    [Fact]
    public void SourceRangeWithMismatchedFileAndVirtualDeltaIsAmbiguous()
    {
        var map = CreateMap(
            new AddressMapEntry(
                SemanticEntityId.Function("function"),
                new SemanticSourceRange(new FileOffset(0x200), new VirtualAddress(0x1000), 8),
                new SemanticSourceRange(new FileOffset(0x900), new VirtualAddress(0x5000), 8)));

        Assert.False(map.TryMapSourceRange(
            new SemanticSourceRange(new FileOffset(0x204), new VirtualAddress(0x1000), sizeof(uint)),
            out _));
    }

    [Fact]
    public void LoadStoreRelocationRetainsWidthClassification()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.RelocationSite, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.RelocationTarget, 0x1010, 0x210, 0x5010, 0x810));
        var binding = new RelocationBinding(
            Aarch64RelocationKind.LoadStore,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            RelocationType: ElfConstants.RArm64Ldst64AbsLo12Nc);
        var fixup = SemanticFixup.FromRelocation(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x39000000,
            binding);

        var result = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });
        var resolution = result.Plan!.ResolveFixups();

        Assert.False(resolution.IsSuccess);
        Assert.Contains(
            resolution.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed);
    }

    [Fact]
    public void RelocationBindingRejectsMismatchedRawType()
    {
        var addressMap = CreateMap(
            Mapping("source", SemanticEntityKind.RelocationSite, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("target", SemanticEntityKind.RelocationTarget, 0x1010, 0x210, 0x5010, 0x810));
        var binding = new RelocationBinding(
            Aarch64RelocationKind.Call26,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            RelocationType: ElfConstants.RArm64Ldst64AbsLo12Nc);
        var fixup = SemanticFixup.FromRelocation(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x94000000,
            binding);

        var result = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { fixup });

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticFixupMalformed);
    }

    [Fact]
    public void Lo12RelocationsEncodeAddAndLoadStoreFields()
    {
        var addressMap = CreateMap(
            Mapping("source-add", SemanticEntityKind.RelocationSite, 0x1000, 0x200, 0x5000, 0x800),
            Mapping("source-load", SemanticEntityKind.RelocationSite, 0x1020, 0x240, 0x5020, 0x840),
            Mapping("target", SemanticEntityKind.RelocationTarget, 0x1010, 0x210, 0x5010, 0x810));

        var addBinding = new RelocationBinding(
            Aarch64RelocationKind.AddAbsLo12,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            RelocationType: ElfConstants.RArm64AddAbsLo12Nc);
        var addFixup = SemanticFixup.FromRelocation(
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            0x91000000,
            addBinding);
        var addPlan = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { addFixup });
        var addResolution = addPlan.Plan!.ResolveFixups();
        Assert.True(addResolution.IsSuccess, string.Join(Environment.NewLine, addResolution.Diagnostics));
        Assert.Equal(0x91004000u, Assert.Single(addResolution.Fixups).InstructionEncoding);

        var loadBinding = new RelocationBinding(
            Aarch64RelocationKind.LoadStore,
            SemanticTarget.Exact(new VirtualAddress(0x1010)),
            RelocationType: ElfConstants.RArm64Ldst64AbsLo12Nc);
        var loadFixup = SemanticFixup.FromRelocation(
            new VirtualAddress(0x1020),
            new FileOffset(0x240),
            0xF9400000,
            loadBinding);
        var loadPlan = SemanticRewritePlanBuilder.Build(addressMap, Array.Empty<SemanticInstruction>(), new[] { loadFixup });
        var loadResolution = loadPlan.Plan!.ResolveFixups();
        Assert.True(loadResolution.IsSuccess, string.Join(Environment.NewLine, loadResolution.Diagnostics));
        Assert.Equal(0xF9400800u, Assert.Single(loadResolution.Fixups).InstructionEncoding);
    }

    [Fact]
    public void RelaRelocationClassifiesLiteralAndAdrpNoCheckVariants()
    {
        var literal = new RelaRelocation(0, ElfConstants.RArm64LdPrelLo19, 0, 0x1000, false);
        var adrpNoCheck = new RelaRelocation(0, ElfConstants.RArm64AdrPrelPgHi21Nc, 0, 0x1000, false);

        Assert.Equal(Aarch64RelocationKind.Literal19, literal.Kind);
        Assert.Equal(Aarch64RelocationKind.AdrPrelPgHi21, adrpNoCheck.Kind);
        Assert.Equal((uint?)ElfConstants.RArm64LdPrelLo19, new RelocationBinding(
            literal.Kind,
            SemanticTarget.RuntimeResolved("TARGET"),
            RelocationType: literal.Type).RelocationType);
    }

    [Fact]
    public void RelaRelocationClassifiesTestBranchAndPreservesPltBinding()
    {
        var relocation = new RelaRelocation(
            0x1000,
            ElfConstants.RArm64Tstbr14,
            0,
            0x1000,
            IsPlt: true);

        Assert.Equal(Aarch64RelocationKind.TestBranch14, relocation.Kind);
        var binding = RelocationBinding.FromRelocation(
            relocation,
            SemanticTarget.RuntimeResolved("plt:TARGET"));
        Assert.True(binding.IsExternalBinding);
        Assert.Equal((uint?)ElfConstants.RArm64Tstbr14, binding.RelocationType);
    }

    [Fact]
    public void SemanticCollectionsCopyCallerOwnedArrays()
    {
        var candidates = new[] { new VirtualAddress(0x1000) };
        var target = SemanticTarget.BoundedSet(candidates);
        candidates[0] = new VirtualAddress(0x2000);

        Assert.Equal(new VirtualAddress(0x1000), Assert.Single(target.CandidateAddresses));
        Assert.Throws<NotSupportedException>(() =>
            ((IList<VirtualAddress>)target.CandidateAddresses)[0] = new VirtualAddress(0x3000));
    }

    private static SemanticFixup CreatePcRelativeFixup(
        SemanticFixupKind fixupKind,
        PcRelativeExpressionKind expressionKind,
        SemanticTarget target,
        uint originalEncoding) =>
        new(
            fixupKind,
            new VirtualAddress(0x1000),
            new FileOffset(0x200),
            originalEncoding,
            target,
            expression: new PcRelativeExpression(
                expressionKind,
                new VirtualAddress(0x1000),
                target,
                expressionKind switch
                {
                    PcRelativeExpressionKind.AdrPrelLo21 => 1,
                    PcRelativeExpressionKind.AdrPrelPgHi21 => 0x1000,
                    _ => sizeof(uint),
                },
                expressionKind == PcRelativeExpressionKind.AdrPrelPgHi21));

    private static AddressMap CreateMap(params AddressMapEntry[] entries)
    {
        var result = AddressMap.Create(entries);
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        return result.Map!;
    }

    private static AddressMapEntry Mapping(
        string identity,
        SemanticEntityKind kind,
        ulong sourceVirtualAddress,
        ulong sourceFileOffset,
        ulong outputVirtualAddress,
        ulong outputFileOffset) =>
        new(
            new SemanticEntityId(kind, identity),
            new SemanticSourceRange(
                new FileOffset(sourceFileOffset),
                new VirtualAddress(sourceVirtualAddress),
                sizeof(uint)),
            new SemanticSourceRange(
                new FileOffset(outputFileOffset),
                new VirtualAddress(outputVirtualAddress),
                sizeof(uint)));
}
