using UrProtect.Core.Aarch64;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class Aarch64SemanticPlanFactoryTests
{
    [Fact]
    public void ProjectsFunctionBlocksFixupsAndDiscoverableRelocationSites()
    {
        var analysis = CreateAnalysis();
        var relocation = new RelaRelocation(
            0x1004,
            ElfConstants.RArm64Call26,
            0,
            0x4000,
            false);

        var result = Aarch64SemanticPlanFactory.Create(
            analysis,
            new[] { relocation },
            new Aarch64SemanticPlanFactoryOptions(loadMap: CreateLoadMap()));

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Plan);
        var plan = result.Plan!;
        Assert.Single(plan.AddressMap.Functions);
        Assert.Equal(2, plan.AddressMap.BasicBlocks.Count);
        Assert.Equal(4, plan.AddressMap.GetEntries(SemanticEntityKind.Instruction).Count);
        Assert.Single(plan.AddressMap.Literals);
        Assert.Single(plan.AddressMap.RelocationSites);
        Assert.Equal(4, plan.Instructions.Count);
        Assert.Equal(3, plan.Fixups.Count);
        Assert.Contains(plan.Fixups, fixup => fixup.Kind == SemanticFixupKind.Branch26);
        Assert.Contains(plan.Fixups, fixup => fixup.Kind == SemanticFixupKind.Relocation);
        Assert.Contains(plan.Fixups, fixup => fixup.Kind == SemanticFixupKind.Literal19);

        var resolution = plan.ResolveFixups();
        Assert.True(resolution.IsSuccess, Describe(resolution.Diagnostics));
        Assert.All(resolution.Fixups, fixup => Assert.True(fixup.IsFinal));
        Assert.Contains(
            plan.Instructions[1].Relocations,
            binding => binding.Kind == Aarch64RelocationKind.Call26
                && binding.RelocationAddress == new VirtualAddress(0x1004)
                && binding.RelocationTableAddress == new VirtualAddress(0x4000));
    }

    [Fact]
    public void DirectTargetsPreferTheSmallestTypedInstructionRange()
    {
        var result = Aarch64SemanticPlanFactory.Create(CreateAnalysis());

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Plan);
        var plan = result.Plan!;
        var branch = Assert.Single(
            plan.ResolveFixups().Fixups,
            fixup => fixup.Fixup.Kind == SemanticFixupKind.Branch26);

        Assert.Equal(new VirtualAddress(0x1008), branch.OutputTargetAddress);
        Assert.True(plan.AddressMap.TryMapSourceAddress(
            new VirtualAddress(0x1008),
            SemanticEntityKind.Instruction,
            out var outputAddress));
        Assert.Equal(new VirtualAddress(0x1008), outputAddress);
    }

    [Fact]
    public void SuppliedPlacementMapIsConsumedWithoutChangingSourceIdentity()
    {
        var analysis = CreateAnalysis();
        var identity = Aarch64SemanticPlanFactory.Create(analysis);
        Assert.True(identity.IsSuccess, Describe(identity.Diagnostics));

        var placedEntries = identity.Plan!.AddressMap.Entries
            .Select(entry => entry with
            {
                OutputRange = new SemanticSourceRange(
                    new FileOffset(entry.OutputRange.FileOffset.Value + 0x1000),
                    new VirtualAddress(entry.OutputRange.VirtualAddress.Value + 0x2000),
                    entry.OutputRange.Size),
            })
            .ToArray();
        var placementResult = AddressMap.Create(placedEntries);
        Assert.True(placementResult.IsSuccess, Describe(placementResult.Diagnostics));

        var result = Aarch64SemanticPlanFactory.CreateWithPlacement(
            analysis,
            placementResult.Map!);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Plan);
        var plan = result.Plan!;
        Assert.Equal(
            new VirtualAddress(0x3000),
            plan.AddressMap.TryMapEntity(
                SemanticEntityId.Instruction(new VirtualAddress(0x1000)),
                out var outputAddress)
                ? outputAddress
                : throw new Xunit.Sdk.XunitException("The placed instruction was not mapped."));
        Assert.Equal(new FileOffset(0x1200), plan.AddressMap.Entries
            .Single(entry => entry.Identity == SemanticEntityId.Instruction(new VirtualAddress(0x1000)))
            .OutputFileOffset);
    }

    [Fact]
    public void DuplicateRelocationSitesFailBeforeAPlanIsReturned()
    {
        var relocation = new RelaRelocation(
            0x2000,
            ElfConstants.RArm64Abs64,
            0,
            0x4000,
            false);
        var result = Aarch64SemanticPlanFactory.Create(
            CreateAnalysis(),
            new[] { relocation, relocation },
            new Aarch64SemanticPlanFactoryOptions(loadMap: LoadMap.Create(new[]
            {
                new ProgramHeader(
                    ElfConstants.PtLoad,
                    ElfConstants.PfR | ElfConstants.PfX,
                    0x200,
                    0x1000,
                    0,
                    0x10,
                    0x10,
                    0x1000),
                new ProgramHeader(
                    ElfConstants.PtLoad,
                    ElfConstants.PfR | ElfConstants.PfW,
                    0x300,
                    0x2000,
                    0,
                    8,
                    8,
                    0x1000),
            })));

        Assert.False(result.IsSuccess);
        Assert.Null(result.Plan);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapDuplicate);
    }

    [Fact]
    public void MissingPlacementIdentityProducesStableDiagnostic()
    {
        var analysis = CreateAnalysis();
        var identity = Aarch64SemanticPlanFactory.Create(analysis);
        Assert.True(identity.IsSuccess, Describe(identity.Diagnostics));
        var onlyFunction = identity.Plan!.AddressMap.Entries
            .Where(entry => entry.Identity.Kind == SemanticEntityKind.Function)
            .ToArray();
        var mapResult = AddressMap.Create(onlyFunction);
        Assert.True(mapResult.IsSuccess, Describe(mapResult.Diagnostics));

        var result = Aarch64SemanticPlanFactory.CreateWithPlacement(analysis, mapResult.Map!);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Plan);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticAddressMapMissing);
    }

    [Fact]
    public void IncompleteOrMalformedAnalysisDoesNotProduceAPlan()
    {
        var incomplete = CreateAnalysis() with
        {
            Status = Aarch64FunctionAnalysisStatus.IncompleteControlFlow,
        };
        var incompleteResult = Aarch64SemanticPlanFactory.Create(incomplete);

        Assert.False(incompleteResult.IsSuccess);
        Assert.Null(incompleteResult.Plan);
        Assert.Contains(
            incompleteResult.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.FunctionAnalysisIncomplete);

        var malformed = CreateAnalysis() with
        {
            Blocks = new[]
            {
                CreateBlock(0x1000, 0, 1),
                CreateBlock(0x1000, 0, 1),
            },
        };
        var malformedResult = Aarch64SemanticPlanFactory.Create(malformed);

        Assert.False(malformedResult.IsSuccess);
        Assert.Null(malformedResult.Plan);
        Assert.Contains(
            malformedResult.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanMalformed);
    }

    [Fact]
    public void SuppliedLoadMapMustAgreeWithAnalyzedSourceRanges()
    {
        var mismatchedLoadMap = LoadMap.Create(new[]
        {
            new ProgramHeader(
                ElfConstants.PtLoad,
                ElfConstants.PfR | ElfConstants.PfX,
                0x400,
                0x1000,
                0,
                0x10,
                0x10,
                0x1000),
        });

        var result = Aarch64SemanticPlanFactory.Create(
            CreateAnalysis(),
            options: new Aarch64SemanticPlanFactoryOptions(loadMap: mismatchedLoadMap));

        Assert.False(result.IsSuccess);
        Assert.Null(result.Plan);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanMalformed
                || diagnostic.Code == DiagnosticCode.SemanticAddressMapMissing);
    }

    [Fact]
    public void InitialAnalysisDiagnosticsAreRetainedAndErrorsBlockPublication()
    {
        var warning = new Diagnostic(
            DiagnosticSeverity.Warning,
            DiagnosticCode.SemanticTargetUnresolved,
            "synthetic warning");
        var warningResult = Aarch64SemanticPlanFactory.Create(
            CreateAnalysis() with { Diagnostics = new[] { warning } });

        Assert.True(warningResult.IsSuccess, Describe(warningResult.Diagnostics));
        Assert.Contains(warningResult.Diagnostics, diagnostic => diagnostic == warning);
        Assert.Contains(warningResult.Plan!.Diagnostics, diagnostic => diagnostic == warning);

        var error = new Diagnostic(
            DiagnosticSeverity.Error,
            DiagnosticCode.SemanticPlanMalformed,
            "synthetic error");
        var errorResult = Aarch64SemanticPlanFactory.Create(
            CreateAnalysis() with { Diagnostics = new[] { error } });

        Assert.False(errorResult.IsSuccess);
        Assert.Null(errorResult.Plan);
        Assert.Contains(errorResult.Diagnostics, diagnostic => diagnostic == error);
    }

    [Fact]
    public void UndiscoverableLiteralIsUnresolvedInsteadOfBecomingAFunctionTarget()
    {
        var result = Aarch64SemanticPlanFactory.Create(CreateAnalysis());

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Plan);
        var plan = result.Plan!;
        Assert.Empty(plan.AddressMap.Literals);
        Assert.Contains(
            plan.Extensions,
            extension => extension is SemanticUnresolvedReferenceExtension unresolved
                && unresolved.ReferenceKind == SemanticReferenceKind.Literal);
        var literalFixup = Assert.Single(
            plan.Fixups,
            fixup => fixup.Kind == SemanticFixupKind.Literal19);
        Assert.True(literalFixup.Target.IsUnresolved);
        Assert.False(plan.ResolveFixups().IsSuccess);
    }

    [Fact]
    public void IndirectAndUnmappedLiteralTargetsBecomeExtensionsInsteadOfGuesses()
    {
        var indirect = CreateInstruction(
            0x1000,
            0xD61F0000,
            "BR",
            Aarch64InstructionProperties.Branch | Aarch64InstructionProperties.Terminator,
            Aarch64ControlFlowKind.IndirectBranch,
            null);
        var analysis = CreateAnalysis(
            new[] { indirect },
            new[] { CreateBlock(0x1000, 0, 1, new[] { indirect }) },
            size: sizeof(uint));

        var result = Aarch64SemanticPlanFactory.Create(analysis);

        Assert.True(result.IsSuccess, Describe(result.Diagnostics));
        Assert.NotNull(result.Plan);
        var plan = result.Plan!;
        Assert.Contains(
            plan.Extensions,
            extension => extension is SemanticIndirectTargetExtension
                && extension.Kind == SemanticPlanExtensionKind.IndirectTargets);
        Assert.Empty(plan.Fixups);
    }

    private static Aarch64FunctionAnalysis CreateAnalysis(
        IReadOnlyList<Aarch64FunctionInstruction>? instructions = null,
        IReadOnlyList<Aarch64BasicBlock>? blocks = null,
        ulong size = 0x10)
    {
        var sourceInstructions = instructions ?? new[]
        {
            CreateInstruction(
                0x1000,
                0x14000002,
                "B",
                Aarch64InstructionProperties.Branch
                    | Aarch64InstructionProperties.PcRelative
                    | Aarch64InstructionProperties.Terminator,
                Aarch64ControlFlowKind.DirectBranch,
                0x1008,
                TargetOperand("am_bcond", 0x1008, 0)),
            CreateInstruction(
                0x1004,
                0x94000002,
                "BL",
                Aarch64InstructionProperties.Branch
                    | Aarch64InstructionProperties.Call
                    | Aarch64InstructionProperties.PcRelative,
                Aarch64ControlFlowKind.DirectCall,
                0x100C,
                TargetOperand("am_imm26", 0x100C, 0)),
            CreateInstruction(
                0x1008,
                0x18000020,
                "LDR",
                Aarch64InstructionProperties.Load | Aarch64InstructionProperties.PcRelative,
                Aarch64ControlFlowKind.None,
                0x100C,
                TargetOperand("am_ldrlit", 0x100C, 32)),
            CreateInstruction(
                0x100C,
                0xD503201F,
                "NOP",
                Aarch64InstructionProperties.None,
                Aarch64ControlFlowKind.Return,
                null),
        };

        var sourceBlocks = blocks ?? new[]
        {
            CreateBlock(0x1000, 0, 2, sourceInstructions),
            CreateBlock(0x1008, 2, 2, sourceInstructions),
        };
        return new Aarch64FunctionAnalysis(
            new ElfFunctionSymbol(
                "fixture_function",
                ElfSymbolTableKind.Static,
                1,
                0,
                0,
                0,
                0x1000,
                size),
            Aarch64FunctionAnalysisStatus.Complete,
            sourceBlocks,
            sourceInstructions,
            Array.Empty<Diagnostic>());
    }

    private static Aarch64BasicBlock CreateBlock(
        ulong startAddress,
        int startIndex,
        int count,
        IReadOnlyList<Aarch64FunctionInstruction>? instructions = null)
    {
        var source = instructions ?? new[]
        {
            CreateInstruction(
                startAddress,
                0xD503201F,
                "NOP",
                Aarch64InstructionProperties.None,
                Aarch64ControlFlowKind.None,
                null),
        };
        return new Aarch64BasicBlock(
            startAddress,
            source.Skip(startIndex).Take(count).ToArray(),
            Array.Empty<Aarch64ControlFlowEdge>());
    }

    private static Aarch64FunctionInstruction CreateInstruction(
        ulong address,
        uint encoding,
        string sourceName,
        Aarch64InstructionProperties properties,
        Aarch64ControlFlowKind controlFlow,
        ulong? target,
        Aarch64SemanticOperand? targetOperand = null)
    {
        var decoded = new Aarch64Instruction(
            address,
            encoding,
            sourceName,
            properties,
            controlFlow,
            target)
        {
            Mnemonic = sourceName,
            Operands = targetOperand is null
                ? Array.Empty<Aarch64SemanticOperand>()
                : new[] { targetOperand },
        };
        return new Aarch64FunctionInstruction(
            0x200 + (address - 0x1000),
            address,
            encoding,
            new Aarch64DecodeResult(
                Aarch64DecodeStatus.Decoded,
                decoded,
                string.Empty));
    }

    private static Aarch64SemanticOperand TargetOperand(
        string codec,
        ulong target,
        int registerWidth) =>
        new(
            "target",
            Aarch64OperandKind.Target,
            Aarch64OperandDirection.Input,
            false,
            codec,
            null,
            null,
            Array.Empty<Aarch64RegisterView>(),
            null,
            null,
            target,
            new Aarch64RegisterConstraint(0, 31, 1, 0),
            registerWidth,
            19,
            1,
            false,
            false,
            false,
            "pc-relative");

    private static LoadMap CreateLoadMap() =>
        LoadMap.Create(new[]
        {
            new ProgramHeader(
                ElfConstants.PtLoad,
                ElfConstants.PfR | ElfConstants.PfX,
                0x200,
                0x1000,
                0,
                0x10,
                0x10,
                0x1000),
        });

    private static string Describe(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(Environment.NewLine, diagnostics);
}
