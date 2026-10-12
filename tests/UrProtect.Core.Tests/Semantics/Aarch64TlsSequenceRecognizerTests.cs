using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Semantics;

public sealed class Aarch64TlsSequenceRecognizerTests
{
    [Theory]
    [InlineData(TlsAccessModel.LocalExec)]
    [InlineData(TlsAccessModel.InitialExec)]
    [InlineData(TlsAccessModel.LocalDynamic)]
    [InlineData(TlsAccessModel.GeneralDynamic)]
    [InlineData(TlsAccessModel.TlsDesc)]
    public void RecognizesTypedInstructionSequencesForRelocationFamilies(TlsAccessModel expectedModel)
    {
        var (instructions, sites, resolver) = CreateAccess(expectedModel);
        var result = Aarch64TlsSequenceRecognizer.Recognize(
            instructions,
            sites,
            CreateModule(),
            CreateSymbol(),
            resolver,
            gotEntry: expectedModel == TlsAccessModel.InitialExec ? CreateGotEntry() : null,
            resolverCall: expectedModel is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic ? CreateResolverCall() : null,
            moduleOwner: expectedModel == TlsAccessModel.LocalDynamic
                ? CreateModuleOwner()
                : expectedModel == TlsAccessModel.GeneralDynamic ? CreateGeneralDynamicModuleOwner() : null,
            dtpRelOwner: expectedModel == TlsAccessModel.GeneralDynamic ? CreateDtpRelOwner() : null,
            descriptorOwner: expectedModel == TlsAccessModel.TlsDesc ? CreateDescriptorOwner() : null);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        var binding = result.Binding!;
        Assert.Equal(expectedModel, binding.AccessModel);
        Assert.Equal(sites.Count, binding.RelocationSites.Count);
        Assert.Equal(checked((ulong)instructions.Count * sizeof(uint)), binding.SourceRange.Size);
        Assert.Equal(expectedModel is TlsAccessModel.GeneralDynamic or TlsAccessModel.LocalDynamic
                ? TlsResolverKind.TlsGetAddr
                : expectedModel == TlsAccessModel.TlsDesc
                    ? TlsResolverKind.TlsDesc
                    : TlsResolverKind.None,
            binding.InstructionSequence.ResolverKind);
        Assert.Equal(4, binding.AccessSize);
        Assert.Contains(
            binding.InstructionSequence.Instructions,
            instruction => instruction.Role == TlsInstructionRole.TlsMemoryAccess);
        Assert.All(binding.RuntimeRequirements, requirement =>
            Assert.Contains(requirement.Runtime, new[] { TlsRuntime.Glibc, TlsRuntime.Musl, TlsRuntime.Bionic }));
    }

    [Fact]
    public void RejectsTlsDescSequenceWithoutDescriptorOwner()
    {
        var (instructions, sites, resolver) = CreateAccess(TlsAccessModel.TlsDesc);
        var result = Aarch64TlsSequenceRecognizer.Recognize(
            instructions,
            sites,
            CreateModule(),
            CreateSymbol(),
            resolver);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, item => item.Code == DiagnosticCode.TlsBindingUnresolved);
    }

    [Fact]
    public void ReencodesTlsDescMarkersThroughAsmStoneBackedEncoder()
    {
        var owner = CreateDescriptorOwner();
        var markers = new[]
        {
            (ElfConstants.RArm64TlsDescAdrPage21, 0x90000000u, 0x90000020u, 0x3000UL, 0x4000UL),
            (ElfConstants.RArm64TlsDescLd64Lo12, 0xF9400001u, 0xF9400001u, 0x3004UL, 0x4004UL),
            (ElfConstants.RArm64TlsDescAddLo12, 0x91000000u, 0x91000000u, 0x3008UL, 0x4008UL),
            (ElfConstants.RArm64TlsDescCall, 0xD63F0020u, 0xD63F0020u, 0x300CUL, 0x400CUL),
        };

        foreach (var marker in markers)
        {
            Assert.True(
                Aarch64TlsInstructionSemantics.TryEncodeTlsDescInstruction(
                    marker.Item1,
                    marker.Item2,
                    marker.Item3,
                    marker.Item4,
                    marker.Item5,
                    owner,
                    out var encoded),
                $"Relocation {marker.Item1} was not re-encoded.");
            Assert.NotEqual(0u, encoded);
        }
    }
    [Fact]
    public void RejectsSequencesThatExceedTheBoundedInstructionLimit()
    {
        var (instructions, sites, resolver) = CreateAccess(TlsAccessModel.LocalExec);
        var oversized = Enumerable.Repeat(instructions[0], SemanticPlanSnapshotLimits.MaximumTlsInstructions + 1);

        var result = Aarch64TlsSequenceRecognizer.Recognize(
            oversized,
            sites,
            CreateModule(),
            CreateSymbol(),
            resolver);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, item => item.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    public void RejectsASequenceThatMixesTheInitialAndLocalExecRelocationFamilies()
    {
        var (instructions, sites, resolver) = CreateAccess(TlsAccessModel.InitialExec);
        var mixed = sites.Concat(new[]
        {
            CreateSite(ElfConstants.RArm64TlsLeAddTprelLo12Nc, 0x300C, 0x60C, sites.Count),
        }).ToArray();

        var result = Aarch64TlsSequenceRecognizer.Recognize(
            instructions,
            mixed,
            CreateModule(),
            CreateSymbol(),
            resolver);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, item => item.Code == DiagnosticCode.TlsSequenceMalformed);
    }

    [Fact]
    public void RejectsIncompleteInitialExecPairAndWrongResolverTarget()
    {
        var (instructions, sites, resolver) = CreateAccess(TlsAccessModel.InitialExec);
        var incompletePair = sites.Where(site => site.Binding.RelocationType != ElfConstants.RArm64TlsIeMovwGottprelG0Nc).ToArray();
        var incomplete = Aarch64TlsSequenceRecognizer.Recognize(
            instructions,
            incompletePair,
            CreateModule(),
            CreateSymbol(),
            gotEntry: CreateGotEntry());
        Assert.False(incomplete.IsSuccess);
        Assert.Contains(incomplete.Diagnostics, item => item.Code == DiagnosticCode.TlsSequenceMalformed);

        var (dynamicInstructions, dynamicSites, _) = CreateAccess(TlsAccessModel.GeneralDynamic);
        var wrongResolver = Aarch64TlsSequenceRecognizer.Recognize(
            dynamicInstructions,
            dynamicSites,
            CreateModule(),
            CreateSymbol(),
            SemanticTarget.RuntimeResolved("symbol:wrong_resolver"),
            resolverCall: CreateResolverCall(),
            moduleOwner: CreateGeneralDynamicModuleOwner(),
            dtpRelOwner: CreateDtpRelOwner());
        Assert.False(wrongResolver.IsSuccess);
        Assert.Contains(wrongResolver.Diagnostics, item => item.Code == DiagnosticCode.TlsBindingUnresolved);
    }

    [Fact]
    public void RejectsDynamicModuleRelocationsWithoutAnInstructionModelInsteadOfGuessing()
    {
        var instructions = CreateAccess(TlsAccessModel.GeneralDynamic).Instructions;
        var sites = new[]
        {
            CreateSite(ElfConstants.RArm64TlsDtpMod64, 0x5000, 0x900, 0),
            CreateSite(ElfConstants.RArm64TlsDtpRel64, 0x5008, 0x908, 1),
        };

        var result = Aarch64TlsSequenceRecognizer.Recognize(
            instructions,
            sites,
            CreateModule(),
            CreateSymbol(),
            SemanticTarget.RuntimeResolved("symbol:__tls_get_addr"));

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, item =>
            item.Code == DiagnosticCode.TlsSequenceMalformed
            && item.Message.Contains("not sufficient to guess", StringComparison.Ordinal));
    }

    private static (IReadOnlyList<SemanticInstruction> Instructions, IReadOnlyList<TlsRelocationSite> Sites, SemanticTarget? Resolver)
        CreateAccess(TlsAccessModel model)
    {
        var x0 = new Aarch64RegisterView(Aarch64RegisterClass.General, 0, 64, Aarch64RegisterRole.None);
        var x1 = new Aarch64RegisterView(Aarch64RegisterClass.General, 1, 64, Aarch64RegisterRole.None);
        var x10 = new Aarch64RegisterView(Aarch64RegisterClass.General, 10, 64, Aarch64RegisterRole.None);
        var x9 = new Aarch64RegisterView(Aarch64RegisterClass.General, 9, 64, Aarch64RegisterRole.None);
        var instructions = model switch
        {
            TlsAccessModel.LocalExec => new[]
            {
                Mrs(0x3000, 0x600, x0),
                Op(0x3004, 0x604, 0x91400000, "add"),
                Op(0x3008, 0x608, 0x91000000, "add"),
                Memory(0x300C, 0x60C, "ldr", 4, x0),
            },
            TlsAccessModel.InitialExec => new[]
            {
                Op(0x3000, 0x600, 0xD2A00009, "movz"),
                Op(0x3004, 0x604, 0xF2800009, "movk"),
                Mrs(0x3008, 0x608, x10),
                Op(0x300C, 0x60C, 0x8B090149, "add"),
                Memory(0x3010, 0x610, "ldr", 8, x9, x9),
                Op(0x3014, 0x614, 0x8B090149, "add"),
                Memory(0x3018, 0x618, "ldr", 4, x9),
                Op(0x301C, 0x61C, 0xD65F03C0, "ret"),
            },
            TlsAccessModel.LocalDynamic => new[]
            {
                Op(0x3000, 0x600, 0x90000000, "adrp"),
                Op(0x3004, 0x604, 0x91000000, "add"),
                Call(0x3008, 0x608, "bl"),
                Op(0x300C, 0x60C, 0x91400000, "add"),
                Op(0x3010, 0x610, 0x91000000, "add"),
                Memory(0x3014, 0x614, "ldr", 4, x0),
            },
            TlsAccessModel.GeneralDynamic => new[]
            {
                Op(0x3000, 0x600, 0x90000000, "adrp"),
                Op(0x3004, 0x604, 0x91000000, "add"),
                Call(0x3008, 0x608, "bl"),
                Memory(0x300C, 0x60C, "ldr", 4, x0),
            },
            TlsAccessModel.TlsDesc => new[]
            {
                Adrp(0x3000, 0x600, x0, 0x4000),
                Memory(0x3004, 0x604, "ldr", 8, x0, x1),
                RegisterAdd(0x3008, 0x608, x0, x0, immediate: 0),
                IndirectCall(0x300C, 0x60C, x1),
                Mrs(0x3010, 0x610, x1),
                RegisterAdd(0x3014, 0x614, x0, x0, x1),
                Memory(0x3018, 0x618, "ldr", 4, x0, x0),
                Ret(0x301C, 0x61C),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(model)),
        };

        var sites = model switch
        {
            TlsAccessModel.LocalExec => new[]
            {
                CreateSite(ElfConstants.RArm64TlsLeAddTprelHi12, 0x3004, 0x604, 0),
                CreateSite(ElfConstants.RArm64TlsLeAddTprelLo12Nc, 0x3008, 0x608, 1),
            },
            TlsAccessModel.InitialExec => new[]
            {
                CreateSite(ElfConstants.RArm64TlsIeMovwGottprelG1, 0x3000, 0x600, 0),
                CreateSite(ElfConstants.RArm64TlsIeMovwGottprelG0Nc, 0x3004, 0x604, 1),
            },
            TlsAccessModel.LocalDynamic => new[]
            {
                CreateSite(ElfConstants.RArm64TlsLdAdrPage21, 0x3000, 0x600, 0),
                CreateSite(ElfConstants.RArm64TlsLdAddLo12Nc, 0x3004, 0x604, 1),
                CreateSite(ElfConstants.RArm64TlsLdAddDtprelHi12, 0x300C, 0x60C, 2, addend: 4),
                CreateSite(ElfConstants.RArm64TlsLdAddDtprelLo12Nc, 0x3010, 0x610, 3, addend: 4),
            },
            TlsAccessModel.GeneralDynamic => new[]
            {
                CreateSite(ElfConstants.RArm64TlsGdAdrPage21, 0x3000, 0x600, 0),
                CreateSite(ElfConstants.RArm64TlsGdAddLo12Nc, 0x3004, 0x604, 1),
            },
            TlsAccessModel.TlsDesc => new[]
            {
                CreateSite(ElfConstants.RArm64TlsDescAdrPage21, 0x3000, 0x600, 0),
                CreateSite(ElfConstants.RArm64TlsDescLd64Lo12, 0x3004, 0x604, 1),
                CreateSite(ElfConstants.RArm64TlsDescAddLo12, 0x3008, 0x608, 2),
                CreateSite(ElfConstants.RArm64TlsDescCall, 0x300C, 0x60C, 3),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(model)),
        };
        var resolver = model switch
        {
            TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic =>
                SemanticTarget.RuntimeResolved("symbol:__tls_get_addr"),
            TlsAccessModel.TlsDesc => SemanticTarget.RuntimeResolved("tlsdesc:resolver"),
            _ => null,
        };
        return (instructions, sites, resolver);
    }

    private static SemanticInstruction Adrp(
        ulong address,
        ulong fileOffset,
        Aarch64RegisterView destination,
        ulong target) =>
        new(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            0x90000020u,
            "adrp",
            Range(address, fileOffset),
            new[]
            {
                RegisterOperand("rd", destination, Aarch64OperandDirection.Output),
                TargetOperand("target", target),
            });

    private static SemanticInstruction RegisterAdd(
        ulong address,
        ulong fileOffset,
        Aarch64RegisterView destination,
        Aarch64RegisterView firstInput,
        Aarch64RegisterView? secondInput = null,
        long? immediate = null)
    {
        var operands = new List<SemanticOperand>
        {
            RegisterOperand("rd", destination, Aarch64OperandDirection.Output),
            RegisterOperand("rn", firstInput, Aarch64OperandDirection.Input),
        };
        if (secondInput is { } register)
        {
            operands.Add(RegisterOperand("rm", register, Aarch64OperandDirection.Input));
        }
        if (immediate is { } value)
        {
            operands.Add(ImmediateOperand("imm", value));
        }

        return new SemanticInstruction(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            secondInput is null ? 0x91000000u : 0x8B010000u,
            "add",
            Range(address, fileOffset),
            operands);
    }

    private static SemanticInstruction IndirectCall(
        ulong address,
        ulong fileOffset,
        Aarch64RegisterView targetRegister) =>
        new(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            0xD63F0020u,
            "blr",
            Range(address, fileOffset),
            new[] { RegisterOperand("rn", targetRegister, Aarch64OperandDirection.Input) },
            controlFlow: Aarch64ControlFlowKind.IndirectBranch);

    private static SemanticInstruction Ret(ulong address, ulong fileOffset) =>
        new(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            0xD65F03C0u,
            "ret",
            Range(address, fileOffset),
            controlFlow: Aarch64ControlFlowKind.Return);

    private static SemanticOperand ImmediateOperand(string name, long value) => new(
        name,
        Aarch64OperandKind.Immediate,
        Aarch64OperandDirection.Input,
        false,
        "immediate",
        null,
        null,
        Array.Empty<Aarch64RegisterView>(),
        null,
        value,
        null,
        new Aarch64RegisterConstraint(0, 31, 1, uint.MaxValue),
        0,
        12,
        12,
        false,
        false,
        false,
        "immediate");

    private static SemanticOperand TargetOperand(string name, ulong target) => new(
        name,
        Aarch64OperandKind.Target,
        Aarch64OperandDirection.Input,
        false,
        "target",
        null,
        null,
        Array.Empty<Aarch64RegisterView>(),
        null,
        null,
        target,
        new Aarch64RegisterConstraint(0, 31, 1, uint.MaxValue),
        0,
        21,
        21,
        false,
        false,
        true,
        "target");

    private static SemanticInstruction Mrs(ulong address, ulong fileOffset, Aarch64RegisterView destination) =>
        new(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            0xD53BD040u | destination.Index,
            "mrs",
            Range(address, fileOffset),
            new[] { RegisterOperand("rt", destination, Aarch64OperandDirection.Output) });

    private static SemanticInstruction Call(ulong address, ulong fileOffset, string mnemonic) =>
        new(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            mnemonic == "blr" ? 0xD63F0020u : 0x94000000u,
            mnemonic,
            Range(address, fileOffset),
            controlFlow: mnemonic == "bl"
                ? Aarch64ControlFlowKind.DirectCall
                : Aarch64ControlFlowKind.IndirectBranch);

    private static SemanticInstruction Op(ulong address, ulong fileOffset, uint encoding, string mnemonic) =>
        new(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            encoding,
            mnemonic,
            Range(address, fileOffset));

    private static SemanticInstruction Memory(
        ulong address,
        ulong fileOffset,
        string mnemonic,
        int accessSize,
        Aarch64RegisterView baseRegister,
        Aarch64RegisterView? valueRegisterOverride = null)
    {
        var valueRegister = valueRegisterOverride ?? new Aarch64RegisterView(
            Aarch64RegisterClass.General,
            0,
            accessSize <= 4 ? (byte)32 : (byte)64,
            Aarch64RegisterRole.None);
        var memory = new Aarch64MemoryReference(
            baseRegister,
            null,
            0,
            "Offset",
            null,
            accessSize,
            "None",
            false);
        return new SemanticInstruction(
            new VirtualAddress(address),
            new FileOffset(fileOffset),
            (accessSize == 4 ? 0xB9400000u : 0xF9400000u)
                | ((uint)baseRegister.Index << 5)
                | valueRegister.Index,
            mnemonic,
            Range(address, fileOffset),
            new[]
            {
                RegisterOperand("rt", valueRegister, Aarch64OperandDirection.Output),
                new SemanticOperand(
                    "mem",
                    Aarch64OperandKind.Memory,
                    Aarch64OperandDirection.Input,
                    false,
                    "memory",
                    null,
                    null,
                    Array.Empty<Aarch64RegisterView>(),
                    memory,
                    null,
                    null,
                    new Aarch64RegisterConstraint(0, 31, 1, uint.MaxValue),
                    64,
                    1,
                    1,
                    false,
                    false,
                    false,
                    "memory"),
            });
    }

    private static SemanticOperand RegisterOperand(
        string name,
        Aarch64RegisterView register,
        Aarch64OperandDirection direction) => new(
        name,
        Aarch64OperandKind.Register,
        direction,
        false,
        "register",
        null,
        register,
        Array.Empty<Aarch64RegisterView>(),
        null,
        null,
        null,
        new Aarch64RegisterConstraint(0, 31, 1, uint.MaxValue),
        register.Width,
        register.Width,
        register.Width,
        false,
        false,
        false,
        "register");

    private static TlsRelocationSite CreateSite(
        uint type,
        ulong address,
        ulong fileOffset,
        int ordinal,
        long addend = 0)
    {
        var family = TlsRelocationClassifier.GetFamily(type)
            ?? throw new InvalidOperationException($"Relocation type {type} has no TLS family.");
        var relocation = new RelocationBinding(
            Aarch64RelocationKind.ThreadLocal,
            SemanticTarget.RuntimeResolved("tls-symbol:tls_value"),
            addend,
            SymbolIndex: 1,
            SymbolName: "tls_value",
            RelocationType: type,
            RelocationAddress: new VirtualAddress(address),
            RelocationTableAddress: new VirtualAddress(0x4800));
        return new TlsRelocationSite(
            family,
            Range(address, fileOffset, TlsRelocationClassifier.GetWriteSize(type)),
            relocation,
            ordinal,
            IsGotOrDescriptorOwned: type == ElfConstants.RArm64TlsDtpMod64
                || type is >= ElfConstants.RArm64TlsIeMovwGottprelG1
                    and <= ElfConstants.RArm64TlsIeLdGottprelPrel19
                || type is >= ElfConstants.RArm64TlsDescLdPrel19
                    and <= ElfConstants.RArm64TlsDescCall);
    }

    private static TlsModuleIdentity CreateModule() => new(
        TlsModuleIdentityKind.ImageLocal,
        "image:tls-fixture",
        "libtls-fixture.so",
        null,
        new TlsTemplateContract(
            new FileOffset(0x700),
            new VirtualAddress(0x4000),
            4,
            16,
            4,
            ElfConstants.PfR | ElfConstants.PfW,
            0,
            new string('0', 64)));

    private static TlsResolverCallBinding CreateResolverCall()
    {
        var relocation = new RelocationBinding(
            Aarch64RelocationKind.Call26,
            SemanticTarget.RuntimeResolved("symbol:__tls_get_addr"),
            SymbolIndex: 2,
            SymbolName: "__tls_get_addr",
            RelocationType: ElfConstants.RArm64Call26,
            RelocationAddress: new VirtualAddress(0x3008),
            RelocationTableAddress: new VirtualAddress(0x4800));
        return new TlsResolverCallBinding(Range(0x3008, 0x608), relocation);
    }

    private static TlsModuleOwnerBinding CreateModuleOwner()
    {
        var relocation = new RelocationBinding(
            Aarch64RelocationKind.ThreadLocal,
            SemanticTarget.RuntimeResolved("tls-module:image:tls-fixture"),
            RelocationType: ElfConstants.RArm64TlsDtpMod64,
            RelocationAddress: new VirtualAddress(0x5000),
            RelocationTableAddress: new VirtualAddress(0x4800));
        return new TlsModuleOwnerBinding(
            SemanticEntityId.RelocationSite("tls-module-owner:5000"),
            Range(0x5000, 0x900, sizeof(ulong)),
            relocation);
    }

    private static TlsModuleOwnerBinding CreateGeneralDynamicModuleOwner()
    {
        var relocation = new RelocationBinding(
            Aarch64RelocationKind.ThreadLocal,
            SemanticTarget.RuntimeResolved("tls-module:image:tls-fixture:tls_value"),
            RelocationType: ElfConstants.RArm64TlsDtpMod64,
            SymbolIndex: 1,
            SymbolName: "tls_value",
            RelocationAddress: new VirtualAddress(0x5000),
            RelocationTableAddress: new VirtualAddress(0x4800));
        return new TlsModuleOwnerBinding(
            SemanticEntityId.RelocationSite("tls-module-owner:5000"),
            Range(0x5000, 0x900, sizeof(ulong)),
            relocation);
    }

    private static TlsDtpRelOwnerBinding CreateDtpRelOwner()
    {
        var relocation = new RelocationBinding(
            Aarch64RelocationKind.ThreadLocal,
            SemanticTarget.RuntimeResolved("tls-symbol:image:tls-fixture:tls_value"),
            SymbolIndex: 1,
            SymbolName: "tls_value",
            RelocationType: ElfConstants.RArm64TlsDtpRel64,
            RelocationAddress: new VirtualAddress(0x5008),
            RelocationTableAddress: new VirtualAddress(0x4800));
        return new TlsDtpRelOwnerBinding(
            SemanticEntityId.RelocationSite("tls-dtprel-owner:5008"),
            Range(0x5008, 0x908, sizeof(ulong)),
            relocation);
    }

    private static TlsDescriptorOwnerBinding CreateDescriptorOwner()
    {
        var symbol = CreateSymbol();
        var relocation = new RelocationBinding(
            Aarch64RelocationKind.ThreadLocal,
            SemanticTarget.RuntimeResolved("tls-descriptor:image:tls-fixture:tls_value"),
            SymbolIndex: symbol.SymbolIndex,
            IsPlt: true,
            SymbolName: symbol.Name,
            RelocationType: ElfConstants.RArm64TlsDesc,
            RelocationAddress: new VirtualAddress(0x4000),
            RelocationTableAddress: new VirtualAddress(0x4800));
        return new TlsDescriptorOwnerBinding(
            SemanticEntityId.RelocationSite("tls-descriptor:4000"),
            Range(0x4000, 0x800, 2 * sizeof(ulong)),
            relocation,
            symbol,
            0,
            new VirtualAddress(0x5000),
            new VirtualAddress(0x6000),
            new VirtualAddress(0x7000),
            Range(0x5000, 0x900, 6 * sizeof(uint)),
            Range(0x6000, 0x920, sizeof(ulong)));
    }
    [Fact]
    public void MatchesTlsOwnerAcrossDynamicAndRegularSymbolTableIndexSpaces()
    {
        var retainedRelocationSymbol = new TlsRelocationSymbolIdentity(
            25,
            "tls_value",
            1,
            ElfConstants.SttTls,
            0,
            12,
            0,
            4);
        var dynamicGotSymbol = new TlsSymbolIdentity(
            3,
            "tls_value",
            1,
            ElfConstants.SttTls,
            0,
            12,
            0,
            4,
            true);

        Assert.True(TlsStructuralAdapter.SymbolsMatch(retainedRelocationSymbol, dynamicGotSymbol));
        Assert.False(TlsStructuralAdapter.SymbolsMatch(
            retainedRelocationSymbol with { Size = 8 },
            dynamicGotSymbol));
    }

    private static TlsGotEntryBinding CreateGotEntry()
    {
        var symbol = CreateSymbol();
        var relocation = new RelocationBinding(
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
        return new TlsGotEntryBinding(
            SemanticEntityId.RelocationSite("tls-got:5000"),
            Range(0x5000, 0x900, sizeof(ulong)),
            relocation,
            symbol,
            0);
    }

    private static TlsSymbolIdentity CreateSymbol() => new(
        1,
        "tls_value",
        1,
        ElfConstants.SttTls,
        0,
        1,
        0,
        4,
        true);

    private static SemanticSourceRange Range(ulong virtualAddress, ulong fileOffset) =>
        Range(virtualAddress, fileOffset, sizeof(uint));

    private static SemanticSourceRange Range(ulong virtualAddress, ulong fileOffset, ulong size) =>
        new(new FileOffset(fileOffset), new VirtualAddress(virtualAddress), size);
}
