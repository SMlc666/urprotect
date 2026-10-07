using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>The five ABI-defined AArch64 TLS access models.</summary>
public enum TlsAccessModel : byte
{
    LocalExec = 1,
    InitialExec = 2,
    LocalDynamic = 3,
    GeneralDynamic = 4,
    TlsDesc = 5,
}

/// <summary>The relocation expression family used by an AArch64 TLS access.</summary>
public enum TlsRelocationFamily : byte
{
    Tprel = 1,
    GotTprel = 2,
    Dtpmod = 3,
    Dtprel = 4,
    TlsDesc = 5,
}

public enum TlsAddressExpressionKind : byte
{
    ThreadPointerRelative = 1,
    ModuleRelative = 2,
    ResolverReturned = 3,
    DescriptorMediated = 4,
}

public enum TlsResolverKind : byte
{
    None = 0,
    TlsGetAddr = 1,
    TlsDesc = 2,
}

public enum TlsModuleIdentityKind : byte
{
    ImageLocal = 1,
    DynamicSymbol = 2,
    RuntimeAssigned = 3,
}

public enum TlsProfile : byte
{
    OuterExecveat = 1,
    HostContextEntry = 2,
}

public enum TlsRuntime : byte
{
    Glibc = 1,
    Musl = 2,
    Bionic = 3,
    Aarch64SystemLoader = 4,
}

public enum TlsRuntimeRequirementKind : byte
{
    LoaderAllocatedTlsModule = 1,
    StaticTlsSlot = 2,
    ThreadPointerRelativeAccess = 3,
    TlsGetAddrResolver = 4,
    TlsDescResolver = 5,
    CurrentThreadLifecycle = 6,
    RegisteredWorkerLifecycle = 7,
}

public enum TlsInstructionRole : byte
{
    AddressFormation = 1,
    ModuleLookup = 2,
    SymbolOffsetFormation = 3,
    ResolverCall = 4,
    TlsMemoryAccess = 5,
    ThreadPointerRead = 6,
    DescriptorLoad = 7,
    DescriptorCall = 8,
    AddressFinalization = 9,
    SequencePreservation = 10,
    GotEntryLoad = 11,
}

/// <summary>PT_TLS facts bound to the semantic module and authenticated by the source image.</summary>
public sealed record TlsTemplateContract(
    FileOffset FileOffset,
    VirtualAddress VirtualAddress,
    ulong FileSize,
    ulong MemorySize,
    ulong Alignment,
    uint Permissions,
    int OwningLoadProgramHeaderIndex,
    string InitializedTemplateSha256)
{
    public ulong ZeroFillSize => MemorySize - FileSize;
}

/// <summary>Typed module identity; loader-assigned module numbers are never guessed.</summary>
public sealed record TlsModuleIdentity(
    TlsModuleIdentityKind Kind,
    string Identity,
    string? Soname,
    uint? RuntimeModuleIndex,
    TlsTemplateContract? Template);

/// <summary>Bounded TLS dynamic-symbol identity used by the semantic access model.</summary>
public sealed record TlsSymbolIdentity(
    uint SymbolIndex,
    string Name,
    byte Binding,
    byte SymbolType,
    byte Visibility,
    ushort SectionIndex,
    ulong Value,
    ulong Size,
    bool IsDefined);

/// <summary>One source AArch64 instruction and its TLS-specific register/resource effects.</summary>
public sealed record TlsInstructionRecord(
    SemanticSourceRange SourceRange,
    uint Encoding,
    string Mnemonic,
    TlsInstructionRole Role,
    IReadOnlyList<Aarch64RegisterView> InputRegisters,
    IReadOnlyList<Aarch64RegisterView> OutputRegisters,
    IReadOnlyList<SemanticRegisterEffect> RegisterEffects,
    bool IsCall,
    bool IsResolverCall);

/// <summary>A complete, contiguous instruction sequence for one TLS model access.</summary>
public sealed record TlsInstructionSequence(
    SemanticSourceRange SourceRange,
    IReadOnlyList<TlsInstructionRecord> Instructions,
    TlsResolverKind ResolverKind,
    SemanticTarget? ResolverTarget);

/// <summary>One relocation and its explicit membership in a TLS semantic sequence.</summary>
public sealed record TlsRelocationSite(
    TlsRelocationFamily Family,
    SemanticSourceRange SourceRange,
    RelocationBinding Binding,
    int PairOrdinal,
    bool IsGotOrDescriptorOwned);

/// <summary>
/// The one source-preserved GOT entry owned by a TLSIE access. The entry is not
/// emitted by semantic/layout code; its source range and loader-owned relocation
/// are carried so the shared layout/materializer can prove that it stayed in place.
/// </summary>
public sealed record TlsGotEntryBinding(
    SemanticEntityId SourceIdentity,
    SemanticSourceRange SourceRange,
    RelocationBinding Relocation,
    TlsSymbolIdentity Symbol,
    long Addend);

/// <summary>Typed thread- or module-relative value formation.</summary>
public sealed record TlsAddressExpression(
    TlsAddressExpressionKind Kind,
    TlsModuleIdentity Module,
    TlsSymbolIdentity? Symbol,
    Aarch64RegisterView? BaseRegister,
    Aarch64RegisterView? ValueRegister,
    long Addend);

public sealed record TlsProfileRequirement(TlsProfile Profile, bool Required);

public sealed record TlsRuntimeRequirement(
    TlsRuntime Runtime,
    TlsRuntimeRequirementKind Kind,
    bool Required);

/// <summary>
/// Typed semantic binding for one complete TLS access. It is carried by the existing
/// semantic-plan extension and preserves source sites for source-to-output fixups.
/// </summary>
public sealed record TlsBinding
{
    public TlsBinding(
        TlsAccessModel accessModel,
        TlsRelocationFamily relocationFamily,
        SemanticEntityId sourceIdentity,
        SemanticSourceRange sourceRange,
        TlsInstructionSequence instructionSequence,
        TlsModuleIdentity module,
        TlsSymbolIdentity? symbol,
        long addend,
        IEnumerable<TlsRelocationSite> relocationSites,
        int accessSize,
        TlsAddressExpression addressExpression,
        IEnumerable<TlsProfileRequirement> profileRequirements,
        IEnumerable<TlsRuntimeRequirement> runtimeRequirements,
        TlsGotEntryBinding? gotEntry = null)
    {
        ArgumentNullException.ThrowIfNull(instructionSequence);
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(relocationSites);
        ArgumentNullException.ThrowIfNull(addressExpression);
        ArgumentNullException.ThrowIfNull(profileRequirements);
        ArgumentNullException.ThrowIfNull(runtimeRequirements);
        AccessModel = accessModel;
        RelocationFamily = relocationFamily;
        SourceIdentity = sourceIdentity;
        SourceRange = sourceRange;
        InstructionSequence = instructionSequence with
        {
            Instructions = Array.AsReadOnly(instructionSequence.Instructions
                .Select(instruction => instruction with
                {
                    InputRegisters = Array.AsReadOnly(instruction.InputRegisters.ToArray()),
                    OutputRegisters = Array.AsReadOnly(instruction.OutputRegisters.ToArray()),
                    RegisterEffects = Array.AsReadOnly(instruction.RegisterEffects.ToArray()),
                })
                .ToArray()),
        };
        Module = module;
        Symbol = symbol;
        Addend = addend;
        RelocationSites = Array.AsReadOnly(relocationSites.ToArray());
        AccessSize = accessSize;
        AddressExpression = addressExpression;
        ProfileRequirements = Array.AsReadOnly(profileRequirements.ToArray());
        RuntimeRequirements = Array.AsReadOnly(runtimeRequirements.ToArray());
        GotEntry = gotEntry;
    }

    public TlsAccessModel AccessModel { get; }

    public TlsRelocationFamily RelocationFamily { get; }

    public SemanticEntityId SourceIdentity { get; }

    public SemanticSourceRange SourceRange { get; }

    public TlsInstructionSequence InstructionSequence { get; }

    public TlsModuleIdentity Module { get; }

    public TlsSymbolIdentity? Symbol { get; }

    public long Addend { get; }

    public IReadOnlyList<TlsRelocationSite> RelocationSites { get; }

    public int AccessSize { get; }

    public TlsAddressExpression AddressExpression { get; }

    public IReadOnlyList<TlsProfileRequirement> ProfileRequirements { get; }

    public IReadOnlyList<TlsRuntimeRequirement> RuntimeRequirements { get; }

    public TlsGotEntryBinding? GotEntry { get; }
}

/// <summary>Stable relocation-family classification for the AArch64 ELF ABI constants.</summary>
public static class TlsRelocationClassifier
{
    /// <summary>
    /// Returns whether a relocation is a TLS relocation whose semantics must be
    /// explicitly carried or rejected. A null access model is intentional for
    /// relocation forms that cannot distinguish local-dynamic from general-dynamic
    /// (or another model) without the surrounding instruction sequence.
    /// </summary>
    public static bool IsTlsRelocation(uint relocationType) => GetFamily(relocationType).HasValue;

    public static TlsRelocationFamily? GetFamily(uint relocationType) => relocationType switch
    {
        >= ElfConstants.RArm64TlsLeMovwTprelG2 and <= ElfConstants.RArm64TlsLeLdst64TprelLo12Nc
            or >= ElfConstants.RArm64TlsLeLdst128TprelLo12 and <= ElfConstants.RArm64TlsLeLdst128TprelLo12Nc =>
            TlsRelocationFamily.Tprel,
        >= ElfConstants.RArm64TlsIeMovwGottprelG1 and <= ElfConstants.RArm64TlsIeLdGottprelPrel19 =>
            TlsRelocationFamily.GotTprel,
        ElfConstants.RArm64TlsDtpMod64
            or >= ElfConstants.RArm64TlsGdAdrPrel21 and <= ElfConstants.RArm64TlsLdLdPrel19 =>
            TlsRelocationFamily.Dtpmod,
        ElfConstants.RArm64TlsDtpRel64
            or >= ElfConstants.RArm64TlsLdMovwDtprelG2 and <= ElfConstants.RArm64TlsLdLdst64DtprelLo12Nc
            or >= ElfConstants.RArm64TlsLdLdst128DtprelLo12 and <= ElfConstants.RArm64TlsLdLdst128DtprelLo12Nc =>
            TlsRelocationFamily.Dtprel,
        ElfConstants.RArm64TlsDesc
            or >= ElfConstants.RArm64TlsDescLdPrel19 and <= ElfConstants.RArm64TlsDescCall =>
            TlsRelocationFamily.TlsDesc,
        ElfConstants.RArm64TlsTprel64 => TlsRelocationFamily.Tprel,
        _ => null,
    };

    public static TlsAccessModel? GetAccessModel(uint relocationType) => relocationType switch
    {
        >= ElfConstants.RArm64TlsGdAdrPrel21 and <= ElfConstants.RArm64TlsGdMovwG0Nc => TlsAccessModel.GeneralDynamic,
        >= ElfConstants.RArm64TlsLdAdrPrel21 and <= ElfConstants.RArm64TlsLdLdst64DtprelLo12Nc
            or >= ElfConstants.RArm64TlsLdLdst128DtprelLo12 and <= ElfConstants.RArm64TlsLdLdst128DtprelLo12Nc => TlsAccessModel.LocalDynamic,
        >= ElfConstants.RArm64TlsIeMovwGottprelG1 and <= ElfConstants.RArm64TlsIeLdGottprelPrel19 => TlsAccessModel.InitialExec,
        >= ElfConstants.RArm64TlsLeMovwTprelG2 and <= ElfConstants.RArm64TlsLeLdst64TprelLo12Nc
            or >= ElfConstants.RArm64TlsLeLdst128TprelLo12 and <= ElfConstants.RArm64TlsLeLdst128TprelLo12Nc => TlsAccessModel.LocalExec,
        >= ElfConstants.RArm64TlsDescLdPrel19 and <= ElfConstants.RArm64TlsDescCall => TlsAccessModel.TlsDesc,
        _ => null,
    };

    public static ulong GetWriteSize(uint relocationType) => relocationType is >= ElfConstants.RArm64TlsGdAdrPrel21
        and <= ElfConstants.RArm64TlsLdLdst128DtprelLo12Nc
        ? (ulong)sizeof(uint)
        : relocationType is ElfConstants.RArm64TlsDtpMod64
            or ElfConstants.RArm64TlsDtpRel64
            or ElfConstants.RArm64TlsTprel64
            or ElfConstants.RArm64TlsDesc
            ? (ulong)sizeof(ulong)
            : 0;

    public static bool IsCompleteRelocationPattern(
        TlsAccessModel model,
        IEnumerable<uint> relocationTypes)
    {
        ArgumentNullException.ThrowIfNull(relocationTypes);
        var relocationArray = relocationTypes.ToArray();
        var types = relocationArray.ToHashSet();
        var families = types.Select(GetFamily).Where(family => family.HasValue).Select(family => family!.Value).ToHashSet();
        return model switch
        {
            TlsAccessModel.LocalExec => relocationArray.Length == 2
                && families.Contains(TlsRelocationFamily.Tprel)
                && (HasPair(types, ElfConstants.RArm64TlsLeAddTprelHi12, ElfConstants.RArm64TlsLeAddTprelLo12)
                    || HasPair(types, ElfConstants.RArm64TlsLeAddTprelHi12, ElfConstants.RArm64TlsLeAddTprelLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsLeAddTprelHi12, ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsLeMovwTprelG1, ElfConstants.RArm64TlsLeMovwTprelG0Nc)),
            TlsAccessModel.InitialExec => families.Contains(TlsRelocationFamily.GotTprel)
                && HasPair(types, ElfConstants.RArm64TlsIeMovwGottprelG1, ElfConstants.RArm64TlsIeMovwGottprelG0Nc),
            TlsAccessModel.LocalDynamic => families.Contains(TlsRelocationFamily.Dtpmod)
                && families.Contains(TlsRelocationFamily.Dtprel)
                && (HasPair(types, ElfConstants.RArm64TlsLdAdrPage21, ElfConstants.RArm64TlsLdAddLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsLdAdrPrel21, ElfConstants.RArm64TlsLdAddLo12Nc)),
            TlsAccessModel.GeneralDynamic => families.Contains(TlsRelocationFamily.Dtpmod)
                && families.Contains(TlsRelocationFamily.Dtprel)
                && (HasPair(types, ElfConstants.RArm64TlsGdAdrPage21, ElfConstants.RArm64TlsGdAddLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsGdAdrPrel21, ElfConstants.RArm64TlsGdAddLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsGdMovwG1, ElfConstants.RArm64TlsGdMovwG0Nc)),
            TlsAccessModel.TlsDesc => new[]
            {
                ElfConstants.RArm64TlsDescAdrPage21,
                ElfConstants.RArm64TlsDescLd64Lo12,
                ElfConstants.RArm64TlsDescAddLo12,
                ElfConstants.RArm64TlsDescCall,
            }.All(types.Contains),
            _ => false,
        };
    }

    private static bool HasPair(HashSet<uint> types, uint first, uint second) =>
        types.Contains(first) && types.Contains(second);

    public static bool IsModelCompatible(TlsAccessModel model, TlsRelocationFamily family) => model switch
    {
        TlsAccessModel.LocalExec => family == TlsRelocationFamily.Tprel,
        TlsAccessModel.InitialExec => family is TlsRelocationFamily.GotTprel or TlsRelocationFamily.Tprel,
        TlsAccessModel.LocalDynamic => family is TlsRelocationFamily.Dtpmod or TlsRelocationFamily.Dtprel,
        TlsAccessModel.GeneralDynamic => family is TlsRelocationFamily.Dtpmod or TlsRelocationFamily.Dtprel,
        TlsAccessModel.TlsDesc => family == TlsRelocationFamily.TlsDesc,
        _ => false,
    };
}

/// <summary>Exact AArch64 instruction constraints for the implemented TLSLE relocation subset.</summary>
public static class Aarch64TlsInstructionSemantics
{
    private const uint AddImmediateOpcodeMask = 0x7F00_0000;
    private const uint AddImmediateOpcode = 0x1100_0000;
    private const uint MovwOpcodeMask = 0xFF80_0000;
    private const uint MovzOpcode = 0xD280_0000;
    private const uint MovnOpcode = 0x9280_0000;
    private const uint MovkOpcode = 0xF280_0000;
    private const uint AddRegisterOpcodeMask = 0xFF20_0000;
    private const uint AddRegisterOpcode = 0x8B00_0000;
    private const uint AddRegisterShiftMask = 0x00C0_FC00;
    private const uint ThreadPointerMrsMask = 0xFFFF_FFE0;
    private const uint ThreadPointerMrsEncoding = 0xD53B_D040;

    public static bool IsSupportedLocalExecRelocationInstruction(uint relocationType, uint encoding)
    {
        return relocationType switch
        {
            ElfConstants.RArm64TlsLeAddTprelHi12 => TryGetLocalExecAddImmediateRegisters(
                relocationType,
                encoding,
                out _,
                out _),
            ElfConstants.RArm64TlsLeAddTprelLo12
                or ElfConstants.RArm64TlsLeAddTprelLo12Nc => TryGetLocalExecAddImmediateRegisters(
                    relocationType,
                    encoding,
                    out _,
                    out _),
            ElfConstants.RArm64TlsLeMovwTprelG1 => TryGetLocalExecMovwRegister(relocationType, encoding, out _),
            ElfConstants.RArm64TlsLeMovwTprelG0Nc => TryGetLocalExecMovwRegister(relocationType, encoding, out _),
            ElfConstants.RArm64TlsLeLdst32TprelLo12Nc => TryGetLocalExecLdst32Registers(
                relocationType,
                encoding,
                out _,
                out _),
            _ => false,
        };
    }

    public static bool IsSupportedLocalExecAddPair(
        IReadOnlyList<TlsInstructionRecord> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateLocalExecAddPairRelocations(relocationSites, out var firstAddress, out var secondAddress))
        {
            return false;
        }

        var firstIndex = FindInstructionIndex(instructions, firstAddress);
        var secondIndex = FindInstructionIndex(instructions, secondAddress);
        if (firstIndex < 0
            || secondIndex != firstIndex + 1
            || !TryGetLocalExecAddImmediateRegisters(
                relocationSites[0].Binding.RelocationType!.Value,
                instructions[firstIndex].Encoding,
                out var firstSource,
                out var firstDestination)
            || !TryGetLocalExecAddImmediateRegisters(
                relocationSites[1].Binding.RelocationType!.Value,
                instructions[secondIndex].Encoding,
                out var secondSource,
                out var secondDestination))
        {
            return false;
        }

        var threadPointerInstructions = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => TryGetThreadPointerRegister(item.instruction.Encoding, out _))
            .ToArray();
        if (threadPointerInstructions.Length != 1
            || threadPointerInstructions[0].index != firstIndex - 1
            || !TryGetThreadPointerRegister(
                threadPointerInstructions[0].instruction.Encoding,
                out var threadPointerRegister)
            || firstSource != threadPointerRegister
            || secondSource != firstDestination)
        {
            return false;
        }

        var memoryAccesses = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Role == TlsInstructionRole.TlsMemoryAccess)
            .ToArray();
        return memoryAccesses.Length == 1
            && memoryAccesses[0].index == secondIndex + 1
            && memoryAccesses[0].instruction.InputRegisters.Any(register =>
                register.Class == Aarch64RegisterClass.General
                && register.Role == Aarch64RegisterRole.None
                && register.Width == 64
                && register.Index == secondDestination);
    }

    public static bool IsSupportedLocalExecAddPair(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateLocalExecAddPairRelocations(relocationSites, out var firstAddress, out var secondAddress))
        {
            return false;
        }

        var firstIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == firstAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        var secondIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == secondAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        if (firstIndex < 0
            || secondIndex != firstIndex + 1
            || !TryGetLocalExecAddImmediateRegisters(
                relocationSites[0].Binding.RelocationType!.Value,
                instructions[firstIndex].Encoding,
                out var firstSource,
                out var firstDestination)
            || !TryGetLocalExecAddImmediateRegisters(
                relocationSites[1].Binding.RelocationType!.Value,
                instructions[secondIndex].Encoding,
                out var secondSource,
                out var secondDestination))
        {
            return false;
        }

        var threadPointerInstructions = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => TryGetThreadPointerRegister(item.instruction.Encoding, out _))
            .ToArray();
        if (threadPointerInstructions.Length != 1
            || threadPointerInstructions[0].index != firstIndex - 1
            || !TryGetThreadPointerRegister(
                threadPointerInstructions[0].instruction.Encoding,
                out var threadPointerRegister)
            || firstSource != threadPointerRegister
            || secondSource != firstDestination)
        {
            return false;
        }

        var memoryAccesses = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Operands.Any(operand => operand.Memory is not null)
                || item.instruction.Mnemonic.StartsWith("ldr", StringComparison.OrdinalIgnoreCase)
                || item.instruction.Mnemonic.StartsWith("str", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var memoryBase = memoryAccesses.Length == 1
            ? memoryAccesses[0].instruction.Operands
                .Select(operand => operand.Memory?.Base)
                .FirstOrDefault(register => register.HasValue)
            : null;
        return memoryAccesses.Length == 1
            && memoryAccesses[0].index == secondIndex + 1
            && memoryBase is { } baseRegister
            && baseRegister.Class == Aarch64RegisterClass.General
            && baseRegister.Role == Aarch64RegisterRole.None
            && baseRegister.Width == 64
            && baseRegister.Index == secondDestination;
    }

    private static bool TryValidateInitialExecMovwPairRelocations(
        IReadOnlyList<TlsRelocationSite> relocationSites,
        out VirtualAddress firstAddress,
        out VirtualAddress secondAddress)
    {
        firstAddress = default;
        secondAddress = default;
        if (relocationSites.Count != 2
            || relocationSites[0] is null
            || relocationSites[1] is null
            || relocationSites[0].PairOrdinal != 0
            || relocationSites[1].PairOrdinal != 1
            || relocationSites[0].Binding.RelocationType != ElfConstants.RArm64TlsIeMovwGottprelG1
            || relocationSites[1].Binding.RelocationType != ElfConstants.RArm64TlsIeMovwGottprelG0Nc
            || relocationSites[0].Binding.Addend != relocationSites[1].Binding.Addend
            || relocationSites[0].SourceRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
            || relocationSites[1].SourceRange.VirtualAddress.Value
                != relocationSites[0].SourceRange.VirtualAddress.Value + sizeof(uint)
            || relocationSites[0].SourceRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
            || relocationSites[1].SourceRange.FileOffset.Value
                != relocationSites[0].SourceRange.FileOffset.Value + sizeof(uint))
        {
            return false;
        }

        firstAddress = relocationSites[0].SourceRange.VirtualAddress;
        secondAddress = relocationSites[1].SourceRange.VirtualAddress;
        return true;
    }

    private static bool TryValidateLocalExecAddPairRelocations(
        IReadOnlyList<TlsRelocationSite> relocationSites,
        out VirtualAddress firstAddress,
        out VirtualAddress secondAddress)
    {
        firstAddress = default;
        secondAddress = default;
        if (relocationSites.Count != 2
            || relocationSites[0] is null
            || relocationSites[1] is null
            || relocationSites[0].PairOrdinal != 0
            || relocationSites[1].PairOrdinal != 1
            || relocationSites[0].Binding.RelocationType != ElfConstants.RArm64TlsLeAddTprelHi12
            || relocationSites[1].Binding.RelocationType is not (
                ElfConstants.RArm64TlsLeAddTprelLo12
                or ElfConstants.RArm64TlsLeAddTprelLo12Nc)
            || relocationSites[0].Binding.Addend != relocationSites[1].Binding.Addend
            || relocationSites[0].SourceRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
            || relocationSites[1].SourceRange.VirtualAddress.Value
                != relocationSites[0].SourceRange.VirtualAddress.Value + sizeof(uint)
            || relocationSites[0].SourceRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
            || relocationSites[1].SourceRange.FileOffset.Value
                != relocationSites[0].SourceRange.FileOffset.Value + sizeof(uint))
        {
            return false;
        }

        firstAddress = relocationSites[0].SourceRange.VirtualAddress;
        secondAddress = relocationSites[1].SourceRange.VirtualAddress;
        return true;
    }

    public static bool IsSupportedLocalExecMovwPair(
        uint firstType,
        uint firstEncoding,
        ulong firstAddress,
        long firstAddend,
        uint secondType,
        uint secondEncoding,
        ulong secondAddress,
        long secondAddend)
    {
        return firstType == ElfConstants.RArm64TlsLeMovwTprelG1
            && secondType == ElfConstants.RArm64TlsLeMovwTprelG0Nc
            && firstAddress <= ulong.MaxValue - sizeof(uint)
            && secondAddress == firstAddress + sizeof(uint)
            && firstAddend == secondAddend
            && TryGetLocalExecMovwRegister(firstType, firstEncoding, out var firstRegister)
            && TryGetLocalExecMovwRegister(secondType, secondEncoding, out var secondRegister)
            && firstRegister == secondRegister;
    }

    /// <summary>
    /// Validates the exact TLSIE MOVW GOTTPREL sequence observed from GNU
    /// AArch64: MOVW pair, TP read, GOT address ADD, zero-offset 64-bit GOT
    /// load, final TP-relative ADD, and one scalar TLS access.
    /// </summary>
    public static bool IsSupportedInitialExecMovwPair(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateInitialExecMovwPairRelocations(relocationSites, out var firstAddress, out var secondAddress))
        {
            return false;
        }

        var firstIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == firstAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        var secondIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == secondAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        if (firstIndex < 0 || secondIndex != firstIndex + 1)
        {
            return false;
        }

        var encodings = instructions.Select(instruction => instruction.Encoding).ToArray();
        if (!IsSupportedInitialExecMovwSequence(encodings, firstIndex))
        {
            return false;
        }

        var memoryIndices = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => IsMemoryInstruction(item.instruction))
            .Select(item => item.index)
            .ToArray();
        return memoryIndices.Length == 2
            && memoryIndices[0] == firstIndex + 4
            && memoryIndices[1] == firstIndex + 6;
    }

    /// <summary>Validates the canonical TLSIE sequence after instruction projection.</summary>
    public static bool IsSupportedInitialExecMovwPair(
        IReadOnlyList<TlsInstructionRecord> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateInitialExecMovwPairRelocations(relocationSites, out var firstAddress, out var secondAddress))
        {
            return false;
        }

        var firstIndex = FindInstructionIndex(instructions, firstAddress);
        var secondIndex = FindInstructionIndex(instructions, secondAddress);
        if (firstIndex < 0 || secondIndex != firstIndex + 1)
        {
            return false;
        }

        var encodings = instructions.Select(instruction => instruction.Encoding).ToArray();
        if (!IsSupportedInitialExecMovwSequence(encodings, firstIndex))
        {
            return false;
        }

        var memoryIndices = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Role == TlsInstructionRole.TlsMemoryAccess)
            .Select(item => item.index)
            .ToArray();
        return memoryIndices.Length == 1
            && memoryIndices[0] == firstIndex + 6
            && instructions[firstIndex + 4].Role == TlsInstructionRole.GotEntryLoad;
    }

    /// <summary>Validates the raw instruction chain at a pair-relative index.</summary>
    public static bool IsSupportedInitialExecMovwSequence(
        IReadOnlyList<uint> encodings,
        int pairIndex)
    {
        ArgumentNullException.ThrowIfNull(encodings);
        if (pairIndex < 0 || pairIndex > encodings.Count - 7
            || !TryGetInitialExecMovwRegister(
                ElfConstants.RArm64TlsIeMovwGottprelG1,
                encodings[pairIndex],
                out var movwRegister)
            || !TryGetInitialExecMovwRegister(
                ElfConstants.RArm64TlsIeMovwGottprelG0Nc,
                encodings[pairIndex + 1],
                out var movkRegister)
            || movwRegister != movkRegister
            || !TryGetThreadPointerRegister(encodings[pairIndex + 2], out var threadPointerRegister)
            || !TryGetLocalExecAddressRegister(
                encodings[pairIndex + 3],
                threadPointerRegister,
                movwRegister,
                out var gotAddressRegister)
            || !TryGetInitialExecGotLoadRegisters(
                encodings[pairIndex + 4],
                out var gotBaseRegister,
                out var gotValueRegister)
            || gotBaseRegister != gotAddressRegister
            || !TryGetLocalExecAddressRegister(
                encodings[pairIndex + 5],
                threadPointerRegister,
                gotValueRegister,
                out var tlsAddressRegister)
            || !TryGetInitialExecTlsAccessRegisters(
                encodings[pairIndex + 6],
                out var tlsBaseRegister,
                out _)
            || tlsBaseRegister != tlsAddressRegister)
        {
            return false;
        }

        return true;
    }

    public static bool IsSupportedInitialExecRelocationInstruction(uint relocationType, uint encoding) =>
        relocationType switch
        {
            ElfConstants.RArm64TlsIeMovwGottprelG1 => TryGetInitialExecMovwRegister(relocationType, encoding, out _),
            ElfConstants.RArm64TlsIeMovwGottprelG0Nc => TryGetInitialExecMovwRegister(relocationType, encoding, out _),
            _ => false,
        };

    public static bool TryGetInitialExecMovwRegister(
        uint relocationType,
        uint encoding,
        out byte register)
    {
        register = 0;
        if ((encoding & 0x8000_0000u) == 0)
        {
            return false;
        }

        var opcode = encoding & MovwOpcodeMask;
        var shift = (encoding >> 21) & 0x3;
        var valid = relocationType switch
        {
            ElfConstants.RArm64TlsIeMovwGottprelG1 => shift == 1 && opcode is MovzOpcode or MovnOpcode,
            ElfConstants.RArm64TlsIeMovwGottprelG0Nc => shift == 0 && opcode == MovkOpcode,
            _ => false,
        };
        if (!valid)
        {
            return false;
        }

        register = (byte)(encoding & 0x1F);
        return register != 31;
    }

    public static bool TryGetInitialExecGotLoadRegisters(
        uint encoding,
        out byte baseRegister,
        out byte valueRegister)
    {
        baseRegister = 0;
        valueRegister = 0;
        if ((encoding & 0xFFC0_0000u) != 0xF940_0000u
            || ((encoding >> 10) & 0xFFF) != 0)
        {
            return false;
        }

        baseRegister = (byte)((encoding >> 5) & 0x1F);
        valueRegister = (byte)(encoding & 0x1F);
        return baseRegister != 31 && valueRegister != 31;
    }

    public static bool TryGetInitialExecTlsAccessRegisters(
        uint encoding,
        out byte baseRegister,
        out byte valueRegister)
    {
        baseRegister = 0;
        valueRegister = 0;
        var opcode = encoding & 0xFFC0_0000u;
        if (opcode is not (
                0xF940_0000u or 0xF900_0000u
                or 0xB940_0000u or 0xB900_0000u
                or 0x7940_0000u or 0x7900_0000u
                or 0x3940_0000u or 0x3900_0000u)
            || ((encoding >> 10) & 0xFFF) != 0)
        {
            return false;
        }

        baseRegister = (byte)((encoding >> 5) & 0x1F);
        valueRegister = (byte)(encoding & 0x1F);
        return baseRegister != 31 && valueRegister != 31;
    }

    /// <summary>
    /// Validates the one implemented TLSLE LDST32 sequence. The ABI/toolchain
    /// shape is ADD TPREL HI12 immediately followed by an unsigned-immediate
    /// 32-bit load/store carrying TLSLE_LDST32_TPREL_LO12_NC.
    /// </summary>
    public static bool IsSupportedLocalExecLdst32Pair(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateLocalExecLdst32PairRelocations(
                relocationSites.Count == 2 ? relocationSites[0].Binding.RelocationType.GetValueOrDefault() : 0,
                relocationSites.Count == 2 ? relocationSites[0].Binding.Addend : 0,
                relocationSites.Count == 2 ? relocationSites[0].SourceRange.VirtualAddress.Value : 0,
                relocationSites.Count == 2 ? relocationSites[1].Binding.RelocationType.GetValueOrDefault() : 0,
                relocationSites.Count == 2 ? relocationSites[1].Binding.Addend : 0,
                relocationSites.Count == 2 ? relocationSites[1].SourceRange.VirtualAddress.Value : 0))
        {
            return false;
        }

        var firstIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == relocationSites[0].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        var secondIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == relocationSites[1].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        if (firstIndex < 0
            || secondIndex != firstIndex + 1
            || !TryGetLocalExecAddImmediateRegisters(
                relocationSites[0].Binding.RelocationType!.Value,
                instructions[firstIndex].Encoding,
                out var firstSource,
                out var firstDestination)
            || !TryGetLocalExecLdst32Registers(
                relocationSites[1].Binding.RelocationType!.Value,
                instructions[secondIndex].Encoding,
                out var secondBase,
                out _)
            || secondBase != firstDestination)
        {
            return false;
        }

        var threadPointerInstructions = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => TryGetThreadPointerRegister(item.instruction.Encoding, out _))
            .ToArray();
        if (threadPointerInstructions.Length != 1
            || threadPointerInstructions[0].index != firstIndex - 1
            || !TryGetThreadPointerRegister(
                threadPointerInstructions[0].instruction.Encoding,
                out var threadPointerRegister)
            || firstSource != threadPointerRegister)
        {
            return false;
        }

        var memoryAccesses = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Operands.Any(operand => operand.Memory is not null)
                || item.instruction.Mnemonic.StartsWith("ldr", StringComparison.OrdinalIgnoreCase)
                || item.instruction.Mnemonic.StartsWith("str", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return memoryAccesses.Length == 1
            && memoryAccesses[0].index == secondIndex
            && TryGetLocalExecLdst32Registers(
                relocationSites[1].Binding.RelocationType!.Value,
                memoryAccesses[0].instruction.Encoding,
                out var memoryBase,
                out _)
            && memoryBase == firstDestination;
    }

    public static bool IsSupportedLocalExecLdst32Pair(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        ulong tprelOffset)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!IsSupportedLocalExecLdst32Pair(instructions, relocationSites))
        {
            return false;
        }

        var first = instructions.First(instruction =>
            instruction.SourceVirtualAddress == relocationSites[0].SourceRange.VirtualAddress);
        var second = instructions.First(instruction =>
            instruction.SourceVirtualAddress == relocationSites[1].SourceRange.VirtualAddress);
        return TryGetLocalExecLdst32Immediate(first.Encoding, second.Encoding, tprelOffset);
    }

    public static bool IsSupportedLocalExecLdst32Pair(
        IReadOnlyList<TlsInstructionRecord> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateLocalExecLdst32PairRelocations(
                relocationSites.Count == 2 ? relocationSites[0].Binding.RelocationType.GetValueOrDefault() : 0,
                relocationSites.Count == 2 ? relocationSites[0].Binding.Addend : 0,
                relocationSites.Count == 2 ? relocationSites[0].SourceRange.VirtualAddress.Value : 0,
                relocationSites.Count == 2 ? relocationSites[1].Binding.RelocationType.GetValueOrDefault() : 0,
                relocationSites.Count == 2 ? relocationSites[1].Binding.Addend : 0,
                relocationSites.Count == 2 ? relocationSites[1].SourceRange.VirtualAddress.Value : 0))
        {
            return false;
        }

        var firstIndex = FindInstructionIndex(instructions, relocationSites[0].SourceRange.VirtualAddress);
        var secondIndex = FindInstructionIndex(instructions, relocationSites[1].SourceRange.VirtualAddress);
        if (firstIndex < 0
            || secondIndex != firstIndex + 1
            || !TryGetLocalExecAddImmediateRegisters(
                relocationSites[0].Binding.RelocationType!.Value,
                instructions[firstIndex].Encoding,
                out var firstSource,
                out var firstDestination)
            || !TryGetLocalExecLdst32Registers(
                relocationSites[1].Binding.RelocationType!.Value,
                instructions[secondIndex].Encoding,
                out var secondBase,
                out _)
            || secondBase != firstDestination)
        {
            return false;
        }

        var threadPointerInstructions = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => TryGetThreadPointerRegister(item.instruction.Encoding, out _))
            .ToArray();
        if (threadPointerInstructions.Length != 1
            || threadPointerInstructions[0].index != firstIndex - 1
            || !TryGetThreadPointerRegister(
                threadPointerInstructions[0].instruction.Encoding,
                out var threadPointerRegister)
            || firstSource != threadPointerRegister)
        {
            return false;
        }

        var memoryAccesses = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Role == TlsInstructionRole.TlsMemoryAccess)
            .ToArray();
        return memoryAccesses.Length == 1
            && memoryAccesses[0].index == secondIndex
            && TryGetLocalExecLdst32Registers(
                relocationSites[1].Binding.RelocationType!.Value,
                memoryAccesses[0].instruction.Encoding,
                out var memoryBase,
                out _)
            && memoryBase == firstDestination;
    }

    public static bool IsSupportedLocalExecLdst32Pair(
        IReadOnlyList<TlsInstructionRecord> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        ulong tprelOffset)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!IsSupportedLocalExecLdst32Pair(instructions, relocationSites))
        {
            return false;
        }

        var first = instructions.First(instruction =>
            instruction.SourceRange.VirtualAddress == relocationSites[0].SourceRange.VirtualAddress);
        var second = instructions.First(instruction =>
            instruction.SourceRange.VirtualAddress == relocationSites[1].SourceRange.VirtualAddress);
        return TryGetLocalExecLdst32Immediate(first.Encoding, second.Encoding, tprelOffset);
    }

    /// <summary>Validates TPIDR_EL0, ADD HI12, and the scaled LDST32 low relocation as one access chain.</summary>
    public static bool IsSupportedLocalExecLdst32Sequence(
        uint threadPointerEncoding,
        uint addEncoding,
        uint loadStoreEncoding)
    {
        return TryGetThreadPointerRegister(threadPointerEncoding, out var threadPointerRegister)
            && TryGetLocalExecAddImmediateRegisters(
                ElfConstants.RArm64TlsLeAddTprelHi12,
                addEncoding,
                out var addSource,
                out var addDestination)
            && addSource == threadPointerRegister
            && TryGetLocalExecLdst32Registers(
                ElfConstants.RArm64TlsLeLdst32TprelLo12Nc,
                loadStoreEncoding,
                out var loadStoreBase,
                out _)
            && loadStoreBase == addDestination;
    }

    /// <summary>Validates the raw instruction pair at a planned source or output address.</summary>
    public static bool IsSupportedLocalExecLdst32Pair(
        uint firstType,
        uint firstEncoding,
        ulong firstAddress,
        long firstAddend,
        uint secondType,
        uint secondEncoding,
        ulong secondAddress,
        long secondAddend) =>
        TryValidateLocalExecLdst32PairRelocations(
            firstType,
            firstAddend,
            firstAddress,
            secondType,
            secondAddend,
            secondAddress)
        && TryGetLocalExecAddImmediateRegisters(
            firstType,
            firstEncoding,
            out _,
            out var firstDestination)
        && TryGetLocalExecLdst32Registers(
            secondType,
            secondEncoding,
            out var secondBase,
            out _)
        && firstDestination == secondBase;

    public static bool IsSupportedLocalExecLdst32Pair(
        uint firstType,
        uint firstEncoding,
        ulong firstAddress,
        long firstAddend,
        uint secondType,
        uint secondEncoding,
        ulong secondAddress,
        long secondAddend,
        ulong tprelOffset) =>
        IsSupportedLocalExecLdst32Pair(
            firstType,
            firstEncoding,
            firstAddress,
            firstAddend,
            secondType,
            secondEncoding,
            secondAddress,
            secondAddend)
        && TryGetLocalExecLdst32Immediate(firstEncoding, secondEncoding, tprelOffset);

    public static bool TryGetLocalExecLdst32Immediate(
        uint addEncoding,
        uint loadStoreEncoding,
        ulong tprelOffset)
    {
        const ulong MaximumRepresentableOffset = 0x00FF_FFFF;
        if (tprelOffset > MaximumRepresentableOffset || (tprelOffset & 3) != 0)
        {
            return false;
        }

        var addHigh = (addEncoding >> 10) & 0xFFF;
        var loadStoreLow = (loadStoreEncoding >> 10) & 0xFFF;
        return addHigh == ((tprelOffset >> 12) & 0xFFF)
            && loadStoreLow == ((tprelOffset & 0xFFF) >> 2);
    }

    public static bool TryAddSigned(ulong value, long addend, out ulong result)
    {
        if (addend >= 0)
        {
            if ((ulong)addend > ulong.MaxValue - value)
            {
                result = 0;
                return false;
            }

            result = value + (ulong)addend;
            return true;
        }

        var magnitude = unchecked((ulong)(-(addend + 1))) + 1;
        if (magnitude > value)
        {
            result = 0;
            return false;
        }

        result = value - magnitude;
        return true;
    }

    public static bool TryGetLocalExecMovwRegister(uint relocationType, uint encoding, out byte register)
    {
        register = 0;
        if ((encoding & 0x8000_0000u) == 0)
        {
            return false;
        }

        var opcode = encoding & MovwOpcodeMask;
        var shift = (encoding >> 21) & 0x3;
        var valid = relocationType switch
        {
            ElfConstants.RArm64TlsLeMovwTprelG1 =>
                shift == 1 && opcode is MovzOpcode or MovnOpcode,
            ElfConstants.RArm64TlsLeMovwTprelG0Nc => shift == 0 && opcode == MovkOpcode,
            _ => false,
        };
        if (!valid)
        {
            return false;
        }

        register = (byte)(encoding & 0x1F);
        return register != 31;
    }

    public static bool TryGetThreadPointerRegister(uint encoding, out byte register)
    {
        register = 0;
        if ((encoding & ThreadPointerMrsMask) != ThreadPointerMrsEncoding)
        {
            return false;
        }

        register = (byte)(encoding & 0x1F);
        return register != 31;
    }

    /// <summary>
    /// Extracts the base and 32-bit value registers from the AArch64 unsigned
    /// immediate LDR/STR form. The opcode mask deliberately excludes the
    /// scaled imm12 and register fields so the materializer can copy only the
    /// linker-resolved low-12 field after a register rewrite.
    /// </summary>
    public static bool TryGetLocalExecLdst32Registers(
        uint relocationType,
        uint encoding,
        out byte baseRegister,
        out byte valueRegister)
    {
        baseRegister = 0;
        valueRegister = 0;
        if (relocationType != ElfConstants.RArm64TlsLeLdst32TprelLo12Nc
            || (encoding & 0xC000_0000u) != 0x8000_0000u
            || (encoding & 0x3FC0_0000u) is not (0x3900_0000u or 0x3940_0000u))
        {
            return false;
        }

        baseRegister = (byte)((encoding >> 5) & 0x1F);
        valueRegister = (byte)(encoding & 0x1F);
        return baseRegister != 31 && valueRegister != 31;
    }

    public static bool TryGetLocalExecAddressRegister(
        uint encoding,
        byte threadPointerRegister,
        byte tprelRegister,
        out byte destinationRegister)
    {
        destinationRegister = 0;
        if ((encoding & AddRegisterOpcodeMask) != AddRegisterOpcode
            || (encoding & AddRegisterShiftMask) != 0)
        {
            return false;
        }

        var destination = (byte)(encoding & 0x1F);
        var firstSource = (byte)((encoding >> 5) & 0x1F);
        var secondSource = (byte)((encoding >> 16) & 0x1F);
        if (destination == 31
            || firstSource != threadPointerRegister
            || secondSource != tprelRegister)
        {
            return false;
        }

        destinationRegister = destination;
        return true;
    }

    public static bool TryGetLocalExecAddImmediateRegisters(
        uint relocationType,
        uint encoding,
        out byte sourceRegister,
        out byte destinationRegister)
    {
        sourceRegister = 0;
        destinationRegister = 0;
        var expectedShift = relocationType switch
        {
            ElfConstants.RArm64TlsLeAddTprelHi12 => 1u,
            ElfConstants.RArm64TlsLeAddTprelLo12
                or ElfConstants.RArm64TlsLeAddTprelLo12Nc => 0u,
            _ => uint.MaxValue,
        };
        if (expectedShift == uint.MaxValue
            || (encoding & 0x8000_0000u) == 0
            || (encoding & AddImmediateOpcodeMask) != AddImmediateOpcode
            || ((encoding >> 22) & 1) != expectedShift)
        {
            return false;
        }

        sourceRegister = (byte)((encoding >> 5) & 0x1F);
        destinationRegister = (byte)(encoding & 0x1F);
        return sourceRegister != 31 && destinationRegister != 31;
    }

    public static bool IsSupportedLocalExecAddSequence(
        uint firstType,
        uint firstEncoding,
        uint secondType,
        uint secondEncoding,
        uint threadPointerEncoding,
        uint memoryEncoding)
    {
        return TryGetThreadPointerRegister(threadPointerEncoding, out var threadPointerRegister)
            && TryGetLocalExecAddImmediateRegisters(
                firstType,
                firstEncoding,
                out var firstSource,
                out var firstDestination)
            && TryGetLocalExecAddImmediateRegisters(
                secondType,
                secondEncoding,
                out var secondSource,
                out var secondDestination)
            && TryGetInitialExecTlsAccessRegisters(
                memoryEncoding,
                out var memoryBase,
                out _)
            && firstSource == threadPointerRegister
            && secondSource == firstDestination
            && memoryBase == secondDestination;
    }

    private static bool TryValidateLocalExecLdst32PairRelocations(
        uint firstType,
        long firstAddend,
        ulong firstAddress,
        uint secondType,
        long secondAddend,
        ulong secondAddress) =>
        firstType == ElfConstants.RArm64TlsLeAddTprelHi12
        && secondType == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc
        && firstAddress <= ulong.MaxValue - sizeof(uint)
        && secondAddress == firstAddress + sizeof(uint)
        && firstAddend == secondAddend;

    private static bool IsMemoryInstruction(SemanticInstruction instruction) =>
        instruction.Operands.Any(operand => operand.Memory is not null)
        || instruction.Mnemonic.StartsWith("ldr", StringComparison.OrdinalIgnoreCase)
        || instruction.Mnemonic.StartsWith("str", StringComparison.OrdinalIgnoreCase);

    private static int FindInstructionIndex(
        IReadOnlyList<TlsInstructionRecord> instructions,
        VirtualAddress address) => instructions
        .Select((instruction, index) => (instruction, index))
        .Where(item => item.instruction.SourceRange.VirtualAddress == address)
        .Select(item => item.index)
        .DefaultIfEmpty(-1)
        .First();
}
