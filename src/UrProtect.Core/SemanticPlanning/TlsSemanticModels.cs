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


/// <summary>Source-owned resolver call and its exact relocation identity.</summary>
public sealed record TlsResolverCallBinding(
    SemanticSourceRange SourceRange,
    RelocationBinding Relocation);

/// <summary>Loader-owned TLS module-ID storage retained outside the instruction sequence.</summary>
public sealed record TlsModuleOwnerBinding(
    SemanticEntityId SourceIdentity,
    SemanticSourceRange SourceRange,
    RelocationBinding Relocation);
/// <summary>Loader-owned TLS symbol-offset storage retained outside the instruction sequence.</summary>
public sealed record TlsDtpRelOwnerBinding(
    SemanticEntityId SourceIdentity,
    SemanticSourceRange SourceRange,
    RelocationBinding Relocation);

/// <summary>Loader-owned per-symbol TLSDESC descriptor and resolver metadata.</summary>
/// <remarks>
/// <see cref="DescriptorRange"/> is the complete 16-byte descriptor, while
/// <see cref="Relocation"/> describes only the loader-owned first eight-byte
/// word. <see cref="ResolverGotRange"/> is the distinct DT_TLSDESC_GOT
/// resolver slot and is never treated as the per-symbol descriptor.
/// </remarks>
public sealed record TlsDescriptorOwnerBinding(
    SemanticEntityId SourceIdentity,
    SemanticSourceRange DescriptorRange,
    RelocationBinding Relocation,
    TlsSymbolIdentity Symbol,
    long Addend,
    VirtualAddress DescriptorPlt,
    VirtualAddress DescriptorGot,
    VirtualAddress PltGot,
    SemanticSourceRange ResolverPltRange,
    SemanticSourceRange ResolverGotRange);

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
        TlsGotEntryBinding? gotEntry = null,
        TlsResolverCallBinding? resolverCall = null,
        TlsModuleOwnerBinding? moduleOwner = null,
        TlsDtpRelOwnerBinding? dtpRelOwner = null,
        TlsDescriptorOwnerBinding? descriptorOwner = null)
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
        ResolverCall = resolverCall;
        ModuleOwner = moduleOwner;
        DtpRelOwner = dtpRelOwner;
        DescriptorOwner = descriptorOwner;
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

    public TlsResolverCallBinding? ResolverCall { get; }

    public TlsModuleOwnerBinding? ModuleOwner { get; }

    public TlsDtpRelOwnerBinding? DtpRelOwner { get; }

    public TlsDescriptorOwnerBinding? DescriptorOwner { get; }
}

/// <summary>Stable relocation-family classification for the AArch64 ELF ABI constants.</summary>
public static class TlsRelocationClassifier
{
    private static readonly uint[] TlsDescRelocationPattern =
    {
        ElfConstants.RArm64TlsDescAdrPage21,
        ElfConstants.RArm64TlsDescLd64Lo12,
        ElfConstants.RArm64TlsDescAddLo12,
        ElfConstants.RArm64TlsDescCall,
    };

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
                && (relocationArray.Length == 1
                    && relocationArray[0] == ElfConstants.RArm64TlsIeLdGottprelPrel19
                    || relocationArray.Length == 2
                    && (HasPair(types, ElfConstants.RArm64TlsIeMovwGottprelG1, ElfConstants.RArm64TlsIeMovwGottprelG0Nc)
                        || HasPair(types, ElfConstants.RArm64TlsIeAdrGottprelPage21, ElfConstants.RArm64TlsIeLd64GottprelLo12Nc))),
            TlsAccessModel.LocalDynamic => families.Contains(TlsRelocationFamily.Dtpmod)
                && families.Contains(TlsRelocationFamily.Dtprel)
                && (HasPair(types, ElfConstants.RArm64TlsLdAdrPage21, ElfConstants.RArm64TlsLdAddLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsLdAdrPrel21, ElfConstants.RArm64TlsLdAddLo12Nc)),
            TlsAccessModel.GeneralDynamic => families.Contains(TlsRelocationFamily.Dtpmod)
                && families.Contains(TlsRelocationFamily.Dtprel)
                && (HasPair(types, ElfConstants.RArm64TlsGdAdrPage21, ElfConstants.RArm64TlsGdAddLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsGdAdrPrel21, ElfConstants.RArm64TlsGdAddLo12Nc)
                    || HasPair(types, ElfConstants.RArm64TlsGdMovwG1, ElfConstants.RArm64TlsGdMovwG0Nc)),
            TlsAccessModel.TlsDesc => relocationArray.Length == 4
                && relocationArray.SequenceEqual(TlsDescRelocationPattern),
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
    private const uint AdrpOpcodeMask = 0x9F00_0000;
    private const uint AdrpOpcode = 0x9000_0000;
    private const uint Ld64UnsignedOpcodeMask = 0xFFC0_0000;
    private const uint Ld64UnsignedOpcode = 0xF940_0000;
    private const uint LdGotPrel19OpcodeMask = 0xFF00_0000;
    private const uint LdGotPrel19Opcode = 0x5800_0000;
    private const uint AddRegisterOpcodeMask = 0xFF20_0000;
    private const uint AddRegisterOpcode = 0x8B00_0000;
    private const uint AddRegisterShiftMask = 0x00C0_FC00;
    private const uint ThreadPointerMrsMask = 0xFFFF_FFE0;
    private const uint ThreadPointerMrsEncoding = 0xD53B_D040;
    private static readonly Aarch64InstructionEncoder InstructionEncoder = new();
    private static readonly uint[] TlsDescRelocationOrder =
    {
        ElfConstants.RArm64TlsDescAdrPage21,
        ElfConstants.RArm64TlsDescLd64Lo12,
        ElfConstants.RArm64TlsDescAddLo12,
        ElfConstants.RArm64TlsDescCall,
    };
    private static readonly int[] TlsDescPairOrdinals = { 0, 1, 2, 3 };



    /// <summary>
    /// Validates the exact linker-oracle TLSDESC page/LD64/ADD/BLR sequence.
    /// The descriptor owner is separate from the DT_TLSDESC_GOT resolver slot;
    /// no resolver target string is inferred from the indirect BLR.
    /// </summary>
    public static bool IsSupportedTlsDescSequence(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        TlsDescriptorOwnerBinding descriptorOwner)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        ArgumentNullException.ThrowIfNull(descriptorOwner);
        if (instructions.Count < 8
            || relocationSites.Count != 4
            || descriptorOwner.DescriptorRange.Size != 2 * sizeof(ulong)
            || descriptorOwner.ResolverPltRange.Size != 6 * sizeof(uint)
            || descriptorOwner.ResolverGotRange.Size != sizeof(ulong)
            || descriptorOwner.Relocation.RelocationType != ElfConstants.RArm64TlsDesc
            || descriptorOwner.Relocation.Kind != Aarch64RelocationKind.ThreadLocal
            || descriptorOwner.Relocation.Addend != 0
            || descriptorOwner.Addend != 0
            || descriptorOwner.DescriptorRange.VirtualAddress.Value % sizeof(ulong) != 0
            || descriptorOwner.DescriptorRange.FileOffset.Value % sizeof(ulong) != 0)
        {
            return false;
        }

        var orderedSites = relocationSites.OrderBy(site => site.PairOrdinal).ToArray();
        if (!orderedSites.Select(site => site.PairOrdinal).SequenceEqual(TlsDescPairOrdinals)
            || !orderedSites.Select(site => site.Binding.RelocationType).SequenceEqual(TlsDescRelocationOrder.Select(type => (uint?)type))
            || orderedSites.Any(site => site.Binding.Addend != 0 || site.SourceRange.Size != sizeof(uint))
            || orderedSites.Zip(orderedSites.Skip(1)).Any(pair => !IsAdjacentTlsSites(pair.First, pair.Second))
            || orderedSites.Any(site => site.Binding.SymbolIndex != descriptorOwner.Symbol.SymbolIndex
                || !string.Equals(site.Binding.SymbolName, descriptorOwner.Symbol.Name, StringComparison.Ordinal)
                || site.Binding.RelocationAddress != site.SourceRange.VirtualAddress))
        {
            return false;
        }

        var siteIndices = orderedSites
            .Select(site => FindInstructionIndex(instructions, site.SourceRange.VirtualAddress))
            .ToArray();
        if (siteIndices.Length != 4
            || siteIndices.Any(index => index < 0)
            || !siteIndices.Select((index, ordinal) => index == siteIndices[0] + ordinal).All(value => value)
            || instructions.Zip(instructions.Skip(1)).Any(pair =>
                pair.Second.SourceVirtualAddress.Value != pair.First.SourceVirtualAddress.Value + sizeof(uint)
                || pair.Second.SourceFileOffset.Value != pair.First.SourceFileOffset.Value + sizeof(uint)))
        {
            return false;
        }

        var coreIndex = siteIndices[0];
        if (coreIndex > instructions.Count - 7)
        {
            return false;
        }

        var descriptorAddress = descriptorOwner.DescriptorRange.VirtualAddress.Value;
        var descriptorLow12 = descriptorAddress & 0xFFFUL;
        var adrp = instructions[coreIndex];
        var load = instructions[coreIndex + 1];
        var add = instructions[coreIndex + 2];
        var call = instructions[coreIndex + 3];
        var threadPointer = instructions[coreIndex + 4];
        var finalAdd = instructions[coreIndex + 5];
        var access = instructions[coreIndex + 6];
        var loadMemory = GetMemory(load);
        var accessMemory = GetMemory(access);
        var adrpTarget = GetTarget(adrp);
        var loadValueRegister = GetRegister(load, Aarch64OperandDirection.Output);
        var addImmediate = GetImmediate(add);
        var finalAddInputs = GetRegisters(finalAdd, Aarch64OperandDirection.Input);
        var finalAddOutput = GetRegister(finalAdd, Aarch64OperandDirection.Output);
        var returnIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.index > coreIndex + 6
                && string.Equals(item.instruction.Mnemonic, "ret", StringComparison.OrdinalIgnoreCase)
                && item.instruction.ControlFlow == Aarch64ControlFlowKind.Return)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        if (returnIndex < 0
            || instructions
                .Skip(coreIndex + 7)
                .Take(returnIndex - (coreIndex + 7))
                .Any(instruction => instruction.ControlFlow != Aarch64ControlFlowKind.None))
        {
            return false;
        }

        return string.Equals(adrp.Mnemonic, "adrp", StringComparison.OrdinalIgnoreCase)
            && HasRegister(adrp, Aarch64OperandDirection.Output, 0, 64)
            && adrpTarget is { } target
            && (target & ~0xFFFUL) == (descriptorAddress & ~0xFFFUL)
            && string.Equals(load.Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
            && loadValueRegister is { Class: Aarch64RegisterClass.General, Index: 1, Width: 64, Role: Aarch64RegisterRole.None }
            && loadMemory is { Base: { Class: Aarch64RegisterClass.General, Index: 0, Width: 64, Role: Aarch64RegisterRole.None }, Index: null, AccessSize: 8, WritesBack: false }
            && loadMemory.Offset == checked((long)descriptorLow12)
            && string.Equals(add.Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
            && HasRegister(add, Aarch64OperandDirection.Input, 0, 64)
            && HasRegister(add, Aarch64OperandDirection.Output, 0, 64)
            && addImmediate == checked((long)descriptorLow12)
            && string.Equals(call.Mnemonic, "blr", StringComparison.OrdinalIgnoreCase)
            && call.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
            && HasRegister(call, Aarch64OperandDirection.Input, 1, 64)
            && IsThreadPointerMrs(threadPointer)
            && HasRegister(threadPointer, Aarch64OperandDirection.Output, 1, 64)
            && string.Equals(finalAdd.Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
            && finalAddOutput is { Class: Aarch64RegisterClass.General, Index: 0, Width: 64, Role: Aarch64RegisterRole.None }
            && finalAddInputs.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 1, Width: 64, Role: Aarch64RegisterRole.None })
            && finalAddInputs.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 0, Width: 64, Role: Aarch64RegisterRole.None })
            && GetImmediate(finalAdd) is null
            && accessMemory is { Base: { Class: Aarch64RegisterClass.General, Index: 0, Width: 64, Role: Aarch64RegisterRole.None }, Index: null, AccessSize: 1 or 2 or 4 or 8, WritesBack: false }
            && string.Equals(access.Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
            && returnIndex > coreIndex + 6;
    }

    /// <summary>Re-encodes one exact TLSDESC marker through the project encoder.</summary>
    public static bool TryEncodeTlsDescInstruction(
        uint relocationType,
        uint sourceEncoding,
        uint outputEncoding,
        ulong sourceAddress,
        ulong outputAddress,
        TlsDescriptorOwnerBinding descriptorOwner,
        out uint encoded)
    {
        ArgumentNullException.ThrowIfNull(descriptorOwner);
        encoded = 0;
        if (descriptorOwner.DescriptorRange.VirtualAddress.Value > ulong.MaxValue - (2 * sizeof(ulong))
            || descriptorOwner.DescriptorRange.VirtualAddress.Value % sizeof(ulong) != 0)
        {
            return false;
        }

        var descriptorAddress = descriptorOwner.DescriptorRange.VirtualAddress.Value;
        var low12 = descriptorAddress & 0xFFFUL;
        if (relocationType == ElfConstants.RArm64TlsDescCall)
        {
            var source = new AsmStoneAdapter().Decode(sourceEncoding, sourceAddress);
            var output = new AsmStoneAdapter().Decode(outputEncoding, outputAddress);
            encoded = outputEncoding;
            return source.IsSuccess
                && output.IsSuccess
                && IsTlsDescCall(source.Instruction)
                && IsTlsDescCall(output.Instruction);
        }

        var family = relocationType switch
        {
            ElfConstants.RArm64TlsDescAdrPage21 => Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            ElfConstants.RArm64TlsDescLd64Lo12 => Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
            ElfConstants.RArm64TlsDescAddLo12 => Aarch64InstructionEncodingFamily.AddImmediate,
            _ => (Aarch64InstructionEncodingFamily?)null,
        };
        if (family is null)
        {
            return false;
        }

        var sourceInstruction = new AsmStoneAdapter().Decode(sourceEncoding, sourceAddress);
        if (!sourceInstruction.IsSuccess)
        {
            return false;
        }

        if (relocationType == ElfConstants.RArm64TlsDescLd64Lo12
            && (GetMemory(sourceInstruction.Instruction!) is not { AccessSize: 8 } sourceMemory
                || sourceMemory.Offset != checked((long)low12)))
        {
            return false;
        }

        if (relocationType == ElfConstants.RArm64TlsDescAddLo12
            && GetImmediate(sourceInstruction.Instruction!) != checked((long)low12))
        {
            return false;
        }

        var request = new Aarch64InstructionEncodeRequest(
            sourceEncoding,
            sourceAddress,
            outputAddress,
            family.Value,
            relocationType == ElfConstants.RArm64TlsDescAdrPage21 ? descriptorAddress : low12,
            relocationType == ElfConstants.RArm64TlsDescLd64Lo12 ? 64 : 0,
            outputEncoding);
        var result = InstructionEncoder.TryEncode(request);
        if (!result.IsSuccess)
        {
            return false;
        }

        encoded = result.Encoding;
        return true;
    }

    private static bool IsTlsDescCall(Aarch64Instruction? instruction) =>
        instruction is not null
        && string.Equals(instruction.Mnemonic, "blr", StringComparison.OrdinalIgnoreCase)
        && instruction.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
        && HasRegister(instruction, Aarch64OperandDirection.Input, 1, 64);

    private static Aarch64MemoryReference? GetMemory(Aarch64Instruction instruction) =>
        instruction.Operands.Select(operand => operand.Memory).FirstOrDefault(memory => memory is not null);

    private static Aarch64MemoryReference? GetMemory(SemanticInstruction instruction) =>
        instruction.Operands.Select(operand => operand.Memory).FirstOrDefault(memory => memory is not null);

    private static ulong? GetTarget(SemanticInstruction instruction) =>
        instruction.Operands.Select(operand => operand.Target).FirstOrDefault(target => target.HasValue);

    private static long? GetImmediate(Aarch64Instruction instruction) =>
        instruction.Operands.Select(operand => operand.Immediate).FirstOrDefault(value => value.HasValue);

    private static long? GetImmediate(SemanticInstruction instruction) =>
        instruction.Operands.Select(operand => operand.Immediate).FirstOrDefault(value => value.HasValue);

    private static bool HasRegister(
        Aarch64Instruction instruction,
        Aarch64OperandDirection direction,
        byte index,
        byte width) => instruction.Operands
        .Where(operand => operand.Direction == direction
            || (direction == Aarch64OperandDirection.Input
                && operand.Direction == Aarch64OperandDirection.InputOutput)
            || (direction == Aarch64OperandDirection.Output
                && operand.Direction == Aarch64OperandDirection.InputOutput))
        .SelectMany(operand =>
        {
            var registers = new List<Aarch64RegisterView>();
            if (operand.Register is { } register)
            {
                registers.Add(register);
            }

            registers.AddRange(operand.Registers);
            if (operand.Memory is { } memory)
            {
                registers.Add(memory.Base);
                if (memory.Index is { } memoryIndex)
                {
                    registers.Add(memoryIndex);
                }
            }

            return registers;
        })
        .Any(register => register.Class == Aarch64RegisterClass.General
            && register.Role == Aarch64RegisterRole.None
            && register.Index == index
            && register.Width == width);

    private static Aarch64RegisterView? GetRegister(
        SemanticInstruction instruction,
        Aarch64OperandDirection direction) =>
        instruction.Operands
            .Where(operand => operand.Direction == direction)
            .Select(operand => operand.Register)
            .FirstOrDefault(register => register.HasValue);

    private static Aarch64RegisterView[] GetRegisters(
        SemanticInstruction instruction,
        Aarch64OperandDirection direction) => instruction.Operands
        .Where(operand => operand.Direction == direction
            || (direction == Aarch64OperandDirection.Input
                && operand.Direction == Aarch64OperandDirection.InputOutput)
            || (direction == Aarch64OperandDirection.Output
                && operand.Direction == Aarch64OperandDirection.InputOutput))
        .SelectMany(operand =>
        {
            var registers = new List<Aarch64RegisterView>();
            if (operand.Register is { } register)
            {
                registers.Add(register);
            }

            registers.AddRange(operand.Registers);
            if (operand.Memory is { } memory)
            {
                registers.Add(memory.Base);
                if (memory.Index is { } index)
                {
                    registers.Add(index);
                }
            }

            return registers;
        })
        .Distinct()
        .ToArray();

    private static bool HasRegister(
        SemanticInstruction instruction,
        Aarch64OperandDirection direction,
        byte index,
        byte width) => GetRegisters(instruction, direction).Any(register =>
            register is
            {
                Class: Aarch64RegisterClass.General,
                Role: Aarch64RegisterRole.None,
            }
            && register.Index == index
            && register.Width == width);

    private static bool IsThreadPointerMrs(SemanticInstruction instruction) =>
        string.Equals(instruction.Mnemonic, "mrs", StringComparison.OrdinalIgnoreCase)
        && (instruction.Encoding & ThreadPointerMrsMask) == ThreadPointerMrsEncoding;



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

    /// <summary>
    /// Validates the exact TLSGD ADRP/ADD module-ID formation, direct resolver
    /// call, final TLS access, and paired loader-owned GOT words.
    /// </summary>
    public static bool IsSupportedGeneralDynamicTlsGdSequence(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        TlsResolverCallBinding? resolverCall,
        TlsModuleOwnerBinding? moduleOwner,
        TlsDtpRelOwnerBinding? dtpRelOwner)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (relocationSites.Count != 2 || resolverCall is null || moduleOwner is null || dtpRelOwner is null)
        {
            return false;
        }

        var orderedSites = relocationSites.OrderBy(site => site.PairOrdinal).ToArray();
        if (orderedSites[0].PairOrdinal != 0
            || orderedSites[1].PairOrdinal != 1
            || orderedSites[0].Binding.RelocationType != ElfConstants.RArm64TlsGdAdrPage21
            || orderedSites[1].Binding.RelocationType != ElfConstants.RArm64TlsGdAddLo12Nc
            || orderedSites[0].Binding.Addend != 0
            || orderedSites[1].Binding.Addend != 0
            || !IsAdjacentTlsSites(orderedSites[0], orderedSites[1])
            || !IsAdjacentTlsOwner(moduleOwner, dtpRelOwner)
            || moduleOwner.Relocation.RelocationType != ElfConstants.RArm64TlsDtpMod64
            || dtpRelOwner.Relocation.RelocationType != ElfConstants.RArm64TlsDtpRel64
            || moduleOwner.Relocation.SymbolIndex != dtpRelOwner.Relocation.SymbolIndex
            || moduleOwner.Relocation.SymbolName != dtpRelOwner.Relocation.SymbolName
            || moduleOwner.Relocation.Addend != 0
            || resolverCall.SourceRange.Size != sizeof(uint)
            || resolverCall.Relocation.RelocationType != ElfConstants.RArm64Call26
            || resolverCall.Relocation.Kind != Aarch64RelocationKind.Call26
            || resolverCall.Relocation.SymbolName != "__tls_get_addr"
            || resolverCall.Relocation.IsPlt)
        {
            return false;
        }

        var moduleIndex = FindInstructionIndex(instructions, orderedSites[0].SourceRange.VirtualAddress);
        var moduleAddIndex = FindInstructionIndex(instructions, orderedSites[1].SourceRange.VirtualAddress);
        var resolverIndex = FindInstructionIndex(instructions, resolverCall.SourceRange.VirtualAddress);
        if (moduleIndex < 0
            || moduleAddIndex != moduleIndex + 1
            || resolverIndex != moduleIndex + 2
            || moduleIndex + 3 >= instructions.Count
            || !TryGetInitialExecAdrRegister(instructions[moduleIndex].Encoding, out var moduleRegister)
            || moduleRegister != 0
            || !TryGetTlsDynamicAddImmediateRegisters(
                ElfConstants.RArm64TlsGdAddLo12Nc,
                instructions[moduleAddIndex].Encoding,
                out var addSource,
                out var addDestination)
            || addSource != moduleRegister
            || addDestination != moduleRegister
            || !IsDirectTlsResolverCall(instructions[resolverIndex]))
        {
            return false;
        }

        var memoryIndices = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => IsMemoryInstruction(item.instruction))
            .Select(item => item.index)
            .ToArray();
        var tlsAccessIndices = memoryIndices
            .Where(index => index > resolverIndex)
            .ToArray();
        if (tlsAccessIndices.Length == 0 || tlsAccessIndices[0] != moduleIndex + 3)
        {
            return false;
        }

        var memoryBase = instructions[tlsAccessIndices[0]].Operands
            .Select(operand => operand.Memory?.Base)
            .FirstOrDefault(register => register.HasValue);
        return memoryBase is { } baseRegister
            && baseRegister.Class == Aarch64RegisterClass.General
            && baseRegister.Role == Aarch64RegisterRole.None
            && baseRegister.Width == 64
            && baseRegister.Index == moduleRegister;
    }

    private static int FindInstructionIndex(
        IReadOnlyList<SemanticInstruction> instructions,
        VirtualAddress address) => instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == address)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();

    private static bool IsAdjacentTlsOwner(
        TlsModuleOwnerBinding moduleOwner,
        TlsDtpRelOwnerBinding dtpRelOwner) =>
        moduleOwner.SourceRange.Size == sizeof(ulong)
        && dtpRelOwner.SourceRange.Size == sizeof(ulong)
        && moduleOwner.SourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(ulong)
        && moduleOwner.SourceRange.FileOffset.Value <= ulong.MaxValue - sizeof(ulong)
        && dtpRelOwner.SourceRange.VirtualAddress.Value == moduleOwner.SourceRange.VirtualAddress.Value + sizeof(ulong)
        && dtpRelOwner.SourceRange.FileOffset.Value == moduleOwner.SourceRange.FileOffset.Value + sizeof(ulong);

    /// <summary>
    /// Validates the first bounded TLSLD sequence: an adjacent module-ID ADRP/ADD
    /// pair, direct resolver call, adjacent DTPREL ADD pair, and one final access.
    /// The loader-owned DTPMOD64 owner is carried as the fifth site.
    /// </summary>
    public static bool IsSupportedLocalDynamicTlsLdSequence(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        TlsResolverCallBinding? resolverCall = null,
        TlsModuleOwnerBinding? moduleOwner = null)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (relocationSites.Count != 4 || resolverCall is null || moduleOwner is null)
        {
            return false;
        }

        var moduleSites = relocationSites
            .Where(site => site.Binding.RelocationType is
                ElfConstants.RArm64TlsLdAdrPage21
                or ElfConstants.RArm64TlsLdAddLo12Nc)
            .OrderBy(site => site.PairOrdinal)
            .ToArray();
        var dtpRelSites = relocationSites
            .Where(site => site.Binding.RelocationType is
                ElfConstants.RArm64TlsLdAddDtprelHi12
                or ElfConstants.RArm64TlsLdAddDtprelLo12
                or ElfConstants.RArm64TlsLdAddDtprelLo12Nc)
            .OrderBy(site => site.PairOrdinal)
            .ToArray();
        if (moduleSites.Length != 2
            || dtpRelSites.Length != 2
            || moduleSites.Length + dtpRelSites.Length != relocationSites.Count
            || moduleSites[0].PairOrdinal != 0
            || moduleSites[1].PairOrdinal != 1
            || dtpRelSites[0].PairOrdinal != 2
            || dtpRelSites[1].PairOrdinal != 3
            || !IsAdjacentTlsSites(moduleSites[0], moduleSites[1])
            || !IsAdjacentTlsSites(dtpRelSites[0], dtpRelSites[1])
            || moduleSites[0].Binding.Addend != 0
            || moduleSites[1].Binding.Addend != 0
            || dtpRelSites[0].Binding.Addend != dtpRelSites[1].Binding.Addend
            || moduleOwner.Relocation.Addend != 0
            || moduleOwner.SourceRange.Size != sizeof(ulong)
            || moduleOwner.SourceRange.FileOffset.Value % sizeof(ulong) != 0
            || moduleOwner.SourceRange.VirtualAddress.Value % sizeof(ulong) != 0
            || moduleOwner.Relocation.RelocationType != ElfConstants.RArm64TlsDtpMod64
            || moduleOwner.Relocation.SymbolIndex != 0
            || moduleOwner.Relocation.SymbolName is not null
            || moduleOwner.Relocation.RelocationAddress != moduleOwner.SourceRange.VirtualAddress
            || moduleOwner.Relocation.Kind != Aarch64RelocationKind.ThreadLocal
            || resolverCall.SourceRange.Size != sizeof(uint)
            || resolverCall.Relocation.RelocationType != ElfConstants.RArm64Call26
            || resolverCall.Relocation.Kind != Aarch64RelocationKind.Call26
            || resolverCall.Relocation.SymbolName != "__tls_get_addr"
            || resolverCall.Relocation.IsPlt)
        {
            return false;
        }

        var moduleIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == moduleSites[0].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        var moduleAddIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == moduleSites[1].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        var dtpRelHighIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == dtpRelSites[0].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        var dtpRelLowIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == dtpRelSites[1].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        if (moduleIndex < 0
            || moduleAddIndex != moduleIndex + 1
            || dtpRelHighIndex != moduleIndex + 3
            || dtpRelLowIndex != moduleIndex + 4
            || moduleIndex > instructions.Count - 6
            || !TryGetInitialExecAdrRegister(instructions[moduleIndex].Encoding, out var moduleRegister)
            || moduleRegister != 0
            || !TryGetTlsDynamicAddImmediateRegisters(
                moduleSites[1].Binding.RelocationType!.Value,
                instructions[moduleAddIndex].Encoding,
                out var moduleAddSource,
                out var moduleAddDestination)
            || moduleAddSource != moduleRegister
            || moduleAddDestination != moduleRegister
            || !IsDirectTlsResolverCall(instructions[moduleIndex + 2])
            || !TryGetTlsDynamicAddImmediateRegisters(
                dtpRelSites[0].Binding.RelocationType!.Value,
                instructions[dtpRelHighIndex].Encoding,
                out var dtpRelHighSource,
                out var dtpRelHighDestination)
            || !TryGetTlsDynamicAddImmediateRegisters(
                dtpRelSites[1].Binding.RelocationType!.Value,
                instructions[dtpRelLowIndex].Encoding,
                out var dtpRelLowSource,
                out var dtpRelLowDestination)
            || dtpRelHighSource != moduleRegister
            || dtpRelHighDestination != moduleRegister
            || dtpRelLowSource != dtpRelHighDestination
            || dtpRelLowDestination != moduleRegister)
        {
            return false;
        }

        var tlsAccessIndex = moduleIndex + 5;
        if (tlsAccessIndex >= instructions.Count
            || !IsMemoryInstruction(instructions[tlsAccessIndex]))
        {
            return false;
        }

        var memoryBase = instructions[tlsAccessIndex].Operands
            .Select(operand => operand.Memory?.Base)
            .FirstOrDefault(register => register.HasValue);
        return memoryBase is { } baseRegister
            && baseRegister.Class == Aarch64RegisterClass.General
            && baseRegister.Role == Aarch64RegisterRole.None
            && baseRegister.Width == 64
            && baseRegister.Index == moduleRegister;
    }
    public static bool TryEncodeLocalDynamicModulePair(
        uint sourceAdrEncoding,
        uint sourceAddEncoding,
        uint outputAdrEncoding,
        uint outputAddEncoding,
        uint moduleAddRelocationType,
        ulong sourceAdrAddress,
        ulong outputAdrAddress,
        ulong moduleOwnerAddress,
        long addend,
        out uint encodedAdr,
        out uint encodedAdd)
    {
        encodedAdr = 0;
        encodedAdd = 0;
        var sourceAdrValid = TryGetInitialExecAdrRegister(sourceAdrEncoding, out var sourceAdrRegister);
        var sourceAddValid = TryGetTlsDynamicAddImmediateRegisters(
            moduleAddRelocationType,
            sourceAddEncoding,
            out var sourceAddSource,
            out var sourceAddDestination);
        var outputAdrValid = TryGetInitialExecAdrRegister(outputAdrEncoding, out var outputAdrRegister);
        var outputAddValid = TryGetTlsDynamicAddImmediateRegisters(
            moduleAddRelocationType,
            outputAddEncoding,
            out var outputAddSource,
            out var outputAddDestination);
        var targetValid = TryAddSigned(moduleOwnerAddress, addend, out var targetAddress);
        var sourceAddAddressValid = TryAdd(sourceAdrAddress, sizeof(uint), out var sourceAddAddress);
        var outputAddAddressValid = TryAdd(outputAdrAddress, sizeof(uint), out var outputAddAddress);
        if (!sourceAdrValid
            || !sourceAddValid
            || sourceAddSource != sourceAdrRegister
            || sourceAddDestination != sourceAdrRegister
            || !outputAdrValid
            || !outputAddValid
            || outputAddSource != outputAdrRegister
            || outputAddDestination != outputAdrRegister
            || !targetValid
            || !sourceAddAddressValid
            || !outputAddAddressValid)
        {
            return false;
        }

        var encodedAdrp = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceAdrEncoding,
            sourceAdrAddress,
            outputAdrAddress,
            Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            targetAddress,
            OutputTemplateEncoding: outputAdrEncoding));
        if (!encodedAdrp.IsSuccess)
        {
            return false;
        }

        var low12 = targetAddress & 0xFFFUL;
        var encodedAddResult = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceAddEncoding,
            sourceAddAddress,
            outputAddAddress,
            Aarch64InstructionEncodingFamily.AddImmediate,
            low12,
            OutputTemplateEncoding: outputAddEncoding));
        if (!encodedAddResult.IsSuccess)
        {
            return false;
        }

        encodedAdr = encodedAdrp.Encoding;
        encodedAdd = encodedAddResult.Encoding;
        return true;
    }

    public static bool TryEncodeLocalDynamicDtprel(
        uint relocationType,
        uint sourceEncoding,
        uint outputEncoding,
        ulong sourceAddress,
        ulong outputAddress,
        out uint encoded)
    {
        encoded = 0;
        if (relocationType is not (
                ElfConstants.RArm64TlsLdAddDtprelHi12
                or ElfConstants.RArm64TlsLdAddDtprelLo12
                or ElfConstants.RArm64TlsLdAddDtprelLo12Nc)
            || !TryGetTlsDynamicAddImmediateRegisters(
                relocationType,
                sourceEncoding,
                out var sourceRegister,
                out var sourceDestination)
            || !TryGetTlsDynamicAddImmediateRegisters(
                relocationType,
                outputEncoding,
                out var outputRegister,
                out var outputDestination)
            || sourceRegister == 31
            || sourceDestination == 31
            || outputRegister == 31
            || outputDestination == 31)
        {
            return false;
        }

        var result = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceEncoding,
            sourceAddress,
            outputAddress,
            Aarch64InstructionEncodingFamily.AddImmediate,
            TargetOrImmediate: 0,
            OutputTemplateEncoding: outputEncoding,
            PreserveSourceImmediate: true));
        if (!result.IsSuccess)
        {
            return false;
        }

        encoded = result.Encoding;
        return true;
    }

    public static bool TryEncodeLocalDynamicResolverCall(
        uint sourceEncoding,
        uint outputEncoding,
        ulong sourceAddress,
        ulong outputAddress,
        out uint encoded)
    {
        encoded = 0;
        var source = new AsmStoneAdapter().Decode(sourceEncoding, sourceAddress);
        if (!source.IsSuccess
            || source.Instruction?.ControlFlow != Aarch64ControlFlowKind.DirectCall
            || source.Instruction.DirectTarget is not { } targetAddress)
        {
            return false;
        }

        var result = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceEncoding,
            sourceAddress,
            outputAddress,
            Aarch64InstructionEncodingFamily.Call26,
            targetAddress,
            OutputTemplateEncoding: outputEncoding));
        if (!result.IsSuccess)
        {
            return false;
        }

        encoded = result.Encoding;
        return true;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        if (right > ulong.MaxValue - left)
        {
            result = 0;
            return false;
        }

        result = left + right;
        return true;
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

    /// <summary>
    /// Validates the exact TLSIE ADRP/LD64 GOTTPREL sequence emitted by GNU
    /// AArch64 toolchains. Relocatable source records may have a zero low-12
    /// field; linked retained-reloc records may carry the resolved GOT low-12
    /// field, which is checked against the preserved GOT owner when available.
    /// </summary>
    public static bool IsSupportedInitialExecAdrLd64Pair(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        TlsGotEntryBinding? gotEntry = null)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateInitialExecAdrLd64PairRelocations(relocationSites, out var firstAddress, out var secondAddress))
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
        return firstIndex >= 0
            && secondIndex == firstIndex + 1
            && IsSupportedInitialExecAdrLd64Sequence(
                instructions.Select(instruction => instruction.Encoding).ToArray(),
                firstIndex,
                requireSourceLow12Zero: gotEntry is null)
            && (gotEntry is null || IsResolvedInitialExecGotLow12(
                instructions[firstIndex].Encoding,
                instructions[secondIndex].Encoding,
                firstAddress.Value,
                gotEntry.SourceRange.VirtualAddress.Value,
                relocationSites[0].Binding.Addend));
    }

    /// <summary>Validates the canonical TLSIE ADRP/LD64 sequence after projection.</summary>
    public static bool IsSupportedInitialExecAdrLd64Pair(
        IReadOnlyList<TlsInstructionRecord> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        TlsGotEntryBinding? gotEntry = null)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (!TryValidateInitialExecAdrLd64PairRelocations(relocationSites, out var firstAddress, out var secondAddress))
        {
            return false;
        }

        var firstIndex = FindInstructionIndex(instructions, firstAddress);
        var secondIndex = FindInstructionIndex(instructions, secondAddress);
        return firstIndex >= 0
            && secondIndex == firstIndex + 1
            && IsSupportedInitialExecAdrLd64Sequence(
                instructions.Select(instruction => instruction.Encoding).ToArray(),
                firstIndex,
                requireSourceLow12Zero: gotEntry is null)
            && (gotEntry is null || IsResolvedInitialExecGotLow12(
                instructions[firstIndex].Encoding,
                instructions[secondIndex].Encoding,
                firstAddress.Value,
                gotEntry.SourceRange.VirtualAddress.Value,
                relocationSites[0].Binding.Addend))
            && instructions.Count(item => item.Role == TlsInstructionRole.TlsMemoryAccess) == 1
            && instructions.Count(item => item.Role == TlsInstructionRole.GotEntryLoad) == 1;
    }

    /// <summary>
    /// Validates the raw TLSIE ADRP/LD64 chain at a pair-relative instruction index.
    /// </summary>
    private static bool IsResolvedInitialExecGotLow12(
        uint adrpEncoding,
        uint ldEncoding,
        ulong adrpAddress,
        ulong gotAddress,
        long addend)
    {
        if (!TryGetInitialExecLd64GotRegisters(ldEncoding, out _, out _, out var low12)
            || low12 == 0
            || !TryAddSigned(gotAddress, addend, out var targetAddress)
            || targetAddress % sizeof(ulong) != 0)
        {
            return low12 == 0;
        }

        var decoded = new AsmStoneAdapter().Decode(adrpEncoding, adrpAddress);
        return decoded.IsSuccess
            && decoded.Instruction?.DirectTarget is { } pageTarget
            && (pageTarget & ~0xFFFUL) == (targetAddress & ~0xFFFUL)
            && low12 == (targetAddress & 0xFFF);
    }

    public static bool IsSupportedInitialExecAdrLd64Sequence(
        IReadOnlyList<uint> encodings,
        int pairIndex,
        bool requireSourceLow12Zero = false)
    {
        ArgumentNullException.ThrowIfNull(encodings);
        if (pairIndex < 0 || pairIndex > encodings.Count - 5
            || !TryGetInitialExecAdrRegister(encodings[pairIndex], out var adrRegister)
            || !TryGetInitialExecLd64GotRegisters(
                encodings[pairIndex + 1],
                out var gotBaseRegister,
                out var gotValueRegister,
                out var gotOffset)
            || gotBaseRegister != adrRegister
            || (requireSourceLow12Zero && gotOffset != 0)
            || !TryGetThreadPointerRegister(encodings[pairIndex + 2], out var threadPointerRegister)
            || threadPointerRegister == gotValueRegister)
        {
            return false;
        }

        var hasAddressAdd = TryGetLocalExecAddressRegister(
            encodings[pairIndex + 3],
            threadPointerRegister,
            gotValueRegister,
            out var tlsAddressRegister);
        var hasRegisterOffsetAccess = TryGetInitialExecRegisterOffsetAccess(
            encodings[pairIndex + 3],
            threadPointerRegister,
            gotValueRegister,
            out _);
        if (!hasAddressAdd && !hasRegisterOffsetAccess)
        {
            return false;
        }

        if (!IsLoadStoreEncoding(encodings[pairIndex + 1]))
        {
            return false;
        }

        if (hasRegisterOffsetAccess)
        {
            return IsLoadStoreEncoding(encodings[pairIndex + 3]);
        }

        return IsLoadStoreEncoding(encodings[pairIndex + 4])
            && TryGetInitialExecTlsAccessRegisters(
                encodings[pairIndex + 4],
                out var tlsBaseRegister,
                out _)
            && tlsBaseRegister == tlsAddressRegister;
    }

    private static bool TryGetInitialExecRegisterOffsetAccess(
        uint encoding,
        byte threadPointerRegister,
        byte gotValueRegister,
        out byte destinationRegister)
    {
        destinationRegister = 0;
        var decoded = new AsmStoneAdapter().Decode(encoding, 0);
        if (!decoded.IsSuccess || decoded.Instruction is null
            || !string.Equals(decoded.Instruction.Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var memory = GetMemory(decoded.Instruction);
        var output = decoded.Instruction.Operands
            .Where(operand => operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput)
            .Select(operand => operand.Register)
            .FirstOrDefault(register => register.HasValue);
        if (memory is not
            {
                Base: { Class: Aarch64RegisterClass.General, Role: Aarch64RegisterRole.None, Width: 64 } baseRegister,
                Index: { } indexRegister,
                Offset: 0,
                AccessSize: 1 or 2 or 4 or 8,
                WritesBack: false
            }
            || baseRegister.Index != threadPointerRegister
            || indexRegister.Class != Aarch64RegisterClass.General
            || indexRegister.Role != Aarch64RegisterRole.None
            || indexRegister.Width != 64
            || indexRegister.Index != gotValueRegister
            || output is not { } valueRegister
            || valueRegister.Class != Aarch64RegisterClass.General
            || valueRegister.Role != Aarch64RegisterRole.None
            || valueRegister.Width is not (32 or 64))
        {
            return false;
        }

        destinationRegister = valueRegister.Index;
        return destinationRegister != 31;
    }

    /// <summary>
    /// Validates the standalone TLSIE literal-load sequence emitted by GNU AArch64.
    /// The literal load targets the preserved GOT TPREL64 owner, then the loaded
    /// offset is combined with TP before the final scalar TLS access.
    /// </summary>
    public static bool IsSupportedInitialExecLdGotPrel19Pair(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (relocationSites.Count != 1
            || relocationSites[0] is null
            || relocationSites[0].PairOrdinal != 0
            || relocationSites[0].Binding.RelocationType != ElfConstants.RArm64TlsIeLdGottprelPrel19)
        {
            return false;
        }

        var index = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceVirtualAddress == relocationSites[0].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        return index >= 0
            && IsSupportedInitialExecLdGotPrel19Sequence(
                instructions.Select(instruction => instruction.Encoding).ToArray(),
                index,
                requireZeroSourceImmediate: true)
            && instructions
                .Select((instruction, instructionIndex) => (instruction, instructionIndex))
                .Where(item => item.instructionIndex != index)
                .Count(item => IsMemoryInstruction(item.instruction)) == 1;
    }

    public static bool IsSupportedInitialExecLdGotPrel19Pair(
        IReadOnlyList<TlsInstructionRecord> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        if (relocationSites.Count != 1
            || relocationSites[0] is null
            || relocationSites[0].PairOrdinal != 0
            || relocationSites[0].Binding.RelocationType != ElfConstants.RArm64TlsIeLdGottprelPrel19)
        {
            return false;
        }

        var index = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.SourceRange.VirtualAddress == relocationSites[0].SourceRange.VirtualAddress)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        return index >= 0
            && IsSupportedInitialExecLdGotPrel19Sequence(
                instructions.Select(instruction => instruction.Encoding).ToArray(),
                index,
                requireZeroSourceImmediate: true)
            && instructions.Count(item => item.Role == TlsInstructionRole.GotEntryLoad) == 1
            && instructions.Count(item => item.Role == TlsInstructionRole.TlsMemoryAccess) == 1;
    }

    /// <summary>Validates the standalone TLSIE literal-load chain at a sequence index.</summary>
    public static bool IsSupportedInitialExecLdGotPrel19Sequence(
        IReadOnlyList<uint> encodings,
        int loadIndex,
        bool requireZeroSourceImmediate = false)
    {
        ArgumentNullException.ThrowIfNull(encodings);
        return loadIndex >= 0
            && loadIndex <= encodings.Count - 4
            && (!requireZeroSourceImmediate || (encodings[loadIndex] & (0x7FFFFu << 5)) == 0)
            && TryGetInitialExecLdGotPrel19Register(encodings[loadIndex], out var gotValueRegister)
            && TryGetThreadPointerRegister(encodings[loadIndex + 1], out var threadPointerRegister)
            && threadPointerRegister != gotValueRegister
            && TryGetLocalExecAddressRegister(
                encodings[loadIndex + 2],
                threadPointerRegister,
                gotValueRegister,
                out var tlsAddressRegister)
            && TryGetInitialExecTlsAccessRegisters(
                encodings[loadIndex + 3],
                out var tlsBaseRegister,
                out _)
            && tlsBaseRegister == tlsAddressRegister
            && IsLoadStoreEncoding(encodings[loadIndex + 3])
            && encodings
                .Select((encoding, index) => (encoding, index))
                .Count(item => IsLoadStoreEncoding(item.encoding)) == 1;
    }

    public static bool IsSupportedTlsDescWordSequence(
        IReadOnlyList<uint> words,
        TlsDescriptorOwnerBinding descriptorOwner,
        ulong sequenceAddress = 0x1000)
    {
        ArgumentNullException.ThrowIfNull(words);
        ArgumentNullException.ThrowIfNull(descriptorOwner);
        if (words.Count < 8
            || descriptorOwner.DescriptorRange.Size != 2 * sizeof(ulong)
            || descriptorOwner.DescriptorRange.FileOffset.Value % sizeof(ulong) != 0
            || descriptorOwner.DescriptorRange.VirtualAddress.Value % sizeof(ulong) != 0
            || descriptorOwner.Relocation.Kind != Aarch64RelocationKind.ThreadLocal
            || descriptorOwner.Relocation.RelocationType != ElfConstants.RArm64TlsDesc
            || descriptorOwner.Relocation.Addend != 0
            || descriptorOwner.Addend != 0
            || descriptorOwner.ResolverPltRange.Size != 6 * sizeof(uint)
            || descriptorOwner.ResolverGotRange.Size != sizeof(ulong)
            || descriptorOwner.DescriptorPlt != descriptorOwner.ResolverPltRange.VirtualAddress
            || descriptorOwner.DescriptorGot != descriptorOwner.ResolverGotRange.VirtualAddress
            || sequenceAddress > ulong.MaxValue - (7 * sizeof(uint)))
        {
            return false;
        }

        var adapter = new AsmStoneAdapter();
        var decoded = words
            .Select((word, index) => adapter.Decode(word, sequenceAddress + ((ulong)index * sizeof(uint))))
            .ToArray();
        if (decoded.Any(result => !result.IsSuccess))
        {
            return false;
        }

        var instructions = decoded.Select(result => result.Instruction!).ToArray();
        var returnIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.ControlFlow == Aarch64ControlFlowKind.Return)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .Last();
        var loadMemory = GetMemory(instructions[1]);
        var accessMemory = GetMemory(instructions[6]);
        var descriptorAddress = descriptorOwner.DescriptorRange.VirtualAddress.Value;
        var descriptorLow12 = descriptorAddress & 0xFFFUL;
        return returnIndex >= 7
            && returnIndex == instructions.Length - 1
            && instructions
                .Skip(7)
                .Take(returnIndex - 7)
                .All(instruction => instruction.ControlFlow == Aarch64ControlFlowKind.None)
            && string.Equals(instructions[0].Mnemonic, "adrp", StringComparison.OrdinalIgnoreCase)
            && HasRegister(instructions[0], Aarch64OperandDirection.Output, 0, 64)
            && instructions[0].DirectTarget is { } adrpTarget
            && (adrpTarget & ~0xFFFUL) == (descriptorAddress & ~0xFFFUL)
            && string.Equals(instructions[1].Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
            && HasRegister(instructions[1], Aarch64OperandDirection.Output, 1, 64)
            && loadMemory is { Base: { Class: Aarch64RegisterClass.General, Index: 0, Width: 64 }, AccessSize: 8, Index: null, WritesBack: false }
            && loadMemory.Offset == checked((long)descriptorLow12)
            && string.Equals(instructions[2].Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
            && HasRegister(instructions[2], Aarch64OperandDirection.Input, 0, 64)
            && HasRegister(instructions[2], Aarch64OperandDirection.Output, 0, 64)
            && GetImmediate(instructions[2]) == checked((long)descriptorLow12)
            && IsTlsDescCall(instructions[3])
            && IsThreadPointerMrs(words[4])
            && HasRegister(instructions[4], Aarch64OperandDirection.Output, 1, 64)
            && string.Equals(instructions[5].Mnemonic, "add", StringComparison.OrdinalIgnoreCase)
            && HasRegister(instructions[5], Aarch64OperandDirection.Input, 0, 64)
            && HasRegister(instructions[5], Aarch64OperandDirection.Input, 1, 64)
            && HasRegister(instructions[5], Aarch64OperandDirection.Output, 0, 64)
            && accessMemory is { Base: { Class: Aarch64RegisterClass.General, Index: 0, Width: 64 }, Index: null, AccessSize: 1 or 2 or 4 or 8, WritesBack: false }
            && string.Equals(instructions[6].Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsThreadPointerMrs(uint encoding) =>
        (encoding & ThreadPointerMrsMask) == ThreadPointerMrsEncoding;

    public static bool IsSupportedTlsDescRecordSequence(
        IReadOnlyList<TlsInstructionRecord> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        TlsDescriptorOwnerBinding descriptorOwner)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        ArgumentNullException.ThrowIfNull(descriptorOwner);
        if (instructions.Count < 8
            || relocationSites.Count != 4
            || descriptorOwner.DescriptorRange.Size != 2 * sizeof(ulong))
        {
            return false;
        }

        var orderedSites = relocationSites.OrderBy(site => site.PairOrdinal).ToArray();
        var siteIndices = orderedSites
            .Select(site => instructions
                .Select((instruction, index) => (instruction, index))
                .Where(item => item.instruction.SourceRange.VirtualAddress == site.SourceRange.VirtualAddress)
                .Select(item => item.index)
                .DefaultIfEmpty(-1)
                .First())
            .ToArray();
        var coreIndex = siteIndices.Length == 0 ? -1 : siteIndices[0];
        var returnIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Mnemonic.Equals("ret", StringComparison.OrdinalIgnoreCase))
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .Last();
        return coreIndex >= 0
            && coreIndex <= instructions.Count - 8
            && siteIndices.Length == 4
            && siteIndices.All(index => index >= coreIndex && index < coreIndex + 4)
            && siteIndices.Select((index, ordinal) => index == coreIndex + ordinal).All(value => value)
            && returnIndex == instructions.Count - 1
            && orderedSites.Select(site => site.PairOrdinal).SequenceEqual(TlsDescPairOrdinals)
            && orderedSites.Select(site => site.Binding.RelocationType).SequenceEqual(TlsDescRelocationOrder.Select(type => (uint?)type))
            && orderedSites.Zip(orderedSites.Skip(1)).All(pair => IsAdjacentTlsSites(pair.First, pair.Second))
            && instructions[coreIndex].Role == TlsInstructionRole.AddressFormation
            && instructions[coreIndex + 1].Role == TlsInstructionRole.DescriptorLoad
            && instructions[coreIndex + 2].Role == TlsInstructionRole.AddressFormation
            && instructions[coreIndex + 3].Role == TlsInstructionRole.DescriptorCall
            && instructions[coreIndex + 4].Role == TlsInstructionRole.ThreadPointerRead
            && instructions[coreIndex + 5].Role == TlsInstructionRole.AddressFinalization
            && instructions[coreIndex + 6].Role == TlsInstructionRole.TlsMemoryAccess
            && instructions.Skip(coreIndex + 7).Take(returnIndex - (coreIndex + 7)).All(instruction =>
                instruction.Role == TlsInstructionRole.SequencePreservation)
            && instructions[coreIndex + 1].OutputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 1, Width: 64 })
            && instructions[coreIndex + 1].InputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 0, Width: 64 })
            && instructions[coreIndex + 3].IsCall
            && instructions[coreIndex + 3].InputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 1, Width: 64 })
            && instructions[coreIndex + 4].OutputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 1, Width: 64 })
            && instructions[coreIndex + 5].OutputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 0, Width: 64 })
            && instructions[coreIndex + 5].InputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 1, Width: 64 })
            && instructions[coreIndex + 5].InputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 0, Width: 64 })
            && instructions[coreIndex + 6].InputRegisters.Any(register => register is { Class: Aarch64RegisterClass.General, Index: 0, Width: 64 });
    }


    public static bool TryEncodeInitialExecLdGotPrel19(
        uint sourceEncoding,
        uint outputEncoding,
        ulong outputAddress,
        ulong gotAddress,
        long addend,
        out uint encoded)
    {
        encoded = 0;
        if (!TryGetInitialExecLdGotPrel19Register(sourceEncoding, out _)
            || !TryGetInitialExecLdGotPrel19Register(outputEncoding, out _)
            || (sourceEncoding & (0x7FFFFu << 5)) != 0
            || outputAddress % sizeof(uint) != 0
            || !TryAddSigned(gotAddress, addend, out var targetAddress)
            || targetAddress % sizeof(uint) != 0
            || !TryGetScaledSignedImmediate(targetAddress, outputAddress, sizeof(uint), 19, out _))
        {
            return false;
        }

        var result = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceEncoding,
            outputAddress,
            outputAddress,
            Aarch64InstructionEncodingFamily.Literal19,
            targetAddress,
            OutputTemplateEncoding: outputEncoding));
        if (!result.IsSuccess)
        {
            return false;
        }

        encoded = result.Encoding;
        return true;
    }

    public static bool TryGetInitialExecLdGotPrel19Register(uint encoding, out byte register)
    {
        register = 0;
        if ((encoding & LdGotPrel19OpcodeMask) != LdGotPrel19Opcode)
        {
            return false;
        }

        register = (byte)(encoding & 0x1F);
        return register != 31;
    }

    public static bool TryGetInitialExecLdGotPrel19Relocation(
        uint relocationType,
        ulong address,
        int pairOrdinal) =>
        relocationType == ElfConstants.RArm64TlsIeLdGottprelPrel19
        && pairOrdinal == 0
        && address % sizeof(uint) == 0
        && address <= ulong.MaxValue - sizeof(uint);


    public static bool IsSupportedInitialExecRelocationInstruction(uint relocationType, uint encoding) =>
        relocationType switch
        {
            ElfConstants.RArm64TlsIeMovwGottprelG1 => TryGetInitialExecMovwRegister(relocationType, encoding, out _),
            ElfConstants.RArm64TlsIeMovwGottprelG0Nc => TryGetInitialExecMovwRegister(relocationType, encoding, out _),
            ElfConstants.RArm64TlsIeAdrGottprelPage21 => TryGetInitialExecAdrRegister(encoding, out _),
            ElfConstants.RArm64TlsIeLd64GottprelLo12Nc => TryGetInitialExecLd64GotRegisters(
                encoding,
                out _,
                out _,
                out _),
            ElfConstants.RArm64TlsIeLdGottprelPrel19 => TryGetInitialExecLdGotPrel19Register(
                encoding,
                out _),
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

    public static bool TryGetInitialExecAdrRegister(uint encoding, out byte register)
    {
        register = 0;
        if ((encoding & AdrpOpcodeMask) != AdrpOpcode)
        {
            return false;
        }

        register = (byte)(encoding & 0x1F);
        return register != 31;
    }

    public static bool TryGetInitialExecLd64GotRegisters(
        uint encoding,
        out byte baseRegister,
        out byte valueRegister,
        out uint low12Offset)
    {
        baseRegister = 0;
        valueRegister = 0;
        low12Offset = 0;
        if ((encoding & Ld64UnsignedOpcodeMask) != Ld64UnsignedOpcode)
        {
            return false;
        }

        baseRegister = (byte)((encoding >> 5) & 0x1F);
        valueRegister = (byte)(encoding & 0x1F);
        low12Offset = ((encoding >> 10) & 0xFFFu) * sizeof(ulong);
        return baseRegister != 31 && valueRegister != 31;
    }

    /// <summary>
    /// Encodes the output words for the bounded TLSIE ADRP/LD64 pair. The ADRP
    /// points at the source-preserved GOT owner and the LD64 carries its scaled
    /// low-12 field; register/opcode ownership remains output-owned.
    /// </summary>
    public static bool TryEncodeInitialExecAdrLd64Pair(
        uint sourceAdrEncoding,
        uint sourceLdEncoding,
        uint outputAdrEncoding,
        uint outputLdEncoding,
        ulong outputAdrAddress,
        ulong gotAddress,
        long addend,
        out uint encodedAdr,
        out uint encodedLd)
    {
        encodedAdr = 0;
        encodedLd = 0;
        if (!TryGetInitialExecAdrRegister(sourceAdrEncoding, out var sourceAdrRegister)
            || !TryGetInitialExecLd64GotRegisters(
                sourceLdEncoding,
                out var sourceLdBase,
                out _,
                out var sourceLdOffset)
            || sourceAdrRegister != sourceLdBase)
        {
            return false;
        }

        if (!TryGetInitialExecAdrRegister(outputAdrEncoding, out var outputAdrRegister)
            || !TryGetInitialExecLd64GotRegisters(
                outputLdEncoding,
                out var outputLdBase,
                out _,
                out _)
            || outputAdrRegister != outputLdBase)
        {
            return false;
        }

        if (!TryAddSigned(gotAddress, addend, out var targetAddress)
            || !TryGetPageImmediate(targetAddress, outputAdrAddress, out _)
            || targetAddress % sizeof(ulong) != 0)
        {
            return false;
        }

        var low12 = targetAddress & 0xFFF;
        if (low12 % sizeof(ulong) != 0 || low12 / sizeof(ulong) > 0xFFF)
        {
            return false;
        }

        var encodedAdrResult = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceAdrEncoding,
            outputAdrAddress,
            outputAdrAddress,
            Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            targetAddress,
            OutputTemplateEncoding: outputAdrEncoding));
        if (!encodedAdrResult.IsSuccess)
        {
            return false;
        }

        var encodedLdResult = InstructionEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceLdEncoding,
            checked(outputAdrAddress + sizeof(uint)),
            checked(outputAdrAddress + sizeof(uint)),
            Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
            low12,
            AccessWidth: 64,
            OutputTemplateEncoding: outputLdEncoding));
        if (!encodedLdResult.IsSuccess)
        {
            return false;
        }

        encodedAdr = encodedAdrResult.Encoding;
        encodedLd = encodedLdResult.Encoding;
        return true;
    }

    public static bool TryGetInitialExecAdrLd64PairRelocation(
        uint firstType,
        uint secondType,
        ulong firstAddress,
        ulong secondAddress,
        long firstAddend,
        long secondAddend) =>
        firstType == ElfConstants.RArm64TlsIeAdrGottprelPage21
        && secondType == ElfConstants.RArm64TlsIeLd64GottprelLo12Nc
        && firstAddress <= ulong.MaxValue - sizeof(uint)
        && secondAddress == firstAddress + sizeof(uint)
        && firstAddend == secondAddend;
    public static bool IsSupportedInitialExecAdrLd64EmitterSequence(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        IReadOnlyList<TlsRelocationFacts> relocationFacts)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationFacts);
        var ordered = relocationFacts
            .Where(fact => fact.Relocation.Type is
                ElfConstants.RArm64TlsIeAdrGottprelPage21
                or ElfConstants.RArm64TlsIeLd64GottprelLo12Nc)
            .OrderBy(fact => fact.Relocation.Offset)
            .ToArray();
        if (ordered.Length != 2
            || ordered[0].Symbol is null
            || ordered[1].Symbol is null
            || ordered[0].Symbol!.SymbolIndex != ordered[1].Symbol!.SymbolIndex
            || !string.Equals(ordered[0].Symbol!.Name, ordered[1].Symbol!.Name, StringComparison.Ordinal)
            || !TryGetInitialExecAdrLd64PairRelocation(
                ordered[0].Relocation.Type,
                ordered[1].Relocation.Type,
                ordered[0].Relocation.Offset,
                ordered[1].Relocation.Offset,
                ordered[0].Relocation.Addend,
                ordered[1].Relocation.Addend))
        {
            return false;
        }

        var firstIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Address == ordered[0].Relocation.Offset)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        return firstIndex >= 0
            && IsSupportedInitialExecAdrLd64Sequence(
                instructions.Select(instruction => instruction.Encoding).ToArray(),
                firstIndex,
                requireSourceLow12Zero: false);
    }

    public static bool IsSupportedInitialExecLdGotPrel19EmitterSequence(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        IReadOnlyList<TlsRelocationFacts> relocationFacts)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationFacts);
        var relocations = relocationFacts
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsIeLdGottprelPrel19)
            .ToArray();
        if (relocations.Length != 1
            || relocations[0].Symbol is null
            || !TryGetInitialExecLdGotPrel19Relocation(
                relocations[0].Relocation.Type,
                relocations[0].Relocation.Offset,
                pairOrdinal: 0))
        {
            return false;
        }

        var instructionIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Address == relocations[0].Relocation.Offset)
            .Select(item => item.index)
            .DefaultIfEmpty(-1)
            .First();
        return instructionIndex >= 0
            && IsSupportedInitialExecLdGotPrel19Sequence(
                instructions.Select(instruction => instruction.Encoding).ToArray(),
                instructionIndex,
                requireZeroSourceImmediate: true);
    }
    private static bool TryValidateInitialExecAdrLd64PairRelocations(
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
            || relocationSites[0].Binding.RelocationType != ElfConstants.RArm64TlsIeAdrGottprelPage21
            || relocationSites[1].Binding.RelocationType != ElfConstants.RArm64TlsIeLd64GottprelLo12Nc
            || relocationSites[0].Binding.SymbolIndex != relocationSites[1].Binding.SymbolIndex
            || !string.Equals(
                relocationSites[0].Binding.SymbolName,
                relocationSites[1].Binding.SymbolName,
                StringComparison.Ordinal)
            || !TryGetInitialExecAdrLd64PairRelocation(
                relocationSites[0].Binding.RelocationType!.Value,
                relocationSites[1].Binding.RelocationType!.Value,
                relocationSites[0].SourceRange.VirtualAddress.Value,
                relocationSites[1].SourceRange.VirtualAddress.Value,
                relocationSites[0].Binding.Addend,
                relocationSites[1].Binding.Addend)
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

    private static bool IsLoadStoreEncoding(uint encoding) =>
        (encoding & 0x3FC0_0000u) is
            0x3900_0000u or 0x3940_0000u
            or 0x7900_0000u or 0x7940_0000u
            or 0xB900_0000u or 0xB940_0000u
            or 0xF900_0000u or 0xF940_0000u
            or 0x3840_0000u or 0x7840_0000u
            or 0xB840_0000u or 0xF840_0000u;

    private static bool IsMemoryInstruction(SemanticInstruction instruction) =>
        instruction.Operands.Any(operand => operand.Memory is not null)
        || instruction.Mnemonic.StartsWith("ldr", StringComparison.OrdinalIgnoreCase)
        || instruction.Mnemonic.StartsWith("str", StringComparison.OrdinalIgnoreCase);
    private static bool TryGetScaledSignedImmediate(
        ulong target,
        ulong place,
        ulong scale,
        int width,
        out long immediate)
    {
        immediate = default;
        if (scale == 0 || width <= 0 || width >= 63)
        {
            return false;
        }

        long delta;
        if (target >= place)
        {
            var positive = target - place;
            if (positive > long.MaxValue)
            {
                return false;
            }

            delta = (long)positive;
        }
        else
        {
            var negative = place - target;
            if (negative > (1UL << 63))
            {
                return false;
            }

            delta = negative == (1UL << 63)
                ? long.MinValue
                : -(long)negative;
        }

        if (delta % (long)scale != 0)
        {
            return false;
        }

        var scaled = delta / (long)scale;
        var minimum = -(1L << (width - 1));
        var maximum = (1L << (width - 1)) - 1;
        if (scaled < minimum || scaled > maximum)
        {
            return false;
        }

        immediate = scaled;
        return true;
    }

    private static bool TryGetPageImmediate(ulong target, ulong place, out long immediate)
    {
        var targetPage = target & ~0xFFFUL;
        var placePage = place & ~0xFFFUL;
        if (targetPage >= placePage)
        {
            var delta = targetPage - placePage;
            if (delta % 0x1000 != 0 || delta / 0x1000 > (ulong)((1L << 20) - 1))
            {
                immediate = default;
                return false;
            }

            immediate = (long)(delta / 0x1000);
            return true;
        }

        var reverse = placePage - targetPage;
        if (reverse % 0x1000 != 0 || reverse / 0x1000 > (ulong)(1L << 20))
        {
            immediate = default;
            return false;
        }

        immediate = -(long)(reverse / 0x1000);
        return true;
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

    private static bool IsAdjacentTlsSites(TlsRelocationSite first, TlsRelocationSite second) =>
        first.SourceRange.Size == sizeof(uint)
        && second.SourceRange.Size == sizeof(uint)
        && first.SourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
        && first.SourceRange.FileOffset.Value <= ulong.MaxValue - sizeof(uint)
        && second.SourceRange.VirtualAddress.Value == first.SourceRange.VirtualAddress.Value + sizeof(uint)
        && second.SourceRange.FileOffset.Value == first.SourceRange.FileOffset.Value + sizeof(uint);

    private static bool TryGetTlsDynamicAddImmediateRegisters(
        uint relocationType,
        uint encoding,
        out byte sourceRegister,
        out byte destinationRegister)
    {
        sourceRegister = 0;
        destinationRegister = 0;
        var expectedShift = relocationType switch
        {
            ElfConstants.RArm64TlsLdAddLo12Nc
                or ElfConstants.RArm64TlsGdAddLo12Nc
                or ElfConstants.RArm64TlsLdAddDtprelLo12
                or ElfConstants.RArm64TlsLdAddDtprelLo12Nc => 0u,
            ElfConstants.RArm64TlsLdAddDtprelHi12 => 1u,
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

    private static bool IsDirectTlsResolverCall(SemanticInstruction instruction) =>
        string.Equals(instruction.Mnemonic, "bl", StringComparison.OrdinalIgnoreCase)
        && instruction.ControlFlow == Aarch64ControlFlowKind.DirectCall;

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

    private static int FindInstructionIndex(
        IReadOnlyList<TlsInstructionRecord> instructions,
        VirtualAddress address) => instructions
        .Select((instruction, index) => (instruction, index))
        .Where(item => item.instruction.SourceRange.VirtualAddress == address)
        .Select(item => item.index)
        .DefaultIfEmpty(-1)
        .First();
}
