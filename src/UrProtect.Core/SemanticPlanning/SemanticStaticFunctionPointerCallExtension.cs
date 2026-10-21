using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

public enum SemanticStaticFunctionPointerMappingPolicy
{
    PreserveOriginalAddress = 0,
}

/// <summary>
/// A fully typed section-RELA owner for one bounded same-image function-pointer BLR.
/// It is distinct from dynamic-import and runtime-resolved indirect-call owners.
/// </summary>
public sealed record SemanticStaticFunctionPointerCallExtension : ISemanticPlanExtension
{
    public SemanticStaticFunctionPointerCallExtension(
        SemanticEntityId sourceIdentity,
        SemanticSourceRange sourceRange,
        Aarch64RegisterView targetRegister,
        IEnumerable<VirtualAddress> producerAddresses,
        long stackSlotOffset,
        ElfFunctionSymbol ownerFunction,
        int relocationSectionIndex,
        SectionHeader relocationSectionHeader,
        uint symbolTableSectionIndex,
        SectionHeader symbolTableSectionHeader,
        SectionHeader callerSectionHeader,
        SectionHeader targetSectionHeader,
        SemanticStaticFunctionPointerRelocationRow adrpRelocation,
        SemanticStaticFunctionPointerRelocationRow addRelocation,
        SemanticSourceRange targetSourceRange,
        SemanticEntityId targetMappingIdentity,
        SemanticSourceRange targetOutputRange,
        SemanticStaticFunctionPointerMappingPolicy mappingPolicy)
    {
        ArgumentNullException.ThrowIfNull(producerAddresses);
        ProducerAddresses = Array.AsReadOnly(producerAddresses.ToArray());
        SourceIdentity = sourceIdentity;
        SourceRange = sourceRange;
        TargetRegister = targetRegister;
        StackSlotOffset = stackSlotOffset;
        OwnerFunction = ownerFunction;
        RelocationSectionIndex = relocationSectionIndex;
        RelocationSectionHeader = relocationSectionHeader;
        SymbolTableSectionIndex = symbolTableSectionIndex;
        SymbolTableSectionHeader = symbolTableSectionHeader;
        CallerSectionHeader = callerSectionHeader;
        TargetSectionHeader = targetSectionHeader;
        AdrpRelocation = adrpRelocation;
        AddRelocation = addRelocation;
        TargetSourceRange = targetSourceRange;
        TargetMappingIdentity = targetMappingIdentity;
        TargetOutputRange = targetOutputRange;
        MappingPolicy = mappingPolicy;
    }

    public SemanticEntityId SourceIdentity { get; }

    public SemanticSourceRange SourceRange { get; }

    public VirtualAddress CallAddress => SourceRange.VirtualAddress;

    public Aarch64RegisterView TargetRegister { get; }

    /// <summary>ADRP, ADD, STR, and LDR source sites in execution order.</summary>
    public IReadOnlyList<VirtualAddress> ProducerAddresses { get; }

    public long StackSlotOffset { get; }

    public ElfFunctionSymbol OwnerFunction { get; }

    public int RelocationSectionIndex { get; }

    public SectionHeader RelocationSectionHeader { get; }

    public uint SymbolTableSectionIndex { get; }

    public SectionHeader SymbolTableSectionHeader { get; }

    public SectionHeader CallerSectionHeader { get; }

    public SectionHeader TargetSectionHeader { get; }

    public SemanticStaticFunctionPointerRelocationRow AdrpRelocation { get; }

    public SemanticStaticFunctionPointerRelocationRow AddRelocation { get; }

    public SemanticSourceRange TargetSourceRange { get; }

    public SemanticEntityId TargetMappingIdentity { get; }

    public SemanticSourceRange TargetOutputRange { get; }

    public SemanticStaticFunctionPointerMappingPolicy MappingPolicy { get; }

    public bool HasStructuredProof =>
        SourceIdentity.Kind == SemanticEntityKind.Instruction
        && SourceRange.Size == sizeof(uint)
        && TargetRegister.Class == Aarch64RegisterClass.General
        && TargetRegister.Role == Aarch64RegisterRole.None
        && TargetRegister.Width == 64
        && TargetRegister.Index < 31
        && ProducerAddresses.Count == 4
        && ProducerAddresses.Select(address => address.Value).Distinct().Count() == 4
        && ProducerAddresses.Zip(ProducerAddresses.Skip(1), (left, right) => left.Value < right.Value).All(increasing => increasing)
        && OwnerFunction.Size > 0
        && OwnerFunction.Table == ElfSymbolTableKind.Dynamic
        && RelocationSectionIndex >= 0
        && SymbolTableSectionHeader.Type == ElfConstants.ShtSymTab
        && TargetSourceRange.Size > 0
        && TargetOutputRange == TargetSourceRange
        && TargetMappingIdentity.Kind == SemanticEntityKind.RelocationTarget
        && MappingPolicy == SemanticStaticFunctionPointerMappingPolicy.PreserveOriginalAddress
        && AdrpRelocation.SiteAddress == ProducerAddresses[0].Value
        && AddRelocation.SiteAddress == ProducerAddresses[1].Value
        && AdrpRelocation.RelocationSectionIndex == RelocationSectionIndex
        && AddRelocation.RelocationSectionIndex == RelocationSectionIndex
        && AdrpRelocation.SymbolIndex == AddRelocation.SymbolIndex
        && AdrpRelocation.Name == AddRelocation.Name
        && AdrpRelocation.SymbolValue == AddRelocation.SymbolValue
        && AdrpRelocation.SymbolSize == AddRelocation.SymbolSize
        && AdrpRelocation.SymbolSectionIndex == AddRelocation.SymbolSectionIndex;

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.StaticFunctionPointerCall;
}

public sealed record SemanticStaticFunctionPointerRelocationRow(
    int RelocationSectionIndex,
    FileOffset RelocationSectionFileOffset,
    VirtualAddress RelocationSectionAddress,
    uint SymbolTableSectionIndex,
    uint TargetSectionIndex,
    ulong RelocationSourceAddress,
    ulong SiteAddress,
    ulong Info,
    uint Type,
    uint SymbolIndex,
    long Addend,
    bool IsPlt,
    uint SymbolNameOffset,
    string Name,
    byte SymbolInfo,
    byte SymbolOther,
    ushort SymbolSectionIndex,
    ulong SymbolValue,
    ulong SymbolSize);
