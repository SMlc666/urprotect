using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>
/// Exact bounded GNU version-need row associated with one dynamic symbol.
/// The raw version index remains separate because its hidden bit is part of
/// the symbol-version-table identity.
/// </summary>
public sealed record SemanticDynamicImportVersionRequirement(
    ushort RecordVersion,
    ushort AuxiliaryCount,
    uint FileNameOffset,
    uint AuxiliaryOffset,
    uint NextOffset,
    string FileName,
    uint Hash,
    ushort Flags,
    ushort Other,
    uint NameOffset,
    string Name);

/// <summary>
/// The typed owner relation for one selected BLR through a dynamic-import GOT
/// slot. It is semantic evidence, not a proof-string or free-form binding.
/// </summary>
public sealed record SemanticDynamicImportCallExtension : ISemanticPlanExtension
{
    public SemanticDynamicImportCallExtension(
        SemanticEntityId callIdentity,
        VirtualAddress callAddress,
        Aarch64RegisterView targetRegister,
        IEnumerable<VirtualAddress> producerAddresses,
        VirtualAddress pageProducerAddress,
        VirtualAddress loadProducerAddress,
        VirtualAddress pageAddress,
        SemanticSourceRange gotRange,
        SemanticEntityId relocationSiteIdentity,
        ulong relocationOffset,
        ulong relocationInfo,
        long relocationAddend,
        bool relocationIsPlt,
        VirtualAddress relocationTableAddress,
        uint symbolIndex,
        uint symbolNameOffset,
        string symbolName,
        byte symbolInfo,
        byte symbolOther,
        byte symbolBinding,
        byte symbolType,
        byte symbolVisibility,
        ushort symbolSectionIndex,
        ulong symbolValue,
        ulong symbolSize,
        ushort? symbolVersionIndexRaw = null,
        SemanticDynamicImportVersionRequirement? versionRequirement = null)
    {
        ArgumentNullException.ThrowIfNull(producerAddresses);
        ArgumentException.ThrowIfNullOrWhiteSpace(symbolName);
        CallIdentity = callIdentity;
        CallAddress = callAddress;
        TargetRegister = targetRegister;
        ProducerAddresses = Array.AsReadOnly(producerAddresses.ToArray());
        PageProducerAddress = pageProducerAddress;
        LoadProducerAddress = loadProducerAddress;
        PageAddress = pageAddress;
        GotRange = gotRange;
        RelocationSiteIdentity = relocationSiteIdentity;
        RelocationOffset = relocationOffset;
        RelocationInfo = relocationInfo;
        RelocationAddend = relocationAddend;
        RelocationIsPlt = relocationIsPlt;
        RelocationTableAddress = relocationTableAddress;
        SymbolIndex = symbolIndex;
        SymbolNameOffset = symbolNameOffset;
        SymbolName = symbolName;
        SymbolInfo = symbolInfo;
        SymbolOther = symbolOther;
        SymbolBinding = symbolBinding;
        SymbolType = symbolType;
        SymbolVisibility = symbolVisibility;
        SymbolSectionIndex = symbolSectionIndex;
        SymbolValue = symbolValue;
        SymbolSize = symbolSize;
        SymbolVersionIndexRaw = symbolVersionIndexRaw;
        VersionRequirement = versionRequirement;
    }

    public SemanticEntityId CallIdentity { get; }

    public VirtualAddress CallAddress { get; }

    public Aarch64RegisterView TargetRegister { get; }

    /// <summary>Complete bounded data-flow producer chain, in canonical address order.</summary>
    public IReadOnlyList<VirtualAddress> ProducerAddresses { get; }

    public VirtualAddress PageProducerAddress { get; }

    public VirtualAddress LoadProducerAddress { get; }

    public VirtualAddress PageAddress { get; }

    public SemanticSourceRange GotRange { get; }

    public SemanticEntityId RelocationSiteIdentity { get; }

    public ulong RelocationOffset { get; }

    public ulong RelocationInfo { get; }

    public long RelocationAddend { get; }

    public bool RelocationIsPlt { get; }

    public VirtualAddress RelocationTableAddress { get; }

    public uint SymbolIndex { get; }

    public uint SymbolNameOffset { get; }

    public string SymbolName { get; }

    public byte SymbolInfo { get; }

    public byte SymbolOther { get; }

    public byte SymbolBinding { get; }

    public byte SymbolType { get; }

    public byte SymbolVisibility { get; }

    public ushort SymbolSectionIndex { get; }

    public ulong SymbolValue { get; }

    public ulong SymbolSize { get; }

    /// <summary>Raw DT_VERSYM value for this exact dynsym index, when a table exists.</summary>
    public ushort? SymbolVersionIndexRaw { get; }

    /// <summary>Exact DT_VERNEED/Vernaux row for this symbol when its version index is greater than one.</summary>
    public SemanticDynamicImportVersionRequirement? VersionRequirement { get; }

    public string RuntimeBinding =>
        $"aarch64:elf-import:{SymbolName}:glob-dat@0x{GotRange.VirtualAddress.Value:X}";

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.DynamicImportCall;
}
