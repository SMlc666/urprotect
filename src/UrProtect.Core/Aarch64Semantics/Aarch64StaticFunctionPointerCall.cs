using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

/// <summary>
/// One exact, section-relocation-owned same-image function-pointer BLR. This
/// is deliberately separate from runtime-owned indirect-call resolutions.
/// </summary>
public sealed record Aarch64StaticFunctionPointerCallResolution
{
    public Aarch64StaticFunctionPointerCallResolution(
        ulong sourceAddress,
        Aarch64RegisterView targetRegister,
        IEnumerable<ulong> producerAddresses,
        long stackSlotOffset,
        ElfFunctionSymbol ownerFunction,
        ElfSectionRelocation adrpRelocation,
        ElfSectionRelocation addRelocation,
        SectionHeader relocationSectionHeader,
        SectionHeader symbolTableSectionHeader,
        SectionHeader callerSectionHeader,
        SectionHeader targetSectionHeader,
        FileOffset targetFileOffset,
        ulong targetAddress,
        ulong targetSize)
    {
        ArgumentNullException.ThrowIfNull(producerAddresses);
        SourceAddress = sourceAddress;
        TargetRegister = targetRegister;
        ProducerAddresses = Array.AsReadOnly(producerAddresses.ToArray());
        StackSlotOffset = stackSlotOffset;
        OwnerFunction = ownerFunction;
        AdrpRelocation = adrpRelocation;
        AddRelocation = addRelocation;
        RelocationSectionHeader = relocationSectionHeader;
        SymbolTableSectionHeader = symbolTableSectionHeader;
        CallerSectionHeader = callerSectionHeader;
        TargetSectionHeader = targetSectionHeader;
        TargetFileOffset = targetFileOffset;
        TargetAddress = targetAddress;
        TargetSize = targetSize;
    }

    public ulong SourceAddress { get; }

    public Aarch64RegisterView TargetRegister { get; }

    /// <summary>ADRP, ADD, STR, and LDR sites in execution order.</summary>
    public IReadOnlyList<ulong> ProducerAddresses { get; }

    public long StackSlotOffset { get; }

    public ElfFunctionSymbol OwnerFunction { get; }

    public ElfSectionRelocation AdrpRelocation { get; }

    public ElfSectionRelocation AddRelocation { get; }

    public SectionHeader RelocationSectionHeader { get; }

    public SectionHeader SymbolTableSectionHeader { get; }

    public SectionHeader CallerSectionHeader { get; }

    public SectionHeader TargetSectionHeader { get; }

    public FileOffset TargetFileOffset { get; }

    public ulong TargetAddress { get; }

    public ulong TargetSize { get; }
}
