using System.Buffers.Binary;
using System.Text;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

public sealed record Aarch64JumpTableEntry(
    int Index,
    int EncodedValue,
    VirtualAddress TargetAddress,
    FileOffset SourceFileOffset,
    VirtualAddress SourceAddress);

public enum Aarch64JumpTableReferenceKind
{
    AdrpPage = 1,
    AddLow12 = 2,
}

public sealed record Aarch64JumpTableReferenceProducer(
    ulong InstructionAddress,
    Aarch64JumpTableReferenceKind Kind);

/// <summary>Static RELA evidence tying one consumer instruction to the resolved table object.</summary>
public sealed record Aarch64JumpTableOwnerReference(
    ulong InstructionAddress,
    int RelocationSectionIndex,
    uint SymbolTableSectionIndex,
    uint TargetSectionIndex,
    uint OwnerFunctionSectionIndex,
    SectionHeader OwnerFunctionSection,
    ulong RelocationSourceAddress,
    uint RelocationType,
    long Addend,
    uint SymbolIndex,
    string SymbolName,
    byte SymbolBinding,
    byte SymbolType,
    byte SymbolVisibility,
    ushort SymbolSectionIndex,
    ulong SymbolValue,
    ulong SymbolSize,
    string OwnerFunctionName,
    ulong OwnerFunctionStart,
    ulong OwnerFunctionSize,
    bool IsSelectedFunction);

public sealed record Aarch64JumpTableResolution
{
    public Aarch64JumpTableResolution(
        ulong sourceAddress,
        VirtualAddress tableBase,
        VirtualAddress targetBaseAddress,
        FileOffset tableFileOffset,
        int entryWidth,
        Aarch64RegisterView indexRegister,
        bool isSigned,
        int scale,
        long addend,
        int lowerBound,
        int upperBound,
        VirtualAddress defaultTargetAddress,
        IEnumerable<Aarch64JumpTableEntry> entries,
        IEnumerable<ulong> producerAddresses,
        IEnumerable<Aarch64JumpTableReferenceProducer> tableReferenceProducers,
        IEnumerable<Aarch64JumpTableOwnerReference> ownerReferences,
        bool hasObservedAdditionalOwner,
        string proof)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(producerAddresses);
        ArgumentNullException.ThrowIfNull(tableReferenceProducers);
        ArgumentNullException.ThrowIfNull(ownerReferences);
        ArgumentException.ThrowIfNullOrWhiteSpace(proof);
        if (entryWidth is not (1 or 2 or 4 or 8))
        {
            throw new ArgumentOutOfRangeException(nameof(entryWidth));
        }

        ArgumentOutOfRangeException.ThrowIfGreaterThan(lowerBound, upperBound, nameof(lowerBound));

        SourceAddress = sourceAddress;
        TableBase = tableBase;
        TargetBaseAddress = targetBaseAddress;
        TableFileOffset = tableFileOffset;
        EntryWidth = entryWidth;
        IndexRegister = indexRegister;
        IsSigned = isSigned;
        Scale = scale;
        Addend = addend;
        LowerBound = lowerBound;
        UpperBound = upperBound;
        DefaultTargetAddress = defaultTargetAddress;
        Entries = Array.AsReadOnly(entries.ToArray());
        ProducerAddresses = Array.AsReadOnly(producerAddresses.ToArray());
        TableReferenceProducers = Array.AsReadOnly(tableReferenceProducers
            .OrderBy(producer => producer.InstructionAddress)
            .ThenBy(producer => producer.Kind)
            .ToArray());
        OwnerReferences = Array.AsReadOnly(ownerReferences
            .OrderBy(reference => reference.InstructionAddress)
            .ThenBy(reference => reference.OwnerFunctionStart)
            .ThenBy(reference => reference.RelocationType)
            .ToArray());
        HasObservedAdditionalOwner = hasObservedAdditionalOwner;
        Proof = proof;
    }

    public ulong SourceAddress { get; }

    public VirtualAddress TableBase { get; }

    public VirtualAddress TargetBaseAddress { get; }

    public FileOffset TableFileOffset { get; }

    public int EntryWidth { get; }

    public Aarch64RegisterView IndexRegister { get; }

    public bool IsSigned { get; }

    public int Scale { get; }

    public long Addend { get; }

    public int LowerBound { get; }

    public int UpperBound { get; }

    public VirtualAddress DefaultTargetAddress { get; }

    public IReadOnlyList<Aarch64JumpTableEntry> Entries { get; }

    public IReadOnlyList<ulong> ProducerAddresses { get; }

    public IReadOnlyList<Aarch64JumpTableReferenceProducer> TableReferenceProducers { get; }

    public IReadOnlyList<Aarch64JumpTableOwnerReference> OwnerReferences { get; }

    /// <summary>True only when retained RELA evidence identifies another function consumer.</summary>
    public bool HasObservedAdditionalOwner { get; }

    public string Proof { get; }

    public ulong TableSize => checked((ulong)Entries.Count * (ulong)EntryWidth);

    public IReadOnlyList<VirtualAddress> TargetAddresses =>
        Entries.Select(entry => entry.TargetAddress).Distinct().ToArray();
}

/// <summary>
/// Resolves the first bounded compiler-shaped relative jump-table family from
/// a selected function. The helper performs only targeted reads named by the
/// producer chain and never scans unrelated executable ranges.
/// </summary>
public static class Aarch64JumpTableResolver
{
    private const ulong InstructionSize = sizeof(uint);
    private const int MaximumTableEntries = 65536;
    private const int MaximumExternalProofInstructions = 65536;
    private const int MaximumExternalProofDynamicEntries = 4096;
    private const int MaximumExternalProofDynamicSymbols = 65536;
    private const int MaximumExternalProofRelocations = 65536;
    private const int MaximumExternalProofStringTableBytes = 8 * 1024 * 1024;
    private const int MaximumSafeDefaultInstructions = 16;
    private static readonly int[] RequiredProviderEntryIndices = { 0, 1, 2, 3 };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static bool TryResolve(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        int branchIndex,
        ulong functionStart,
        ulong functionEnd,
        IReadOnlyDictionary<ulong, Aarch64FunctionInstruction> instructionsByAddress,
        ElfFile file,
        out Aarch64JumpTableResolution? resolution,
        out string failure,
        out bool recognized)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(instructionsByAddress);
        ArgumentNullException.ThrowIfNull(file);

        resolution = null;
        failure = "The selected instruction does not match the promoted relative jump-table family.";
        recognized = false;
        if (branchIndex < 5 || branchIndex >= instructions.Count)
        {
            return false;
        }

        var branch = instructions[branchIndex].Decode.Instruction;
        var addTarget = instructions[branchIndex - 1].Decode.Instruction;
        var adr = instructions[branchIndex - 2].Decode.Instruction;
        var load = instructions[branchIndex - 3].Decode.Instruction;
        var addTable = instructions[branchIndex - 4].Decode.Instruction;
        var adrp = instructions[branchIndex - 5].Decode.Instruction;
        if (branch is null
            || addTarget is null
            || adr is null
            || load is null
            || addTable is null
            || adrp is null
            || !string.Equals(branch.Mnemonic, "br", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!TryGetInputRegister(branch, out var branchRegister)
            || !TryGetOutputRegister(addTarget, out var addTargetRegister)
            || branchRegister != addTargetRegister
            || !TryGetRegisterAdd(addTarget, out var targetBaseRegister, out var loadedRegister)
            || !TryGetOutputRegister(adr, out var adrRegister)
            || !TryGetDirectTarget(adr, out var targetBaseAddress)
            || adrRegister != targetBaseRegister
            || !TryGetOutputRegister(load, out var loadedOutputRegister)
            || loadedRegister != loadedOutputRegister
            || !TryGetIndexedLoad(load, out var tableBaseRegister, out var indexRegister)
            || !TryGetOutputRegister(addTable, out var tableOutputRegister)
            || tableOutputRegister != tableBaseRegister
            || !TryGetImmediateAdd(addTable, tableBaseRegister, out var tableLow12)
            || !TryGetOutputRegister(adrp, out var pageRegister)
            || pageRegister != tableBaseRegister
            || !TryGetDirectTarget(adrp, out var pageAddress))
        {
            return false;
        }

        recognized = true;
        // The CMP/B.HI proof remains valid only while its architectural GPR survives
        // every producer through BR. Wn and Xn are aliases, and the flattened
        // dispatcher consumes the live index at BR rather than the stale CMP value.
        if (loadedOutputRegister.Index == indexRegister.Index
            || targetBaseRegister.Index == indexRegister.Index
            || addTargetRegister.Index == indexRegister.Index)
        {
            failure = "The bounded jump-table index is overwritten between CMP/B.HI and BR.";
            return false;
        }

        if (loadedOutputRegister.Index == targetBaseRegister.Index)
        {
            failure = "The relative jump-table target-base ADR overwrites the loaded signed displacement.";
            return false;
        }

        var dispatchStart = branchIndex - 5;
        if (!TryGetBoundedUnsignedSwitch(
                instructions,
                dispatchStart,
                indexRegister,
                functionStart,
                functionEnd,
                out var lowerBound,
                out var upperBound,
                out var defaultTarget,
                out var boundsProof))
        {
            failure = "The jump-table index does not have one adjacent unsigned CMP/B.HI bounds proof.";
            return false;
        }

        var indexedLoadIndex = branchIndex - 3;
        if (HasInterveningIndexWrite(instructions, dispatchStart, indexedLoadIndex, indexRegister))
        {
            failure = $"The checked jump-table index register W{indexRegister.Index}/X{indexRegister.Index} is overwritten "
                + "between B.HI and the indexed LDRSW.";
            return false;
        }

        if (lowerBound != 0
            || upperBound < lowerBound
            || upperBound - lowerBound >= MaximumTableEntries
            || tableLow12 > 0xFFF)
        {
            failure = "The jump-table bounds exceed the configured bounded target-set limit.";
            return false;
        }

        var pageBase = pageAddress.Value & ~0xFFFUL;
        if (pageBase > ulong.MaxValue - tableLow12)
        {
            failure = "The jump-table base calculation overflowed.";
            return false;
        }

        var tableAddress = pageBase + tableLow12;
        var entryCount = checked((ulong)(upperBound - lowerBound + 1));
        var tableSize = checked(entryCount * sizeof(int));
        if (!file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(tableAddress),
                tableSize,
                out var tableFileOffset)
            || tableFileOffset.Value > (ulong)file.Bytes.Length
            || tableSize > (ulong)file.Bytes.Length - tableFileOffset.Value)
        {
            failure = "The jump-table range is not wholly file-backed by one bounded load mapping.";
            return false;
        }

        var entries = new List<Aarch64JumpTableEntry>(checked((int)entryCount));
        for (var index = lowerBound; index <= upperBound; index++)
        {
            var delta = checked((ulong)(index - lowerBound) * sizeof(int));
            var sourceFileOffset = checked(tableFileOffset.Value + delta);
            var sourceAddress = checked(tableAddress + delta);
            var encodedValue = BinaryPrimitives.ReadInt32LittleEndian(
                file.Bytes.Span.Slice(checked((int)sourceFileOffset), sizeof(int)));
            if (!TryAddSigned(targetBaseAddress.Value, encodedValue, out var targetAddress))
            {
                failure = "A signed relative jump-table entry target calculation overflows the ELF64 address range.";
                return false;
            }

            if (!file.LoadMap.Segments.Any(segment =>
                    segment.IsExecutable
                    && segment.ContainsVirtualAddress(targetAddress, InstructionSize)))
            {
                failure = "A signed relative jump-table entry resolves outside an executable PT_LOAD range.";
                return false;
            }

            if (targetAddress < functionStart
                || targetAddress >= functionEnd
                || targetAddress % InstructionSize != 0
                || !instructionsByAddress.ContainsKey(targetAddress))
            {
                failure = "A signed relative jump-table entry resolves outside the selected function closure.";
                return false;
            }

            entries.Add(new Aarch64JumpTableEntry(
                index,
                encodedValue,
                new VirtualAddress(targetAddress),
                new FileOffset(sourceFileOffset),
                new VirtualAddress(sourceAddress)));
        }

        if (!instructionsByAddress.ContainsKey(defaultTarget))
        {
            failure = "The jump-table default target is not an instruction in the selected function closure.";
            return false;
        }

        var referenceProducers = new[]
        {
            new Aarch64JumpTableReferenceProducer(
                instructions[branchIndex - 5].Address,
                Aarch64JumpTableReferenceKind.AdrpPage),
            new Aarch64JumpTableReferenceProducer(
                instructions[branchIndex - 4].Address,
                Aarch64JumpTableReferenceKind.AddLow12),
        };
        if (!ValidateSelectedReferenceRelocations(
                file,
                referenceProducers,
                tableAddress,
                tableSize,
                out failure))
        {
            return false;
        }

        ResolveOwnerReferences(
            file,
            functionStart,
            functionEnd,
            tableAddress,
            tableSize,
            referenceProducers,
            out var ownerReferences,
            out var hasObservedAdditionalOwner);

        resolution = new Aarch64JumpTableResolution(
            instructions[branchIndex].Address,
            new VirtualAddress(tableAddress),
            targetBaseAddress,
            tableFileOffset,
            sizeof(int),
            indexRegister,
            isSigned: true,
            scale: 1,
            addend: 0,
            lowerBound,
            upperBound,
            new VirtualAddress(defaultTarget),
            entries,
            instructions
                .Skip(branchIndex - 5)
                .Take(5)
                .Select(instruction => instruction.Address),
            referenceProducers,
            ownerReferences,
            hasObservedAdditionalOwner,
            $"signed 32-bit relative table; {boundsProof}; source table range is file-backed; ownership is {(hasObservedAdditionalOwner ? "observed shared" : "ambiguous")}");
        return true;
    }

    /// <summary>
    /// Proves one explicitly selected function's bounded external signed-32
    /// table consumer. This demand-driven query is not production admission:
    /// callers must supply provider facts already verified against trusted
    /// provider bytes, and provider addresses are never placed in the consumer
    /// AddressMap or treated as consumer table bytes.
    /// </summary>
    public static bool TryProveExternalProviderTableConsumer(
        IReadOnlyList<Aarch64FunctionInstruction> selectedInstructions,
        int branchIndex,
        ElfFunctionSymbol selectedFunction,
        ElfFile consumer,
        Aarch64ExternalJumpTableProviderFacts providerFacts,
        out Aarch64ExternalJumpTableConsumerProof? proof,
        out string failure)
    {
        ArgumentNullException.ThrowIfNull(selectedInstructions);
        ArgumentNullException.ThrowIfNull(consumer);
        ArgumentNullException.ThrowIfNull(providerFacts);

        proof = null;
        failure = "The selected BR does not match the bounded external provider-table consumer proof family.";
        if (!TryValidateExternalProviderFacts(providerFacts, out failure)
            || !TryReDecodeSelectedFunction(
                selectedInstructions,
                selectedFunction,
                consumer,
                out var decodedInstructions,
                out var functionEnd,
                out failure)
            || !TryValidateExternalProviderDependency(consumer, providerFacts, out failure))
        {
            return false;
        }

        if (branchIndex < 4 || branchIndex >= decodedInstructions.Count)
        {
            failure = "The selected BR index is outside the bounded selected-function instruction sequence.";
            return false;
        }

        var branch = decodedInstructions[branchIndex].Decode.Instruction!;
        var targetAdd = decodedInstructions[branchIndex - 1].Decode.Instruction!;
        var indexedLoad = decodedInstructions[branchIndex - 2].Decode.Instruction!;
        var gotLoad = decodedInstructions[branchIndex - 3].Decode.Instruction!;
        var gotAdrp = decodedInstructions[branchIndex - 4].Decode.Instruction!;
        if (!string.Equals(branch.Mnemonic, "br", StringComparison.OrdinalIgnoreCase)
            || branch.ControlFlow != Aarch64ControlFlowKind.IndirectBranch
            || !TryGetInputRegister(branch, out var branchRegister)
            || branchRegister.Width != 64
            || !string.Equals(gotAdrp.Mnemonic, "adrp", StringComparison.OrdinalIgnoreCase)
            || !gotAdrp.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
            || !TryGetOutputRegister(gotAdrp, out var gotPageRegister)
            || gotPageRegister.Width != 64
            || gotPageRegister.Role != Aarch64RegisterRole.None
            || !TryGetDirectTarget(gotAdrp, out var gotPageAddress)
            || (gotPageAddress.Value & 0xFFFUL) != 0
            || !TryGetExternalGotLoad(gotLoad, gotPageRegister, out var gotPointerRegister, out var gotOffset)
            || !TryGetExternalIndexedSignedLoad(
                indexedLoad,
                out var indexedBaseRegister,
                out var indexRegister,
                out var loadedDisplacementRegister,
                out var indexScaleShift)
            || indexedBaseRegister != gotPointerRegister
            || !TryGetOutputRegister(targetAdd, out var targetRegister)
            || targetRegister.Width != 64
            || targetRegister.Role != Aarch64RegisterRole.None
            || !TryGetRegisterAdd(targetAdd, out var tableBaseRegister, out var displacementRegister)
            || tableBaseRegister != gotPointerRegister
            || displacementRegister != loadedDisplacementRegister
            || targetRegister != branchRegister)
        {
            failure = "The selected BR does not have the exact ordered ADRP/GOT-LDR/indexed-LDRSW/table-base-ADD register-flow chain.";
            return false;
        }

        // The signed load and final ADD must preserve the checked index used by
        // the flattened dispatcher. Also reject an LDRSW destination that aliases
        // the table pointer: the ADD still needs that pointer as its base.
        if (gotPageRegister.Index == indexRegister.Index
            || gotPointerRegister.Index == indexRegister.Index
            || loadedDisplacementRegister.Index == indexRegister.Index
            || targetRegister.Index == indexRegister.Index)
        {
            failure = "The bounded external-table index is overwritten between CMP/B.HI and BR.";
            return false;
        }

        if (loadedDisplacementRegister.Index == tableBaseRegister.Index)
        {
            failure = "The external-table LDRSW overwrites the table-base register before the target ADD.";
            return false;
        }

        var dispatchStart = branchIndex - 4;
        if (!TryGetBoundedUnsignedSwitch(
                decodedInstructions,
                dispatchStart,
                indexRegister,
                selectedFunction.Value,
                functionEnd,
                out var lowerBound,
                out var upperBound,
                out var defaultTarget,
                out var boundsProof)
            || lowerBound != 0
            || upperBound != providerFacts.TargetSymbols.Count - 1
            || providerFacts.TargetSymbols.Count != Aarch64ExternalJumpTableProviderFacts.RequiredEntryCount)
        {
            failure = "The selected external-table index does not have one CMP/B.HI proof exactly bounded to the verified four-entry provider table.";
            return false;
        }

        if (HasInterveningIndexWrite(
                decodedInstructions,
                dispatchStart,
                branchIndex - 2,
                indexRegister))
        {
            failure = "The checked external-table index register is overwritten between B.HI and the indexed LDRSW.";
            return false;
        }

        if (!TryVerifySafeDefaultPath(
                decodedInstructions,
                branchIndex - 4,
                branchIndex,
                defaultTarget,
                selectedFunction.Value,
                functionEnd,
                out var safeDefaultPath,
                out failure))
        {
            return false;
        }

        if (gotPageAddress.Value > ulong.MaxValue - gotOffset)
        {
            failure = "The selected GOT-page plus low-12 displacement overflows the consumer address domain.";
            return false;
        }

        var gotAddress = checked(gotPageAddress.Value + gotOffset);
        if (gotAddress % sizeof(ulong) != 0)
        {
            failure = "The external provider GOT pointer slot is not aligned to an 8-byte consumer pointer.";
            return false;
        }

        var gotOwners = consumer.RelaRelocations
            .Where(relocation => relocation.Offset == gotAddress)
            .ToArray();
        if (gotOwners.Length != 1
            || gotOwners[0] is not { Type: ElfConstants.RArm64GlobDat, IsPlt: false } relocation
            || relocation.Addend != 0
            || relocation.SymbolIndex == 0
            || relocation.SymbolIndex >= (uint)consumer.DynamicSymbols.Count)
        {
            failure = "The external provider GOT slot does not have one exact non-PLT R_AARCH64_GLOB_DAT owner.";
            return false;
        }

        var symbolOwners = consumer.RelaRelocations
            .Where(candidate => candidate.SymbolIndex == relocation.SymbolIndex)
            .ToArray();
        if (symbolOwners.Length != 1
            || symbolOwners[0] != relocation)
        {
            failure = "The imported provider table symbol has duplicate or ambiguous dynamic relocation owners.";
            return false;
        }

        if (!Aarch64IndirectCallProofAnalyzer.TryResolveImportOwner(
                consumer,
                relocation,
                gotAddress,
                gotPageAddress.Value,
                decodedInstructions[branchIndex - 4].Address,
                decodedInstructions[branchIndex - 3].Address,
                out var importOwner,
                out failure)
            || importOwner is null
            || importOwner.SymbolBinding != 1
            || importOwner.SymbolType != ElfConstants.SttObject
            || importOwner.SymbolVisibility != 0
            || !string.Equals(importOwner.SymbolName, providerFacts.TableObjectName, StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(failure))
            {
                failure = "The unique GLOB_DAT owner is not the exact undefined global/default provider table object.";
            }

            return false;
        }

        if (!TryValidateUniqueImportedObjectSymbol(
                consumer,
                relocation.SymbolIndex,
                importOwner.SymbolName,
                providerFacts.TableObjectSize,
                out failure)
            || !Aarch64IndirectCallProofAnalyzer.TryGetMappedRange(
                consumer,
                gotAddress,
                sizeof(ulong),
                out var gotFileOffset))
        {
            if (string.IsNullOrEmpty(failure))
            {
                failure = "The consumer GOT slot does not map to one unique writable, file-backed 8-byte range.";
            }

            return false;
        }

        var compareAddress = decodedInstructions[dispatchStart - 2].Address;
        var boundsBranchAddress = decodedInstructions[dispatchStart - 1].Address;
        var producerAddresses = new[]
        {
            decodedInstructions[branchIndex - 4].Address,
            decodedInstructions[branchIndex - 3].Address,
            decodedInstructions[branchIndex - 2].Address,
            decodedInstructions[branchIndex - 1].Address,
            decodedInstructions[branchIndex].Address,
        };
        proof = new Aarch64ExternalJumpTableConsumerProof(
            selectedFunction,
            compareAddress,
            boundsBranchAddress,
            defaultTarget,
            safeDefaultPath,
            producerAddresses[0],
            producerAddresses[1],
            producerAddresses[2],
            producerAddresses[3],
            producerAddresses[4],
            producerAddresses,
            indexRegister,
            gotPointerRegister,
            loadedDisplacementRegister,
            targetRegister,
            sizeof(int),
            isSigned: true,
            indexScaleShift,
            lowerBound,
            upperBound,
            new VirtualAddress(gotAddress),
            gotFileOffset,
            importOwner,
            providerFacts,
            $"{boundsProof}; one exact undefined global/default STT_OBJECT is bound by a unique writable/file-backed GLOB_DAT GOT pointer slot; provider table identity {providerFacts.TableIdentity} is retained in the provider domain.");
        failure = string.Empty;
        return true;
    }

    private static bool TryValidateExternalProviderFacts(
        Aarch64ExternalJumpTableProviderFacts facts,
        out string failure)
    {
        failure = "The supplied verified provider facts do not satisfy the bounded four-entry signed-relative provider contract.";
        if (!IsCanonicalIdentity(facts.TableIdentity)
            || !IsCanonicalSoname(facts.ProviderSoname)
            || !IsCanonicalHex(facts.ProviderBuildIdHex, 8, 128, evenLength: true)
            || !IsCanonicalHex(facts.ProviderSha256, 64, 64, evenLength: false)
            || !IsCanonicalHex(facts.TableBytesSha256, 64, 64, evenLength: false)
            || !IsCanonicalSymbolName(facts.TableObjectName)
            || facts.TableObjectSize != Aarch64ExternalJumpTableProviderFacts.RequiredTableByteLength
            || facts.TargetSymbols.Count != Aarch64ExternalJumpTableProviderFacts.RequiredEntryCount
            || facts.TargetSymbols.Any(target => target is null || target.Index < 0
                || target.Index >= Aarch64ExternalJumpTableProviderFacts.RequiredEntryCount
                || !IsCanonicalSymbolName(target.SymbolName))
            || !facts.TargetSymbols.Select(target => target.Index).Order().SequenceEqual(RequiredProviderEntryIndices)
            || facts.TargetSymbols.Select(target => target.SymbolName).Distinct(StringComparer.Ordinal).Count()
                != Aarch64ExternalJumpTableProviderFacts.RequiredEntryCount)
        {
            return false;
        }

        return true;
    }

    private static bool TryReDecodeSelectedFunction(
        IReadOnlyList<Aarch64FunctionInstruction> suppliedInstructions,
        ElfFunctionSymbol selectedFunction,
        ElfFile consumer,
        out IReadOnlyList<Aarch64FunctionInstruction> decodedInstructions,
        out ulong functionEnd,
        out string failure)
    {
        decodedInstructions = Array.Empty<Aarch64FunctionInstruction>();
        functionEnd = default;
        failure = "The selected function is not one exact bounded executable source range.";
        if (consumer.Header.Machine != ElfConstants.MachineAarch64
            || consumer.Header.Type != ElfConstants.TypeDyn
            || selectedFunction.Table != ElfSymbolTableKind.Dynamic
            || selectedFunction.Size == 0
            || selectedFunction.Value % InstructionSize != 0
            || selectedFunction.Size % InstructionSize != 0
            || !selectedFunction.TryGetEnd(out functionEnd)
            || consumer.FunctionSymbols.Count(candidate => candidate == selectedFunction) != 1)
        {
            return false;
        }

        var instructionCount = selectedFunction.Size / InstructionSize;
        if (instructionCount > MaximumExternalProofInstructions
            || instructionCount != (ulong)suppliedInstructions.Count)
        {
            failure = "The selected function exceeds the external-table proof instruction bound or is not a complete selected-function input.";
            return false;
        }

        var executableOwners = consumer.LoadMap.Segments
            .Where(segment => segment.IsExecutable
                && segment.ContainsVirtualAddress(selectedFunction.Value, selectedFunction.Size))
            .ToArray();
        if (executableOwners.Length != 1
            || !consumer.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(selectedFunction.Value),
                selectedFunction.Size,
                out var functionFileOffset)
            || functionFileOffset.Value > (ulong)consumer.Bytes.Length
            || selectedFunction.Size > (ulong)consumer.Bytes.Length - functionFileOffset.Value
            || executableOwners[0].VirtualAddress > selectedFunction.Value
            || selectedFunction.Value - executableOwners[0].VirtualAddress
                != functionFileOffset.Value - executableOwners[0].FileOffset)
        {
            return false;
        }

        var decoder = new AsmStoneAdapter();
        var instructions = new List<Aarch64FunctionInstruction>(checked((int)instructionCount));
        for (ulong index = 0; index < instructionCount; index++)
        {
            var expectedAddress = checked(selectedFunction.Value + (index * InstructionSize));
            var expectedOffset = checked(functionFileOffset.Value + (index * InstructionSize));
            if (suppliedInstructions[checked((int)index)].Address != expectedAddress
                || suppliedInstructions[checked((int)index)].FileOffset != expectedOffset
                || expectedOffset > int.MaxValue
                || expectedOffset > (ulong)consumer.Bytes.Length - sizeof(uint))
            {
                failure = "The selected-function instruction sequence is not a contiguous source-linked bounded range.";
                return false;
            }

            var encoding = BinaryPrimitives.ReadUInt32LittleEndian(
                consumer.Bytes.Span.Slice(checked((int)expectedOffset), sizeof(uint)));
            if (suppliedInstructions[checked((int)index)].Encoding != encoding)
            {
                failure = "A selected-function instruction encoding differs from its source ELF bytes.";
                return false;
            }

            var decoded = decoder.Decode(encoding, expectedAddress);
            if (!decoded.IsSuccess)
            {
                failure = "The selected-function source bytes contain an instruction that the project decoder cannot prove.";
                return false;
            }

            instructions.Add(new Aarch64FunctionInstruction(expectedOffset, expectedAddress, encoding, decoded));
        }

        decodedInstructions = Array.AsReadOnly(instructions.ToArray());
        failure = string.Empty;
        return true;
    }

    private static bool TryValidateExternalProviderDependency(
        ElfFile consumer,
        Aarch64ExternalJumpTableProviderFacts providerFacts,
        out string failure)
    {
        failure = "The consumer does not declare exactly the configured provider SONAME dependency.";
        if (consumer.DynamicEntries.Count is 0 or > MaximumExternalProofDynamicEntries
            || consumer.DynamicEntries.Count(entry => entry.Tag == ElfConstants.DtNull) != 1
            || !consumer.DynamicEntries[^1].IsTerminator
            || consumer.DynamicMetadata.NeededLibraries.Count != 1
            || !string.Equals(
                consumer.DynamicMetadata.NeededLibraries[0],
                providerFacts.ProviderSoname,
                StringComparison.Ordinal)
            || consumer.DynamicMetadata.Rpath is not null
            || consumer.DynamicMetadata.RunPath is not null
            || consumer.DynamicMetadata.StringTable.Length > MaximumExternalProofStringTableBytes)
        {
            return false;
        }

        var neededRows = consumer.DynamicEntries
            .Where(entry => entry.Tag == ElfConstants.DtNeeded)
            .ToArray();
        if (neededRows.Length != 1
            || neededRows[0].Value > uint.MaxValue
            || !ElfParserUtilities.TryReadString(
                consumer.DynamicMetadata.StringTable,
                checked((uint)neededRows[0].Value),
                out var neededName)
            || !string.Equals(neededName, providerFacts.ProviderSoname, StringComparison.Ordinal))
        {
            failure = "The consumer has a missing, duplicate, path-bearing, or mismatched provider DT_NEEDED row.";
            return false;
        }

        var forbiddenTags = new[]
        {
            ElfConstants.DtRpath,
            ElfConstants.DtRunPath,
            ElfConstants.DtConfig,
            ElfConstants.DtAudit,
            ElfConstants.DtDepAudit,
            ElfConstants.DtAuxiliary,
            ElfConstants.DtFilter,
            ElfConstants.DtSymbolic,
            ElfConstants.DtTextRel,
            ElfConstants.DtVersym,
            ElfConstants.DtVerneed,
            ElfConstants.DtVerneedNum,
            ElfConstants.DtVerdef,
            ElfConstants.DtVerdefNum,
        };
        if (forbiddenTags.Any(tag => consumer.DynamicEntries.Any(entry => entry.Tag == tag)))
        {
            failure = "The provider consumer carries a forbidden search-path, symbol-version, audit, symbolic-binding, or text-relocation dynamic tag.";
            return false;
        }

        var requiredTags = new[]
        {
            ElfConstants.DtStrTab,
            ElfConstants.DtStrSz,
            ElfConstants.DtSymTab,
            ElfConstants.DtSymEnt,
            ElfConstants.DtRela,
            ElfConstants.DtRelaSz,
            ElfConstants.DtRelaEnt,
        };
        if (requiredTags.Any(tag => consumer.DynamicEntries.Count(entry => entry.Tag == tag) != 1)
            || !TryGetDynamicValue(consumer.DynamicEntries, ElfConstants.DtStrTab, out var stringTableAddress)
            || !TryGetDynamicValue(consumer.DynamicEntries, ElfConstants.DtStrSz, out var stringTableSize)
            || !TryGetDynamicValue(consumer.DynamicEntries, ElfConstants.DtSymTab, out var symbolTableAddress)
            || !TryGetDynamicValue(consumer.DynamicEntries, ElfConstants.DtSymEnt, out var symbolEntrySize)
            || !TryGetDynamicValue(consumer.DynamicEntries, ElfConstants.DtRela, out var relaAddress)
            || !TryGetDynamicValue(consumer.DynamicEntries, ElfConstants.DtRelaSz, out var relaSize)
            || !TryGetDynamicValue(consumer.DynamicEntries, ElfConstants.DtRelaEnt, out var relaEntrySize)
            || symbolEntrySize != ElfConstants.SymbolEntrySize64
            || stringTableSize != (ulong)consumer.DynamicMetadata.StringTable.Length
            || relaEntrySize != ElfConstants.RelaEntrySize64
            || relaSize < ElfConstants.RelaEntrySize64
            || relaSize % ElfConstants.RelaEntrySize64 != 0
            || consumer.DynamicSymbols.Count is 0 or > MaximumExternalProofDynamicSymbols
            || consumer.RelaRelocations.Count > MaximumExternalProofRelocations
            || relaSize / ElfConstants.RelaEntrySize64 != (ulong)consumer.RelaRelocations.Count(relocation => !relocation.IsPlt)
            || !Aarch64IndirectCallProofAnalyzer.TryGetMappedRange(
                consumer,
                stringTableAddress,
                stringTableSize,
                out _)
            || !Aarch64IndirectCallProofAnalyzer.TryGetMappedRange(
                consumer,
                symbolTableAddress,
                checked((ulong)consumer.DynamicSymbols.Count * ElfConstants.SymbolEntrySize64),
                out _)
            || !Aarch64IndirectCallProofAnalyzer.TryGetMappedRange(consumer, relaAddress, relaSize, out _))
        {
            failure = "The consumer dynamic symbol/string/RELA tables are missing, duplicated, inconsistent, or not uniquely file-backed within proof limits.";
            return false;
        }

        failure = string.Empty;
        return true;
    }

    private static bool TryValidateUniqueImportedObjectSymbol(
        ElfFile consumer,
        uint symbolIndex,
        string symbolName,
        ulong providerTableSize,
        out string failure)
    {
        failure = "The GLOB_DAT row does not identify one unique undefined global/default STT_OBJECT matching the provider table object.";
        if (symbolIndex >= (uint)consumer.DynamicSymbols.Count
            || consumer.DynamicSymbols.Count > MaximumExternalProofDynamicSymbols
            || consumer.DynamicMetadata.StringTable.Length > MaximumExternalProofStringTableBytes
            || !TryEncodeStrictName(symbolName, out var expectedName))
        {
            return false;
        }

        var matches = new List<uint>(1);
        for (var index = 0; index < consumer.DynamicSymbols.Count; index++)
        {
            var candidate = consumer.DynamicSymbols[index];
            if (candidate.Name >= (uint)consumer.DynamicMetadata.StringTable.Length)
            {
                failure = "A consumer dynamic-symbol name offset is outside the bounded dynamic string table.";
                return false;
            }

            if (IsExactStringAt(consumer.DynamicMetadata.StringTable.Span, candidate.Name, expectedName))
            {
                matches.Add(checked((uint)index));
            }
        }

        var symbol = consumer.DynamicSymbols[checked((int)symbolIndex)];
        if (matches.Count != 1
            || matches[0] != symbolIndex
            || symbol.SectionIndex != 0
            || symbol.Value != 0
            || (symbol.Info >> 4) != 1
            || (symbol.Info & 0x0F) != ElfConstants.SttObject
            || symbol.Other != 0
            || (symbol.Size != 0 && symbol.Size != providerTableSize))
        {
            return false;
        }

        failure = string.Empty;
        return true;
    }

    private static bool TryGetExternalGotLoad(
        Aarch64Instruction instruction,
        Aarch64RegisterView expectedPageRegister,
        out Aarch64RegisterView gotPointerRegister,
        out ulong low12Offset)
    {
        gotPointerRegister = default;
        low12Offset = default;
        var memories = instruction.Operands
            .Where(operand => operand.Memory is not null)
            .Select(operand => operand.Memory!)
            .ToArray();
        if (!string.Equals(instruction.Mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
            || memories.Length != 1
            || memories[0].Index is not null
            || memories[0].WritesBack
            || memories[0].AccessSize != sizeof(ulong)
            || memories[0].Base != expectedPageRegister
            || memories[0].Offset < 0
            || memories[0].Offset >= 0x1000
            || !TryGetOutputRegister(instruction, out var destination)
            || destination.Width != 64
            || destination.Role != Aarch64RegisterRole.None)
        {
            return false;
        }

        gotPointerRegister = destination;
        low12Offset = checked((ulong)memories[0].Offset);
        return true;
    }

    private static bool TryGetExternalIndexedSignedLoad(
        Aarch64Instruction instruction,
        out Aarch64RegisterView baseRegister,
        out Aarch64RegisterView indexRegister,
        out Aarch64RegisterView destinationRegister,
        out int indexScaleShift)
    {
        baseRegister = default;
        indexRegister = default;
        destinationRegister = default;
        indexScaleShift = default;
        var memories = instruction.Operands
            .Where(operand => operand.Memory is not null)
            .Select(operand => operand.Memory!)
            .ToArray();
        if (!string.Equals(instruction.Mnemonic, "ldrsw", StringComparison.OrdinalIgnoreCase)
            || memories.Length != 1
            || !TryGetIndexedLoad(instruction, out baseRegister, out indexRegister)
            || memories[0].AccessSize != sizeof(int)
            || memories[0].IndexModifierKind != "Uxtw"
            || memories[0].IndexModifierAmount != 2
            || indexRegister.Width != 32
            || indexRegister.Class != Aarch64RegisterClass.General
            || indexRegister.Role != Aarch64RegisterRole.None
            || baseRegister.Width != 64
            || baseRegister.Role != Aarch64RegisterRole.None
            || !TryGetOutputRegister(instruction, out destinationRegister)
            || destinationRegister.Width != 64
            || destinationRegister.Role != Aarch64RegisterRole.None)
        {
            return false;
        }

        indexScaleShift = memories[0].IndexModifierAmount;
        return true;
    }

    private static bool TryVerifySafeDefaultPath(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        int dispatchStart,
        int branchIndex,
        ulong defaultTarget,
        ulong functionStart,
        ulong functionEnd,
        out IReadOnlyList<ulong> path,
        out string failure)
    {
        path = Array.Empty<ulong>();
        failure = "The B.HI edge does not terminate through one bounded safe default-return path.";
        var defaultIndex = -1;
        for (var index = 0; index < instructions.Count; index++)
        {
            if (instructions[index].Address == defaultTarget)
            {
                defaultIndex = index;
                break;
            }
        }

        if (defaultIndex < 0
            || defaultTarget < functionStart
            || defaultTarget >= functionEnd
            || defaultIndex >= dispatchStart - 2 && defaultIndex <= branchIndex)
        {
            failure = "The B.HI destination is missing, outside the selected function, or enters the bounds/dispatch chain.";
            return false;
        }

        var visited = new List<ulong>(MaximumSafeDefaultInstructions);
        for (var step = 0; step < MaximumSafeDefaultInstructions; step++)
        {
            var index = checked(defaultIndex + step);
            if (index >= instructions.Count)
            {
                break;
            }

            var instruction = instructions[index].Decode.Instruction!;
            var address = instructions[index].Address;
            if (address >= functionEnd
                || address < functionStart
                || address >= instructions[dispatchStart - 2].Address
                    && address <= instructions[branchIndex].Address
                || instruction.MemoryEffect != Aarch64MemoryEffect.None
                || instruction.Operands.Any(operand => operand.Memory is not null))
            {
                failure = "The B.HI default path reaches dispatch code or has a memory side effect before returning.";
                return false;
            }

            visited.Add(address);
            if (instruction.ControlFlow == Aarch64ControlFlowKind.Return)
            {
                path = Array.AsReadOnly(visited.ToArray());
                failure = string.Empty;
                return true;
            }

            if (instruction.ControlFlow != Aarch64ControlFlowKind.None)
            {
                failure = "The B.HI default path branches, calls, or transfers indirectly before its bounded return.";
                return false;
            }
        }

        failure = "The B.HI default path exceeds the bounded instruction limit without reaching RET.";
        return false;
    }

    private static bool IsCanonicalIdentity(string value) =>
        value.Length is > 0 and <= 128
        && value.All(character => character is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '.' or '_' or '-');

    private static bool IsCanonicalSoname(string value) =>
        value.Length is > 0 and <= 255
        && value[0] != '.'
        && value.All(character => character is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '.' or '_' or '+' or '-');

    private static bool IsCanonicalSymbolName(string value) =>
        value.Length is > 0 and <= 255
        && value.All(character => !char.IsControl(character) && character != '\0' && character != '/');

    private static bool IsCanonicalHex(string value, int minimumLength, int maximumLength, bool evenLength) =>
        value.Length >= minimumLength
        && value.Length <= maximumLength
        && (!evenLength || (value.Length & 1) == 0)
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool TryEncodeStrictName(string value, out byte[] bytes)
    {
        try
        {
            bytes = StrictUtf8.GetBytes(value);
            return bytes.Length is > 0 and <= 255;
        }
        catch (EncoderFallbackException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static bool IsExactStringAt(ReadOnlySpan<byte> stringTable, uint offset, ReadOnlySpan<byte> expected)
    {
        if (offset >= (uint)stringTable.Length)
        {
            return false;
        }

        var start = checked((int)offset);
        return expected.Length < stringTable.Length - start
            && stringTable.Slice(start, expected.Length).SequenceEqual(expected)
            && stringTable[start + expected.Length] == 0;
    }

    private static bool TryGetDynamicValue(
        IReadOnlyList<DynamicEntry> entries,
        ulong tag,
        out ulong value)
    {
        var matches = entries.Where(entry => entry.Tag == tag).ToArray();
        value = matches.Length == 1 ? matches[0].Value : default;
        return matches.Length == 1;
    }

    private static bool ValidateSelectedReferenceRelocations(
        ElfFile file,
        IReadOnlyList<Aarch64JumpTableReferenceProducer> producers,
        ulong tableAddress,
        ulong tableSize,
        out string failure)
    {
        failure = string.Empty;
        var pageAddress = producers.Single(producer =>
            producer.Kind == Aarch64JumpTableReferenceKind.AdrpPage).InstructionAddress;
        var addAddress = producers.Single(producer =>
            producer.Kind == Aarch64JumpTableReferenceKind.AddLow12).InstructionAddress;
        var pageRows = file.SectionRelocations
            .Where(row => row.Relocation.Offset == pageAddress)
            .ToArray();
        var addRows = file.SectionRelocations
            .Where(row => row.Relocation.Offset == addAddress)
            .ToArray();
        if (pageRows.Length > 1
            || addRows.Length > 1
            || pageRows.Length == 1
                && (pageRows[0].Relocation.Type is not (ElfConstants.RArm64AdrPrelPgHi21 or ElfConstants.RArm64AdrPrelPgHi21Nc)
                    || !IsTableSymbol(pageRows[0].Symbol, pageRows[0].Relocation.Addend, tableAddress, tableSize))
            || addRows.Length == 1
                && (addRows[0].Relocation.Type != ElfConstants.RArm64AddAbsLo12Nc
                    || !IsTableSymbol(addRows[0].Symbol, addRows[0].Relocation.Addend, tableAddress, tableSize)))
        {
            failure = "The selected jump-table base-reference sites have conflicting or malformed section-linked relocation evidence.";
            return false;
        }

        if (pageRows.Length == 1 && addRows.Length == 1)
        {
            var pageSymbol = pageRows[0].Symbol;
            var addSymbol = addRows[0].Symbol;
            if (pageSymbol is null || addSymbol is null || !SameSymbol(pageSymbol, addSymbol))
            {
                failure = "The selected jump-table base-reference sites identify conflicting section-linked symbols.";
                return false;
            }
        }

        return true;
    }

    private static void ResolveOwnerReferences(
        ElfFile file,
        ulong selectedFunctionStart,
        ulong selectedFunctionEnd,
        ulong tableAddress,
        ulong tableSize,
        IReadOnlyList<Aarch64JumpTableReferenceProducer> selectedProducers,
        out IReadOnlyList<Aarch64JumpTableOwnerReference> ownerReferences,
        out bool hasObservedAdditionalOwner)
    {
        ownerReferences = Array.Empty<Aarch64JumpTableOwnerReference>();
        hasObservedAdditionalOwner = false;
        var pageAddress = selectedProducers.Single(producer =>
            producer.Kind == Aarch64JumpTableReferenceKind.AdrpPage).InstructionAddress;
        var addAddress = selectedProducers.Single(producer =>
            producer.Kind == Aarch64JumpTableReferenceKind.AddLow12).InstructionAddress;
        var pageRelocation = file.SectionRelocations
            .Where(relocation => relocation.Relocation.Offset == pageAddress
                && relocation.Relocation.Type is ElfConstants.RArm64AdrPrelPgHi21
                    or ElfConstants.RArm64AdrPrelPgHi21Nc)
            .Select(relocation => (Relocation: relocation, Symbol: relocation.Symbol))
            .Where(candidate => candidate.Symbol is not null
                && IsTableSymbol(candidate.Symbol, candidate.Relocation.Relocation.Addend, tableAddress, tableSize))
            .ToArray();
        var addRelocation = file.SectionRelocations
            .Where(relocation => relocation.Relocation.Offset == addAddress
                && relocation.Relocation.Type == ElfConstants.RArm64AddAbsLo12Nc)
            .Select(relocation => (Relocation: relocation, Symbol: relocation.Symbol))
            .Where(candidate => candidate.Symbol is not null
                && IsTableSymbol(candidate.Symbol, candidate.Relocation.Relocation.Addend, tableAddress, tableSize))
            .ToArray();
        if (pageRelocation.Length != 1
            || addRelocation.Length != 1
            || !SameSymbol(pageRelocation[0].Symbol!, addRelocation[0].Symbol!))
        {
            return;
        }

        var identity = pageRelocation[0].Symbol!;
        var matchingRows = file.SectionRelocations
            .Where(relocation => relocation.Symbol is { } relocationSymbol
                && SameSymbol(identity, relocationSymbol)
                && relocation.Relocation.Type is ElfConstants.RArm64AdrPrelPgHi21
                    or ElfConstants.RArm64AdrPrelPgHi21Nc
                    or ElfConstants.RArm64AddAbsLo12Nc
                && IsTableSymbol(
                    relocation.Symbol,
                    relocation.Relocation.Addend,
                    tableAddress,
                    tableSize))
            .ToArray();
        var facts = new List<Aarch64JumpTableOwnerReference>();
        foreach (var relocation in matchingRows)
        {
            var ownerFunctions = file.FunctionSymbols
                .Where(function => function.TryGetEnd(out var end)
                    && relocation.Relocation.Offset >= function.Value
                    && relocation.Relocation.Offset < end)
                .GroupBy(function => (function.Name, function.Value, function.Size, function.SectionIndex))
                .Select(group => group.First())
                .ToArray();
            if (ownerFunctions.Length != 1
                || relocation.Symbol is not { } symbol
                || !TryGetValidatedOwnerSection(
                    file,
                    relocation.TargetSectionIndex,
                    ownerFunctions[0],
                    relocation.Relocation.Offset,
                    out var ownerSection))
            {
                // One malformed or section-mismatched candidate invalidates the
                // entire ownership proof; a partial owner inventory must never
                // be used to classify a shared table.
                return;
            }

            var owner = ownerFunctions[0];
            facts.Add(new Aarch64JumpTableOwnerReference(
                relocation.Relocation.Offset,
                relocation.RelocationSectionIndex,
                relocation.SymbolTableSectionIndex,
                relocation.TargetSectionIndex,
                owner.SectionIndex,
                ownerSection,
                relocation.Relocation.SourceAddress,
                relocation.Relocation.Type,
                relocation.Relocation.Addend,
                symbol.SymbolIndex,
                symbol.Name,
                symbol.Binding,
                symbol.Type,
                symbol.Visibility,
                symbol.SectionIndex,
                symbol.Value,
                symbol.Size,
                owner.Name,
                owner.Value,
                owner.Size,
                owner.Value == selectedFunctionStart
                    && owner.TryGetEnd(out var ownerEnd)
                    && ownerEnd == selectedFunctionEnd));
        }

        ownerReferences = Array.AsReadOnly(facts
            .OrderBy(reference => reference.InstructionAddress)
            .ThenBy(reference => reference.OwnerFunctionStart)
            .ThenBy(reference => reference.RelocationType)
            .ToArray());
        hasObservedAdditionalOwner = facts
            .Where(reference => !reference.IsSelectedFunction)
            .GroupBy(reference => (reference.OwnerFunctionName, reference.OwnerFunctionStart, reference.OwnerFunctionSize))
            .Any(group => group.Any(reference => reference.RelocationType is
                    ElfConstants.RArm64AdrPrelPgHi21 or ElfConstants.RArm64AdrPrelPgHi21Nc)
                && group.Any(reference => reference.RelocationType == ElfConstants.RArm64AddAbsLo12Nc));
    }

    private static bool TryGetValidatedOwnerSection(
        ElfFile file,
        uint targetSectionIndex,
        ElfFunctionSymbol owner,
        ulong relocationSite,
        out SectionHeader section)
    {
        section = default;
        if (targetSectionIndex >= (uint)file.SectionHeaders.Count
            || owner.SectionIndex == 0
            || owner.SectionIndex == ElfConstants.ShnXindex
            || owner.SectionIndex != targetSectionIndex
            || relocationSite % InstructionSize != 0)
        {
            return false;
        }

        section = file.SectionHeaders[checked((int)targetSectionIndex)];
        if (section.Type == ElfConstants.ShtNobits
            || (section.Flags & ElfConstants.ShfExecInstr) == 0
            || section.Address > owner.Value
            || !owner.TryGetEnd(out var ownerEnd)
            || owner.Size == 0
            || owner.Value - section.Address > section.Size
            || owner.Size > section.Size - (owner.Value - section.Address)
            || relocationSite < owner.Value
            || relocationSite >= ownerEnd
            || relocationSite < section.Address
            || relocationSite - section.Address > section.Size
            || InstructionSize > section.Size - (relocationSite - section.Address)
            || !TryAdd(section.Offset, section.Size, out var sectionFileEnd)
            || section.Offset > (ulong)file.Bytes.Length
            || section.Size > (ulong)file.Bytes.Length - section.Offset)
        {
            return false;
        }

        var functionFileDelta = owner.Value - section.Address;
        var siteFileDelta = relocationSite - section.Address;
        if (!TryAdd(section.Offset, functionFileDelta, out var functionFileOffset)
            || functionFileOffset > sectionFileEnd
            || owner.Size > sectionFileEnd - functionFileOffset
            || !TryAdd(section.Offset, siteFileDelta, out var siteFileOffset)
            || siteFileOffset > sectionFileEnd
            || InstructionSize > sectionFileEnd - siteFileOffset
            || siteFileOffset > (ulong)file.Bytes.Length
            || InstructionSize > (ulong)file.Bytes.Length - siteFileOffset)
        {
            return false;
        }

        return file.LoadMap.Segments.Any(segment =>
                segment.IsExecutable
                && segment.ContainsVirtualAddress(owner.Value, owner.Size)
                && segment.ContainsFileOffset(functionFileOffset, owner.Size)
                && owner.Value - segment.VirtualAddress == functionFileOffset - segment.FileOffset)
            && file.LoadMap.Segments.Any(segment =>
                segment.IsExecutable
                && segment.ContainsVirtualAddress(relocationSite, InstructionSize)
                && segment.ContainsFileOffset(siteFileOffset, InstructionSize)
                && relocationSite - segment.VirtualAddress == siteFileOffset - segment.FileOffset);
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

    private static bool IsTableSymbol(
        ElfSectionSymbolIdentity? symbol,
        long addend,
        ulong tableAddress,
        ulong tableSize) =>
        symbol is not null
        && symbol.SymbolIndex != 0
        && symbol.SectionIndex != 0
        && TryAddSigned(symbol.Value, addend, out var relocatedAddress)
        && relocatedAddress == tableAddress
        && tableAddress >= symbol.Value
        && tableAddress - symbol.Value <= symbol.Size
        && tableSize <= symbol.Size - (tableAddress - symbol.Value);

    private static bool SameSymbol(ElfSectionSymbolIdentity left, ElfSectionSymbolIdentity right) =>
        left.SymbolIndex == right.SymbolIndex
        && left.SymbolTableSectionIndex == right.SymbolTableSectionIndex
        && left.Name == right.Name
        && left.SectionIndex == right.SectionIndex
        && left.Value == right.Value
        && left.Size == right.Size;

    private static bool HasInterveningIndexWrite(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        int firstInstructionIndex,
        int indexedLoadIndex,
        Aarch64RegisterView indexRegister)
    {
        // Wn and Xn are two views of the same architectural GPR. The interval
        // ends before the indexed LDRSW because that instruction reads its index
        // before writing its destination, even when both registers alias.
        for (var instructionIndex = firstInstructionIndex;
             instructionIndex < indexedLoadIndex;
             instructionIndex++)
        {
            var instruction = instructions[instructionIndex].Decode.Instruction;
            if (instruction is null)
            {
                return true;
            }

            foreach (var operand in instruction.Operands)
            {
                if (operand.Direction is not (Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput))
                {
                    continue;
                }

                if (operand.Kind == Aarch64OperandKind.Register
                    && operand.Register is { } register
                    && IsSameArchitecturalGpr(register, indexRegister))
                {
                    return true;
                }

                if (operand.Kind is Aarch64OperandKind.RegisterPair or Aarch64OperandKind.RegisterList
                    && operand.Registers.Any(register => IsSameArchitecturalGpr(register, indexRegister)))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsSameArchitecturalGpr(
        Aarch64RegisterView left,
        Aarch64RegisterView right) =>
        left.Class == Aarch64RegisterClass.General
        && right.Class == Aarch64RegisterClass.General
        && left.Role == Aarch64RegisterRole.None
        && right.Role == Aarch64RegisterRole.None
        && left.Index == right.Index;

    private static bool TryGetBoundedUnsignedSwitch(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        int dispatchStart,
        Aarch64RegisterView indexRegister,
        ulong functionStart,
        ulong functionEnd,
        out int lowerBound,
        out int upperBound,
        out ulong defaultTarget,
        out string proof)
    {
        lowerBound = 0;
        upperBound = 0;
        defaultTarget = default;
        proof = string.Empty;
        if (dispatchStart < 2)
        {
            return false;
        }

        var compare = instructions[dispatchStart - 2].Decode.Instruction;
        var conditional = instructions[dispatchStart - 1].Decode.Instruction;
        if (compare is null
            || conditional is null
            || !string.Equals(compare.Mnemonic, "cmp", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(compare.Mnemonic, "subs", StringComparison.OrdinalIgnoreCase)
            || !compare.Properties.HasFlag(Aarch64InstructionProperties.WritesNzcv)
            || !conditional.Mnemonic.StartsWith("b.", StringComparison.OrdinalIgnoreCase)
                && !conditional.Mnemonic.Equals("b.$cond", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var compareZeroDestinations = compare.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput
                && operand.Register is { Class: Aarch64RegisterClass.General, Role: Aarch64RegisterRole.Zero })
            .Select(operand => operand.Register!.Value)
            .ToArray();
        var compareWritesIndex = compare.Operands.Any(operand =>
            operand.Kind == Aarch64OperandKind.Register
            && operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput
            && operand.Register is { } register
            && IsSameArchitecturalGpr(register, indexRegister));
        var condition = conditional.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate)
            .Select(operand => operand.Immediate)
            .FirstOrDefault();
        var compareRegisters = compare.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register is { } register
                && register.Class == Aarch64RegisterClass.General
                && register.Role == Aarch64RegisterRole.None)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        var compareImmediate = compare.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate)
            .Select(operand => operand.Immediate)
            .FirstOrDefault();
        if (condition is not 8
            || compareZeroDestinations.Length != 1
            || compareZeroDestinations[0].Width != indexRegister.Width
            || compareWritesIndex
            || compareRegisters.Length != 1
            || compareRegisters[0].Index != indexRegister.Index
            || compareRegisters[0].Width != indexRegister.Width
            || compareImmediate is not { } compareImmediateValue
            || compareImmediateValue < 0
            || compareImmediateValue > 65535
            || conditional.DirectTarget is not { } target)
        {
            return false;
        }

        lowerBound = 0;
        upperBound = checked((int)compareImmediateValue);
        defaultTarget = target;
        if (defaultTarget < functionStart
            || defaultTarget >= functionEnd
            || defaultTarget % InstructionSize != 0)
        {
            return false;
        }

        proof = $"unsigned index x{indexRegister.Index} in [0,{upperBound}] from CMP/B.HI";
        return true;
    }

    private static bool TryGetIndexedLoad(
        Aarch64Instruction instruction,
        out Aarch64RegisterView baseRegister,
        out Aarch64RegisterView indexRegister)
    {
        baseRegister = default;
        indexRegister = default;
        var memory = instruction.Operands
            .Select(operand => operand.Memory)
            .FirstOrDefault(memory => memory is not null && memory.Index is not null);
        if (memory?.Index is not { } index
            || memory.AccessSize != sizeof(uint)
            || !string.Equals(memory.AddressingMode, "RegisterOffset", StringComparison.Ordinal)
            || !string.Equals(memory.IndexModifierKind, "Uxtw", StringComparison.Ordinal)
            || memory.IndexModifierAmount != 2
            || memory.Offset != 0
            || memory.WritesBack)
        {
            return false;
        }

        baseRegister = memory.Base;
        indexRegister = index;
        return true;
    }

    private static bool TryGetInputRegister(
        Aarch64Instruction instruction,
        out Aarch64RegisterView register)
    {
        register = default;
        var inputs = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register is { } value
                && value.Class == Aarch64RegisterClass.General
                && value.Role == Aarch64RegisterRole.None)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        if (inputs.Length != 1)
        {
            return false;
        }

        register = inputs[0];
        return true;
    }

    private static bool TryGetOutputRegister(
        Aarch64Instruction instruction,
        out Aarch64RegisterView register)
    {
        register = default;
        var outputs = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput
                && operand.Register is { } value
                && value.Class == Aarch64RegisterClass.General
                && value.Role == Aarch64RegisterRole.None)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        if (outputs.Length != 1)
        {
            return false;
        }

        register = outputs[0];
        return true;
    }

    private static bool TryGetRegisterAdd(
        Aarch64Instruction instruction,
        out Aarch64RegisterView baseRegister,
        out Aarch64RegisterView loadedRegister)
    {
        baseRegister = default;
        loadedRegister = default;
        if (!string.Equals(instruction.Mnemonic, "add", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var inputs = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register is { } value
                && value.Class == Aarch64RegisterClass.General
                && value.Role == Aarch64RegisterRole.None)
            .ToArray();
        if (inputs.Length != 2
            || !HasIdentityRegisterModifier(inputs[0])
            || !HasIdentityRegisterModifier(inputs[1])
            || instruction.Operands.Any(operand => operand.RegisterModifierKind is not null
                && !HasIdentityRegisterModifier(operand)))
        {
            return false;
        }

        baseRegister = inputs[0].Register!.Value;
        loadedRegister = inputs[1].Register!.Value;
        return true;
    }

    private static bool HasIdentityRegisterModifier(Aarch64SemanticOperand operand) =>
        operand.RegisterModifierKind is null
        || operand.RegisterModifierAmount == 0
            && operand.RegisterModifierKind is ("Lsl" or "Uxtx" or "Sxtx");

    private static bool TryGetImmediateAdd(
        Aarch64Instruction instruction,
        Aarch64RegisterView expectedBase,
        out ulong immediate)
    {
        immediate = default;
        if (!string.Equals(instruction.Mnemonic, "add", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var output = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput
                && operand.Register == expectedBase)
            .ToArray();
        var input = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register == expectedBase)
            .ToArray();
        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate)
            .Select(operand => operand.Immediate)
            .ToArray();
        if (output.Length != 1
            || input.Length != 1
            || immediates.Length == 0
            || immediates[0] is not >= 0)
        {
            return false;
        }

        immediate = checked((ulong)immediates[0]!.Value);
        return true;
    }

    private static bool TryGetDirectTarget(
        Aarch64Instruction instruction,
        out VirtualAddress target)
    {
        target = default;
        if (instruction.DirectTarget is not { } direct)
        {
            return false;
        }

        target = new VirtualAddress(direct);
        return true;
    }

    private static bool TryAddSigned(
        ulong value,
        long delta,
        out ulong result)
    {
        if (delta >= 0)
        {
            var amount = checked((ulong)delta);
            if (value > ulong.MaxValue - amount)
            {
                result = default;
                return false;
            }

            result = value + amount;
            return true;
        }

        var magnitude = checked((ulong)(-(delta + 1))) + 1;
        if (value < magnitude)
        {
            result = default;
            return false;
        }

        result = value - magnitude;
        return true;
    }
}
