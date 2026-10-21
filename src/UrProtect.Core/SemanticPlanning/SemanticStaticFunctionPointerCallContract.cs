using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>
/// Owns the static local function-pointer proof independently of dynamic-import
/// and runtime-resolved indirect-call contracts.
/// </summary>
public static class SemanticStaticFunctionPointerCallContract
{
    private const uint AdrPrelPgHi21 = ElfConstants.RArm64AdrPrelPgHi21;
    private const uint AddAbsLo12Nc = ElfConstants.RArm64AddAbsLo12Nc;
    private const uint StbLocal = 0;
    private const byte SttFunction = 2;
    private const byte StvDefault = 0;
    private const byte StvInternal = 1;
    private const byte StvHidden = 2;
    private const byte StvProtected = 3;
    private const uint ShtProgbits = 1;
    private const uint ShtSymtab = 2;
    private const uint ShtRela = 4;
    private const ulong ShfExecInstr = 0x4;
    private const int RelaEntrySize = 24;
    private const int MaximumSelectedFunctionsToRevalidate = 4096;
    public const string ProofKind = "aarch64-static-function-pointer-section-relocation-owner-v1";

    public static void ValidateExtensionFields(
        SemanticStaticFunctionPointerCallExtension extension,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(extension);
        ArgumentNullException.ThrowIfNull(diagnostics);
        if (!extension.HasStructuredProof
            || extension.SourceRange.VirtualAddress != extension.CallAddress
            || extension.SourceIdentity != SemanticEntityId.Instruction(extension.CallAddress)
            || !extension.SourceRange.IsInstructionRange
            || extension.OwnerFunction.Table != ElfSymbolTableKind.Dynamic
            || extension.OwnerFunction.Binding == StbLocal
            || extension.OwnerFunction.Name.Length == 0
            || extension.OwnerFunction.Size == 0
            || extension.OwnerFunction.Value > ulong.MaxValue - extension.OwnerFunction.Size
            || extension.StackSlotOffset < 0
            || extension.RelocationSectionHeader.Type != ShtRela
            || extension.RelocationSectionHeader.EntrySize != RelaEntrySize
            || extension.RelocationSectionHeader.Size == 0
            || extension.RelocationSectionHeader.Size % RelaEntrySize != 0
            || extension.RelocationSectionHeader.Offset > ulong.MaxValue - extension.RelocationSectionHeader.Size
            || extension.RelocationSectionHeader.Link != extension.SymbolTableSectionIndex
            || extension.RelocationSectionHeader.Info != extension.OwnerFunction.SectionIndex
            || extension.SymbolTableSectionHeader.Type != ShtSymtab
            || extension.SymbolTableSectionHeader.EntrySize != ElfConstants.SymbolEntrySize64
            || extension.SymbolTableSectionHeader.Size == 0
            || extension.SymbolTableSectionHeader.Size % ElfConstants.SymbolEntrySize64 != 0
            || extension.SymbolTableSectionHeader.Offset > ulong.MaxValue - extension.SymbolTableSectionHeader.Size
            || extension.RelocationSectionIndex < 0
            || extension.CallerSectionHeader.Type != ShtProgbits
            || (extension.CallerSectionHeader.Flags & ShfExecInstr) == 0
            || extension.TargetSectionHeader.Type != ShtProgbits
            || (extension.TargetSectionHeader.Flags & ShfExecInstr) == 0
            || extension.OwnerFunction.SectionIndex == 0
            || !SectionContains(
                extension.CallerSectionHeader,
                extension.OwnerFunction.Value,
                extension.OwnerFunction.Size)
            || extension.ProducerAddresses.Count != 4
            || !IsStrictlyContiguous(extension.ProducerAddresses.Select(address => address.Value))
            || extension.ProducerAddresses[^1].Value > ulong.MaxValue - sizeof(uint)
            || extension.CallAddress.Value != extension.ProducerAddresses[^1].Value + sizeof(uint)
            || extension.TargetRegister.Class != Aarch64RegisterClass.General
            || extension.TargetRegister.Role != Aarch64RegisterRole.None
            || extension.TargetRegister.Width != 64
            || extension.TargetRegister.Index >= 31
            || extension.AdrpRelocation.SiteAddress != extension.ProducerAddresses[0].Value
            || extension.AddRelocation.SiteAddress != extension.ProducerAddresses[1].Value
            || !RelocationRowMatches(extension.AdrpRelocation, extension, AdrPrelPgHi21)
            || !RelocationRowMatches(extension.AddRelocation, extension, AddAbsLo12Nc)
            || extension.AdrpRelocation.Addend != 0
            || extension.AddRelocation.Addend != 0
            || extension.AdrpRelocation.IsPlt
            || extension.AddRelocation.IsPlt
            || extension.AdrpRelocation.SymbolIndex == 0
            || extension.AdrpRelocation.SymbolIndex != extension.AddRelocation.SymbolIndex
            || extension.AdrpRelocation.Info != ((ulong)extension.AdrpRelocation.SymbolIndex << 32 | AdrPrelPgHi21)
            || extension.AddRelocation.Info != ((ulong)extension.AddRelocation.SymbolIndex << 32 | AddAbsLo12Nc)
            || extension.AdrpRelocation.Name.Length == 0
            || extension.AdrpRelocation.Name != extension.AddRelocation.Name
            || extension.AdrpRelocation.SymbolNameOffset != extension.AddRelocation.SymbolNameOffset
            || extension.AdrpRelocation.SymbolInfo != extension.AddRelocation.SymbolInfo
            || extension.AdrpRelocation.SymbolOther != extension.AddRelocation.SymbolOther
            || extension.AdrpRelocation.SymbolSectionIndex != extension.AddRelocation.SymbolSectionIndex
            || extension.AdrpRelocation.SymbolValue != extension.AddRelocation.SymbolValue
            || extension.AdrpRelocation.SymbolSize != extension.AddRelocation.SymbolSize
            || !IsNonPreemptibleFunction(extension.AdrpRelocation.SymbolInfo, extension.AdrpRelocation.SymbolOther)
            || extension.AdrpRelocation.SymbolSectionIndex == 0
            || extension.AdrpRelocation.SymbolSize == 0
            || extension.AdrpRelocation.SymbolValue > ulong.MaxValue - extension.AdrpRelocation.SymbolSize
            || !SectionContains(
                extension.TargetSectionHeader,
                extension.AdrpRelocation.SymbolValue,
                extension.AdrpRelocation.SymbolSize)
            || extension.TargetSourceRange.VirtualAddress.Value != extension.AdrpRelocation.SymbolValue
            || extension.TargetSourceRange.Size != extension.AdrpRelocation.SymbolSize
            || !TrySectionFileOffset(
                extension.TargetSectionHeader,
                extension.AdrpRelocation.SymbolValue,
                out var expectedTargetFileOffset)
            || extension.TargetSourceRange.FileOffset.Value != expectedTargetFileOffset
            || extension.TargetMappingIdentity != TargetIdentity(extension)
            || extension.TargetMappingIdentity.Kind != SemanticEntityKind.RelocationTarget
            || extension.TargetOutputRange != extension.TargetSourceRange
            || !extension.TargetSourceRange.TryGetFileEnd(out _)
            || !extension.TargetSourceRange.TryGetVirtualEnd(out _)
            || extension.CallerSectionHeader.Offset > ulong.MaxValue - extension.CallerSectionHeader.Size
            || extension.TargetSectionHeader.Offset > ulong.MaxValue - extension.TargetSectionHeader.Size
            || extension.AdrpRelocation.SymbolIndex >= extension.SymbolTableSectionHeader.Size / ElfConstants.SymbolEntrySize64
            || extension.MappingPolicy != SemanticStaticFunctionPointerMappingPolicy.PreserveOriginalAddress)
        {
            Error(
                diagnostics,
                "The static function-pointer extension does not carry one exact typed same-image owner proof.",
                extension.CallAddress.Value);
        }
    }

    public static void ValidatePlan(SemanticRewritePlan plan, DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var staticOwners = plan.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>().ToArray();
        foreach (var owner in staticOwners)
        {
            ValidateExtensionFields(owner, diagnostics);
        }

        var indirectByCall = plan.Extensions.OfType<SemanticIndirectTargetExtension>()
            .GroupBy(extension => (extension.SourceInstruction, extension.SourceAddress.Value))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var staticByCall = staticOwners
            .GroupBy(owner => (owner.SourceIdentity, owner.CallAddress.Value))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var dynamicByCall = plan.Extensions.OfType<SemanticDynamicImportCallExtension>()
            .GroupBy(owner => (owner.CallIdentity, owner.CallAddress.Value))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var callsByCall = plan.Instructions.Where(IsIndirectCallInstruction)
            .GroupBy(instruction => (SemanticEntityId.Instruction(instruction.SourceVirtualAddress), instruction.SourceVirtualAddress.Value))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var mappingsByIdentity = plan.AddressMap.Entries
            .GroupBy(entry => entry.Identity)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var callerMappingsByRange = plan.AddressMap.Functions
            .GroupBy(entry => (entry.SourceRange.VirtualAddress.Value, entry.SourceRange.Size))
            .ToDictionary(group => group.Key, group => group.ToArray());

        foreach (var (callKey, owners) in staticByCall)
        {
            if (owners.Length != 1)
            {
                Error(diagnostics, "A selected BLR has duplicate static function-pointer owners.", callKey.Value);
                continue;
            }

            var owner = owners[0];
            var calls = callsByCall.GetValueOrDefault(callKey) ?? Array.Empty<SemanticInstruction>();
            var targets = indirectByCall.GetValueOrDefault(callKey) ?? Array.Empty<SemanticIndirectTargetExtension>();
            var dynamicOwners = dynamicByCall.GetValueOrDefault(callKey) ?? Array.Empty<SemanticDynamicImportCallExtension>();
            var mappings = mappingsByIdentity.GetValueOrDefault(owner.TargetMappingIdentity) ?? Array.Empty<AddressMapEntry>();
            var callerMappings = callerMappingsByRange.GetValueOrDefault((owner.OwnerFunction.Value, owner.OwnerFunction.Size))
                ?? Array.Empty<AddressMapEntry>();
            if (calls.Length != 1
                || owner.CallAddress != calls[0].SourceVirtualAddress
                || owner.SourceRange != calls[0].SourceRange
                || targets.Length != 1
                || dynamicOwners.Length != 0
                || !targets[0].Target.IsExact
                || targets[0].Target.Identity != owner.TargetMappingIdentity
                || targets[0].Target.SourceAddress?.Value != owner.TargetSourceRange.VirtualAddress.Value
                || mappings.Length != 1
                || mappings[0].SourceRange != owner.TargetSourceRange
                || mappings[0].OutputRange != owner.TargetOutputRange
                || mappings[0].PlannedIdentity != owner.TargetMappingIdentity
                || callerMappings.Length != 1)
            {
                Error(diagnostics, "The static BLR owner, exact semantic target, preserved callback mapping, selected caller, and source instruction disagree.", callKey.Value);
            }
        }
    }

    public static bool ValidateSourceElf(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var owners = snapshot.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>().ToArray();
        if (owners.Length == 0)
        {
            return true;
        }

        var valid = true;
        foreach (var ownerGroup in owners.GroupBy(owner => owner.OwnerFunction))
        {
            var ownerFunction = ownerGroup.Key;
            var sourceRows = source.FunctionSymbols
                .Where(symbol => symbol == ownerFunction)
                .ToArray();
            if (sourceRows.Length != 1)
            {
                Error(diagnostics, "The static caller symbol row is not independently present exactly once in the parsed source ELF.", ownerFunction.Value);
                valid = false;
                continue;
            }

            var analysis = new Aarch64FunctionAnalyzer().Analyze(source, sourceRows[0]);
            var expected = analysis.StaticFunctionPointerCallResolutions
                .OrderBy(resolution => resolution.SourceAddress)
                .ToArray();
            var carried = ownerGroup.OrderBy(owner => owner.CallAddress.Value).ToArray();
            if (expected.Length != carried.Length)
            {
                Error(diagnostics, "Source reanalysis found a different number of static same-image function-pointer BLR owners.", ownerFunction.Value);
                valid = false;
            }

            foreach (var owner in carried)
            {
                var matching = expected.Where(resolution => resolution.SourceAddress == owner.CallAddress.Value).ToArray();
                if (matching.Length != 1 || !MatchesSourceResolution(source, owner, analysis, matching[0]))
                {
                    Error(diagnostics, "The carried static function-pointer owner differs from independent source CFG, byte, relocation, symbol, or range revalidation.", owner.CallAddress.Value);
                    valid = false;
                }
            }
        }

        return valid && !diagnostics.HasErrors;
    }

    public static bool ValidateSourceCallOwnershipCompleteness(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        IReadOnlyList<SemanticSourceRange> selectedRanges,
        IReadOnlyList<Aarch64FunctionInstruction> sourceInstructions,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(selectedRanges);
        ArgumentNullException.ThrowIfNull(sourceInstructions);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var staticOwners = snapshot.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>()
            .GroupBy(owner => (owner.SourceIdentity, owner.CallAddress.Value))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var indirectTargets = snapshot.Extensions.OfType<SemanticIndirectTargetExtension>()
            .GroupBy(owner => (owner.SourceInstruction, owner.SourceAddress.Value))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var semanticInstructions = snapshot.Instructions
            .Where(IsIndirectCallInstruction)
            .GroupBy(instruction => instruction.SourceVirtualAddress.Value)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var instructionMaps = snapshot.AddressMap.Entries
            .Where(entry => entry.Identity.Kind == SemanticEntityKind.Instruction)
            .GroupBy(entry => entry.SourceRange.VirtualAddress.Value)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var selectedRangeSet = selectedRanges.ToHashSet();
        var sourceCallAddresses = sourceInstructions.Where(IsIndirectCallInstruction)
            .Select(instruction => instruction.Address)
            .Distinct()
            .Order()
            .ToArray();
        var selectedCallAddressSet = sourceCallAddresses.ToHashSet();
        var sourceInstructionsByAddress = sourceInstructions
            .GroupBy(instruction => instruction.Address)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var selectedFunctions = snapshot.AddressMap.Functions
            .Where(function => selectedRangeSet.Contains(function.SourceRange)
                && ContainsAnyCall(function.SourceRange, sourceCallAddresses))
            .ToArray();
        if (selectedFunctions.Length > MaximumSelectedFunctionsToRevalidate)
        {
            Error(diagnostics, "Static function-pointer ownership revalidation exceeds its selected-function bound.", 0);
            return false;
        }
        var expectedStaticCalls = new HashSet<ulong>();
        var validatedInstructionBudget = 0UL;
        var valid = true;

        foreach (var functionEntry in selectedFunctions)
        {
            var functionSymbols = source.FunctionSymbols.Where(symbol =>
                (symbol.Name == functionEntry.Identity.Value
                    || $"{symbol.Table}:{symbol.TableIndex}:0x{symbol.Value:X}" == functionEntry.Identity.Value)
                && symbol.Value == functionEntry.SourceRange.VirtualAddress.Value
                && symbol.Size == functionEntry.SourceRange.Size).ToArray();
            if (functionSymbols.Length == 0)
            {
                Error(diagnostics, "A selected static-callback scan has no exact source function symbol owner.", functionEntry.SourceRange.VirtualAddress.Value);
                valid = false;
                continue;
            }

            var functionInstructionCount = functionEntry.SourceRange.Size / sizeof(uint);
            if (functionEntry.SourceRange.Size % sizeof(uint) != 0
                || functionInstructionCount > (ulong)SemanticPlanSnapshotLimits.MaximumInstructions
                || validatedInstructionBudget > (ulong)SemanticPlanSnapshotLimits.MaximumInstructions - functionInstructionCount)
            {
                Error(diagnostics, "Static function-pointer ownership revalidation exceeds its bounded selected-instruction budget.", functionEntry.SourceRange.VirtualAddress.Value);
                valid = false;
                break;
            }

            validatedInstructionBudget += functionEntry.SourceRange.Size / sizeof(uint);
            var analysis = new Aarch64FunctionAnalyzer().Analyze(source, functionSymbols[0]);
            foreach (var resolution in analysis.StaticFunctionPointerCallResolutions)
            {
                if (selectedCallAddressSet.Contains(resolution.SourceAddress))
                {
                    expectedStaticCalls.Add(resolution.SourceAddress);
                }
            }
        }

        foreach (var address in expectedStaticCalls)
        {
            var callIdentity = SemanticEntityId.Instruction(new VirtualAddress(address));
            var key = (callIdentity, address);
            var owners = staticOwners.GetValueOrDefault(key) ?? Array.Empty<SemanticStaticFunctionPointerCallExtension>();
            if (owners.Length != 1)
            {
                Error(diagnostics, "Independent source CFG analysis found a static local callback BLR without exactly one carried typed owner.", address);
                valid = false;
                continue;
            }

            var sourceMatches = (sourceInstructionsByAddress.GetValueOrDefault(address) ?? Array.Empty<Aarch64FunctionInstruction>())
                .Where(IsIndirectCallInstruction)
                .ToArray();
            var semanticMatches = semanticInstructions.GetValueOrDefault(address) ?? Array.Empty<SemanticInstruction>();
            var mapMatches = instructionMaps.GetValueOrDefault(address) ?? Array.Empty<AddressMapEntry>();
            var targetMatches = indirectTargets.GetValueOrDefault(key) ?? Array.Empty<SemanticIndirectTargetExtension>();
            var owner = owners[0];
            var targetMaps = snapshot.AddressMap.Entries.Where(entry => entry.Identity == owner.TargetMappingIdentity).ToArray();
            if (sourceMatches.Length != 1
                || semanticMatches.Length != 1
                || mapMatches.Length != 1
                || mapMatches[0].SourceRange.FileOffset != new FileOffset(sourceMatches[0].FileOffset)
                || mapMatches[0].SourceRange.Size != sizeof(uint)
                || targetMatches.Length != 1
                || !targetMatches[0].Target.IsExact
                || targetMatches[0].Target.Identity != owner.TargetMappingIdentity
                || targetMatches[0].Target.SourceAddress?.Value != owner.TargetSourceRange.VirtualAddress.Value
                || targetMaps.Length != 1
                || targetMaps[0].SourceRange != owner.TargetSourceRange
                || targetMaps[0].OutputRange != owner.TargetOutputRange
                || owner.CallAddress.Value != address
                || owner.SourceRange != semanticMatches[0].SourceRange)
            {
                Error(diagnostics, "A source static callback BLR is missing an exact semantic instruction, owner, target, or preserve-original mapping carrier at publication.", address);
                valid = false;
            }
        }

        foreach (var owner in snapshot.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>())
        {
            if (!expectedStaticCalls.Contains(owner.CallAddress.Value)
                || !(sourceInstructionsByAddress.GetValueOrDefault(owner.CallAddress.Value)
                    ?? Array.Empty<Aarch64FunctionInstruction>()).Any(IsIndirectCallInstruction))
            {
                Error(diagnostics, "A carried static function-pointer owner does not correspond to one independently analyzed selected source BLR.", owner.CallAddress.Value);
                valid = false;
            }
        }

        return valid && !diagnostics.HasErrors;
    }

    private static bool MatchesSourceResolution(
        ElfFile source,
        SemanticStaticFunctionPointerCallExtension owner,
        Aarch64FunctionAnalysis analysis,
        Aarch64StaticFunctionPointerCallResolution resolution)
    {
        var callSource = analysis.Instructions.SingleOrDefault(instruction => instruction.Address == resolution.SourceAddress);
        var symbol = resolution.AdrpRelocation.Symbol;
        if (symbol is null)
        {
            return false;
        }

        var expectedTargetRange = new SemanticSourceRange(
            resolution.TargetFileOffset,
            new VirtualAddress(resolution.TargetAddress),
            resolution.TargetSize);
        return owner.SourceIdentity == SemanticEntityId.Instruction(new VirtualAddress(resolution.SourceAddress))
            && owner.SourceRange == new SemanticSourceRange(
                new FileOffset(callSource.FileOffset),
                new VirtualAddress(callSource.Address),
                sizeof(uint))
            && owner.TargetRegister == resolution.TargetRegister
            && owner.ProducerAddresses.Select(address => address.Value).SequenceEqual(resolution.ProducerAddresses)
            && owner.StackSlotOffset == resolution.StackSlotOffset
            && owner.OwnerFunction == resolution.OwnerFunction
            && owner.RelocationSectionIndex == resolution.AdrpRelocation.RelocationSectionIndex
            && owner.RelocationSectionHeader == resolution.RelocationSectionHeader
            && owner.SymbolTableSectionIndex == resolution.AdrpRelocation.SymbolTableSectionIndex
            && owner.SymbolTableSectionHeader == resolution.SymbolTableSectionHeader
            && owner.CallerSectionHeader == resolution.CallerSectionHeader
            && owner.TargetSectionHeader == resolution.TargetSectionHeader
            && owner.AdrpRelocation == ToSemanticRow(resolution.AdrpRelocation)
            && owner.AddRelocation == ToSemanticRow(resolution.AddRelocation)
            && owner.TargetSourceRange == expectedTargetRange
            && owner.TargetOutputRange == expectedTargetRange
            && owner.TargetMappingIdentity == TargetIdentity(owner)
            && owner.MappingPolicy == SemanticStaticFunctionPointerMappingPolicy.PreserveOriginalAddress
            && owner.OwnerFunction.SectionIndex < source.SectionHeaders.Count
            && symbol.SectionIndex < source.SectionHeaders.Count
            && source.SectionHeaders[owner.OwnerFunction.SectionIndex] == owner.CallerSectionHeader
            && source.SectionHeaders[symbol.SectionIndex] == owner.TargetSectionHeader;
    }

    private static SemanticStaticFunctionPointerRelocationRow ToSemanticRow(ElfSectionRelocation row)
    {
        if (row.Symbol is not { } symbol)
        {
            throw new InvalidOperationException("A validated static function-pointer relocation lost its symbol row.");
        }

        return new SemanticStaticFunctionPointerRelocationRow(
            row.RelocationSectionIndex,
            row.RelocationSectionFileOffset,
            row.RelocationSectionAddress,
            row.SymbolTableSectionIndex,
            row.TargetSectionIndex,
            row.Relocation.SourceAddress,
            row.Relocation.Offset,
            row.Relocation.Info,
            row.Relocation.Type,
            row.Relocation.SymbolIndex,
            row.Relocation.Addend,
            row.Relocation.IsPlt,
            symbol.NameOffset,
            symbol.Name,
            symbol.Info,
            symbol.Other,
            symbol.SectionIndex,
            symbol.Value,
            symbol.Size);
    }

    private static SemanticEntityId TargetIdentity(SemanticStaticFunctionPointerCallExtension owner) =>
        SemanticEntityId.RelocationTarget(
            $"static-function:{owner.SymbolTableSectionIndex}:{owner.AdrpRelocation.SymbolIndex}:{owner.AdrpRelocation.Name}");

    private static bool RelocationRowMatches(
        SemanticStaticFunctionPointerRelocationRow row,
        SemanticStaticFunctionPointerCallExtension owner,
        uint expectedType)
    {
        if (row.RelocationSectionIndex != owner.RelocationSectionIndex
            || row.SymbolTableSectionIndex != owner.SymbolTableSectionIndex
            || row.TargetSectionIndex != owner.OwnerFunction.SectionIndex
            || row.RelocationSectionFileOffset.Value != owner.RelocationSectionHeader.Offset
            || row.RelocationSectionAddress != new VirtualAddress(owner.RelocationSectionHeader.Address)
            || row.Type != expectedType
            || row.SymbolIndex == 0
            || row.SymbolIndex != unchecked((uint)(row.Info >> 32))
            || row.Type != unchecked((uint)row.Info)
            || row.RelocationSourceAddress < row.RelocationSectionAddress.Value
            || owner.RelocationSectionHeader.Size == 0)
        {
            return false;
        }

        var rowOffset = row.RelocationSourceAddress - row.RelocationSectionAddress.Value;
        return rowOffset < owner.RelocationSectionHeader.Size
            && rowOffset % RelaEntrySize == 0
            && row.Name.Length > 0
            && row.SymbolNameOffset != 0
            && row.SymbolSectionIndex != 0
            && row.SymbolValue == owner.TargetSourceRange.VirtualAddress.Value
            && row.SymbolSize == owner.TargetSourceRange.Size;
    }

    private static bool IsNonPreemptibleFunction(byte info, byte other)
    {
        var binding = (byte)(info >> 4);
        var type = (byte)(info & 0x0F);
        var visibility = (byte)(other & 0x03);
        return type == SttFunction
            && (binding == StbLocal
                || visibility is StvInternal or StvHidden or StvProtected);
    }

    private static bool SectionContains(SectionHeader section, ulong address, ulong size) =>
        size > 0
        && address >= section.Address
        && address <= ulong.MaxValue - size
        && address - section.Address <= section.Size
        && size <= section.Size - (address - section.Address);

    private static bool TrySectionFileOffset(SectionHeader section, ulong address, out ulong fileOffset)
    {
        fileOffset = default;
        if (address < section.Address
            || section.Offset > ulong.MaxValue - (address - section.Address))
        {
            return false;
        }

        fileOffset = section.Offset + (address - section.Address);
        return true;
    }

    private static bool IsStrictlyContiguous(IEnumerable<ulong> addresses)
    {
        var values = addresses.ToArray();
        if (values.Length == 0)
        {
            return false;
        }

        for (var index = 1; index < values.Length; index++)
        {
            if (values[index - 1] > ulong.MaxValue - sizeof(uint)
                || values[index] != values[index - 1] + sizeof(uint))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsIndirectCallInstruction(SemanticInstruction instruction) =>
        instruction.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
        && string.Equals(instruction.Mnemonic, "BLR", StringComparison.OrdinalIgnoreCase);

    private static bool IsIndirectCallInstruction(Aarch64FunctionInstruction instruction) =>
        instruction.Decode.Instruction is { ControlFlow: Aarch64ControlFlowKind.IndirectBranch } decoded
        && string.Equals(decoded.Mnemonic, "BLR", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAnyCall(SemanticSourceRange range, IReadOnlyList<ulong> sortedAddresses)
    {
        var low = 0;
        var high = sortedAddresses.Count;
        while (low < high)
        {
            var middle = low + ((high - low) / 2);
            if (sortedAddresses[middle] < range.VirtualAddress.Value)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        return low < sortedAddresses.Count && Contains(range, sortedAddresses[low], sizeof(uint));
    }

    private static bool Contains(SemanticSourceRange range, ulong address, ulong size) =>
        address >= range.VirtualAddress.Value
        && address - range.VirtualAddress.Value <= range.Size
        && size <= range.Size - (address - range.VirtualAddress.Value);

    private static void Error(DiagnosticBag diagnostics, string message, ulong offset) =>
        diagnostics.Error(DiagnosticCode.IndirectTargetUnresolved, message, offset);
}
