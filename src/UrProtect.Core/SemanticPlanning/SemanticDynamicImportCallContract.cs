using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>Local snapshot and independent source-ELF validation for import-call owner links.</summary>
internal static class SemanticDynamicImportCallContract
{
    private const byte UndefinedSectionIndex = 0;
    private const byte GlobalBinding = 1;
    private const byte WeakBinding = 2;
    private const byte NoType = 0;
    private const byte FunctionType = 2;
    private const byte DefaultVisibility = 0;
    private const ulong GotPointerSize = sizeof(ulong);
    private const ulong InstructionSize = sizeof(uint);
    private const int MaximumDynamicImportOwners = 256;
    private const int MaximumAggregateProducerAddresses = 4096;
    private const int MaximumSourceScanInstructionsPerOwner = 256;
    private const int MaximumAggregateSourceScanInstructions = 16_384;

    public static void ValidateExtensionFields(
        SemanticDynamicImportCallExtension extension,
        DiagnosticBag diagnostics)
    {
        var offset = extension.CallAddress.Value;
        if (extension.CallIdentity.Kind != SemanticEntityKind.Instruction
            || string.IsNullOrWhiteSpace(extension.CallIdentity.Value)
            || extension.CallIdentity != SemanticEntityId.Instruction(extension.CallAddress))
        {
            Error(diagnostics, "The dynamic-import owner has an invalid call identity.", offset);
        }

        if (extension.TargetRegister.Class != Aarch64RegisterClass.General
            || extension.TargetRegister.Index > 30
            || extension.TargetRegister.Width != 64
            || extension.TargetRegister.Role != Aarch64RegisterRole.None)
        {
            Error(diagnostics, "The dynamic-import call target is not one ordinary 64-bit AArch64 general register.", offset);
        }

        if (extension.ProducerAddresses.Count is 0 or > SemanticPlanSnapshotLimits.MaximumProducerAddresses
            || !extension.ProducerAddresses.SequenceEqual(
                extension.ProducerAddresses.Distinct().OrderBy(address => address.Value))
            || !extension.ProducerAddresses.Contains(extension.PageProducerAddress)
            || !extension.ProducerAddresses.Contains(extension.LoadProducerAddress)
            || extension.ProducerAddresses.Contains(extension.CallAddress)
            || extension.ProducerAddresses[^1].Value >= extension.CallAddress.Value
            || extension.PageProducerAddress.Value >= extension.LoadProducerAddress.Value
            || extension.PageProducerAddress == extension.LoadProducerAddress)
        {
            Error(diagnostics, "The dynamic-import owner has an empty, duplicated, out-of-order, or incomplete producer chain.", offset);
        }

        if ((extension.PageAddress.Value & 0xFFFUL) != 0
            || extension.GotRange.Size != GotPointerSize
            || extension.GotRange.VirtualAddress.Value != extension.RelocationOffset
            || extension.GotRange.VirtualAddress.Value < extension.PageAddress.Value
            || extension.GotRange.VirtualAddress.Value - extension.PageAddress.Value >= 0x1000
            || !IsValidRange(extension.GotRange))
        {
            Error(diagnostics, "The dynamic-import GOT range is not one aligned-page, file-backed-width semantic range.", offset);
        }

        var expectedSiteIdentity = SemanticEntityId.RelocationSite(FormatAddress(extension.RelocationOffset));
        if (extension.RelocationSiteIdentity != expectedSiteIdentity
            || extension.RelocationOffset != extension.GotRange.VirtualAddress.Value
            || extension.RelocationInfo != (((ulong)extension.SymbolIndex << 32) | ElfConstants.RArm64GlobDat)
            || extension.RelocationAddend != 0
            || extension.RelocationIsPlt)
        {
            Error(diagnostics, "The dynamic-import owner does not carry one exact non-PLT R_AARCH64_GLOB_DAT RELA tuple for its GOT slot.", offset);
        }

        if (extension.SymbolIndex == 0
            || string.IsNullOrWhiteSpace(extension.SymbolName)
            || extension.SymbolName.Length > SemanticPlanSnapshotLimits.MaximumStringBytes
            || extension.SymbolInfo != (byte)((extension.SymbolBinding << 4) | extension.SymbolType)
            || extension.SymbolBinding is not (GlobalBinding or WeakBinding)
            || extension.SymbolType is not (NoType or FunctionType)
            || extension.SymbolVisibility != DefaultVisibility
            || (extension.SymbolOther & 0x3) != extension.SymbolVisibility
            || extension.SymbolSectionIndex != UndefinedSectionIndex
            || extension.SymbolValue != 0)
        {
            Error(diagnostics, "The dynamic-import owner does not carry the supported undefined global/weak default-visible function-or-NOTYPE symbol identity.", offset);
        }

        if (!TryValidateVersionFacts(extension, out var versionError))
        {
            Error(diagnostics, versionError!, offset);
        }
    }

    private static bool ValidateImportWorkBounds(
        IReadOnlyList<SemanticDynamicImportCallExtension> imports,
        DiagnosticBag diagnostics)
    {
        if (imports.Count > MaximumDynamicImportOwners)
        {
            Error(diagnostics, "The semantic plan exceeds the bounded dynamic-import owner count.");
            return false;
        }

        long aggregateProducers = 0;
        long aggregateScanInstructions = 0;
        foreach (var import in imports)
        {
            aggregateProducers += import.ProducerAddresses.Count;
            var page = import.PageProducerAddress.Value;
            var call = import.CallAddress.Value;
            if (page >= call || (call - page) % InstructionSize != 0)
            {
                Error(diagnostics, "A dynamic-import producer interval is not ordered and instruction aligned.", call);
                return false;
            }

            var scanCount = ((call - page) / InstructionSize) + 1;
            if (scanCount > MaximumSourceScanInstructionsPerOwner)
            {
                Error(diagnostics, "A dynamic-import producer interval exceeds the bounded source instruction scan.", call);
                return false;
            }

            aggregateScanInstructions += checked((long)scanCount);
            if (aggregateProducers > MaximumAggregateProducerAddresses
                || aggregateScanInstructions > MaximumAggregateSourceScanInstructions)
            {
                Error(diagnostics, "The semantic plan exceeds the aggregate dynamic-import producer validation work limit.", call);
                return false;
            }
        }

        return true;
    }

    private static Dictionary<VirtualAddress, SemanticInstruction[]> IndexInstructions(
        IEnumerable<SemanticInstruction> instructions) =>
        instructions.GroupBy(instruction => instruction.SourceVirtualAddress)
            .ToDictionary(group => group.Key, group => group.ToArray());

    private static Dictionary<SemanticSourceRange, AddressMapEntry[]> IndexAddressMapRanges(
        IEnumerable<AddressMapEntry> entries) =>
        entries.GroupBy(entry => entry.SourceRange)
            .ToDictionary(group => group.Key, group => group.ToArray());

    public static void ValidatePlan(SemanticRewritePlan plan, DiagnosticBag diagnostics)
    {
        var imports = plan.Extensions.OfType<SemanticDynamicImportCallExtension>().ToArray();
        if (!ValidateImportWorkBounds(imports, diagnostics))
        {
            return;
        }

        var importCalls = imports.Select(import => (import.CallIdentity, import.CallAddress.Value)).ToHashSet();
        var importSites = imports.Select(import => import.RelocationSiteIdentity).ToHashSet();
        var callTargetsByIdentity = plan.Extensions.OfType<SemanticIndirectTargetExtension>()
            .GroupBy(target => (target.SourceInstruction, target.SourceAddress))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var relocationsBySite = plan.Extensions.OfType<SemanticRelocationBindingExtension>()
            .GroupBy(relocation => relocation.RelocationSite)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var instructionsByAddress = IndexInstructions(plan.Instructions);
        var gotMapsByRange = IndexAddressMapRanges(plan.AddressMap.RelocationTargets);

        if (imports.GroupBy(import => (import.CallIdentity, import.CallAddress.Value)).Any(group => group.Count() != 1))
        {
            Error(diagnostics, "The semantic plan duplicates a typed dynamic-import call or RELA owner.");
        }

        foreach (var import in imports)
        {
            ValidateExtensionFields(import, diagnostics);
            if (!callTargetsByIdentity.TryGetValue((import.CallIdentity, import.CallAddress), out var callTargets)
                || callTargets.Length != 1
                || callTargets[0].Target.Resolution != SemanticTargetResolution.RuntimeResolved
                || !string.Equals(callTargets[0].Target.RuntimeBinding, import.RuntimeBinding, StringComparison.Ordinal))
            {
                Error(diagnostics, "A typed dynamic-import owner must pair uniquely with the exact runtime indirect target binding.", import.CallAddress.Value);
            }

            if (!relocationsBySite.TryGetValue(import.RelocationSiteIdentity, out var relocationExtensions)
                || relocationExtensions.Length != 1
                || !RelocationMatches(import, relocationExtensions[0].Binding))
            {
                Error(diagnostics, "A typed dynamic-import owner must pair uniquely with the exact semantic RELA relocation binding.", import.RelocationOffset);
            }

            ValidateCallAndProducerSemantics(import, instructionsByAddress, diagnostics);
            ValidatePlanAddressMap(import, plan.AddressMap, gotMapsByRange, diagnostics);
        }

        foreach (var target in plan.Extensions.OfType<SemanticIndirectTargetExtension>()
                     .Where(target => target.Target.Resolution == SemanticTargetResolution.RuntimeResolved
                         && target.Target.RuntimeBinding?.StartsWith("aarch64:elf-import:", StringComparison.Ordinal) == true))
        {
            if (!importCalls.Contains((target.SourceInstruction, target.SourceAddress.Value)))
            {
                Error(diagnostics, "A dynamic-import runtime target has no typed call-owner extension.", target.SourceAddress.Value);
            }
        }

        foreach (var relocation in plan.Extensions.OfType<SemanticRelocationBindingExtension>()
                     .Where(relocation => relocation.Binding.Target.Resolution == SemanticTargetResolution.RuntimeResolved
                         && relocation.Binding.Target.RuntimeBinding?.StartsWith("aarch64:elf-import:", StringComparison.Ordinal) == true))
        {
            if (!importSites.Contains(relocation.RelocationSite))
            {
                Error(diagnostics, "A dynamic-import RELA extension has no typed call-owner extension.", relocation.Binding.RelocationAddress?.Value);
            }
        }
    }

    public static bool ValidateSourceElf(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        DiagnosticBag diagnostics)
    {
        var imports = snapshot.Extensions.OfType<SemanticDynamicImportCallExtension>().ToArray();
        if (!ValidateImportWorkBounds(imports, diagnostics))
        {
            return false;
        }

        if (imports.Length == 0)
        {
            return !diagnostics.HasErrors;
        }

        if (!TryGetDynamicSymbolTableFacts(source, out var symbolTables, diagnostics))
        {
            return false;
        }

        var sourceRelocationsByOffset = source.RelaRelocations
            .GroupBy(relocation => relocation.Offset)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var instructionsByAddress = IndexInstructions(snapshot.Plan.Instructions);
        var gotMapsByRange = IndexAddressMapRanges(snapshot.AddressMap.RelocationTargets);
        var blocksByAddress = snapshot.AddressMap.BasicBlocks
            .OrderBy(entry => entry.SourceRange.VirtualAddress.Value)
            .ToArray();
        var valid = true;
        var decoder = new AsmStoneAdapter();
        foreach (var import in imports)
        {
            // ElfParser.ParseRelaRelocations only projects bounded DT_RELA/DT_JMPREL rows.
            // Exact SourceAddress plus !IsPlt in this tuple match therefore identifies the
            // declared non-PLT DT_RELA row; section RELA records are never in this collection.
            if (!sourceRelocationsByOffset.TryGetValue(import.RelocationOffset, out var sourceRelocations)
                || sourceRelocations.Length != 1
                || !RelocationTupleMatches(import, sourceRelocations[0]))
            {
                Error(diagnostics, "The typed dynamic-import RELA tuple does not match exactly one independently parsed non-PLT dynamic RELA row.", import.RelocationOffset);
                valid = false;
            }

            // DynamicSymbols and DynamicMetadata.StringTable are parsed from DT_SYMTAB/DT_STRTAB,
            // not section-header symbol/string tables; compare the complete exact row and name.
            if (import.SymbolIndex >= (uint)source.DynamicSymbols.Count)
            {
                Error(diagnostics, "The dynamic-import symbol index is outside the independently parsed DT_SYMTAB.", import.RelocationOffset);
                valid = false;
            }
            else
            {
                var symbol = source.DynamicSymbols[checked((int)import.SymbolIndex)];
                var rowMatches = TryValidateDynamicSymbolRow(source, symbolTables, import.SymbolIndex, symbol);
                var nameMatches = ElfParserUtilities.TryReadString(
                    symbolTables.StringTable,
                    symbol.Name,
                    out var sourceName);
                if (!rowMatches
                    || symbol.Name != import.SymbolNameOffset
                    || !nameMatches
                    || !string.Equals(sourceName, import.SymbolName, StringComparison.Ordinal)
                    || symbol.Info != import.SymbolInfo
                    || symbol.Other != import.SymbolOther
                    || (byte)(symbol.Info >> 4) != import.SymbolBinding
                    || (byte)(symbol.Info & 0x0F) != import.SymbolType
                    || (byte)(symbol.Other & 0x03) != import.SymbolVisibility
                    || symbol.SectionIndex != import.SymbolSectionIndex
                    || symbol.Value != import.SymbolValue
                    || symbol.Size != import.SymbolSize)
                {
                    Error(diagnostics, "The typed dynamic-import symbol identity differs from its exact bounded DT_SYMTAB/DT_STRTAB row.", import.RelocationOffset);
                    valid = false;
                }

                if (!TryProjectVersionFacts(source, import.SymbolIndex, out var versionIndex, out var versionRequirement, out var versionError)
                    || versionIndex != import.SymbolVersionIndexRaw
                    || versionRequirement != import.VersionRequirement)
                {
                    Error(diagnostics, versionError ?? "The typed dynamic-import symbol-version facts differ from the exact source DT_VERSYM/DT_VERNEED owner.", import.RelocationOffset);
                    valid = false;
                }
            }

            if (!TryGetUniqueSourceRange(source, import.GotRange.VirtualAddress.Value, GotPointerSize, out var gotFileOffset, requireWritable: true)
                || gotFileOffset != import.GotRange.FileOffset)
            {
                Error(diagnostics, "The imported GOT slot is not one uniquely file-backed writable PT_LOAD range at the carried source file offset.", import.GotRange.VirtualAddress.Value);
                valid = false;
            }

            if (!ValidateCompleteSourceProducerChain(
                    source,
                    snapshot,
                    import,
                    decoder,
                    instructionsByAddress,
                    blocksByAddress,
                    diagnostics))
            {
                valid = false;
            }

            if (!ValidateSourceAddressMap(import, snapshot.AddressMap, gotMapsByRange, diagnostics))
            {
                valid = false;
            }
        }

        return valid && !diagnostics.HasErrors;
    }

    internal static bool ValidateSourceCallOwnershipCompleteness(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        IReadOnlyList<SemanticSourceRange> selectedRanges,
        IReadOnlyList<Aarch64FunctionInstruction> sourceInstructions,
        DiagnosticBag diagnostics)
    {
        var carriedOwners = snapshot.Extensions
            .OfType<SemanticDynamicImportCallExtension>()
            .Select(owner => (CallAddress: owner.CallAddress.Value, RelocationOffset: owner.RelocationOffset))
            .ToArray();
        var dynamicGotOffsets = source.RelaRelocations
            .Where(relocation => !relocation.IsPlt && relocation.Type == ElfConstants.RArm64GlobDat)
            .Select(relocation => relocation.Offset)
            .ToHashSet();
        if (dynamicGotOffsets.Count == 0)
        {
            if (carriedOwners.Length > 0)
            {
                Error(diagnostics, "The semantic snapshot carries dynamic-import call owners but the source has no non-PLT GLOB_DAT relocation rows.");
                return false;
            }

            return true;
        }

        var dynamicGotPages = dynamicGotOffsets
            .Select(offset => offset & ~0xFFFUL)
            .ToHashSet();
        var orderedRanges = selectedRanges
            .OrderBy(range => range.VirtualAddress.Value)
            .ToArray();
        var instructionsByAddress = new Dictionary<ulong, Aarch64FunctionInstruction>();
        foreach (var instruction in sourceInstructions)
        {
            if (!instructionsByAddress.TryAdd(instruction.Address, instruction))
            {
                Error(diagnostics, "The selected source regions duplicate an instruction address during dynamic-import ownership validation.", instruction.Address);
                return false;
            }
        }

        var expectedOwners = new HashSet<(ulong CallAddress, ulong RelocationOffset)>();
        long aggregateScanInstructions = 0;
        var valid = true;
        foreach (var sourceInstruction in sourceInstructions.OrderBy(instruction => instruction.Address))
        {
            if (!string.Equals(sourceInstruction.Decode.Instruction?.Mnemonic, "ADRP", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!TryFindContainingSourceRange(
                    orderedRanges,
                    sourceInstruction.Address,
                    InstructionSize,
                    out var selectedRange))
            {
                continue;
            }

            var pageProjection = Aarch64SemanticInstructionProjector.Project(sourceInstruction, source.RelaRelocations);
            if (!pageProjection.IsSuccess || pageProjection.Instruction is null)
            {
                Error(diagnostics, "A selected source ADRP cannot be independently projected while checking dynamic-import ownership completeness.", sourceInstruction.Address);
                valid = false;
                continue;
            }

            var pageInstruction = pageProjection.Instruction;
            if (pageInstruction.PcRelativeExpression is not
                {
                    Kind: PcRelativeExpressionKind.AdrPrelPgHi21,
                    IsPageRelative: true,
                    Scale: 0x1000,
                    Target.SourceAddress: { } pageAddress,
                }
                || !dynamicGotPages.Contains(pageAddress.Value)
                || (pageAddress.Value & 0xFFFUL) != 0
                || GetSingleOutputRegister(pageInstruction) is not
                {
                    Width: 64,
                    Class: Aarch64RegisterClass.General,
                    Role: Aarch64RegisterRole.None,
                } pageRegister)
            {
                continue;
            }

            var startOffset = sourceInstruction.Address - selectedRange.VirtualAddress.Value;
            var remainingInstructions = (selectedRange.Size - startOffset) / InstructionSize;
            if (remainingInstructions == 0)
            {
                continue;
            }

            var state = new Dictionary<(Aarch64RegisterClass Class, byte Index), SourceImportProvenance>
            {
                [RegisterIdentity(pageRegister)] = new SourceImportProvenance(
                    pageRegister,
                    SourceImportProvenanceKind.Page,
                    pageAddress.Value),
            };
            var scanCount = Math.Min((long)remainingInstructions, MaximumSourceScanInstructionsPerOwner);
            for (long step = 1; step < scanCount; step++)
            {
                aggregateScanInstructions++;
                if (aggregateScanInstructions > MaximumAggregateSourceScanInstructions)
                {
                    Error(diagnostics, "The selected source exceeds the aggregate dynamic-import ownership scan bound.", sourceInstruction.Address);
                    return false;
                }

                var address = checked(sourceInstruction.Address + ((ulong)step * InstructionSize));
                if (!instructionsByAddress.TryGetValue(address, out var boundedInstruction))
                {
                    Error(diagnostics, "A bounded dynamic-import source scan encountered a missing selected-region instruction.", address);
                    valid = false;
                    break;
                }

                var projection = Aarch64SemanticInstructionProjector.Project(boundedInstruction, source.RelaRelocations);
                if (!projection.IsSuccess || projection.Instruction is null)
                {
                    Error(diagnostics, "A dynamic-import source producer interval contains an instruction that cannot be independently projected.", address);
                    valid = false;
                    break;
                }

                var instruction = projection.Instruction;
                if (TryGetIndirectCallTargetRegister(instruction, out var callTarget)
                    && state.TryGetValue(RegisterIdentity(callTarget), out var targetProvenance)
                    && targetProvenance.Kind == SourceImportProvenanceKind.Got
                    && dynamicGotOffsets.Contains(targetProvenance.Address))
                {
                    expectedOwners.Add((address, targetProvenance.Address));
                    break;
                }

                if (instruction.ControlFlow != Aarch64ControlFlowKind.None)
                {
                    if (state.Count > 0)
                    {
                        Error(
                            diagnostics,
                            "A source-derived dynamic-import provenance interval reaches a control-flow edge before its BLR call.",
                            address);
                        valid = false;
                    }

                    break;
                }

                var aliasTransfers = state.Values
                    .Where(provenance => TryGetAliasTransfer(instruction, provenance.Register, out _))
                    .Select(provenance =>
                    {
                        _ = TryGetAliasTransfer(instruction, provenance.Register, out var output);
                        return (Provenance: provenance, Output: output);
                    })
                    .ToArray();
                if (aliasTransfers.Length > 1)
                {
                    Error(diagnostics, "A dynamic-import source instruction has ambiguous tracked register-copy provenance.", address);
                    valid = false;
                    break;
                }

                var loadedGot = TryGetSourceGotLoad(instruction, state, dynamicGotOffsets, out var gotRegister, out var gotOffset);
                foreach (var write in GetWrittenRegisters(instruction))
                {
                    state.Remove(RegisterIdentity(write));
                }

                if (aliasTransfers.Length == 1)
                {
                    var alias = aliasTransfers[0];
                    state[RegisterIdentity(alias.Output)] = alias.Provenance with { Register = alias.Output };
                }

                if (loadedGot)
                {
                    state[RegisterIdentity(gotRegister)] = new SourceImportProvenance(
                        gotRegister,
                        SourceImportProvenanceKind.Got,
                        gotOffset);
                }
            }
        }

        if (expectedOwners.Count > MaximumDynamicImportOwners)
        {
            Error(diagnostics, "The selected source exceeds the bounded dynamic-import owner count.");
            return false;
        }

        var distinctCarried = carriedOwners.Distinct().ToHashSet();
        if (distinctCarried.Count != carriedOwners.Length
            || !expectedOwners.SetEquals(distinctCarried))
        {
            Error(
                diagnostics,
                "The typed dynamic-import owner set does not match BLR calls independently derived from selected source GOT/RELA dataflow.");
            valid = false;
        }

        return valid;
    }

    private static bool TryFindContainingSourceRange(
        SemanticSourceRange[] sortedRanges,
        ulong address,
        ulong size,
        out SemanticSourceRange range)
    {
        range = default;
        var low = 0;
        var high = sortedRanges.Length;
        while (low < high)
        {
            var middle = low + ((high - low) / 2);
            if (sortedRanges[middle].VirtualAddress.Value <= address)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        var index = low - 1;
        if (index < 0)
        {
            return false;
        }

        var candidate = sortedRanges[index];
        var delta = address - candidate.VirtualAddress.Value;
        if (delta > candidate.Size || size > candidate.Size - delta)
        {
            return false;
        }

        range = candidate;
        return true;
    }

    private static bool TryGetIndirectCallTargetRegister(
        SemanticInstruction instruction,
        out Aarch64RegisterView register)
    {
        register = default;
        if (!string.Equals(instruction.Mnemonic, "BLR", StringComparison.OrdinalIgnoreCase)
            || instruction.ControlFlow != Aarch64ControlFlowKind.IndirectBranch)
        {
            return false;
        }

        var inputs = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction == Aarch64OperandDirection.Input
                && operand.Register is not null)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        if (inputs.Length != 1
            || inputs[0].Class != Aarch64RegisterClass.General
            || inputs[0].Width != 64
            || inputs[0].Role != Aarch64RegisterRole.None)
        {
            return false;
        }

        register = inputs[0];
        return true;
    }

    private static bool TryGetSourceGotLoad(
        SemanticInstruction instruction,
        Dictionary<(Aarch64RegisterClass Class, byte Index), SourceImportProvenance> state,
        HashSet<ulong> dynamicGotOffsets,
        out Aarch64RegisterView destination,
        out ulong gotOffset)
    {
        destination = default;
        gotOffset = default;
        if (!string.Equals(instruction.Mnemonic, "LDR", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var memories = instruction.Operands
            .Where(operand => operand.Memory is not null)
            .Select(operand => operand.Memory!)
            .ToArray();
        if (memories.Length != 1
            || memories[0].Index is not null
            || memories[0].WritesBack
            || memories[0].AccessSize != (int)GotPointerSize
            || memories[0].Offset < 0
            || memories[0].Offset >= 0x1000
            || !state.TryGetValue(RegisterIdentity(memories[0].Base), out var baseProvenance)
            || baseProvenance.Kind != SourceImportProvenanceKind.Page
            || baseProvenance.Address > ulong.MaxValue - (ulong)memories[0].Offset)
        {
            return false;
        }

        var effectiveAddress = baseProvenance.Address + (ulong)memories[0].Offset;
        if (!dynamicGotOffsets.Contains(effectiveAddress)
            || GetSingleOutputRegister(instruction) is not
            {
                Width: 64,
                Class: Aarch64RegisterClass.General,
                Role: Aarch64RegisterRole.None,
            } outputRegister)
        {
            return false;
        }

        destination = outputRegister;
        gotOffset = effectiveAddress;
        return true;
    }

    private static IEnumerable<Aarch64RegisterView> GetWrittenRegisters(SemanticInstruction instruction)
    {
        var written = instruction.RegisterEffects
            .Where(effect => effect.Kind is SemanticRegisterEffectKind.Write or SemanticRegisterEffectKind.ReadWrite)
            .Select(effect => effect.Register)
            .Concat(instruction.Operands
                .Where(operand => operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput)
                .Where(operand => operand.Kind == Aarch64OperandKind.Register && operand.Register is not null)
                .Select(operand => operand.Register!.Value))
            .DistinctBy(RegisterIdentity);
        return written;
    }

    private static (Aarch64RegisterClass Class, byte Index) RegisterIdentity(Aarch64RegisterView register) =>
        (register.Class, register.Index);

    private enum SourceImportProvenanceKind
    {
        Page,
        Got,
    }

    private readonly record struct SourceImportProvenance(
        Aarch64RegisterView Register,
        SourceImportProvenanceKind Kind,
        ulong Address);

    private static bool ValidateCompleteSourceProducerChain(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        SemanticDynamicImportCallExtension import,
        AsmStoneAdapter decoder,
        Dictionary<VirtualAddress, SemanticInstruction[]> instructionsByAddress,
        AddressMapEntry[] blocksByAddress,
        DiagnosticBag diagnostics)
    {
        var pageAddress = import.PageProducerAddress.Value;
        var callAddress = import.CallAddress.Value;
        if (pageAddress >= callAddress
            || (callAddress - pageAddress) % InstructionSize != 0
            || import.ProducerAddresses.Count == 0
            || import.ProducerAddresses[0] != import.PageProducerAddress
            || import.ProducerAddresses[^1].Value >= callAddress)
        {
            Error(diagnostics, "The dynamic-import producer chain does not precede its call in source instruction order.", callAddress);
            return false;
        }

        var instructionCount = checked(((callAddress - pageAddress) / InstructionSize) + 1);
        var rangeSize = checked(instructionCount * InstructionSize);
        if (!TryFindContainingRange(blocksByAddress, pageAddress, rangeSize, out _))
        {
            Error(diagnostics, "The dynamic-import ADRP-to-BLR interval is not contained in one canonical source basic block.", callAddress);
            return false;
        }

        var listedProducers = import.ProducerAddresses.ToHashSet();
        var pageKnown = new HashSet<Aarch64RegisterView>();
        var pageListed = new HashSet<Aarch64RegisterView>();
        var targetKnown = new HashSet<Aarch64RegisterView>();
        var targetListed = new HashSet<Aarch64RegisterView>();
        var reachedLoad = false;
        var valid = true;

        for (ulong index = 0; index < instructionCount; index++)
        {
            var address = new VirtualAddress(checked(pageAddress + (index * InstructionSize)));
            var isCall = address.Value == callAddress;
            var isPageProducer = address == import.PageProducerAddress;
            var isLoadProducer = address == import.LoadProducerAddress;
            var isListedProducer = listedProducers.Contains(address);
            var expectedKind = isCall
                ? SourceInstructionKind.Call
                : isPageProducer
                    ? SourceInstructionKind.PageProducer
                    : isLoadProducer
                        ? SourceInstructionKind.LoadProducer
                        : isListedProducer
                            ? SourceInstructionKind.OtherProducer
                            : SourceInstructionKind.Intervening;
            if (!ValidateSourceInstruction(
                    source,
                    snapshot,
                    instructionsByAddress,
                    import,
                    address,
                    decoder,
                    expectedKind,
                    diagnostics))
            {
                valid = false;
                continue;
            }

            if (!TryGetInstruction(instructionsByAddress, address, out var instruction))
            {
                valid = false;
                continue;
            }

            if (isCall)
            {
                if (!reachedLoad
                    || !targetListed.Any(register => SameRegisterIdentity(register, import.TargetRegister)))
                {
                    Error(diagnostics, "The BLR target register has no complete reaching definition from the exact GOT load producer chain.", callAddress);
                    valid = false;
                }

                continue;
            }

            if (instruction.ControlFlow != Aarch64ControlFlowKind.None)
            {
                Error(diagnostics, "The dynamic-import ADRP-to-BLR interval crosses a control-flow edge or alternate path.", address.Value);
                valid = false;
                continue;
            }

            if (isPageProducer)
            {
                if (GetSingleOutputRegister(instruction) is not { } pageRegister)
                {
                    Error(diagnostics, "The ADRP producer does not define one exact page register.", address.Value);
                    valid = false;
                    continue;
                }

                pageKnown.Add(pageRegister);
                pageListed.Add(pageRegister);
                continue;
            }

            if (!reachedLoad)
            {
                if (isLoadProducer)
                {
                    var memory = instruction.Operands.Select(operand => operand.Memory).FirstOrDefault(candidate => candidate is not null);
                    var output = GetSingleOutputRegister(instruction);
                    if (memory is null
                        || !pageListed.Any(register => SameRegisterIdentity(register, memory.Base))
                        || output is null)
                    {
                        Error(diagnostics, "The GOT pointer load is not reached from the complete listed ADRP page producer chain.", address.Value);
                        valid = false;
                        continue;
                    }

                    reachedLoad = true;
                    targetKnown.Clear();
                    targetListed.Clear();
                    targetKnown.Add(output.Value);
                    targetListed.Add(output.Value);
                    continue;
                }

                if (!AdvanceRegisterProvenance(
                        instruction,
                        isListedProducer,
                        pageKnown,
                        pageListed,
                        diagnostics,
                        address.Value))
                {
                    valid = false;
                }
            }
            else
            {
                if (isPageProducer || isLoadProducer)
                {
                    Error(diagnostics, "A dynamic-import page or load producer appears after the GOT load or before the call unexpectedly.", address.Value);
                    valid = false;
                    continue;
                }

                if (!AdvanceRegisterProvenance(
                        instruction,
                        isListedProducer,
                        targetKnown,
                        targetListed,
                        diagnostics,
                        address.Value))
                {
                    valid = false;
                }
            }
        }

        if (!reachedLoad)
        {
            Error(diagnostics, "The dynamic-import producer scan did not reach its exact pointer load.", import.LoadProducerAddress.Value);
            valid = false;
        }

        return valid;
    }

    private static bool AdvanceRegisterProvenance(
        SemanticInstruction instruction,
        bool producerListed,
        HashSet<Aarch64RegisterView> known,
        HashSet<Aarch64RegisterView> listed,
        DiagnosticBag diagnostics,
        ulong address)
    {
        var aliasFound = TryGetAliasTransferFromKnown(instruction, known, out var aliasInput, out var aliasOutput);
        if (producerListed && (!aliasFound || !listed.Any(register => SameRegisterIdentity(register, aliasInput))))
        {
            Error(diagnostics, "A listed dynamic-import producer is not a connected alias of a reaching page or GOT-pointer value.", address);
            return false;
        }

        var aliasIsListed = producerListed && listed.Any(register => SameRegisterIdentity(register, aliasInput));
        foreach (var effect in instruction.RegisterEffects.Where(effect =>
                     effect.Kind is SemanticRegisterEffectKind.Write or SemanticRegisterEffectKind.ReadWrite))
        {
            known.RemoveWhere(register => SameRegisterIdentity(register, effect.Register));
            listed.RemoveWhere(register => SameRegisterIdentity(register, effect.Register));
        }

        if (aliasFound)
        {
            known.Add(aliasOutput);
            if (aliasIsListed)
            {
                listed.Add(aliasOutput);
            }
        }

        return true;
    }

    private static bool TryGetAliasTransferFromKnown(
        SemanticInstruction instruction,
        HashSet<Aarch64RegisterView> known,
        out Aarch64RegisterView input,
        out Aarch64RegisterView output)
    {
        foreach (var candidate in known)
        {
            if (TryGetAliasTransfer(instruction, candidate, out output))
            {
                input = candidate;
                return true;
            }
        }

        input = default;
        output = default;
        return false;
    }

    private static bool SameRegisterIdentity(Aarch64RegisterView left, Aarch64RegisterView right) =>
        left.Class == right.Class && left.Index == right.Index;

    private static bool TryFindContainingRange(
        AddressMapEntry[] sortedRanges,
        ulong address,
        ulong size,
        out AddressMapEntry entry)
    {
        entry = null!;
        var low = 0;
        var high = sortedRanges.Length;
        while (low < high)
        {
            var middle = low + ((high - low) / 2);
            if (sortedRanges[middle].SourceRange.VirtualAddress.Value <= address)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        var candidateIndex = low - 1;
        if (candidateIndex < 0)
        {
            return false;
        }

        var candidate = sortedRanges[candidateIndex];
        var range = candidate.SourceRange;
        var delta = address - range.VirtualAddress.Value;
        if (size == 0 || delta > range.Size || size > range.Size - delta)
        {
            return false;
        }

        entry = candidate;
        return true;
    }

    private static bool ValidateSourceAddressMap(
        SemanticDynamicImportCallExtension import,
        AddressMap addressMap,
        Dictionary<SemanticSourceRange, AddressMapEntry[]> gotMapsByRange,
        DiagnosticBag diagnostics)
    {
        var gotMaps = gotMapsByRange.TryGetValue(import.GotRange, out var entries)
            ? entries
            : Array.Empty<AddressMapEntry>();
        var siteFound = addressMap.TryGet(import.RelocationSiteIdentity, out var siteMap);
        if (gotMaps.Length != 1
            || gotMaps[0].OutputRange != import.GotRange
            || !siteFound
            || siteMap.SourceRange != import.GotRange
            || siteMap.OutputRange != import.GotRange)
        {
            Error(diagnostics, "The decoded canonical address map does not preserve the exact source and output GOT/RELA site ranges.", import.RelocationOffset);
            return false;
        }

        return true;
    }

    private static bool ValidateSourceInstruction(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        Dictionary<VirtualAddress, SemanticInstruction[]> instructionsByAddress,
        SemanticDynamicImportCallExtension import,
        VirtualAddress address,
        AsmStoneAdapter decoder,
        SourceInstructionKind expectedKind,
        DiagnosticBag diagnostics)
    {
        var identity = SemanticEntityId.Instruction(address);
        if (!instructionsByAddress.TryGetValue(address, out var matches)
            || matches.Length != 1
            || !snapshot.AddressMap.TryGet(identity, out var mapEntry)
            || matches[0].SourceRange != mapEntry.SourceRange
            || mapEntry.SourceRange.Size != InstructionSize
            || !TryGetUniqueSourceRange(source, address.Value, InstructionSize, out var sourceOffset, requireWritable: false, requireExecutable: true)
            || sourceOffset != mapEntry.SourceRange.FileOffset
            || sourceOffset.Value > (ulong)source.Bytes.Length - InstructionSize)
        {
            Error(diagnostics, "A dynamic-import call or producer is missing its exact bounded source instruction and address-map owner.", address.Value);
            return false;
        }

        var raw = BinaryPrimitives.ReadUInt32LittleEndian(source.Bytes.Span.Slice(
            checked((int)sourceOffset.Value),
            checked((int)InstructionSize)));
        if (matches[0].Encoding != raw)
        {
            Error(diagnostics, "A dynamic-import call or producer encoding differs from the independently parsed source ELF bytes.", address.Value);
            return false;
        }

        var decode = decoder.Decode(raw, address.Value);
        if (!decode.IsSuccess || decode.Instruction is null)
        {
            Error(diagnostics, "A dynamic-import call or producer cannot be independently decoded from its source ELF instruction bytes.", address.Value);
            return false;
        }

        var projected = Aarch64SemanticInstructionProjector.Project(
            new Aarch64FunctionInstruction(sourceOffset.Value, address.Value, raw, decode));
        if (!projected.IsSuccess || projected.Instruction is null
            || !SameDecodedInstruction(
                projected.Instruction,
                matches[0],
                expectedKind == SourceInstructionKind.Call
                    ? SemanticTarget.RuntimeResolved(import.RuntimeBinding)
                    : null))
        {
            Error(diagnostics, "A dynamic-import call or producer semantic record differs from the independently decoded source ELF instruction.", address.Value);
            return false;
        }

        var shapeValid = expectedKind switch
        {
            SourceInstructionKind.Call => IsCallTargetRegister(matches[0], import.TargetRegister),
            SourceInstructionKind.PageProducer => IsPageProducer(matches[0], import.PageAddress),
            SourceInstructionKind.LoadProducer => IsLoadProducer(matches[0], import),
            SourceInstructionKind.OtherProducer => IsSupportedAliasProducer(matches[0]),
            SourceInstructionKind.Intervening => true,
            _ => false,
        };
        if (!shapeValid)
        {
            Error(diagnostics, "A dynamic-import call or producer instruction does not match its typed owner role.", address.Value);
            return false;
        }

        return true;
    }

    internal static bool SameDecodedInstruction(
        SemanticInstruction left,
        SemanticInstruction right,
        SemanticTarget? expectedIndirectTarget = null)
    {
        var indirectTargetChangeIsBound = expectedIndirectTarget is not null
            && string.Equals(left.Mnemonic, "BLR", StringComparison.OrdinalIgnoreCase)
            && left.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
            && SameTarget(right.ControlFlowTarget, expectedIndirectTarget);
        if (left.SourceVirtualAddress != right.SourceVirtualAddress
            || left.SourceFileOffset != right.SourceFileOffset
            || left.SourceRange != right.SourceRange
            || left.Encoding != right.Encoding
            || !string.Equals(left.Mnemonic, right.Mnemonic, StringComparison.OrdinalIgnoreCase)
            || left.ControlFlow != right.ControlFlow
            || (!SameTarget(left.ControlFlowTarget, right.ControlFlowTarget) && !indirectTargetChangeIsBound)
            || !SameExpression(left.PcRelativeExpression, right.PcRelativeExpression)
            || !SameLiteral(left.LiteralReference, right.LiteralReference)
            || left.FlagEffects != right.FlagEffects
            || left.OpaquePreservation != right.OpaquePreservation
            || left.Operands.Count != right.Operands.Count
            || left.Relocations.Count != right.Relocations.Count
            || left.References.Count != right.References.Count
            || !left.RegisterEffects.OrderBy(effect => effect.Register.Class)
                .ThenBy(effect => effect.Register.Index)
                .ThenBy(effect => effect.Register.Width)
                .ThenBy(effect => effect.Register.Role)
                .ThenBy(effect => (int)effect.Kind)
                .ThenBy(effect => effect.IsImplicit)
                .SequenceEqual(right.RegisterEffects.OrderBy(effect => effect.Register.Class)
                    .ThenBy(effect => effect.Register.Index)
                    .ThenBy(effect => effect.Register.Width)
                    .ThenBy(effect => effect.Register.Role)
                    .ThenBy(effect => (int)effect.Kind)
                    .ThenBy(effect => effect.IsImplicit)))
        {
            return false;
        }

        for (var index = 0; index < left.Operands.Count; index++)
        {
            var expected = left.Operands[index];
            var actual = right.Operands[index];
            if (expected.Kind != actual.Kind
                || expected.Direction != actual.Direction
                || expected.IsImplicit != actual.IsImplicit
                || expected.Name != actual.Name
                || expected.Codec != actual.Codec
                || expected.TiedTo != actual.TiedTo
                || expected.Register != actual.Register
                || expected.RegisterConstraint != actual.RegisterConstraint
                || expected.RegisterWidth != actual.RegisterWidth
                || expected.FieldWidth != actual.FieldWidth
                || expected.ElementWidth != actual.ElementWidth
                || expected.AllowsStackPointer != actual.AllowsStackPointer
                || expected.AllowsZeroRegister != actual.AllowsZeroRegister
                || expected.IsPageRelative != actual.IsPageRelative
                || expected.SemanticDomain != actual.SemanticDomain
                || !Equals(expected.Memory, actual.Memory)
                || expected.Immediate != actual.Immediate
                || expected.Target != actual.Target
                || !expected.Registers.SequenceEqual(actual.Registers))
            {
                return false;
            }
        }

        return left.Relocations.Zip(right.Relocations).All(pair => SameRelocation(pair.First, pair.Second))
            && left.References.Zip(right.References).All(pair => SameReference(
                pair.First,
                pair.Second,
                indirectTargetChangeIsBound ? expectedIndirectTarget : null));
    }

    private static bool SameTarget(SemanticTarget? left, SemanticTarget? right) =>
        left is null
            ? right is null
            : right is not null
                && left.Resolution == right.Resolution
                && left.SourceAddress == right.SourceAddress
                && left.Identity == right.Identity
                && left.CandidateIdentities.SequenceEqual(right.CandidateIdentities)
                && left.CandidateAddresses.SequenceEqual(right.CandidateAddresses)
                && left.RuntimeBinding == right.RuntimeBinding
                && left.Diagnostic == right.Diagnostic;

    private static bool SameExpression(PcRelativeExpression? left, PcRelativeExpression? right) =>
        left is null
            ? right is null
            : right is not null
                && left.Kind == right.Kind
                && left.Place == right.Place
                && SameTarget(left.Target, right.Target)
                && left.Scale == right.Scale
                && left.IsPageRelative == right.IsPageRelative
                && left.Addend == right.Addend;

    private static bool SameLiteral(LiteralReference? left, LiteralReference? right) =>
        left is null
            ? right is null
            : right is not null
                && SameTarget(left.Target, right.Target)
                && left.AccessSize == right.AccessSize
                && left.IsLoad == right.IsLoad
                && left.PoolRange == right.PoolRange;

    private static bool SameRelocation(RelocationBinding left, RelocationBinding right) =>
        left.Kind == right.Kind
        && SameTarget(left.Target, right.Target)
        && left.Addend == right.Addend
        && left.SymbolIndex == right.SymbolIndex
        && left.IsPlt == right.IsPlt
        && left.SymbolName == right.SymbolName
        && left.RelocationType == right.RelocationType
        && left.RelocationAddress == right.RelocationAddress
        && left.RelocationTableAddress == right.RelocationTableAddress
        && left.RawInfo == right.RawInfo;

    private static bool SameReference(
        SemanticReference left,
        SemanticReference right,
        SemanticTarget? expectedIndirectTarget) =>
        left.Kind == right.Kind
        && (SameTarget(left.Target, right.Target)
            || (left.Kind == SemanticReferenceKind.ControlFlowTarget
                && expectedIndirectTarget is not null
                && SameTarget(right.Target, expectedIndirectTarget)))
        && left.OperandIndex == right.OperandIndex
        && SameExpression(left.PcRelative, right.PcRelative)
        && SameLiteral(left.Literal, right.Literal)
        && (left.Relocation is null
            ? right.Relocation is null
            : right.Relocation is not null && SameRelocation(left.Relocation, right.Relocation))
        && left.Description == right.Description;

    private static bool ValidateCallAndProducerSemantics(
        SemanticDynamicImportCallExtension import,
        Dictionary<VirtualAddress, SemanticInstruction[]> instructionGroups,
        DiagnosticBag diagnostics)
    {
        if (!TryGetInstruction(instructionGroups, import.CallAddress, out var call)
            || !IsCallTargetRegister(call, import.TargetRegister)
            || !TryGetInstruction(instructionGroups, import.PageProducerAddress, out var page)
            || !IsPageProducer(page, import.PageAddress)
            || !TryGetInstruction(instructionGroups, import.LoadProducerAddress, out var load)
            || !IsLoadProducer(load, import))
        {
            Error(diagnostics, "The dynamic-import owner is not linked to one semantic BLR, ADRP page producer, and matching 64-bit GOT load.", import.CallAddress.Value);
            return false;
        }

        var chain = import.ProducerAddresses
            .Select(address => TryGetInstruction(instructionGroups, address, out var producer) ? producer : null)
            .ToArray();
        if (chain.Any(instruction => instruction is null))
        {
            Error(diagnostics, "The dynamic-import producer chain names a missing semantic instruction.", import.CallAddress.Value);
            return false;
        }

        var pageIndex = Array.FindIndex(import.ProducerAddresses.ToArray(), address => address == import.PageProducerAddress);
        var loadIndex = Array.FindIndex(import.ProducerAddresses.ToArray(), address => address == import.LoadProducerAddress);
        if (pageIndex < 0 || loadIndex <= pageIndex || loadIndex >= chain.Length)
        {
            Error(diagnostics, "The dynamic-import ADRP/LDR producer order is inconsistent.", import.CallAddress.Value);
            return false;
        }

        var pageRegister = GetSingleOutputRegister(page);
        if (pageRegister is null)
        {
            Error(diagnostics, "The dynamic-import ADRP producer has no unique output register.", page.SourceVirtualAddress.Value);
            return false;
        }

        var currentPageRegister = pageRegister.Value;
        for (var index = pageIndex + 1; index < loadIndex; index++)
        {
            if (!TryGetAliasTransfer(chain[index]!, currentPageRegister, out currentPageRegister))
            {
                Error(diagnostics, "The dynamic-import page producer chain contains an unsupported or disconnected register transfer.", import.ProducerAddresses[index].Value);
                return false;
            }
        }

        var memory = load.Operands.Select(operand => operand.Memory).FirstOrDefault(candidate => candidate is not null);
        if (memory is null || memory.Base != currentPageRegister)
        {
            Error(diagnostics, "The dynamic-import GOT load does not consume the carried ADRP page value.", load.SourceVirtualAddress.Value);
            return false;
        }

        var currentTargetRegister = GetSingleOutputRegister(load);
        if (currentTargetRegister is null)
        {
            Error(diagnostics, "The dynamic-import GOT load has no unique destination register.", load.SourceVirtualAddress.Value);
            return false;
        }

        for (var index = loadIndex + 1; index < chain.Length; index++)
        {
            if (!TryGetAliasTransfer(chain[index]!, currentTargetRegister.Value, out var nextTargetRegister))
            {
                Error(diagnostics, "The dynamic-import pointer producer chain contains an unsupported or disconnected register transfer.", import.ProducerAddresses[index].Value);
                return false;
            }

            currentTargetRegister = nextTargetRegister;
        }

        if (currentTargetRegister.Value != import.TargetRegister)
        {
            Error(diagnostics, "The dynamic-import producer chain does not deliver its GOT function pointer to the BLR target register.", import.CallAddress.Value);
            return false;
        }

        return true;
    }

    private static bool ValidatePlanAddressMap(
        SemanticDynamicImportCallExtension import,
        AddressMap addressMap,
        Dictionary<SemanticSourceRange, AddressMapEntry[]> gotMapsByRange,
        DiagnosticBag diagnostics)
    {
        var valid = true;
        foreach (var address in import.ProducerAddresses.Append(import.CallAddress))
        {
            if (!addressMap.TryGet(SemanticEntityId.Instruction(address), out var entry)
                || entry.SourceRange.VirtualAddress != address
                || entry.SourceRange.Size != InstructionSize
                || entry.OutputRange.Size != InstructionSize)
            {
                Error(diagnostics, "The canonical address map is missing an exact call/producer instruction binding for a dynamic import.", address.Value);
                valid = false;
            }
        }

        if (!gotMapsByRange.TryGetValue(import.GotRange, out var gotMaps) || gotMaps.Length != 1)
        {
            Error(diagnostics, "The canonical address map must carry exactly one exact GOT range binding for a dynamic import.", import.GotRange.VirtualAddress.Value);
            valid = false;
        }

        if (!addressMap.TryGet(import.RelocationSiteIdentity, out var siteMap)
            || siteMap.Identity.Kind != SemanticEntityKind.RelocationSite
            || siteMap.SourceRange != import.GotRange
            || siteMap.OutputRange.Size != import.GotRange.Size)
        {
            Error(diagnostics, "The canonical address map is missing the exact source/output GOT and relocation-site binding.", import.RelocationOffset);
            valid = false;
        }

        return valid;
    }

    private static bool IsCallTargetRegister(SemanticInstruction instruction, Aarch64RegisterView register) =>
        string.Equals(instruction.Mnemonic, "BLR", StringComparison.OrdinalIgnoreCase)
        && instruction.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
        && instruction.Operands.Count(operand => operand.Kind == Aarch64OperandKind.Register
            && operand.Direction == Aarch64OperandDirection.Input
            && operand.Register == register) == 1;

    private static bool IsPageProducer(SemanticInstruction instruction, VirtualAddress pageAddress) =>
        string.Equals(instruction.Mnemonic, "ADRP", StringComparison.OrdinalIgnoreCase)
        && instruction.PcRelativeExpression is
        {
            Kind: PcRelativeExpressionKind.AdrPrelPgHi21,
            IsPageRelative: true,
            Scale: 0x1000,
            Target.SourceAddress: { } targetAddress,
        }
        && targetAddress == pageAddress
        && (pageAddress.Value & 0xFFFUL) == 0
        && GetSingleOutputRegister(instruction) is { Width: 64, Class: Aarch64RegisterClass.General, Role: Aarch64RegisterRole.None };

    private static bool IsLoadProducer(SemanticInstruction instruction, SemanticDynamicImportCallExtension import)
    {
        if (!string.Equals(instruction.Mnemonic, "LDR", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var memories = instruction.Operands.Where(operand => operand.Memory is not null).Select(operand => operand.Memory!).ToArray();
        if (memories.Length != 1
            || memories[0].Index is not null
            || memories[0].WritesBack
            || memories[0].AccessSize != (int)GotPointerSize
            || memories[0].Offset < 0
            || memories[0].Offset >= 0x1000
            || import.PageAddress.Value > ulong.MaxValue - (ulong)memories[0].Offset
            || import.PageAddress.Value + (ulong)memories[0].Offset != import.GotRange.VirtualAddress.Value)
        {
            return false;
        }

        return GetSingleOutputRegister(instruction) is
        {
            Width: 64,
            Class: Aarch64RegisterClass.General,
            Role: Aarch64RegisterRole.None,
        };
    }

    private static bool IsSupportedAliasProducer(SemanticInstruction instruction) =>
        string.Equals(instruction.Mnemonic, "MOV", StringComparison.OrdinalIgnoreCase)
        || string.Equals(instruction.Mnemonic, "ORR", StringComparison.OrdinalIgnoreCase);

    private static bool TryGetAliasTransfer(
        SemanticInstruction instruction,
        Aarch64RegisterView expectedInput,
        out Aarch64RegisterView output)
    {
        output = default;
        if (!IsSupportedAliasProducer(instruction)
            || GetSingleOutputRegister(instruction) is not { } candidateOutput
            || candidateOutput.Width != 64
            || candidateOutput.Class != Aarch64RegisterClass.General
            || candidateOutput.Role != Aarch64RegisterRole.None)
        {
            return false;
        }

        var inputRegisters = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register is not null)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        var realInputs = inputRegisters.Where(register => register.Role != Aarch64RegisterRole.Zero).ToArray();
        var zeroInputs = inputRegisters.Count(register => register.Role == Aarch64RegisterRole.Zero);
        var validAlias = realInputs.Length == 1
            && realInputs[0] == expectedInput
            && realInputs[0].Width == 64
            && (string.Equals(instruction.Mnemonic, "MOV", StringComparison.OrdinalIgnoreCase)
                ? zeroInputs == 0 && !instruction.Operands.Any(operand => operand.Kind == Aarch64OperandKind.Immediate)
                : zeroInputs == 1 && instruction.Operands.Where(operand => operand.Kind == Aarch64OperandKind.Immediate)
                    .All(operand => operand.Immediate == 0));
        if (!validAlias)
        {
            return false;
        }

        output = candidateOutput;
        return true;
    }

    private static Aarch64RegisterView? GetSingleOutputRegister(SemanticInstruction instruction)
    {
        var outputs = instruction.Operands
            .Where(operand => operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput)
            .Where(operand => operand.Kind == Aarch64OperandKind.Register && operand.Register is not null)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        return outputs.Length == 1 ? outputs[0] : null;
    }

    private static bool TryGetInstruction(
        Dictionary<VirtualAddress, SemanticInstruction[]> instructions,
        VirtualAddress address,
        out SemanticInstruction instruction)
    {
        instruction = null!;
        if (!instructions.TryGetValue(address, out var matches) || matches.Length != 1)
        {
            return false;
        }

        instruction = matches[0];
        return true;
    }

    private static bool RelocationMatches(SemanticDynamicImportCallExtension import, RelocationBinding binding) =>
        binding.Kind == Aarch64RelocationKind.GlobalData
        && binding.RelocationType == ElfConstants.RArm64GlobDat
        && binding.RawInfo == import.RelocationInfo
        && binding.Addend == import.RelocationAddend
        && binding.SymbolIndex == import.SymbolIndex
        && !binding.IsPlt
        && string.Equals(binding.SymbolName, import.SymbolName, StringComparison.Ordinal)
        && binding.RelocationAddress == new VirtualAddress(import.RelocationOffset)
        && binding.RelocationTableAddress == import.RelocationTableAddress
        && binding.Target.Resolution == SemanticTargetResolution.RuntimeResolved
        && string.Equals(binding.Target.RuntimeBinding, import.RuntimeBinding, StringComparison.Ordinal);

    private static bool RelocationTupleMatches(SemanticDynamicImportCallExtension import, RelaRelocation relocation) =>
        relocation.Offset == import.RelocationOffset
        && relocation.Info == import.RelocationInfo
        && relocation.Addend == import.RelocationAddend
        && relocation.IsPlt == import.RelocationIsPlt
        && relocation.SourceAddress == import.RelocationTableAddress.Value
        && relocation.Type == ElfConstants.RArm64GlobDat
        && relocation.SymbolIndex == import.SymbolIndex;

    private static bool TryGetDynamicSymbolTableFacts(
        ElfFile source,
        out DynamicSymbolTableFacts facts,
        DiagnosticBag diagnostics)
    {
        facts = default!;
        if (!TryGetUniqueDynamicValue(source.DynamicEntries, ElfConstants.DtSymTab, out var symbolAddress)
            || !TryGetUniqueDynamicValue(source.DynamicEntries, ElfConstants.DtSymEnt, out var symbolEntrySize)
            || !TryGetUniqueDynamicValue(source.DynamicEntries, ElfConstants.DtStrTab, out var stringAddress)
            || !TryGetUniqueDynamicValue(source.DynamicEntries, ElfConstants.DtStrSz, out var stringSize)
            || symbolEntrySize != ElfConstants.SymbolEntrySize64
            || stringSize == 0
            || stringSize > int.MaxValue
            || !TryGetUniqueSourceRange(source, stringAddress, stringSize, out var stringOffset, requireWritable: false))
        {
            Error(diagnostics, "The import owner requires unique, bounded DT_SYMTAB/DT_SYMENT/DT_STRTAB/DT_STRSZ dynamic tables.");
            return false;
        }

        var stringTable = source.Bytes.Slice(checked((int)stringOffset.Value), checked((int)stringSize));
        if (!stringTable.Span.SequenceEqual(source.DynamicMetadata.StringTable.Span))
        {
            Error(diagnostics, "The parsed dynamic string table differs from its exact bounded DT_STRTAB/DT_STRSZ source bytes.");
            return false;
        }

        facts = new DynamicSymbolTableFacts(symbolAddress, symbolEntrySize, stringTable);
        return true;
    }

    private static bool TryGetUniqueDynamicValue(
        IReadOnlyList<DynamicEntry> entries,
        ulong tag,
        out ulong value)
    {
        var matches = entries.Where(entry => entry.Tag == tag).Take(2).ToArray();
        value = matches.Length == 1 ? matches[0].Value : default;
        return matches.Length == 1;
    }

    private static bool TryValidateDynamicSymbolRow(
        ElfFile source,
        DynamicSymbolTableFacts tables,
        uint symbolIndex,
        DynamicSymbol parsedSymbol)
    {
        if (symbolIndex >= (uint)source.DynamicSymbols.Count
            || tables.EntrySize == 0
            || symbolIndex > (ulong.MaxValue / tables.EntrySize))
        {
            return false;
        }

        var rowDelta = (ulong)symbolIndex * tables.EntrySize;
        if (tables.Address > ulong.MaxValue - rowDelta)
        {
            return false;
        }

        var rowAddress = tables.Address + rowDelta;
        if (!TryGetUniqueSourceRange(
                source,
                rowAddress,
                tables.EntrySize,
                out var rowOffset,
                requireWritable: false)
            || rowOffset.Value > (ulong)source.Bytes.Length
            || tables.EntrySize > (ulong)source.Bytes.Length - rowOffset.Value)
        {
            return false;
        }

        var row = source.Bytes.Span.Slice(checked((int)rowOffset.Value), checked((int)tables.EntrySize));
        var name = BinaryPrimitives.ReadUInt32LittleEndian(row);
        var info = row[4];
        var other = row[5];
        var sectionIndex = BinaryPrimitives.ReadUInt16LittleEndian(row[6..]);
        var value = BinaryPrimitives.ReadUInt64LittleEndian(row[8..]);
        var size = BinaryPrimitives.ReadUInt64LittleEndian(row[16..]);
        return name == parsedSymbol.Name
            && info == parsedSymbol.Info
            && other == parsedSymbol.Other
            && sectionIndex == parsedSymbol.SectionIndex
            && value == parsedSymbol.Value
            && size == parsedSymbol.Size;
    }

    internal static bool TryProjectVersionFacts(
        ElfFile file,
        uint symbolIndex,
        out ushort? rawVersionIndex,
        out SemanticDynamicImportVersionRequirement? requirement,
        out string? failure)
    {
        rawVersionIndex = null;
        requirement = null;
        failure = null;
        if (file.SymbolVersions.VersionIndices.Count == 0)
        {
            return true;
        }

        if (symbolIndex >= (uint)file.SymbolVersions.VersionIndices.Count)
        {
            failure = "The dynamic symbol's DT_VERSYM row is missing from the parsed version table.";
            return false;
        }

        var versionIndex = file.SymbolVersions.VersionIndices[checked((int)symbolIndex)];
        rawVersionIndex = versionIndex.RawValue;
        if (versionIndex.IsHidden)
        {
            failure = "The dynamic import has a hidden symbol-version index outside the supported default-visible import contract.";
            return false;
        }

        if (versionIndex.Index <= 1)
        {
            return true;
        }

        var matches = file.SymbolVersions.NeededVersions
            .SelectMany(need => need.Auxiliaries.Select(auxiliary => (Need: need, Auxiliary: auxiliary)))
            .Where(pair => pair.Auxiliary.Other == versionIndex.Index)
            .ToArray();
        if (matches.Length != 1)
        {
            failure = "The dynamic import's non-global DT_VERSYM index has no unique DT_VERNEED/Vernaux owner.";
            return false;
        }

        var match = matches[0];
        if (match.Need.Version != 1
            || match.Need.AuxiliaryCount == 0
            || match.Need.AuxiliaryCount != match.Need.Auxiliaries.Count
            || string.IsNullOrWhiteSpace(match.Need.FileName)
            || string.IsNullOrWhiteSpace(match.Auxiliary.Name)
            || file.DynamicMetadata.NeededLibraries.Count(name =>
                string.Equals(name, match.Need.FileName, StringComparison.Ordinal)) != 1)
        {
            failure = "The dynamic import's DT_VERNEED owner does not match one complete declared dependency/version requirement.";
            return false;
        }

        requirement = new SemanticDynamicImportVersionRequirement(
            match.Need.Version,
            match.Need.AuxiliaryCount,
            match.Need.FileNameOffset,
            match.Need.AuxiliaryOffset,
            match.Need.NextOffset,
            match.Need.FileName,
            match.Auxiliary.Hash,
            match.Auxiliary.Flags,
            match.Auxiliary.Other,
            match.Auxiliary.NameOffset,
            match.Auxiliary.Name);
        return true;
    }

    private static bool TryValidateVersionFacts(
        SemanticDynamicImportCallExtension extension,
        out string? failure)
    {
        failure = null;
        if (extension.SymbolVersionIndexRaw is null)
        {
            if (extension.VersionRequirement is not null)
            {
                failure = "A dynamic import has version-requirement facts but no raw DT_VERSYM index.";
                return false;
            }

            return true;
        }

        var raw = new SymbolVersionIndex(extension.SymbolVersionIndexRaw.Value);
        if (raw.IsHidden)
        {
            failure = "A dynamic import carries an unsupported hidden symbol-version index.";
            return false;
        }

        if (raw.Index <= 1)
        {
            if (extension.VersionRequirement is not null)
            {
                failure = "A global/unversioned dynamic import unexpectedly carries a DT_VERNEED owner.";
                return false;
            }

            return true;
        }

        var requirement = extension.VersionRequirement;
        if (requirement is null
            || requirement.RecordVersion != 1
            || requirement.AuxiliaryCount == 0
            || requirement.Other != raw.Index
            || string.IsNullOrWhiteSpace(requirement.FileName)
            || string.IsNullOrWhiteSpace(requirement.Name))
        {
            failure = "A versioned dynamic import is missing its exact DT_VERNEED/Vernaux facts.";
            return false;
        }

        return true;
    }

    private static bool TryGetUniqueSourceRange(
        ElfFile file,
        ulong address,
        ulong size,
        out FileOffset fileOffset,
        bool requireWritable,
        bool requireExecutable = false)
    {
        fileOffset = default;
        if (size == 0 || address > ulong.MaxValue - size)
        {
            return false;
        }

        var owners = new List<(LoadSegment Segment, FileOffset Offset)>();
        foreach (var segment in file.LoadMap.Segments)
        {
            if (!segment.ContainsVirtualAddress(address, size))
            {
                continue;
            }

            var delta = address - segment.VirtualAddress;
            if (segment.FileOffset > ulong.MaxValue - delta)
            {
                continue;
            }

            var candidate = segment.FileOffset + delta;
            if (segment.ContainsFileOffset(candidate, size))
            {
                owners.Add((segment, new FileOffset(candidate)));
            }
        }

        if (owners.Count != 1
            || (requireWritable && (owners[0].Segment.Flags & ElfConstants.PfW) == 0)
            || (requireExecutable && !owners[0].Segment.IsExecutable)
            || owners[0].Offset.Value > (ulong)file.Bytes.Length
            || size > (ulong)file.Bytes.Length - owners[0].Offset.Value)
        {
            return false;
        }

        fileOffset = owners[0].Offset;
        return file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), size, out var mapped)
            && mapped == fileOffset;
    }

    private static bool IsValidRange(SemanticSourceRange range) =>
        range.Size > 0 && range.TryGetFileEnd(out _) && range.TryGetVirtualEnd(out _);

    private static string FormatAddress(ulong address) => $"0x{address:X}";

    private static void Error(DiagnosticBag diagnostics, string message, ulong? offset = null) =>
        diagnostics.Error(DiagnosticCode.SemanticDynamicImportOwnerMismatch, message, offset);

    private sealed record DynamicSymbolTableFacts(
        ulong Address,
        ulong EntrySize,
        ReadOnlyMemory<byte> StringTable);

    private enum SourceInstructionKind
    {
        Call,
        PageProducer,
        LoadProducer,
        OtherProducer,
        Intervening,
    }
}
