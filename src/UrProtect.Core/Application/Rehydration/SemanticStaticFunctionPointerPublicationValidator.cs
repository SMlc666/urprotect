using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.ElfLayout;

namespace UrProtect.Core.Application.Rehydration;

/// <summary>
/// Independently validates selected static function-pointer publication and final-image preservation.
/// </summary>
public static class SemanticStaticFunctionPointerPublicationValidator
{
    public static bool ValidateLogicalOutputMap(
        ProtectedImageDocument document,
        SemanticPlanSnapshot snapshot,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var valid = true;
        var functions = snapshot.AddressMap.Functions.OrderBy(entry => entry.SourceRange.VirtualAddress.Value).ToArray();
        var regions = document.Operations.OfType<ProtectedImageEmitRegion>()
            .GroupBy(region => (region.SourceAddress, region.SourceSize))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var decoder = new AsmStoneAdapter();

        foreach (var owner in snapshot.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>())
        {
            var callMap = snapshot.AddressMap.Entries.Where(entry =>
                entry.Identity == owner.SourceIdentity
                && entry.SourceRange == owner.SourceRange).ToArray();
            var targetMap = snapshot.AddressMap.Entries.Where(entry =>
                entry.Identity == owner.TargetMappingIdentity
                && entry.SourceRange == owner.TargetSourceRange
                && entry.OutputRange == owner.TargetOutputRange).ToArray();
            var parentFunction = FindContainingFunction(functions, owner.SourceRange);
            if (callMap.Length != 1
                || targetMap.Length != 1
                || parentFunction is null
                || !regions.TryGetValue((parentFunction.SourceRange.VirtualAddress, parentFunction.SourceRange.Size), out var regionMatches)
                || regionMatches.Length != 1
                || parentFunction.OutputRange.Size != (ulong)regionMatches[0].CodeBytes.Length)
            {
                Error(diagnostics, "The static function-pointer call or preserved callback target is not bound to one selected output function and exact original-address mapping.", owner.CallAddress.Value);
                valid = false;
                continue;
            }

            var mappedProducerAddresses = new List<ulong>();
            foreach (var sourceAddress in owner.ProducerAddresses.Append(owner.CallAddress))
            {
                var identity = SemanticEntityId.Instruction(sourceAddress);
                var entries = snapshot.AddressMap.Entries.Where(entry => entry.Identity == identity).ToArray();
                if (entries.Length != 1
                    || !Contains(parentFunction.OutputRange, entries[0].OutputRange)
                    || entries[0].OutputRange.FileOffset.Value - parentFunction.OutputRange.FileOffset.Value
                        != entries[0].OutputRange.VirtualAddress.Value - parentFunction.OutputRange.VirtualAddress.Value
                    || entries[0].OutputRange.Size != sizeof(uint))
                {
                    Error(diagnostics, "A static function-pointer BLR or producer lacks one exact mapped instruction inside the emitted caller region.", sourceAddress.Value);
                    valid = false;
                    continue;
                }

                mappedProducerAddresses.Add(entries[0].OutputRange.VirtualAddress.Value);
            }

            if (mappedProducerAddresses.Count != 5
                || !IsStrictlyContiguous(mappedProducerAddresses)
                || mappedProducerAddresses[^1] != mappedProducerAddresses[^2] + sizeof(uint))
            {
                Error(diagnostics, "The emitted static function-pointer producer chain is not one complete contiguous ADRP/ADD/stack-store/stack-load/BLR sequence.", owner.CallAddress.Value);
                valid = false;
                continue;
            }

            if (!TryReadOutputWord(regionMatches[0], parentFunction.OutputRange, mappedProducerAddresses[0], out var adrpWord)
                || !TryReadOutputWord(regionMatches[0], parentFunction.OutputRange, mappedProducerAddresses[1], out var addWord)
                || !TryReadOutputWord(regionMatches[0], parentFunction.OutputRange, mappedProducerAddresses[2], out var storeWord)
                || !TryReadOutputWord(regionMatches[0], parentFunction.OutputRange, mappedProducerAddresses[3], out var loadWord)
                || !TryReadOutputWord(regionMatches[0], parentFunction.OutputRange, mappedProducerAddresses[4], out var callWord))
            {
                Error(diagnostics, "The emitted static function-pointer producer chain is outside the Protected Image caller bytes.", owner.CallAddress.Value);
                valid = false;
                continue;
            }

            var decodedAdrp = decoder.Decode(adrpWord, mappedProducerAddresses[0]);
            var decodedAdd = decoder.Decode(addWord, mappedProducerAddresses[1]);
            var decodedStore = decoder.Decode(storeWord, mappedProducerAddresses[2]);
            var decodedLoad = decoder.Decode(loadWord, mappedProducerAddresses[3]);
            var decodedCall = decoder.Decode(callWord, mappedProducerAddresses[4]);
            if (!decodedAdrp.IsSuccess
                || decodedAdrp.Instruction is not { Mnemonic: var adrpMnemonic, DirectTarget: { } outputPage }
                || !string.Equals(adrpMnemonic, "ADRP", StringComparison.OrdinalIgnoreCase)
                || (outputPage & 0xFFFUL) != 0
                || outputPage != (owner.TargetOutputRange.VirtualAddress.Value & ~0xFFFUL)
                || !TryGetSingleRegister(decodedAdrp.Instruction, Aarch64OperandDirection.Output, out var pageRegister)
                || !decodedAdd.IsSuccess
                || decodedAdd.Instruction is null
                || !string.Equals(decodedAdd.Instruction.Mnemonic, "ADD", StringComparison.OrdinalIgnoreCase)
                || !TryGetAddRegisters(decodedAdd.Instruction, out var addSource, out var addDestination)
                || addSource != pageRegister
                || addDestination != pageRegister
                || !TryGetOneImmediate(decodedAdd.Instruction, out var outputAddImmediate)
                || outputAddImmediate is < 0 or > 0xFFF
                || outputPage > ulong.MaxValue - checked((ulong)outputAddImmediate)
                || outputPage + checked((ulong)outputAddImmediate) != owner.TargetOutputRange.VirtualAddress.Value
                || !decodedStore.IsSuccess
                || decodedStore.Instruction is null
                || !string.Equals(decodedStore.Instruction.Mnemonic, "STR", StringComparison.OrdinalIgnoreCase)
                || !TryGetStackSlot(decodedStore.Instruction, "STR", out var storeRegister, out var storeOffset)
                || storeRegister != pageRegister
                || !decodedLoad.IsSuccess
                || decodedLoad.Instruction is null
                || !string.Equals(decodedLoad.Instruction.Mnemonic, "LDR", StringComparison.OrdinalIgnoreCase)
                || !TryGetStackSlot(decodedLoad.Instruction, "LDR", out var loadRegister, out var loadOffset)
                || !decodedCall.IsSuccess
                || decodedCall.Instruction is null
                || !TryGetSingleRegister(decodedCall.Instruction, Aarch64OperandDirection.Input, out var callRegister)
                || loadRegister != callRegister
                || storeRegister != loadRegister
                || storeOffset != owner.StackSlotOffset
                || loadOffset != owner.StackSlotOffset
                || decodedCall.Instruction is not { Mnemonic: var callMnemonic, ControlFlow: Aarch64ControlFlowKind.IndirectBranch }
                || !string.Equals(callMnemonic, "BLR", StringComparison.OrdinalIgnoreCase))
            {
                Error(diagnostics, "The emitted ADRP/ADD expression does not reach the preserved callback VA through the exact stack reload and returning BLR semantics.", owner.CallAddress.Value);
                valid = false;
            }
        }

        return valid && !diagnostics.HasErrors;
    }

    public static bool ValidateRehydratedImage(
        ElfFile source,
        ElfFile output,
        ElfLayoutPlan layoutPlan,
        SemanticPlanSnapshot? snapshot,
        DiagnosticBag diagnostics)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(layoutPlan);
        ArgumentNullException.ThrowIfNull(diagnostics);
        var owners = snapshot?.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>().ToArray()
            ?? Array.Empty<SemanticStaticFunctionPointerCallExtension>();
        var valid = true;
        foreach (var owner in owners)
        {
            if (!source.LoadMap.TryVirtualAddressToFileOffset(
                    owner.TargetSourceRange.VirtualAddress,
                    owner.TargetSourceRange.Size,
                    out var sourceFileOffset)
                || sourceFileOffset != owner.TargetSourceRange.FileOffset
                || !output.LoadMap.TryVirtualAddressToFileOffset(
                    owner.TargetOutputRange.VirtualAddress,
                    owner.TargetOutputRange.Size,
                    out var outputFileOffset)
                || sourceFileOffset.Value > (ulong)source.Bytes.Length
                || outputFileOffset.Value > (ulong)output.Bytes.Length
                || owner.TargetSourceRange.Size > (ulong)source.Bytes.Length - sourceFileOffset.Value
                || owner.TargetOutputRange.Size > (ulong)output.Bytes.Length - outputFileOffset.Value
                || !source.Bytes.Span.Slice(
                    checked((int)sourceFileOffset.Value),
                    checked((int)owner.TargetSourceRange.Size))
                    .SequenceEqual(output.Bytes.Span.Slice(
                        checked((int)outputFileOffset.Value),
                        checked((int)owner.TargetOutputRange.Size)))
                || !output.FunctionSymbols.Any(symbol =>
                    symbol.Table == ElfSymbolTableKind.Static
                    && symbol.Name == owner.AdrpRelocation.Name
                    && symbol.Value == owner.TargetSourceRange.VirtualAddress.Value
                    && symbol.Size == owner.TargetSourceRange.Size
                    && symbol.SectionIndex == owner.AdrpRelocation.SymbolSectionIndex))
            {
                Error(diagnostics, "The rehydrated image did not preserve the statically owned callback bytes and symbol at the exact original virtual address.", owner.TargetSourceRange.VirtualAddress.Value);
                valid = false;
                continue;
            }

            if (!ValidateRehydratedCallerCall(source, output, layoutPlan, snapshot!, owner))
            {
                Error(diagnostics, "The final rehydrated caller does not independently retain the exact ADRP/ADD/stack-reload/BLR chain targeting the preserved callback VA.", owner.CallAddress.Value);
                valid = false;
            }
        }

        return valid && !diagnostics.HasErrors;
    }

    private static bool ValidateRehydratedCallerCall(
        ElfFile source,
        ElfFile output,
        ElfLayoutPlan layoutPlan,
        SemanticPlanSnapshot snapshot,
        SemanticStaticFunctionPointerCallExtension owner)
    {
        var logicalFunctions = snapshot.AddressMap.Functions.Where(entry =>
            entry.SourceRange.VirtualAddress.Value == owner.OwnerFunction.Value
            && entry.SourceRange.Size == owner.OwnerFunction.Size).ToArray();
        if (logicalFunctions.Length != 1
            || !source.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(owner.OwnerFunction.Value),
                owner.OwnerFunction.Size,
                out var sourceFunctionOffset))
        {
            return false;
        }

        var logicalFunction = logicalFunctions[0];
        var physicalRegions = layoutPlan.AddressMap.Where(entry =>
            entry.SourceRange is { HasVirtualAddress: true } sourceRange
            && sourceRange.VirtualAddress.Value == owner.OwnerFunction.Value
            && sourceRange.FileOffset == sourceFunctionOffset
            && sourceRange.Size == owner.OwnerFunction.Size
            && entry.OutputRange.Size == logicalFunction.OutputRange.Size).ToArray();
        if (physicalRegions.Length != 1
            || logicalFunction.OutputRange.Size == 0
            || logicalFunction.OutputRange.Size % sizeof(uint) != 0
            || logicalFunction.OutputRange.Size / sizeof(uint) > 65_536)
        {
            return false;
        }

        var physicalRegion = physicalRegions[0];
        if (!output.LoadMap.TryVirtualAddressToFileOffset(
                physicalRegion.OutputRange.VirtualAddress,
                physicalRegion.OutputRange.Size,
                out var physicalFileOffset)
            || physicalFileOffset != physicalRegion.OutputRange.FileOffset
            || physicalFileOffset.Value > (ulong)output.Bytes.Length
            || physicalRegion.OutputRange.Size > (ulong)output.Bytes.Length - physicalFileOffset.Value)
        {
            return false;
        }

        var mappedInstructions = new List<ulong>(5);
        foreach (var sourceAddress in owner.ProducerAddresses.Append(owner.CallAddress))
        {
            var semanticIdentity = SemanticEntityId.Instruction(sourceAddress);
            var entries = snapshot.AddressMap.Entries.Where(entry =>
                entry.Identity == semanticIdentity
                && entry.SourceRange.VirtualAddress == sourceAddress).ToArray();
            if (entries.Length != 1
                || entries[0].OutputRange.VirtualAddress.Value < logicalFunction.OutputRange.VirtualAddress.Value)
            {
                return false;
            }

            var delta = entries[0].OutputRange.VirtualAddress.Value - logicalFunction.OutputRange.VirtualAddress.Value;
            if (delta > physicalRegion.OutputRange.Size
                || sizeof(uint) > physicalRegion.OutputRange.Size - delta
                || physicalRegion.OutputRange.VirtualAddress.Value > ulong.MaxValue - delta)
            {
                return false;
            }

            mappedInstructions.Add(physicalRegion.OutputRange.VirtualAddress.Value + delta);
        }

        if (mappedInstructions.Count != 5 || !IsStrictlyContiguous(mappedInstructions))
        {
            return false;
        }

        var decoder = new AsmStoneAdapter();
        if (physicalRegion.OutputRange.VirtualAddress != new VirtualAddress(owner.OwnerFunction.Value))
        {
            var callerSymbols = output.FunctionSymbols.Where(symbol =>
                symbol.Table == owner.OwnerFunction.Table
                && symbol.TableIndex == owner.OwnerFunction.TableIndex
                && string.Equals(symbol.Name, owner.OwnerFunction.Name, StringComparison.Ordinal)
                && symbol.Value == owner.OwnerFunction.Value
                && symbol.Size == owner.OwnerFunction.Size).ToArray();
            if (callerSymbols.Length != 1
                || !output.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(owner.OwnerFunction.Value),
                    sizeof(uint),
                    out var entryOffset)
                || entryOffset.Value > (ulong)output.Bytes.Length
                || sizeof(uint) > (ulong)output.Bytes.Length - entryOffset.Value)
            {
                return false;
            }

            var entryWord = BinaryPrimitives.ReadUInt32LittleEndian(output.Bytes.Span.Slice(
                checked((int)entryOffset.Value),
                sizeof(uint)));
            var entry = decoder.Decode(entryWord, owner.OwnerFunction.Value);
            if (!entry.IsSuccess
                || entry.Instruction is not { Mnemonic: var branchMnemonic, ControlFlow: Aarch64ControlFlowKind.DirectBranch, DirectTarget: { } branchTarget }
                || !string.Equals(branchMnemonic, "B", StringComparison.OrdinalIgnoreCase)
                || branchTarget != physicalRegion.OutputRange.VirtualAddress.Value)
            {
                return false;
            }
        }

        var instructionCount = checked((int)(physicalRegion.OutputRange.Size / sizeof(uint)));
        var blrAddresses = new List<ulong>();
        Aarch64Instruction? callInstruction = null;
        for (var index = 0; index < instructionCount; index++)
        {
            var relativeOffset = (ulong)index * sizeof(uint);
            var address = physicalRegion.OutputRange.VirtualAddress.Value + relativeOffset;
            var fileOffset = physicalRegion.OutputRange.FileOffset.Value + relativeOffset;
            if (!output.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), sizeof(uint), out var mappedFileOffset)
                || mappedFileOffset.Value != fileOffset
                || mappedFileOffset.Value > (ulong)output.Bytes.Length
                || sizeof(uint) > (ulong)output.Bytes.Length - mappedFileOffset.Value)
            {
                return false;
            }

            var raw = BinaryPrimitives.ReadUInt32LittleEndian(output.Bytes.Span.Slice(
                checked((int)mappedFileOffset.Value),
                sizeof(uint)));
            var decoded = decoder.Decode(raw, address);
            if (!decoded.IsSuccess || decoded.Instruction is null)
            {
                return false;
            }

            if (decoded.Instruction.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
                && string.Equals(decoded.Instruction.Mnemonic, "BLR", StringComparison.OrdinalIgnoreCase))
            {
                blrAddresses.Add(address);
                callInstruction = decoded.Instruction;
            }
        }

        if (blrAddresses.Count != 1
            || blrAddresses[0] != mappedInstructions[^1]
            || callInstruction is null)
        {
            return false;
        }

        var producerWords = new Aarch64Instruction[4];
        for (var index = 0; index < producerWords.Length; index++)
        {
            var address = mappedInstructions[index];
            if (!output.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), sizeof(uint), out var fileOffset)
                || fileOffset.Value > (ulong)output.Bytes.Length
                || sizeof(uint) > (ulong)output.Bytes.Length - fileOffset.Value)
            {
                return false;
            }

            var raw = BinaryPrimitives.ReadUInt32LittleEndian(output.Bytes.Span.Slice(
                checked((int)fileOffset.Value),
                sizeof(uint)));
            var decoded = decoder.Decode(raw, address);
            if (!decoded.IsSuccess || decoded.Instruction is null
                || decoded.Instruction.ControlFlow != Aarch64ControlFlowKind.None)
            {
                return false;
            }

            producerWords[index] = decoded.Instruction;
        }

        var adrp = producerWords[0];
        var add = producerWords[1];
        var store = producerWords[2];
        var load = producerWords[3];
        if (!string.Equals(adrp.Mnemonic, "ADRP", StringComparison.OrdinalIgnoreCase)
            || adrp.DirectTarget is not { } page
            || page != (owner.TargetOutputRange.VirtualAddress.Value & ~0xFFFUL)
            || !TryGetSingleRegister(adrp, Aarch64OperandDirection.Output, out var pageRegister)
            || !string.Equals(add.Mnemonic, "ADD", StringComparison.OrdinalIgnoreCase)
            || !TryGetAddRegisters(add, out var addSource, out var addDestination)
            || addSource != pageRegister
            || addDestination != pageRegister
            || !TryGetOneImmediate(add, out var low12)
            || low12 is < 0 or > 0xFFF
            || page > ulong.MaxValue - checked((ulong)low12)
            || page + checked((ulong)low12) != owner.TargetOutputRange.VirtualAddress.Value
            || !TryGetStackSlot(store, "STR", out var storeRegister, out var storeOffset)
            || storeRegister != pageRegister
            || !TryGetStackSlot(load, "LDR", out var loadRegister, out var loadOffset)
            || loadRegister != pageRegister
            || !TryGetSingleRegister(callInstruction, Aarch64OperandDirection.Input, out var callRegister)
            || callRegister != loadRegister
            || storeOffset != owner.StackSlotOffset
            || loadOffset != owner.StackSlotOffset)
        {
            return false;
        }

        return true;
    }

    private static bool IsStrictlyContiguous(IReadOnlyList<ulong> addresses)
    {
        if (addresses.Count == 0)
        {
            return false;
        }

        for (var index = 1; index < addresses.Count; index++)
        {
            if (addresses[index - 1] > ulong.MaxValue - sizeof(uint)
                || addresses[index] != addresses[index - 1] + sizeof(uint))
            {
                return false;
            }
        }

        return true;
    }

    private static bool Contains(SemanticSourceRange outer, SemanticSourceRange inner) =>
        inner.VirtualAddress.Value >= outer.VirtualAddress.Value
        && inner.VirtualAddress.Value - outer.VirtualAddress.Value <= outer.Size
        && inner.Size <= outer.Size - (inner.VirtualAddress.Value - outer.VirtualAddress.Value)
        && inner.FileOffset.Value >= outer.FileOffset.Value
        && inner.FileOffset.Value - outer.FileOffset.Value <= outer.Size
        && inner.Size <= outer.Size - (inner.FileOffset.Value - outer.FileOffset.Value);

    private static AddressMapEntry? FindContainingFunction(
        IReadOnlyList<AddressMapEntry> functions,
        SemanticSourceRange range)
    {
        var matches = functions.Where(function => Contains(function.SourceRange, range)).ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }

    private static bool TryReadOutputWord(
        ProtectedImageEmitRegion region,
        SemanticSourceRange functionRange,
        ulong outputAddress,
        out uint word)
    {
        word = default;
        if (outputAddress < functionRange.VirtualAddress.Value
            || outputAddress - functionRange.VirtualAddress.Value > (ulong)region.CodeBytes.Length
            || sizeof(uint) > (ulong)region.CodeBytes.Length - (outputAddress - functionRange.VirtualAddress.Value))
        {
            return false;
        }

        var offset = checked((int)(outputAddress - functionRange.VirtualAddress.Value));
        word = BinaryPrimitives.ReadUInt32LittleEndian(region.CodeBytes.AsSpan(offset, sizeof(uint)));
        return true;
    }

    private static bool TryGetSingleRegister(
        Aarch64Instruction instruction,
        Aarch64OperandDirection direction,
        out Aarch64RegisterView register)
    {
        var registers = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction == direction
                && operand.Register is not null)
            .Select(operand => operand.Register!.Value)
            .Where(candidate => candidate.Class == Aarch64RegisterClass.General
                && candidate.Role == Aarch64RegisterRole.None)
            .ToArray();
        register = registers.Length == 1 ? registers[0] : default;
        return registers.Length == 1 && register.Width == 64;
    }

    private static bool TryGetAddRegisters(
        Aarch64Instruction instruction,
        out Aarch64RegisterView source,
        out Aarch64RegisterView destination)
    {
        source = default;
        destination = default;
        var inputs = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction == Aarch64OperandDirection.Input
                && operand.Register is not null)
            .Select(operand => operand.Register!.Value)
            .Where(register => register.Class == Aarch64RegisterClass.General
                && register.Role == Aarch64RegisterRole.None)
            .ToArray();
        var outputs = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction == Aarch64OperandDirection.Output
                && operand.Register is not null)
            .Select(operand => operand.Register!.Value)
            .Where(register => register.Class == Aarch64RegisterClass.General
                && register.Role == Aarch64RegisterRole.None)
            .ToArray();
        if (inputs.Length != 1 || outputs.Length != 1 || inputs[0].Width != 64 || outputs[0].Width != 64)
        {
            return false;
        }

        source = inputs[0];
        destination = outputs[0];
        return true;
    }

    private static bool TryGetOneImmediate(Aarch64Instruction instruction, out long immediate)
    {
        var values = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null)
            .Select(operand => operand.Immediate!.Value)
            .ToArray();
        immediate = values.Length == 1 ? values[0] : default;
        return values.Length == 1;
    }

    private static bool TryGetStackSlot(
        Aarch64Instruction instruction,
        string mnemonic,
        out Aarch64RegisterView dataRegister,
        out long stackOffset)
    {
        dataRegister = default;
        stackOffset = default;
        var memory = instruction.Operands.Where(operand => operand.Memory is not null)
            .Select(operand => operand.Memory!)
            .ToArray();
        var registers = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput
                && operand.Register is not null)
            .Select(operand => operand.Register!.Value)
            .Where(register => register.Role == Aarch64RegisterRole.None && register.Class == Aarch64RegisterClass.General)
            .ToArray();
        if (!string.Equals(instruction.Mnemonic, mnemonic, StringComparison.OrdinalIgnoreCase)
            || memory.Length != 1
            || memory[0].Base.Role != Aarch64RegisterRole.StackPointer
            || memory[0].Base.Index != 31
            || memory[0].Index is not null
            || memory[0].WritesBack
            || memory[0].AccessSize != sizeof(ulong)
            || memory[0].Offset < 0
            || registers.Length != 1
            || registers[0].Width != 64)
        {
            return false;
        }

        dataRegister = registers[0];
        stackOffset = memory[0].Offset;
        return true;
    }

    private static void Error(DiagnosticBag diagnostics, string message, ulong offset) =>
        diagnostics.Error(DiagnosticCode.SemanticAddressMapMissing, message, offset);
}
