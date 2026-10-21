using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

internal sealed record Aarch64IndirectCallProofResult(
    IReadOnlyDictionary<ulong, Aarch64RuntimeIndirectCallResolution> Resolutions,
    IReadOnlyDictionary<ulong, Aarch64StaticFunctionPointerCallResolution> StaticFunctionPointerResolutions,
    IReadOnlyDictionary<ulong, string> Failures,
    IReadOnlyList<Aarch64AddressReferenceResolution> AddressReferences);

/// <summary>
/// Resolves only selected-function indirect calls whose register, stack, CFG,
/// HostContext ABI, or ELF relocation provenance is complete and bounded.
/// </summary>
internal static class Aarch64IndirectCallProofAnalyzer
{
    private const int MaximumProofInstructions = 65_536;
    private const int MaximumStackSlots = 4_096;
    private const int MaximumProducersPerValue = 64;
    private const int CallerSavedRegisterMaximum = 18;
    private const byte LinkRegister = 30;
    private const ulong StackPointerIndex = 31;
    private const uint SymbolBindingGlobal = 1;
    private const uint SymbolBindingWeak = 2;
    private const byte SymbolBindingLocal = 0;
    private const byte SymbolTypeNoType = 0;
    private const byte SymbolTypeObject = 1;
    private const byte SymbolTypeFunction = 2;
    private const ushort UndefinedSectionIndex = 0;
    private const byte DefaultVisibility = 0;
    private const byte InternalVisibility = 1;
    private const byte HiddenVisibility = 2;
    private const byte ProtectedVisibility = 3;
    private const int MaximumStaticCallOwnerScanInstructions = 128;

    public static Aarch64IndirectCallProofResult Analyze(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        ElfFunctionSymbol selectedFunction,
        ulong functionStart,
        ulong functionEnd,
        Aarch64HostContextProofContext? proofContext)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(instructions);

        var resolutions = new Dictionary<ulong, Aarch64RuntimeIndirectCallResolution>();
        var staticFunctionPointerResolutions = new Dictionary<ulong, Aarch64StaticFunctionPointerCallResolution>();
        var failures = new Dictionary<ulong, string>();
        var addressReferences = new Dictionary<(ulong PageProducer, ulong LoadAddress), Aarch64AddressReferenceResolution>();
        var conflictingAddressReferences = new HashSet<(ulong PageProducer, ulong LoadAddress)>();
        var callIndices = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(pair => IsIndirectCall(pair.instruction.Decode.Instruction))
            .ToArray();
        if (callIndices.Length == 0)
        {
            return new Aarch64IndirectCallProofResult(
                resolutions,
                staticFunctionPointerResolutions,
                failures,
                Array.Empty<Aarch64AddressReferenceResolution>());
        }

        if (instructions.Count > MaximumProofInstructions)
        {
            foreach (var pair in callIndices)
            {
                failures[pair.instruction.Address] = "The selected function exceeds the bounded indirect-call provenance instruction limit.";
            }

            return new Aarch64IndirectCallProofResult(
                resolutions,
                staticFunctionPointerResolutions,
                failures,
                Array.Empty<Aarch64AddressReferenceResolution>());
        }

        var indexByAddress = instructions
            .Select((instruction, index) => (instruction.Address, index))
            .ToDictionary(pair => pair.Address, pair => pair.index);
        var successors = BuildSuccessors(instructions, indexByAddress, functionStart, functionEnd);
        var predecessorSources = BuildPredecessorSources(successors, instructions.Count);
        var incoming = new FlowState?[instructions.Count];
        incoming[0] = FlowState.CreateEntry(proofContext);
        var pending = new Queue<int>();
        pending.Enqueue(0);
        var updateCount = 0;
        var updateLimit = checked((instructions.Count * 128) + 128);
        var converged = true;

        while (pending.Count > 0)
        {
            var index = pending.Dequeue();
            if (incoming[index] is not { } before)
            {
                continue;
            }

            var instruction = instructions[index];
            var after = Transfer(
                file,
                instruction,
                before,
                addressReferences,
                conflictingAddressReferences);
            foreach (var edge in successors[index])
            {
                var outgoing = after.Clone();
                AddEdgeProofFacts(instruction.Decode.Instruction!, before, edge, outgoing);
                var changed = false;
                if (incoming[edge.TargetIndex] is not { } existing)
                {
                    incoming[edge.TargetIndex] = outgoing;
                    changed = true;
                }
                else
                {
                    changed = MergeInto(existing, outgoing);
                }
                if (changed)
                {
                    pending.Enqueue(edge.TargetIndex);
                    updateCount++;
                    if (updateCount > updateLimit)
                    {
                        converged = false;
                        pending.Clear();
                        break;
                    }
                }
            }
        }

        foreach (var pair in callIndices)
        {
            var instruction = pair.instruction;
            if (!converged)
            {
                failures[instruction.Address] = "The selected function's bounded register/stack provenance dataflow did not converge.";
                continue;
            }

            if (incoming[pair.index] is not { } state)
            {
                failures[instruction.Address] = "The BLR target has no reachable bounded register/stack provenance state.";
                continue;
            }

            if (TryProveCall(file, instruction, state, out var resolution, out var runtimeFailure))
            {
                resolutions.Add(instruction.Address, resolution);
                continue;
            }

            if (TryProveStaticFunctionPointerCall(
                    file,
                    instructions,
                    predecessorSources,
                    selectedFunction,
                    instruction,
                    pair.index,
                    out var staticResolution,
                    out var staticApplies,
                    out var staticFailure))
            {
                staticFunctionPointerResolutions.Add(instruction.Address, staticResolution);
                continue;
            }

            failures[instruction.Address] = staticApplies
                ? staticFailure ?? "The static function-pointer call has no complete section-linked source proof."
                : runtimeFailure ?? "The BLR target has no complete HostContext callback or dynamic relocation owner proof.";
        }

        return new Aarch64IndirectCallProofResult(
            resolutions,
            staticFunctionPointerResolutions,
            failures,
            addressReferences.Values
                .OrderBy(reference => reference.PageProducerAddress)
                .ThenBy(reference => reference.LoadProducerAddress)
                .ToArray());
    }

    private static IReadOnlyList<FlowEdge>[] BuildSuccessors(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        Dictionary<ulong, int> indexByAddress,
        ulong functionStart,
        ulong functionEnd)
    {
        var graph = new IReadOnlyList<FlowEdge>[instructions.Count];
        for (var index = 0; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            var decoded = instruction.Decode.Instruction;
            var edges = new List<FlowEdge>(2);
            var nextAddress = instruction.Address <= ulong.MaxValue - sizeof(uint)
                ? instruction.Address + sizeof(uint)
                : ulong.MaxValue;
            var nextIndex = -1;
            var hasFallthrough = nextAddress < functionEnd && indexByAddress.TryGetValue(nextAddress, out nextIndex);
            switch (decoded?.ControlFlow)
            {
                case Aarch64ControlFlowKind.Return:
                    break;
                case Aarch64ControlFlowKind.DirectBranch:
                    AddTarget(decoded.DirectTarget, FlowEdgeKind.Unconditional);
                    break;
                case Aarch64ControlFlowKind.ConditionalBranch:
                    AddTarget(decoded.DirectTarget, FlowEdgeKind.BranchTaken);
                    if (hasFallthrough)
                    {
                        edges.Add(new FlowEdge(nextIndex, FlowEdgeKind.BranchNotTaken));
                    }
                    break;
                case Aarch64ControlFlowKind.DirectCall:
                case Aarch64ControlFlowKind.IndirectBranch when IsIndirectCall(decoded):
                    if (hasFallthrough)
                    {
                        edges.Add(new FlowEdge(nextIndex, FlowEdgeKind.Fallthrough));
                    }
                    break;
                case Aarch64ControlFlowKind.IndirectBranch when IsTlsDescCallMarkerMnemonic(decoded):
                    if (hasFallthrough)
                    {
                        edges.Add(new FlowEdge(nextIndex, FlowEdgeKind.Fallthrough));
                    }
                    break;
                case Aarch64ControlFlowKind.IndirectBranch:
                    break;
                default:
                    if (hasFallthrough)
                    {
                        edges.Add(new FlowEdge(nextIndex, FlowEdgeKind.Fallthrough));
                    }
                    break;
            }

            graph[index] = Array.AsReadOnly(edges.ToArray());

            void AddTarget(ulong? target, FlowEdgeKind edgeKind)
            {
                if (target is { } address
                    && address >= functionStart
                    && address < functionEnd
                    && indexByAddress.TryGetValue(address, out var targetIndex))
                {
                    edges.Add(new FlowEdge(targetIndex, edgeKind));
                }
            }
        }

        return graph;
    }

    private static IReadOnlyList<int>[] BuildPredecessorSources(
        IReadOnlyList<FlowEdge>[] successors,
        int instructionCount)
    {
        var result = Enumerable.Range(0, instructionCount)
            .Select(_ => new List<int>())
            .ToArray();
        for (var sourceIndex = 0; sourceIndex < successors.Length; sourceIndex++)
        {
            foreach (var edge in successors[sourceIndex])
            {
                result[edge.TargetIndex].Add(sourceIndex);
            }
        }

        return result.Select(sources => (IReadOnlyList<int>)Array.AsReadOnly(sources.ToArray())).ToArray();
    }

    private static bool TryProveStaticFunctionPointerCall(
        ElfFile file,
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        IReadOnlyList<int>[] predecessorSources,
        ElfFunctionSymbol selectedFunction,
        Aarch64FunctionInstruction call,
        int callIndex,
        out Aarch64StaticFunctionPointerCallResolution resolution,
        out bool applies,
        out string? failure)
    {
        resolution = null!;
        applies = false;
        failure = null;
        var targetRegister = GetIndirectCallTargetRegister(call.Decode.Instruction!);
        if (targetRegister is not { } register)
        {
            return false;
        }

        if (callIndex < 4
            || !string.Equals(
                instructions[callIndex - 4].Decode.Instruction?.Mnemonic,
                "ADRP",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        applies = true;
        var producerIndices = new[] { callIndex - 4, callIndex - 3, callIndex - 2, callIndex - 1 };
        var producerAddresses = producerIndices.Select(index => instructions[index].Address).ToArray();
        if (call.Address > ulong.MaxValue - sizeof(uint)
            || callIndex - producerIndices[0] > MaximumStaticCallOwnerScanInstructions)
        {
            failure = "The static function-pointer producer chain is not one contiguous bounded basic block ending in BLR.";
            return false;
        }

        for (var index = producerIndices[0]; index <= callIndex; index++)
        {
            var expectedPredecessors = index == producerIndices[0] && index == 0 ? 0 : 1;
            if (predecessorSources[index].Count != expectedPredecessors
                || expectedPredecessors == 1 && predecessorSources[index][0] != index - 1)
            {
                failure = "The static function-pointer producer chain has a control-flow merge or a conflicting reaching definition.";
                return false;
            }

            var instruction = instructions[index].Decode.Instruction!;
            if (index < callIndex && instruction.ControlFlow != Aarch64ControlFlowKind.None)
            {
                failure = "The static function-pointer producer chain crosses an intervening control-flow edge.";
                return false;
            }
        }

        var adrp = instructions[producerIndices[0]];
        var add = instructions[producerIndices[1]];
        var store = instructions[producerIndices[2]];
        var load = instructions[producerIndices[3]];
        if (!TryGetSingleOutputRegister(adrp.Decode.Instruction!, out var addressRegister)
            || addressRegister.Class != Aarch64RegisterClass.General
            || addressRegister.Width != 64
            || addressRegister.Role != Aarch64RegisterRole.None
            || !string.Equals(adrp.Decode.Instruction!.Mnemonic, "ADRP", StringComparison.OrdinalIgnoreCase)
            || adrp.Decode.Instruction.DirectTarget is not { } pageAddress
            || (pageAddress & 0xFFFUL) != 0
            || !TryGetAddImmediate(add.Decode.Instruction!, out var addSource, out var addDestination, out var addImmediate)
            || addSource != addressRegister
            || addDestination != addressRegister
            || addImmediate is < 0 or > 0xFFF
            || !TryGetStackStore(store.Decode.Instruction!, out var storedRegister, out var storeSlot)
            || storedRegister != addressRegister
            || !TryGetStackLoad(load.Decode.Instruction!, out var loadedRegister, out var loadSlot)
            || loadedRegister != register
            || loadSlot != storeSlot)
        {
            failure = "The static function-pointer producer chain does not preserve one exact ADRP/ADD expression through the same 64-bit stack slot to BLR.";
            return false;
        }

        var callerSectionIndex = selectedFunction.SectionIndex;
        if (callerSectionIndex == UndefinedSectionIndex
            || callerSectionIndex >= file.SectionHeaders.Count
            || !TryGetExecutableFileBackedSectionRange(
                file,
                callerSectionIndex,
                selectedFunction.Value,
                selectedFunction.Size,
                out _))
        {
            failure = "The static function-pointer caller is not contained in one exact executable, file-backed source section.";
            return false;
        }

        var adrpRows = file.SectionRelocations
            .Where(row => row.Relocation.Offset == adrp.Address
                && row.Relocation.Type == ElfConstants.RArm64AdrPrelPgHi21)
            .ToArray();
        var addRows = file.SectionRelocations
            .Where(row => row.Relocation.Offset == add.Address
                && row.Relocation.Type == ElfConstants.RArm64AddAbsLo12Nc)
            .ToArray();
        if (adrpRows.Length != 1 || addRows.Length != 1)
        {
            failure = "The static function-pointer ADRP/ADD producer pair lacks exactly one matching section-linked RELA row per site.";
            return false;
        }

        var adrpRow = adrpRows[0];
        var addRow = addRows[0];
        var relocationSectionIndex = adrpRow.RelocationSectionIndex;
        var symbolTableSectionIndex = adrpRow.SymbolTableSectionIndex;
        if (relocationSectionIndex < 0
            || relocationSectionIndex != addRow.RelocationSectionIndex
            || symbolTableSectionIndex == 0
            || symbolTableSectionIndex != addRow.SymbolTableSectionIndex
            || adrpRow.TargetSectionIndex != callerSectionIndex
            || addRow.TargetSectionIndex != callerSectionIndex
            || adrpRow.Relocation.SymbolIndex == 0
            || adrpRow.Relocation.SymbolIndex != addRow.Relocation.SymbolIndex
            || adrpRow.Relocation.Addend != 0
            || addRow.Relocation.Addend != 0
            || adrpRow.Relocation.IsPlt
            || addRow.Relocation.IsPlt
            || adrpRow.Symbol is not { } symbol
            || addRow.Symbol is not { } addSymbol
            || symbol != addSymbol
            || symbol.SymbolTableSectionIndex != symbolTableSectionIndex
            || symbol.SymbolIndex != adrpRow.Relocation.SymbolIndex
            || symbol.Type != SymbolTypeFunction
            || symbol.SectionIndex == UndefinedSectionIndex
            || symbol.Binding != SymbolBindingLocal
                && symbol.Visibility == DefaultVisibility
            || pageAddress > ulong.MaxValue - checked((ulong)addImmediate)
            || pageAddress + checked((ulong)addImmediate) != symbol.Value
            || symbol.Size == 0
            || (symbol.Value & 3) != 0
            || symbol.Size % sizeof(uint) != 0
            || symbol.SectionIndex >= file.SectionHeaders.Count
            || relocationSectionIndex >= file.SectionHeaders.Count
            || symbolTableSectionIndex >= file.SectionHeaders.Count)
        {
            failure = "The static function-pointer RELA pair does not identify one exact same-image, non-preemptible STT_FUNC symbol and section owner.";
            return false;
        }

        var relocationSection = file.SectionHeaders[relocationSectionIndex];
        var symbolTableSection = file.SectionHeaders[checked((int)symbolTableSectionIndex)];
        var callerSection = file.SectionHeaders[callerSectionIndex];
        var targetSection = file.SectionHeaders[symbol.SectionIndex];
        if (relocationSection.Type != ElfConstants.ShtRela
            || relocationSection.EntrySize != ElfConstants.RelaEntrySize64
            || relocationSection.Link != symbolTableSectionIndex
            || relocationSection.Info != callerSectionIndex
            || symbolTableSection.Type != ElfConstants.ShtSymTab
            || symbolTableSection.EntrySize != ElfConstants.SymbolEntrySize64
            || targetSection.Type == ElfConstants.ShtNobits
            || (targetSection.Flags & ElfConstants.ShfExecInstr) == 0
            || !TryGetExecutableFileBackedSectionRange(
                file,
                callerSectionIndex,
                selectedFunction.Value,
                selectedFunction.Size,
                out _)
            || !TryGetExecutableFileBackedSectionRange(
                file,
                symbol.SectionIndex,
                symbol.Value,
                symbol.Size,
                out var targetFileOffset))
        {
            failure = "The static function-pointer RELA sh_link/sh_info or executable section/file-range ownership is inconsistent.";
            return false;
        }

        if (!TryGetSingleSectionRelocationRow(file, adrpRow, adrp.Address, ElfConstants.RArm64AdrPrelPgHi21)
            || !TryGetSingleSectionRelocationRow(file, addRow, add.Address, ElfConstants.RArm64AddAbsLo12Nc)
            || !TryGetTargetRegisterForCall(call.Decode.Instruction!, out var decodedTargetRegister)
            || decodedTargetRegister != register)
        {
            failure = "The static function-pointer relocation sites or BLR register differ from their independently decoded source instructions.";
            return false;
        }

        resolution = new Aarch64StaticFunctionPointerCallResolution(
            call.Address,
            register,
            producerAddresses,
            storeSlot,
            selectedFunction,
            adrpRow,
            addRow,
            relocationSection,
            symbolTableSection,
            callerSection,
            targetSection,
            targetFileOffset,
            symbol.Value,
            symbol.Size);
        return true;
    }

    private static bool TryGetSingleSectionRelocationRow(
        ElfFile file,
        ElfSectionRelocation row,
        ulong siteAddress,
        uint relocationType)
    {
        var matches = file.SectionRelocations.Count(candidate =>
            candidate.RelocationSectionIndex == row.RelocationSectionIndex
            && candidate.SymbolTableSectionIndex == row.SymbolTableSectionIndex
            && candidate.TargetSectionIndex == row.TargetSectionIndex
            && candidate.Relocation.Offset == siteAddress
            && candidate.Relocation.Type == relocationType
            && candidate.Relocation.SourceAddress == row.Relocation.SourceAddress
            && candidate.Relocation.Info == row.Relocation.Info
            && candidate.Relocation.Addend == row.Relocation.Addend);
        return matches == 1;
    }

    private static bool TryGetExecutableFileBackedSectionRange(
        ElfFile file,
        ushort sectionIndex,
        ulong address,
        ulong size,
        out FileOffset fileOffset)
    {
        fileOffset = default;
        if (sectionIndex == UndefinedSectionIndex
            || sectionIndex >= file.SectionHeaders.Count
            || size == 0
            || address > ulong.MaxValue - size)
        {
            return false;
        }

        var section = file.SectionHeaders[sectionIndex];
        if (section.Type == ElfConstants.ShtNobits
            || (section.Flags & ElfConstants.ShfExecInstr) == 0
            || address < section.Address
            || address - section.Address > section.Size
            || size > section.Size - (address - section.Address)
            || section.Offset > ulong.MaxValue - (address - section.Address))
        {
            return false;
        }

        var expectedOffset = section.Offset + (address - section.Address);
        if (expectedOffset > (ulong)file.Bytes.Length
            || size > (ulong)file.Bytes.Length - expectedOffset
            || !file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), size, out fileOffset)
            || fileOffset.Value != expectedOffset)
        {
            return false;
        }

        return file.LoadMap.Segments.Count(segment =>
            segment.IsExecutable
            && segment.ContainsVirtualAddress(address, size)
            && segment.ContainsFileOffset(expectedOffset, size)
            && address - segment.VirtualAddress == expectedOffset - segment.FileOffset) == 1;
    }

    private static bool TryGetSingleOutputRegister(
        Aarch64Instruction instruction,
        out Aarch64RegisterView register)
    {
        var outputs = GetOutputRegisters(instruction)
            .Where(candidate => candidate.Class == Aarch64RegisterClass.General
                && candidate.Role == Aarch64RegisterRole.None)
            .ToArray();
        register = outputs.Length == 1 ? outputs[0] : default;
        return outputs.Length == 1;
    }

    private static bool TryGetAddImmediate(
        Aarch64Instruction instruction,
        out Aarch64RegisterView source,
        out Aarch64RegisterView destination,
        out long immediate)
    {
        source = default;
        destination = default;
        immediate = default;
        if (!string.Equals(instruction.Mnemonic, "ADD", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var inputs = GetInputRegisters(instruction)
            .Where(candidate => candidate.Class == Aarch64RegisterClass.General
                && candidate.Role == Aarch64RegisterRole.None)
            .ToArray();
        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null)
            .Select(operand => operand.Immediate!.Value)
            .ToArray();
        if (inputs.Length != 1
            || !TryGetSingleOutputRegister(instruction, out destination)
            || destination.Width != 64
            || inputs[0].Width != 64
            || immediates.Length != 1)
        {
            return false;
        }

        source = inputs[0];
        immediate = immediates[0];
        return true;
    }

    private static bool TryGetStackStore(
        Aarch64Instruction instruction,
        out Aarch64RegisterView source,
        out long stackSlot)
    {
        source = default;
        stackSlot = default;
        var memories = instruction.Operands.Where(operand => operand.Memory is not null)
            .Select(operand => operand.Memory!)
            .ToArray();
        var inputs = GetInputRegisters(instruction)
            .Where(candidate => candidate.Class == Aarch64RegisterClass.General
                && candidate.Role == Aarch64RegisterRole.None)
            .ToArray();
        if (!string.Equals(instruction.Mnemonic, "STR", StringComparison.OrdinalIgnoreCase)
            || memories.Length != 1
            || memories[0].Base.Role != Aarch64RegisterRole.StackPointer
            || memories[0].Base.Index != StackPointerIndex
            || memories[0].Index is not null
            || memories[0].WritesBack
            || memories[0].AccessSize != sizeof(ulong)
            || memories[0].Offset < 0
            || inputs.Length != 1
            || inputs[0].Width != 64)
        {
            return false;
        }

        source = inputs[0];
        stackSlot = memories[0].Offset;
        return true;
    }

    private static bool TryGetStackLoad(
        Aarch64Instruction instruction,
        out Aarch64RegisterView destination,
        out long stackSlot)
    {
        destination = default;
        stackSlot = default;
        var memories = instruction.Operands.Where(operand => operand.Memory is not null)
            .Select(operand => operand.Memory!)
            .ToArray();
        if (!string.Equals(instruction.Mnemonic, "LDR", StringComparison.OrdinalIgnoreCase)
            || memories.Length != 1
            || memories[0].Base.Role != Aarch64RegisterRole.StackPointer
            || memories[0].Base.Index != StackPointerIndex
            || memories[0].Index is not null
            || memories[0].WritesBack
            || memories[0].AccessSize != sizeof(ulong)
            || memories[0].Offset < 0
            || !TryGetSingleOutputRegister(instruction, out destination)
            || destination.Width != 64)
        {
            return false;
        }

        stackSlot = memories[0].Offset;
        return true;
    }

    private static Aarch64RegisterView[] GetInputRegisters(Aarch64Instruction instruction) => instruction.Operands
        .Where(operand => operand.Kind == Aarch64OperandKind.Register
            && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
            && operand.Register is not null)
        .Select(operand => operand.Register!.Value)
        .ToArray();

    private static bool TryGetTargetRegisterForCall(
        Aarch64Instruction instruction,
        out Aarch64RegisterView register)
    {
        var target = GetIndirectCallTargetRegister(instruction);
        register = target.GetValueOrDefault();
        return target.HasValue;
    }

    private static FlowState Transfer(
        ElfFile file,
        Aarch64FunctionInstruction source,
        FlowState before,
        IDictionary<(ulong PageProducer, ulong LoadAddress), Aarch64AddressReferenceResolution> addressReferences,
        ISet<(ulong PageProducer, ulong LoadAddress)> conflictingAddressReferences)
    {
        var decoded = source.Decode.Instruction!;
        var state = before.Clone();
        var mnemonic = decoded.Mnemonic;

        if (decoded.ControlFlow == Aarch64ControlFlowKind.DirectCall
            || IsIndirectCall(decoded))
        {
            ApplyCallClobbers(before, state);
            return state;
        }

        var isComparison = IsComparisonInstruction(decoded);
        if (decoded.Properties.HasFlag(Aarch64InstructionProperties.WritesNzcv) && !isComparison)
        {
            state.Condition = null;
        }

        var outputs = GetOutputRegisters(decoded).ToArray();
        foreach (var output in outputs)
        {
            state.Registers.Remove(RegisterKey.From(output));
        }

        var memory = decoded.Operands
            .Select(operand => operand.Memory)
            .FirstOrDefault(operand => operand is not null);
        if (memory?.WritesBack == true)
        {
            state.Registers.Remove(RegisterKey.From(memory.Base));
        }

        if (TryTransferMove(decoded, source.Address, before, state)
            || TryTransferMoveWide(decoded, source.Address, before, state)
            || TryTransferPcRelativeAddress(
                file,
                decoded,
                source.Address,
                state,
                addressReferences,
                conflictingAddressReferences)
            || TryTransferAddSubtract(decoded, source.Address, before, state)
            || TryTransferThreadPointer(source, decoded, state))
        {
            return state;
        }

        if (isComparison)
        {
            state.Condition = CreateComparison(decoded, before, source.Address);
            return state;
        }

        if (decoded.MemoryEffect != Aarch64MemoryEffect.None
            || decoded.Operands.Any(operand => operand.Memory is not null))
        {
            switch (decoded.MemoryEffect)
            {
                case Aarch64MemoryEffect.Read:
                    if (mnemonic.StartsWith("ldr", StringComparison.OrdinalIgnoreCase)
                        || mnemonic.StartsWith("ldp", StringComparison.OrdinalIgnoreCase))
                    {
                        TransferLoad(file, source, before, state, addressReferences, conflictingAddressReferences);
                    }

                    return state;
                case Aarch64MemoryEffect.PlainWrite:
                    TransferStore(source, before, state);
                    return state;
                case Aarch64MemoryEffect.ReadModifyWrite:
                case Aarch64MemoryEffect.ConditionalWrite:
                case Aarch64MemoryEffect.Unclassified:
                case Aarch64MemoryEffect.None:
                default:
                    InvalidateUnknownMemoryWrite(state);
                    return state;
            }
        }

        return state;
    }

    private static bool TryTransferMove(
        Aarch64Instruction instruction,
        ulong address,
        FlowState before,
        FlowState state)
    {
        var isMoveAlias = instruction.Mnemonic.Equals("mov", StringComparison.OrdinalIgnoreCase);
        var isZeroingOrAlias = instruction.Mnemonic.Equals("orr", StringComparison.OrdinalIgnoreCase);
        if (!isMoveAlias && !isZeroingOrAlias)
        {
            return false;
        }

        var outputs = GetOutputRegisters(instruction)
            .Where(IsGeneralRegister)
            .ToArray();
        if (outputs.Length != 1)
        {
            return false;
        }

        var inputRegisters = instruction.Operands
            .Where(operand => operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput)
            .Where(operand => operand.Kind == Aarch64OperandKind.Register && operand.Register is { } register && IsGeneralRegister(register))
            .Select(operand => operand.Register!.Value)
            .ToArray();
        var copyInputs = inputRegisters.Where(register => register.Role != Aarch64RegisterRole.Zero).ToArray();
        var zeroRegisterInputs = inputRegisters.Count(register => register.Role == Aarch64RegisterRole.Zero);
        if (copyInputs.Length == 1
            && (inputRegisters.Length == 1
                    && !instruction.Operands.Any(operand => operand.Kind == Aarch64OperandKind.Immediate)
                || isZeroingOrAlias
                    && inputRegisters.Length == 2
                    && zeroRegisterInputs == 1
                    && instruction.Operands
                        .Where(operand => operand.Kind == Aarch64OperandKind.Immediate)
                        .All(operand => operand.Immediate == 0))
            && outputs[0].Width == 64
            && copyInputs[0].Width == 64)
        {
            var value = ReadRegister(before, copyInputs[0]);
            state.Set(RegisterKey.From(outputs[0]), value.AddProducer(address));
            return true;
        }

        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null)
            .Select(operand => operand.Immediate!.Value)
            .ToArray();
        if (inputRegisters.Length == 0 && outputs[0].Width is 32 or 64 && immediates.Length == 1)
        {
            state.Set(RegisterKey.From(outputs[0]), FlowValue.Constant(immediates[0]).AddProducer(address));
            return true;
        }

        return false;
    }

    private static bool TryTransferMoveWide(
        Aarch64Instruction instruction,
        ulong address,
        FlowState before,
        FlowState state)
    {
        var mnemonic = instruction.Mnemonic;
        if (!mnemonic.StartsWith("movz", StringComparison.OrdinalIgnoreCase)
            && !mnemonic.StartsWith("movn", StringComparison.OrdinalIgnoreCase)
            && !mnemonic.StartsWith("movk", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var outputs = GetOutputRegisters(instruction).Where(IsGeneralRegister).ToArray();
        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null)
            .Select(operand => operand.Immediate!.Value)
            .ToArray();
        if (outputs.Length != 1
            || outputs[0].Width is not (32 or 64)
            || immediates.Length is < 1 or > 2
            || immediates[0] is < 0 or > ushort.MaxValue)
        {
            return false;
        }

        var shift = immediates.Length == 2 ? immediates[1] : 0;
        if (shift is not (0 or 16 or 32 or 48)
            || shift >= outputs[0].Width)
        {
            return false;
        }

        var baseValue = checked((ulong)immediates[0]);
        var key = RegisterKey.From(outputs[0]);
        if (mnemonic.StartsWith("movz", StringComparison.OrdinalIgnoreCase))
        {
            state.Set(key, FlowValue.Constant(unchecked((long)(baseValue << checked((int)shift)))).AddProducer(address));
            return true;
        }

        if (mnemonic.StartsWith("movn", StringComparison.OrdinalIgnoreCase))
        {
            var value = ~(baseValue << checked((int)shift));
            if (outputs[0].Width == 32)
            {
                value &= uint.MaxValue;
            }

            state.Set(key, FlowValue.Constant(unchecked((long)value)).AddProducer(address));
            return true;
        }

        if (before.Registers.TryGetValue(key, out var previous) && previous.Kind == FlowValueKind.Constant)
        {
            var mask = 0xFFFFUL << checked((int)shift);
            var merged = (unchecked((ulong)previous.ConstantValue) & ~mask) | (baseValue << checked((int)shift));
            if (outputs[0].Width == 32)
            {
                merged &= uint.MaxValue;
            }

            state.Set(key, FlowValue.Constant(unchecked((long)merged))
                .WithProducers(previous.Producers, previous.ProducerOverflow)
                .AddProducer(address));
        }

        return true;
    }

    private static bool TryTransferPcRelativeAddress(
        ElfFile file,
        Aarch64Instruction instruction,
        ulong address,
        FlowState state,
        IDictionary<(ulong PageProducer, ulong LoadAddress), Aarch64AddressReferenceResolution> addressReferences,
        ISet<(ulong PageProducer, ulong LoadAddress)> conflictingAddressReferences)
    {
        if (!instruction.Properties.HasFlag(Aarch64InstructionProperties.PcRelative)
            || !instruction.Mnemonic.Equals("adrp", StringComparison.OrdinalIgnoreCase)
            && !instruction.Mnemonic.Equals("adr", StringComparison.OrdinalIgnoreCase)
            || instruction.DirectTarget is not { } target)
        {
            return false;
        }

        var outputs = GetOutputRegisters(instruction)
            .Where(register => register.Class == Aarch64RegisterClass.General
                && register.Width == 64
                && register.Role == Aarch64RegisterRole.None)
            .ToArray();
        if (outputs.Length != 1)
        {
            return false;
        }

        var isPageRelative = instruction.Mnemonic.Equals("adrp", StringComparison.OrdinalIgnoreCase);
        if (isPageRelative && (target & 0xFFFUL) != 0)
        {
            return false;
        }

        state.Set(
            RegisterKey.From(outputs[0]),
            FlowValue.ElfAddress(
                target,
                isPageRelative ? address : null,
                isPageRelative,
                isPageRelative ? target : null).AddProducer(address));
        if (isPageRelative
            && TryGetMappedRange(file, target, 1, out _))
        {
            var key = (address, address);
            var reference = new Aarch64AddressReferenceResolution(
                address,
                address,
                new VirtualAddress(target),
                new VirtualAddress(target),
                1,
                null,
                null,
                "The selected ADRP operand resolves to one checked, page-aligned, file-backed source page.");
            if (!conflictingAddressReferences.Contains(key))
            {
                addressReferences[key] = reference;
            }
        }

        return true;
    }

    private static bool TryTransferAddSubtract(
        Aarch64Instruction instruction,
        ulong address,
        FlowState before,
        FlowState state)
    {
        var isAdd = instruction.Mnemonic.Equals("add", StringComparison.OrdinalIgnoreCase);
        var isSubtract = instruction.Mnemonic.Equals("sub", StringComparison.OrdinalIgnoreCase);
        if (!isAdd && !isSubtract)
        {
            return false;
        }

        var outputs = GetOutputRegisters(instruction)
            .Where(register => register.Class == Aarch64RegisterClass.General
                && register.Role is Aarch64RegisterRole.None or Aarch64RegisterRole.StackPointer)
            .ToArray();
        var inputs = instruction.Operands
            .Where(operand => operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput)
            .Where(operand => operand.Kind == Aarch64OperandKind.Register && operand.Register is { } register
                && register.Class == Aarch64RegisterClass.General
                && register.Role is Aarch64RegisterRole.None or Aarch64RegisterRole.StackPointer)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null)
            .Select(operand => operand.Immediate!.Value)
            .ToArray();
        if (outputs.Length != 1 || inputs.Length != 1 || immediates.Length != 1)
        {
            return false;
        }

        var source = ReadRegister(before, inputs[0]);
        var adjustment = isSubtract ? -immediates[0] : immediates[0];
        if (TryAdjustAddress(source, adjustment, out var adjusted))
        {
            state.Set(RegisterKey.From(outputs[0]), adjusted.AddProducer(address));
        }
        else if (source.Kind == FlowValueKind.Constant
            && TryAdjustSigned(source.ConstantValue, adjustment, out var constant))
        {
            state.Set(RegisterKey.From(outputs[0]), FlowValue.Constant(constant).AddProducer(address));
        }

        return true;
    }

    private static bool TryTransferThreadPointer(
        Aarch64FunctionInstruction source,
        Aarch64Instruction instruction,
        FlowState state)
    {
        if (!instruction.Mnemonic.Equals("mrs", StringComparison.OrdinalIgnoreCase)
            || (source.Encoding & 0xFFFFFFE0u) != 0xD53BD040u)
        {
            return false;
        }

        var outputs = GetOutputRegisters(instruction)
            .Where(register => register.Class == Aarch64RegisterClass.General
                && register.Width == 64
                && register.Role == Aarch64RegisterRole.None)
            .ToArray();
        if (outputs.Length != 1)
        {
            return false;
        }

        state.Set(RegisterKey.From(outputs[0]), FlowValue.ThreadPointer().AddProducer(source.Address));
        return true;
    }

    private static void TransferLoad(
        ElfFile file,
        Aarch64FunctionInstruction source,
        FlowState before,
        FlowState state,
        IDictionary<(ulong PageProducer, ulong LoadAddress), Aarch64AddressReferenceResolution> addressReferences,
        ISet<(ulong PageProducer, ulong LoadAddress)> conflictingAddressReferences)
    {
        var instruction = source.Decode.Instruction!;
        var memory = instruction.Operands
            .Select(operand => operand.Memory)
            .FirstOrDefault(operand => operand is not null);
        var destinations = GetOutputRegisters(instruction)
            .Where(IsGeneralRegister)
            .ToArray();
        if (memory is null || destinations.Length == 0)
        {
            return;
        }

        if (instruction.Mnemonic.StartsWith("ldp", StringComparison.OrdinalIgnoreCase))
        {
            TransferPairLoad(source, before, state, memory, destinations);
            return;
        }

        if (destinations.Length != 1
            || destinations[0].Width % 8 != 0
            || memory.Index is not null
            || memory.WritesBack)
        {
            return;
        }

        var accessSize = memory.AccessSize;
        if (accessSize <= 0 || accessSize != destinations[0].Width / 8)
        {
            return;
        }

        var baseValue = ReadRegister(before, memory.Base);
        if (before.ProofContext is { } proofContext
            && (baseValue.Kind == FlowValueKind.HostContextBase
                || baseValue.Kind == FlowValueKind.HostContextAddress))
        {
            if (!TryAddSigned(baseValue.Offset, memory.Offset, out var fieldOffset)
                || fieldOffset is < 0 or > int.MaxValue)
            {
                return;
            }

            var offset = checked((uint)fieldOffset);
            FlowValue fieldValue;
            if (accessSize == sizeof(ulong)
                && destinations[0].Width == 64
                && (offset == proofContext.EmitDiagnosticCallbackOffset
                    || offset == proofContext.CreateImageThreadCallbackOffset
                    || offset == proofContext.JoinImageThreadCallbackOffset))
            {
                fieldValue = FlowValue.HostCallback(offset);
            }
            else
            {
                fieldValue = FlowValue.HostContextField(offset, accessSize);
            }

            state.Set(
                RegisterKey.From(destinations[0]),
                fieldValue.WithProducers(baseValue.Producers, baseValue.ProducerOverflow).AddProducer(source.Address));
            return;
        }

        if (baseValue.Kind == FlowValueKind.StackAddress)
        {
            if (!TryAddSigned(baseValue.StackOffset, memory.Offset, out var slotAddress))
            {
                return;
            }

            if (before.StackSlots.TryGetValue(slotAddress, out var slot)
                && slot.Size == accessSize)
            {
                state.Set(RegisterKey.From(destinations[0]), slot.Value.AddProducer(source.Address));
            }

            return;
        }

        if (baseValue.Kind != FlowValueKind.ElfAddress
            || !TryAddSigned(baseValue.Address, memory.Offset, out var effectiveAddress)
            || effectiveAddress < 0)
        {
            return;
        }

        var targetAddress = checked((ulong)effectiveAddress);
        var ownerFacts = file.RelaRelocations
            .Where(relocation => relocation.Offset == targetAddress)
            .ToArray();
        RelaRelocation? owner = ownerFacts.Length == 1 ? ownerFacts[0] : null;
        Aarch64DynamicImportBinding? import = null;
        var invalidImportOwner = (string?)null;
        if (accessSize == sizeof(ulong)
            && destinations[0].Width == 64
            && owner is { Type: ElfConstants.RArm64GlobDat, IsPlt: false } relocation)
        {
            if (TryResolveImportOwner(
                    file,
                    relocation,
                    targetAddress,
                    baseValue.PageAddress,
                    baseValue.PageProducerAddress,
                    source.Address,
                    out var resolvedImport,
                    out var importFailure))
            {
                import = resolvedImport;
            }
            else
            {
                invalidImportOwner = importFailure;
            }
        }

        if (baseValue.IsPageRelative
            && baseValue.PageAddress is { } pageAddress
            && (pageAddress & 0xFFFUL) == 0
            && baseValue.PageProducerAddress is { } pageProducer
            && TryGetMappedRange(file, targetAddress, checked((ulong)accessSize), out _)
            && !conflictingAddressReferences.Contains((pageProducer, source.Address)))
        {
            var reference = new Aarch64AddressReferenceResolution(
                pageProducer,
                source.Address,
                new VirtualAddress(pageAddress),
                new VirtualAddress(targetAddress),
                checked((uint)accessSize),
                owner,
                import,
                "An ADRP-derived register plus the decoded memory displacement reaches one file-backed source range.");
            var key = (pageProducer, source.Address);
            if (addressReferences.TryGetValue(key, out var existing)
                && (existing.TargetAddress != reference.TargetAddress
                    || existing.AccessSize != reference.AccessSize
                    || existing.RelocationOwner != reference.RelocationOwner))
            {
                addressReferences.Remove(key);
                conflictingAddressReferences.Add(key);
            }
            else
            {
                addressReferences[key] = reference;
            }
        }

        if (import is not null)
        {
            state.Set(
                RegisterKey.From(destinations[0]),
                FlowValue.ImportedFunction(import)
                    .WithProducers(baseValue.Producers, baseValue.ProducerOverflow)
                    .AddProducer(source.Address));
        }
        else if (invalidImportOwner is not null)
        {
            state.Set(
                RegisterKey.From(destinations[0]),
                FlowValue.InvalidOwner(invalidImportOwner).AddProducer(source.Address));
        }
    }

    private static void TransferPairLoad(
        Aarch64FunctionInstruction source,
        FlowState before,
        FlowState state,
        Aarch64MemoryReference memory,
        IReadOnlyList<Aarch64RegisterView> destinations)
    {
        if (memory.Index is not null
            || memory.WritesBack
            || destinations.Count != 2
            || destinations.Any(register => register.Width % 8 != 0)
            || destinations[0].Width != destinations[1].Width
            || ReadRegister(before, memory.Base).Kind != FlowValueKind.StackAddress)
        {
            return;
        }

        var elementSize = destinations[0].Width / 8;
        if (memory.AccessSize != elementSize
            && memory.AccessSize != elementSize * destinations.Count)
        {
            return;
        }

        var baseAddress = ReadRegister(before, memory.Base).StackOffset;
        if (!TryAddSigned(baseAddress, memory.Offset, out var firstAddress)
            || !TryAddSigned(firstAddress, elementSize, out var secondAddress))
        {
            return;
        }

        if (before.StackSlots.TryGetValue(firstAddress, out var first) && first.Size == elementSize)
        {
            state.Set(RegisterKey.From(destinations[0]), first.Value.AddProducer(source.Address));
        }

        if (before.StackSlots.TryGetValue(secondAddress, out var second) && second.Size == elementSize)
        {
            state.Set(RegisterKey.From(destinations[1]), second.Value.AddProducer(source.Address));
        }
    }

    private static void TransferStore(
        Aarch64FunctionInstruction source,
        FlowState before,
        FlowState state)
    {
        var instruction = source.Decode.Instruction!;
        var memory = instruction.Operands
            .Select(operand => operand.Memory)
            .FirstOrDefault(operand => operand is not null);
        var storedRegisters = instruction.Operands
            .Where(operand => operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput)
            .SelectMany(operand => operand.Kind == Aarch64OperandKind.Register && operand.Register is { } register
                ? new[] { register }
                : operand.Kind == Aarch64OperandKind.RegisterPair
                    ? operand.Registers
                    : Array.Empty<Aarch64RegisterView>())
            .Where(IsGeneralRegister)
            .ToArray();
        if (memory is null)
        {
            InvalidateUnknownMemoryWrite(state);
            return;
        }

        var baseValue = ReadRegister(before, memory.Base);
        if (baseValue.Kind != FlowValueKind.StackAddress
            && storedRegisters.Any(register => ReadRegister(before, register).Kind == FlowValueKind.StackAddress))
        {
            state.MayHaveEscapedStackAddress = true;
            state.StackSlots.Clear();
        }

        if (baseValue.Kind is FlowValueKind.HostContextBase or FlowValueKind.HostContextAddress)
        {
            if (memory.Index is not null || memory.WritesBack || memory.AccessSize <= 0)
            {
                InvalidateAllHostContextFacts(state);
            }
            else
            {
                InvalidateHostGuardsForStore(state, baseValue, memory.Offset, memory.AccessSize);
            }

            return;
        }

        if (baseValue.Kind is FlowValueKind.ThreadPointer or FlowValueKind.ElfAddress)
        {
            // These addresses are not proven disjoint from the opaque HostContext
            // root or local spill range. Treat writes through them as unknown effects.
            InvalidateUnknownMemoryWrite(state);
            return;
        }

        if (baseValue.Kind != FlowValueKind.StackAddress
            || memory.Index is not null
            || memory.WritesBack
            || memory.AccessSize <= 0
            || storedRegisters.Length == 0)
        {
            state.StackSlots.Clear();
            InvalidateAllHostContextFacts(state);
            return;
        }

        var elementSize = storedRegisters[0].Width / 8;
        if (elementSize == 0
            || storedRegisters.Any(register => register.Width / 8 != elementSize)
            || memory.AccessSize != elementSize
                && memory.AccessSize != elementSize * storedRegisters.Length
            || !TryAddSigned(baseValue.StackOffset, memory.Offset, out var firstAddress))
        {
            state.StackSlots.Clear();
            return;
        }

        for (var registerIndex = 0; registerIndex < storedRegisters.Length; registerIndex++)
        {
            if (!TryAddSigned(firstAddress, checked((long)registerIndex * elementSize), out var slotAddress))
            {
                state.StackSlots.Clear();
                return;
            }

            var value = ReadRegister(before, storedRegisters[registerIndex]).AddProducer(source.Address);
            StoreStackSlot(state, slotAddress, elementSize, value);
        }
    }

    private static void InvalidateUnknownMemoryWrite(FlowState state)
    {
        state.StackSlots.Clear();
        InvalidateAllHostContextFacts(state);
    }

    private static void InvalidateAllHostContextFacts(FlowState state)
    {
        state.Guards.Clear();
        state.Condition = null;
        foreach (var key in state.Registers
            .Where(pair => pair.Value.Kind is FlowValueKind.HostContextField or FlowValueKind.HostCallback)
            .Select(pair => pair.Key)
            .ToArray())
        {
            state.Registers.Remove(key);
        }

        foreach (var key in state.StackSlots
            .Where(pair => pair.Value.Value.Kind is FlowValueKind.HostContextField or FlowValueKind.HostCallback)
            .Select(pair => pair.Key)
            .ToArray())
        {
            state.StackSlots.Remove(key);
        }
    }

    private static void StoreStackSlot(FlowState state, long address, int size, FlowValue value)
    {
        var overlapping = state.StackSlots
            .Where(pair => RangesOverlap(pair.Key, pair.Value.Size, address, size))
            .Select(pair => pair.Key)
            .ToArray();
        foreach (var key in overlapping)
        {
            state.StackSlots.Remove(key);
        }

        if (state.StackSlots.Count < MaximumStackSlots)
        {
            state.StackSlots[address] = new StackSlot(value, size);
        }
    }

    private static void InvalidateHostGuardsForStore(
        FlowState state,
        FlowValue baseValue,
        long memoryOffset,
        int accessSize)
    {
        if (!TryAddSigned(baseValue.Offset, memoryOffset, out var offset) || accessSize <= 0)
        {
            InvalidateAllHostContextFacts(state);
            return;
        }

        if (state.Condition is { } condition
            && (IsOverlappingHostField(condition.Left, offset, accessSize)
                || IsOverlappingHostField(condition.Right, offset, accessSize)))
        {
            state.Condition = null;
        }

        if (state.ProofContext is not { } proofContext)
        {
            InvalidateAllHostContextFacts(state);
            return;
        }

        if (RangesOverlap(offset, accessSize, proofContext.StructSizeOffset, sizeof(uint)))
        {
            state.Guards.Remove(ProofGuard.ThreadLifetimeTableSize);
        }

        if (RangesOverlap(offset, accessSize, proofContext.CapabilitiesOffset, sizeof(ulong)))
        {
            state.Guards.Remove(ProofGuard.ThreadLifetimeCapability);
        }

        if (RangesOverlap(offset, accessSize, proofContext.EmitDiagnosticCallbackOffset, sizeof(ulong)))
        {
            state.Guards.Remove(ProofGuard.EmitDiagnosticNonNull);
        }

        if (RangesOverlap(offset, accessSize, proofContext.CreateImageThreadCallbackOffset, sizeof(ulong)))
        {
            state.Guards.Remove(ProofGuard.CreateImageThreadNonNull);
        }

        if (RangesOverlap(offset, accessSize, proofContext.JoinImageThreadCallbackOffset, sizeof(ulong)))
        {
            state.Guards.Remove(ProofGuard.JoinImageThreadNonNull);
        }

        foreach (var key in state.Registers
            .Where(pair => IsOverlappingHostField(pair.Value, offset, accessSize))
            .Select(pair => pair.Key)
            .ToArray())
        {
            state.Registers.Remove(key);
        }

        foreach (var key in state.StackSlots
            .Where(pair => IsOverlappingHostField(pair.Value.Value, offset, accessSize))
            .Select(pair => pair.Key)
            .ToArray())
        {
            state.StackSlots.Remove(key);
        }
    }

    private static bool IsOverlappingHostField(FlowValue value, long offset, int accessSize)
    {
        var width = value.Kind switch
        {
            FlowValueKind.HostCallback => sizeof(ulong),
            FlowValueKind.HostContextField => value.Width,
            _ => 0,
        };
        return width > 0 && RangesOverlap(offset, accessSize, value.Offset, width);
    }

    private static void ApplyCallClobbers(FlowState before, FlowState after)
    {
        // No direct/imported/HostContext call-effect contract currently proves that
        // the callee cannot mutate HostContext memory.  A loaded field or a prior
        // non-null guard therefore cannot survive a call, even when the field is
        // reloaded afterward; only a new CFG check can establish a fresh guard.
        InvalidateAllHostContextFacts(after);

        // A pointer to any part of this frame is an escape.  The callback ABI has
        // bounded output pointers, but it has no verified no-retain/no-alias rule
        // for userdata or other arguments, so range-clearing just out_thread is
        // insufficient: the callee may write another escaped slot now or later.
        var stackAddressEscapes = before.MayHaveEscapedStackAddress
            || Enumerable.Range(0, 9).Any(index =>
            {
                var argument = ReadRegister(before, new Aarch64RegisterView(
                    Aarch64RegisterClass.General,
                    checked((byte)index),
                    64,
                    Aarch64RegisterRole.None));
                return argument.Kind is FlowValueKind.StackAddress or FlowValueKind.Unknown
                    || before.ProofContext is { } proofContext
                        && argument.Kind == FlowValueKind.HostContextField
                        && argument.Offset == proofContext.UserDataOffset;
            });
        if (stackAddressEscapes)
        {
            after.MayHaveEscapedStackAddress = true;
            after.StackSlots.Clear();
        }

        for (byte register = 0; register <= CallerSavedRegisterMaximum; register++)
        {
            after.Registers.Remove(new RegisterKey(register, Aarch64RegisterRole.None));
        }

        after.Registers.Remove(new RegisterKey(LinkRegister, Aarch64RegisterRole.None));
        after.Condition = null;
    }

    private static void AddEdgeProofFacts(
        Aarch64Instruction instruction,
        FlowState before,
        FlowEdge edge,
        FlowState outgoing)
    {
        var mnemonic = instruction.Mnemonic;
        var register = GetFirstInputRegister(instruction);
        if (register is { } inputRegister)
        {
            var value = ReadRegister(before, inputRegister);
            var branchTaken = edge.Kind == FlowEdgeKind.BranchTaken;
            if ((mnemonic.Equals("cbz", StringComparison.OrdinalIgnoreCase)
                    && !branchTaken
                    || mnemonic.Equals("cbnz", StringComparison.OrdinalIgnoreCase)
                        && branchTaken)
                && value.Kind == FlowValueKind.HostCallback
                && outgoing.ProofContext is { } proofContext)
            {
                ProofGuard? nonNullGuard = value.Offset switch
                {
                    var offset when offset == proofContext.EmitDiagnosticCallbackOffset => ProofGuard.EmitDiagnosticNonNull,
                    var offset when offset == proofContext.CreateImageThreadCallbackOffset => ProofGuard.CreateImageThreadNonNull,
                    var offset when offset == proofContext.JoinImageThreadCallbackOffset => ProofGuard.JoinImageThreadNonNull,
                    _ => null,
                };
                if (value.ProducerOverflow)
                {
                    outgoing.Guards.Add(ProofGuard.ProducerLimitExceeded);
                }
                else if (nonNullGuard is { } guard)
                {
                    outgoing.Guards.Add(guard);
                }
            }

            if (mnemonic is not null
                && (mnemonic.Equals("tbz", StringComparison.OrdinalIgnoreCase)
                    || mnemonic.Equals("tbnz", StringComparison.OrdinalIgnoreCase))
                && value.Kind == FlowValueKind.HostContextField
                && outgoing.ProofContext is { } capabilityContext
                && value.Offset == capabilityContext.CapabilitiesOffset
                && value.Width == sizeof(ulong)
                && IsThreadLifetimeBit(instruction, out var bit)
                && (mnemonic.Equals("tbz", StringComparison.OrdinalIgnoreCase) && !branchTaken
                    || mnemonic.Equals("tbnz", StringComparison.OrdinalIgnoreCase) && branchTaken)
                && bit == capabilityContext.ThreadLifetimeCapabilityBitIndex)
            {
                if (value.ProducerOverflow)
                {
                    outgoing.Guards.Add(ProofGuard.ProducerLimitExceeded);
                }
                else
                {
                    outgoing.Guards.Add(ProofGuard.ThreadLifetimeCapability);
                }
            }
        }

        if (instruction.ControlFlow == Aarch64ControlFlowKind.ConditionalBranch
            && before.Condition is { } condition)
        {
            if (condition.Left.ProducerOverflow || condition.Right.ProducerOverflow)
            {
                outgoing.Guards.Add(ProofGuard.ProducerLimitExceeded);
            }
            else if (IsThreadLifetimeSizeSuccessEdge(
                         instruction,
                         condition,
                         edge,
                         before.ProofContext))
            {
                outgoing.Guards.Add(ProofGuard.ThreadLifetimeTableSize);
            }
            else if (TryGetCallbackNonNullGuard(
                         instruction,
                         condition,
                         edge,
                         before.ProofContext,
                         out var callbackGuard))
            {
                outgoing.Guards.Add(callbackGuard);
            }
        }
    }

    private static bool TryGetCallbackNonNullGuard(
        Aarch64Instruction instruction,
        FlowCondition condition,
        FlowEdge edge,
        Aarch64HostContextProofContext? proofContext,
        out ProofGuard guard)
    {
        guard = default;
        if (proofContext is null
            || condition.Left.Kind != FlowValueKind.HostCallback
            || condition.Left.Width != sizeof(ulong)
            || condition.Right.Kind != FlowValueKind.Constant
            || condition.Right.ConstantValue != 0
            || edge.Kind is not (FlowEdgeKind.BranchTaken or FlowEdgeKind.BranchNotTaken))
        {
            return false;
        }

        // CMP Xn, #0 followed by B.EQ proves non-null on fallthrough; B.NE
        // proves non-null on the taken edge. Never infer a callback guard from
        // an unrelated condition or the null branch itself.
        var conditionCode = GetConditionCode(instruction);
        var nonNullEdge = conditionCode == 0 && edge.Kind == FlowEdgeKind.BranchNotTaken
            || conditionCode == 1 && edge.Kind == FlowEdgeKind.BranchTaken;
        if (!nonNullEdge)
        {
            return false;
        }

        var callbackOffset = checked((uint)condition.Left.Offset);
        guard = callbackOffset switch
        {
            var offset when offset == proofContext.EmitDiagnosticCallbackOffset => ProofGuard.EmitDiagnosticNonNull,
            var offset when offset == proofContext.CreateImageThreadCallbackOffset => ProofGuard.CreateImageThreadNonNull,
            var offset when offset == proofContext.JoinImageThreadCallbackOffset => ProofGuard.JoinImageThreadNonNull,
            _ => default,
        };
        return callbackOffset == proofContext.EmitDiagnosticCallbackOffset
            || callbackOffset == proofContext.CreateImageThreadCallbackOffset
            || callbackOffset == proofContext.JoinImageThreadCallbackOffset;
    }

    private static bool IsThreadLifetimeSizeSuccessEdge(
        Aarch64Instruction instruction,
        FlowCondition condition,
        FlowEdge edge,
        Aarch64HostContextProofContext? proofContext)
    {
        if (proofContext is null
            || condition.Left.Kind != FlowValueKind.HostContextField
            || condition.Left.Offset != proofContext.StructSizeOffset
            || condition.Left.Width != sizeof(uint)
            || condition.Right.Kind != FlowValueKind.Constant
            || edge.Kind is not (FlowEdgeKind.BranchTaken or FlowEdgeKind.BranchNotTaken))
        {
            return false;
        }

        var conditionCode = GetConditionCode(instruction);
        var constant = condition.Right.ConstantValue;
        var taken = edge.Kind == FlowEdgeKind.BranchTaken;
        return (constant == (long)proofContext.ThreadLifetimeContextSize
                && conditionCode == 3
                && !taken)
            || (constant == (long)proofContext.ThreadLifetimeContextSize
                && conditionCode == 2
                && taken)
            || (constant == (long)proofContext.ThreadLifetimeContextSize - 1
                && conditionCode == 9
                && !taken)
            || (constant == (long)proofContext.ThreadLifetimeContextSize - 1
                && conditionCode == 8
                && taken);
    }

    private static bool IsComparisonInstruction(Aarch64Instruction instruction)
    {
        if (instruction.Mnemonic.Equals("cmp", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return instruction.Mnemonic.Equals("subs", StringComparison.OrdinalIgnoreCase)
            && GetOutputRegisters(instruction).Any(register => register.Role == Aarch64RegisterRole.Zero);
    }

    private static int? GetConditionCode(Aarch64Instruction instruction)
    {
        var condition = instruction.Operands
            .Where(operand => (operand.Kind is Aarch64OperandKind.Immediate or Aarch64OperandKind.EncodedField)
                && operand.Name.Contains("cond", StringComparison.OrdinalIgnoreCase))
            .Select(operand => operand.Immediate)
            .SingleOrDefault();
        return condition is { } immediate && immediate is >= 0 and <= 15
            ? checked((int)immediate)
            : null;
    }

    private static FlowCondition? CreateComparison(
        Aarch64Instruction instruction,
        FlowState state,
        ulong address)
    {
        var registers = instruction.Operands
            .Where(operand => operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput)
            .Where(operand => operand.Kind == Aarch64OperandKind.Register && operand.Register is { } register
                && register.Class == Aarch64RegisterClass.General)
            .Select(operand => operand.Register!.Value)
            .ToArray();
        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null)
            .Select(operand => operand.Immediate!.Value)
            .ToArray();
        if (registers.Length == 2 && immediates.Length == 0 && registers[0].Width == registers[1].Width)
        {
            return new FlowCondition(
                ReadRegister(state, registers[0]).AddProducer(address),
                ReadRegister(state, registers[1]).AddProducer(address));
        }

        if (registers.Length == 1 && immediates.Length == 1)
        {
            return new FlowCondition(
                ReadRegister(state, registers[0]).AddProducer(address),
                FlowValue.Constant(immediates[0]).AddProducer(address));
        }

        return null;
    }

    private static bool IsThreadLifetimeBit(Aarch64Instruction instruction, out long bit)
    {
        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate && operand.Immediate is not null)
            .Select(operand => operand.Immediate!.Value)
            .ToArray();
        bit = immediates.Length == 1 ? immediates[0] : -1;
        return immediates.Length == 1;
    }

    private static bool TryProveCall(
        ElfFile file,
        Aarch64FunctionInstruction instruction,
        FlowState state,
        out Aarch64RuntimeIndirectCallResolution resolution,
        out string? failure)
    {
        resolution = null!;
        failure = null;
        var targetRegister = GetIndirectCallTargetRegister(instruction.Decode.Instruction!);
        if (targetRegister is not { } register)
        {
            failure = "BLR must consume exactly one 64-bit general-register target.";
            return false;
        }

        var value = ReadRegister(state, register);
        if (value.ProducerOverflow || state.Guards.Contains(ProofGuard.ProducerLimitExceeded))
        {
            failure = $"The indirect-call proof exceeds the {MaximumProducersPerValue}-producer provenance limit.";
            return false;
        }

        if (value.Kind == FlowValueKind.HostCallback)
        {
            if (state.ProofContext is not { } proofContext)
            {
                failure = "HostContext callback provenance is unavailable without a validated HostContext entry invocation context.";
                return false;
            }

            var offset = checked((uint)value.Offset);
            if (offset == proofContext.EmitDiagnosticCallbackOffset)
            {
                if (!state.Guards.Contains(ProofGuard.EmitDiagnosticNonNull))
                {
                    failure = "The HostContext emit_diagnostic callback load lacks a dominating non-null guard.";
                    return false;
                }

                resolution = new Aarch64RuntimeIndirectCallResolution(
                    instruction.Address,
                    register,
                    value.Producers,
                    "aarch64:host-context:emit-diagnostic:v1",
                    $"HostContext ABI {proofContext.AbiVersion} entry {proofContext.EntryFunction.Name} at 0x{proofContext.EntryFunction.Value:X}+0x{proofContext.EntryFunction.Size:X}; the validated invocation contract provides at least {proofContext.MinimumContextSize} bytes, and a CFG path proves the emit_diagnostic callback at byte offset {offset} is non-null.",
                    Aarch64RuntimeIndirectCallOwnerKind.HostContextCallback,
                    offset);
                return true;
            }

            var isCreateCallback = offset == proofContext.CreateImageThreadCallbackOffset;
            var isJoinCallback = offset == proofContext.JoinImageThreadCallbackOffset;
            if ((!isCreateCallback && !isJoinCallback)
                || !state.Guards.Contains(ProofGuard.ThreadLifetimeTableSize)
                || !state.Guards.Contains(ProofGuard.ThreadLifetimeCapability)
                || !state.Guards.Contains(isCreateCallback
                    ? ProofGuard.CreateImageThreadNonNull
                    : ProofGuard.JoinImageThreadNonNull)
                || !state.Guards.Contains(isCreateCallback
                    ? ProofGuard.JoinImageThreadNonNull
                    : ProofGuard.CreateImageThreadNonNull))
            {
                failure = "The HostContext callback load lacks dominating table-size, thread-capability, and complete callback non-null guards.";
                return false;
            }

            var binding = isCreateCallback
                ? "aarch64:host-context:create-image-thread:v1"
                : "aarch64:host-context:join-image-thread:v1";
            var member = isCreateCallback ? "create_image_thread" : "join_image_thread";
            var proof = $"HostContext ABI {proofContext.AbiVersion} entry {proofContext.EntryFunction.Name} at 0x{proofContext.EntryFunction.Value:X}+0x{proofContext.EntryFunction.Size:X}; {member} is one 64-bit field at byte offset {offset} on the X0-derived host table; a CFG-merged path proves struct_size >= {proofContext.ThreadLifetimeContextSize}, ThreadLifetime capability, and both appended callbacks non-null; BLR fallthrough is retained under AAPCS64.";
            resolution = new Aarch64RuntimeIndirectCallResolution(
                instruction.Address,
                register,
                value.Producers,
                binding,
                proof,
                Aarch64RuntimeIndirectCallOwnerKind.HostContextCallback,
                offset);
            return true;
        }

        if (value.Kind == FlowValueKind.ImportedFunction
            && value.ImportBinding is { } imported
            && IsIndirectCall(instruction.Decode.Instruction))
        {
            if (imported.SymbolType is not (SymbolTypeNoType or SymbolTypeFunction))
            {
                failure = "The BLR target's GLOB_DAT owner is an imported data object rather than a callable undefined function/NONE symbol.";
                return false;
            }

            var producerAddresses = value.Producers.ToArray();
            var binding = $"aarch64:elf-import:{imported.SymbolName}:glob-dat@0x{imported.GotAddress:X}";
            var proof = $"The BLR target flows through a 64-bit load from writable file-backed GOT address 0x{imported.GotAddress:X}, computed from decoded ADRP page 0x{imported.PageAddress:X} plus an in-page low-12 displacement; one non-PLT R_AARCH64_GLOB_DAT at RELA source 0x{imported.RelocationSourceAddress:X} owns dynamic symbol {imported.SymbolName}[{imported.SymbolIndex}] (undefined, global/weak, default visibility), and ADRP/LDR producers {imported.AddressPageProducerAddress:X}/{imported.PointerLoadProducerAddress:X} retain that page and exact slot.";
            resolution = new Aarch64RuntimeIndirectCallResolution(
                instruction.Address,
                register,
                producerAddresses,
                binding,
                proof,
                Aarch64RuntimeIndirectCallOwnerKind.DynamicImport,
                importBinding: imported);
            return true;
        }

        if (value.Kind == FlowValueKind.InvalidOwner && value.Failure is not null)
        {
            failure = value.Failure;
        }
        else if (value.Kind == FlowValueKind.Unknown)
        {
            var registerSummary = string.Join(",", state.Registers
                .OrderBy(pair => pair.Key.Index)
                .Select(pair => string.Concat(
                    "x",
                    pair.Key.Index,
                    "=",
                    pair.Value.Kind,
                    ":",
                    pair.Value.Offset,
                    ":",
                    pair.Value.Address.ToString("X", System.Globalization.CultureInfo.InvariantCulture),
                    ":",
                    pair.Value.StackOffset)));
            var guardSummary = string.Join(",", state.Guards.OrderBy(guard => guard));
            failure = $"BLR X{register.Index} target provenance is missing or conflicts across control-flow paths, register writes, stack slots, or AAPCS call clobbers; incoming registers: {registerSummary}; guards: {guardSummary}.";
        }
        else
        {
            failure = "BLR target is not loaded from a guarded HostContext callback field or a uniquely owned dynamic import GOT slot.";
        }
        _ = file;
        return false;
    }

    internal static bool TryResolveImportOwner(
        ElfFile file,
        RelaRelocation relocation,
        ulong gotAddress,
        ulong? pageAddress,
        ulong? pageProducerAddress,
        ulong pointerLoadProducerAddress,
        out Aarch64DynamicImportBinding? binding,
        out string failure)
    {
        binding = null;
        failure = "The indirect-call GOT slot has no valid dynamic-symbol owner.";
        var matchingRelocations = file.RelaRelocations
            .Where(candidate => candidate.Offset == gotAddress)
            .ToArray();
        if (matchingRelocations.Length != 1
            || matchingRelocations[0] != relocation
            || relocation.IsPlt
            || relocation.Type != ElfConstants.RArm64GlobDat
            || relocation.Addend != 0
            || gotAddress % sizeof(ulong) != 0
            || relocation.SymbolIndex == 0
            || relocation.SymbolIndex >= (uint)file.DynamicSymbols.Count
            || pageAddress is not { } page
            || (page & 0xFFFUL) != 0
            || gotAddress < page
            || gotAddress - page >= 0x1000
            || !TryGetMappedRange(file, gotAddress, sizeof(ulong), out _))
        {
            failure = "The indirect-call GOT slot does not have one aligned, writable, file-backed non-PLT R_AARCH64_GLOB_DAT owner.";
            return false;
        }

        var writableOwners = file.LoadMap.Segments.Count(segment =>
            segment.ContainsVirtualAddress(gotAddress, sizeof(ulong))
            && (segment.Flags & ElfConstants.PfW) != 0);
        if (writableOwners != 1)
        {
            failure = "The indirect-call GOT slot is not owned by one writable PT_LOAD range.";
            return false;
        }

        var symbol = file.DynamicSymbols[checked((int)relocation.SymbolIndex)];
        var bindingCode = (byte)(symbol.Info >> 4);
        var symbolType = (byte)(symbol.Info & 0x0F);
        var visibility = (byte)(symbol.Other & 0x03);
        if (symbol.SectionIndex != UndefinedSectionIndex
            || symbol.Value != 0
            || (bindingCode != SymbolBindingGlobal && bindingCode != SymbolBindingWeak)
            || (symbolType != SymbolTypeNoType
                && symbolType != SymbolTypeObject
                && symbolType != SymbolTypeFunction)
            || visibility != DefaultVisibility
            || !ElfParserUtilities.TryReadString(file.DynamicMetadata.StringTable, symbol.Name, out var name)
            || string.IsNullOrWhiteSpace(name))
        {
            failure = "The R_AARCH64_GLOB_DAT owner is not one bounded undefined global/weak default-visible NOTYPE/object/function dynamic symbol.";
            return false;
        }

        if (file.SymbolVersions.VersionIndices.Count > relocation.SymbolIndex)
        {
            var versionIndex = file.SymbolVersions.VersionIndices[checked((int)relocation.SymbolIndex)];
            if (versionIndex.IsHidden || versionIndex.Index > 1)
            {
                failure = "The dynamic import's symbol-version owner is outside the unversioned call-binding slice.";
                return false;
            }
        }

        if (pageProducerAddress is not { } pageProducer)
        {
            failure = "The dynamic import GOT address has no decoded ADRP page producer.";
            return false;
        }

        binding = new Aarch64DynamicImportBinding(
            gotAddress,
            relocation.SourceAddress,
            relocation.SymbolIndex,
            name,
            bindingCode,
            symbolType,
            visibility,
            pageProducer,
            pointerLoadProducerAddress,
            relocation)
        {
            PageAddress = page,
        };
        return true;
    }

    internal static bool TryGetMappedRange(ElfFile file, ulong address, ulong size, out FileOffset fileOffset)
    {
        fileOffset = default;
        var owners = new List<LoadSegment>();
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

            if (segment.ContainsFileOffset(segment.FileOffset + delta, size))
            {
                owners.Add(segment);
            }
        }

        if (owners.Count != 1
            || !file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), size, out fileOffset))
        {
            return false;
        }

        var owner = owners[0];
        return fileOffset.Value <= (ulong)file.Bytes.Length
            && size <= (ulong)file.Bytes.Length - fileOffset.Value
            && owner.FileOffset <= ulong.MaxValue - (address - owner.VirtualAddress)
            && fileOffset.Value == owner.FileOffset + (address - owner.VirtualAddress);
    }

    private static bool TryAdjustAddress(FlowValue source, long adjustment, out FlowValue adjusted)
    {
        adjusted = FlowValue.Unknown;
        if (source.Kind is not (FlowValueKind.HostContextBase
            or FlowValueKind.HostContextAddress
            or FlowValueKind.ElfAddress
            or FlowValueKind.StackAddress))
        {
            return false;
        }

        switch (source.Kind)
        {
            case FlowValueKind.HostContextBase:
            case FlowValueKind.HostContextAddress:
                if (!TryAddSigned(source.Offset, adjustment, out var hostOffset))
                {
                    return false;
                }

                adjusted = hostOffset == 0
                    ? FlowValue.HostContextBase.WithProducers(source.Producers, source.ProducerOverflow)
                    : FlowValue.HostContextAddress(hostOffset).WithProducers(source.Producers, source.ProducerOverflow);
                return true;
            case FlowValueKind.ElfAddress:
                if (!TryAddSigned(source.Address, adjustment, out var address) || address < 0)
                {
                    return false;
                }

                adjusted = FlowValue.ElfAddress(
                    checked((ulong)address),
                    source.PageProducerAddress,
                    source.IsPageRelative,
                    source.PageAddress).WithProducers(source.Producers, source.ProducerOverflow);
                return true;
            case FlowValueKind.StackAddress:
                if (!TryAddSigned(source.StackOffset, adjustment, out var stackOffset))
                {
                    return false;
                }

                adjusted = FlowValue.StackAddress(stackOffset).WithProducers(source.Producers, source.ProducerOverflow);
                return true;
            default:
                return false;
        }
    }

    private static bool TryAdjustSigned(long left, long right, out long result)
    {
        try
        {
            result = checked(left + right);
            return true;
        }
        catch (OverflowException)
        {
            result = default;
            return false;
        }
    }

    private static bool TryAddSigned(ulong left, long right, out long result)
    {
        if (left > long.MaxValue)
        {
            result = default;
            return false;
        }

        return TryAdjustSigned(checked((long)left), right, out result);
    }

    private static bool TryAddSigned(long left, long right, out long result) => TryAdjustSigned(left, right, out result);

    private static bool RangesOverlap(long leftStart, int leftSize, long rightStart, int rightSize)
    {
        if (leftSize <= 0 || rightSize <= 0)
        {
            return false;
        }

        return leftStart <= rightStart
            ? rightStart - leftStart < leftSize
            : leftStart - rightStart < rightSize;
    }

    private static bool IsIndirectCall(Aarch64Instruction? instruction) => instruction is
    {
        ControlFlow: Aarch64ControlFlowKind.IndirectBranch,
    } && instruction.Mnemonic.Equals("blr", StringComparison.OrdinalIgnoreCase);

    private static bool IsTlsDescCallMarkerMnemonic(Aarch64Instruction instruction) =>
        instruction.Mnemonic.Equals("blr", StringComparison.OrdinalIgnoreCase)
        && GetIndirectCallTargetRegister(instruction) is { Index: 1 };

    private static Aarch64RegisterView? GetIndirectCallTargetRegister(Aarch64Instruction instruction)
    {
        if (!IsIndirectCall(instruction))
        {
            return null;
        }

        var registers = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register is
                {
                    Class: Aarch64RegisterClass.General,
                    Width: 64,
                    Role: Aarch64RegisterRole.None,
                })
            .Select(operand => operand.Register!.Value)
            .ToArray();
        return registers.Length == 1 ? registers[0] : null;
    }

    private static Aarch64RegisterView? GetFirstInputRegister(Aarch64Instruction instruction) =>
        instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register is { Class: Aarch64RegisterClass.General })
            .Select(operand => operand.Register)
            .FirstOrDefault();

    private static IEnumerable<Aarch64RegisterView> GetOutputRegisters(Aarch64Instruction instruction) =>
        instruction.Operands
            .Where(operand => operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput)
            .SelectMany(operand => operand.Kind == Aarch64OperandKind.Register && operand.Register is { } register
                ? new[] { register }
                : operand.Kind is Aarch64OperandKind.RegisterPair or Aarch64OperandKind.RegisterList
                    ? operand.Registers
                    : Array.Empty<Aarch64RegisterView>());

    private static bool IsGeneralRegister(Aarch64RegisterView register) =>
        register.Class == Aarch64RegisterClass.General
        && register.Role is Aarch64RegisterRole.None or Aarch64RegisterRole.StackPointer or Aarch64RegisterRole.Zero;

    private static FlowValue ReadRegister(FlowState state, Aarch64RegisterView register)
    {
        if (register.Role == Aarch64RegisterRole.Zero)
        {
            return FlowValue.Constant(0);
        }

        return state.Registers.TryGetValue(RegisterKey.From(register), out var value)
            ? value
            : FlowValue.Unknown;
    }

    private static bool MergeInto(FlowState current, FlowState incoming)
    {
        var changed = false;
        foreach (var key in current.Registers.Keys.ToArray())
        {
            if (!incoming.Registers.TryGetValue(key, out var value)
                || !current.Registers[key].EquivalentTo(value))
            {
                current.Registers.Remove(key);
                changed = true;
            }
            else
            {
                var merged = current.Registers[key].MergeProducers(value);
                if (!current.Registers[key].ProducerSequenceEqual(merged))
                {
                    current.Registers[key] = merged;
                    changed = true;
                }
            }
        }

        foreach (var key in current.StackSlots.Keys.ToArray())
        {
            if (!incoming.StackSlots.TryGetValue(key, out var slot)
                || current.StackSlots[key].Size != slot.Size
                || !current.StackSlots[key].Value.EquivalentTo(slot.Value))
            {
                current.StackSlots.Remove(key);
                changed = true;
            }
            else
            {
                var merged = current.StackSlots[key].Value.MergeProducers(slot.Value);
                if (!current.StackSlots[key].Value.ProducerSequenceEqual(merged))
                {
                    current.StackSlots[key] = new StackSlot(merged, slot.Size);
                    changed = true;
                }
            }
        }

        foreach (var key in incoming.Registers.Keys)
        {
            if (!current.Registers.ContainsKey(key))
            {
                // A fact absent on one incoming path is unknown at the merge.
                continue;
            }
        }

        var priorGuardCount = current.Guards.Count;
        current.Guards.IntersectWith(incoming.Guards);
        changed |= current.Guards.Count != priorGuardCount;

        if (incoming.MayHaveEscapedStackAddress && !current.MayHaveEscapedStackAddress)
        {
            current.MayHaveEscapedStackAddress = true;
            changed = true;
        }

        if (current.Condition is { } currentCondition
            && incoming.Condition is { } incomingCondition
            && currentCondition.EquivalentTo(incomingCondition))
        {
            var merged = new FlowCondition(
                currentCondition.Left.MergeProducers(incomingCondition.Left),
                currentCondition.Right.MergeProducers(incomingCondition.Right));
            if (!currentCondition.Equals(merged))
            {
                current.Condition = merged;
                changed = true;
            }
        }
        else if (current.Condition is not null)
        {
            current.Condition = null;
            changed = true;
        }

        return changed;
    }

    private enum FlowValueKind
    {
        Unknown,
        Constant,
        HostContextBase,
        HostContextAddress,
        HostContextField,
        HostCallback,
        ElfAddress,
        StackAddress,
        ThreadPointer,
        ImportedFunction,
        InvalidOwner,
    }

    private enum ProofGuard
    {
        ProducerLimitExceeded,
        ThreadLifetimeTableSize,
        ThreadLifetimeCapability,
        EmitDiagnosticNonNull,
        CreateImageThreadNonNull,
        JoinImageThreadNonNull,
    }

    private enum FlowEdgeKind
    {
        Fallthrough,
        Unconditional,
        BranchTaken,
        BranchNotTaken,
    }

    private readonly record struct FlowEdge(int TargetIndex, FlowEdgeKind Kind);

    private readonly record struct RegisterKey(byte Index, Aarch64RegisterRole Role)
    {
        public static RegisterKey From(Aarch64RegisterView register) => new(register.Index, register.Role);
    }

    private sealed class FlowState
    {
        private FlowState(
            Dictionary<RegisterKey, FlowValue> registers,
            Dictionary<long, StackSlot> stackSlots,
            HashSet<ProofGuard> guards,
            FlowCondition? condition,
            bool mayHaveEscapedStackAddress,
            Aarch64HostContextProofContext? proofContext)
        {
            Registers = registers;
            StackSlots = stackSlots;
            Guards = guards;
            Condition = condition;
            MayHaveEscapedStackAddress = mayHaveEscapedStackAddress;
            ProofContext = proofContext;
        }

        public Dictionary<RegisterKey, FlowValue> Registers { get; }

        public Dictionary<long, StackSlot> StackSlots { get; }

        public HashSet<ProofGuard> Guards { get; }

        public FlowCondition? Condition { get; set; }

        public bool MayHaveEscapedStackAddress { get; set; }

        public Aarch64HostContextProofContext? ProofContext { get; }

        public static FlowState CreateEntry(Aarch64HostContextProofContext? proofContext)
        {
            var registers = new Dictionary<RegisterKey, FlowValue>
            {
                [new RegisterKey(1, Aarch64RegisterRole.None)] = FlowValue.LaunchArgumentsBase,
                [new RegisterKey(checked((byte)StackPointerIndex), Aarch64RegisterRole.StackPointer)] = FlowValue.StackAddress(0),
            };
            if (proofContext is not null)
            {
                registers[new RegisterKey(0, Aarch64RegisterRole.None)] = FlowValue.HostContextBase;
            }

            return new FlowState(
                registers,
                new Dictionary<long, StackSlot>(),
                new HashSet<ProofGuard>(),
                null,
                mayHaveEscapedStackAddress: false,
                proofContext: proofContext);
        }

        public FlowState Clone() => new(
            new Dictionary<RegisterKey, FlowValue>(Registers),
            new Dictionary<long, StackSlot>(StackSlots),
            new HashSet<ProofGuard>(Guards),
            Condition,
            MayHaveEscapedStackAddress,
            ProofContext);

        public void Set(RegisterKey key, FlowValue value)
        {
            if (value.Kind == FlowValueKind.Unknown)
            {
                Registers.Remove(key);
            }
            else
            {
                Registers[key] = value;
            }
        }
    }

    private sealed record FlowValue(
        FlowValueKind Kind,
        long ConstantValue = 0,
        long Offset = 0,
        int Width = 0,
        ulong Address = 0,
        long StackOffset = 0,
        ulong? PageProducerAddress = null,
        ulong? PageAddress = null,
        bool IsPageRelative = false,
        Aarch64DynamicImportBinding? ImportBinding = null,
        IReadOnlyList<ulong>? ProducerAddresses = null,
        string? Failure = null,
        bool ProducerOverflow = false)
    {
        public static FlowValue Unknown { get; } = new(FlowValueKind.Unknown);

        public static FlowValue HostContextBase { get; } = new(FlowValueKind.HostContextBase);

        public static FlowValue LaunchArgumentsBase { get; } = new(FlowValueKind.Unknown);

        public IReadOnlyList<ulong> Producers => ProducerAddresses ?? Array.Empty<ulong>();

        public static FlowValue Constant(long value) => new(FlowValueKind.Constant, ConstantValue: value);

        public static FlowValue HostContextAddress(long offset) => new(FlowValueKind.HostContextAddress, Offset: offset);

        public static FlowValue HostContextField(uint offset, int width) =>
            new(FlowValueKind.HostContextField, Offset: offset, Width: width);

        public static FlowValue HostCallback(uint offset) => new(FlowValueKind.HostCallback, Offset: offset, Width: sizeof(ulong));

        public static FlowValue ElfAddress(
            ulong address,
            ulong? pageProducerAddress,
            bool isPageRelative,
            ulong? pageAddress = null) =>
            new(
                FlowValueKind.ElfAddress,
                Address: address,
                PageProducerAddress: pageProducerAddress,
                PageAddress: isPageRelative ? pageAddress ?? address : null,
                IsPageRelative: isPageRelative);

        public static FlowValue StackAddress(long offset) => new(FlowValueKind.StackAddress, StackOffset: offset);

        public static FlowValue ThreadPointer() => new(FlowValueKind.ThreadPointer);

        public static FlowValue ImportedFunction(Aarch64DynamicImportBinding binding) =>
            new(
                FlowValueKind.ImportedFunction,
                ImportBinding: binding,
                PageProducerAddress: binding.AddressPageProducerAddress,
                PageAddress: binding.PageAddress,
                IsPageRelative: true);

        public static FlowValue InvalidOwner(string failure) =>
            new(FlowValueKind.InvalidOwner, Failure: failure);

        public FlowValue AddProducer(ulong address)
        {
            if (Kind == FlowValueKind.Unknown || Producers.Contains(address))
            {
                return this;
            }

            if (Producers.Count >= MaximumProducersPerValue)
            {
                return this with { ProducerOverflow = true };
            }

            return this with { ProducerAddresses = Producers.Append(address).OrderBy(value => value).ToArray() };
        }

        public FlowValue WithProducers(IEnumerable<ulong> producers, bool inheritedOverflow = false)
        {
            var observed = producers
                .Distinct()
                .OrderBy(value => value)
                .Take(MaximumProducersPerValue + 1)
                .ToArray();
            return this with
            {
                ProducerAddresses = Array.AsReadOnly(observed.Take(MaximumProducersPerValue).ToArray()),
                ProducerOverflow = ProducerOverflow || inheritedOverflow || observed.Length > MaximumProducersPerValue,
            };
        }

        public bool EquivalentTo(FlowValue other) =>
            Kind == other.Kind
            && ConstantValue == other.ConstantValue
            && Offset == other.Offset
            && Width == other.Width
            && Address == other.Address
            && StackOffset == other.StackOffset
            && PageProducerAddress == other.PageProducerAddress
            && PageAddress == other.PageAddress
            && IsPageRelative == other.IsPageRelative
            && Equals(ImportBinding, other.ImportBinding)
            && string.Equals(Failure, other.Failure, StringComparison.Ordinal);

        public FlowValue MergeProducers(FlowValue other) =>
            WithProducers(Producers.Concat(other.Producers), other.ProducerOverflow);

        public bool ProducerSequenceEqual(FlowValue other) =>
            ProducerOverflow == other.ProducerOverflow && Producers.SequenceEqual(other.Producers);
    }

    private sealed record FlowCondition(FlowValue Left, FlowValue Right)
    {
        public bool EquivalentTo(FlowCondition other) =>
            Left.EquivalentTo(other.Left) && Right.EquivalentTo(other.Right);
    }

    private sealed record StackSlot(FlowValue Value, int Size);
}

public enum Aarch64RuntimeIndirectCallOwnerKind
{
    HostContextCallback,
    DynamicImport,
}

/// <summary>Exact dynamic relocation and symbol owner of a selected indirect-call target.</summary>
public sealed record Aarch64DynamicImportBinding(
    ulong GotAddress,
    ulong RelocationSourceAddress,
    uint SymbolIndex,
    string SymbolName,
    byte SymbolBinding,
    byte SymbolType,
    byte SymbolVisibility,
    ulong AddressPageProducerAddress,
    ulong PointerLoadProducerAddress,
    RelaRelocation Relocation)
{
    public ulong PageAddress { get; init; }
}

/// <summary>A bounded ADRP-derived data range and its source relocation owner, when present.</summary>
public sealed record Aarch64AddressReferenceResolution(
    ulong PageProducerAddress,
    ulong LoadProducerAddress,
    VirtualAddress PageAddress,
    VirtualAddress TargetAddress,
    uint AccessSize,
    RelaRelocation? RelocationOwner,
    Aarch64DynamicImportBinding? ImportOwner,
    string Proof);
