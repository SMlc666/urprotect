using System.Buffers.Binary;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

public sealed record Aarch64JumpTableEntry(
    int Index,
    int EncodedValue,
    VirtualAddress TargetAddress,
    FileOffset SourceFileOffset,
    VirtualAddress SourceAddress);

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
        string proof)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(producerAddresses);
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
        // The source bounds check proves Wn only while that register survives
        // the complete producer chain. Wn and Xn alias in AArch64, so comparing
        // register views (including Width) would miss ADRP Xn overwriting Wn.
        // Flattened output dispatches on the live index at BR, not the stale
        // value seen by CMP: reject every producer that clobbers that index.
        if (tableBaseRegister.Index == indexRegister.Index
            || loadedOutputRegister.Index == indexRegister.Index
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

        if (!TryGetBoundedUnsignedSwitch(
                instructions,
                branchIndex - 5,
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
            if (!TryAddSigned(targetBaseAddress.Value, encodedValue, out var targetAddress)
                || targetAddress < functionStart
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
            $"signed 32-bit relative table; {boundsProof}; table range is file-backed and selected-function private");
        return true;
    }

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
            || !compare.Mnemonic.StartsWith("cmp", StringComparison.OrdinalIgnoreCase)
                && !compare.Mnemonic.StartsWith("subs", StringComparison.OrdinalIgnoreCase)
            || !conditional.Mnemonic.StartsWith("b.", StringComparison.OrdinalIgnoreCase)
                && !conditional.Mnemonic.Equals("b.$cond", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

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
            .Select(operand => operand.Register!.Value)
            .ToArray();
        if (inputs.Length != 2)
        {
            return false;
        }

        baseRegister = inputs[0];
        loadedRegister = inputs[1];
        return true;
    }

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
