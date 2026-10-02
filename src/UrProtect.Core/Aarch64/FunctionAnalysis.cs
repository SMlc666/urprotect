using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

public enum Aarch64FunctionAnalysisStatus
{
    Complete,
    InvalidRange,
    UnsupportedInstruction,
    IncompleteControlFlow,
    ResourceUnavailable,
}

public enum Aarch64ControlFlowEdgeKind
{
    Fallthrough,
    DirectBranch,
    ConditionalBranch,
    Call,
    Return,
    Indirect,
}

public readonly record struct Aarch64FunctionInstruction(
    ulong FileOffset,
    ulong Address,
    uint Encoding,
    Aarch64DecodeResult Decode);

public sealed record Aarch64ControlFlowEdge(
    ulong SourceAddress,
    ulong? TargetAddress,
    Aarch64ControlFlowEdgeKind Kind);

public sealed record Aarch64BasicBlock(
    ulong StartAddress,
    IReadOnlyList<Aarch64FunctionInstruction> Instructions,
    IReadOnlyList<Aarch64ControlFlowEdge> Successors);

public sealed record Aarch64FunctionAnalysis(
    ElfFunctionSymbol Function,
    Aarch64FunctionAnalysisStatus Status,
    IReadOnlyList<Aarch64BasicBlock> Blocks,
    IReadOnlyList<Aarch64FunctionInstruction> Instructions,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsComplete => Status == Aarch64FunctionAnalysisStatus.Complete;
}

public sealed record Aarch64RegisterResourcePlan(
    IReadOnlyList<byte> UsedGeneralRegisters,
    IReadOnlyList<byte> ReservedGeneralRegisters,
    IReadOnlyList<byte> AvailableScratchRegisters,
    int Pressure,
    bool IsSufficient,
    string? FailureReason);

public static class Aarch64RegisterResourcePlanner
{
    private const byte PlatformRegister = 18;
    private const byte StateRegister = 16;
    private const byte CombinedScratchRegister = 17;

    public static Aarch64RegisterResourcePlan Plan(
        Aarch64FunctionAnalysis analysis,
        AsmStoneAdapter decoder,
        bool flatten,
        bool permutation)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        ArgumentNullException.ThrowIfNull(decoder);

        var used = new SortedSet<byte>();
        for (byte register = 0; register <= 30; register++)
        {
            if (analysis.Instructions.Any(instruction =>
                    decoder.UsesGeneralRegister(instruction.Encoding, instruction.Address, register)))
            {
                used.Add(register);
            }
        }

        var reserved = new SortedSet<byte> { PlatformRegister };
        if (flatten || permutation)
        {
            reserved.Add(StateRegister);
        }

        if (flatten && permutation)
        {
            reserved.Add(CombinedScratchRegister);
        }

        var available = Enumerable.Range(0, 31)
            .Select(value => (byte)value)
            .Where(register => !used.Contains(register) && !reserved.Contains(register))
            .ToArray();
        var conflict = used.Intersect(reserved).OrderBy(register => register).ToArray();
        string? failureReason = conflict.Length > 0
            ? $"Reserved AArch64 register(s) are used by the selected function: {Describe(conflict)}."
            : null;
        if (failureReason is null
            && permutation
            && (!used.Contains(9) || !used.Contains(10)))
        {
            failureReason = "Register permutation requires both x9 and x10 to carry function values.";
        }

        return new Aarch64RegisterResourcePlan(
            used.ToArray(),
            reserved.ToArray(),
            available,
            used.Count,
            failureReason is null,
            failureReason);
    }

    private static string Describe(IEnumerable<byte> registers) =>
        string.Join(", ", registers.Select(register => $"x{register}"));
}

public sealed class Aarch64FunctionAnalyzer
{
    private const ulong InstructionSize = sizeof(uint);
    private const ulong MaxInstructionsPerFunction = 1_000_000;
    private readonly AsmStoneAdapter decoder;

    public Aarch64FunctionAnalyzer(AsmStoneAdapter? decoder = null)
    {
        this.decoder = decoder ?? new AsmStoneAdapter();
    }

    public Aarch64FunctionAnalysis Analyze(ElfFile file, ElfFunctionSymbol function)
    {
        ArgumentNullException.ThrowIfNull(file);
        var diagnostics = new DiagnosticBag();
        if (!TryGetFunctionRange(file, function, out var fileOffset, out var functionEnd, out var rangeDiagnostic))
        {
            diagnostics.Error(rangeDiagnostic.Code, rangeDiagnostic.Message, rangeDiagnostic.Offset);
            return Failure(function, Aarch64FunctionAnalysisStatus.InvalidRange, diagnostics);
        }

        var instructionCount = function.Size / InstructionSize;
        if (instructionCount == 0 || instructionCount > MaxInstructionsPerFunction)
        {
            diagnostics.Error(
                DiagnosticCode.TableOutOfBounds,
                $"Function '{function.Name}' exceeds the bounded instruction-analysis limit.",
                function.Value);
            return Failure(function, Aarch64FunctionAnalysisStatus.InvalidRange, diagnostics);
        }

        var instructions = new List<Aarch64FunctionInstruction>(checked((int)instructionCount));
        for (ulong index = 0; index < instructionCount; index++)
        {
            if (!TryAdd(fileOffset, checked(index * InstructionSize), out var offset)
                || !TryAdd(function.Value, checked(index * InstructionSize), out var address)
                || offset > int.MaxValue
                || offset > (ulong)file.Bytes.Length - sizeof(uint))
            {
                diagnostics.Error(
                    DiagnosticCode.TableOutOfBounds,
                    "The function instruction range is outside the input.",
                    offset);
                return new Aarch64FunctionAnalysis(
                    function,
                    Aarch64FunctionAnalysisStatus.InvalidRange,
                    Array.Empty<Aarch64BasicBlock>(),
                    instructions,
                    diagnostics.ToArray());
            }

            var encoding = BinaryPrimitives.ReadUInt32LittleEndian(
                file.Bytes.Span.Slice(checked((int)offset), sizeof(uint)));
            var decode = decoder.Decode(encoding, address);
            var instruction = new Aarch64FunctionInstruction(offset, address, encoding, decode);
            instructions.Add(instruction);
            if (!decode.IsSuccess)
            {
                var code = decode.Status switch
                {
                    Aarch64DecodeStatus.BackendUnavailable => DiagnosticCode.AsmStoneUnavailable,
                    Aarch64DecodeStatus.UnsupportedFeature => DiagnosticCode.UnsupportedInstructionFeature,
                    _ => DiagnosticCode.UnknownInstruction,
                };
                diagnostics.Error(code, decode.Diagnostic, offset);
                return new Aarch64FunctionAnalysis(
                    function,
                    Aarch64FunctionAnalysisStatus.UnsupportedInstruction,
                    Array.Empty<Aarch64BasicBlock>(),
                    instructions,
                    diagnostics.ToArray());
            }
        }

        var byAddress = instructions.ToDictionary(instruction => instruction.Address);
        var starts = new SortedSet<ulong> { function.Value };
        foreach (var instruction in instructions)
        {
            var decoded = instruction.Decode.Instruction!;
            switch (decoded.ControlFlow)
            {
                case Aarch64ControlFlowKind.DirectBranch:
                case Aarch64ControlFlowKind.ConditionalBranch:
                    if (!TryValidateTarget(
                            decoded.DirectTarget,
                            function.Value,
                            functionEnd,
                            byAddress,
                            out var target))
                    {
                        diagnostics.Error(
                            DiagnosticCode.AddressUnmapped,
                            $"Function '{function.Name}' has a branch target outside its symbol range.",
                            instruction.Address);
                        return Failure(
                            function,
                            Aarch64FunctionAnalysisStatus.IncompleteControlFlow,
                            diagnostics,
                            instructions);
                    }

                    starts.Add(target);
                    AddFallthroughStart(starts, instruction.Address, functionEnd);
                    break;
                case Aarch64ControlFlowKind.DirectCall:
                    // Calls return to the next instruction. The callee itself is
                    // not part of this symbol-bounded CFG.
                    AddFallthroughStart(starts, instruction.Address, functionEnd);
                    break;
                case Aarch64ControlFlowKind.IndirectBranch:
                case Aarch64ControlFlowKind.Return:
                    // A boundary after a terminator lets us identify unreachable
                    // trailing bytes instead of silently treating them as part of
                    // the preceding block.
                    AddFallthroughStart(starts, instruction.Address, functionEnd);
                    break;
            }
        }

        var blocks = new List<Aarch64BasicBlock>(starts.Count);
        var startsArray = starts.ToArray();
        for (var startIndex = 0; startIndex < startsArray.Length; startIndex++)
        {
            var start = startsArray[startIndex];
            var end = startIndex + 1 < startsArray.Length
                ? startsArray[startIndex + 1]
                : functionEnd;
            var blockInstructions = instructions
                .Where(instruction => instruction.Address >= start && instruction.Address < end)
                .ToArray();
            if (blockInstructions.Length == 0)
            {
                diagnostics.Error(
                    DiagnosticCode.AddressUnmapped,
                    $"Function '{function.Name}' has a basic-block boundary that is not an instruction.",
                    start);
                return Failure(
                    function,
                    Aarch64FunctionAnalysisStatus.IncompleteControlFlow,
                    diagnostics,
                    instructions,
                    blocks);
            }

            var last = blockInstructions[^1];
            var successors = GetSuccessors(last, functionEnd);
            if (successors.Any(edge => edge.Kind == Aarch64ControlFlowEdgeKind.Indirect))
            {
                diagnostics.Error(
                    DiagnosticCode.FunctionAnalysisIncomplete,
                    $"Function '{function.Name}' contains unresolved indirect control flow.",
                    last.Address);
                return Failure(
                    function,
                    Aarch64FunctionAnalysisStatus.IncompleteControlFlow,
                    diagnostics,
                    instructions,
                    blocks);
            }

            blocks.Add(new Aarch64BasicBlock(start, blockInstructions, successors));
        }

        var blocksByStart = blocks.ToDictionary(block => block.StartAddress);
        var reachable = new HashSet<ulong>();
        var pending = new Stack<ulong>();
        pending.Push(function.Value);
        while (pending.Count > 0)
        {
            var start = pending.Pop();
            if (!reachable.Add(start) || !blocksByStart.TryGetValue(start, out var block))
            {
                continue;
            }

            foreach (var edge in block.Successors)
            {
                if (edge.TargetAddress is { } target
                    && edge.Kind is not Aarch64ControlFlowEdgeKind.Call
                    && blocksByStart.ContainsKey(target))
                {
                    pending.Push(target);
                }
            }
        }

        if (reachable.Count != blocks.Count)
        {
            var unreachable = blocks.First(block => !reachable.Contains(block.StartAddress));
            diagnostics.Error(
                DiagnosticCode.FunctionAnalysisIncomplete,
                $"Function '{function.Name}' contains unreachable or data-like bytes after a control-flow terminator.",
                unreachable.StartAddress);
            return Failure(
                function,
                Aarch64FunctionAnalysisStatus.IncompleteControlFlow,
                diagnostics,
                instructions,
                blocks);
        }

        return new Aarch64FunctionAnalysis(
            function,
            Aarch64FunctionAnalysisStatus.Complete,
            blocks,
            instructions,
            diagnostics.ToArray());
    }

    private static bool TryGetFunctionRange(
        ElfFile file,
        ElfFunctionSymbol function,
        out ulong fileOffset,
        out ulong functionEnd,
        out Diagnostic diagnostic)
    {
        fileOffset = default;
        functionEnd = default;
        diagnostic = default;
        if (function.Size == 0
            || function.Value % InstructionSize != 0
            || function.Size % InstructionSize != 0
            || !function.TryGetEnd(out functionEnd))
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.AddressUnmapped,
                $"Function '{function.Name}' does not occupy one aligned executable load range.",
                function.Value);
            return false;
        }

        var executableSegments = file.LoadMap.Segments
            .Where(segment => segment.IsExecutable && segment.ContainsVirtualAddress(function.Value, function.Size))
            .ToArray();
        if (executableSegments.Length != 1)
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.AddressUnmapped,
                $"Function '{function.Name}' does not occupy exactly one executable load range.",
                function.Value);
            return false;
        }

        var segment = executableSegments[0];
        var delta = function.Value - segment.VirtualAddress;
        if (segment.FileOffset > ulong.MaxValue - delta)
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.AddressOverflow,
                "The function file offset overflowed.",
                function.Value);
            return false;
        }

        fileOffset = segment.FileOffset + delta;
        if (fileOffset > (ulong)file.Bytes.Length
            || function.Size > (ulong)file.Bytes.Length - fileOffset)
        {
            diagnostic = new Diagnostic(
                DiagnosticSeverity.Error,
                DiagnosticCode.TableOutOfBounds,
                "The function instruction range is outside the input.",
                fileOffset);
            return false;
        }

        return true;
    }

    private static bool TryValidateTarget(
        ulong? target,
        ulong functionStart,
        ulong functionEnd,
        Dictionary<ulong, Aarch64FunctionInstruction> instructions,
        out ulong validatedTarget)
    {
        validatedTarget = default;
        if (target is not { } value
            || value < functionStart
            || value >= functionEnd
            || value % InstructionSize != 0
            || !instructions.ContainsKey(value))
        {
            return false;
        }

        validatedTarget = value;
        return true;
    }

    private static void AddFallthroughStart(SortedSet<ulong> starts, ulong address, ulong functionEnd)
    {
        if (TryAdd(address, InstructionSize, out var next) && next < functionEnd)
        {
            starts.Add(next);
        }
    }

    private static Aarch64ControlFlowEdge[] GetSuccessors(
        Aarch64FunctionInstruction instruction,
        ulong functionEnd)
    {
        var decoded = instruction.Decode.Instruction!;
        var next = instruction.Address + InstructionSize;
        return decoded.ControlFlow switch
        {
            Aarch64ControlFlowKind.Return =>
                new[] { new Aarch64ControlFlowEdge(instruction.Address, null, Aarch64ControlFlowEdgeKind.Return) },
            Aarch64ControlFlowKind.IndirectBranch =>
                new[] { new Aarch64ControlFlowEdge(instruction.Address, null, Aarch64ControlFlowEdgeKind.Indirect) },
            Aarch64ControlFlowKind.DirectCall =>
                new[]
                {
                    new Aarch64ControlFlowEdge(instruction.Address, decoded.DirectTarget, Aarch64ControlFlowEdgeKind.Call),
                    new Aarch64ControlFlowEdge(instruction.Address, next < functionEnd ? next : null, Aarch64ControlFlowEdgeKind.Fallthrough),
                },
            Aarch64ControlFlowKind.ConditionalBranch =>
                new[]
                {
                    new Aarch64ControlFlowEdge(instruction.Address, decoded.DirectTarget, Aarch64ControlFlowEdgeKind.ConditionalBranch),
                    new Aarch64ControlFlowEdge(instruction.Address, next < functionEnd ? next : null, Aarch64ControlFlowEdgeKind.Fallthrough),
                },
            Aarch64ControlFlowKind.DirectBranch =>
                new[] { new Aarch64ControlFlowEdge(instruction.Address, decoded.DirectTarget, Aarch64ControlFlowEdgeKind.DirectBranch) },
            _ when next < functionEnd =>
                new[] { new Aarch64ControlFlowEdge(instruction.Address, next, Aarch64ControlFlowEdgeKind.Fallthrough) },
            _ => Array.Empty<Aarch64ControlFlowEdge>(),
        };
    }

    private static Aarch64FunctionAnalysis Failure(
        ElfFunctionSymbol function,
        Aarch64FunctionAnalysisStatus status,
        DiagnosticBag diagnostics,
        IReadOnlyList<Aarch64FunctionInstruction>? instructions = null,
        IReadOnlyList<Aarch64BasicBlock>? blocks = null) =>
        new(
            function,
            status,
            blocks ?? Array.Empty<Aarch64BasicBlock>(),
            instructions ?? Array.Empty<Aarch64FunctionInstruction>(),
            diagnostics.ToArray());

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        if (left > ulong.MaxValue - right)
        {
            result = default;
            return false;
        }

        result = left + right;
        return true;
    }
}
