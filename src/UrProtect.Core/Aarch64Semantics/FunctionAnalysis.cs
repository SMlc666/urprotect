using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Aarch64Semantics;

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
    public IReadOnlyList<Aarch64IndirectTargetResolution> IndirectTargetResolutions { get; init; } =
        Array.Empty<Aarch64IndirectTargetResolution>();

    public IReadOnlyList<Aarch64JumpTableResolution> JumpTableResolutions { get; init; } =
        Array.Empty<Aarch64JumpTableResolution>();

    public IReadOnlyList<Aarch64RuntimeIndirectCallResolution> RuntimeIndirectCallResolutions { get; init; } =
        Array.Empty<Aarch64RuntimeIndirectCallResolution>();

    public IReadOnlyList<Aarch64StaticFunctionPointerCallResolution> StaticFunctionPointerCallResolutions { get; init; } =
        Array.Empty<Aarch64StaticFunctionPointerCallResolution>();

    public IReadOnlyList<Aarch64ExternalJumpTableConsumerProof> ExternalJumpTableConsumerProofs { get; init; } =
        Array.Empty<Aarch64ExternalJumpTableConsumerProof>();

    public IReadOnlyList<Aarch64AddressReferenceResolution> AddressReferences { get; init; } =
        Array.Empty<Aarch64AddressReferenceResolution>();

    public bool IsComplete => Status == Aarch64FunctionAnalysisStatus.Complete;
}

/// <summary>
/// One runtime-owned indirect call whose ABI owner and fallthrough are proven.
/// </summary>
public sealed record Aarch64RuntimeIndirectCallResolution
{
    public Aarch64RuntimeIndirectCallResolution(
        ulong sourceAddress,
        Aarch64RegisterView targetRegister,
        IEnumerable<ulong> producerAddresses,
        string runtimeBinding,
        string proof,
        Aarch64RuntimeIndirectCallOwnerKind ownerKind = Aarch64RuntimeIndirectCallOwnerKind.HostContextCallback,
        uint? hostContextFieldOffset = null,
        Aarch64DynamicImportBinding? importBinding = null)
    {
        ArgumentNullException.ThrowIfNull(producerAddresses);
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeBinding);
        ArgumentException.ThrowIfNullOrWhiteSpace(proof);
        SourceAddress = sourceAddress;
        TargetRegister = targetRegister;
        ProducerAddresses = Array.AsReadOnly(producerAddresses.Distinct().OrderBy(address => address).ToArray());
        RuntimeBinding = runtimeBinding;
        Proof = proof;
        OwnerKind = ownerKind;
        HostContextFieldOffset = hostContextFieldOffset;
        ImportBinding = importBinding;
    }

    public ulong SourceAddress { get; }

    public Aarch64RegisterView TargetRegister { get; }

    public IReadOnlyList<ulong> ProducerAddresses { get; }

    public string RuntimeBinding { get; }

    public string Proof { get; }

    public Aarch64RuntimeIndirectCallOwnerKind OwnerKind { get; }

    public uint? HostContextFieldOffset { get; }

    public Aarch64DynamicImportBinding? ImportBinding { get; }
}

/// <summary>One exact indirect target proven from a selected function's bounded producer chain.</summary>
public sealed record Aarch64IndirectTargetResolution
{
    public Aarch64IndirectTargetResolution(
        ulong sourceAddress,
        VirtualAddress targetAddress,
        Aarch64RegisterView targetRegister,
        IEnumerable<ulong> producerAddresses,
        string proof)
    {
        ArgumentNullException.ThrowIfNull(producerAddresses);
        ArgumentException.ThrowIfNullOrWhiteSpace(proof);
        SourceAddress = sourceAddress;
        TargetAddress = targetAddress;
        TargetRegister = targetRegister;
        ProducerAddresses = Array.AsReadOnly(producerAddresses.ToArray());
        Proof = proof;
    }

    public ulong SourceAddress { get; }

    public VirtualAddress TargetAddress { get; }

    public Aarch64RegisterView TargetRegister { get; }

    public IReadOnlyList<ulong> ProducerAddresses { get; }

    public string Proof { get; }
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
    private static readonly uint[] TlsDescInstructionRelocationOrder =
    {
        ElfConstants.RArm64TlsDescAdrPage21,
        ElfConstants.RArm64TlsDescLd64Lo12,
        ElfConstants.RArm64TlsDescAddLo12,
        ElfConstants.RArm64TlsDescCall,
    };
    private readonly AsmStoneAdapter decoder;

    public Aarch64FunctionAnalyzer(AsmStoneAdapter? decoder = null)
    {
        this.decoder = decoder ?? new AsmStoneAdapter();
    }

    public Aarch64FunctionAnalysis Analyze(
        ElfFile file,
        ElfFunctionSymbol function,
        Aarch64HostContextProofContext? proofContext = null) =>
        AnalyzeCore(file, function, proofContext, externalProviderFacts: null);

    internal Aarch64FunctionAnalysis AnalyzeWithExternalProvider(
        ElfFile file,
        ElfFunctionSymbol function,
        Aarch64ExternalJumpTableProviderFacts externalProviderFacts,
        Aarch64HostContextProofContext? proofContext = null)
    {
        ArgumentNullException.ThrowIfNull(externalProviderFacts);
        return AnalyzeCore(file, function, proofContext, externalProviderFacts);
    }

    private Aarch64FunctionAnalysis AnalyzeCore(
        ElfFile file,
        ElfFunctionSymbol function,
        Aarch64HostContextProofContext? proofContext,
        Aarch64ExternalJumpTableProviderFacts? externalProviderFacts)
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
        var indirectResolutions = new Dictionary<ulong, Aarch64IndirectTargetResolution>();
        var jumpTableResolutions = new Dictionary<ulong, Aarch64JumpTableResolution>();
        var runtimeIndirectCalls = new Dictionary<ulong, Aarch64RuntimeIndirectCallResolution>();
        var staticFunctionPointerCalls = new Dictionary<ulong, Aarch64StaticFunctionPointerCallResolution>();
        var externalJumpTableConsumers = new Dictionary<ulong, Aarch64ExternalJumpTableConsumerProof>();
        var establishedProofContext = proofContext is not null
            && proofContext.MatchesEntry(function)
            && proofContext.MatchesSource(file)
                ? proofContext
                : null;
        var indirectCallProof = Aarch64IndirectCallProofAnalyzer.Analyze(
            file,
            instructions,
            function,
            function.Value,
            functionEnd,
            establishedProofContext);
        for (var instructionIndex = 0; instructionIndex < instructions.Count; instructionIndex++)
        {
            var instruction = instructions[instructionIndex];
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
                    AddFallthroughStart(starts, instruction.Address, functionEnd);
                    break;
                case Aarch64ControlFlowKind.IndirectBranch when IsTlsDescCallMarker(
                    file,
                    instruction,
                    function.Value,
                    functionEnd):
                    AddFallthroughStart(starts, instruction.Address, functionEnd);
                    break;
                case Aarch64ControlFlowKind.IndirectBranch
                    when indirectCallProof.Resolutions.TryGetValue(instruction.Address, out var runtimeCall):
                    runtimeIndirectCalls.Add(instruction.Address, runtimeCall);
                    AddFallthroughStart(starts, instruction.Address, functionEnd);
                    break;
                case Aarch64ControlFlowKind.IndirectBranch
                    when indirectCallProof.StaticFunctionPointerResolutions.TryGetValue(
                        instruction.Address,
                        out var staticFunctionPointerCall):
                    staticFunctionPointerCalls.Add(instruction.Address, staticFunctionPointerCall);
                    AddFallthroughStart(starts, instruction.Address, functionEnd);
                    break;
                case Aarch64ControlFlowKind.IndirectBranch
                    when externalProviderFacts is not null
                        && Aarch64JumpTableResolver.TryProveExternalProviderTableConsumer(
                            instructions,
                            instructionIndex,
                            function,
                            file,
                            externalProviderFacts,
                            out var externalConsumer,
                            out _)
                        && externalConsumer is not null:
                    externalJumpTableConsumers.Add(instruction.Address, externalConsumer);
                    break;
                case Aarch64ControlFlowKind.IndirectBranch
                    when decoded.Mnemonic.Equals("blr", StringComparison.OrdinalIgnoreCase):
                    diagnostics.Error(
                        DiagnosticCode.IndirectTargetUnresolved,
                        indirectCallProof.Failures.TryGetValue(instruction.Address, out var proofFailure)
                            ? proofFailure
                            : "The indirect-call target has no complete register, stack, HostContext, or relocation-owner proof.",
                        instruction.Address);
                    return Failure(
                        function,
                        Aarch64FunctionAnalysisStatus.IncompleteControlFlow,
                        diagnostics,
                        instructions);
                case Aarch64ControlFlowKind.IndirectBranch:
                    if (!TryResolveBoundedIndirectBranch(
                            instructions,
                            instructionIndex,
                            function.Value,
                            functionEnd,
                            byAddress,
                            file,
                            out var indirectResolution,
                            out var jumpTableResolution,
                            out var indirectFailure,
                            out var unsupportedIndirect))
                    {
                        diagnostics.Error(
                            unsupportedIndirect
                                ? DiagnosticCode.IndirectTargetUnsupported
                                : DiagnosticCode.IndirectTargetUnresolved,
                            indirectFailure,
                            instruction.Address);
                        return Failure(
                            function,
                            Aarch64FunctionAnalysisStatus.IncompleteControlFlow,
                            diagnostics,
                            instructions);
                    }

                    if (indirectResolution is not null)
                    {
                        indirectResolutions.Add(instruction.Address, indirectResolution);
                        starts.Add(indirectResolution.TargetAddress.Value);
                    }

                    if (jumpTableResolution is not null)
                    {
                        jumpTableResolutions.Add(instruction.Address, jumpTableResolution);
                        foreach (var targetAddress in jumpTableResolution.TargetAddresses)
                        {
                            starts.Add(targetAddress.Value);
                        }

                        starts.Add(jumpTableResolution.DefaultTargetAddress.Value);
                    }

                    break;
                case Aarch64ControlFlowKind.Return:
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
            var isTlsDescCall = IsTlsDescCallMarker(file, last, function.Value, functionEnd);
            indirectResolutions.TryGetValue(last.Address, out var indirectResolution);
            jumpTableResolutions.TryGetValue(last.Address, out var jumpTableResolution);
            var isRuntimeIndirectCall = runtimeIndirectCalls.ContainsKey(last.Address)
                || staticFunctionPointerCalls.ContainsKey(last.Address);
            var successors = GetSuccessors(
                last,
                functionEnd,
                isTlsDescCall,
                isRuntimeIndirectCall,
                indirectResolution?.TargetAddress,
                jumpTableResolution?.TargetAddresses,
                jumpTableResolution?.DefaultTargetAddress);

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
            var unreachableBlocks = blocks
                .Where(block => !reachable.Contains(block.StartAddress))
                .ToArray();
            var lastReachableInstruction = blocks
                .Where(block => reachable.Contains(block.StartAddress))
                .SelectMany(block => block.Instructions)
                .Select(instruction => instruction.Address)
                .DefaultIfEmpty(function.Value)
                .Max();
            var isTrailingAlignmentPadding = unreachableBlocks.Length > 0
                && unreachableBlocks.All(block =>
                    block.StartAddress > lastReachableInstruction
                    && block.Instructions.All(instruction => instruction.Encoding == 0xD503201Fu));

            if (!isTrailingAlignmentPadding)
            {
                var unreachable = unreachableBlocks[0];
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
        }

        var externalProviderAddressReferences = externalJumpTableConsumers.Values
            .Select(proof => new Aarch64AddressReferenceResolution(
                proof.GotPageProducerAddress,
                proof.GotLoadProducerAddress,
                new VirtualAddress(proof.GotSlotAddress.Value & ~0xFFFUL),
                proof.GotSlotAddress,
                sizeof(ulong),
                proof.ImportOwner.Relocation,
                proof.ImportOwner,
                "The selected external provider-table consumer uses the source consumer's pinned GLOB_DAT-owned GOT slot."));

        return new Aarch64FunctionAnalysis(
            function,
            Aarch64FunctionAnalysisStatus.Complete,
            blocks,
            instructions,
            diagnostics.ToArray())
        {
            IndirectTargetResolutions = Array.AsReadOnly(indirectResolutions.Values
                .OrderBy(resolution => resolution.SourceAddress)
                .ToArray()),
            JumpTableResolutions = Array.AsReadOnly(jumpTableResolutions.Values
                .OrderBy(resolution => resolution.SourceAddress)
                .ToArray()),
            RuntimeIndirectCallResolutions = Array.AsReadOnly(runtimeIndirectCalls.Values
                .OrderBy(resolution => resolution.SourceAddress)
                .ToArray()),
            StaticFunctionPointerCallResolutions = Array.AsReadOnly(staticFunctionPointerCalls.Values
                .OrderBy(resolution => resolution.SourceAddress)
                .ToArray()),
            ExternalJumpTableConsumerProofs = Array.AsReadOnly(externalJumpTableConsumers.Values
                .OrderBy(resolution => resolution.BranchAddress)
                .ToArray()),
            AddressReferences = Array.AsReadOnly(indirectCallProof.AddressReferences
                .Concat(externalProviderAddressReferences)
                .OrderBy(reference => reference.PageProducerAddress)
                .ThenBy(reference => reference.LoadProducerAddress)
                .ToArray()),
        };
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
        ulong functionEnd,
        bool isTlsDescCall,
        bool isRuntimeIndirectCall,
        VirtualAddress? indirectTarget,
        IReadOnlyList<VirtualAddress>? indirectTargets,
        VirtualAddress? defaultTarget)
    {
        var decoded = instruction.Decode.Instruction!;
        var next = instruction.Address + InstructionSize;
        return decoded.ControlFlow switch
        {
            Aarch64ControlFlowKind.Return =>
                new[] { new Aarch64ControlFlowEdge(instruction.Address, null, Aarch64ControlFlowEdgeKind.Return) },
            Aarch64ControlFlowKind.IndirectBranch when isTlsDescCall || isRuntimeIndirectCall =>
                next < functionEnd
                    ? new[] { new Aarch64ControlFlowEdge(instruction.Address, next, Aarch64ControlFlowEdgeKind.Fallthrough) }
                    : Array.Empty<Aarch64ControlFlowEdge>(),
            Aarch64ControlFlowKind.IndirectBranch when indirectTargets is { Count: > 0 } targets =>
                targets
                    .Select(target => new Aarch64ControlFlowEdge(
                        instruction.Address,
                        target.Value,
                        Aarch64ControlFlowEdgeKind.Indirect))
                    .Concat(defaultTarget is { } fallback
                        ? new[]
                        {
                            new Aarch64ControlFlowEdge(
                                instruction.Address,
                                fallback.Value,
                                Aarch64ControlFlowEdgeKind.Indirect),
                        }
                        : Array.Empty<Aarch64ControlFlowEdge>())
                    .ToArray(),
            Aarch64ControlFlowKind.IndirectBranch when indirectTarget is { } target =>
                new[] { new Aarch64ControlFlowEdge(instruction.Address, target.Value, Aarch64ControlFlowEdgeKind.Indirect) },
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

    private static bool TryResolveBoundedIndirectBranch(
        IReadOnlyList<Aarch64FunctionInstruction> instructions,
        int branchIndex,
        ulong functionStart,
        ulong functionEnd,
        Dictionary<ulong, Aarch64FunctionInstruction> byAddress,
        ElfFile file,
        out Aarch64IndirectTargetResolution? resolution,
        out Aarch64JumpTableResolution? jumpTableResolution,
        out string failure,
        out bool unsupported)
    {
        resolution = null;
        jumpTableResolution = null;
        failure = "The indirect target is not proven by an exact producer chain or bounded jump table.";
        unsupported = false;
        var branch = instructions[branchIndex].Decode.Instruction!;
        if (!string.Equals(branch.Mnemonic, "br", StringComparison.OrdinalIgnoreCase))
        {
            failure = "Only an in-function BR target is supported; indirect calls retain runtime-owned return semantics.";
            unsupported = true;
            return false;
        }

        var branchRegisters = branch.Operands
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
        if (branchRegisters.Length != 1 || branchIndex == 0)
        {
            return false;
        }

        var targetRegister = branchRegisters[0];
        var maximumProducerCount = Math.Min(4, branchIndex);
        for (var producerCount = 1; producerCount <= maximumProducerCount; producerCount++)
        {
            var firstIndex = branchIndex - producerCount;
            var producers = instructions.Skip(firstIndex).Take(producerCount).ToArray();
            if (!TryReadMoveWideProducerChain(producers, targetRegister, out var target))
            {
                continue;
            }

            if (target < functionStart
                || target >= functionEnd
                || target % InstructionSize != 0
                || !byAddress.ContainsKey(target))
            {
                failure = "The exact move-wide indirect target is outside the selected function's aligned instruction range.";
                return false;
            }

            resolution = new Aarch64IndirectTargetResolution(
                instructions[branchIndex].Address,
                new VirtualAddress(target),
                targetRegister,
                producers.Select(producer => producer.Address),
                "exact target from a contiguous 64-bit MOVZ/MOVN and MOVK producer chain");
            return true;
        }

        if (Aarch64JumpTableResolver.TryResolve(
                instructions,
                branchIndex,
                functionStart,
                functionEnd,
                byAddress,
                file,
                out jumpTableResolution,
                out failure,
                out var recognized)
            && recognized)
        {
            return true;
        }

        return false;
    }

    private static bool TryReadMoveWideProducerChain(
        IReadOnlyList<Aarch64FunctionInstruction> producers,
        Aarch64RegisterView targetRegister,
        out ulong value)
    {
        value = default;
        if (producers.Count is < 1 or > 4)
        {
            return false;
        }

        var first = producers[0].Decode.Instruction!;
        var firstIsMovz = first.Mnemonic.StartsWith("MOVZ", StringComparison.OrdinalIgnoreCase);
        var firstIsMovn = first.Mnemonic.StartsWith("MOVN", StringComparison.OrdinalIgnoreCase);
        if ((!firstIsMovz && !firstIsMovn)
            || !TryGetMoveWideOperands(first, allowInputOutput: false, out var firstRegister, out var firstImmediate, out var firstShift)
            || firstRegister != targetRegister)
        {
            return false;
        }

        value = firstIsMovn ? ~(firstImmediate << firstShift) : firstImmediate << firstShift;
        for (var index = 1; index < producers.Count; index++)
        {
            var decoded = producers[index].Decode.Instruction!;
            if (!decoded.Mnemonic.StartsWith("MOVK", StringComparison.OrdinalIgnoreCase)
                || !TryGetMoveWideOperands(decoded, allowInputOutput: true, out var register, out var immediate, out var shift)
                || register != targetRegister)
            {
                return false;
            }

            var mask = 0xFFFFUL << shift;
            value = (value & ~mask) | (immediate << shift);
        }

        return true;
    }

    private static bool TryGetMoveWideOperands(
        Aarch64Instruction instruction,
        bool allowInputOutput,
        out Aarch64RegisterView register,
        out ulong immediate,
        out int shift)
    {
        register = default;
        immediate = default;
        shift = default;
        var registerOperands = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && (operand.Direction == Aarch64OperandDirection.Output
                    || (allowInputOutput && operand.Direction == Aarch64OperandDirection.InputOutput))
                && operand.Register is
                {
                    Class: Aarch64RegisterClass.General,
                    Width: 64,
                    Role: Aarch64RegisterRole.None,
                })
            .Select(operand => operand.Register!.Value)
            .ToArray();
        var immediates = instruction.Operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Immediate)
            .Select(operand => operand.Immediate)
            .ToArray();
        if (registerOperands.Length != 1
            || immediates.Length != 2
            || immediates.Any(item => item is null or < 0 or > ushort.MaxValue)
            || immediates[1] is not (0 or 16 or 32 or 48))
        {
            return false;
        }

        register = registerOperands[0];
        immediate = checked((ulong)immediates[0]!.Value);
        shift = checked((int)immediates[1]!.Value);
        return true;
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

    private static bool IsTlsDescCallMarker(
        ElfFile file,
        Aarch64FunctionInstruction instruction,
        ulong functionStart,
        ulong functionEnd)
    {
        var decoded = instruction.Decode.Instruction;
        if (decoded is null
            || !string.Equals(decoded.Mnemonic, "blr", StringComparison.OrdinalIgnoreCase)
            || decoded.ControlFlow != Aarch64ControlFlowKind.IndirectBranch
            || !decoded.Operands.Any(operand =>
                operand.Direction is Aarch64OperandDirection.Input or Aarch64OperandDirection.InputOutput
                && operand.Register is
                {
                    Class: Aarch64RegisterClass.General,
                    Index: 1,
                    Width: 64,
                    Role: Aarch64RegisterRole.None,
                }))
        {
            return false;
        }

        var markers = file.TlsMetadata.StaticRelocations
            .Concat(file.TlsMetadata.Dynamic.Relocations)
            .Where(fact => fact.Relocation.Offset >= functionStart
                && fact.Relocation.Offset < functionEnd
                && TlsDescInstructionRelocationOrder.Contains(fact.Relocation.Type))
            .OrderBy(fact => fact.Relocation.Offset)
            .ToArray();
        return markers.Length == TlsDescInstructionRelocationOrder.Length
            && markers.Select(fact => fact.Relocation.Type).SequenceEqual(TlsDescInstructionRelocationOrder)
            && markers.Select(fact => fact.Relocation.Offset).SequenceEqual(
                Enumerable.Range(0, TlsDescInstructionRelocationOrder.Length)
                    .Select(index => instruction.Address - ((ulong)(TlsDescInstructionRelocationOrder.Length - 1 - index) * InstructionSize)))
            && markers[^1].Relocation.Offset == instruction.Address;
    }

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
