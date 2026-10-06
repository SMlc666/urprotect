using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Aarch64;

public enum SemanticTargetResolution
{
    Exact,
    BoundedSet,
    RuntimeResolved,
    Unresolved,
}

public enum SemanticEntityKind
{
    Function,
    BasicBlock,
    Instruction,
    Literal,
    Veneer,
    Table,
    RelocationTarget,
    RelocationSite,
}

public readonly record struct SemanticEntityId(SemanticEntityKind Kind, string Value)
{
    public static SemanticEntityId Function(string value) => new(SemanticEntityKind.Function, value);

    public static SemanticEntityId BasicBlock(string value) => new(SemanticEntityKind.BasicBlock, value);

    public static SemanticEntityId Instruction(VirtualAddress address) =>
        new(SemanticEntityKind.Instruction, $"0x{address.Value:X}");

    public static SemanticEntityId Literal(string value) => new(SemanticEntityKind.Literal, value);

    public static SemanticEntityId Veneer(string value) => new(SemanticEntityKind.Veneer, value);

    public static SemanticEntityId Table(string value) => new(SemanticEntityKind.Table, value);

    public static SemanticEntityId RelocationTarget(string value) =>
        new(SemanticEntityKind.RelocationTarget, value);

    public static SemanticEntityId RelocationSite(string value) =>
        new(SemanticEntityKind.RelocationSite, value);
}

public sealed record SemanticTarget
{
    public SemanticTarget(
        SemanticTargetResolution resolution,
        VirtualAddress? sourceAddress = null,
        SemanticEntityId? identity = null,
        IEnumerable<SemanticEntityId>? candidateIdentities = null,
        IEnumerable<VirtualAddress>? candidateAddresses = null,
        string? runtimeBinding = null,
        string? diagnostic = null)
    {
        Resolution = resolution;
        SourceAddress = sourceAddress;
        Identity = identity;
        CandidateIdentities = Array.AsReadOnly(
            (candidateIdentities ?? Array.Empty<SemanticEntityId>()).ToArray());
        CandidateAddresses = Array.AsReadOnly(
            (candidateAddresses ?? Array.Empty<VirtualAddress>()).ToArray());
        RuntimeBinding = runtimeBinding;
        Diagnostic = diagnostic;
    }

    public SemanticTargetResolution Resolution { get; }

    public SemanticTargetResolution Kind => Resolution;

    public VirtualAddress? SourceAddress { get; }

    public SemanticEntityId? Identity { get; }

    public IReadOnlyList<SemanticEntityId> CandidateIdentities { get; }

    public IReadOnlyList<VirtualAddress> CandidateAddresses { get; }

    public string? RuntimeBinding { get; }

    public string? Diagnostic { get; }

    public bool IsExact => Resolution == SemanticTargetResolution.Exact;

    public bool IsBoundedSet => Resolution == SemanticTargetResolution.BoundedSet;

    public bool IsRuntimeResolved => Resolution == SemanticTargetResolution.RuntimeResolved;

    public bool IsUnresolved => Resolution == SemanticTargetResolution.Unresolved;

    public static SemanticTarget Exact(VirtualAddress sourceAddress) =>
        new(SemanticTargetResolution.Exact, sourceAddress: sourceAddress);

    public static SemanticTarget Exact(SemanticEntityId identity, VirtualAddress? sourceAddress = null) =>
        new(SemanticTargetResolution.Exact, sourceAddress, identity);

    public static SemanticTarget BoundedSet(IEnumerable<SemanticEntityId> identities) =>
        new(SemanticTargetResolution.BoundedSet, candidateIdentities: identities);

    public static SemanticTarget BoundedSet(IEnumerable<VirtualAddress> addresses) =>
        new(SemanticTargetResolution.BoundedSet, candidateAddresses: addresses);

    public static SemanticTarget RuntimeResolved(string binding) =>
        new(SemanticTargetResolution.RuntimeResolved, runtimeBinding: binding);

    public static SemanticTarget Unresolved(string diagnostic) =>
        new(SemanticTargetResolution.Unresolved, diagnostic: diagnostic);
}

public readonly record struct SemanticSourceRange(
    FileOffset FileOffset,
    VirtualAddress VirtualAddress,
    ulong Size)
{
    public bool IsInstructionRange => Size == sizeof(uint)
        && FileOffset.Value % sizeof(uint) == 0
        && VirtualAddress.Value % sizeof(uint) == 0
        && TryGetFileEnd(out _)
        && TryGetVirtualEnd(out _);

    public bool TryGetFileEnd(out ulong end)
    {
        if (Size > ulong.MaxValue - FileOffset.Value)
        {
            end = default;
            return false;
        }

        end = checked(FileOffset.Value + Size);
        return true;
    }

    public bool TryGetVirtualEnd(out ulong end)
    {
        if (Size > ulong.MaxValue - VirtualAddress.Value)
        {
            end = default;
            return false;
        }

        end = checked(VirtualAddress.Value + Size);
        return true;
    }
}

public sealed record SemanticOperand
{
    public SemanticOperand(
        string Name,
        Aarch64OperandKind Kind,
        Aarch64OperandDirection Direction,
        bool IsImplicit,
        string Codec,
        string? TiedTo,
        Aarch64RegisterView? Register,
        IEnumerable<Aarch64RegisterView>? Registers,
        Aarch64MemoryReference? Memory,
        long? Immediate,
        ulong? Target,
        Aarch64RegisterConstraint RegisterConstraint,
        int RegisterWidth,
        int FieldWidth,
        int ElementWidth,
        bool AllowsStackPointer,
        bool AllowsZeroRegister,
        bool IsPageRelative,
        string SemanticDomain)
    {
        ArgumentNullException.ThrowIfNull(Name);
        ArgumentNullException.ThrowIfNull(Codec);
        ArgumentNullException.ThrowIfNull(SemanticDomain);
        this.Name = Name;
        this.Kind = Kind;
        this.Direction = Direction;
        this.IsImplicit = IsImplicit;
        this.Codec = Codec;
        this.TiedTo = TiedTo;
        this.Register = Register;
        this.Registers = Array.AsReadOnly((Registers ?? Array.Empty<Aarch64RegisterView>()).ToArray());
        this.Memory = Memory;
        this.Immediate = Immediate;
        this.Target = Target;
        this.RegisterConstraint = RegisterConstraint;
        this.RegisterWidth = RegisterWidth;
        this.FieldWidth = FieldWidth;
        this.ElementWidth = ElementWidth;
        this.AllowsStackPointer = AllowsStackPointer;
        this.AllowsZeroRegister = AllowsZeroRegister;
        this.IsPageRelative = IsPageRelative;
        this.SemanticDomain = SemanticDomain;
    }

    public string Name { get; }

    public Aarch64OperandKind Kind { get; }

    public Aarch64OperandDirection Direction { get; }

    public bool IsImplicit { get; }

    public string Codec { get; }

    public string? TiedTo { get; }

    public Aarch64RegisterView? Register { get; }

    public IReadOnlyList<Aarch64RegisterView> Registers { get; }

    public Aarch64MemoryReference? Memory { get; }

    public long? Immediate { get; }

    public ulong? Target { get; }

    public Aarch64RegisterConstraint RegisterConstraint { get; }

    public int RegisterWidth { get; }

    public int FieldWidth { get; }

    public int ElementWidth { get; }

    public bool AllowsStackPointer { get; }

    public bool AllowsZeroRegister { get; }

    public bool IsPageRelative { get; }

    public string SemanticDomain { get; }
}

public enum SemanticRegisterEffectKind
{
    Read,
    Write,
    ReadWrite,
}

public readonly record struct SemanticRegisterEffect(
    Aarch64RegisterView Register,
    SemanticRegisterEffectKind Kind,
    bool IsImplicit);

[Flags]
public enum SemanticFlagEffects
{
    None = 0,
    ReadNzcv = 1 << 0,
    WriteNzcv = 1 << 1,
}

public enum PcRelativeExpressionKind
{
    Branch26,
    Call26,
    ConditionalBranch19,
    TestBranch14,
    AdrPrelLo21,
    AdrPrelPgHi21,
    Literal19,
}

public sealed record PcRelativeExpression(
    PcRelativeExpressionKind Kind,
    VirtualAddress Place,
    SemanticTarget Target,
    int Scale = 1,
    bool IsPageRelative = false,
    long Addend = 0);

public sealed record LiteralReference(
    SemanticTarget Target,
    int AccessSize,
    bool IsLoad = true,
    SemanticSourceRange? PoolRange = null);

public sealed record RelocationBinding(
    Aarch64RelocationKind Kind,
    SemanticTarget Target,
    long Addend = 0,
    uint SymbolIndex = 0,
    bool IsPlt = false,
    string? SymbolName = null,
    uint? RelocationType = null,
    VirtualAddress? RelocationAddress = null,
    VirtualAddress? RelocationTableAddress = null)
{
    public static RelocationBinding FromRelocation(
        RelaRelocation relocation,
        SemanticTarget target,
        string? symbolName = null) =>
        new(
            relocation.Kind,
            target,
            relocation.Addend,
            relocation.SymbolIndex,
            relocation.IsPlt,
            symbolName,
            relocation.Type,
            new VirtualAddress(relocation.Offset),
            new VirtualAddress(relocation.SourceAddress))
        {
            RawInfo = relocation.Info,
        };

    /// <summary>
    /// Gets the original ELF <c>r_info</c> word when this binding was projected
    /// from a raw RELA record. The decoded type and symbol index remain available
    /// separately for semantic matching, while this field preserves the source
    /// metadata for round-trip serialization and diagnostics.
    /// </summary>
    public ulong? RawInfo { get; init; }

    public bool IsExternalBinding => IsPlt
        || SymbolIndex != 0
        || Kind is
            Aarch64RelocationKind.GlobalData
            or Aarch64RelocationKind.JumpSlot;

    public bool IsKindConsistent =>
        (RelocationType is not { } type || RelaRelocation.Classify(type) == Kind)
        && (RawInfo is not { } rawInfo
            || rawInfo == (((ulong)SymbolIndex << 32) | (RelocationType ?? 0)));
}

public enum SemanticReferenceKind
{
    ControlFlowTarget,
    PcRelative,
    Literal,
    Relocation,
    Memory,
}

public sealed record SemanticReference(
    SemanticReferenceKind Kind,
    SemanticTarget Target,
    int OperandIndex = -1,
    PcRelativeExpression? PcRelative = null,
    LiteralReference? Literal = null,
    RelocationBinding? Relocation = null,
    string? Description = null);

public sealed record SemanticInstruction
{
    public SemanticInstruction(
        VirtualAddress sourceVirtualAddress,
        FileOffset sourceFileOffset,
        uint encoding,
        string mnemonic,
        SemanticSourceRange sourceRange,
        IEnumerable<SemanticOperand>? operands = null,
        IEnumerable<SemanticRegisterEffect>? registerEffects = null,
        SemanticFlagEffects flagEffects = SemanticFlagEffects.None,
        Aarch64ControlFlowKind controlFlow = Aarch64ControlFlowKind.None,
        SemanticTarget? controlFlowTarget = null,
        PcRelativeExpression? pcRelativeExpression = null,
        LiteralReference? literalReference = null,
        IEnumerable<RelocationBinding>? relocations = null,
        IEnumerable<SemanticReference>? references = null,
        bool opaquePreservation = false)
    {
        ArgumentNullException.ThrowIfNull(mnemonic);
        if (mnemonic.Length == 0)
        {
            throw new ArgumentException("A semantic instruction mnemonic is required.", nameof(mnemonic));
        }

        SourceVirtualAddress = sourceVirtualAddress;
        SourceFileOffset = sourceFileOffset;
        Encoding = encoding;
        Mnemonic = mnemonic;
        SourceRange = sourceRange;
        Operands = Array.AsReadOnly((operands ?? Array.Empty<SemanticOperand>()).ToArray());
        RegisterEffects = Array.AsReadOnly(
            (registerEffects ?? Array.Empty<SemanticRegisterEffect>()).ToArray());
        FlagEffects = flagEffects;
        ControlFlow = controlFlow;
        ControlFlowTarget = controlFlowTarget;
        PcRelativeExpression = pcRelativeExpression;
        LiteralReference = literalReference;
        Relocations = Array.AsReadOnly((relocations ?? Array.Empty<RelocationBinding>()).ToArray());
        References = Array.AsReadOnly((references ?? Array.Empty<SemanticReference>()).ToArray());
        OpaquePreservation = opaquePreservation;
    }

    public VirtualAddress SourceVirtualAddress { get; }

    public FileOffset SourceFileOffset { get; }

    public uint Encoding { get; }

    public uint RawEncoding => Encoding;

    public string Mnemonic { get; }

    public SemanticSourceRange SourceRange { get; }

    public IReadOnlyList<SemanticOperand> Operands { get; }

    public IReadOnlyList<SemanticRegisterEffect> RegisterEffects { get; }

    public SemanticFlagEffects FlagEffects { get; }

    public Aarch64ControlFlowKind ControlFlow { get; }

    public SemanticTarget? ControlFlowTarget { get; }

    public PcRelativeExpression? PcRelativeExpression { get; }

    public LiteralReference? LiteralReference { get; }

    public IReadOnlyList<RelocationBinding> Relocations { get; }

    public IReadOnlyList<SemanticReference> References { get; }

    public bool OpaquePreservation { get; }
}

public enum SemanticFixupKind
{
    Branch26,
    Call26,
    ConditionalBranch19,
    TestBranch14,
    AdrPrelLo21,
    AdrPrelPgHi21,
    Literal19,
    Relocation,

    Adr = AdrPrelLo21,
    Adrp = AdrPrelPgHi21,
    LiteralLoad19 = Literal19,
}

public enum SemanticRelaxationKind
{
    None,
    NearVeneer,
    LongAddress,
}

public sealed record SemanticFixup
{
    public SemanticFixup(
        SemanticFixupKind kind,
        VirtualAddress sourceAddress,
        FileOffset sourceFileOffset,
        uint originalEncoding,
        SemanticTarget target,
        SemanticSourceRange? sourceRange = null,
        PcRelativeExpression? expression = null,
        RelocationBinding? relocation = null,
        SemanticRelaxationKind relaxation = SemanticRelaxationKind.None,
        IEnumerable<SemanticRelaxationKind>? relaxationOptions = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        Kind = kind;
        SourceAddress = sourceAddress;
        SourceFileOffset = sourceFileOffset;
        OriginalEncoding = originalEncoding;
        Target = target;
        SourceRange = sourceRange ?? new SemanticSourceRange(sourceFileOffset, sourceAddress, sizeof(uint));
        Expression = expression;
        Relocation = relocation;
        Relaxation = relaxation;
        RelaxationOptions = Array.AsReadOnly((relaxationOptions ?? new[]
        {
            SemanticRelaxationKind.None,
            SemanticRelaxationKind.NearVeneer,
            SemanticRelaxationKind.LongAddress,
        }).Distinct().ToArray());
    }

    public SemanticFixupKind Kind { get; }

    public VirtualAddress SourceAddress { get; }

    public FileOffset SourceFileOffset { get; }

    public uint OriginalEncoding { get; }

    public SemanticTarget Target { get; }

    public SemanticSourceRange SourceRange { get; }

    public PcRelativeExpression? Expression { get; }

    public RelocationBinding? Relocation { get; }

    public SemanticRelaxationKind Relaxation { get; }

    public IReadOnlyList<SemanticRelaxationKind> RelaxationOptions { get; }

    public static SemanticFixup? FromInstruction(SemanticInstruction instruction)
    {
        ArgumentNullException.ThrowIfNull(instruction);
        var expression = instruction.PcRelativeExpression
            ?? (instruction.LiteralReference is { } literal
                ? new PcRelativeExpression(
                    PcRelativeExpressionKind.Literal19,
                    instruction.SourceVirtualAddress,
                    literal.Target,
                    Scale: sizeof(uint))
                : null);
        if (expression is null)
        {
            return null;
        }

        var kind = expression.Kind switch
        {
            PcRelativeExpressionKind.Branch26 => SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Call26 => SemanticFixupKind.Call26,
            PcRelativeExpressionKind.ConditionalBranch19 => SemanticFixupKind.ConditionalBranch19,
            PcRelativeExpressionKind.TestBranch14 => SemanticFixupKind.TestBranch14,
            PcRelativeExpressionKind.AdrPrelLo21 => SemanticFixupKind.AdrPrelLo21,
            PcRelativeExpressionKind.AdrPrelPgHi21 => SemanticFixupKind.AdrPrelPgHi21,
            PcRelativeExpressionKind.Literal19 => SemanticFixupKind.Literal19,
            _ => throw new ArgumentOutOfRangeException(
                nameof(instruction),
                expression.Kind,
                "The PC-relative expression kind is not supported."),
        };

        return new SemanticFixup(
            kind,
            instruction.SourceVirtualAddress,
            instruction.SourceFileOffset,
            instruction.Encoding,
            expression.Target,
            instruction.SourceRange,
            expression);
    }

    public static SemanticFixup FromRelocation(
        VirtualAddress sourceAddress,
        FileOffset sourceFileOffset,
        uint originalEncoding,
        RelocationBinding relocation,
        SemanticSourceRange? sourceRange = null)
    {
        ArgumentNullException.ThrowIfNull(relocation);
        return new SemanticFixup(
            SemanticFixupKind.Relocation,
            sourceAddress,
            sourceFileOffset,
            originalEncoding,
            relocation.Target,
            sourceRange ?? new SemanticSourceRange(
                sourceFileOffset,
                sourceAddress,
                GetRelocationWriteSize(relocation.Kind)),
            relocation: relocation);
    }

    public static ulong GetRelocationWriteSize(Aarch64RelocationKind kind) => kind switch
    {
        Aarch64RelocationKind.Absolute64
            or Aarch64RelocationKind.Prel64
            or Aarch64RelocationKind.Relative
            or Aarch64RelocationKind.GlobalData
            or Aarch64RelocationKind.JumpSlot
            or Aarch64RelocationKind.ThreadLocal
            or Aarch64RelocationKind.IRelative => sizeof(ulong),
        Aarch64RelocationKind.Absolute32
            or Aarch64RelocationKind.Prel32
            or Aarch64RelocationKind.Call26
            or Aarch64RelocationKind.Jump26
            or Aarch64RelocationKind.ConditionalBranch19
            or Aarch64RelocationKind.TestBranch14
            or Aarch64RelocationKind.AdrPrelLo21
            or Aarch64RelocationKind.AdrPrelPgHi21
            or Aarch64RelocationKind.Literal19
            or Aarch64RelocationKind.AddAbsLo12
            or Aarch64RelocationKind.LoadStore => sizeof(uint),
        _ => 0,
    };
}

public enum SemanticPlanExtensionKind
{
    IndirectTargets,
    TlsBinding,
    JumpTable,
    CfiEffect,
    RelocationBinding,
    UnresolvedReference,
}

public interface ISemanticPlanExtension
{
    SemanticPlanExtensionKind Kind { get; }
}

public sealed record SemanticFixupResolution
{
    public SemanticFixupResolution(
        SemanticFixup Fixup,
        bool IsSuccess,
        bool IsDeferred,
        VirtualAddress? OutputSourceAddress,
        VirtualAddress? OutputTargetAddress,
        uint? InstructionEncoding,
        ulong? RelocationValue,
        IEnumerable<Diagnostic> Diagnostics)
    {
        ArgumentNullException.ThrowIfNull(Fixup);
        ArgumentNullException.ThrowIfNull(Diagnostics);
        this.Fixup = Fixup;
        this.IsSuccess = IsSuccess;
        this.IsDeferred = IsDeferred;
        this.OutputSourceAddress = OutputSourceAddress;
        this.OutputTargetAddress = OutputTargetAddress;
        this.InstructionEncoding = InstructionEncoding;
        this.RelocationValue = RelocationValue;
        this.Diagnostics = Array.AsReadOnly(Diagnostics.ToArray());
    }

    public SemanticFixup Fixup { get; }

    public bool IsSuccess { get; }

    public bool IsDeferred { get; }

    public VirtualAddress? OutputSourceAddress { get; }

    public VirtualAddress? OutputTargetAddress { get; }

    public uint? InstructionEncoding { get; }

    public ulong? RelocationValue { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsFinal => IsSuccess && !IsDeferred;
}

public sealed record SemanticPlanResolutionResult
{
    public SemanticPlanResolutionResult(
        IEnumerable<SemanticFixupResolution> Fixups,
        IEnumerable<Diagnostic> Diagnostics)
    {
        ArgumentNullException.ThrowIfNull(Fixups);
        ArgumentNullException.ThrowIfNull(Diagnostics);
        this.Fixups = Array.AsReadOnly(Fixups.ToArray());
        this.Diagnostics = Array.AsReadOnly(Diagnostics.ToArray());
    }

    public IReadOnlyList<SemanticFixupResolution> Fixups { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError)
        && Fixups.All(fixup => fixup.IsFinal);

    public bool HasDeferredFixups => Fixups.Any(fixup => fixup.IsDeferred);
}

public sealed record SemanticRewritePlanResult
{
    public SemanticRewritePlanResult(
        SemanticRewritePlan? Plan,
        IEnumerable<Diagnostic> Diagnostics)
    {
        ArgumentNullException.ThrowIfNull(Diagnostics);
        this.Plan = Plan;
        this.Diagnostics = Array.AsReadOnly(Diagnostics.ToArray());
    }

    public SemanticRewritePlan? Plan { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsSuccess => Plan is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed record SemanticRewritePlan
{
    public SemanticRewritePlan(
        AddressMap addressMap,
        IEnumerable<SemanticInstruction> instructions,
        IEnumerable<SemanticFixup> fixups,
        IEnumerable<ISemanticPlanExtension>? extensions = null,
        IEnumerable<Diagnostic>? diagnostics = null)
    {
        ArgumentNullException.ThrowIfNull(addressMap);
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(fixups);
        AddressMap = addressMap;
        Instructions = Array.AsReadOnly(instructions.ToArray());
        Fixups = Array.AsReadOnly(fixups.ToArray());
        Extensions = Array.AsReadOnly(
            (extensions ?? Array.Empty<ISemanticPlanExtension>()).ToArray());
        Diagnostics = Array.AsReadOnly((diagnostics ?? Array.Empty<Diagnostic>()).ToArray());
    }

    public AddressMap AddressMap { get; }

    public IReadOnlyList<SemanticInstruction> Instructions { get; }

    public IReadOnlyList<SemanticFixup> Fixups { get; }

    public IReadOnlyList<ISemanticPlanExtension> Extensions { get; }

    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    public bool IsValid => Diagnostics.All(diagnostic => !diagnostic.IsError);

    public SemanticPlanResolutionResult ResolveFixups() =>
        Aarch64SemanticFixupEncoder.Resolve(this);

    public SemanticPlanValidationResult Validate(
        SemanticPlanResolutionResult resolution,
        IAarch64Decoder decoder) =>
        Aarch64SemanticPlanValidator.Validate(this, resolution, decoder);

    public SemanticPlanValidationResult Validate(IAarch64Decoder decoder) =>
        Aarch64SemanticPlanValidator.Validate(this, decoder);
}

public static class SemanticRewritePlanBuilder
{
    public static SemanticRewritePlanResult Build(
        AddressMap addressMap,
        IEnumerable<SemanticInstruction> instructions,
        IEnumerable<SemanticFixup> fixups,
        IEnumerable<ISemanticPlanExtension>? extensions = null,
        IEnumerable<Diagnostic>? initialDiagnostics = null)
    {
        ArgumentNullException.ThrowIfNull(addressMap);
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(fixups);

        var diagnostics = new DiagnosticBag();
        if (initialDiagnostics is not null)
        {
            diagnostics.AddRange(initialDiagnostics);
        }

        var instructionArray = instructions.ToArray();
        var fixupArray = fixups.ToArray();

        var instructionAddresses = new HashSet<VirtualAddress>();
        var instructionFileOffsets = new HashSet<FileOffset>();
        var pcRelativeInstructionSites = new HashSet<VirtualAddress>();
        var pcRelativeFixupSites = new HashSet<VirtualAddress>();
        var fixupSites = new HashSet<VirtualAddress>();
        var fixupFileSites = new HashSet<FileOffset>();
        foreach (var instruction in instructionArray)
        {
            if (instruction is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticInstructionMalformed,
                    "A semantic rewrite plan contains a null instruction.");
                continue;
            }

            if (!instruction.SourceRange.IsInstructionRange
                || !instruction.SourceRange.TryGetFileEnd(out _)
                || !instruction.SourceRange.TryGetVirtualEnd(out _)
                || instruction.SourceRange.VirtualAddress != instruction.SourceVirtualAddress
                || instruction.SourceRange.FileOffset != instruction.SourceFileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticInstructionMalformed,
                    "A semantic instruction has an invalid or mismatched AArch64 source range.",
                    instruction.SourceFileOffset.Value);
            }
            else if (!addressMap.TryMapSourceRange(
                instruction.SourceRange,
                SemanticEntityKind.Instruction,
                out _))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "A semantic instruction source range has no unique planned output mapping.",
                    instruction.SourceFileOffset.Value);
            }

            if (instruction.LiteralReference is { } literalReference)
            {
                if (literalReference.AccessSize <= 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticInstructionMalformed,
                        "A literal reference must have a positive access size.",
                        instruction.SourceFileOffset.Value);
                }

                if (literalReference.PoolRange is { } poolRange
                    && (poolRange.Size == 0
                        || !poolRange.TryGetFileEnd(out _)
                        || !poolRange.TryGetVirtualEnd(out _)))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticInstructionMalformed,
                        "A literal-pool range is empty or overflows its address domain.",
                        instruction.SourceFileOffset.Value);
                }
            }

            if (!instructionAddresses.Add(instruction.SourceVirtualAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate instruction addresses.",
                    instruction.SourceVirtualAddress.Value);
            }

            if (!instructionFileOffsets.Add(instruction.SourceFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate instruction file offsets.",
                    instruction.SourceFileOffset.Value);
            }

            if (instruction.PcRelativeExpression is not null
                && !pcRelativeInstructionSites.Add(instruction.SourceVirtualAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate PC-relative instruction sites.",
                    instruction.SourceFileOffset.Value);
            }
        }

        foreach (var fixup in fixupArray)
        {
            if (fixup is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A semantic rewrite plan contains a null fixup.");
                continue;
            }

            if (!fixupSites.Add(fixup.SourceAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate fixup source sites.",
                    fixup.SourceFileOffset.Value);
            }

            if (IsPcRelativeFixup(fixup))
            {
                pcRelativeFixupSites.Add(fixup.SourceAddress);
            }

            if (!fixupFileSites.Add(fixup.SourceFileOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic rewrite plan contains duplicate fixup file sites.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.SourceRange.Size == 0
                || !fixup.SourceRange.TryGetFileEnd(out _)
                || !fixup.SourceRange.TryGetVirtualEnd(out _)
                || fixup.SourceRange.VirtualAddress != fixup.SourceAddress
                || fixup.SourceRange.FileOffset != fixup.SourceFileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A semantic fixup source range is empty or overflows its address domain.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind != SemanticFixupKind.Relocation && !fixup.SourceRange.IsInstructionRange)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "An instruction fixup must address one aligned AArch64 instruction.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Relocation is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A relocation fixup is missing its symbolic relocation binding.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Relocation is { } relocation)
            {
                if (!relocation.IsKindConsistent)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A relocation binding kind does not match its raw AArch64 relocation type.",
                        fixup.SourceFileOffset.Value);
                }

                if (relocation.RelocationAddress is { } relocationAddress
                    && relocationAddress != fixup.SourceAddress)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A relocation binding address does not match its semantic fixup source address.",
                        fixup.SourceFileOffset.Value);
                }

                var writeSize = SemanticFixup.GetRelocationWriteSize(relocation.Kind);
                if (writeSize == 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupUnsupported,
                        "The semantic relocation has no defined write width.",
                        fixup.SourceFileOffset.Value);
                }
                else if (fixup.SourceRange.Size != writeSize
                    || fixup.SourceRange.FileOffset.Value % writeSize != 0
                    || fixup.SourceRange.VirtualAddress.Value % writeSize != 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticFixupMalformed,
                        "A relocation fixup source range has an invalid size or alignment for its relocation kind.",
                        fixup.SourceFileOffset.Value);
                }
            }

            if (fixup.Kind != SemanticFixupKind.Relocation && fixup.Expression is null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A PC-relative instruction fixup is missing its expression.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Expression is not null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A relocation fixup cannot also carry a PC-relative expression.",
                    fixup.SourceFileOffset.Value);
            }

            if (fixup.Kind != SemanticFixupKind.Relocation && fixup.Relocation is not null)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticFixupMalformed,
                    "A PC-relative instruction fixup cannot carry an ELF relocation binding.",
                    fixup.SourceFileOffset.Value);
            }

            ValidateExpressionKind(fixup, diagnostics);
            ValidateTargetRelationships(fixup, diagnostics);
            ValidateTarget(fixup.Target, fixup.SourceFileOffset.Value, diagnostics);
        }

        foreach (var instructionSite in pcRelativeInstructionSites)
        {
            if (!pcRelativeFixupSites.Contains(instructionSite))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A PC-relative instruction is missing its semantic fixup.",
                    instructionSite.Value);
            }
        }

        var plan = new SemanticRewritePlan(
            addressMap,
            instructionArray,
            fixupArray,
            extensions,
            diagnostics.ToArray());
        return new SemanticRewritePlanResult(plan, diagnostics.ToArray());
    }

    private static bool IsPcRelativeFixup(SemanticFixup fixup) =>
        fixup.Kind != SemanticFixupKind.Relocation
        || fixup.Relocation?.Kind is
            Aarch64RelocationKind.Call26
                or Aarch64RelocationKind.Jump26
                or Aarch64RelocationKind.ConditionalBranch19
                or Aarch64RelocationKind.TestBranch14
                or Aarch64RelocationKind.AdrPrelLo21
                or Aarch64RelocationKind.AdrPrelPgHi21
                or Aarch64RelocationKind.Literal19;

    private static void ValidateExpressionKind(
        SemanticFixup fixup,
        DiagnosticBag diagnostics)
    {
        if (fixup.Expression is not { } expression || fixup.Kind == SemanticFixupKind.Relocation)
        {
            return;
        }

        var expectedKind = expression.Kind switch
        {
            PcRelativeExpressionKind.Branch26 => SemanticFixupKind.Branch26,
            PcRelativeExpressionKind.Call26 => SemanticFixupKind.Call26,
            PcRelativeExpressionKind.ConditionalBranch19 => SemanticFixupKind.ConditionalBranch19,
            PcRelativeExpressionKind.TestBranch14 => SemanticFixupKind.TestBranch14,
            PcRelativeExpressionKind.AdrPrelLo21 => SemanticFixupKind.AdrPrelLo21,
            PcRelativeExpressionKind.AdrPrelPgHi21 => SemanticFixupKind.AdrPrelPgHi21,
            PcRelativeExpressionKind.Literal19 => SemanticFixupKind.Literal19,
            _ => (SemanticFixupKind?)null,
        };
        var expectedScale = expression.Kind switch
        {
            PcRelativeExpressionKind.Branch26
                or PcRelativeExpressionKind.Call26
                or PcRelativeExpressionKind.ConditionalBranch19
                or PcRelativeExpressionKind.TestBranch14
                or PcRelativeExpressionKind.Literal19 => sizeof(uint),
            PcRelativeExpressionKind.AdrPrelLo21 => 1,
            PcRelativeExpressionKind.AdrPrelPgHi21 => 0x1000,
            _ => 0,
        };
        var expectedPageRelative = expression.Kind == PcRelativeExpressionKind.AdrPrelPgHi21;
        if (expression.Scale != expectedScale
            || expression.IsPageRelative != expectedPageRelative)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The PC-relative expression has an invalid scale or page-relative mode for its family.",
                fixup.SourceFileOffset.Value);
        }

        if (expression.Place.Value % sizeof(uint) != 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A PC-relative expression place is not aligned to an AArch64 instruction.",
                fixup.SourceFileOffset.Value);
        }

        if (expectedKind is null || expectedKind.Value != fixup.Kind)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "The semantic fixup kind does not match its PC-relative expression kind.",
                fixup.SourceFileOffset.Value);
        }
    }

    private static void ValidateTargetRelationships(
        SemanticFixup fixup,
        DiagnosticBag diagnostics)
    {
        if (fixup.Expression is { } expression
            && !TargetsMatch(fixup.Target, expression.Target))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A PC-relative fixup target does not match its expression target.",
                fixup.SourceFileOffset.Value);
        }

        if (fixup.Relocation is { } relocation
            && !TargetsMatch(fixup.Target, relocation.Target))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticFixupMalformed,
                "A relocation fixup target does not match its relocation binding target.",
                fixup.SourceFileOffset.Value);
        }
    }

    private static bool TargetsMatch(SemanticTarget left, SemanticTarget right) =>
        left.Resolution == right.Resolution
        && left.SourceAddress == right.SourceAddress
        && left.Identity == right.Identity
        && string.Equals(left.RuntimeBinding, right.RuntimeBinding, StringComparison.Ordinal)
        && string.Equals(left.Diagnostic, right.Diagnostic, StringComparison.Ordinal)
        && left.CandidateIdentities.ToHashSet().SetEquals(right.CandidateIdentities)
        && left.CandidateAddresses.ToHashSet().SetEquals(right.CandidateAddresses);

    private static void ValidateEntityIdentity(
        SemanticEntityId identity,
        string name,
        ulong offset,
        DiagnosticBag diagnostics)
    {
        if (!Enum.IsDefined(typeof(SemanticEntityKind), identity.Kind)
            || string.IsNullOrWhiteSpace(identity.Value))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanMalformed,
                $"A {name} has an unsupported kind or empty value.",
                offset);
        }
    }

    private static void ValidateTarget(
        SemanticTarget target,
        ulong offset,
        DiagnosticBag diagnostics)
    {
        if (target.Identity is { } identity)
        {
            ValidateEntityIdentity(identity, "semantic target identity", offset, diagnostics);
        }

        var candidateIdentities = new HashSet<SemanticEntityId>();
        foreach (var candidateIdentity in target.CandidateIdentities)
        {
            ValidateEntityIdentity(candidateIdentity, "semantic target candidate identity", offset, diagnostics);
            if (!candidateIdentities.Add(candidateIdentity))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic target contains duplicate candidate identities.",
                    offset);
            }
        }

        var candidateAddresses = new HashSet<VirtualAddress>();
        foreach (var candidateAddress in target.CandidateAddresses)
        {
            if (!candidateAddresses.Add(candidateAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanMalformed,
                    "A semantic target contains duplicate candidate addresses.",
                    offset);
            }
        }

        switch (target.Resolution)
        {
            case SemanticTargetResolution.Exact
                when target.SourceAddress is null && target.Identity is null:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "An exact semantic target has no source address or entity identity.",
                    offset);
                break;
            case SemanticTargetResolution.Exact:
                break;
            case SemanticTargetResolution.BoundedSet
                when target.CandidateAddresses.Count == 0 && target.CandidateIdentities.Count == 0:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "A bounded semantic target set is empty.",
                    offset);
                break;
            case SemanticTargetResolution.RuntimeResolved
                when string.IsNullOrWhiteSpace(target.RuntimeBinding):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "A runtime-resolved semantic target is missing its binding identity.",
                    offset);
                break;
            case SemanticTargetResolution.Unresolved
                when string.IsNullOrWhiteSpace(target.Diagnostic):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "An unresolved semantic target is missing a diagnostic.",
                    offset);
                break;
            case SemanticTargetResolution.BoundedSet:
            case SemanticTargetResolution.RuntimeResolved:
            case SemanticTargetResolution.Unresolved:
                diagnostics.Warning(
                    DiagnosticCode.SemanticTargetUnresolved,
                    target.Diagnostic ?? "The semantic target requires a sibling resolver before final encoding.",
                    offset);
                break;
            default:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    "The semantic target has an unknown resolution kind.",
                    offset);
                break;
        }
    }
}
