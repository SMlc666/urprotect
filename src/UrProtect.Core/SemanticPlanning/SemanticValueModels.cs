using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.SemanticPlanning;

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
