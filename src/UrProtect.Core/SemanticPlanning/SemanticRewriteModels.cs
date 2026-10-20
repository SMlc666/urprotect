using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.SemanticPlanning;

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
                GetRelocationWriteSize(relocation)),
            relocation: relocation);
    }

    public static ulong GetRelocationWriteSize(RelocationBinding relocation)
    {
        ArgumentNullException.ThrowIfNull(relocation);
        return relocation.RelocationType is { } type
            && TlsRelocationClassifier.IsTlsRelocation(type)
                ? TlsRelocationClassifier.GetWriteSize(type)
                : GetRelocationWriteSize(relocation.Kind);
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
    DynamicImportCall,
    StaticFunctionPointerCall,
    ExternalJumpTable,
    // SPS6 discriminators are stable; append new extension kinds only.
    ExternalJumpTableConsumer = 9,
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
