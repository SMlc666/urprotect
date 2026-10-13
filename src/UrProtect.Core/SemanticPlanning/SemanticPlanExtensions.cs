using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>
/// Carries the single typed TLS access contract through the current semantic-plan
/// extension owner. Model and relocation family are enums, never string aliases.
/// </summary>
public sealed record SemanticTlsBindingExtension : ISemanticPlanExtension
{
    public SemanticTlsBindingExtension(TlsBinding binding, string? diagnostic = null)
    {
        Binding = binding ?? throw new ArgumentNullException(nameof(binding));
        Diagnostic = diagnostic;
    }

    public TlsBinding Binding { get; }

    public SemanticEntityId SourceIdentity => Binding.SourceIdentity;

    public SemanticSourceRange SourceRange => Binding.SourceRange;

    public TlsAccessModel Model => Binding.AccessModel;

    public string? Diagnostic { get; }

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.TlsBinding;
}

/// <summary>
/// Keeps a jump-table range and its symbolic target set visible to layout and
/// indirect-control-flow consumers.
/// </summary>
public enum SemanticJumpTableOwnership
{
    SelectedFunctionPrivate,
    Shared,
    External,
    RuntimeOwned,
}

public enum SemanticJumpTableRewritePolicy
{
    InPlace,
    CopiedAndRetargeted,
    PreservedAtOriginalAddress,
    StableVeneer,
    RuntimeTranslation,
}

public sealed record SemanticJumpTableEntryBinding(
    SemanticEntityId EntryIdentity,
    int Index,
    int EncodedValue,
    SemanticSourceRange SourceRange,
    SemanticTarget Target);

public sealed record SemanticJumpTableExtension : ISemanticPlanExtension
{
    public SemanticJumpTableExtension(
        SemanticEntityId tableIdentity,
        SemanticSourceRange tableRange,
        int entrySize,
        IEnumerable<SemanticTarget> targets,
        string? encoding = null,
        VirtualAddress? baseAddress = null,
        VirtualAddress? targetBaseAddress = null,
        SemanticEntityId? sourceInstruction = null,
        bool isSigned = false,
        int scale = 1,
        long addend = 0,
        int lowerBound = 0,
        int upperBound = -1,
        SemanticTarget? defaultTarget = null,
        SemanticJumpTableOwnership ownership = SemanticJumpTableOwnership.SelectedFunctionPrivate,
        SemanticJumpTableRewritePolicy rewritePolicy = SemanticJumpTableRewritePolicy.InPlace,
        SemanticSourceRange? outputRange = null,
        IEnumerable<SemanticJumpTableEntryBinding>? entries = null,
        string? diagnostic = null)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(entrySize, nameof(entrySize));

        TableIdentity = tableIdentity;
        TableRange = tableRange;
        EntrySize = entrySize;
        Targets = Array.AsReadOnly(targets.ToArray());
        Encoding = encoding;
        BaseAddress = baseAddress;
        TargetBaseAddress = targetBaseAddress;
        SourceInstruction = sourceInstruction;
        IsSigned = isSigned;
        Scale = scale;
        Addend = addend;
        LowerBound = lowerBound;
        UpperBound = upperBound;
        DefaultTarget = defaultTarget;
        Ownership = ownership;
        RewritePolicy = rewritePolicy;
        OutputRange = outputRange;
        Entries = Array.AsReadOnly((entries ?? Array.Empty<SemanticJumpTableEntryBinding>()).ToArray());
        Diagnostic = diagnostic;
    }

    public SemanticEntityId TableIdentity { get; }

    public SemanticSourceRange TableRange { get; }

    public int EntrySize { get; }

    public IReadOnlyList<SemanticTarget> Targets { get; }

    public string? Encoding { get; }

    public VirtualAddress? BaseAddress { get; }

    public VirtualAddress? TargetBaseAddress { get; }

    public SemanticEntityId? SourceInstruction { get; }

    public bool IsSigned { get; }

    public int Scale { get; }

    public long Addend { get; }

    public int LowerBound { get; }

    public int UpperBound { get; }

    public SemanticTarget? DefaultTarget { get; }

    public SemanticJumpTableOwnership Ownership { get; }

    public SemanticJumpTableRewritePolicy RewritePolicy { get; }

    public SemanticSourceRange? OutputRange { get; }

    public IReadOnlyList<SemanticJumpTableEntryBinding> Entries { get; }

    public string? Diagnostic { get; }

    public bool HasStructuredProof =>
        Entries.Count > 0
        && BaseAddress is not null
        && TargetBaseAddress is not null
        && SourceInstruction is not null;

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.JumpTable;
}

/// <summary>
/// Carries a project-owned CFI/frame effect without making the semantic
/// relocator responsible for emitting unwind records.
/// </summary>
public sealed record SemanticCfiEffectExtension : ISemanticPlanExtension
{
    public SemanticCfiEffectExtension(
        SemanticEntityId sourceIdentity,
        SemanticSourceRange sourceRange,
        string effect,
        IEnumerable<SemanticRegisterEffect>? registerEffects = null,
        string? diagnostic = null)
    {
        ArgumentNullException.ThrowIfNull(effect);
        if (effect.Length == 0)
        {
            throw new ArgumentException("A CFI effect is required.", nameof(effect));
        }

        SourceIdentity = sourceIdentity;
        SourceRange = sourceRange;
        Effect = effect;
        RegisterEffects = Array.AsReadOnly(
            (registerEffects ?? Array.Empty<SemanticRegisterEffect>()).ToArray());
        Diagnostic = diagnostic;
    }

    public SemanticEntityId SourceIdentity { get; }

    public SemanticSourceRange SourceRange { get; }

    public string Effect { get; }

    public IReadOnlyList<SemanticRegisterEffect> RegisterEffects { get; }

    public string? Diagnostic { get; }

    public SemanticPlanExtensionKind Kind => SemanticPlanExtensionKind.CfiEffect;
}
