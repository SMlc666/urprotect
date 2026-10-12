using UrProtect.Core.Aarch64Semantics;

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
public sealed record SemanticJumpTableExtension : ISemanticPlanExtension
{
    public SemanticJumpTableExtension(
        SemanticEntityId tableIdentity,
        SemanticSourceRange tableRange,
        int entrySize,
        IEnumerable<SemanticTarget> targets,
        string? encoding = null)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(entrySize, nameof(entrySize));

        TableIdentity = tableIdentity;
        TableRange = tableRange;
        EntrySize = entrySize;
        Targets = Array.AsReadOnly(targets.ToArray());
        Encoding = encoding;
    }

    public SemanticEntityId TableIdentity { get; }

    public SemanticSourceRange TableRange { get; }

    public int EntrySize { get; }

    public IReadOnlyList<SemanticTarget> Targets { get; }

    public string? Encoding { get; }

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
