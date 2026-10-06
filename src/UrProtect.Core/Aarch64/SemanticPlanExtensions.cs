namespace UrProtect.Core.Aarch64;

/// <summary>
/// Preserves a TLS relocation or binding for the TLS semantic child.
/// </summary>
public sealed record SemanticTlsBindingExtension : ISemanticPlanExtension
{
    public SemanticTlsBindingExtension(
        SemanticEntityId sourceIdentity,
        SemanticSourceRange sourceRange,
        RelocationBinding binding,
        string model,
        string? diagnostic = null)
    {
        SourceIdentity = sourceIdentity;
        SourceRange = sourceRange;
        Binding = binding ?? throw new ArgumentNullException(nameof(binding));
        if (string.IsNullOrWhiteSpace(model))
        {
            throw new ArgumentException("A TLS binding model is required.", nameof(model));
        }

        Model = model;
        Diagnostic = diagnostic;
    }

    public SemanticEntityId SourceIdentity { get; }

    public SemanticSourceRange SourceRange { get; }

    public RelocationBinding Binding { get; }

    public string Model { get; }

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
