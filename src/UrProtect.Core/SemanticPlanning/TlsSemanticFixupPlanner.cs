using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

/// <summary>One TLS relocation carried from its source range to the planned output range.</summary>
public sealed record TlsSemanticFixup(
    TlsAccessModel AccessModel,
    TlsRelocationFamily RelocationFamily,
    SemanticSourceRange SequenceSourceRange,
    SemanticSourceRange SequenceOutputRange,
    SemanticSourceRange RelocationSourceRange,
    SemanticSourceRange RelocationOutputRange,
    RelocationBinding Relocation,
    int PairOrdinal,
    TlsModuleIdentity Module,
    TlsSymbolIdentity? Symbol,
    long Addend,
    int AccessSize,
    TlsAddressExpression AddressExpression,
    IReadOnlyList<TlsProfileRequirement> ProfileRequirements,
    IReadOnlyList<TlsRuntimeRequirement> RuntimeRequirements,
    TlsGotEntryBinding? GotEntry,
    TlsResolverCallBinding? ResolverCall = null,
    SemanticSourceRange? ResolverCallOutputRange = null,
    TlsModuleOwnerBinding? ModuleOwner = null,
    TlsDtpRelOwnerBinding? DtpRelOwner = null,
    TlsDescriptorOwnerBinding? DescriptorOwner = null);

/// <summary>Bounded TLS semantic fixup planning result; it never writes image bytes.</summary>
public sealed record TlsSemanticFixupPlanResult(
    IReadOnlyList<TlsSemanticFixup> Fixups,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Maps the current TLS semantic extension through the existing source-to-output
/// address map. Physical placement and byte emission remain owned by ElfLayout.
/// </summary>
public static class TlsSemanticFixupPlanner
{
    public static TlsSemanticFixupPlanResult Build(SemanticRewritePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var diagnostics = new DiagnosticBag();
        var fixups = new List<TlsSemanticFixup>();
        foreach (var extension in plan.Extensions.OfType<SemanticTlsBindingExtension>())
        {
            var binding = extension.Binding;
            if (!plan.AddressMap.TryMapSourceRange(
                    binding.SourceRange,
                    SemanticEntityKind.Function,
                    out var outputSequenceRange))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticAddressMapMissing,
                    "The TLS instruction sequence has no unique source-to-output mapping.",
                    binding.SourceRange.FileOffset.Value);
                continue;
            }

            SemanticSourceRange? resolverCallOutputRange = null;
            if (binding.ResolverCall is { } resolverCall)
            {
                if (!plan.AddressMap.TryMapSourceRange(
                        resolverCall.SourceRange,
                        SemanticEntityKind.Instruction,
                        out var mappedResolverCallRange))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        "The TLS resolver call has no unique source-to-output mapping.",
                        resolverCall.SourceRange.FileOffset.Value);
                    continue;
                }

                resolverCallOutputRange = mappedResolverCallRange;
            }

            foreach (var site in binding.RelocationSites)
            {
                if (site is null || site.Binding is null)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsSequenceMalformed,
                        "A TLS semantic binding contains a null relocation site or relocation binding.",
                        binding.SourceRange.FileOffset.Value);
                    continue;
                }

                if (!plan.AddressMap.TryMapSourceRange(
                        site.SourceRange,
                        SemanticEntityKind.RelocationSite,
                        out var outputRelocationRange))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticAddressMapMissing,
                        "A TLS relocation site has no unique source-to-output mapping.",
                        site.SourceRange.FileOffset.Value);
                    continue;
                }

                var writeSize = site.Binding.RelocationType is { } relocationType
                    ? TlsRelocationClassifier.GetWriteSize(relocationType)
                    : 0;
                if (writeSize == 0
                    || outputRelocationRange.Size != writeSize
                    || outputRelocationRange.FileOffset.Value % writeSize != 0
                    || outputRelocationRange.VirtualAddress.Value % writeSize != 0)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsLayoutMismatch,
                        "The planned TLS relocation output range does not preserve its typed write width and alignment.",
                        site.SourceRange.FileOffset.Value);
                    continue;
                }

                fixups.Add(new TlsSemanticFixup(
                    binding.AccessModel,
                    site.Family,
                    binding.SourceRange,
                    outputSequenceRange,
                    site.SourceRange,
                    outputRelocationRange,
                    site.Binding,
                    site.PairOrdinal,
                    binding.Module,
                    binding.Symbol,
                    site.Binding.Addend,
                    binding.AccessSize,
                    binding.AddressExpression,
                    binding.ProfileRequirements,
                    binding.RuntimeRequirements,
                    binding.GotEntry,
                    binding.ResolverCall,
                    resolverCallOutputRange,
                    binding.ModuleOwner,
                    binding.DtpRelOwner,
                    binding.DescriptorOwner));
            }
            if (binding.ResolverCall is { } callBinding
                && resolverCallOutputRange is { } resolverOutputRange)
            {
                fixups.Add(new TlsSemanticFixup(
                    binding.AccessModel,
                    TlsRelocationFamily.Dtpmod,
                    binding.SourceRange,
                    outputSequenceRange,
                    callBinding.SourceRange,
                    resolverOutputRange,
                    callBinding.Relocation,
                    -1,
                    binding.Module,
                    binding.Symbol,
                    callBinding.Relocation.Addend,
                    binding.AccessSize,
                    binding.AddressExpression,
                    binding.ProfileRequirements,
                    binding.RuntimeRequirements,
                    GotEntry: null,
                    ResolverCall: callBinding,
                    ResolverCallOutputRange: resolverOutputRange,
                    ModuleOwner: binding.ModuleOwner,
                    DtpRelOwner: binding.DtpRelOwner,
                    DescriptorOwner: binding.DescriptorOwner));
            }
        }

        ValidateOutputSites(fixups, diagnostics);
        return new TlsSemanticFixupPlanResult(
            Array.AsReadOnly(fixups
                .OrderBy(fixup => fixup.RelocationOutputRange.VirtualAddress.Value)
                .ThenBy(fixup => fixup.RelocationOutputRange.FileOffset.Value)
                .ThenBy(fixup => (int)fixup.RelocationFamily)
                .ToArray()),
            diagnostics.ToArray());
    }

    private static void ValidateOutputSites(
        IReadOnlyList<TlsSemanticFixup> fixups,
        DiagnosticBag diagnostics)
    {
        var ordered = fixups
            .OrderBy(fixup => fixup.RelocationOutputRange.VirtualAddress.Value)
            .ThenBy(fixup => fixup.RelocationOutputRange.FileOffset.Value)
            .ToArray();
        for (var index = 1; index < ordered.Length; index++)
        {
            var previous = ordered[index - 1].RelocationOutputRange;
            var current = ordered[index].RelocationOutputRange;
            if (Overlaps(previous.VirtualAddress.Value, previous.Size, current.VirtualAddress.Value, current.Size)
                || Overlaps(previous.FileOffset.Value, previous.Size, current.FileOffset.Value, current.Size))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "Planned TLS relocation fixups overlap in output file or virtual address space.",
                    current.FileOffset.Value);
            }
        }
    }

    private static bool Overlaps(ulong leftStart, ulong leftSize, ulong rightStart, ulong rightSize) =>
        leftStart <= rightStart
            ? rightStart - leftStart < leftSize
            : leftStart - rightStart < rightSize;
}
